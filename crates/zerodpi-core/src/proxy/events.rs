//! Lifecycle events are queued; progress is sampled from current counters.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::ProxyEvent;

const PROGRESS_INTERVAL: Duration = Duration::from_millis(500);

/// Cumulative byte counts for one active relay at a batch's sample time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayProgress {
    pub src_port: u16,
    pub c2s_bytes: u64,
    pub s2c_bytes: u64,
}

#[derive(Debug, Default)]
pub(super) struct RelayCounters {
    pub c2s: AtomicU64,
    pub s2c: AtomicU64,
}

#[derive(Debug)]
struct RegisteredRelay {
    generation: u64,
    counters: Arc<RelayCounters>,
}

#[derive(Debug, Default)]
struct ProgressRegistry {
    generation: u64,
    relays: HashMap<u16, RegisteredRelay>,
}

/// Lifecycle sender and optional registry shared by active relays.
#[derive(Debug, Clone)]
pub struct ProxyEventSender {
    events: mpsc::UnboundedSender<ProxyEvent>,
    progress: Option<Arc<Mutex<ProgressRegistry>>>,
}

/// Receives lifecycle events first and samples live progress at most twice a second.
/// Progress is never enqueued, so a slow receiver sees only the latest counters.
#[derive(Debug)]
pub struct ProxyEventReceiver {
    events: mpsc::UnboundedReceiver<ProxyEvent>,
    progress: Option<Arc<Mutex<ProgressRegistry>>>,
    next_progress: Instant,
}

/// Create a proxy event channel. Disable progress for lifecycle-only consumers.
/// This creates no tasks or per-connection timers and needs no runtime to construct.
pub fn proxy_event_channel(progress_enabled: bool) -> (ProxyEventSender, ProxyEventReceiver) {
    let (tx, rx) = mpsc::unbounded_channel();
    let progress = progress_enabled.then(|| Arc::new(Mutex::new(ProgressRegistry::default())));
    (
        ProxyEventSender {
            events: tx,
            progress: progress.clone(),
        },
        ProxyEventReceiver {
            events: rx,
            progress,
            next_progress: Instant::now() + PROGRESS_INTERVAL,
        },
    )
}

impl ProxyEventSender {
    pub fn send(&self, event: ProxyEvent) -> Result<(), mpsc::error::SendError<ProxyEvent>> {
        self.events.send(event)
    }

    pub fn is_closed(&self) -> bool {
        self.events.is_closed()
    }

    pub(super) fn register_relay(&self, src_port: u16) -> Option<RelayRegistration> {
        if self.is_closed() {
            return None;
        }
        let registry = self.progress.as_ref()?;
        let counters = Arc::new(RelayCounters::default());
        let mut progress = registry.lock();
        progress.generation = progress.generation.wrapping_add(1);
        let generation = progress.generation;
        progress.relays.insert(
            src_port,
            RegisteredRelay {
                generation,
                counters: counters.clone(),
            },
        );
        Some(RelayRegistration {
            registry: registry.clone(),
            src_port,
            generation,
            counters,
        })
    }
}

impl ProxyEventReceiver {
    pub fn try_recv(&mut self) -> Result<ProxyEvent, mpsc::error::TryRecvError> {
        match self.events.try_recv() {
            Err(mpsc::error::TryRecvError::Empty) => self
                .sample_progress()
                .ok_or(mpsc::error::TryRecvError::Empty),
            result => result,
        }
    }

    pub async fn recv(&mut self) -> Option<ProxyEvent> {
        if self.progress.is_none() {
            return self.events.recv().await;
        }
        loop {
            match self.try_recv() {
                Ok(event) => return Some(event),
                Err(mpsc::error::TryRecvError::Disconnected) => return None,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
            tokio::select! {
                biased;
                event = self.events.recv() => return event,
                _ = tokio::time::sleep_until(self.next_progress) => {}
            }
        }
    }

    fn sample_progress(&mut self) -> Option<ProxyEvent> {
        let now = Instant::now();
        if now < self.next_progress {
            return None;
        }
        // Skip missed intervals instead of replaying snapshots after a stall.
        self.next_progress = now + PROGRESS_INTERVAL;
        let progress = self.progress.as_ref()?.lock();
        if progress.relays.is_empty() {
            return None;
        }
        let entries = progress
            .relays
            .iter()
            .map(|(&src_port, relay)| RelayProgress {
                src_port,
                c2s_bytes: relay.counters.c2s.load(Ordering::Relaxed),
                s2c_bytes: relay.counters.s2c.load(Ordering::Relaxed),
            })
            .collect();
        Some(ProxyEvent::RelayProgressBatch {
            sampled_at: now.into_std(),
            entries,
        })
    }
}

/// Removing a registration on every exit also covers an aborted relay future.
#[derive(Debug)]
pub(super) struct RelayRegistration {
    registry: Arc<Mutex<ProgressRegistry>>,
    src_port: u16,
    generation: u64,
    pub counters: Arc<RelayCounters>,
}

impl Drop for RelayRegistration {
    fn drop(&mut self) {
        let mut registry = self.registry.lock();
        if registry
            .relays
            .get(&self.src_port)
            .is_some_and(|relay| relay.generation == self.generation)
        {
            registry.relays.remove(&self.src_port);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::BypassOutcome;
    use crate::proxy::{ProxyEvent, RelayEndReason};
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::sync::mpsc::error::TryRecvError;

    fn entries(event: ProxyEvent) -> Vec<RelayProgress> {
        let ProxyEvent::RelayProgressBatch { mut entries, .. } = event else {
            panic!("expected a progress batch, got {event:?}");
        };
        entries.sort_unstable_by_key(|entry| entry.src_port);
        entries
    }

    #[tokio::test(start_paused = true)]
    async fn samples_all_relays_once_per_interval_including_idle_ones() {
        let (tx, mut rx) = proxy_event_channel(true);
        let first = tx.register_relay(1200).unwrap();
        let second = tx.register_relay(1201).unwrap();
        first.counters.c2s.store(25, Ordering::Relaxed);
        second.counters.s2c.store(70, Ordering::Relaxed);
        tokio::time::advance(Duration::from_millis(499)).await;
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        tokio::time::advance(Duration::from_millis(1)).await;
        let expected = vec![
            RelayProgress {
                src_port: 1200,
                c2s_bytes: 25,
                s2c_bytes: 0,
            },
            RelayProgress {
                src_port: 1201,
                c2s_bytes: 0,
                s2c_bytes: 70,
            },
        ];
        assert_eq!(entries(rx.try_recv().unwrap()), expected);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(entries(rx.try_recv().unwrap()), expected);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_consumer_reads_only_the_latest_snapshot() {
        let (tx, mut rx) = proxy_event_channel(true);
        let relay = tx.register_relay(1234).unwrap();
        for value in 1..=10 {
            relay.counters.c2s.store(value * 100, Ordering::Relaxed);
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert_eq!(
            entries(rx.try_recv().unwrap()),
            vec![RelayProgress {
                src_port: 1234,
                c2s_bytes: 1000,
                s2c_bytes: 0
            }]
        );
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test(start_paused = true)]
    async fn completed_relay_cannot_emit_late_progress() {
        let (tx, mut rx) = proxy_event_channel(true);
        let relay = tx.register_relay(1234).unwrap();
        relay.counters.c2s.store(100, Ordering::Relaxed);
        tokio::time::advance(Duration::from_millis(500)).await;
        drop(relay);
        tx.send(ProxyEvent::RelayFinished {
            src_port: 1234,
            c2s_bytes: 100,
            s2c_bytes: 0,
            reason: RelayEndReason::Completed,
        })
        .unwrap();
        assert!(matches!(
            rx.try_recv().unwrap(),
            ProxyEvent::RelayFinished { c2s_bytes: 100, .. }
        ));
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test(start_paused = true)]
    async fn old_registration_cannot_remove_a_reused_port() {
        let (tx, mut rx) = proxy_event_channel(true);
        let old = tx.register_relay(1234).unwrap();
        old.counters.c2s.store(10, Ordering::Relaxed);
        let current = tx.register_relay(1234).unwrap();
        current.counters.c2s.store(99, Ordering::Relaxed);
        drop(old);
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(
            entries(rx.try_recv().unwrap()),
            vec![RelayProgress {
                src_port: 1234,
                c2s_bytes: 99,
                s2c_bytes: 0
            }]
        );
        drop(current);
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test(start_paused = true)]
    async fn lifecycle_events_precede_due_progress() {
        let (tx, mut rx) = proxy_event_channel(true);
        let _relay = tx.register_relay(1234).unwrap();
        tx.send(ProxyEvent::BypassComplete {
            src_port: 1234,
            outcome: BypassOutcome::FakeDataAcked,
        })
        .unwrap();
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(matches!(
            rx.try_recv().unwrap(),
            ProxyEvent::BypassComplete { .. }
        ));
        assert_eq!(entries(rx.try_recv().unwrap()).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn async_receiver_samples_without_lifecycle_events() {
        let (tx, mut rx) = proxy_event_channel(true);
        let _relay = tx.register_relay(1234).unwrap();
        let event = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entries(event).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_progress_does_not_register_relays_or_emit_samples() {
        let (tx, mut rx) = proxy_event_channel(false);
        assert!(tx.register_relay(1234).is_none());
        assert!(tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn closed_receiver_disables_relay_registration() {
        let (tx, rx) = proxy_event_channel(true);
        drop(rx);
        assert!(tx.is_closed());
        assert!(tx.register_relay(1234).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn receiver_drains_lifecycle_events_then_closes() {
        let (tx, mut rx) = proxy_event_channel(true);
        tx.send(ProxyEvent::LowTtlDiscovered { value: 7 }).unwrap();
        drop(tx);
        assert!(matches!(
            rx.recv().await.unwrap(),
            ProxyEvent::LowTtlDiscovered { value: 7 }
        ));
        assert!(rx.recv().await.is_none());
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Disconnected)));
    }
}
