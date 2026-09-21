//! Network change detection.
//!
//! The monitor answers one question: did the local routing situation change?
//! The canonical new address is discovered by the caller with
//! `default_interface_ipv4`, so platform event payloads are deliberately
//! ignored — only the event kind matters.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::broadcast;
use zerodpi_core::net::{default_interface_ipv4, NetworkChangeSource};

mod platform;

// Linux netlink ABI constants. Kept platform-independent (and test-only
// outside Linux/Android) so the pure classifier is testable everywhere.
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) const RTM_NEWLINK: u16 = 16;
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) const RTM_DELLINK: u16 = 17;
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) const RTM_NEWADDR: u16 = 20;
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) const RTM_DELADDR: u16 = 21;
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) const RTM_NEWROUTE: u16 = 24;
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) const RTM_DELROUTE: u16 = 25;

/// Map a netlink message type to the change kind it represents.
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) fn classify_nlmsg(msg_type: u16) -> Option<NetworkChangeSource> {
    match msg_type {
        RTM_NEWADDR | RTM_DELADDR => Some(NetworkChangeSource::Address),
        RTM_NEWROUTE | RTM_DELROUTE => Some(NetworkChangeSource::Route),
        RTM_NEWLINK | RTM_DELLINK => Some(NetworkChangeSource::Link),
        _ => None,
    }
}

/// A settled, routing-relevant change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEvent {
    Changed { source: NetworkChangeSource },
}

/// Coalesces raw platform ticks into settled change notifications.
#[derive(Debug)]
pub struct SettleState {
    settle: Duration,
    pending: Option<(NetworkChangeSource, Duration)>,
}

impl SettleState {
    pub fn new(settle: Duration) -> Self {
        Self {
            settle,
            pending: None,
        }
    }

    /// Record a raw tick; a newer tick replaces the pending deadline.
    pub fn record(&mut self, source: NetworkChangeSource, now: Duration) {
        self.pending = Some((source, now.saturating_add(self.settle)));
    }

    /// Time until the pending tick settles, or `None` when nothing is pending.
    pub fn timeout(&self, now: Duration) -> Option<Duration> {
        self.pending
            .as_ref()
            .map(|(_, deadline)| deadline.saturating_sub(now))
    }

    /// Take the settled tick when its deadline has passed.
    pub fn due(&mut self, now: Duration) -> Option<NetworkChangeSource> {
        match self.pending {
            Some((source, deadline)) if now >= deadline => {
                self.pending = None;
                Some(source)
            }
            _ => None,
        }
    }
}

/// Emits `true` once per real address/up-state transition.
#[derive(Debug, Default)]
pub struct ChangeFilter {
    last: Option<Ipv4Addr>,
}

impl ChangeFilter {
    pub fn seed(&mut self, value: Option<Ipv4Addr>) {
        self.last = value;
    }

    pub fn observe(&mut self, value: Option<Ipv4Addr>) -> bool {
        if value != self.last {
            self.last = value;
            true
        } else {
            false
        }
    }
}

/// What a platform source reports while the monitor waits.
#[derive(Debug)]
pub(crate) enum SourceEvent {
    Change(NetworkChangeSource),
    Timeout,
    Shutdown,
}

/// Blocking platform event source.
pub(crate) trait NetworkSource: Send {
    /// Block for at most `timeout`.
    fn wait(&mut self, timeout: Duration) -> SourceEvent;
}

/// Wake handle used to interrupt [`NetworkSource::wait`] at shutdown.
pub(crate) trait NetworkWaker: Send + Sync {
    fn wake(&self);
}

pub(crate) struct SourceParts<S: NetworkSource> {
    pub source: S,
    pub waker: Arc<dyn NetworkWaker>,
}

/// One monitor iteration. Exposed for platform wiring and tests.
pub(crate) fn run_loop<S: NetworkSource>(
    mut source: S,
    probe: impl Fn() -> Option<Ipv4Addr>,
    seed: Option<Ipv4Addr>,
    settle: Duration,
    poll_interval: Duration,
    should_run: impl Fn() -> bool,
    emit: impl Fn(NetworkEvent),
) {
    let mut settle_state = SettleState::new(settle);
    let mut filter = ChangeFilter::default();
    filter.seed(seed);
    let start = std::time::Instant::now();
    loop {
        if !should_run() {
            break;
        }
        let now = start.elapsed();
        let timeout = settle_state.timeout(now).unwrap_or(poll_interval);
        match source.wait(timeout) {
            SourceEvent::Change(kind) => settle_state.record(kind, start.elapsed()),
            SourceEvent::Shutdown => break,
            SourceEvent::Timeout => {
                let now = start.elapsed();
                if let Some(kind) = settle_state.due(now) {
                    if filter.observe(probe()) {
                        emit(NetworkEvent::Changed { source: kind });
                    }
                } else if filter.observe(probe()) {
                    emit(NetworkEvent::Changed {
                        source: NetworkChangeSource::Poll,
                    });
                }
            }
        }
    }
}

/// Owns the platform detection thread and its event channel.
pub struct NetworkMonitor {
    stop: Arc<AtomicBool>,
    waker: Arc<dyn NetworkWaker>,
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    tx: broadcast::Sender<NetworkEvent>,
}

impl NetworkMonitor {
    /// Start detection.
    ///
    /// `probe_target` is the active relay IPv4 address (0 = unknown); the
    /// canonical interface address is discovered with
    /// `default_interface_ipv4`. `initial` is the address probed at startup.
    pub fn start(
        probe_target: Arc<AtomicU32>,
        initial: Option<Ipv4Addr>,
        settle: Duration,
        poll_interval: Duration,
    ) -> Result<Self> {
        let (tx, _rx) = broadcast::channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let SourceParts { source, waker } = platform::source()?;
        let emit_tx = tx.clone();
        let thread_stop = stop.clone();
        let probe = move || {
            let raw = probe_target.load(Ordering::SeqCst);
            if raw == 0 {
                return None;
            }
            default_interface_ipv4(Ipv4Addr::from(raw)).ok()
        };
        // Seed the filter from the startup probe so the first safety-net tick
        // does not emit a spurious change for an address we already know.
        let seed = initial.or_else(&probe);
        let handle = std::thread::Builder::new()
            .name("zerodpi-netmon".into())
            .spawn(move || {
                run_loop(
                    source,
                    probe,
                    seed,
                    settle,
                    poll_interval,
                    || !thread_stop.load(Ordering::SeqCst),
                    |event| {
                        let _ = emit_tx.send(event);
                    },
                );
            })?;
        Ok(Self {
            stop,
            waker,
            handle: Mutex::new(Some(handle)),
            tx,
        })
    }

    pub fn events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.tx.subscribe()
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.waker.wake();
        let handle = self.handle.lock().expect("netmon handle poisoned").take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

/// Source used only on platforms without a native notification API.
#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
pub(crate) struct PollOnlySource;

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
impl NetworkSource for PollOnlySource {
    fn wait(&mut self, timeout: Duration) -> SourceEvent {
        std::thread::sleep(timeout);
        SourceEvent::Timeout
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
pub(crate) struct NoopWaker;

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
impl NetworkWaker for NoopWaker {
    fn wake(&self) {}
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use zerodpi_core::net::NetworkChangeSource;

    #[test]
    fn settle_waits_for_the_window_to_elapse() {
        let mut settle = SettleState::new(Duration::from_secs(1));
        settle.record(NetworkChangeSource::Address, Duration::from_secs(10));
        assert_eq!(settle.due(Duration::from_millis(10_999)), None);
        assert_eq!(
            settle.due(Duration::from_secs(11)),
            Some(NetworkChangeSource::Address)
        );
        // The pending change is consumed exactly once.
        assert_eq!(settle.due(Duration::from_secs(12)), None);
    }

    #[test]
    fn a_newer_tick_resets_the_deadline_and_keeps_the_latest_source() {
        let mut settle = SettleState::new(Duration::from_secs(1));
        settle.record(NetworkChangeSource::Address, Duration::from_secs(10));
        settle.record(NetworkChangeSource::Route, Duration::from_millis(10_500));
        assert_eq!(settle.due(Duration::from_secs(11)), None);
        assert_eq!(
            settle.due(Duration::from_millis(11_500)),
            Some(NetworkChangeSource::Route)
        );
    }

    #[test]
    fn timeout_reports_the_remaining_window() {
        let mut settle = SettleState::new(Duration::from_secs(2));
        assert_eq!(settle.timeout(Duration::ZERO), None);
        settle.record(NetworkChangeSource::Link, Duration::from_secs(5));
        assert_eq!(
            settle.timeout(Duration::from_millis(5_500)),
            Some(Duration::from_millis(1_500))
        );
    }

    #[test]
    fn classifies_netlink_message_types() {
        assert_eq!(classify_nlmsg(RTM_NEWADDR), Some(NetworkChangeSource::Address));
        assert_eq!(classify_nlmsg(RTM_DELADDR), Some(NetworkChangeSource::Address));
        assert_eq!(classify_nlmsg(RTM_NEWROUTE), Some(NetworkChangeSource::Route));
        assert_eq!(classify_nlmsg(RTM_DELROUTE), Some(NetworkChangeSource::Route));
        assert_eq!(classify_nlmsg(RTM_NEWLINK), Some(NetworkChangeSource::Link));
        assert_eq!(classify_nlmsg(RTM_DELLINK), Some(NetworkChangeSource::Link));
        assert_eq!(classify_nlmsg(0xffff), None);
    }

    #[test]
    fn change_filter_reports_only_real_changes() {
        let mut filter = ChangeFilter::default();
        filter.seed(None);
        assert!(!filter.observe(None));
        assert!(filter.observe(Some("10.0.0.1".parse().unwrap())));
        assert!(!filter.observe(Some("10.0.0.1".parse().unwrap())));
        assert!(filter.observe(None));
    }
}
