//! In-place network recovery policy.
//!
//! The coordinator reacts to settled network changes, rebuilds the data plane
//! with the new interface address, verifies the active target, and only then
//! asks for a rescan when the selection policy allows it.
// Remove this allow when Task 12 wires the coordinator into the modes.
#![allow(dead_code)]

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;

use zerodpi_core::net::NetworkChangeSource;
use zerodpi_platform::netmon::NetworkEvent;

/// Settle window handed to `NetworkMonitor::start`.
pub const SETTLE: Duration = Duration::from_secs(1);
/// Poll safety-net interval handed to `NetworkMonitor::start`.
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
pub const RECOVERY_RESCAN_MIN_INTERVAL: Duration = Duration::from_secs(60);

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One status update produced by recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkStatus {
    Online {
        interface_ip: Ipv4Addr,
    },
    Unavailable {
        message: String,
    },
    Changing {
        interface_ip: Ipv4Addr,
        source: NetworkChangeSource,
    },
    Recovering {
        attempt: u32,
        next_retry_ms: u64,
        message: String,
    },
    Recovered {
        interface_ip: Ipv4Addr,
        target_verified: bool,
        target_switched: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RescanOutcome {
    pub found: usize,
    pub switched: bool,
}

/// Everything the coordinator needs from the running mode.
pub trait RecoveryEnv: Send + Sync + 'static {
    /// Probe the canonical interface address for `target`.
    fn probe(&self, target: Ipv4Addr) -> anyhow::Result<Ipv4Addr>;
    fn rebuild<'a>(&'a self, interface_ip: Ipv4Addr) -> BoxFuture<'a, anyhow::Result<()>>;
    fn verify<'a>(&'a self) -> BoxFuture<'a, bool>;
    fn rescan<'a>(&'a self) -> BoxFuture<'a, RescanOutcome>;
    fn apply_interface_ip(&self, interface_ip: Ipv4Addr);
    fn remote_disconnected(&self) -> bool {
        false
    }
    fn publish(&self, status: NetworkStatus);
}

pub struct RecoveryCoordinator<E: RecoveryEnv> {
    env: Arc<E>,
    probe_target: Arc<AtomicU32>,
    auto_select: bool,
    current: Option<Ipv4Addr>,
    last_rescan: Option<tokio::time::Instant>,
}

impl<E: RecoveryEnv> RecoveryCoordinator<E> {
    pub fn new(
        env: Arc<E>,
        probe_target: Arc<AtomicU32>,
        auto_select: bool,
        initial: Option<Ipv4Addr>,
    ) -> Self {
        Self {
            env,
            probe_target,
            auto_select,
            current: initial,
            last_rescan: None,
        }
    }

    /// Run until the monitor channel closes.
    pub async fn run(mut self, mut rx: broadcast::Receiver<NetworkEvent>) {
        if let Some(interface_ip) = self.current {
            self.env.publish(NetworkStatus::Online { interface_ip });
        }
        loop {
            let source = match rx.recv().await {
                Ok(NetworkEvent::Changed { source }) => source,
                Err(broadcast::error::RecvError::Lagged(_)) => NetworkChangeSource::Poll,
                Err(broadcast::error::RecvError::Closed) => break,
            };
            self.handle_change(source, &mut rx).await;
        }
    }

    /// Process one settled change until a stable outcome is published.
    pub(crate) async fn handle_change(
        &mut self,
        source: NetworkChangeSource,
        rx: &mut broadcast::Receiver<NetworkEvent>,
    ) {
        loop {
            if self.env.remote_disconnected() {
                self.current = None;
                self.env.publish(NetworkStatus::Unavailable {
                    message: "root helper disconnected".to_owned(),
                });
                return;
            }
            let target = match self.probe_target.load(Ordering::SeqCst) {
                0 => {
                    self.env.publish(NetworkStatus::Unavailable {
                        message: "no active target to probe".to_owned(),
                    });
                    return;
                }
                raw => Ipv4Addr::from(raw),
            };
            match self.env.probe(target) {
                Err(error) => {
                    self.current = None;
                    self.env.publish(NetworkStatus::Unavailable {
                        message: error.to_string(),
                    });
                    return;
                }
                Ok(ip) if Some(ip) == self.current => {
                    self.env.publish(NetworkStatus::Online { interface_ip: ip });
                    return;
                }
                Ok(ip) => {
                    self.env.publish(NetworkStatus::Changing {
                        interface_ip: ip,
                        source,
                    });
                    if !self.rebuild_with_retry(ip, rx).await {
                        continue;
                    }
                    self.current = Some(ip);
                    self.env.apply_interface_ip(ip);
                    let target_verified = self.env.verify().await;
                    let mut target_switched = false;
                    if !target_verified && self.auto_select && self.rescan_allowed() {
                        let outcome = self.env.rescan().await;
                        target_switched = outcome.switched;
                        self.last_rescan = Some(tokio::time::Instant::now());
                        if outcome.found == 0 {
                            self.env.publish(NetworkStatus::Unavailable {
                                message: "recovery rescan found no reachable target".to_owned(),
                            });
                        }
                    }
                    self.env.publish(NetworkStatus::Recovered {
                        interface_ip: ip,
                        target_verified,
                        target_switched,
                    });
                    return;
                }
            }
        }
    }

    /// Rebuild once, then retry with exponential backoff. Returns `false`
    /// when a newer network event arrived and the caller should re-probe.
    async fn rebuild_with_retry(
        &mut self,
        interface_ip: Ipv4Addr,
        rx: &mut broadcast::Receiver<NetworkEvent>,
    ) -> bool {
        let mut delay = BACKOFF_INITIAL;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match self.env.rebuild(interface_ip).await {
                Ok(()) => return true,
                Err(error) => {
                    self.env.publish(NetworkStatus::Recovering {
                        attempt,
                        next_retry_ms: delay.as_millis() as u64,
                        message: error.to_string(),
                    });
                    let newer_event = tokio::select! {
                        _ = tokio::time::sleep(delay) => false,
                        received = rx.recv() => !matches!(
                            received,
                            Err(broadcast::error::RecvError::Closed)
                        ),
                    };
                    if newer_event {
                        return false;
                    }
                    delay = (delay * 2).min(BACKOFF_MAX);
                }
            }
        }
    }

    fn rescan_allowed(&self) -> bool {
        match self.last_rescan {
            None => true,
            Some(at) => at.elapsed() >= RECOVERY_RESCAN_MIN_INTERVAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use zerodpi_core::net::NetworkChangeSource;

    use super::*;

    struct FakeEnv {
        probe_result: Mutex<anyhow::Result<Ipv4Addr>>,
        probe_calls: AtomicUsize,
        fail_rebuilds: AtomicUsize,
        rebuilds: Mutex<Vec<Ipv4Addr>>,
        verify_ok: AtomicBool,
        rescans: AtomicUsize,
        rescan_switched: AtomicBool,
        statuses: Mutex<Vec<NetworkStatus>>,
        applied: Mutex<Vec<Ipv4Addr>>,
        disconnected: AtomicBool,
    }

    impl FakeEnv {
        fn arc() -> Arc<Self> {
            Arc::new(Self {
                probe_result: Mutex::new(Ok(Ipv4Addr::new(10, 0, 0, 2))),
                probe_calls: AtomicUsize::new(0),
                fail_rebuilds: AtomicUsize::new(0),
                rebuilds: Mutex::new(Vec::new()),
                verify_ok: AtomicBool::new(true),
                rescans: AtomicUsize::new(0),
                rescan_switched: AtomicBool::new(false),
                statuses: Mutex::new(Vec::new()),
                applied: Mutex::new(Vec::new()),
                disconnected: AtomicBool::new(false),
            })
        }

        fn statuses(&self) -> Vec<NetworkStatus> {
            self.statuses.lock().unwrap().clone()
        }
    }

    impl RecoveryEnv for FakeEnv {
        fn probe(&self, _target: Ipv4Addr) -> anyhow::Result<Ipv4Addr> {
            self.probe_calls.fetch_add(1, Ordering::SeqCst);
            match &*self.probe_result.lock().unwrap() {
                Ok(ip) => Ok(*ip),
                Err(error) => Err(anyhow::anyhow!("{error}")),
            }
        }

        fn rebuild<'a>(&'a self, interface_ip: Ipv4Addr) -> BoxFuture<'a, anyhow::Result<()>> {
            Box::pin(async move {
                self.rebuilds.lock().unwrap().push(interface_ip);
                if self.fail_rebuilds.load(Ordering::SeqCst) > 0 {
                    self.fail_rebuilds.fetch_sub(1, Ordering::SeqCst);
                    anyhow::bail!("rebuild failed");
                }
                Ok(())
            })
        }

        fn verify<'a>(&'a self) -> BoxFuture<'a, bool> {
            Box::pin(async move { self.verify_ok.load(Ordering::SeqCst) })
        }

        fn rescan<'a>(&'a self) -> BoxFuture<'a, RescanOutcome> {
            Box::pin(async move {
                self.rescans.fetch_add(1, Ordering::SeqCst);
                RescanOutcome {
                    found: 1,
                    switched: self.rescan_switched.load(Ordering::SeqCst),
                }
            })
        }

        fn apply_interface_ip(&self, interface_ip: Ipv4Addr) {
            self.applied.lock().unwrap().push(interface_ip);
        }

        fn remote_disconnected(&self) -> bool {
            self.disconnected.load(Ordering::SeqCst)
        }

        fn publish(&self, status: NetworkStatus) {
            self.statuses.lock().unwrap().push(status);
        }
    }

    fn event() -> NetworkEvent {
        NetworkEvent::Changed {
            source: NetworkChangeSource::Address,
        }
    }

    fn probe_target() -> Arc<AtomicU32> {
        Arc::new(AtomicU32::new(u32::from(Ipv4Addr::new(1, 1, 1, 1))))
    }

    async fn run_once(
        coordinator: &mut RecoveryCoordinator<FakeEnv>,
        rx: &mut broadcast::Receiver<NetworkEvent>,
    ) {
        coordinator
            .handle_change(NetworkChangeSource::Address, rx)
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn rebuilds_when_interface_changes() {
        let env = FakeEnv::arc();
        let mut rx = broadcast::channel(8).1;
        let mut coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(&mut coordinator, &mut rx).await;
        assert_eq!(
            env.rebuilds.lock().unwrap().as_slice(),
            &[Ipv4Addr::new(10, 0, 0, 2)]
        );
        assert_eq!(
            env.applied.lock().unwrap().as_slice(),
            &[Ipv4Addr::new(10, 0, 0, 2)]
        );
        assert!(env.statuses().iter().any(|status| matches!(
            status,
            NetworkStatus::Recovered {
                target_verified: true,
                target_switched: false,
                ..
            }
        )));
    }

    #[tokio::test(start_paused = true)]
    async fn ignores_unchanged_address() {
        let env = FakeEnv::arc();
        *env.probe_result.lock().unwrap() = Ok(Ipv4Addr::new(10, 0, 0, 1));
        let mut rx = broadcast::channel(8).1;
        let mut coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(&mut coordinator, &mut rx).await;
        assert!(env.rebuilds.lock().unwrap().is_empty());
        assert!(matches!(
            env.statuses().last(),
            Some(NetworkStatus::Online { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn marks_unavailable_when_probe_fails() {
        let env = FakeEnv::arc();
        *env.probe_result.lock().unwrap() = Err(anyhow::anyhow!("no route"));
        let mut rx = broadcast::channel(8).1;
        let mut coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(&mut coordinator, &mut rx).await;
        assert!(env.rebuilds.lock().unwrap().is_empty());
        assert!(matches!(
            env.statuses().last(),
            Some(NetworkStatus::Unavailable { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn retries_rebuild_with_backoff_until_success() {
        let env = FakeEnv::arc();
        env.fail_rebuilds.store(2, Ordering::SeqCst);
        let mut rx = broadcast::channel(8).1;
        let mut coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(&mut coordinator, &mut rx).await;
        assert_eq!(env.rebuilds.lock().unwrap().len(), 3);
        let retries: Vec<u64> = env
            .statuses()
            .iter()
            .filter_map(|status| match status {
                NetworkStatus::Recovering { next_retry_ms, .. } => Some(*next_retry_ms),
                _ => None,
            })
            .collect();
        assert_eq!(retries, vec![1_000, 2_000]);
        assert!(env
            .statuses()
            .iter()
            .any(|status| matches!(status, NetworkStatus::Recovered { .. })));
    }

    #[tokio::test(start_paused = true)]
    async fn rescan_is_gated_and_rate_limited() {
        let env = FakeEnv::arc();
        env.verify_ok.store(false, Ordering::SeqCst);
        let mut rx = broadcast::channel(8).1;
        let mut coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(&mut coordinator, &mut rx).await;
        assert_eq!(env.rescans.load(Ordering::SeqCst), 1);

        *env.probe_result.lock().unwrap() = Ok(Ipv4Addr::new(10, 0, 0, 3));
        run_once(&mut coordinator, &mut rx).await;
        assert_eq!(
            env.rescans.load(Ordering::SeqCst),
            1,
            "rate limit must hold"
        );

        let env = FakeEnv::arc();
        env.verify_ok.store(false, Ordering::SeqCst);
        let mut rx = broadcast::channel(8).1;
        let mut coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            false,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(&mut coordinator, &mut rx).await;
        assert_eq!(
            env.rescans.load(Ordering::SeqCst),
            0,
            "pinned mode never scans"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_event_resets_the_backoff() {
        let env = FakeEnv::arc();
        env.fail_rebuilds.store(10, Ordering::SeqCst);
        let (tx, mut rx) = broadcast::channel(8);
        let mut coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        tokio::spawn(async move {
            coordinator
                .handle_change(NetworkChangeSource::Address, &mut rx)
                .await;
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(500)).await;
        tx.send(event()).unwrap();
        tokio::task::yield_now().await;
        assert!(env.rebuilds.lock().unwrap().len() >= 2);
        let last_retry = env
            .statuses()
            .iter()
            .rev()
            .find_map(|status| match status {
                NetworkStatus::Recovering { next_retry_ms, .. } => Some(*next_retry_ms),
                _ => None,
            })
            .expect("retry status");
        assert_eq!(last_retry, 1_000, "backoff must reset after a new event");
    }

    #[tokio::test(start_paused = true)]
    async fn a_disconnected_helper_stops_recovery() {
        let env = FakeEnv::arc();
        env.disconnected.store(true, Ordering::SeqCst);
        let mut rx = broadcast::channel(8).1;
        let mut coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(&mut coordinator, &mut rx).await;
        assert!(env.rebuilds.lock().unwrap().is_empty());
        assert!(matches!(
            env.statuses().last(),
            Some(NetworkStatus::Unavailable { .. })
        ));
    }
}
