//! In-place network recovery policy.
//!
//! The coordinator reacts to settled network changes, rebuilds the data plane
//! with the new interface address, verifies the active target, and only then
//! asks for a rescan when the selection policy allows it.

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;

use zerodpi_core::net::{InterfaceBinding, NetworkChangeSource};
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
    /// Probe the physical outbound binding for `target`.
    fn probe(&self, target: Ipv4Addr) -> anyhow::Result<InterfaceBinding>;
    fn rebuild<'a>(&'a self, binding: InterfaceBinding) -> BoxFuture<'a, anyhow::Result<()>>;
    fn verify<'a>(&'a self) -> BoxFuture<'a, bool>;
    fn rescan<'a>(&'a self) -> BoxFuture<'a, RescanOutcome>;
    fn apply_interface_binding(&self, binding: InterfaceBinding);
    fn remote_disconnected(&self) -> bool {
        false
    }
    fn publish(&self, status: NetworkStatus);
}

pub struct RecoveryCoordinator<E: RecoveryEnv> {
    env: Arc<E>,
    probe_target: Arc<AtomicU32>,
    auto_select: bool,
    current: Option<InterfaceBinding>,
    last_rescan: Option<tokio::time::Instant>,
}

impl<E: RecoveryEnv> RecoveryCoordinator<E> {
    pub fn new(
        env: Arc<E>,
        probe_target: Arc<AtomicU32>,
        auto_select: bool,
        initial: Option<InterfaceBinding>,
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
        if let Some(binding) = &self.current {
            self.env.publish(NetworkStatus::Online {
                interface_ip: binding.ip,
            });
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
                Ok(binding) if self.current.as_ref() == Some(&binding) => {
                    self.env.publish(NetworkStatus::Online {
                        interface_ip: binding.ip,
                    });
                    return;
                }
                Ok(binding) => {
                    self.env.publish(NetworkStatus::Changing {
                        interface_ip: binding.ip,
                        source,
                    });
                    if !self.rebuild_with_retry(binding.clone(), rx).await {
                        continue;
                    }
                    self.current = Some(binding.clone());
                    self.env.apply_interface_binding(binding.clone());
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
                        interface_ip: binding.ip,
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
        binding: InterfaceBinding,
        rx: &mut broadcast::Receiver<NetworkEvent>,
    ) -> bool {
        let mut delay = BACKOFF_INITIAL;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match self.env.rebuild(binding.clone()).await {
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

use zerodpi_core::net::InterfaceBindingHandle;
use zerodpi_core::proxy::{NetworkStatus as ProxyNetworkStatus, ProxyEvent, ProxyEventSender};

use crate::data_plane::DataPlane;
use crate::runtime_events::{RuntimeEvent, RuntimeEventEmitter};

/// Runtime event for a status, when the contract defines one.
pub(crate) fn runtime_event_for(status: &NetworkStatus) -> Option<RuntimeEvent> {
    match status {
        NetworkStatus::Online { .. } => None,
        NetworkStatus::Unavailable { message } => Some(RuntimeEvent::NetworkUnavailable {
            message: message.clone(),
        }),
        NetworkStatus::Changing {
            interface_ip,
            source,
        } => Some(RuntimeEvent::NetworkChanged {
            source: *source,
            interface_ip: interface_ip.to_string(),
        }),
        NetworkStatus::Recovering {
            attempt,
            next_retry_ms,
            message,
        } => Some(RuntimeEvent::NetworkRecoveryFailed {
            attempt: *attempt,
            next_retry_ms: *next_retry_ms,
            message: message.clone(),
        }),
        NetworkStatus::Recovered {
            interface_ip,
            target_verified,
            target_switched,
        } => Some(RuntimeEvent::NetworkRecovered {
            interface_ip: interface_ip.to_string(),
            target_verified: *target_verified,
            target_switched: *target_switched,
        }),
    }
}

/// Dashboard event for a status.
pub(crate) fn proxy_status_for(status: &NetworkStatus) -> Option<ProxyNetworkStatus> {
    match status {
        NetworkStatus::Online { interface_ip } => Some(ProxyNetworkStatus::Online {
            interface_ip: *interface_ip,
        }),
        NetworkStatus::Unavailable { message } => Some(ProxyNetworkStatus::Unavailable {
            message: message.clone(),
        }),
        NetworkStatus::Changing { interface_ip, .. } => Some(ProxyNetworkStatus::Changing {
            interface_ip: *interface_ip,
        }),
        NetworkStatus::Recovering { attempt, .. } => {
            Some(ProxyNetworkStatus::Recovering { attempt: *attempt })
        }
        NetworkStatus::Recovered { interface_ip, .. } => Some(ProxyNetworkStatus::Online {
            interface_ip: *interface_ip,
        }),
    }
}

/// Callbacks the running mode supplies to recovery.
pub struct RecoveryCallbacks {
    pub verify: Arc<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync>,
    pub rescan: Arc<dyn Fn() -> BoxFuture<'static, RescanOutcome> + Send + Sync>,
}

/// Concrete [`RecoveryEnv`] used by the CLI.
pub struct MainRecoveryEnv {
    interface_binding_handle: InterfaceBindingHandle,
    data_plane: Arc<dyn DataPlane>,
    callbacks: RecoveryCallbacks,
    events: RuntimeEventEmitter,
    proxy_events: Option<ProxyEventSender>,
}

impl MainRecoveryEnv {
    pub fn new(
        interface_binding_handle: InterfaceBindingHandle,
        data_plane: Arc<dyn DataPlane>,
        callbacks: RecoveryCallbacks,
        events: RuntimeEventEmitter,
        proxy_events: Option<ProxyEventSender>,
    ) -> Self {
        Self {
            interface_binding_handle,
            data_plane,
            callbacks,
            events,
            proxy_events,
        }
    }
}

impl RecoveryEnv for MainRecoveryEnv {
    fn probe(&self, target: Ipv4Addr) -> anyhow::Result<InterfaceBinding> {
        zerodpi_platform::uplink::resolve_physical_binding(target)
    }

    fn rebuild<'a>(&'a self, binding: InterfaceBinding) -> BoxFuture<'a, anyhow::Result<()>> {
        self.data_plane.rebuild(binding)
    }

    fn verify<'a>(&'a self) -> BoxFuture<'a, bool> {
        (self.callbacks.verify)()
    }

    fn rescan<'a>(&'a self) -> BoxFuture<'a, RescanOutcome> {
        (self.callbacks.rescan)()
    }

    fn apply_interface_binding(&self, binding: InterfaceBinding) {
        self.interface_binding_handle.set(binding);
    }

    fn remote_disconnected(&self) -> bool {
        self.data_plane.remote_disconnected()
    }

    fn publish(&self, status: NetworkStatus) {
        if let Some(event) = runtime_event_for(&status) {
            self.events.emit(event);
        }
        if let (Some(tx), Some(proxy_status)) = (&self.proxy_events, proxy_status_for(&status)) {
            let _ = tx.send(ProxyEvent::NetworkStatus {
                status: proxy_status,
            });
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
        probe_result: Mutex<anyhow::Result<InterfaceBinding>>,
        probe_calls: AtomicUsize,
        fail_rebuilds: AtomicUsize,
        rebuilds: Mutex<Vec<InterfaceBinding>>,
        verify_ok: AtomicBool,
        rescans: AtomicUsize,
        rescan_switched: AtomicBool,
        statuses: Mutex<Vec<NetworkStatus>>,
        applied: Mutex<Vec<InterfaceBinding>>,
        disconnected: AtomicBool,
    }

    impl FakeEnv {
        fn arc() -> Arc<Self> {
            Arc::new(Self {
                probe_result: Mutex::new(Ok(binding(Ipv4Addr::new(10, 0, 0, 2), 2))),
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
        fn probe(&self, _target: Ipv4Addr) -> anyhow::Result<InterfaceBinding> {
            self.probe_calls.fetch_add(1, Ordering::SeqCst);
            match &*self.probe_result.lock().unwrap() {
                Ok(binding) => Ok(binding.clone()),
                Err(error) => Err(anyhow::anyhow!("{error}")),
            }
        }

        fn rebuild<'a>(&'a self, binding: InterfaceBinding) -> BoxFuture<'a, anyhow::Result<()>> {
            Box::pin(async move {
                self.rebuilds.lock().unwrap().push(binding);
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

        fn apply_interface_binding(&self, binding: InterfaceBinding) {
            self.applied.lock().unwrap().push(binding);
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

    fn binding(ip: Ipv4Addr, if_index: u32) -> InterfaceBinding {
        InterfaceBinding::new(ip, if_index, format!("if{if_index}"))
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
            Some(binding(Ipv4Addr::new(10, 0, 0, 1), 1)),
        );
        run_once(&mut coordinator, &mut rx).await;
        assert_eq!(
            env.rebuilds.lock().unwrap().as_slice(),
            &[binding(Ipv4Addr::new(10, 0, 0, 2), 2)]
        );
        assert_eq!(
            env.applied.lock().unwrap().as_slice(),
            &[binding(Ipv4Addr::new(10, 0, 0, 2), 2)]
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
        *env.probe_result.lock().unwrap() = Ok(binding(Ipv4Addr::new(10, 0, 0, 1), 1));
        let mut rx = broadcast::channel(8).1;
        let mut coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(binding(Ipv4Addr::new(10, 0, 0, 1), 1)),
        );
        run_once(&mut coordinator, &mut rx).await;
        assert!(env.rebuilds.lock().unwrap().is_empty());
        assert!(matches!(
            env.statuses().last(),
            Some(NetworkStatus::Online { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn rebuilds_when_same_address_moves_to_another_interface() {
        let env = FakeEnv::arc();
        *env.probe_result.lock().unwrap() = Ok(binding(Ipv4Addr::new(10, 0, 0, 1), 2));
        let mut rx = broadcast::channel(8).1;
        let mut coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(binding(Ipv4Addr::new(10, 0, 0, 1), 1)),
        );

        run_once(&mut coordinator, &mut rx).await;

        assert_eq!(
            env.rebuilds.lock().unwrap().as_slice(),
            &[binding(Ipv4Addr::new(10, 0, 0, 1), 2)]
        );
        assert_eq!(
            env.applied.lock().unwrap().as_slice(),
            &[binding(Ipv4Addr::new(10, 0, 0, 1), 2)]
        );
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
            Some(binding(Ipv4Addr::new(10, 0, 0, 1), 1)),
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
            Some(binding(Ipv4Addr::new(10, 0, 0, 1), 1)),
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
            Some(binding(Ipv4Addr::new(10, 0, 0, 1), 1)),
        );
        run_once(&mut coordinator, &mut rx).await;
        assert_eq!(env.rescans.load(Ordering::SeqCst), 1);

        *env.probe_result.lock().unwrap() = Ok(binding(Ipv4Addr::new(10, 0, 0, 3), 3));
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
            Some(binding(Ipv4Addr::new(10, 0, 0, 1), 1)),
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
            Some(binding(Ipv4Addr::new(10, 0, 0, 1), 1)),
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
            Some(binding(Ipv4Addr::new(10, 0, 0, 1), 1)),
        );
        run_once(&mut coordinator, &mut rx).await;
        assert!(env.rebuilds.lock().unwrap().is_empty());
        assert!(matches!(
            env.statuses().last(),
            Some(NetworkStatus::Unavailable { .. })
        ));
    }
    #[test]
    fn maps_changing_status_to_network_changed_event() {
        let status = NetworkStatus::Changing {
            interface_ip: Ipv4Addr::new(192, 0, 2, 10),
            source: NetworkChangeSource::Route,
        };
        let event = runtime_event_for(&status).expect("runtime event");
        assert!(matches!(
            event,
            crate::runtime_events::RuntimeEvent::NetworkChanged {
                interface_ip,
                ..
            } if interface_ip == "192.0.2.10"
        ));
        assert!(proxy_status_for(&status).is_some());
    }

    #[test]
    fn maps_recovered_status_to_runtime_and_proxy_events() {
        let status = NetworkStatus::Recovered {
            interface_ip: Ipv4Addr::new(192, 0, 2, 10),
            target_verified: false,
            target_switched: true,
        };
        assert!(matches!(
            runtime_event_for(&status),
            Some(crate::runtime_events::RuntimeEvent::NetworkRecovered {
                target_switched: true,
                ..
            })
        ));
        assert!(proxy_status_for(&status).is_some());
    }

    #[test]
    fn online_status_has_no_runtime_event() {
        let status = NetworkStatus::Online {
            interface_ip: Ipv4Addr::LOCALHOST,
        };
        assert!(runtime_event_for(&status).is_none());
        assert!(proxy_status_for(&status).is_some());
    }
}
