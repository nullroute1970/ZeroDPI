//! TCP latency sampling, scoped to the lifetime of its proxy listener.
use super::*;
use crate::config::Config;
use crate::net::{InterfaceBindingWatch, OutboundNetwork, OutboundSocketBinder};
use std::future::Future;
use tokio::task::{JoinHandle, JoinSet};

pub struct PingMonitor(JoinHandle<()>);

impl Drop for PingMonitor {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub fn start(
    cfg: &Config,
    pool: TargetPool,
    binding: InterfaceBindingWatch,
    binder: Arc<dyn OutboundSocketBinder>,
) -> Option<PingMonitor> {
    if !cfg.LOAD_BALANCE_ENABLED
        || cfg.LOAD_BALANCE_STRATEGY != SelectionStrategy::LeastPing
        || !matches!(
            cfg.MODE.as_str(),
            "sni_spoof" | "ip_bypass" | "ip_bypass_plus"
        )
    {
        return None;
    }
    let limit = if cfg.MODE == "sni_spoof" {
        cfg.SNI_MAX_CONCURRENT
    } else {
        cfg.IP_MAX_P1_CONCURRENT
    };
    Some(PingMonitor(tokio::spawn(monitor(
        pool,
        binding,
        binder,
        Duration::from_secs(cfg.LOAD_BALANCE_PING_INTERVAL_SECS),
        Duration::from_secs(cfg.SCAN_TIMEOUT_SECS),
        limit,
        |target, network| async move {
            let started = tokio::time::Instant::now();
            network
                .connect(std::net::SocketAddr::new(target.ip, 443))
                .await
                .ok()
                .map(|_stream| started.elapsed())
        },
    ))))
}

async fn monitor<P, F>(
    pool: TargetPool,
    binding: InterfaceBindingWatch,
    binder: Arc<dyn OutboundSocketBinder>,
    interval: Duration,
    timeout: Duration,
    limit: usize,
    probe: P,
) where
    P: Fn(Target, OutboundNetwork) -> F + Clone + Send + 'static,
    F: Future<Output = Option<Duration>> + Send + 'static,
{
    loop {
        let (generation, targets) = pool.probe_snapshot();
        let mut round_binding = binding.clone();
        let current = round_binding.mark_current();
        let network = OutboundNetwork::new(current, binder.clone());
        let mut remaining = targets.into_iter();
        let mut tasks = JoinSet::new();
        loop {
            while tasks.len() < limit.max(1) {
                let Some(target) = remaining.next() else {
                    break;
                };
                let probe = probe.clone();
                let network = network.clone();
                tasks.spawn(async move {
                    let ping = tokio::time::timeout(timeout, probe(target.clone(), network))
                        .await
                        .ok()
                        .flatten();
                    (target, ping)
                });
            }
            match tasks.join_next().await {
                Some(Ok((target, ping))) => {
                    if let Some(_binding_guard) = round_binding.unchanged() {
                        pool.update_ping(generation, &target, ping);
                    }
                }
                Some(_) => {}
                None => break,
            }
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{interface_binding_channel, InterfaceBinding, NoopSocketBinder};
    use std::net::Ipv4Addr;

    struct InFlight(Arc<AtomicUsize>);
    impl Drop for InFlight {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timeouts_bound_concurrency_and_rounds_do_not_overlap() {
        let targets: Vec<_> = (1..=5)
            .map(|n| {
                let mut target = Target::ip(Ipv4Addr::new(192, 0, 2, n).into(), 90);
                target.tcp_latency = Some(Duration::from_millis(1));
                target
            })
            .collect();
        let pool = TargetPool::new(SelectionStrategy::LeastPing, targets).unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (probe_active, probe_calls, probe_peak) = (active.clone(), calls.clone(), peak.clone());
        let (_, binding) = interface_binding_channel(InterfaceBinding::fixed(Ipv4Addr::LOCALHOST));
        let monitor = PingMonitor(tokio::spawn(monitor(
            pool.clone(),
            binding,
            Arc::new(NoopSocketBinder),
            Duration::from_secs(60),
            Duration::from_secs(5),
            2,
            move |_, _| {
                let (active, calls, peak) = (
                    probe_active.clone(),
                    probe_calls.clone(),
                    probe_peak.clone(),
                );
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    peak.fetch_max(active.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                    let _guard = InFlight(active);
                    std::future::pending::<Option<Duration>>().await
                }
            },
        )));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        for expected_calls in [4, 5, 5] {
            tokio::time::advance(Duration::from_secs(5)).await;
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
        }
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert_ne!(pool.acquire().target.ip, pool.acquire().target.ip);
        tokio::time::advance(Duration::from_secs(59)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(active.load(Ordering::SeqCst), 2);
        drop(monitor);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "listener cancellation must abort probes"
        );
        assert_eq!(pool.active_connections(), 0);
    }

    #[tokio::test]
    async fn results_from_a_previous_network_revision_are_discarded() {
        let mut first = Target::ip(Ipv4Addr::new(192, 0, 2, 1).into(), 90);
        first.tcp_latency = Some(Duration::from_millis(30));
        let mut second = Target::ip(Ipv4Addr::new(192, 0, 2, 2).into(), 80);
        second.tcp_latency = Some(Duration::from_millis(10));
        let pool = TargetPool::new(
            SelectionStrategy::LeastPing,
            vec![first.clone(), second.clone()],
        )
        .unwrap();
        let initial = InterfaceBinding::fixed(Ipv4Addr::LOCALHOST);
        let (handle, binding) = interface_binding_channel(initial.clone());
        let (requests, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let monitor = PingMonitor(tokio::spawn(monitor(
            pool.clone(),
            binding,
            Arc::new(NoopSocketBinder),
            Duration::from_secs(60),
            Duration::from_secs(5),
            2,
            move |target, _| {
                let (tx, rx) = tokio::sync::oneshot::channel();
                requests.send((target, tx)).unwrap();
                async move { rx.await.unwrap() }
            },
        )));
        let a = rx.recv().await.unwrap();
        let b = rx.recv().await.unwrap();
        // Even switching back to the same IP must not make an old probe fresh.
        handle.set(InterfaceBinding::fixed(Ipv4Addr::new(192, 0, 2, 100)));
        handle.set(initial);
        drop(handle);
        for (target, reply) in [a, b] {
            reply
                .send(if target.ip == first.ip {
                    Some(Duration::ZERO)
                } else {
                    None
                })
                .unwrap();
        }
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(pool.acquire().target.ip, second.ip);
        drop(monitor);
    }

    #[test]
    fn sampler_is_disabled_for_legacy_routing_and_scan_only_modes() {
        let mut cfg = crate::config::test_support::minimal_config();
        let pool = TargetPool::single(Target::ip(Ipv4Addr::LOCALHOST.into(), 90));
        let binding = InterfaceBindingWatch::fixed(InterfaceBinding::fixed(Ipv4Addr::LOCALHOST));
        cfg.LOAD_BALANCE_STRATEGY = SelectionStrategy::LeastPing;
        assert!(start(
            &cfg,
            pool.clone(),
            binding.clone(),
            Arc::new(NoopSocketBinder)
        )
        .is_none());
        cfg.LOAD_BALANCE_ENABLED = true;
        for mode in [
            "sni_scan",
            "ip_scan",
            "proxy_scan",
            "sni_method_scan",
            "ip_method_scan",
        ] {
            cfg.MODE = mode.into();
            assert!(start(
                &cfg,
                pool.clone(),
                binding.clone(),
                Arc::new(NoopSocketBinder)
            )
            .is_none());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn probes_immediately_then_waits_sixty_seconds_and_recovers() {
        let mut first = Target::ip(Ipv4Addr::new(192, 0, 2, 1).into(), 90);
        first.tcp_latency = Some(Duration::from_millis(5));
        let mut second = Target::ip(Ipv4Addr::new(192, 0, 2, 2).into(), 80);
        second.tcp_latency = Some(Duration::from_millis(10));
        let pool = TargetPool::new(
            SelectionStrategy::LeastPing,
            vec![first.clone(), second.clone()],
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let monitor_pool = pool.clone();
        let (_handle, binding) =
            interface_binding_channel(InterfaceBinding::fixed(Ipv4Addr::LOCALHOST));
        let task = tokio::spawn(monitor(
            monitor_pool,
            binding,
            Arc::new(NoopSocketBinder),
            Duration::from_secs(60),
            Duration::from_secs(5),
            1,
            move |target, _network| {
                let round = observed.fetch_add(1, Ordering::SeqCst) / 2;
                async move {
                    if round == 0 && target.ip == first.ip {
                        None
                    } else {
                        Some(Duration::from_millis(if target.ip == first.ip {
                            1
                        } else {
                            20
                        }))
                    }
                }
            },
        ));
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(pool.acquire().target.ip, second.ip);
        tokio::time::advance(Duration::from_secs(59)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(pool.acquire().target.ip, first.ip);
        assert_eq!(pool.active_connections(), 0);
        task.abort();
    }
}
