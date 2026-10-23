use super::*;
use crate::flow::FlowRegistrationFuture;
use crate::net::NoopSocketBinder;
use tokio::sync::mpsc;

type Registration = (FlowKey, Vec<u8>, Option<u8>);

struct CompletingController(mpsc::UnboundedSender<Registration>);

impl FlowController for CompletingController {
    fn register_flow(
        &self,
        key: FlowKey,
        data: Vec<u8>,
        ttl: Option<u8>,
    ) -> FlowRegistrationFuture<'_> {
        Box::pin(async move {
            self.0.send((key, data.clone(), ttl)).unwrap();
            let entry = FlowEntry::new(data, ttl);
            // Replace only the packet interceptor. The listener, outbound TCP
            // connection, bypass worker, reservations and relay are all real.
            entry.finish(BypassOutcome::FakeDataAcked);
            Ok(entry)
        })
    }
    fn flow_exists(&self, _: FlowKey) -> bool {
        false
    }
    fn remove_flow(&self, _: FlowKey) {}
    fn reset(&self) {}
}

async fn echo(listener: TcpListener, id: u8) {
    let mut workers = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut stream, _) = accepted.unwrap();
                workers.spawn(async move {
                    let mut byte = [0];
                    while stream.read_exact(&mut byte).await.is_ok() {
                        if stream.write_all(&[id, byte[0]]).await.is_err() { break; }
                    }
                });
            }
            Some(_) = workers.join_next(), if !workers.is_empty() => {}
        }
    }
}

async fn exchange(client: &mut TcpStream, id: u8, byte: u8) {
    client.write_all(&[byte]).await.unwrap();
    let mut response = [0; 2];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [id, byte]);
}

#[tokio::test]
async fn listeners_distribute_connections_keep_existing_relays_and_release_load() {
    for (mode, method) in [
        (0, "wrong_seq"),
        (0, "tls_frag"),
        (1, "wrong_seq"),
        (2, "tls_record_frag"),
        (2, "tls_frag"),
    ] {
        let ip1 = Ipv4Addr::LOCALHOST;
        let ip2 = Ipv4Addr::new(127, 0, 0, 2);
        let first = TcpListener::bind((ip1, 0)).await.unwrap();
        let port = first.local_addr().unwrap().port();
        let second = TcpListener::bind((ip2, port)).await.unwrap();
        let server1 = tokio::spawn(echo(first, 1));
        let server2 = tokio::spawn(echo(second, 2));
        let mut cfg = crate::config::test_support::minimal_config();
        cfg.LISTEN_HOST = ip1.to_string();
        cfg.LISTEN_PORT = 0;
        cfg.LOAD_BALANCE_ENABLED = true;
        cfg.BYPASS_METHOD = method.into();
        cfg.TLS_FRAG_PACKETS = "9-9".into();
        cfg.MODE = match mode {
            0 => "sni_spoof",
            1 => "ip_bypass",
            _ => "ip_bypass_plus",
        }
        .into();
        let mut t1 = if mode == 0 {
            Target::sni("first.example", ip1, 90)
        } else {
            Target::ip(ip1.into(), 90)
        };
        let mut t2 = if mode == 0 {
            Target::sni("second.example", ip2, 80)
        } else {
            Target::ip(ip2.into(), 80)
        };
        t1.low_ttl = Some(5);
        t2.low_ttl = Some(9);
        let pool = TargetPool::new(SelectionStrategy::RoundRobin, vec![t1, t2.clone()]).unwrap();
        let worker_pool = pool.clone();
        let cfg = Arc::new(cfg);
        let binding = InterfaceBindingWatch::fixed(InterfaceBinding::fixed(ip1));
        let binder = Arc::new(NoopSocketBinder);
        let (registrations, mut registration_rx) = mpsc::unbounded_channel();
        let controller = Arc::new(CompletingController(registrations));
        let (events, mut event_rx) = proxy_event_channel(false);
        let task = tokio::spawn(async move {
            match mode {
                0 => {
                    run_proxy_on_port(
                        cfg,
                        worker_pool,
                        binding,
                        binder,
                        controller,
                        Some(events),
                        port,
                    )
                    .await
                }
                1 => {
                    run_ip_bypass_proxy_on_port(
                        cfg,
                        worker_pool,
                        binding,
                        binder,
                        Some(events),
                        port,
                    )
                    .await
                }
                _ => {
                    run_ip_bypass_plus_proxy_on_port(
                        cfg,
                        worker_pool,
                        binding,
                        binder,
                        controller,
                        Some(events),
                        port,
                    )
                    .await
                }
            }
        });
        let Some(ProxyEvent::ListenerStarted { listen_addr, .. }) = event_rx.recv().await else {
            panic!("listener not ready");
        };
        let mut client1 = TcpStream::connect(listen_addr).await.unwrap();
        exchange(&mut client1, 1, 11).await;
        let mut client2 = TcpStream::connect(listen_addr).await.unwrap();
        exchange(&mut client2, 2, 22).await;
        assert_eq!(pool.active_connections(), 2);
        t2.low_ttl = Some(12);
        pool.replace(vec![t2]);
        let mut client3 = TcpStream::connect(listen_addr).await.unwrap();
        exchange(&mut client3, 2, 33).await;
        exchange(&mut client1, 1, 44).await;
        assert_eq!(pool.active_connections(), 3);
        let snapshot = pool.snapshot();
        let old = snapshot
            .targets
            .iter()
            .find(|t| t.target.ip == IpAddr::V4(ip1))
            .unwrap();
        let current = &snapshot.targets[0];
        assert_eq!((old.c2s_bytes, old.s2c_bytes), (2, 4));
        assert_eq!((current.c2s_bytes, current.s2c_bytes), (2, 4));
        assert_eq!(old.active_connections, 1);
        assert_eq!(current.active_connections, 2);
        let mut accepted = Vec::new();
        while let Ok(event) = event_rx.try_recv() {
            if let ProxyEvent::ConnectionAccepted {
                target_ip,
                target_sni,
                ..
            } = event
            {
                accepted.push((target_ip, target_sni));
            }
        }
        assert_eq!(accepted.len(), 3);
        for ((ip, sni), (expected_ip, expected_sni)) in accepted.iter().zip([
            (ip1, "first.example"),
            (ip2, "second.example"),
            (ip2, "second.example"),
        ]) {
            assert_eq!(*ip, IpAddr::V4(expected_ip));
            assert_eq!(sni.as_deref(), (mode == 0).then_some(expected_sni));
        }
        if !method.eq("tls_frag") && mode != 1 {
            for (expected_ip, expected_ttl, expected_sni) in [
                (ip1, 5, "first.example"),
                (ip2, 9, "second.example"),
                (ip2, 12, "second.example"),
            ] {
                let (key, data, ttl) = registration_rx.recv().await.unwrap();
                assert_eq!(key.dst_ip, expected_ip);
                assert_eq!(key.dst_port, port);
                assert_eq!(ttl, Some(expected_ttl));
                if mode == 0 {
                    assert!(data
                        .windows(expected_sni.len())
                        .any(|bytes| bytes == expected_sni.as_bytes()));
                } else {
                    assert!(data.is_empty());
                }
            }
        }
        drop((client1, client2, client3));
        tokio::time::timeout(Duration::from_secs(2), async {
            while pool.active_connections() > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let snapshot = pool.snapshot();
        assert!(snapshot.targets.iter().all(|t| t.active_connections == 0));
        assert_eq!(snapshot.targets.iter().map(|t| t.c2s_bytes).sum::<u64>(), 4);
        task.abort();
        let _ = task.await;
        server1.abort();
        server2.abort();
        let _ = tokio::join!(server1, server2);
    }
}

#[tokio::test]
async fn connect_errors_release_reservations_without_retrying() {
    let unused = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    let mut cfg = crate::config::test_support::minimal_config();
    cfg.LISTEN_HOST = Ipv4Addr::LOCALHOST.to_string();
    cfg.LISTEN_PORT = 0;
    let pool = TargetPool::new(
        SelectionStrategy::RoundRobin,
        vec![
            Target::ip(Ipv4Addr::LOCALHOST.into(), 90),
            Target::ip(Ipv4Addr::new(127, 0, 0, 2).into(), 80),
        ],
    )
    .unwrap();
    let (tx, mut rx) = proxy_event_channel(false);
    let task = tokio::spawn(run_ip_bypass_proxy_on_port(
        Arc::new(cfg),
        pool.clone(),
        InterfaceBindingWatch::fixed(InterfaceBinding::fixed(Ipv4Addr::LOCALHOST)),
        Arc::new(NoopSocketBinder),
        Some(tx),
        port,
    ));
    let Some(ProxyEvent::ListenerStarted { listen_addr, .. }) = rx.recv().await else {
        panic!("no listener");
    };
    let _client = TcpStream::connect(listen_addr).await.unwrap();
    let Some(ProxyEvent::ConnectionAccepted { target_ip, .. }) = rx.recv().await else {
        panic!("no accepted connection");
    };
    assert_eq!(target_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap(),
        Some(ProxyEvent::ConnectionError { .. })
    ));
    tokio::task::yield_now().await;
    assert_eq!(pool.active_connections(), 0);
    assert!(pool
        .snapshot()
        .targets
        .iter()
        .all(|target| target.c2s_bytes == 0 && target.s2c_bytes == 0));
    assert!(rx.try_recv().is_err());
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn concurrent_sni_targets_on_the_same_ip_have_separate_connection_metadata_and_traffic() {
    let ip = Ipv4Addr::LOCALHOST;
    let listener = TcpListener::bind((ip, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(echo(listener, 1));
    let pool = TargetPool::new(
        SelectionStrategy::RoundRobin,
        vec![
            Target::sni("first.example", ip, 90),
            Target::sni("second.example", ip, 80),
        ],
    )
    .unwrap();
    let mut cfg = crate::config::test_support::minimal_config();
    cfg.MODE = "sni_spoof".into();
    cfg.LISTEN_HOST = ip.to_string();
    cfg.LISTEN_PORT = 0;
    cfg.BYPASS_METHOD = "tls_frag".into();
    cfg.TLS_FRAG_PACKETS = "9-9".into();
    let (events, mut rx) = proxy_event_channel(false);
    let (registrations, _rx) = mpsc::unbounded_channel();
    let worker = tokio::spawn(run_proxy_on_port(
        Arc::new(cfg),
        pool.clone(),
        InterfaceBindingWatch::fixed(InterfaceBinding::fixed(ip)),
        Arc::new(NoopSocketBinder),
        Arc::new(CompletingController(registrations)),
        Some(events),
        port,
    ));
    let Some(ProxyEvent::ListenerStarted { listen_addr, .. }) = rx.recv().await else {
        panic!("listener not ready")
    };
    let mut first = TcpStream::connect(listen_addr).await.unwrap();
    exchange(&mut first, 1, 11).await;
    let mut second = TcpStream::connect(listen_addr).await.unwrap();
    exchange(&mut second, 1, 22).await;
    let mut names = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let ProxyEvent::ConnectionAccepted { target_sni, .. } = event {
            names.push(target_sni.unwrap());
        }
    }
    assert_eq!(
        names.iter().map(AsRef::as_ref).collect::<Vec<&str>>(),
        ["first.example", "second.example"]
    );
    let snapshot = pool.snapshot();
    assert_eq!(snapshot.targets.len(), 2);
    for target in &snapshot.targets {
        assert_eq!(target.active_connections, 1);
        assert_eq!((target.c2s_bytes, target.s2c_bytes), (1, 2));
    }
    worker.abort();
    let _ = worker.await;
    server.abort();
    let _ = server.await;
}

#[tokio::test]
#[allow(deprecated)]
async fn target_traffic_and_load_survive_every_relay_exit() {
    for exit in ["eof", "reset", "rotate", "cancel"] {
        let pool = TargetPool::single(Target::ip(Ipv4Addr::LOCALHOST.into(), 90));
        let lease = pool.acquire();
        let (mut client, incoming) = super::tests::tcp_pair().await;
        let (mut server, outgoing) = super::tests::tcp_pair().await;
        let lifetime = (exit == "rotate").then_some(Duration::from_millis(100));
        let worker = tokio::spawn(async move {
            counting_relay_with_client_fragmentation(
                incoming,
                outgoing,
                &None,
                1234,
                lifetime,
                None,
                Some(&lease.traffic),
            )
            .await
        });
        client.write_all(b"ping").await.unwrap();
        let mut bytes = [0; 4];
        server.read_exact(&mut bytes).await.unwrap();
        server.write_all(b"pong").await.unwrap();
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(pool.snapshot().targets[0].c2s_bytes, 4);
        match exit {
            "cancel" => {
                worker.abort();
                assert!(worker.await.unwrap_err().is_cancelled());
            }
            "reset" => {
                client.set_linger(Some(Duration::ZERO)).unwrap();
                drop(client);
                let result = tokio::time::timeout(Duration::from_secs(2), worker)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(result.reason, RelayEndReason::NetworkError);
            }
            "rotate" => {
                let result = tokio::time::timeout(Duration::from_secs(2), worker)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(result.reason, RelayEndReason::MaxLifetime);
            }
            _ => {
                client.shutdown().await.unwrap();
                server.shutdown().await.unwrap();
                let result = tokio::time::timeout(Duration::from_secs(2), worker)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(result.reason, RelayEndReason::Completed);
            }
        }
        let target = &pool.snapshot().targets[0];
        assert_eq!(target.active_connections, 0, "{exit}");
        assert_eq!((target.c2s_bytes, target.s2c_bytes), (4, 4), "{exit}");
    }
}
