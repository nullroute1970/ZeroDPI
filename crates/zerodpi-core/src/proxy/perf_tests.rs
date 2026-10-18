//! Repeatable loopback measurements; run with tools/relay_benchmark.py.

use super::*;
use std::time::Instant;
use tokio::sync::Barrier;

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let (client, accepted) = tokio::join!(connect, listener.accept());
    (client.unwrap(), accepted.unwrap().0)
}

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "loopback performance measurement, not a correctness test"]
async fn relay_benchmark() {
    let connections = setting("ZERODPI_BENCH_CONNECTIONS", 1);
    let progress = setting("ZERODPI_BENCH_PROGRESS", 1) != 0;
    let nodelay = setting("ZERODPI_BENCH_NODELAY", 1) != 0;
    let duration = Duration::from_millis(setting("ZERODPI_BENCH_DURATION_MS", 750) as u64);
    let (tx, mut rx) = proxy_event_channel(progress);
    let consumer = tokio::spawn(async move {
        let mut reports = 0usize;
        while let Some(event) = rx.recv().await {
            match event {
                ProxyEvent::RelayProgress { .. } => reports += 1,
                ProxyEvent::RelayProgressBatch { entries, .. } => reports += entries.len(),
                _ => {}
            }
        }
        reports
    });
    let mut relays = JoinSet::new();
    let mut servers = JoinSet::new();
    let mut clients = JoinSet::new();
    let ready = Arc::new(Barrier::new(connections + 1));
    for index in 0..connections {
        let (mut client, incoming) = pair().await;
        let (outgoing, mut server) = pair().await;
        client.set_nodelay(true).unwrap();
        server.set_nodelay(true).unwrap();
        incoming.set_nodelay(nodelay).unwrap();
        outgoing.set_nodelay(nodelay).unwrap();
        let relay_tx = progress.then(|| tx.clone());
        relays.spawn(async move {
            counting_relay(incoming, outgoing, &relay_tx, 40000 + index as u16, None).await
        });
        servers.spawn(async move {
            let mut buf = vec![0; 64 * 1024];
            loop {
                let n = server.read(&mut buf).await.unwrap();
                if n == 0 {
                    server.shutdown().await.unwrap();
                    break;
                }
                server.write_all(&buf[..n]).await.unwrap();
            }
        });
        let ready = ready.clone();
        clients.spawn(async move {
            let mut small = [0u8; 64];
            let mut latencies = Vec::with_capacity(20);
            for _ in 0..20 {
                let start = Instant::now();
                client.write_all(&small).await.unwrap();
                client.read_exact(&mut small).await.unwrap();
                latencies.push(start.elapsed().as_secs_f64() * 1_000_000.0);
            }
            ready.wait().await;
            let deadline = Instant::now() + duration;
            let mut bulk = vec![0x5A; 64 * 1024];
            let mut bytes = 0u64;
            while Instant::now() < deadline {
                client.write_all(&bulk).await.unwrap();
                client.read_exact(&mut bulk).await.unwrap();
                bytes += bulk.len() as u64;
            }
            client.shutdown().await.unwrap();
            assert_eq!(client.read(&mut small).await.unwrap(), 0);
            (latencies, bytes)
        });
    }
    ready.wait().await;
    let start = Instant::now();
    let mut latencies = Vec::new();
    let mut bytes = 0u64;
    while let Some(result) = clients.join_next().await {
        let (mut samples, copied) = result.unwrap();
        latencies.append(&mut samples);
        bytes += copied;
    }
    let elapsed = start.elapsed().as_secs_f64();
    let mut relay_bytes = 0;
    while let Some(result) = relays.join_next().await {
        let result = result.unwrap();
        assert_eq!(result.reason, RelayEndReason::Completed);
        assert_eq!(result.c2s_bytes, result.s2c_bytes);
        relay_bytes += result.c2s_bytes;
    }
    assert_eq!(relay_bytes, bytes + (connections * 20 * 64) as u64);
    while let Some(result) = servers.join_next().await {
        result.unwrap();
    }
    drop(tx);
    let reports = consumer.await.unwrap();
    latencies.sort_by(f64::total_cmp);
    println!(
        "RELAY_BENCH {{\"connections\":{connections},\"progress\":{progress},\"nodelay\":{nodelay},\"mib_per_sec\":{},\"p50_us\":{},\"p95_us\":{},\"reports\":{reports}}}",
        bytes as f64 * 2.0 / elapsed / (1024.0 * 1024.0),
        latencies[latencies.len() / 2],
        latencies[latencies.len() * 95 / 100],
    );
}
