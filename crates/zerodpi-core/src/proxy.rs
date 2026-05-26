//! tokio-based TCP proxy that drives the bypass:
//!
//! For interceptor-based methods (`wrong_seq`, `tls_record_frag`):
//! 1. Accept incoming TCP on `LISTEN_HOST:LISTEN_PORT`.
//! 2. Open an outbound TCP socket bound to the local interface IP.
//! 3. Build a fake ClientHello and register the flow in the [`FlowTable`].
//! 4. The platform interceptor observes the handshake and, on the first
//!    outbound bare ACK, mutates it into the spoofed ClientHello and signals
//!    the proxy task via the flow's `Notify`.
//! 5. With a 2 s timeout for that signal, the proxy then runs a normal
//!    bidirectional copy between the two sockets.
//!
//! For socket-based methods (`tcp_segmentation`):
//! 1. Accept incoming TCP on `LISTEN_HOST:LISTEN_PORT`.
//! 2. Connect to the upstream server (no FlowTable registration, no interceptor).
//! 3. Read one complete TLS record (the ClientHello) from the client socket.
//! 4. Write it to the upstream socket in tiny chunks with `TCP_NODELAY` so
//!    each chunk arrives as a separate TCP segment.
//! 5. Hand off to the normal bidirectional relay.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::flow::{BypassOutcome, FlowEntry, FlowKey, FlowTable};
use crate::methods::tcp_segmentation::{read_one_tls_record, write_segmented, TcpSegmentation};
use crate::tls_template::build_client_hello;

// ---------------------------------------------------------------------------
// Active SNI target
// ---------------------------------------------------------------------------

/// Currently selected SNI-spoof target. The proxy snapshots this once per new
/// connection, so background switches affect new connections only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSniTarget {
    pub sni: Arc<str>,
    pub ip: Ipv4Addr,
    pub score: u8,
}

impl ActiveSniTarget {
    pub fn new(sni: impl Into<Arc<str>>, ip: Ipv4Addr, score: u8) -> Self {
        Self {
            sni: sni.into(),
            ip,
            score,
        }
    }
}

pub type SharedSniTarget = Arc<RwLock<ActiveSniTarget>>;

// ---------------------------------------------------------------------------
// Proxy events
// ---------------------------------------------------------------------------

/// Events emitted by the proxy for each connection, used to drive the live
/// dashboard when running in interactive mode.
#[derive(Debug)]
pub enum ProxyEvent {
    /// A new inbound connection was accepted and the outbound source port is known.
    ConnectionAccepted { peer: SocketAddr, src_port: u16 },
    /// The SNI-bypass phase finished (successfully or not).
    BypassComplete {
        src_port: u16,
        outcome: BypassOutcome,
    },
    /// The bidirectional relay ended.
    ///
    /// `c2s_bytes` and `s2c_bytes` are the bytes transferred in each direction.
    /// Both are reported as `0` when the relay encountered an I/O error, since
    /// [`tokio::io::copy_bidirectional`] does not expose partial byte counts on
    /// failure.
    RelayFinished {
        src_port: u16,
        c2s_bytes: u64,
        s2c_bytes: u64,
    },
    /// A fatal error occurred before the relay could start (e.g. upstream
    /// TCP connect failed).
    ConnectionError { src_port: u16, error: String },
    /// Periodic progress report while the relay is running (emitted every 500 ms).
    RelayProgress {
        src_port: u16,
        c2s_bytes: u64,
        s2c_bytes: u64,
    },
    /// The active SNI-spoof target changed after a background rescan.
    SniTargetChanged {
        sni: String,
        ip: Ipv4Addr,
        score: u8,
    },
    /// The active IP-bypass target changed after a background rescan.
    IpTargetChanged { ip: IpAddr },
}

/// Sender half of the [`ProxyEvent`] channel; pass to [`run_proxy`] to enable
/// the live dashboard.  When `None` is passed the proxy operates silently.
pub type ProxyEventSender = mpsc::UnboundedSender<ProxyEvent>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Send a [`ProxyEvent`] if a sender is present; silently drop if not.
#[inline]
fn emit(tx: &Option<ProxyEventSender>, event: ProxyEvent) {
    if let Some(ref tx) = tx {
        let _ = tx.send(event);
    }
}

/// How long to wait for the bypass to complete before giving up.
/// This constant is kept for use in tests; the proxy uses `cfg.BYPASS_TIMEOUT_SECS`.
pub const BYPASS_TIMEOUT: Duration = Duration::from_secs(2);

/// The upstream port — always 443.
pub const CONNECT_PORT: u16 = 443;

/// Build the spoofed ClientHello payload for one new flow.
pub fn fresh_fake_client_hello(fake_sni: &[u8]) -> Vec<u8> {
    use rand_lite::random32;
    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    let mut key_share = [0u8; 32];
    random32(&mut random);
    random32(&mut session_id);
    random32(&mut key_share);
    build_client_hello(&random, &session_id, fake_sni, &key_share)
}

/// A tiny inline RNG so we don't pull in the `rand` crate just for 96 bytes
/// of nonce material per connection. Seeded from system time + an atomic
/// counter; quality is good enough for nonces (not for crypto-strong key
/// generation, but the spoofed ClientHello is discarded by the server).
mod rand_lite {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub fn random32(buf: &mut [u8]) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut state = nanos
            ^ COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
            ^ (buf.as_ptr() as usize as u64);
        for chunk in buf.chunks_mut(8) {
            // splitmix64
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            for (b, s) in chunk.iter_mut().zip(bytes.iter()) {
                *b = *s;
            }
        }
    }
}

/// Run the proxy: bind the listener and accept connections forever.
///
/// Each accepted connection is handled on its own tokio task; the platform
/// interceptor (running on a dedicated OS thread) is expected to be looking
/// at the same `flows` table.
///
/// Pass `Some(sender)` to receive [`ProxyEvent`] notifications for the live
/// dashboard; pass `None` when no dashboard is attached.
pub async fn run_proxy(
    cfg: Arc<Config>,
    active_target: SharedSniTarget,
    interface_ip: Ipv4Addr,
    flows: FlowTable,
    event_tx: Option<ProxyEventSender>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
        .parse()
        .context("invalid LISTEN_HOST/LISTEN_PORT")?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind {listen_addr}"))?;
    info!(%listen_addr, "listening");

    loop {
        let (incoming, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        debug!(%peer, "accepted");

        // Route to the socket-based path for tcp_segmentation.
        // No FlowTable registration; no interceptor involvement.
        if cfg.BYPASS_METHOD == "tcp_segmentation" {
            let cfg = cfg.clone();
            let connect_ip = active_target.read().unwrap().ip;
            let event_tx = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_tcp_seg_connection_with_ip(cfg, connect_ip, incoming, peer, event_tx)
                        .await
                {
                    warn!(%peer, error = %e, "tcp_seg connection failed");
                }
            });
            continue;
        }

        let target = active_target.read().unwrap().clone();
        let flows = flows.clone();
        let event_tx = event_tx.clone();
        let bypass_timeout = Duration::from_secs(cfg.BYPASS_TIMEOUT_SECS);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                interface_ip,
                target,
                flows,
                incoming,
                peer,
                event_tx,
                bypass_timeout,
            )
            .await
            {
                warn!(%peer, error = %e, "connection failed");
            }
        });
    }
}

async fn handle_connection(
    interface_ip: Ipv4Addr,
    target: ActiveSniTarget,
    flows: FlowTable,
    incoming: TcpStream,
    peer: SocketAddr,
    event_tx: Option<ProxyEventSender>,
    bypass_timeout: Duration,
) -> anyhow::Result<()> {
    let connect_port = CONNECT_PORT;
    let connect_ip = target.ip;

    // Build outbound socket bound to the host's interface IP, kernel-chosen port.
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::from((interface_ip, 0)))?;
    let local = socket.local_addr()?;
    let src_port = local.port();

    // Now that we have the source port, report the accepted connection.
    emit(&event_tx, ProxyEvent::ConnectionAccepted { peer, src_port });

    let key = FlowKey {
        src_ip: interface_ip,
        src_port,
        dst_ip: connect_ip,
        dst_port: connect_port,
    };

    let fake = fresh_fake_client_hello(target.sni.as_bytes());
    let entry = FlowEntry::new(fake);
    flows.insert(key, entry.clone());

    // Make sure we always remove the entry on this path's exit.
    let cleanup = scopeguard(|| {
        flows.remove(&key);
    });

    // Connect: while this is happening, the kernel emits SYN, receives SYN-ACK,
    // and sends the bare ACK that the interceptor will rewrite.
    let outgoing = match socket
        .connect(SocketAddr::from((connect_ip, connect_port)))
        .await
    {
        Ok(s) => s,
        Err(e) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                &event_tx,
                ProxyEvent::ConnectionError {
                    src_port,
                    error: e.to_string(),
                },
            );
            return Err(e).context("connect upstream");
        }
    };

    // Wait (with timeout) for the interceptor to finish the bypass.
    let waited = tokio::time::timeout(bypass_timeout, entry.notify.notified()).await;
    let outcome = entry.state.lock().outcome;
    match (waited, outcome) {
        (Ok(()), Some(BypassOutcome::FakeDataAcked)) => {
            debug!(?key, "bypass complete");
            emit(
                &event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::FakeDataAcked,
                },
            );
        }
        (Ok(()), Some(BypassOutcome::UnexpectedClose)) => {
            emit(
                &event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!("interceptor closed the flow");
        }
        _ => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                &event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!("bypass timed out");
        }
    }

    // Release the flow before relaying so any further packets pass through.
    drop(cleanup);

    // Bidirectional relay with periodic progress events.
    let (c2s_bytes, s2c_bytes) = counting_relay(incoming, outgoing, &event_tx, src_port).await;
    debug!(c2s_bytes, s2c_bytes, "relay finished");
    emit(
        &event_tx,
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes,
            s2c_bytes,
        },
    );

    Ok(())
}

/// Tiny scope-guard so we don't pull in the `scopeguard` crate.
fn scopeguard<F: FnOnce()>(f: F) -> ScopeGuard<F> {
    ScopeGuard(Some(f))
}
struct ScopeGuard<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for ScopeGuard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

// ---------------------------------------------------------------------------
// tcp_segmentation proxy path (no packet interceptor)
// ---------------------------------------------------------------------------

/// Handle a single connection using the `tcp_segmentation` bypass method.
///
/// Does **not** register a flow in the [`FlowTable`] and does **not** involve
/// the platform packet interceptor.  Instead:
///
/// 1. Connects to the upstream server (with `TCP_NODELAY` if configured).
/// 2. Reads exactly one complete TLS record from the client — the ClientHello.
/// 3. Writes it to the upstream socket in chunks of `TCP_SEG_SIZE` bytes.
///    With `TCP_NODELAY` each chunk is sent as a separate TCP segment.
/// 4. Hands off to the normal bidirectional relay.
async fn handle_tcp_seg_connection_with_ip(
    cfg: Arc<Config>,
    connect_ip: Ipv4Addr,
    mut incoming: TcpStream,
    peer: SocketAddr,
    event_tx: Option<ProxyEventSender>,
) -> anyhow::Result<()> {
    let src_port = peer.port();
    emit(&event_tx, ProxyEvent::ConnectionAccepted { peer, src_port });

    let method = TcpSegmentation::new(&cfg);
    let connect_addr = SocketAddr::from((connect_ip, CONNECT_PORT));

    // Connect to upstream.
    let mut outgoing = match TcpStream::connect(connect_addr).await {
        Ok(s) => s,
        Err(e) => {
            emit(
                &event_tx,
                ProxyEvent::ConnectionError {
                    src_port,
                    error: e.to_string(),
                },
            );
            return Err(e).context("tcp_seg: connect upstream");
        }
    };

    // Enable TCP_NODELAY on the upstream socket if configured.
    if method.nodelay {
        outgoing
            .set_nodelay(true)
            .context("tcp_seg: set_nodelay on upstream socket")?;
    }

    // Read exactly one TLS record (the ClientHello) from the client.
    let client_hello = read_one_tls_record(&mut incoming)
        .await
        .context("tcp_seg: reading ClientHello from client")?;

    // Write it to the upstream socket in small segments.
    write_segmented(&mut outgoing, &client_hello, method.seg_size)
        .await
        .context("tcp_seg: writing segmented ClientHello")?;

    debug!(
        seg_size = method.seg_size,
        nodelay = method.nodelay,
        total_bytes = client_hello.len(),
        "tcp_seg: ClientHello written in segments; handing off to relay"
    );

    emit(
        &event_tx,
        ProxyEvent::BypassComplete {
            src_port,
            outcome: BypassOutcome::FakeDataAcked,
        },
    );

    // Bidirectional relay for the rest of the session.
    // The ClientHello has already been forwarded; the relay starts mid-stream.
    let (c2s_bytes, s2c_bytes) = counting_relay(incoming, outgoing, &event_tx, src_port).await;
    debug!(c2s_bytes, s2c_bytes, "tcp_seg: relay finished");
    emit(
        &event_tx,
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes,
            s2c_bytes,
        },
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Counting relay
// ---------------------------------------------------------------------------

/// Run a bidirectional relay between `incoming` and `outgoing`, emitting
/// [`ProxyEvent::RelayProgress`] every 500 ms when a sender is present.
///
/// Returns `(c2s_bytes, s2c_bytes)` — the total bytes transferred in each
/// direction.  Shutdown of each write half is handled internally when the
/// corresponding read half reaches EOF.
async fn counting_relay(
    incoming: TcpStream,
    outgoing: TcpStream,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
) -> (u64, u64) {
    let (inc_rd, inc_wr) = incoming.into_split();
    let (out_rd, out_wr) = outgoing.into_split();

    let c2s_atomic = Arc::new(AtomicU64::new(0));
    let s2c_atomic = Arc::new(AtomicU64::new(0));

    let c2s_task = tokio::spawn(copy_counting(inc_rd, out_wr, c2s_atomic.clone()));
    let s2c_task = tokio::spawn(copy_counting(out_rd, inc_wr, s2c_atomic.clone()));

    // Progress ticker — only spawned in interactive mode.
    let ticker = event_tx.as_ref().map(|tx| {
        let tx = tx.clone();
        let c = c2s_atomic.clone();
        let s = s2c_atomic.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                let _ = tx.send(ProxyEvent::RelayProgress {
                    src_port,
                    c2s_bytes: c.load(Ordering::Relaxed),
                    s2c_bytes: s.load(Ordering::Relaxed),
                });
            }
        })
    });

    let (c2s_result, s2c_result) = tokio::join!(c2s_task, s2c_task);
    if let Some(t) = ticker {
        t.abort();
    }

    (c2s_result.unwrap_or(0), s2c_result.unwrap_or(0))
}

/// Copy all bytes from `reader` to `writer`, updating `counter` after each
/// chunk.  Shuts down `writer` gracefully on EOF or error, then returns the
/// total bytes copied.
async fn copy_counting(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    counter: Arc<AtomicU64>,
) -> u64 {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
        counter.store(total, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
    total
}

// ---------------------------------------------------------------------------
// IP-bypass proxy (no packet interception, no SNI manipulation)
// ---------------------------------------------------------------------------

/// Run the IP-bypass proxy.
///
/// Unlike [`run_proxy`], this function performs **no packet interception**.
/// It simply accepts incoming TCP connections and relays them to whichever
/// IP is currently stored in `active_ip:443`, forwarding all data verbatim
/// so that the upstream app's own TLS SNI passes through unchanged.
///
/// `active_ip` is an `Arc<RwLock<IpAddr>>` that can be hot-swapped by the
/// background rescan task — each new accepted connection reads the current
/// value, so the swap applies to new connections only.
pub async fn run_ip_bypass_proxy(
    cfg: Arc<Config>,
    active_ip: Arc<RwLock<IpAddr>>,
    event_tx: Option<ProxyEventSender>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
        .parse()
        .context("invalid LISTEN_HOST/LISTEN_PORT")?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind {listen_addr}"))?;
    info!(%listen_addr, "ip_bypass: listening");

    loop {
        let (incoming, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "ip_bypass: accept failed");
                continue;
            }
        };
        debug!(%peer, "ip_bypass: accepted");

        let ip = *active_ip.read().unwrap();
        let event_tx = event_tx.clone();
        let src_port = peer.port();

        tokio::spawn(async move {
            if let Err(e) =
                handle_ip_bypass_connection(ip, incoming, peer, src_port, event_tx).await
            {
                warn!(%peer, error = %e, "ip_bypass: connection failed");
            }
        });
    }
}

async fn handle_ip_bypass_connection(
    connect_ip: IpAddr,
    incoming: TcpStream,
    peer: SocketAddr,
    src_port: u16,
    event_tx: Option<ProxyEventSender>,
) -> anyhow::Result<()> {
    let connect_addr = SocketAddr::new(connect_ip, CONNECT_PORT);
    emit(&event_tx, ProxyEvent::ConnectionAccepted { peer, src_port });

    let outgoing = match TcpStream::connect(connect_addr).await {
        Ok(s) => {
            // Reuse BypassComplete / FakeDataAcked to signal "TCP connect OK".
            emit(
                &event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: crate::flow::BypassOutcome::FakeDataAcked,
                },
            );
            s
        }
        Err(e) => {
            emit(
                &event_tx,
                ProxyEvent::ConnectionError {
                    src_port,
                    error: e.to_string(),
                },
            );
            return Err(e).context("ip_bypass: connect upstream");
        }
    };

    let (c2s_bytes, s2c_bytes) = counting_relay(incoming, outgoing, &event_tx, src_port).await;
    debug!(c2s_bytes, s2c_bytes, "ip_bypass: relay finished");
    emit(
        &event_tx,
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes,
            s2c_bytes,
        },
    );
    Ok(())
}
