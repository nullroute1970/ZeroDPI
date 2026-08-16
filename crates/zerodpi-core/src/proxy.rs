//! tokio-based TCP proxy that drives the bypass:
//!
//! For interceptor-based methods (`wrong_seq`, `wrong_ack`, `wrong_checksum`,
//! `wrong_md5`, `wrong_seq_wrong_md5`, `wrong_timestamp`, `tls_record_frag`,
//! `wrong_seq_tls_frag`, `wrong_md5_tls_frag`, `wrong_seq_tls_record_frag`):
//! 1. Accept incoming TCP on `LISTEN_HOST:LISTEN_PORT`.
//! 2. Open an outbound TCP socket bound to the local interface IP.
//! 3. Build a fake ClientHello and register the flow in the [`FlowTable`].
//! 4. The platform interceptor observes the handshake and either completes the
//!    fake-packet bypass or asks the proxy to write the first ClientHello while
//!    the flow is still being intercepted.
//! 5. Once the bypass completes, the proxy runs a normal bidirectional copy
//!    between the two sockets.
//! 6. For `wrong_seq_tls_frag` and `wrong_md5_tls_frag`, step 4 writes
//!    configured client data in small TCP chunks using the same `TLS_FRAG_*`
//!    settings as `tls_frag`.
//!
//! For `ip_bypass_plus`, IP scanning selects the upstream IPv4 address, then
//! only real-SNI-preserving methods (`tls_record_frag` or `tls_frag`)
//! are applied to the first ClientHello. No fake SNI payload is generated.
//!
//! For socket-based methods (`tls_frag`, TCP-level TLS Fragment):
//! 1. Accept incoming TCP on `LISTEN_HOST:LISTEN_PORT`.
//! 2. Connect to the upstream server (no FlowTable registration, no interceptor).
//! 3. In `tlshello` mode, read one complete TLS record (the ClientHello) and
//!    write it to the upstream socket in configured chunks.
//! 4. In packet-range mode, let the relay fragment selected client writes.
//! 5. Relay the rest of the session normally.
//!
//! For `ccs_prefix` (TLS 1.3 middlebox-compat ChangeCipherSpec prefix), a
//! 6-byte dummy ChangeCipherSpec record is written as the very first
//! upstream bytes before the ClientHello; the TLS bytes are not modified.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::{Config, TlsFragPackets};
use crate::flow::{BypassOutcome, FlowController, FlowEntry, FlowKey};
use crate::methods::ccs_prefix::CcsPrefix;
use crate::methods::mixed_case_sni::MixedCaseSni;
use crate::methods::sni_boundary_frag::{write_boundary_split, SniBoundaryFrag};
use crate::methods::tcp_segmentation::{read_one_tls_record, write_fragmented, TcpSegmentation};
use crate::methods::tls_padding::TlsPadding;
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
    /// The local listener was bound and is ready to accept inbound connections.
    ListenerStarted {
        mode: String,
        listen_addr: SocketAddr,
    },
    /// A new inbound connection was accepted and the outbound source port is known.
    ConnectionAccepted {
        peer: SocketAddr,
        src_port: u16,
        /// The outbound IP this connection relays to (snapshot at accept time).
        target_ip: IpAddr,
    },
    /// The SNI-bypass phase finished (successfully or not).
    BypassComplete {
        src_port: u16,
        outcome: BypassOutcome,
    },
    /// The bidirectional relay ended.
    ///
    /// `c2s_bytes` and `s2c_bytes` are the bytes transferred in each direction.
    /// They include bytes copied before a configured max-lifetime rotation.
    RelayFinished {
        src_port: u16,
        c2s_bytes: u64,
        s2c_bytes: u64,
        reason: RelayEndReason,
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
    IpTargetChanged { ip: IpAddr, score: u8 },
    /// `LOW_TTL_DISCOVER` found a working TTL and applied it.
    LowTtlDiscovered { value: u8 },
    /// A periodic background rescan started (includes any TTL discovery
    /// probe run before a potential hot-swap).
    RescanStarted { kind: RescanKind },
    /// A periodic background rescan finished (success, empty result, or failure).
    RescanFinished {
        kind: RescanKind,
        /// Number of working candidates the scan produced (0 on failure).
        found: usize,
        /// Score of the best candidate, if the scan produced any.
        best_score: Option<u8>,
        /// How long the scan took (including list loading), in milliseconds.
        duration_ms: u64,
        /// Whether this rescan hot-swapped the active target.
        switched: bool,
    },
    /// A new rescan cycle was scheduled; the TUI uses this for its countdown.
    NextRescanScheduled {
        kind: RescanKind,
        interval_secs: u64,
    },
}

/// Which background rescan produced a [`ProxyEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RescanKind {
    /// `sni_spoof` mode background SNI rescan.
    Sni,
    /// `ip_bypass` / `ip_bypass_plus` mode background IP rescan.
    Ip,
}

/// Sender half of the [`ProxyEvent`] channel; pass to [`run_proxy`] to enable
/// the live dashboard.  When `None` is passed the proxy operates silently.
pub type ProxyEventSender = mpsc::UnboundedSender<ProxyEvent>;

/// Why a relay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEndReason {
    /// Both relay directions ended naturally.
    Completed,
    /// The configured maximum relay lifetime expired and the relay was closed
    /// so the upstream client can reconnect through the current target.
    MaxLifetime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelayResult {
    c2s_bytes: u64,
    s2c_bytes: u64,
    reason: RelayEndReason,
}

#[derive(Debug, Clone, Copy)]
struct ConnectionSettings {
    bypass_timeout: Duration,
    max_lifetime: Option<Duration>,
    segment_first_client_hello: bool,
    tls_padding: Option<TlsPadding>,
    ccs_prefix: Option<CcsPrefix>,
    mixed_case_sni: Option<MixedCaseSni>,
    sni_boundary_frag: Option<SniBoundaryFrag>,
    tcp_segmentation: TcpSegmentation,
    /// `ip_frag` with `IP_FRAG_ONLY_FIRST_PACKET = false`, or `disorder`
    /// with `DISORDER_ONLY_FIRST_PACKET = false`: the interceptor keeps
    /// rewriting outbound data packets for the connection's lifetime, so
    /// the flow stays registered after bypass completion.
    fragment_all_data: bool,
}

impl ConnectionSettings {
    fn from_config(cfg: &Config) -> Self {
        let tcp_segmentation = TcpSegmentation::new(cfg);
        Self {
            bypass_timeout: Duration::from_secs(cfg.BYPASS_TIMEOUT_SECS),
            max_lifetime: configured_relay_max_lifetime(cfg),
            segment_first_client_hello: cfg.BYPASS_METHOD.contains("tls_frag"),
            tls_padding: cfg
                .BYPASS_METHOD
                .contains("tls_padding")
                .then(|| TlsPadding::new(cfg)),
            ccs_prefix: cfg
                .BYPASS_METHOD
                .contains("ccs_prefix")
                .then(|| CcsPrefix::new(cfg)),
            mixed_case_sni: cfg
                .BYPASS_METHOD
                .contains("mixed_case_sni")
                .then(|| MixedCaseSni::new(cfg)),
            sni_boundary_frag: cfg
                .BYPASS_METHOD
                .contains("sni_boundary_frag")
                .then(|| SniBoundaryFrag::new(cfg)),
            fragment_all_data: (cfg.BYPASS_METHOD.contains("ip_frag")
                && !cfg.IP_FRAG_ONLY_FIRST_PACKET)
                || (cfg.BYPASS_METHOD.contains("disorder") && !cfg.DISORDER_ONLY_FIRST_PACKET),
            tcp_segmentation,
        }
    }

    /// Apply the socket-side ClientHello transforms: `tls_padding` first,
    /// then `mixed_case_sni`. Fail-open: a record that does not parse is
    /// returned unchanged.
    fn apply_socket_transforms(&self, record: &[u8]) -> Vec<u8> {
        let mut out = record.to_vec();
        if let Some(padding) = self.tls_padding {
            out = padding.apply(&out).unwrap_or(out);
        }
        if let Some(mixed) = self.mixed_case_sni {
            out = mixed.apply(&out).unwrap_or(out);
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BypassProgress {
    ReadyForData,
    Complete(BypassOutcome),
}

#[derive(Debug)]
struct InterceptConnectionTarget {
    interface_ip: Ipv4Addr,
    connect_ip: Ipv4Addr,
    fake_client_hello: Vec<u8>,
}

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

fn configured_relay_max_lifetime(cfg: &Config) -> Option<Duration> {
    (cfg.RELAY_MAX_LIFETIME_SECS > 0).then(|| Duration::from_secs(cfg.RELAY_MAX_LIFETIME_SECS))
}

async fn read_one_client_write(src: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; 64 * 1024];
    let n = src
        .read(&mut buf)
        .await
        .context("reading client data write")?;
    if n == 0 {
        anyhow::bail!("client closed before sending data");
    }
    buf.truncate(n);
    Ok(buf)
}

async fn write_client_data<W>(
    dst: &mut W,
    data: &[u8],
    segmentation: TcpSegmentation,
    write_index: u32,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if segmentation.fragments_write(write_index) {
        write_fragmented(dst, data, segmentation.length, segmentation.interval_ms).await
    } else {
        dst.write_all(data).await.context("writing client data")?;
        dst.flush().await.context("flushing client data")?;
        Ok(())
    }
}

/// Write the dummy ChangeCipherSpec record of `ccs_prefix` as the very first
/// bytes of the upstream stream, flushed so it leaves as its own segment.
async fn write_ccs_prefix<W>(dst: &mut W, ccs: CcsPrefix) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    dst.write_all(&ccs.record())
        .await
        .context("ccs_prefix: writing dummy ChangeCipherSpec record")?;
    dst.flush()
        .await
        .context("ccs_prefix: flushing dummy ChangeCipherSpec record")
}

async fn read_client_tls_record_with_timeout(
    incoming: &mut TcpStream,
    timeout: Duration,
    entry: &FlowEntry,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
) -> anyhow::Result<Vec<u8>> {
    match tokio::time::timeout(timeout, read_one_tls_record(incoming)).await {
        Ok(Ok(record)) => Ok(record),
        Ok(Err(e)) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            Err(e).context("reading ClientHello from client")
        }
        Err(_) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!("timed out reading ClientHello from client");
        }
    }
}

async fn read_client_write_with_timeout(
    incoming: &mut TcpStream,
    timeout: Duration,
    entry: &FlowEntry,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
) -> anyhow::Result<Vec<u8>> {
    match tokio::time::timeout(timeout, read_one_client_write(incoming)).await {
        Ok(Ok(data)) => Ok(data),
        Ok(Err(e)) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            Err(e).context("reading client data from client")
        }
        Err(_) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!("timed out reading client data from client");
        }
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

fn current_bypass_progress(entry: &FlowEntry) -> Option<BypassProgress> {
    let state = entry.state.lock();
    if let Some(outcome) = state.outcome {
        Some(BypassProgress::Complete(outcome))
    } else if state.waiting_for_data {
        Some(BypassProgress::ReadyForData)
    } else {
        None
    }
}

async fn wait_for_initial_bypass_progress(
    entry: &FlowEntry,
    timeout: Duration,
) -> Option<BypassProgress> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(progress) = current_bypass_progress(entry) {
                return progress;
            }
            tokio::select! {
                _ = entry.notify.notified() => {}
                _ = entry.ready_for_data.notified() => {}
            }
        }
    })
    .await
    .ok()
}

async fn wait_for_bypass_completion(entry: &FlowEntry, timeout: Duration) -> Option<BypassOutcome> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(outcome) = entry.state.lock().outcome {
                return outcome;
            }
            entry.notify.notified().await;
        }
    })
    .await
    .ok()
}

fn finish_bypass_or_error(
    entry: &FlowEntry,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
    outcome: Option<BypassOutcome>,
    timeout_error: &'static str,
) -> anyhow::Result<()> {
    match outcome {
        Some(BypassOutcome::FakeDataAcked) => {
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::FakeDataAcked,
                },
            );
            Ok(())
        }
        Some(BypassOutcome::UnexpectedClose) => {
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!("interceptor closed the flow");
        }
        None => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: BypassOutcome::UnexpectedClose,
                },
            );
            anyhow::bail!(timeout_error);
        }
    }
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
    flow_controller: Arc<dyn FlowController>,
    event_tx: Option<ProxyEventSender>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
        .parse()
        .context("invalid LISTEN_HOST/LISTEN_PORT")?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind {listen_addr}"))?;
    info!(%listen_addr, "listening");
    emit(
        &event_tx,
        ProxyEvent::ListenerStarted {
            mode: cfg.MODE.clone(),
            listen_addr,
        },
    );

    loop {
        let (incoming, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        debug!(%peer, "accepted");

        // Route to the socket-based path for tls_frag.
        // No FlowTable registration; no interceptor involvement.
        if cfg.BYPASS_METHOD.is_socket_only() {
            let cfg = cfg.clone();
            let connect_ip = active_target.read().unwrap().ip;
            let event_tx = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_tcp_seg_connection_with_ip(cfg, connect_ip, incoming, peer, event_tx)
                        .await
                {
                    warn!(%peer, error = %e, "tls_frag connection failed");
                }
            });
            continue;
        }

        let target = active_target.read().unwrap().clone();
        let flow_controller = flow_controller.clone();
        let event_tx = event_tx.clone();
        let connection_settings = ConnectionSettings::from_config(&cfg);
        let fake_client_hello = fresh_fake_client_hello(target.sni.as_bytes());
        tokio::spawn(async move {
            if let Err(e) = handle_intercept_connection(
                InterceptConnectionTarget {
                    interface_ip,
                    connect_ip: target.ip,
                    fake_client_hello,
                },
                flow_controller,
                incoming,
                peer,
                event_tx,
                connection_settings,
            )
            .await
            {
                warn!(%peer, error = %e, "connection failed");
            }
        });
    }
}

async fn handle_intercept_connection(
    target: InterceptConnectionTarget,
    flow_controller: Arc<dyn FlowController>,
    mut incoming: TcpStream,
    peer: SocketAddr,
    event_tx: Option<ProxyEventSender>,
    settings: ConnectionSettings,
) -> anyhow::Result<()> {
    let connect_port = CONNECT_PORT;
    let interface_ip = target.interface_ip;
    let connect_ip = target.connect_ip;

    // Build outbound socket bound to the host's interface IP, kernel-chosen port.
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::from((interface_ip, 0)))?;
    let local = socket.local_addr()?;
    let src_port = local.port();

    // Now that we have the source port, report the accepted connection.
    emit(
        &event_tx,
        ProxyEvent::ConnectionAccepted {
            peer,
            src_port,
            target_ip: IpAddr::V4(connect_ip),
        },
    );

    let key = FlowKey {
        src_ip: interface_ip,
        src_port,
        dst_ip: connect_ip,
        dst_port: connect_port,
    };

    // A remote controller resolves this future only after the root helper has
    // inserted the flow. The upstream connect below must never move above it.
    let entry = flow_controller
        .register_flow(key, target.fake_client_hello, None)
        .await
        .context("register intercepted flow")?;

    // Make sure we always remove the entry on this path's exit.
    let cleanup = scopeguard(|| {
        flow_controller.remove_flow(key);
    });

    // Connect: while this is happening, the kernel emits SYN, receives SYN-ACK,
    // and sends the bare ACK that the interceptor will rewrite.
    let mut outgoing = match socket
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

    let mut client_fragmentation_after_prefix = None;

    // Wait until the interceptor either completes a fake-packet bypass or asks
    // us to send the first real ClientHello while the flow is still tracked.
    match wait_for_initial_bypass_progress(&entry, settings.bypass_timeout).await {
        Some(BypassProgress::Complete(outcome)) => {
            finish_bypass_or_error(
                &entry,
                &event_tx,
                src_port,
                Some(outcome),
                "bypass timed out",
            )?;
        }
        Some(BypassProgress::ReadyForData) => {
            // `ccs_prefix`: the dummy ChangeCipherSpec must be the very first
            // bytes written upstream, before any ClientHello write below.
            if let Some(ccs) = settings.ccs_prefix {
                outgoing
                    .set_nodelay(true)
                    .context("ccs_prefix: set_nodelay on upstream socket")?;
                if let Err(e) = write_ccs_prefix(&mut outgoing, ccs).await {
                    entry.finish(BypassOutcome::UnexpectedClose);
                    emit(
                        &event_tx,
                        ProxyEvent::BypassComplete {
                            src_port,
                            outcome: BypassOutcome::UnexpectedClose,
                        },
                    );
                    return Err(e).context("ccs_prefix: writing ChangeCipherSpec prefix");
                }
            }
            if let Some(boundary) = settings.sni_boundary_frag {
                // The boundary split needs two cleanly separated segments.
                outgoing
                    .set_nodelay(true)
                    .context("combo sni_boundary_frag: set_nodelay on upstream socket")?;

                let client_hello = read_client_tls_record_with_timeout(
                    &mut incoming,
                    settings.bypass_timeout,
                    &entry,
                    &event_tx,
                    src_port,
                )
                .await?;
                let client_hello = settings.apply_socket_transforms(&client_hello);

                match boundary.split_offset(&client_hello) {
                    Some(split) => {
                        if let Err(e) = write_boundary_split(
                            &mut outgoing,
                            &client_hello,
                            split,
                            boundary.delay_ms,
                        )
                        .await
                        {
                            entry.finish(BypassOutcome::UnexpectedClose);
                            emit(
                                &event_tx,
                                ProxyEvent::BypassComplete {
                                    src_port,
                                    outcome: BypassOutcome::UnexpectedClose,
                                },
                            );
                            return Err(e).context(
                                "combo sni_boundary_frag: writing boundary-split ClientHello",
                            );
                        }
                    }
                    None => {
                        // Fail-open: no SNI boundary found; forward whole.
                        if let Err(e) = outgoing.write_all(&client_hello).await {
                            entry.finish(BypassOutcome::UnexpectedClose);
                            emit(
                                &event_tx,
                                ProxyEvent::BypassComplete {
                                    src_port,
                                    outcome: BypassOutcome::UnexpectedClose,
                                },
                            );
                            return Err(e).context(
                                "combo sni_boundary_frag: writing ClientHello to upstream",
                            );
                        }
                        if let Err(e) = outgoing.flush().await {
                            entry.finish(BypassOutcome::UnexpectedClose);
                            emit(
                                &event_tx,
                                ProxyEvent::BypassComplete {
                                    src_port,
                                    outcome: BypassOutcome::UnexpectedClose,
                                },
                            );
                            return Err(e).context(
                                "combo sni_boundary_frag: flushing ClientHello to upstream",
                            );
                        }
                    }
                }

                // With tls_frag also listed, later client writes are
                // segmented per its settings. Write index 1 was the
                // ClientHello above, so the relay resumes at 2.
                if settings.segment_first_client_hello {
                    client_fragmentation_after_prefix = Some((settings.tcp_segmentation, 1));
                }
            } else if settings.segment_first_client_hello {
                let segmentation = settings.tcp_segmentation;
                if segmentation.nodelay {
                    outgoing
                        .set_nodelay(true)
                        .context("combo tls_frag: set_nodelay on upstream socket")?;
                }

                match segmentation.packets {
                    TlsFragPackets::TlsHello => {
                        let client_hello = read_client_tls_record_with_timeout(
                            &mut incoming,
                            settings.bypass_timeout,
                            &entry,
                            &event_tx,
                            src_port,
                        )
                        .await?;
                        let client_hello = settings.apply_socket_transforms(&client_hello);
                        if let Err(e) = write_fragmented(
                            &mut outgoing,
                            &client_hello,
                            segmentation.length,
                            segmentation.interval_ms,
                        )
                        .await
                        {
                            entry.finish(BypassOutcome::UnexpectedClose);
                            emit(
                                &event_tx,
                                ProxyEvent::BypassComplete {
                                    src_port,
                                    outcome: BypassOutcome::UnexpectedClose,
                                },
                            );
                            return Err(e)
                                .context("combo tls_frag: writing fragmented ClientHello");
                        }
                    }
                    TlsFragPackets::WriteRange { .. } => {
                        let client_data = read_client_write_with_timeout(
                            &mut incoming,
                            settings.bypass_timeout,
                            &entry,
                            &event_tx,
                            src_port,
                        )
                        .await?;
                        // Fail-open: transform only when the first write parses as a
                        // complete ClientHello record.
                        let client_data = settings.apply_socket_transforms(&client_data);
                        if let Err(e) =
                            write_client_data(&mut outgoing, &client_data, segmentation, 1).await
                        {
                            entry.finish(BypassOutcome::UnexpectedClose);
                            emit(
                                &event_tx,
                                ProxyEvent::BypassComplete {
                                    src_port,
                                    outcome: BypassOutcome::UnexpectedClose,
                                },
                            );
                            return Err(e).context("combo tls_frag: writing first client data");
                        }
                        client_fragmentation_after_prefix = Some((segmentation, 1));
                    }
                }
            } else {
                let client_hello = read_client_tls_record_with_timeout(
                    &mut incoming,
                    settings.bypass_timeout,
                    &entry,
                    &event_tx,
                    src_port,
                )
                .await?;

                let client_hello = settings.apply_socket_transforms(&client_hello);

                if let Err(e) = outgoing.write_all(&client_hello).await {
                    entry.finish(BypassOutcome::UnexpectedClose);
                    emit(
                        &event_tx,
                        ProxyEvent::BypassComplete {
                            src_port,
                            outcome: BypassOutcome::UnexpectedClose,
                        },
                    );
                    return Err(e).context("writing ClientHello to upstream");
                }
                if let Err(e) = outgoing.flush().await {
                    entry.finish(BypassOutcome::UnexpectedClose);
                    emit(
                        &event_tx,
                        ProxyEvent::BypassComplete {
                            src_port,
                            outcome: BypassOutcome::UnexpectedClose,
                        },
                    );
                    return Err(e).context("flushing ClientHello to upstream");
                }
            }

            let outcome = wait_for_bypass_completion(&entry, settings.bypass_timeout).await;
            finish_bypass_or_error(
                &entry,
                &event_tx,
                src_port,
                outcome,
                "first data bypass timed out",
            )?;
        }
        None => {
            finish_bypass_or_error(&entry, &event_tx, src_port, None, "bypass timed out")?;
        }
    }

    debug!(?key, "bypass complete");

    // Release the flow before relaying so any further packets pass through.
    // Fragment-all mode (ip_frag / disorder with *_ONLY_FIRST_PACKET =
    // false) keeps the flow registered: the interceptor continues rewriting
    // outbound data packets, and the scopeguard removes the entry when this
    // task exits after the relay ends.
    if !settings.fragment_all_data {
        drop(cleanup);
    }

    // Bidirectional relay with periodic progress events.
    let relay = counting_relay_with_client_fragmentation(
        incoming,
        outgoing,
        &event_tx,
        src_port,
        settings.max_lifetime,
        client_fragmentation_after_prefix,
    )
    .await;
    debug!(
        c2s_bytes = relay.c2s_bytes,
        s2c_bytes = relay.s2c_bytes,
        reason = ?relay.reason,
        "relay finished"
    );
    emit(
        &event_tx,
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes: relay.c2s_bytes,
            s2c_bytes: relay.s2c_bytes,
            reason: relay.reason,
        },
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// IP-bypass-plus proxy (IP selection + real-SNI-preserving bypass methods)
// ---------------------------------------------------------------------------

/// Run the IP-bypass-plus proxy.
///
/// The active target is an IP selected by the IP scanner, like `ip_bypass`.
/// Unlike plain `ip_bypass`, this mode may apply a real-SNI-preserving
/// ClientHello bypass method:
///
/// - `tls_frag`: socket-only segmentation, no packet interceptor.
/// - `tls_record_frag`: packet interceptor rewrites the first real ClientHello
///   into TLS record fragments. The flow stores an empty fake payload because
///   no fake SNI packet is emitted.
///
/// This mode is intentionally IPv4-only so the interceptor path can use the
/// existing IPv4 flow tracking and platform filters.
pub async fn run_ip_bypass_plus_proxy(
    cfg: Arc<Config>,
    active_ip: Arc<RwLock<IpAddr>>,
    interface_ip: Ipv4Addr,
    flow_controller: Arc<dyn FlowController>,
    event_tx: Option<ProxyEventSender>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
        .parse()
        .context("invalid LISTEN_HOST/LISTEN_PORT")?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind {listen_addr}"))?;
    info!(%listen_addr, method = %cfg.BYPASS_METHOD, "ip_bypass_plus: listening");
    emit(
        &event_tx,
        ProxyEvent::ListenerStarted {
            mode: cfg.MODE.clone(),
            listen_addr,
        },
    );

    loop {
        let (incoming, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "ip_bypass_plus: accept failed");
                continue;
            }
        };
        debug!(%peer, "ip_bypass_plus: accepted");

        let connect_ip = match *active_ip.read().unwrap() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(ip) => {
                warn!(%ip, "ip_bypass_plus: active IPv6 target rejected");
                continue;
            }
        };

        if cfg.BYPASS_METHOD.is_socket_only() {
            let cfg = cfg.clone();
            let event_tx = event_tx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_tcp_seg_connection_with_ip(cfg, connect_ip, incoming, peer, event_tx)
                        .await
                {
                    warn!(%peer, error = %e, "ip_bypass_plus tls_frag connection failed");
                }
            });
            continue;
        }

        let flow_controller = flow_controller.clone();
        let event_tx = event_tx.clone();
        let connection_settings = ConnectionSettings::from_config(&cfg);
        tokio::spawn(async move {
            if let Err(e) = handle_intercept_connection(
                InterceptConnectionTarget {
                    interface_ip,
                    connect_ip,
                    fake_client_hello: Vec::new(),
                },
                flow_controller,
                incoming,
                peer,
                event_tx,
                connection_settings,
            )
            .await
            {
                warn!(%peer, error = %e, "ip_bypass_plus connection failed");
            }
        });
    }
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
// tls_frag proxy path (no packet interceptor)
// ---------------------------------------------------------------------------

/// Handle a single connection using the `tls_frag` bypass method.
///
/// Does **not** register a flow in the [`FlowTable`] and does **not** involve
/// the platform packet interceptor.  Instead:
///
/// 1. Connects to the upstream server (with `TCP_NODELAY` if configured).
/// 2. In `tlshello` mode, reads and fragments the first complete TLS record.
/// 3. In packet-range mode, lets the relay fragment selected client writes.
/// 4. Hands off to the normal bidirectional relay for all unselected data.
async fn handle_tcp_seg_connection_with_ip(
    cfg: Arc<Config>,
    connect_ip: Ipv4Addr,
    mut incoming: TcpStream,
    peer: SocketAddr,
    event_tx: Option<ProxyEventSender>,
) -> anyhow::Result<()> {
    let src_port = peer.port();
    emit(
        &event_tx,
        ProxyEvent::ConnectionAccepted {
            peer,
            src_port,
            target_ip: IpAddr::V4(connect_ip),
        },
    );

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
            return Err(e).context("tls_frag: connect upstream");
        }
    };

    // Enable TCP_NODELAY on the upstream socket if configured. The boundary
    // split depends on two cleanly separated segments, so sni_boundary_frag
    // always forces it.
    if method.nodelay
        || cfg.BYPASS_METHOD.contains("sni_boundary_frag")
        || cfg.BYPASS_METHOD.contains("ccs_prefix")
    {
        outgoing
            .set_nodelay(true)
            .context("set_nodelay on upstream socket")?;
    }

    // `ccs_prefix`: write the dummy ChangeCipherSpec as the very first
    // upstream bytes; every ClientHello write below follows it.  When
    // `ccs_prefix` is listed alone, the relay then forwards the client's
    // stream untouched — the CCS is still the first record on the wire.
    if cfg.BYPASS_METHOD.contains("ccs_prefix") {
        write_ccs_prefix(&mut outgoing, CcsPrefix::new(&cfg))
            .await
            .context("ccs_prefix: writing ChangeCipherSpec prefix")?;
    }

    // When tls_padding and/or mixed_case_sni are listed, read the first TLS
    // record and transform it before any mode-specific handling. Fail-open:
    // unparseable records are forwarded unchanged.
    let transformed_prefix = if cfg.BYPASS_METHOD.contains("tls_padding")
        || cfg.BYPASS_METHOD.contains("mixed_case_sni")
    {
        let record = read_one_tls_record(&mut incoming)
            .await
            .context("socket transforms: reading ClientHello from client")?;
        let record = if cfg.BYPASS_METHOD.contains("tls_padding") {
            TlsPadding::new(&cfg).apply(&record).unwrap_or(record)
        } else {
            record
        };
        let record = if cfg.BYPASS_METHOD.contains("mixed_case_sni") {
            MixedCaseSni::new(&cfg).apply(&record).unwrap_or(record)
        } else {
            record
        };
        Some(record)
    } else {
        None
    };

    let boundary = cfg
        .BYPASS_METHOD
        .contains("sni_boundary_frag")
        .then(|| SniBoundaryFrag::new(&cfg));
    let segment_tlshello =
        cfg.BYPASS_METHOD.contains("tls_frag") && method.packets == TlsFragPackets::TlsHello;
    let needs_first_record = boundary.is_some() || segment_tlshello;

    // One TLS record is read at most once, transformed first when
    // tls_padding / mixed_case_sni are listed.
    let first_record = if needs_first_record {
        Some(match transformed_prefix {
            Some(record) => record,
            None => read_one_tls_record(&mut incoming)
                .await
                .context("socket path: reading ClientHello from client")?,
        })
    } else {
        transformed_prefix
    };

    let client_fragmentation = match (boundary, first_record) {
        (Some(boundary), Some(record)) => {
            match boundary.split_offset(&record) {
                Some(split) => {
                    write_boundary_split(&mut outgoing, &record, split, boundary.delay_ms)
                        .await
                        .context("sni_boundary_frag: writing boundary-split ClientHello")?;
                    debug!(
                        split,
                        delay_ms = %boundary.delay_ms,
                        total_bytes = record.len(),
                        "sni_boundary_frag: ClientHello written in two boundary segments; handing off to relay"
                    );
                }
                None => {
                    // Fail-open: no SNI boundary found; forward whole.
                    outgoing
                        .write_all(&record)
                        .await
                        .context("sni_boundary_frag: writing ClientHello whole (fail-open)")?;
                    outgoing
                        .flush()
                        .await
                        .context("sni_boundary_frag: flushing ClientHello")?;
                }
            }
            // The first client write was consumed above; with tls_frag also
            // listed, later writes are segmented per its settings.
            if cfg.BYPASS_METHOD.contains("tls_frag") {
                Some((method, 1))
            } else {
                None
            }
        }
        (None, Some(client_hello)) if segment_tlshello => {
            write_fragmented(
                &mut outgoing,
                &client_hello,
                method.length,
                method.interval_ms,
            )
            .await
            .context("tls_frag: writing fragmented ClientHello")?;
            debug!(
                length = %method.length,
                interval_ms = %method.interval_ms,
                nodelay = method.nodelay,
                total_bytes = client_hello.len(),
                "tls_frag: ClientHello written in fragments; handing off to relay"
            );
            None
        }
        (None, first_record) => {
            if let Some(record) = first_record {
                outgoing
                    .write_all(&record)
                    .await
                    .context("tls_padding: writing padded ClientHello")?;
                outgoing
                    .flush()
                    .await
                    .context("tls_padding: flushing padded ClientHello")?;
            }
            if cfg.BYPASS_METHOD.contains("tls_frag") {
                debug!(
                    packets = ?method.packets,
                    length = %method.length,
                    interval_ms = %method.interval_ms,
                    nodelay = method.nodelay,
                    "tls_frag: fragmenting selected client writes in relay"
                );
                Some((method, 0))
            } else {
                None
            }
        }
        // `boundary.is_some()` implies `needs_first_record`, so the record is
        // always present when a boundary method is configured.
        (Some(_), None) => unreachable!("boundary method implies a first record"),
    };

    emit(
        &event_tx,
        ProxyEvent::BypassComplete {
            src_port,
            outcome: BypassOutcome::FakeDataAcked,
        },
    );

    // Bidirectional relay for the rest of the session.
    // In tlshello mode, the ClientHello has already been forwarded; in write
    // range mode, selected client writes are fragmented by the relay itself.
    let relay = counting_relay_with_client_fragmentation(
        incoming,
        outgoing,
        &event_tx,
        src_port,
        configured_relay_max_lifetime(&cfg),
        client_fragmentation,
    )
    .await;
    debug!(
        c2s_bytes = relay.c2s_bytes,
        s2c_bytes = relay.s2c_bytes,
        reason = ?relay.reason,
        "tls_frag: relay finished"
    );
    emit(
        &event_tx,
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes: relay.c2s_bytes,
            s2c_bytes: relay.s2c_bytes,
            reason: relay.reason,
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
/// Returns the total bytes transferred in each direction plus the reason the
/// relay ended.  Shutdown of each write half is handled internally when the
/// corresponding read half reaches EOF.
async fn counting_relay(
    incoming: TcpStream,
    outgoing: TcpStream,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
    max_lifetime: Option<Duration>,
) -> RelayResult {
    counting_relay_with_client_fragmentation(
        incoming,
        outgoing,
        event_tx,
        src_port,
        max_lifetime,
        None,
    )
    .await
}

async fn counting_relay_with_client_fragmentation(
    incoming: TcpStream,
    outgoing: TcpStream,
    event_tx: &Option<ProxyEventSender>,
    src_port: u16,
    max_lifetime: Option<Duration>,
    client_fragmentation: Option<(TcpSegmentation, u32)>,
) -> RelayResult {
    let (inc_rd, inc_wr) = incoming.into_split();
    let (out_rd, out_wr) = outgoing.into_split();

    let c2s_atomic = Arc::new(AtomicU64::new(0));
    let s2c_atomic = Arc::new(AtomicU64::new(0));

    let mut c2s_task = tokio::spawn(copy_counting_client_to_server(
        inc_rd,
        out_wr,
        c2s_atomic.clone(),
        client_fragmentation,
    ));
    let mut s2c_task = tokio::spawn(copy_counting(out_rd, inc_wr, s2c_atomic.clone()));

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

    let result = if let Some(max_lifetime) = max_lifetime {
        let mut c2s_done: Option<u64> = None;
        let mut s2c_done: Option<u64> = None;
        let deadline = tokio::time::sleep(max_lifetime);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => {
                    if c2s_done.is_none() {
                        c2s_task.abort();
                    }
                    if s2c_done.is_none() {
                        s2c_task.abort();
                    }
                    break RelayResult {
                        c2s_bytes: c2s_done.unwrap_or_else(|| c2s_atomic.load(Ordering::Relaxed)),
                        s2c_bytes: s2c_done.unwrap_or_else(|| s2c_atomic.load(Ordering::Relaxed)),
                        reason: RelayEndReason::MaxLifetime,
                    };
                }
                c2s_result = &mut c2s_task, if c2s_done.is_none() => {
                    c2s_done = Some(c2s_result.unwrap_or(0));
                    if let (Some(c2s_bytes), Some(s2c_bytes)) = (c2s_done, s2c_done) {
                        break RelayResult {
                            c2s_bytes,
                            s2c_bytes,
                            reason: RelayEndReason::Completed,
                        };
                    }
                }
                s2c_result = &mut s2c_task, if s2c_done.is_none() => {
                    s2c_done = Some(s2c_result.unwrap_or(0));
                    if let (Some(c2s_bytes), Some(s2c_bytes)) = (c2s_done, s2c_done) {
                        break RelayResult {
                            c2s_bytes,
                            s2c_bytes,
                            reason: RelayEndReason::Completed,
                        };
                    }
                }
            }
        }
    } else {
        let (c2s_result, s2c_result) = tokio::join!(c2s_task, s2c_task);
        RelayResult {
            c2s_bytes: c2s_result.unwrap_or(0),
            s2c_bytes: s2c_result.unwrap_or(0),
            reason: RelayEndReason::Completed,
        }
    };

    if let Some(t) = ticker {
        t.abort();
    }

    result
}

/// Copy all bytes from `reader` to `writer`, updating `counter` after each
/// chunk.  Shuts down `writer` gracefully on EOF or error, then returns the
/// total bytes copied.
async fn copy_counting_client_to_server(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    counter: Arc<AtomicU64>,
    client_fragmentation: Option<(TcpSegmentation, u32)>,
) -> u64 {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    let mut write_index = client_fragmentation.map(|(_, index)| index).unwrap_or(0);
    let segmentation = client_fragmentation.map(|(segmentation, _)| segmentation);

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };

        write_index = write_index.saturating_add(1);
        let write_result = if let Some(segmentation) = segmentation {
            write_client_data(&mut writer, &buf[..n], segmentation, write_index).await
        } else {
            writer
                .write_all(&buf[..n])
                .await
                .map_err(anyhow::Error::from)
        };

        if write_result.is_err() {
            break;
        }
        total += n as u64;
        counter.store(total, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
    total
}

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
    emit(
        &event_tx,
        ProxyEvent::ListenerStarted {
            mode: cfg.MODE.clone(),
            listen_addr,
        },
    );

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
        let relay_max_lifetime = configured_relay_max_lifetime(&cfg);

        tokio::spawn(async move {
            if let Err(e) = handle_ip_bypass_connection(
                ip,
                incoming,
                peer,
                src_port,
                event_tx,
                relay_max_lifetime,
            )
            .await
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
    relay_max_lifetime: Option<Duration>,
) -> anyhow::Result<()> {
    let connect_addr = SocketAddr::new(connect_ip, CONNECT_PORT);
    emit(
        &event_tx,
        ProxyEvent::ConnectionAccepted {
            peer,
            src_port,
            target_ip: connect_ip,
        },
    );

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

    let relay = counting_relay(incoming, outgoing, &event_tx, src_port, relay_max_lifetime).await;
    debug!(
        c2s_bytes = relay.c2s_bytes,
        s2c_bytes = relay.s2c_bytes,
        reason = ?relay.reason,
        "ip_bypass: relay finished"
    );
    emit(
        &event_tx,
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes: relay.c2s_bytes,
            s2c_bytes: relay.s2c_bytes,
            reason: relay.reason,
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    use super::*;
    use tokio::io::AsyncWrite;

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = TcpStream::connect(addr);
        let accept = listener.accept();
        let (client, accepted) = tokio::join!(connect, accept);
        (client.unwrap(), accepted.unwrap().0)
    }

    #[derive(Default)]
    struct RecordingWriter {
        writes: Vec<Vec<u8>>,
    }

    impl AsyncWrite for RecordingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.writes.push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn test_segmentation() -> TcpSegmentation {
        TcpSegmentation {
            packets: TlsFragPackets::WriteRange { start: 1, end: 1 },
            length: crate::config::Int32Range::exact(1),
            interval_ms: crate::config::Int32Range::exact(0),
            nodelay: true,
        }
    }

    #[tokio::test]
    async fn relay_without_max_lifetime_completes_on_eof() {
        let (mut client, incoming) = tcp_pair().await;
        let (mut upstream, outgoing) = tcp_pair().await;

        let relay = tokio::spawn(counting_relay(incoming, outgoing, &None, 1234, None));

        client.write_all(b"ping").await.unwrap();
        let mut upstream_buf = [0u8; 4];
        upstream.read_exact(&mut upstream_buf).await.unwrap();
        assert_eq!(&upstream_buf, b"ping");

        upstream.write_all(b"pong").await.unwrap();
        let mut client_buf = [0u8; 4];
        client.read_exact(&mut client_buf).await.unwrap();
        assert_eq!(&client_buf, b"pong");

        client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.reason, RelayEndReason::Completed);
        assert_eq!(result.c2s_bytes, 4);
        assert_eq!(result.s2c_bytes, 4);
    }

    #[tokio::test]
    async fn relay_with_max_lifetime_rotates_open_connection() {
        let (_client, incoming) = tcp_pair().await;
        let (_upstream, outgoing) = tcp_pair().await;

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            counting_relay(
                incoming,
                outgoing,
                &None,
                1234,
                Some(Duration::from_millis(25)),
            ),
        )
        .await
        .unwrap();

        assert_eq!(result.reason, RelayEndReason::MaxLifetime);
        assert_eq!(result.c2s_bytes, 0);
        assert_eq!(result.s2c_bytes, 0);
    }

    #[tokio::test]
    async fn selected_client_write_is_fragmented() {
        let mut writer = RecordingWriter::default();

        write_client_data(&mut writer, b"abc", test_segmentation(), 1)
            .await
            .unwrap();

        assert_eq!(
            writer.writes,
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
    }

    #[tokio::test]
    async fn unselected_client_write_is_forwarded_once() {
        let mut writer = RecordingWriter::default();

        write_client_data(&mut writer, b"abc", test_segmentation(), 2)
            .await
            .unwrap();

        assert_eq!(writer.writes, vec![b"abc".to_vec()]);
    }

    #[tokio::test]
    async fn relay_rotation_preserves_bytes_copied_before_expiry() {
        let (mut client, incoming) = tcp_pair().await;
        let (mut upstream, outgoing) = tcp_pair().await;

        let relay = tokio::spawn(counting_relay(
            incoming,
            outgoing,
            &None,
            1234,
            Some(Duration::from_millis(50)),
        ));

        client.write_all(b"hello").await.unwrap();
        let mut upstream_buf = [0u8; 5];
        upstream.read_exact(&mut upstream_buf).await.unwrap();
        assert_eq!(&upstream_buf, b"hello");

        let result = tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.reason, RelayEndReason::MaxLifetime);
        assert_eq!(result.c2s_bytes, 5);
        assert_eq!(result.s2c_bytes, 0);
    }

    #[test]
    fn tls_padding_in_list_populates_settings() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["wrong_seq", "tls_padding"]
               TLS_PADDING_SIZE = "2000-3000"
               TLS_PADDING_POSITION = "after""#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        let padding = settings.tls_padding.expect("tls_padding is listed");
        assert_eq!(
            padding.size,
            crate::config::Int32Range::parse("2000-3000").unwrap()
        );
        assert_eq!(
            padding.position,
            crate::methods::tls_padding::PaddingPosition::After
        );
    }

    #[test]
    fn socket_only_lists_disable_padding_settings() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "tls_frag""#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(settings.tls_padding.is_none());
    }

    #[test]
    fn tls_frag_in_list_segments_first_client_hello() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["wrong_seq", "tls_frag"]"#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(settings.segment_first_client_hello);

        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "wrong_seq_tls_record_frag""#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(!settings.segment_first_client_hello);
    }

    #[test]
    fn ip_frag_fragment_all_populates_settings() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "ip_frag"
               IP_FRAG_ONLY_FIRST_PACKET = false"#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(settings.fragment_all_data);
    }

    #[test]
    fn ip_frag_only_first_leaves_settings_false() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "ip_frag""#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(!settings.fragment_all_data);
    }

    #[test]
    fn disorder_fragment_all_populates_settings() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "disorder"
               DISORDER_ONLY_FIRST_PACKET = false"#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(settings.fragment_all_data);
    }

    #[test]
    fn disorder_only_first_leaves_settings_false() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "disorder""#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(!settings.fragment_all_data);
    }

    #[test]
    fn unrelated_methods_leave_fragment_all_false() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["wrong_seq", "tls_frag"]
               IP_FRAG_ONLY_FIRST_PACKET = false"#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(!settings.fragment_all_data);
    }

    #[test]
    fn rescan_events_construct_with_kind_and_interval() {
        let started = ProxyEvent::RescanStarted {
            kind: RescanKind::Sni,
        };
        let finished = ProxyEvent::RescanFinished {
            kind: RescanKind::Ip,
            found: 0,
            best_score: None,
            duration_ms: 0,
            switched: false,
        };
        let scheduled = ProxyEvent::NextRescanScheduled {
            kind: RescanKind::Sni,
            interval_secs: 300,
        };
        assert_eq!(format!("{started:?}"), "RescanStarted { kind: Sni }");
        assert_eq!(
            format!("{finished:?}"),
            "RescanFinished { kind: Ip, found: 0, best_score: None, duration_ms: 0, switched: false }"
        );
        assert_eq!(
            format!("{scheduled:?}"),
            "NextRescanScheduled { kind: Sni, interval_secs: 300 }"
        );
    }

    #[test]
    fn connection_accepted_event_carries_target_ip() {
        let peer: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let target: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let ev = ProxyEvent::ConnectionAccepted {
            peer,
            src_port: 4242,
            target_ip: target,
        };
        match ev {
            ProxyEvent::ConnectionAccepted { target_ip, .. } => {
                assert_eq!(target_ip, target);
            }
            _ => panic!("expected ConnectionAccepted"),
        }
    }

    fn cfg_with(method_line: &str, extra: &str) -> Config {
        toml::from_str(&format!(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               {method_line}
               {extra}"#
        ))
        .unwrap()
    }

    fn swap_case(b: u8) -> u8 {
        if b.is_ascii_lowercase() {
            b.to_ascii_uppercase()
        } else {
            b.to_ascii_lowercase()
        }
    }

    #[test]
    fn settings_include_mixed_case_sni_when_listed() {
        let cfg = cfg_with(r#"BYPASS_METHOD = ["wrong_seq", "mixed_case_sni"]"#, "");
        let s = ConnectionSettings::from_config(&cfg);
        assert!(s.mixed_case_sni.is_some());
        assert!(s.tls_padding.is_none());

        let cfg = cfg_with(r#"BYPASS_METHOD = "tls_padding""#, "");
        let s = ConnectionSettings::from_config(&cfg);
        assert!(s.mixed_case_sni.is_none());
        assert!(s.tls_padding.is_some());
    }

    #[test]
    fn apply_socket_transforms_chains_padding_then_case_randomization() {
        let cfg = cfg_with(
            r#"BYPASS_METHOD = ["tls_padding", "mixed_case_sni"]"#,
            r#"TLS_PADDING_SIZE = 4
               MIXED_CASE_SNI_FLIP_ALL = true"#,
        );
        let settings = ConnectionSettings::from_config(&cfg);
        let record = crate::tls_template::build_client_hello(
            &[0u8; 32],
            &[0u8; 32],
            b"wikipedia.org",
            &[0u8; 32],
        );
        let out = settings.apply_socket_transforms(&record);
        // padding extension header (4 bytes) + 4 zero bytes
        assert_eq!(out.len(), record.len() + 8);
        // SNI was at offset 127; padding moved it by 8 bytes
        let (start, len) =
            crate::methods::sni::find_sni_range(&out).expect("transformed record must still parse");
        assert_eq!((start, len), (127 + 8, 13));
        for (i, &orig) in b"wikipedia.org".iter().enumerate() {
            let got = out[start + i];
            if orig.is_ascii_alphabetic() {
                assert_eq!(got, swap_case(orig), "letter {i} must be case-inverted");
            } else {
                assert_eq!(got, orig, "non-alpha byte {i} must be untouched");
            }
        }
    }

    #[test]
    fn sni_boundary_frag_in_list_populates_settings() {
        let cfg = cfg_with(
            r#"BYPASS_METHOD = ["wrong_seq", "sni_boundary_frag"]"#,
            r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = "middle"
               SNI_BOUNDARY_FRAG_DELAY_MS = "7-9""#,
        );
        let settings = ConnectionSettings::from_config(&cfg);
        let boundary = settings
            .sni_boundary_frag
            .expect("sni_boundary_frag is listed");
        assert_eq!(
            boundary.split_point,
            crate::config::SniBoundarySplitPoint::Middle
        );
        assert_eq!(
            boundary.delay_ms,
            crate::config::Int32Range::parse("7-9").unwrap()
        );
        assert!(!settings.segment_first_client_hello);
    }

    #[test]
    fn socket_only_list_keeps_sni_boundary_frag_settings() {
        let cfg = cfg_with(r#"BYPASS_METHOD = "sni_boundary_frag""#, "");
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(settings.sni_boundary_frag.is_some());
    }

    #[test]
    fn other_lists_leave_sni_boundary_frag_unset() {
        let cfg = cfg_with(r#"BYPASS_METHOD = "tls_frag""#, "");
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(settings.sni_boundary_frag.is_none());
    }

    #[test]
    fn connection_settings_enable_ccs_prefix_from_config() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "ccs_prefix""#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert_eq!(settings.ccs_prefix, Some(CcsPrefix::exact(0x0303)));

        let plain: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap();
        assert!(ConnectionSettings::from_config(&plain).ccs_prefix.is_none());
    }

    #[tokio::test]
    async fn ccs_prefix_write_emits_the_six_byte_record() {
        let mut writer = RecordingWriter::default();
        write_ccs_prefix(&mut writer, CcsPrefix::exact(0x0303))
            .await
            .unwrap();
        assert_eq!(
            writer.writes,
            vec![vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01]]
        );
    }
}
