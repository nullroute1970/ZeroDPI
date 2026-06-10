//! Per-candidate proxy tester for `proxy_scan` mode.
//!
//! ## How it works
//!
//! For each SNI candidate that passed Phase 1 (the normal SNI scan), this
//! module:
//!
//! 1. Spins up ZeroDPI's full bypass engine on `LISTEN_HOST:LISTEN_PORT` with
//!    the candidate's SNI and IP.
//! 2. Connects to V2RayN's SOCKS5 mixed port (`PROXY_TEST_SOCKS5_HOST:PORT`)
//!    and requests the host extracted from `PROXY_TEST_URL`.
//! 3. Sends an HTTP/1.1 GET request, measures TCP latency to the SOCKS5
//!    proxy, TTFB through the full chain, and download speed.
//! 4. Tears down the bypass engine (dropping the WinDivert handle stops the
//!    intercept thread; aborting the proxy task stops the listener).
//! 5. Computes `proxy_score` (0–100) and blends it with the Phase 1
//!    `sni_score` into `final_score`.
//!
//! ## Scoring formula
//!
//! | Component              | Max pts | Formula                                      |
//! |------------------------|---------|----------------------------------------------|
//! | Proxy TCP latency      | 20      | linear: 0 ms → 20, ≥ `LATENCY_CAP_MS` → 0   |
//! | Proxy TTFB             | 40      | linear: 0 ms → 40, ≥ `TTFB_CAP_MS` → 0      |
//! | Proxy download speed   | 40      | linear: 0 → 0, ≥ `SPEED_CAP_BPS` → 40       |
//!
//! `final_score = round(SNI_WEIGHT × sni_score + (1 − SNI_WEIGHT) × proxy_score)`

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::config::Config;
use crate::flow::new_flow_table;
use crate::handler::Handler;
use crate::interceptor::{FilterSpec, PacketInterceptor};
use crate::methods::build_method;
use crate::proxy::{run_proxy, ActiveSniTarget, CONNECT_PORT};
use crate::sni_scanner::SniProbeEntry;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// All measurements for one (SNI, IP) candidate after both phases.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyTestEntry {
    /// SNI hostname.
    pub sni: String,
    /// Cloudflare IP probed in Phase 1.
    pub ip: Ipv4Addr,
    /// Phase 1 SNI-scan score (0–100).
    pub sni_score: u8,
    /// Whether the SOCKS5 + HTTP probe succeeded at all.
    pub proxy_ok: bool,
    /// TCP connect latency to the SOCKS5 proxy (ms).
    pub proxy_tcp_ms: Option<u64>,
    /// Time-to-first-byte through the full chain (ms).
    pub proxy_ttfb_ms: Option<u64>,
    /// Download throughput through the full chain (bytes/sec).
    pub proxy_speed_bps: Option<f64>,
    /// HTTP status code returned through the proxy.
    pub proxy_http_status: Option<u16>,
    /// Proxy-test-only score (0–100).
    pub proxy_score: u8,
    /// Blended final score (0–100).
    pub final_score: u8,
}

impl ProxyTestEntry {
    /// Single-line summary suitable for console output.
    pub fn summary_line(&self) -> String {
        let proxy_ttfb = self
            .proxy_ttfb_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "—".into());
        let proxy_speed = self
            .proxy_speed_bps
            .map(|bps| {
                if bps >= 1_048_576.0 {
                    format!("{:.1}MB/s", bps / 1_048_576.0)
                } else {
                    format!("{:.0}KB/s", bps / 1024.0)
                }
            })
            .unwrap_or_else(|| "—".into());
        let status = if self.proxy_ok { "ok" } else { "fail" };
        format!(
            "  [final={final:>3} sni={sni_s:>3} proxy={proxy_s:>3}] {sni:<40} {ip:<16} proxy={status:<4} ttfb={ttfb:<8} speed={speed}",
            final = self.final_score,
            sni_s = self.sni_score,
            proxy_s = self.proxy_score,
            sni = self.sni,
            ip = self.ip,
            ttfb = proxy_ttfb,
            speed = proxy_speed,
        )
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run proxy tests for all `candidates` sequentially.
///
/// Each result is sent over `progress_tx` as soon as it is ready so the TUI
/// can show live progress.  The returned `Vec` is sorted by `final_score`
/// (descending).
///
/// `interface_ip` should be the local IPv4 address of the outbound interface;
/// pass the result of [`crate::net::default_interface_ipv4`] called with a Cloudflare IP.
pub async fn run_proxy_tests(
    candidates: Vec<SniProbeEntry>,
    config: Arc<Config>,
    interface_ip: Ipv4Addr,
    progress_tx: Option<mpsc::UnboundedSender<ProxyTestEntry>>,
) -> Vec<ProxyTestEntry> {
    let mut results = Vec::with_capacity(candidates.len());

    for candidate in &candidates {
        // run_proxy_tests is only used when no interceptor is needed (unit
        // tests / future headless mode).  For the real proxy_scan flow, see
        // test_candidate_full called from main.rs.
        let timeout = Duration::from_secs(config.PROXY_TEST_TIMEOUT_SECS);
        let active_target = Arc::new(std::sync::RwLock::new(ActiveSniTarget::new(
            candidate.sni.clone(),
            candidate.ip,
            candidate.sni_score(),
        )));
        let flows = new_flow_table();
        let probe =
            run_socks5_probe(config.clone(), active_target, flows, interface_ip, timeout).await;
        let entry = build_entry(candidate, probe, &config);
        debug!("{}", entry.summary_line());
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(entry.clone());
        }
        results.push(entry);
    }

    results.sort_by(|a, b| {
        b.final_score.cmp(&a.final_score).then(
            a.proxy_ttfb_ms
                .unwrap_or(u64::MAX)
                .cmp(&b.proxy_ttfb_ms.unwrap_or(u64::MAX)),
        )
    });
    results
}

// ---------------------------------------------------------------------------
// Interceptor-aware entry point (called from main.rs)
// ---------------------------------------------------------------------------

/// Full per-candidate test including starting/stopping the bypass engine.
///
/// The `interceptor_factory` closure opens the packet interceptor with the
/// given [`FilterSpec`] and spawns the intercept thread, returning a
/// join-handle.  Dropping the returned `InterceptHandle` stops the thread.
///
/// This function lives in `zerodpi-core` but is generic over the concrete
/// interceptor type, keeping platform code out of this crate.
pub async fn test_candidate_full<F, I>(
    candidate: &SniProbeEntry,
    config: Arc<Config>,
    interface_ip: Ipv4Addr,
    interceptor_factory: F,
) -> ProxyTestEntry
where
    F: FnOnce(FilterSpec) -> anyhow::Result<I> + Send + 'static,
    I: PacketInterceptor,
{
    let timeout = Duration::from_secs(config.PROXY_TEST_TIMEOUT_SECS);

    let active_target = Arc::new(std::sync::RwLock::new(ActiveSniTarget::new(
        candidate.sni.clone(),
        candidate.ip,
        candidate.sni_score(),
    )));

    if config.BYPASS_METHOD == "tls_frag" {
        let flows = new_flow_table();
        let probe_result =
            run_socks5_probe(config.clone(), active_target, flows, interface_ip, timeout).await;
        return build_entry(candidate, probe_result, &config);
    }

    let method_box = match build_method(&config) {
        Some(m) => m,
        None => {
            warn!("build_method returned None for proxy test — no method configured");
            return failed_entry(candidate, config.PROXY_TEST_SNI_WEIGHT);
        }
    };
    let method: Arc<dyn crate::methods::BypassMethod> = Arc::from(method_box);
    let flows = new_flow_table();

    // Open the packet interceptor for this candidate's IP.
    let filter = FilterSpec {
        interface_ip,
        remote_ip: Some(candidate.ip),
        remote_port: CONNECT_PORT,
        queue_num: config.NFQUEUE_NUM,
        linux_firewall_backend: config.linux_firewall_backend(),
    };

    let interceptor = match interceptor_factory(filter) {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, "failed to open packet interceptor for proxy test");
            return failed_entry(candidate, config.PROXY_TEST_SNI_WEIGHT);
        }
    };

    let handler = Handler::new(flows.clone(), method);
    // Spawn the intercept thread.  It exits naturally when the WinDivert
    // handle is closed (interceptor is dropped at end of this fn).
    let _intercept_thread = std::thread::Builder::new()
        .name(format!("zerodpi-intercept-test-{}", candidate.sni))
        .spawn(move || {
            if let Err(e) = interceptor.run(handler) {
                debug!(error = %e, "proxy_scan intercept thread ended");
            }
        });

    // Start the proxy listener on LISTEN_PORT.
    let probe_result =
        run_socks5_probe(config.clone(), active_target, flows, interface_ip, timeout).await;

    // When this function returns, `interceptor` was moved into the thread
    // closure. The thread will exit on the next recv() after the handle is
    // dropped inside the closure (WinDivert drop closes the handle).
    // The thread join is best-effort — we don't block on it.

    build_entry(candidate, probe_result, &config)
}

// ---------------------------------------------------------------------------
// SOCKS5 + HTTP probe
// ---------------------------------------------------------------------------

/// Outcome of a single SOCKS5 + HTTP GET probe.
struct ProbeResult {
    proxy_tcp_ms: Option<u64>,
    proxy_ttfb_ms: Option<u64>,
    proxy_speed_bps: Option<f64>,
    proxy_http_status: Option<u16>,
}

/// Start the proxy listener, run the SOCKS5 probe, abort the proxy task, and
/// return the measurements.
async fn run_socks5_probe(
    config: Arc<Config>,
    active_target: Arc<std::sync::RwLock<ActiveSniTarget>>,
    flows: crate::flow::FlowTable,
    interface_ip: Ipv4Addr,
    timeout: Duration,
) -> ProbeResult {
    // Spawn the proxy task.
    let cfg_clone = config.clone();
    let at_clone = active_target.clone();
    let fl_clone = flows.clone();
    let proxy_task = tokio::spawn(async move {
        let _ = run_proxy(cfg_clone, at_clone, interface_ip, fl_clone, None).await;
    });

    // Give the listener a moment to bind before connecting.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Parse the target host and port from PROXY_TEST_URL.
    let (target_host, target_port) = match parse_url_host_port(&config.PROXY_TEST_URL) {
        Some(hp) => hp,
        None => {
            warn!(url = %config.PROXY_TEST_URL, "cannot parse host/port from PROXY_TEST_URL");
            proxy_task.abort();
            return ProbeResult {
                proxy_tcp_ms: None,
                proxy_ttfb_ms: None,
                proxy_speed_bps: None,
                proxy_http_status: None,
            };
        }
    };

    let socks5_addr = format!(
        "{}:{}",
        config.PROXY_TEST_SOCKS5_HOST, config.PROXY_TEST_SOCKS5_PORT
    );

    let result = tokio::time::timeout(
        timeout,
        socks5_http_probe(
            &socks5_addr,
            &target_host,
            target_port,
            &config.PROXY_TEST_URL,
            &config,
        ),
    )
    .await;

    // Abort the proxy task — this closes the TcpListener on LISTEN_PORT.
    proxy_task.abort();

    match result {
        Ok(r) => r,
        Err(_) => {
            debug!(url = %config.PROXY_TEST_URL, "proxy test timed out");
            ProbeResult {
                proxy_tcp_ms: None,
                proxy_ttfb_ms: None,
                proxy_speed_bps: None,
                proxy_http_status: None,
            }
        }
    }
}

/// Connect to the SOCKS5 proxy, negotiate, issue an HTTP GET, and measure
/// TCP latency, TTFB, and download speed.
async fn socks5_http_probe(
    socks5_addr: &str,
    target_host: &str,
    target_port: u16,
    url: &str,
    config: &Config,
) -> ProbeResult {
    // --- TCP connect to SOCKS5 proxy ---
    let socks5_sa: SocketAddr = match socks5_addr.parse() {
        Ok(a) => a,
        Err(_) => {
            warn!(%socks5_addr, "invalid SOCKS5 address");
            return ProbeResult {
                proxy_tcp_ms: None,
                proxy_ttfb_ms: None,
                proxy_speed_bps: None,
                proxy_http_status: None,
            };
        }
    };

    let tcp_start = Instant::now();
    let mut stream = match TcpStream::connect(socks5_sa).await {
        Ok(s) => s,
        Err(e) => {
            debug!(error = %e, %socks5_addr, "SOCKS5 TCP connect failed");
            return ProbeResult {
                proxy_tcp_ms: None,
                proxy_ttfb_ms: None,
                proxy_speed_bps: None,
                proxy_http_status: None,
            };
        }
    };
    let proxy_tcp_ms = Some(tcp_start.elapsed().as_millis() as u64);

    // --- SOCKS5 greeting: version + no-auth ---
    if stream.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return ProbeResult {
            proxy_tcp_ms,
            proxy_ttfb_ms: None,
            proxy_speed_bps: None,
            proxy_http_status: None,
        };
    }
    let mut greeting_resp = [0u8; 2];
    if stream.read_exact(&mut greeting_resp).await.is_err()
        || greeting_resp[0] != 0x05
        || greeting_resp[1] != 0x00
    {
        debug!("SOCKS5 greeting rejected or unexpected response");
        return ProbeResult {
            proxy_tcp_ms,
            proxy_ttfb_ms: None,
            proxy_speed_bps: None,
            proxy_http_status: None,
        };
    }

    // --- SOCKS5 CONNECT request (domain name type = 0x03) ---
    let host_bytes = target_host.as_bytes();
    let host_len = host_bytes.len() as u8;
    let port_hi = (target_port >> 8) as u8;
    let port_lo = (target_port & 0xFF) as u8;
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x03, host_len];
    connect_req.extend_from_slice(host_bytes);
    connect_req.push(port_hi);
    connect_req.push(port_lo);

    if stream.write_all(&connect_req).await.is_err() {
        return ProbeResult {
            proxy_tcp_ms,
            proxy_ttfb_ms: None,
            proxy_speed_bps: None,
            proxy_http_status: None,
        };
    }

    // --- SOCKS5 CONNECT response: [ver, rep, rsv, atyp, ...] ---
    // Minimum response is 10 bytes (IPv4 bound address).
    let mut resp_hdr = [0u8; 4];
    if stream.read_exact(&mut resp_hdr).await.is_err() {
        debug!("SOCKS5 CONNECT response header read failed");
        return ProbeResult {
            proxy_tcp_ms,
            proxy_ttfb_ms: None,
            proxy_speed_bps: None,
            proxy_http_status: None,
        };
    }
    if resp_hdr[0] != 0x05 || resp_hdr[1] != 0x00 {
        debug!(rep = resp_hdr[1], "SOCKS5 CONNECT rejected");
        return ProbeResult {
            proxy_tcp_ms,
            proxy_ttfb_ms: None,
            proxy_speed_bps: None,
            proxy_http_status: None,
        };
    }
    // Drain the bound-address field depending on atyp.
    let skip = match resp_hdr[3] {
        0x01 => 4 + 2,  // IPv4 (4) + port (2)
        0x04 => 16 + 2, // IPv6 (16) + port (2)
        0x03 => {
            // Domain: 1-byte length prefix + domain + 2-byte port.
            let mut len_buf = [0u8; 1];
            if stream.read_exact(&mut len_buf).await.is_err() {
                return ProbeResult {
                    proxy_tcp_ms,
                    proxy_ttfb_ms: None,
                    proxy_speed_bps: None,
                    proxy_http_status: None,
                };
            }
            len_buf[0] as usize + 2
        }
        _ => 6, // fallback
    };
    let mut discard = vec![0u8; skip];
    if stream.read_exact(&mut discard).await.is_err() {
        return ProbeResult {
            proxy_tcp_ms,
            proxy_ttfb_ms: None,
            proxy_speed_bps: None,
            proxy_http_status: None,
        };
    }

    // --- HTTP GET ---
    // Extract the path from the URL (everything after host:port).
    let path = extract_url_path(url);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: zerodpi-proxy-scan/0.1\r\n\r\n",
        host = target_host,
    );

    let req_start = Instant::now();
    if stream.write_all(req.as_bytes()).await.is_err() {
        return ProbeResult {
            proxy_tcp_ms,
            proxy_ttfb_ms: None,
            proxy_speed_bps: None,
            proxy_http_status: None,
        };
    }
    let _ = stream.flush().await;

    // --- Read response: measure TTFB + speed ---
    let download_cap = config.SCAN_DOWNLOAD_CAP.max(524_288); // at least 512 KB
    let mut buf = vec![0u8; download_cap];
    let mut total_read = 0usize;
    let mut ttfb_ms: Option<u64> = None;
    let mut http_status: Option<u16> = None;

    loop {
        let remaining = download_cap - total_read;
        if remaining == 0 {
            break;
        }
        match stream.read(&mut buf[total_read..]).await {
            Ok(0) => break,
            Ok(n) => {
                if ttfb_ms.is_none() {
                    ttfb_ms = Some(req_start.elapsed().as_millis() as u64);
                    if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                        http_status = parse_http_status(text);
                    }
                }
                total_read += n;
            }
            Err(_) => break,
        }
    }

    let speed_bps = if total_read > 0 {
        let elapsed = req_start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            Some(total_read as f64 / elapsed)
        } else {
            None
        }
    } else {
        None
    };

    ProbeResult {
        proxy_tcp_ms,
        proxy_ttfb_ms: ttfb_ms,
        proxy_speed_bps: speed_bps,
        proxy_http_status: http_status,
    }
}

// ---------------------------------------------------------------------------
// Score computation
// ---------------------------------------------------------------------------

fn compute_proxy_score(result: &ProbeResult, config: &Config) -> u8 {
    let tcp_pts = match result.proxy_tcp_ms {
        None => 0.0,
        Some(ms) => 20.0 * (1.0 - (ms as f64 / config.PROXY_TEST_LATENCY_CAP_MS).min(1.0)),
    };
    let ttfb_pts = match result.proxy_ttfb_ms {
        None => 0.0,
        Some(ms) => 40.0 * (1.0 - (ms as f64 / config.PROXY_TEST_TTFB_CAP_MS).min(1.0)),
    };
    let speed_pts = match result.proxy_speed_bps {
        None => 0.0,
        Some(bps) => 40.0 * (bps / config.PROXY_TEST_SPEED_CAP_BPS).min(1.0),
    };
    (tcp_pts + ttfb_pts + speed_pts).round().min(100.0) as u8
}

fn blend_scores(sni_score: u8, proxy_score: u8, sni_weight: f64) -> u8 {
    let proxy_weight = 1.0 - sni_weight;
    (sni_weight * sni_score as f64 + proxy_weight * proxy_score as f64)
        .round()
        .clamp(0.0, 100.0) as u8
}

// ---------------------------------------------------------------------------
// Helper constructors
// ---------------------------------------------------------------------------

fn failed_entry(candidate: &SniProbeEntry, sni_weight: f64) -> ProxyTestEntry {
    let sni_score = candidate.sni_score();
    let final_score = blend_scores(sni_score, 0, sni_weight);
    ProxyTestEntry {
        sni: candidate.sni.clone(),
        ip: candidate.ip,
        sni_score,
        proxy_ok: false,
        proxy_tcp_ms: None,
        proxy_ttfb_ms: None,
        proxy_speed_bps: None,
        proxy_http_status: None,
        proxy_score: 0,
        final_score,
    }
}

fn build_entry(candidate: &SniProbeEntry, result: ProbeResult, config: &Config) -> ProxyTestEntry {
    let sni_score = candidate.sni_score();
    let proxy_ok = result.proxy_ttfb_ms.is_some();
    let proxy_score = compute_proxy_score(&result, config);
    let final_score = blend_scores(sni_score, proxy_score, config.PROXY_TEST_SNI_WEIGHT);
    ProxyTestEntry {
        sni: candidate.sni.clone(),
        ip: candidate.ip,
        sni_score,
        proxy_ok,
        proxy_tcp_ms: result.proxy_tcp_ms,
        proxy_ttfb_ms: result.proxy_ttfb_ms,
        proxy_speed_bps: result.proxy_speed_bps,
        proxy_http_status: result.proxy_http_status,
        proxy_score,
        final_score,
    }
}

// ---------------------------------------------------------------------------
// URL / HTTP helpers
// ---------------------------------------------------------------------------

/// Extract `(host, port)` from an `http://…` or `https://…` URL.
fn parse_url_host_port(url: &str) -> Option<(String, u16)> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let is_https = url.starts_with("https://");
    let default_port: u16 = if is_https { 443 } else { 80 };
    // Everything up to the first `/`, `?`, or end of string is the authority.
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if let Some(bracket_end) = authority.rfind(']') {
        // IPv6 literal: [::1]:port or [::1]
        let port = authority
            .get(bracket_end + 1..)
            .and_then(|s| s.strip_prefix(':'))
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        Some((authority[..=bracket_end].to_owned(), port))
    } else if let Some(colon) = authority.rfind(':') {
        let host = authority[..colon].to_owned();
        let port = authority[colon + 1..]
            .parse::<u16>()
            .unwrap_or(default_port);
        Some((host, port))
    } else {
        Some((authority.to_owned(), default_port))
    }
}

/// Extract the request path (including query) from a URL, defaulting to `/`.
fn extract_url_path(url: &str) -> &str {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // Find the first slash that separates the authority from the path.
    match rest.find('/') {
        Some(i) => &rest[i..],
        None => "/",
    }
}

/// Parse the HTTP status code from the first line of an HTTP/1.x response.
fn parse_http_status(text: &str) -> Option<u16> {
    let line = text.lines().next()?;
    let mut parts = line.splitn(3, ' ');
    parts.next(); // "HTTP/1.x"
    parts.next()?.parse::<u16>().ok()
}

// ---------------------------------------------------------------------------
// SniProbeEntry extension
// ---------------------------------------------------------------------------

trait SniProbeEntryExt {
    fn sni_score(&self) -> u8;
}

impl SniProbeEntryExt for SniProbeEntry {
    fn sni_score(&self) -> u8 {
        self.score
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_config() -> Config {
        toml::from_str("LISTEN_HOST=\"0.0.0.0\"\nLISTEN_PORT=44444\nMODE=\"proxy_scan\"").unwrap()
    }

    #[test]
    fn proxy_score_all_perfect() {
        let cfg = dummy_config();
        let result = ProbeResult {
            proxy_tcp_ms: Some(0),
            proxy_ttfb_ms: Some(0),
            proxy_speed_bps: Some(f64::MAX),
            proxy_http_status: Some(200),
        };
        assert_eq!(compute_proxy_score(&result, &cfg), 100);
    }

    #[test]
    fn proxy_score_all_failed() {
        let cfg = dummy_config();
        let result = ProbeResult {
            proxy_tcp_ms: None,
            proxy_ttfb_ms: None,
            proxy_speed_bps: None,
            proxy_http_status: None,
        };
        assert_eq!(compute_proxy_score(&result, &cfg), 0);
    }

    #[test]
    fn blend_equal_weight() {
        assert_eq!(blend_scores(80, 60, 0.5), 70);
    }

    #[test]
    fn blend_sni_only() {
        assert_eq!(blend_scores(80, 0, 1.0), 80);
    }

    #[test]
    fn blend_proxy_only() {
        assert_eq!(blend_scores(0, 60, 0.0), 60);
    }

    #[test]
    fn parse_url_https_with_path() {
        let (host, port) =
            parse_url_host_port("https://speed.cloudflare.com/__down?bytes=524288").unwrap();
        assert_eq!(host, "speed.cloudflare.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_url_with_explicit_port() {
        let (host, port) = parse_url_host_port("https://example.com:8443/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn extract_path_with_query() {
        assert_eq!(
            extract_url_path("https://speed.cloudflare.com/__down?bytes=524288"),
            "/__down?bytes=524288"
        );
    }

    #[test]
    fn extract_path_root() {
        assert_eq!(extract_url_path("https://example.com"), "/");
    }

    #[test]
    fn parse_http_200() {
        assert_eq!(parse_http_status("HTTP/1.1 200 OK\r\n"), Some(200));
    }
}
