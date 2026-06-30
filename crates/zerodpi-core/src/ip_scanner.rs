//! 4-phase IP scanner (TCP → TLS → TTFB → speed) used in `ip_bypass` mode.
//!
//! Inspired by the cfscanner project's scanning logic.
//!
//! ## Phases
//! 1. **TCP connect** — connects to `ip:443`; measures TCP latency.
//! 2. **TLS handshake** — performs a TLS handshake using `IP_SCAN_SNI`; measures
//!    TLS latency and cert validity.
//! 3. **TTFB** — sends `GET /cdn-cgi/trace HTTP/1.1` over the TLS connection and
//!    measures time-to-first-byte and parses the HTTP status code.
//! 4. **Speed** — measures separate download and upload throughput samples.
//!
//! ## Scoring (0–100) — unified with the SNI scanner
//! - TCP latency:  25 pts (linear: 0 ms → 25, ≥500 ms → 0)
//! - TLS success:  10 pts flat
//! - TLS latency:  15 pts (linear: 0 ms → 15, ≥1 000 ms → 0)
//! - Cert valid:    5 pts flat
//! - TTFB:         20 pts (linear: 0 ms → 20, ≥2 000 ms → 0)
//! - Download speed: 7.5 pts (linear: 0 B/s → 0, ≥2 000 KB/s → 7.5)
//! - Upload speed:   7.5 pts (linear: 0 B/s → 0, ≥2 000 KB/s → 7.5)
//! - All phases:   10 pts bonus

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::ser::SerializeStruct;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, trace};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SCAN_PORT: u16 = 443;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Events emitted by [`scan_ip_list`] through the optional progress channel.
#[derive(Debug, Clone)]
pub enum IpScanEvent {
    /// One IP completed Phase 1 (TCP connect), whether or not it succeeded.
    /// `tcp_tested` is the running count of Phase 1 completions so far.
    TcpDone { tcp_tested: usize },
    /// One IP completed Phase 2+3 (TLS + TTFB); the full probe result is
    /// included regardless of whether TLS succeeded.
    ProbeComplete(IpProbeEntry),
}

/// Result for one scanned IP address.
#[derive(Debug, Clone)]
pub struct IpProbeEntry {
    pub ip: IpAddr,
    /// TCP connect latency in milliseconds; `None` if TCP failed.
    pub tcp_latency_ms: Option<u64>,
    /// Whether the TLS handshake succeeded.
    pub tls_ok: bool,
    /// TLS handshake latency in milliseconds; `None` if TLS failed.
    pub tls_latency_ms: Option<u64>,
    /// Whether the TLS certificate was verified successfully.
    /// Always equal to `tls_ok` because rustls validates certs on every connect.
    pub cert_valid: bool,
    /// Time-to-first-byte in milliseconds; `None` if the HTTP phase failed.
    pub ttfb_ms: Option<u64>,
    /// Download throughput in bytes/sec (~10 KB sample); `None` if unavailable.
    pub download_bps: Option<f64>,
    /// Upload throughput in bytes/sec (~10 KB sample); `None` if unavailable.
    pub upload_bps: Option<f64>,
    /// HTTP status code returned by `GET /cdn-cgi/trace`; `None` if request failed.
    pub http_status: Option<u16>,
    /// Composite score 0–100.
    pub score: u8,
}

impl serde::Serialize for IpProbeEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("IpProbeEntry", 11)?;
        state.serialize_field("ip", &self.ip)?;
        state.serialize_field("tcp_latency_ms", &self.tcp_latency_ms)?;
        state.serialize_field("tls_ok", &self.tls_ok)?;
        state.serialize_field("tls_latency_ms", &self.tls_latency_ms)?;
        state.serialize_field("cert_valid", &self.cert_valid)?;
        state.serialize_field("ttfb_ms", &self.ttfb_ms)?;
        state.serialize_field("download_bps", &self.download_bps)?;
        state.serialize_field("upload_bps", &self.upload_bps)?;
        state.serialize_field("speed_bps", &self.download_bps)?;
        state.serialize_field("http_status", &self.http_status)?;
        state.serialize_field("score", &self.score)?;
        state.end()
    }
}

impl IpProbeEntry {
    /// One-line summary suitable for log output or TUI table cells.
    pub fn summary_line(&self) -> String {
        format!(
            "{:<45} tcp={:<6} tls={:<6} cert={} ttfb={:<6} down={:<12} up={:<12} http={:<3} score={}",
            self.ip.to_string(),
            self.tcp_latency_ms
                .map(|v| format!("{v}ms"))
                .unwrap_or_else(|| "fail".into()),
            if self.tls_ok {
                self.tls_latency_ms
                    .map(|v| format!("{v}ms"))
                    .unwrap_or_else(|| "ok".into())
            } else {
                "fail".into()
            },
            if self.cert_valid { "✓" } else { "✗" },
            self.ttfb_ms
                .map(|v| format!("{v}ms"))
                .unwrap_or_else(|| "—".into()),
            self.download_bps
                .map(format_bps)
                .unwrap_or_else(|| "—".into()),
            self.upload_bps
                .map(format_bps)
                .unwrap_or_else(|| "—".into()),
            self.http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "—".into()),
            self.score,
        )
    }
}

fn format_bps(bps: f64) -> String {
    if bps >= 1_048_576.0 {
        format!("{:.1}MB/s", bps / 1_048_576.0)
    } else {
        format!("{:.0}KB/s", bps / 1024.0)
    }
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

fn compute_score(entry: &IpProbeEntry, config: &crate::config::Config) -> u8 {
    // Unified 100-pt formula (same as SNI scanner).
    let tcp_pts = match entry.tcp_latency_ms {
        None => 0.0,
        Some(ms) => 25.0 * (1.0 - (ms as f64 / config.TCP_LATENCY_CAP_MS).min(1.0)),
    };
    let tls_flat = if entry.tls_ok { 10.0f64 } else { 0.0 };
    let tls_pts = match entry.tls_latency_ms {
        None => 0.0,
        Some(ms) => 15.0 * (1.0 - (ms as f64 / config.TLS_LATENCY_CAP_MS).min(1.0)),
    };
    let cert_pts = if entry.cert_valid { 5.0f64 } else { 0.0 };
    let ttfb_pts = match entry.ttfb_ms {
        None => 0.0,
        Some(ms) => 20.0 * (1.0 - (ms as f64 / config.TTFB_CAP_MS).min(1.0)),
    };
    let download_pts = match entry.download_bps {
        None => 0.0,
        Some(bps) => 7.5 * (bps / config.SPEED_CAP_BPS).min(1.0),
    };
    let upload_pts = match entry.upload_bps {
        None => 0.0,
        Some(bps) => 7.5 * (bps / config.UPLOAD_SPEED_CAP_BPS).min(1.0),
    };
    let all_present = entry.tcp_latency_ms.is_some()
        && entry.tls_ok
        && entry.cert_valid
        && entry.ttfb_ms.is_some()
        && entry.download_bps.is_some()
        && entry.upload_bps.is_some();
    let bonus = if all_present { 10.0 } else { 0.0 };
    (tcp_pts + tls_flat + tls_pts + cert_pts + ttfb_pts + download_pts + upload_pts + bonus).round()
        as u8
}

// ---------------------------------------------------------------------------
// IP list loading
// ---------------------------------------------------------------------------

/// Load IPs from `path`.
///
/// - Lines starting with `#` and blank lines are silently skipped.
/// - Plain IPs are taken as-is.
/// - CIDR ranges are expanded to individual host addresses.
///   IPv4 CIDRs are expanded in full; IPv6 CIDRs are capped at
///   `ipv6_max_hosts`.
/// - Entries that are neither a valid IP nor a valid CIDR are silently
///   skipped (e.g. hostnames, malformed lines).
///
/// Returns `Ok(Vec<IpAddr>)`.  The vector may be empty if the file is empty
/// or contains only comments.
pub fn load_ip_list(
    path: impl AsRef<std::path::Path>,
    ipv6_max_hosts: u64,
) -> anyhow::Result<Vec<IpAddr>> {
    let text = std::fs::read_to_string(path.as_ref())
        .map_err(|e| anyhow::anyhow!("cannot read ip_list '{}': {e}", path.as_ref().display()))?;
    let mut ips = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Try as plain IP first.
        if let Ok(ip) = line.parse::<IpAddr>() {
            ips.push(ip);
            continue;
        }
        // Try as CIDR.
        if let Ok(net) = line.parse::<IpNet>() {
            match net {
                IpNet::V4(v4net) => {
                    expand_v4(&v4net, &mut ips);
                }
                IpNet::V6(v6net) => {
                    expand_v6(&v6net, ipv6_max_hosts, &mut ips);
                }
            }
            continue;
        }
        // Silently skip anything else (hostnames, garbage, etc.)
        trace!("ip_list: skipping unrecognised entry: {line}");
    }
    Ok(ips)
}

fn expand_v4(net: &Ipv4Net, out: &mut Vec<IpAddr>) {
    for ip in net.hosts() {
        out.push(IpAddr::V4(ip));
    }
}

fn expand_v6(net: &Ipv6Net, max: u64, out: &mut Vec<IpAddr>) {
    let max_hosts = usize::try_from(max).unwrap_or(usize::MAX);
    for (count, ip) in net.hosts().enumerate() {
        if count >= max_hosts {
            debug!("IPv6 CIDR {} capped at {} hosts", net, max);
            break;
        }
        out.push(IpAddr::V6(ip));
    }
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Scan `ips` in three phases (TCP → TLS → TTFB).
///
/// `progress_tx`, if provided, receives [`IpScanEvent`] values as the scan
/// runs:
/// - [`IpScanEvent::TcpDone`] is sent after every Phase 1 TCP probe
///   (success or failure), carrying the running count of tested IPs.
/// - [`IpScanEvent::ProbeComplete`] is sent after every Phase 2+3 result.
///
/// Phase 2+3 probes are started immediately as each TCP success arrives
/// (pipelined), so results stream in before Phase 1 fully completes.
///
/// Returns all entries (including TCP-only failures) sorted by score desc,
/// then TCP latency asc.
pub async fn scan_ip_list(
    ips: Vec<IpAddr>,
    scan_sni: Arc<str>,
    timeout: Duration,
    config: Arc<crate::config::Config>,
    progress_tx: Option<mpsc::UnboundedSender<IpScanEvent>>,
) -> Vec<IpProbeEntry> {
    if ips.is_empty() {
        return Vec::new();
    }

    // -----------------------------------------------------------------------
    // Phase 1: TCP connect (all IPs, high concurrency)
    // Phase 2+3 is pipelined: each TLS probe starts as soon as its TCP
    // result arrives, without waiting for all of Phase 1 to finish.
    // -----------------------------------------------------------------------
    let sem1 = Arc::new(Semaphore::new(config.IP_MAX_P1_CONCURRENT));
    let sem2 = Arc::new(Semaphore::new(config.IP_MAX_P2_CONCURRENT));
    let (p1_tx, mut p1_rx) = mpsc::unbounded_channel::<(IpAddr, Option<u64>)>();
    let (p2_tx, mut p2_rx) = mpsc::unbounded_channel::<IpProbeEntry>();

    let total = ips.len();
    for ip in ips {
        let sem = sem1.clone();
        let tx = p1_tx.clone();
        tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let addr = SocketAddr::new(ip, SCAN_PORT);
            let start = Instant::now();
            let result = tokio::time::timeout(timeout, TcpStream::connect(addr)).await;
            let tcp_ms = match result {
                Ok(Ok(_)) => Some(start.elapsed().as_millis() as u64),
                _ => None,
            };
            let _ = tx.send((ip, tcp_ms));
        });
    }
    drop(p1_tx);

    // Process Phase 1 results as they arrive; immediately pipeline into Phase 2.
    let mut tcp_results: Vec<(IpAddr, Option<u64>)> = Vec::with_capacity(total);
    let mut tcp_tested: usize = 0;
    while let Some((ip, tcp_ms)) = p1_rx.recv().await {
        tcp_tested += 1;
        tcp_results.push((ip, tcp_ms));

        if let Some(ref ptx) = progress_tx {
            let _ = ptx.send(IpScanEvent::TcpDone { tcp_tested });
        }

        if let Some(ms) = tcp_ms {
            let sem = sem2.clone();
            let tx = p2_tx.clone();
            let ptx = progress_tx.clone();
            let sni = scan_sni.clone();
            let cfg = config.clone();
            tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let entry = probe_tls_ttfb(ip, ms, &sni, timeout, cfg).await;
                if let Some(ref t) = ptx {
                    let _ = t.send(IpScanEvent::ProbeComplete(entry.clone()));
                }
                let _ = tx.send(entry);
            });
        }
    }
    // All Phase 1 done — drop p2_tx so p2_rx closes when all spawns finish.
    drop(p2_tx);

    let mut tls_results: std::collections::HashMap<IpAddr, IpProbeEntry> =
        std::collections::HashMap::new();
    while let Some(entry) = p2_rx.recv().await {
        tls_results.insert(entry.ip, entry);
    }

    // Build final list: merge TCP failures + TLS results.
    let mut all: Vec<IpProbeEntry> = tcp_results
        .into_iter()
        .map(|(ip, tcp_ms)| {
            if let Some(entry) = tls_results.remove(&ip) {
                entry
            } else {
                // TCP-only survivor that was dropped during phase 2 (shouldn't
                // happen), or a TCP failure.
                let mut e = IpProbeEntry {
                    ip,
                    tcp_latency_ms: tcp_ms,
                    tls_ok: false,
                    tls_latency_ms: None,
                    cert_valid: false,
                    ttfb_ms: None,
                    download_bps: None,
                    upload_bps: None,
                    http_status: None,
                    score: 0,
                };
                e.score = compute_score(&e, &config);
                e
            }
        })
        .collect();

    all.sort_by(|a, b| {
        b.score.cmp(&a.score).then_with(|| {
            a.tcp_latency_ms
                .unwrap_or(u64::MAX)
                .cmp(&b.tcp_latency_ms.unwrap_or(u64::MAX))
        })
    });
    all
}

// ---------------------------------------------------------------------------
// TLS + TTFB probe
// ---------------------------------------------------------------------------

async fn probe_tls_ttfb(
    ip: IpAddr,
    tcp_latency_ms: u64,
    sni: &str,
    timeout: Duration,
    config: Arc<crate::config::Config>,
) -> IpProbeEntry {
    let addr = SocketAddr::new(ip, SCAN_PORT);

    // Re-connect for TLS (phase 1 stream has already been dropped).
    let stream = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            return IpProbeEntry {
                ip,
                tcp_latency_ms: Some(tcp_latency_ms),
                tls_ok: false,
                tls_latency_ms: None,
                cert_valid: false,
                ttfb_ms: None,
                download_bps: None,
                upload_bps: None,
                http_status: None,
                score: 0,
            };
        }
    };

    let connector = make_tls_connector();

    let server_name = match rustls::pki_types::ServerName::try_from(sni.to_owned()) {
        Ok(n) => n,
        Err(_) => {
            return IpProbeEntry {
                ip,
                tcp_latency_ms: Some(tcp_latency_ms),
                tls_ok: false,
                tls_latency_ms: None,
                cert_valid: false,
                ttfb_ms: None,
                download_bps: None,
                upload_bps: None,
                http_status: None,
                score: 0,
            };
        }
    };

    let tls_start = Instant::now();
    let mut tls_stream =
        match tokio::time::timeout(timeout, connector.connect(server_name, stream)).await {
            Ok(Ok(s)) => {
                let tls_ms = tls_start.elapsed().as_millis() as u64;
                (s, tls_ms)
            }
            _ => {
                let mut e = IpProbeEntry {
                    ip,
                    tcp_latency_ms: Some(tcp_latency_ms),
                    tls_ok: false,
                    tls_latency_ms: None,
                    cert_valid: false,
                    ttfb_ms: None,
                    download_bps: None,
                    upload_bps: None,
                    http_status: None,
                    score: 0,
                };
                e.score = compute_score(&e, &config);
                return e;
            }
        };

    let tls_latency_ms = tls_stream.1;
    let stream = &mut tls_stream.0;

    // Phase 3: TTFB + speed via HTTP GET /cdn-cgi/trace
    let request =
        format!("GET /cdn-cgi/trace HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n");
    let req_start = Instant::now();
    let write_ok = tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
        .await
        .is_ok_and(|r| r.is_ok());

    let (ttfb_ms, download_bps, http_status) = if write_ok {
        let mut buf = vec![0u8; config.SCAN_DOWNLOAD_CAP];
        let mut total_read = 0usize;
        let mut ttfb: Option<u64> = None;
        let mut status: Option<u16> = None;

        loop {
            let remaining = config.SCAN_DOWNLOAD_CAP - total_read;
            if remaining == 0 {
                break;
            }
            match tokio::time::timeout(timeout, stream.read(&mut buf[total_read..])).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => {
                    if ttfb.is_none() {
                        ttfb = Some(req_start.elapsed().as_millis() as u64);
                        // Parse HTTP status from the first response chunk.
                        if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                            status = parse_http_status(text);
                        }
                    }
                    total_read += n;
                }
                Ok(Err(_)) => break,
            }
        }

        let speed = if total_read > 0 {
            let elapsed = req_start.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                Some(total_read as f64 / elapsed)
            } else {
                None
            }
        } else {
            None
        };
        (ttfb, speed, status)
    } else {
        (None, None, None)
    };

    let upload_bps = if ttfb_ms.is_some() {
        probe_ip_upload(ip, sni, timeout, &config, &connector).await
    } else {
        None
    };

    let mut entry = IpProbeEntry {
        ip,
        tcp_latency_ms: Some(tcp_latency_ms),
        tls_ok: true,
        tls_latency_ms: Some(tls_latency_ms),
        cert_valid: true, // rustls validates cert on every successful connect
        ttfb_ms,
        download_bps,
        upload_bps,
        http_status,
        score: 0,
    };
    entry.score = compute_score(&entry, &config);
    entry
}

/// Extract the HTTP status code from the beginning of an HTTP/1.x response.
fn parse_http_status(text: &str) -> Option<u16> {
    // "HTTP/1.1 200 OK\r\n..."
    let line = text.lines().next()?;
    let mut parts = line.splitn(3, ' ');
    parts.next(); // "HTTP/1.x"
    parts.next()?.parse::<u16>().ok()
}

fn make_tls_connector() -> tokio_rustls::TlsConnector {
    let root_store = {
        let mut store = rustls::RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    };
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(tls_config))
}

async fn probe_ip_upload(
    ip: IpAddr,
    sni: &str,
    timeout: Duration,
    config: &crate::config::Config,
    connector: &tokio_rustls::TlsConnector,
) -> Option<f64> {
    let addr = SocketAddr::new(ip, SCAN_PORT);
    let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned()).ok()?;
    let mut stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp_stream))
        .await
        .ok()?
        .ok()?;

    crate::scanner_http::measure_upload(
        &mut stream,
        sni,
        &config.SCAN_UPLOAD_PATH,
        config.SCAN_UPLOAD_CAP,
        timeout,
    )
    .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn dummy_config() -> crate::config::Config {
        toml::from_str("LISTEN_HOST=\"0.0.0.0\"\nLISTEN_PORT=443").unwrap()
    }

    fn make_entry(
        tcp: Option<u64>,
        tls_ok: bool,
        tls_ms: Option<u64>,
        ttfb: Option<u64>,
        download: Option<f64>,
        upload: Option<f64>,
    ) -> IpProbeEntry {
        let cfg = dummy_config();
        let mut e = IpProbeEntry {
            ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            tcp_latency_ms: tcp,
            tls_ok,
            tls_latency_ms: tls_ms,
            cert_valid: tls_ok,
            ttfb_ms: ttfb,
            download_bps: download,
            upload_bps: upload,
            http_status: None,
            score: 0,
        };
        e.score = compute_score(&e, &cfg);
        e
    }

    #[test]
    fn score_perfect() {
        // 0 ms everywhere + all phases present → 100
        let e = make_entry(
            Some(0),
            true,
            Some(0),
            Some(0),
            Some(f64::MAX),
            Some(f64::MAX),
        );
        assert_eq!(e.score, 100);
    }

    #[test]
    fn score_tcp_fail() {
        let e = make_entry(None, false, None, None, None, None);
        assert_eq!(e.score, 0);
    }

    #[test]
    fn score_tcp_only() {
        // TCP at 0 ms, no TLS = 25 pts
        let e = make_entry(Some(0), false, None, None, None, None);
        assert_eq!(e.score, 25);
    }

    #[test]
    fn score_tcp_at_cap() {
        // TCP exactly at cap → 0 TCP pts; no TLS
        let e = make_entry(Some(500), false, None, None, None, None);
        assert_eq!(e.score, 0);
    }

    #[test]
    fn score_partial_tls_no_ttfb() {
        // TCP 100ms (20pts), TLS flat (10pts), TLS 200ms (12pts), no TTFB, no speed, no bonus
        // tcp: 25 * (1 - 100/500) = 20
        // tls_flat: 10
        // tls_ms: 15 * (1 - 200/1000) = 12
        // cert: 5 (cert_valid = tls_ok = true)
        // ttfb: 0, speed: 0, bonus: 0
        let e = make_entry(Some(100), true, Some(200), None, None, None);
        assert_eq!(e.score, 47);
    }

    #[test]
    fn score_all_phases_with_bonus() {
        // TCP 250ms (12.5), TLS flat (10), TLS 500ms (7.5), cert (5),
        // TTFB 1000ms (10), down/up 1024000 B/s (3.75 each), bonus (10) = 62.5 → 63
        let e = make_entry(
            Some(250),
            true,
            Some(500),
            Some(1000),
            Some(1_024_000.0),
            Some(1_024_000.0),
        );
        assert_eq!(e.score, 63);
    }

    #[test]
    fn score_all_phases_without_upload_has_no_bonus() {
        let e = make_entry(Some(0), true, Some(0), Some(0), Some(f64::MAX), None);
        assert_eq!(e.score, 83);
    }

    #[test]
    fn load_ip_list_plain_ips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ips.txt");
        std::fs::write(&path, "1.1.1.1\n1.0.0.1\n# comment\n\n8.8.8.8\n").unwrap();
        let ips = load_ip_list(&path, 65536).unwrap();
        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn load_ip_list_cidr_v4() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ips.txt");
        // /30 → 2 hosts
        std::fs::write(&path, "192.168.1.0/30\n").unwrap();
        let ips = load_ip_list(&path, 65536).unwrap();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn load_ip_list_cidr_v6_capped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ips.txt");
        // /64 would be enormous; cap at 10
        std::fs::write(&path, "2606:4700::/64\n").unwrap();
        let ips = load_ip_list(&path, 10).unwrap();
        assert_eq!(ips.len(), 10);
    }

    #[test]
    fn load_ip_list_skips_hostnames() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ips.txt");
        std::fs::write(&path, "cloudflare.com\n1.1.1.1\ngarbage!!!\n").unwrap();
        let ips = load_ip_list(&path, 65536).unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "1.1.1.1".parse::<IpAddr>().unwrap());
    }
}
