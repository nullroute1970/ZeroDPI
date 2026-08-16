//! SNI scanner: resolves each hostname from `sni_list.txt`, probes every
//! resolved IPv4 address for TCP connectivity, TLS handshake quality, TTFB,
//! download/upload speed, and HTTP reachability, then ranks the results.
//!
//! ## Checks performed (per SNI × IP pair)
//!
//! | Step  | What is measured |
//! |-------|-----------------|
//! | DNS   | Whether the hostname resolves to at least one IPv4 address |
//! | TCP   | Time to complete a TCP connect to port 443 |
//! | TLS   | Whether a full TLS handshake succeeds; wall-clock latency |
//! | Cert  | Certificate validation (implicit in TLS success via rustls) |
//! | TTFB  | Time to first byte of the HTTP response |
//! | Down  | ~10 KB download throughput from `GET /` |
//! | Up    | ~10 KB upload throughput from a small `POST` |
//! | HTTP  | HTTP status code returned by `GET /` |
//!
//! ## Scoring (0–100 pts) — unified with IP scanner
//!
//! | Component        | Max pts | Formula |
//! |------------------|---------|---------|
//! | TCP latency      | 25      | linear: 0 ms→25, ≥500 ms→0 |
//! | TLS success      | 10      | flat |
//! | TLS latency      | 15      | linear: 0 ms→15, ≥1 000 ms→0 |
//! | Cert valid       |  5      | flat |
//! | TTFB             | 20      | linear: 0 ms→20, ≥2 000 ms→0 |
//! | Download speed   | 7.5     | linear: 0→0, ≥2 000 KB/s→7.5 |
//! | Upload speed     | 7.5     | linear: 0→0, ≥2 000 KB/s→7.5 |
//! | All phases bonus | 10      | all signals present |

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::ser::SerializeStruct;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::dns::DnsResolver;

/// All probe results for one (SNI, IP) combination.
#[derive(Debug, Clone)]
pub struct SniProbeEntry {
    /// The SNI hostname.
    pub sni: String,
    /// The IPv4 address that was probed.
    pub ip: Ipv4Addr,
    /// Round-trip time of the TCP connect in milliseconds, or `None` if it
    /// failed or timed out.
    pub tcp_latency_ms: Option<u64>,
    /// Whether the TLS handshake completed successfully.
    pub tls_ok: bool,
    /// Round-trip time of the TLS handshake in milliseconds.
    pub tls_latency_ms: Option<u64>,
    /// Whether the TLS certificate was successfully verified.
    pub cert_valid: bool,
    /// Time-to-first-byte in milliseconds; `None` if the HTTP phase failed.
    pub ttfb_ms: Option<u64>,
    /// Download throughput in bytes/sec (~10 KB sample); `None` if unavailable.
    pub download_bps: Option<f64>,
    /// Upload throughput in bytes/sec (~10 KB sample); `None` if unavailable.
    pub upload_bps: Option<f64>,
    /// HTTP status code returned by `GET /`, or `None` if the request failed.
    pub http_status: Option<u16>,
    /// Composite score 0–100.
    pub score: u8,
}

impl serde::Serialize for SniProbeEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SniProbeEntry", 12)?;
        state.serialize_field("sni", &self.sni)?;
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

impl SniProbeEntry {
    /// Single-line summary suitable for console output during scanning.
    pub fn summary_line(&self) -> String {
        let tcp = self
            .tcp_latency_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "timeout".into());
        let tls = if self.tls_ok {
            self.tls_latency_ms
                .map(|ms| format!("ok({ms}ms)"))
                .unwrap_or_else(|| "ok".into())
        } else {
            "fail".into()
        };
        let http = self
            .http_status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".into());
        let ttfb = self
            .ttfb_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "-".into());
        let download = self
            .download_bps
            .map(format_bps)
            .unwrap_or_else(|| "-".into());
        let upload = self
            .upload_bps
            .map(format_bps)
            .unwrap_or_else(|| "-".into());
        format!(
            "  [{score:>3}] {sni:<40} {ip:<16} tcp={tcp:<12} tls={tls:<14} cert={cert} ttfb={ttfb:<8} down={download:<12} up={upload:<12} http={http}",
            score = self.score,
            sni = self.sni,
            ip = self.ip,
            cert = if self.cert_valid { "✓" } else { "✗" },
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

async fn probe_sni_upload(
    sni: &str,
    ip: Ipv4Addr,
    timeout: Duration,
    config: &crate::config::Config,
    connector: Arc<TlsConnector>,
) -> Option<f64> {
    let addr = SocketAddr::from((ip, 443u16));
    let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let server_name = ServerName::try_from(sni).map(|sn| sn.to_owned()).ok()?;
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
// Public API
// ---------------------------------------------------------------------------

/// Read SNI hostnames from `path` (one per line; `#`-prefixed lines and blank
/// lines are ignored) and probe each one.
///
/// All (SNI × IP) pairs are probed concurrently (bounded by
/// [`MAX_CONCURRENT_PROBES`]); individual probes are bounded by `timeout`
/// which covers DNS resolution, TCP connect, TLS handshake, and HTTP request.
///
/// Each completed `(SNI, IP)` result is sent over `progress_tx` as soon as it
/// arrives so callers can show live progress.  Pass `None` to disable
/// streaming (e.g., for background rescans where no UI is attached).
///
/// The returned list is sorted by score (descending), then by TCP latency
/// (ascending) as a tiebreaker.
pub async fn scan_sni_list(
    path: &Path,
    timeout: Duration,
    config: Arc<crate::config::Config>,
    progress_tx: Option<mpsc::UnboundedSender<SniProbeEntry>>,
) -> anyhow::Result<Vec<SniProbeEntry>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    let hostnames: Vec<String> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_owned())
        .collect();

    if hostnames.is_empty() {
        anyhow::bail!("sni_list is empty ({})", path.display());
    }

    let connector = Arc::new(make_tls_connector());
    let resolver = Arc::new(DnsResolver::from_config(&config, timeout)?);
    let semaphore = Arc::new(Semaphore::new(config.SNI_MAX_CONCURRENT));
    let mut handles = Vec::new();
    for sni in hostnames {
        let connector = connector.clone();
        let tx = progress_tx.clone();
        let sem = semaphore.clone();
        let cfg = config.clone();
        let resolver = resolver.clone();
        handles.push(tokio::spawn(async move {
            probe_sni(sni, timeout, cfg, resolver, connector, tx, sem).await
        }));
    }

    let mut results: Vec<SniProbeEntry> = Vec::new();
    for h in handles {
        match h.await {
            Ok(entries) => results.extend(entries),
            Err(e) => warn!("probe task panicked: {e}"),
        }
    }

    results.sort_by(|a, b| {
        b.score.cmp(&a.score).then(
            a.tcp_latency_ms
                .unwrap_or(u64::MAX)
                .cmp(&b.tcp_latency_ms.unwrap_or(u64::MAX)),
        )
    });

    Ok(results)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

pub fn make_tls_connector() -> TlsConnector {
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Resolve `sni` to all IPv4 addresses and probe each one.  Returns an empty
/// `Vec` if DNS resolution fails or times out.
async fn probe_sni(
    sni: String,
    timeout: Duration,
    config: Arc<crate::config::Config>,
    resolver: Arc<DnsResolver>,
    connector: Arc<TlsConnector>,
    progress_tx: Option<mpsc::UnboundedSender<SniProbeEntry>>,
    semaphore: Arc<Semaphore>,
) -> Vec<SniProbeEntry> {
    // DNS resolution is covered by the same per-probe timeout.
    let addrs: Vec<Ipv4Addr> = match tokio::time::timeout(timeout, resolver.lookup_ipv4(&sni)).await
    {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(e)) => {
            debug!(sni = %sni, error = %e, "DNS resolution failed");
            return Vec::new();
        }
        Err(_) => {
            debug!(sni = %sni, timeout = ?timeout, "DNS resolution timed out");
            return Vec::new();
        }
    };

    let mut tasks = Vec::new();
    for ip in addrs {
        let sni = sni.clone();
        let connector = connector.clone();
        let tx = progress_tx.clone();
        let sem = semaphore.clone();
        let cfg = config.clone();
        tasks.push(tokio::spawn(async move {
            // Acquire a permit before starting the TCP/TLS/HTTP probe so the
            // total number of concurrent connections stays bounded.
            let _permit = sem.acquire().await.expect("semaphore never closed");
            let entry = probe_sni_ip(sni, ip, timeout, cfg, connector).await;
            // Emit the result to the live-progress channel immediately.
            if let Some(ref tx) = tx {
                let _ = tx.send(entry.clone());
            }
            entry
        }));
    }

    let mut out = Vec::new();
    for t in tasks {
        match t.await {
            Ok(entry) => out.push(entry),
            Err(e) => warn!("ip probe task panicked: {e}"),
        }
    }
    out
}

/// Probe a single (SNI, IP) pair: TCP → TLS → HTTP.
async fn probe_sni_ip(
    sni: String,
    ip: Ipv4Addr,
    timeout: Duration,
    config: Arc<crate::config::Config>,
    connector: Arc<TlsConnector>,
) -> SniProbeEntry {
    let addr = SocketAddr::from((ip, 443u16));

    // --- TCP connect ---
    let tcp_start = Instant::now();
    let tcp_stream = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(sni = %sni, %ip, error = %e, "TCP connect failed");
            let mut entry = blank(&sni, ip);
            compute_score(&mut entry, &config);
            return entry;
        }
        Err(_) => {
            debug!(sni = %sni, %ip, "TCP connect timed out");
            let mut entry = blank(&sni, ip);
            compute_score(&mut entry, &config);
            return entry;
        }
    };
    let tcp_latency_ms = Some(tcp_start.elapsed().as_millis() as u64);

    // --- TLS handshake ---
    let server_name = match ServerName::try_from(sni.as_str())
        .map(|sn| sn.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid SNI '{sni}': {e}"))
    {
        Ok(sn) => sn,
        Err(e) => {
            warn!("{e}");
            let mut entry = blank(&sni, ip);
            entry.tcp_latency_ms = tcp_latency_ms;
            compute_score(&mut entry, &config);
            return entry;
        }
    };

    let tls_start = Instant::now();
    let tls_result =
        tokio::time::timeout(timeout, connector.connect(server_name, tcp_stream)).await;
    let (tls_ok, tls_latency_ms, cert_valid, tls_stream_opt) = match tls_result {
        Ok(Ok(stream)) => {
            let lat = tls_start.elapsed().as_millis() as u64;
            (true, Some(lat), true, Some(stream))
        }
        Ok(Err(e)) => {
            debug!(sni = %sni, %ip, error = %e, "TLS handshake failed");
            (false, None, false, None)
        }
        Err(_) => {
            debug!(sni = %sni, %ip, "TLS handshake timed out");
            (false, None, false, None)
        }
    };

    // --- HTTP GET / + TTFB + speed ---
    let (ttfb_ms, download_bps, http_status) = if let Some(mut stream) = tls_stream_opt {
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\nUser-Agent: zerodpi-scanner/0.1\r\n\r\n"
        );
        let req_start = Instant::now();
        let write_ok = tokio::time::timeout(timeout, async {
            stream.write_all(req.as_bytes()).await?;
            stream.flush().await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .is_ok_and(|r| r.is_ok());

        if write_ok {
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
        }
    } else {
        (None, None, None)
    };

    let upload_bps = if ttfb_ms.is_some() {
        probe_sni_upload(&sni, ip, timeout, &config, connector).await
    } else {
        None
    };

    let mut entry = SniProbeEntry {
        sni,
        ip,
        tcp_latency_ms,
        tls_ok,
        tls_latency_ms,
        cert_valid,
        ttfb_ms,
        download_bps,
        upload_bps,
        http_status,
        score: 0,
    };
    compute_score(&mut entry, &config);
    entry
}

fn blank(sni: &str, ip: Ipv4Addr) -> SniProbeEntry {
    SniProbeEntry {
        sni: sni.to_owned(),
        ip,
        tcp_latency_ms: None,
        tls_ok: false,
        tls_latency_ms: None,
        cert_valid: false,
        ttfb_ms: None,
        download_bps: None,
        upload_bps: None,
        http_status: None,
        score: 0,
    }
}

/// Parse the HTTP status code from the beginning of an HTTP/1.x response.
fn parse_http_status(text: &str) -> Option<u16> {
    let line = text.lines().next()?;
    let mut parts = line.splitn(3, ' ');
    parts.next(); // "HTTP/1.x"
    parts.next()?.parse::<u16>().ok()
}

/// Compute the composite score (unified 0–100 formula) and store it in `entry.score`.
fn compute_score(entry: &mut SniProbeEntry, config: &crate::config::Config) {
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
    entry.score =
        (tcp_pts + tls_flat + tls_pts + cert_pts + ttfb_pts + download_pts + upload_pts + bonus)
            .round() as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

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
    ) -> SniProbeEntry {
        let cfg = dummy_config();
        let mut e = SniProbeEntry {
            sni: "example.com".into(),
            ip: Ipv4Addr::new(1, 2, 3, 4),
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
        compute_score(&mut e, &cfg);
        e
    }

    #[test]
    fn score_with_all_perfect() {
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
    fn score_with_nothing() {
        let cfg = dummy_config();
        let mut e = blank("fail.test", Ipv4Addr::new(1, 2, 3, 4));
        compute_score(&mut e, &cfg);
        assert_eq!(e.score, 0);
    }

    #[test]
    fn score_tcp_only() {
        // TCP at 0 ms, no TLS = 25 pts
        let e = make_entry(Some(0), false, None, None, None, None);
        assert_eq!(e.score, 25);
    }

    #[test]
    fn score_partial_tls_no_ttfb() {
        // TCP 100ms (20), TLS flat (10), TLS 200ms (12), cert (5) = 47
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
    fn parse_http_200() {
        assert_eq!(
            parse_http_status("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"),
            Some(200)
        );
    }

    #[test]
    fn parse_http_301() {
        assert_eq!(
            parse_http_status("HTTP/1.1 301 Moved Permanently\r\n"),
            Some(301)
        );
    }

    #[test]
    fn parse_http_garbage() {
        assert_eq!(parse_http_status("not http"), None);
    }
}
