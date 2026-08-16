//! Method-scan engine for `sni_method_scan` / `ip_method_scan` modes.
//!
//! See the module-level docs added in later tasks.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tracing::debug;

use crate::config::Config;
use crate::sni_scanner::make_tls_connector;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The single target every method is tested against (Phase 0 winner).
#[derive(Debug, Clone)]
pub struct MethodScanTarget {
    /// SNI used for the TLS handshake in every probe.
    pub sni: String,
    /// IPv4 address the engine relays to (and the interceptor filters on).
    pub ip: Ipv4Addr,
    /// Phase-0 score of the candidate, recorded in the report.
    pub score: u8,
    /// HTTP path requested by each probe ("/" for SNI mode,
    /// "/cdn-cgi/trace" for IP mode).
    pub http_path: &'static str,
}

/// Progress events emitted through the optional channel.
#[derive(Debug, Clone)]
pub enum MethodScanEvent {
    /// One method finished all its samples.
    MethodDone {
        method: String,
        /// Cumulative count of methods completed so far.
        completed: usize,
        entry: MethodScanEntry,
    },
    /// One sample finished.
    SampleDone {
        method: String,
        sample: usize,
        ok: bool,
    },
}

/// Outcome of one direct probe.
#[derive(Debug, Clone)]
pub struct MethodSampleResult {
    /// TLS handshake completed AND an HTTP response with body arrived.
    pub ok: bool,
    pub tls_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub speed_bps: Option<f64>,
    pub http_status: Option<u16>,
    pub error: Option<String>,
}

/// Aggregated results for one method.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MethodScanEntry {
    pub method: String,
    pub samples_total: usize,
    pub samples_ok: usize,
    /// 0.0–100.0.
    pub success_rate: f64,
    pub avg_ttfb_ms: Option<f64>,
    pub min_ttfb_ms: Option<u64>,
    pub max_ttfb_ms: Option<u64>,
    pub avg_tls_ms: Option<f64>,
    pub http_status: Option<u16>,
    pub last_error: Option<String>,
}

impl MethodScanEntry {
    /// Single-line summary suitable for console output.
    pub fn summary_line(&self) -> String {
        let ttfb = self
            .avg_ttfb_ms
            .map(|ms| format!("{ms:.0}ms"))
            .unwrap_or_else(|| "-".into());
        let tls = self
            .avg_tls_ms
            .map(|ms| format!("{ms:.0}ms"))
            .unwrap_or_else(|| "-".into());
        let http = self
            .http_status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".into());
        format!(
            "[{rate:>5.1}%] {method:<24} ok={ok}/{total} ttfb={ttfb:<10} tls={tls:<10} http={http}",
            rate = self.success_rate,
            method = self.method,
            ok = self.samples_ok,
            total = self.samples_total,
        )
    }
}

/// Whole report, serialized to `METHOD_SCAN_OUTPUT`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MethodScanReport {
    pub mode: String,
    pub target_sni: String,
    pub target_ip: Ipv4Addr,
    pub target_score: u8,
    pub samples_per_method: usize,
    pub interval_ms: u64,
    pub methods: Vec<MethodScanEntry>,
}

// ---------------------------------------------------------------------------
// Aggregation and ranking (pure functions)
// ---------------------------------------------------------------------------

/// Aggregate raw samples into one ranked-report row.
pub fn entry_from_samples(method: &str, samples: &[MethodSampleResult]) -> MethodScanEntry {
    let total = samples.len();
    let ok_count = samples.iter().filter(|s| s.ok).count();
    let success_rate = if total == 0 {
        0.0
    } else {
        ok_count as f64 * 100.0 / total as f64
    };
    let ttfb_ms: Vec<u64> = samples.iter().filter_map(|s| s.ttfb_ms).collect();
    let avg_ttfb_ms = if ttfb_ms.is_empty() {
        None
    } else {
        Some(ttfb_ms.iter().map(|v| *v as f64).sum::<f64>() / ttfb_ms.len() as f64)
    };
    let tls_ms: Vec<u64> = samples.iter().filter_map(|s| s.tls_ms).collect();
    let avg_tls_ms = if tls_ms.is_empty() {
        None
    } else {
        Some(tls_ms.iter().map(|v| *v as f64).sum::<f64>() / tls_ms.len() as f64)
    };
    let http_status = samples.iter().find_map(|s| s.http_status);
    let last_error = samples.iter().rev().find_map(|s| s.error.clone());
    MethodScanEntry {
        method: method.to_owned(),
        samples_total: total,
        samples_ok: ok_count,
        success_rate,
        avg_ttfb_ms,
        min_ttfb_ms: ttfb_ms.iter().min().copied(),
        max_ttfb_ms: ttfb_ms.iter().max().copied(),
        avg_tls_ms,
        http_status,
        last_error,
    }
}

/// Rank entries: success rate desc, then avg TTFB asc (missing TTFB last),
/// then method name asc for stable ordering.
pub fn rank_entries(mut entries: Vec<MethodScanEntry>) -> Vec<MethodScanEntry> {
    entries.sort_by(|a, b| {
        b.success_rate
            .total_cmp(&a.success_rate)
            .then_with(|| match (a.avg_ttfb_ms, b.avg_ttfb_ms) {
                (Some(x), Some(y)) => x.total_cmp(&y),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
            .then_with(|| a.method.cmp(&b.method))
    });
    entries
}

// ---------------------------------------------------------------------------
// Config helper
// ---------------------------------------------------------------------------

/// Clone `base` with `BYPASS_METHOD` replaced by the single `method`.
pub fn cfg_with_method(base: &Config, method: &str) -> Arc<Config> {
    let mut cfg = base.clone();
    cfg.BYPASS_METHOD = crate::config::BypassMethodList::from_delimited(method);
    Arc::new(cfg)
}

// ---------------------------------------------------------------------------
// Direct probe
// ---------------------------------------------------------------------------

/// Parse the status code out of an HTTP response head.
fn parse_http_status(head: &str) -> Option<u16> {
    let rest = head.strip_prefix("HTTP/")?;
    rest.split_once(' ')?.1.get(0..3)?.parse().ok()
}

/// Read an HTTP response up to `cap` bytes. Returns (TTFB ms, status, body bytes).
async fn read_http_response<S>(stream: &mut S, cap: usize, timeout: Duration) -> (Option<u64>, Option<u16>, usize)
where
    S: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; cap];
    let mut total_read = 0usize;
    let mut ttfb_ms: Option<u64> = None;
    let mut http_status: Option<u16> = None;
    let mut header_end: Option<usize> = None;
    let start = Instant::now();
    loop {
        let remaining = cap - total_read;
        if remaining == 0 {
            break;
        }
        match tokio::time::timeout(timeout, stream.read(&mut buf[total_read..])).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                if ttfb_ms.is_none() {
                    ttfb_ms = Some(start.elapsed().as_millis() as u64);
                }
                total_read += n;
                if header_end.is_none() {
                    if let Some(pos) = find_header_end(&buf[..total_read]) {
                        header_end = Some(pos);
                        if let Ok(head) = std::str::from_utf8(&buf[..pos]) {
                            http_status = parse_http_status(head);
                        }
                    }
                }
            }
            Ok(Err(_)) => break,
        }
    }
    let body_bytes = header_end.map_or(0, |end| total_read.saturating_sub(end));
    (ttfb_ms, http_status, body_bytes)
}

/// Index just past the first `\r\n\r\n` (end of the HTTP response head).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// One probe through ZeroDPI's engine: TCP to the listen port, TLS handshake
/// with `sni`, HTTP GET of `http_path`, bounded by `timeout`.
pub async fn direct_probe(
    config: &Config,
    connect_addr: SocketAddr,
    sni: &str,
    http_path: &str,
    timeout: Duration,
) -> MethodSampleResult {
    // --- TCP connect to the engine's listen port ---
    let tcp_stream = match tokio::time::timeout(timeout, TcpStream::connect(connect_addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(error = %e, %connect_addr, "method probe: TCP connect failed");
            return MethodSampleResult {
                ok: false,
                tls_ms: None,
                ttfb_ms: None,
                speed_bps: None,
                http_status: None,
                error: Some(format!("TCP connect to {connect_addr} failed: {e}")),
            };
        }
        Err(_) => {
            return MethodSampleResult {
                ok: false,
                tls_ms: None,
                ttfb_ms: None,
                speed_bps: None,
                http_status: None,
                error: Some(format!("TCP connect to {connect_addr} timed out")),
            };
        }
    };

    // --- TLS handshake with the target SNI ---
    let server_name = match ServerName::try_from(sni).map(|sn| sn.to_owned()) {
        Ok(sn) => sn,
        Err(e) => {
            return MethodSampleResult {
                ok: false,
                tls_ms: None,
                ttfb_ms: None,
                speed_bps: None,
                http_status: None,
                error: Some(format!("invalid SNI '{sni}': {e}")),
            };
        }
    };
    let connector = make_tls_connector();
    let tls_start = Instant::now();
    let mut stream = match tokio::time::timeout(timeout, connector.connect(server_name, tcp_stream))
        .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(error = %e, "method probe: TLS handshake failed");
            return MethodSampleResult {
                ok: false,
                tls_ms: None,
                ttfb_ms: None,
                speed_bps: None,
                http_status: None,
                error: Some(format!("TLS handshake failed: {e}")),
            };
        }
        Err(_) => {
            return MethodSampleResult {
                ok: false,
                tls_ms: None,
                ttfb_ms: None,
                speed_bps: None,
                http_status: None,
                error: Some("TLS handshake timed out".into()),
            };
        }
    };
    let tls_ms = tls_start.elapsed().as_millis() as u64;

    // --- HTTP GET ---
    let req = format!(
        "GET {http_path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\nUser-Agent: zerodpi-method-scan/0.1\r\n\r\n"
    );
    let req_start = Instant::now();
    let write_ok = tokio::time::timeout(timeout, async {
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .is_ok_and(|r| r.is_ok());
    if !write_ok {
        return MethodSampleResult {
            ok: false,
            tls_ms: Some(tls_ms),
            ttfb_ms: None,
            speed_bps: None,
            http_status: None,
            error: Some("HTTP request write failed or timed out".into()),
        };
    }

    let (ttfb_ms, http_status, total_read) =
        read_http_response(&mut stream, config.SCAN_DOWNLOAD_CAP, timeout).await;

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

    let ok = http_status.is_some() && total_read > 0;
    MethodSampleResult {
        ok,
        tls_ms: Some(tls_ms),
        ttfb_ms,
        speed_bps,
        http_status,
        error: if ok {
            None
        } else {
            Some("no HTTP response received through the relay".into())
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ok: bool, ttfb: Option<u64>, tls: Option<u64>, status: Option<u16>) -> MethodSampleResult {
        MethodSampleResult {
            ok,
            tls_ms: tls,
            ttfb_ms: ttfb,
            speed_bps: None,
            http_status: status,
            error: if ok { None } else { Some("fail".into()) },
        }
    }

    #[test]
    fn aggregates_samples_into_entry() {
        let samples = vec![
            sample(true, Some(100), Some(50), Some(200)),
            sample(false, None, Some(60), None),
            sample(true, Some(200), Some(55), Some(200)),
        ];
        let entry = entry_from_samples("wrong_seq", &samples);
        assert_eq!(entry.method, "wrong_seq");
        assert_eq!(entry.samples_total, 3);
        assert_eq!(entry.samples_ok, 2);
        assert!((entry.success_rate - 66.666).abs() < 0.01);
        assert!((entry.avg_ttfb_ms.unwrap() - 150.0).abs() < 0.01);
        assert_eq!(entry.min_ttfb_ms, Some(100));
        assert_eq!(entry.max_ttfb_ms, Some(200));
        assert_eq!(entry.http_status, Some(200));
        assert_eq!(entry.last_error.as_deref(), Some("fail"));
    }

    #[test]
    fn empty_samples_yield_zero_entry() {
        let entry = entry_from_samples("tls_frag", &[]);
        assert_eq!(entry.samples_total, 0);
        assert_eq!(entry.samples_ok, 0);
        assert_eq!(entry.success_rate, 0.0);
        assert_eq!(entry.avg_ttfb_ms, None);
        assert_eq!(entry.last_error, None);
    }

    #[test]
    fn ranks_by_success_rate_then_avg_ttfb() {
        let a = entry_from_samples("a", &[sample(true, Some(10), None, None)]);
        let b = entry_from_samples("b", &[sample(true, Some(5), None, None)]);
        let c = entry_from_samples("c", &[sample(false, None, None, None)]);
        let ranked = rank_entries(vec![c.clone(), a.clone(), b.clone()]);
        assert_eq!(ranked[0].method, "b");
        assert_eq!(ranked[1].method, "a");
        assert_eq!(ranked[2].method, "c");
    }

    #[test]
    fn ranks_method_with_ttfb_before_method_without_on_tie() {
        let a = entry_from_samples("a", &[sample(true, Some(10), None, None)]);
        let b = entry_from_samples("b", &[sample(true, None, None, None)]);
        let ranked = rank_entries(vec![b, a]);
        assert_eq!(ranked[0].method, "a");
        assert_eq!(ranked[1].method, "b");
    }

    #[test]
    fn report_serializes_to_json() {
        let report = MethodScanReport {
            mode: "sni_method_scan".into(),
            target_sni: "example.com".into(),
            target_ip: std::net::Ipv4Addr::new(1, 1, 1, 1),
            target_score: 95,
            samples_per_method: 10,
            interval_ms: 1000,
            methods: vec![entry_from_samples(
                "tls_frag",
                &[sample(true, Some(42), Some(30), Some(200))],
            )],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["mode"], "sni_method_scan");
        assert_eq!(parsed["target_ip"], "1.1.1.1");
        assert_eq!(parsed["methods"][0]["method"], "tls_frag");
        assert_eq!(parsed["methods"][0]["samples_ok"], 1);
    }

    #[test]
    fn cfg_with_method_overrides_bypass_list() {
        let base: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["wrong_seq", "tls_frag"]"#,
        )
        .unwrap();
        let cfg = cfg_with_method(&base, "tls_padding");
        assert_eq!(cfg.BYPASS_METHOD.to_string(), "tls_padding");
        assert_eq!(base.BYPASS_METHOD.to_string(), "wrong_seq + tls_frag");
    }

    #[test]
    fn parses_http_status_line() {
        assert_eq!(parse_http_status("HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_http_status("HTTP/1.0 404 Not Found\r\n"), Some(404));
        assert_eq!(parse_http_status("garbage"), None);
        assert_eq!(parse_http_status(""), None);
    }

    #[tokio::test]
    async fn reads_status_ttfb_and_body_bytes() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
            // Dropping `sock` here closes the connection -> the reader sees EOF.
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (ttfb, status, total) =
            read_http_response(&mut stream, 1024, std::time::Duration::from_secs(5)).await;
        assert!(ttfb.is_some());
        assert_eq!(status, Some(200));
        assert_eq!(total, 5);
    }

    #[tokio::test]
    async fn probe_fails_on_closed_port() {
        // Bind, then drop, so the address is guaranteed to refuse connections.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap();
        let result = direct_probe(&cfg, addr, "example.com", "/", std::time::Duration::from_secs(1)).await;
        assert!(!result.ok);
        assert!(result.error.is_some());
        assert_eq!(result.tls_ms, None);
    }
}
