//! Method-scan engine for `sni_method_scan` / `ip_method_scan` modes.
//!
//! See the module-level docs added in later tasks.

use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::config::Config;

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
}
