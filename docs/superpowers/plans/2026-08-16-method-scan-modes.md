# Method-Scan Modes Implementation Plan (`sni_method_scan` / `ip_method_scan`)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two scan-only modes that find the best *bypass method* for a fixed target: scan the candidate list, pick the top candidate, test every configured bypass method end-to-end through ZeroDPI's full engine, and report results to a JSON file and the screen.

**Architecture:** Phase 0 reuses the existing `scan_sni_list` / `scan_ip_list` scanners to pick the single top-scoring target. Phase 1 is a new `zerodpi-core::method_scanner` module modeled on `proxy_tester`: per method it clones the config with `BYPASS_METHOD = [method]`, spins up the engine once (proxy task + packet interceptor when the method needs one), runs `METHOD_SCAN_SAMPLES` direct TLS+HTTP probes with `METHOD_SCAN_INTERVAL_MS` between them, tears down, and ranks by success rate (desc) then avg TTFB (asc). `main.rs` wires the two `MODE` values, saves the JSON report, and shows a TUI table (or prints to stdout with `--no-tui`).

**Tech Stack:** Rust 2021 workspace (`zerodpi-core`, `zerodpi`, `zerodpi-platform`), tokio + tokio-rustls, ratatui, serde/serde_json, anyhow, tracing. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-16-method-scan-modes-design.md` — the plan argues from the spec; read both.

## Global Constraints

- 4-space indentation; run `rustfmt` formatting; `snake_case` files/functions, `PascalCase` types, `SCREAMING_SNAKE_CASE` config fields.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` must all pass before each commit.
- No new Cargo dependencies. Platform requirements unchanged (WinDivert/NFQUEUE only where they already exist).
- All `Config` construction goes through TOML parsing — never construct `Config` literally; new fields must have `#[serde(default)]` so existing tests keep compiling.
- Commit messages use conventional prefixes (`feat:`, `refactor:`); imperative, scoped subjects.
- Tests are inline `#[cfg(test)]` modules beside the code; name them by behavior.
- New config options must be documented in `config.toml` comments and `README.md` (Task 7).

---

### Task 1: Config fields, defaults, validation, new MODE values

**Files:**
- Modify: `crates/zerodpi-core/src/config.rs` (fields after the `SCAN_OUTPUT` block near line 1067; default fns near line 1182; validation in `validate()` after the `SCAN_TIMEOUT_SECS` check near line 1355; the MODE `matches!` whitelist near line 1546)

**Interfaces:**
- Produces: `Config` fields `METHOD_SCAN_METHODS: BypassMethodList`, `METHOD_SCAN_SAMPLES: usize`, `METHOD_SCAN_INTERVAL_MS: u64`, `METHOD_SCAN_TIMEOUT_SECS: u64`, `METHOD_SCAN_OUTPUT: Option<String>` (consumed by Tasks 3–6); `MODE` values `"sni_method_scan"` / `"ip_method_scan"` accepted by `Config::validate()`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` in `crates/zerodpi-core/src/config.rs` (next to the existing `sni_scan_mode_valid` test near line 3018):

```rust
    #[test]
    fn method_scan_defaults_apply() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "sni_method_scan"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.METHOD_SCAN_SAMPLES, 10);
        assert_eq!(cfg.METHOD_SCAN_INTERVAL_MS, 1000);
        assert_eq!(cfg.METHOD_SCAN_TIMEOUT_SECS, 10);
        assert_eq!(
            cfg.METHOD_SCAN_METHODS.iter().count(),
            BASE_BYPASS_METHODS.len()
        );
        assert!(cfg.METHOD_SCAN_OUTPUT.is_none());
    }

    #[test]
    fn method_scan_accepts_custom_values() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "ip_method_scan"
            METHOD_SCAN_SAMPLES = 5
            METHOD_SCAN_INTERVAL_MS = 250
            METHOD_SCAN_TIMEOUT_SECS = 20
            METHOD_SCAN_METHODS = ["wrong_seq", "tls_frag"]
            METHOD_SCAN_OUTPUT = "method_report.json"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.METHOD_SCAN_SAMPLES, 5);
        assert_eq!(cfg.METHOD_SCAN_INTERVAL_MS, 250);
        assert_eq!(cfg.METHOD_SCAN_TIMEOUT_SECS, 20);
        assert!(cfg.METHOD_SCAN_METHODS.contains("wrong_seq"));
        assert!(cfg.METHOD_SCAN_METHODS.contains("tls_frag"));
        assert_eq!(cfg.METHOD_SCAN_METHODS.iter().count(), 2);
        assert_eq!(cfg.METHOD_SCAN_OUTPUT.as_deref(), Some("method_report.json"));
    }

    #[test]
    fn method_scan_rejects_zero_samples() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "sni_method_scan"
            METHOD_SCAN_SAMPLES = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn method_scan_rejects_zero_timeout() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "sni_method_scan"
            METHOD_SCAN_TIMEOUT_SECS = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn method_scan_rejects_unknown_method() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "sni_method_scan"
            METHOD_SCAN_METHODS = ["turbo_frag"]
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn method_scan_rejects_duplicate_methods() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "sni_method_scan"
            METHOD_SCAN_METHODS = ["wrong_seq", "wrong_seq"]
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn method_scan_modes_validate() {
        for mode in ["sni_method_scan", "ip_method_scan"] {
            let toml_str = format!(
                "LISTEN_HOST = \"0.0.0.0\"\nLISTEN_PORT = 40443\nMODE = \"{mode}\"\n"
            );
            let cfg: Config = toml::from_str(&toml_str).unwrap();
            cfg.validate().unwrap();
            assert_eq!(cfg.MODE, mode);
        }
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-core config::tests::method_scan`
Expected: compile errors — `METHOD_SCAN_*` fields do not exist on `Config`, and MODE `"sni_method_scan"` is rejected by `validate()`.

- [ ] **Step 3: Add the five fields**

In `crates/zerodpi-core/src/config.rs`, insert immediately after the `SCAN_OUTPUT` field block (after the line `pub SCAN_OUTPUT: Option<String>,`):

```rust
    // -----------------------------------------------------------------------
    // Method-scan modes
    // -----------------------------------------------------------------------
    /// Bypass methods to test in `sni_method_scan` / `ip_method_scan` modes.
    /// Defaults to every base method; trim the list to test a subset.
    #[serde(default = "default_method_scan_methods")]
    pub METHOD_SCAN_METHODS: BypassMethodList,

    /// Number of probe samples per method. Default: `10`.
    #[serde(default = "default_method_scan_samples")]
    pub METHOD_SCAN_SAMPLES: usize,

    /// Interval between samples in milliseconds. Default: `1000`.
    #[serde(default = "default_method_scan_interval_ms")]
    pub METHOD_SCAN_INTERVAL_MS: u64,

    /// Per-sample probe timeout in seconds. Default: `10`.
    #[serde(default = "default_method_scan_timeout_secs")]
    pub METHOD_SCAN_TIMEOUT_SECS: u64,

    /// Optional path to write the method-scan report as a JSON file after a
    /// method-scan run (`MODE = "sni_method_scan"` or `MODE = "ip_method_scan"`).
    /// Relative paths are resolved from the directory containing `config.toml`.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub METHOD_SCAN_OUTPUT: Option<String>,
```

- [ ] **Step 4: Add the four default functions**

Insert after `fn default_scan_timeout()` (near line 1182):

```rust
fn default_method_scan_methods() -> BypassMethodList {
    BypassMethodList::from_delimited(&BASE_BYPASS_METHODS.join(","))
}

fn default_method_scan_samples() -> usize {
    10
}

fn default_method_scan_interval_ms() -> u64 {
    1000
}

fn default_method_scan_timeout_secs() -> u64 {
    10
}
```

- [ ] **Step 5: Add validation rules**

In `Config::validate()`, immediately after the `SCAN_TIMEOUT_SECS` check block:

```rust
        if self.METHOD_SCAN_SAMPLES == 0 {
            anyhow::bail!("METHOD_SCAN_SAMPLES must be >= 1");
        }
        if self.METHOD_SCAN_TIMEOUT_SECS == 0 {
            anyhow::bail!("METHOD_SCAN_TIMEOUT_SECS must be > 0");
        }
        if self.METHOD_SCAN_METHODS.is_empty() {
            anyhow::bail!("METHOD_SCAN_METHODS must not be empty");
        }
        {
            let mut seen = std::collections::HashSet::new();
            for method in self.METHOD_SCAN_METHODS.iter() {
                if !BASE_BYPASS_METHODS.contains(&method) {
                    anyhow::bail!(
                        "Unknown METHOD_SCAN_METHODS entry '{}'. Valid base methods: {:?}",
                        method,
                        BASE_BYPASS_METHODS
                    );
                }
                if !seen.insert(method) {
                    anyhow::bail!("Duplicate METHOD_SCAN_METHODS entry '{method}'");
                }
            }
        }
```

- [ ] **Step 6: Extend the MODE whitelist**

Replace the existing `matches!` block (near line 1546) with:

```rust
        if !matches!(
            self.MODE.as_str(),
            "sni_spoof" | "ip_bypass" | "ip_bypass_plus" | "sni_scan" | "ip_scan"
                | "proxy_scan" | "sni_method_scan" | "ip_method_scan"
        ) {
            anyhow::bail!(
                "Unknown MODE '{}'. Valid values: \"sni_spoof\", \"ip_bypass\", \"ip_bypass_plus\", \"sni_scan\", \"ip_scan\", \"proxy_scan\", \"sni_method_scan\", \"ip_method_scan\"",
                self.MODE
            );
        }
```

(Let `rustfmt` reflow the match arms.)

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core config::tests::method_scan` — all new tests PASS.
Run: `cargo test -p zerodpi-core` — existing config tests still PASS (serde defaults keep old TOML fixtures valid).

- [ ] **Step 8: Commit**

```bash
git add crates/zerodpi-core/src/config.rs
git commit -m "feat: add method-scan config fields and modes"
```

---

### Task 2: `method_scanner` module — types, aggregation, ranking, report

**Files:**
- Create: `crates/zerodpi-core/src/method_scanner.rs`
- Modify: `crates/zerodpi-core/src/lib.rs` (export module)

**Interfaces:**
- Consumes: `Config` fields from Task 1; `crate::config::BypassMethodList::from_delimited`; `crate::config::BASE_BYPASS_METHODS` (tests only).
- Produces (consumed by Tasks 3–6):
  - `pub struct MethodScanTarget { pub sni: String, pub ip: std::net::Ipv4Addr, pub score: u8, pub http_path: &'static str }`
  - `pub struct MethodSampleResult { pub ok: bool, pub tls_ms: Option<u64>, pub ttfb_ms: Option<u64>, pub speed_bps: Option<f64>, pub http_status: Option<u16>, pub error: Option<String> }`
  - `pub struct MethodScanEntry { pub method: String, pub samples_total: usize, pub samples_ok: usize, pub success_rate: f64, pub avg_ttfb_ms: Option<f64>, pub min_ttfb_ms: Option<u64>, pub max_ttfb_ms: Option<u64>, pub avg_tls_ms: Option<f64>, pub http_status: Option<u16>, pub last_error: Option<String> }` + `impl MethodScanEntry { pub fn summary_line(&self) -> String }`
  - `pub struct MethodScanReport { pub mode: String, pub target_sni: String, pub target_ip: std::net::Ipv4Addr, pub target_score: u8, pub samples_per_method: usize, pub interval_ms: u64, pub methods: Vec<MethodScanEntry> }` (all three entry/report types derive `serde::Serialize`, `Debug`, `Clone`)
  - `pub enum MethodScanEvent { MethodDone { method: String, completed: usize, entry: MethodScanEntry }, SampleDone { method: String, sample: usize, ok: bool } }`
  - `pub fn entry_from_samples(method: &str, samples: &[MethodSampleResult]) -> MethodScanEntry`
  - `pub fn rank_entries(entries: Vec<MethodScanEntry>) -> Vec<MethodScanEntry>`
  - `pub fn cfg_with_method(base: &Config, method: &str) -> std::sync::Arc<Config>`

- [ ] **Step 1: Write the failing tests**

Create `crates/zerodpi-core/src/method_scanner.rs` containing only the module skeleton plus the tests:

```rust
//! Method-scan engine for `sni_method_scan` / `ip_method_scan` modes.
//!
//! See the module-level docs added in later tasks.

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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-core method_scanner`
Expected: compile errors — the module isn't exported and none of the types/functions exist.

- [ ] **Step 3: Export the module**

In `crates/zerodpi-core/src/lib.rs`, add `pub mod method_scanner;` between `pub mod low_ttl_discover;` and `pub mod methods;` (alphabetical order).

- [ ] **Step 4: Implement types, aggregation, ranking, and report**

Replace the skeleton content of `crates/zerodpi-core/src/method_scanner.rs` above the tests with:

```rust
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
```

(Import `Config` and `Arc` at the top; `use crate::config::Config;` is already there.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core method_scanner`
Expected: all 7 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/zerodpi-core/src/method_scanner.rs crates/zerodpi-core/src/lib.rs
git commit -m "feat: add method-scan types, ranking, and report"
```

---

### Task 3: Direct probe (TLS + HTTP through the engine)

**Files:**
- Modify: `crates/zerodpi-core/src/method_scanner.rs` (add `direct_probe`, `read_http_response`, `parse_http_status`, imports)
- Modify: `crates/zerodpi-core/src/sni_scanner.rs` (make `make_tls_connector` public — 1 line)

**Interfaces:**
- Consumes: `MethodSampleResult` (Task 2); `Config::SCAN_DOWNLOAD_CAP`, `Config::LISTEN_HOST`, `Config::LISTEN_PORT` (Task 1); `sni_scanner::make_tls_connector` (made `pub` in this task).
- Produces: `pub async fn direct_probe(config: &Config, connect_addr: std::net::SocketAddr, sni: &str, http_path: &str, timeout: std::time::Duration) -> MethodSampleResult` (consumed by Task 4).

- [ ] **Step 1: Make the TLS connector reusable**

In `crates/zerodpi-core/src/sni_scanner.rs` change `fn make_tls_connector() -> TlsConnector {` to `pub fn make_tls_connector() -> TlsConnector {`.

- [ ] **Step 2: Write the failing tests**

Add to the `mod tests` at the bottom of `crates/zerodpi-core/src/method_scanner.rs`:

```rust
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
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-core method_scanner`
Expected: compile errors — `direct_probe`, `read_http_response`, `parse_http_status` do not exist.

- [ ] **Step 4: Implement the probe**

Add these imports to the top of `crates/zerodpi-core/src/method_scanner.rs` (merge with the Task 2 imports):

```rust
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tracing::debug;

use crate::sni_scanner::make_tls_connector;
```

Then add the probe functions after `cfg_with_method`:

```rust
// ---------------------------------------------------------------------------
// Direct probe
// ---------------------------------------------------------------------------

/// Parse the status code out of an HTTP response head.
fn parse_http_status(head: &str) -> Option<u16> {
    let rest = head.strip_prefix("HTTP/")?;
    rest.split_once(' ')?.1.get(0..3)?.parse().ok()
}

/// Read an HTTP response up to `cap` bytes. Returns (TTFB ms, status, bytes).
async fn read_http_response<S>(stream: &mut S, cap: usize, timeout: Duration) -> (Option<u64>, Option<u16>, usize)
where
    S: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; cap];
    let mut total_read = 0usize;
    let mut ttfb_ms: Option<u64> = None;
    let mut http_status: Option<u16> = None;
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
                    if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                        http_status = parse_http_status(text);
                    }
                }
                total_read += n;
            }
            Ok(Err(_)) => break,
        }
    }
    (ttfb_ms, http_status, total_read)
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
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core method_scanner`
Expected: all tests PASS (4 new + 7 from Task 2).

- [ ] **Step 6: Commit**

```bash
git add crates/zerodpi-core/src/method_scanner.rs crates/zerodpi-core/src/sni_scanner.rs
git commit -m "feat: add direct TLS+HTTP probe for method scanning"
```

---

### Task 4: Engine loop — one engine per method, N samples

**Files:**
- Modify: `crates/zerodpi-core/src/method_scanner.rs`

**Interfaces:**
- Consumes: `direct_probe` (Task 3); `entry_from_samples`, `rank_entries`, `cfg_with_method`, `MethodScanTarget`, `MethodScanEvent` (Task 2); existing internals `crate::flow::{new_flow_table, FlowController, LocalFlowController}`, `crate::handler::Handler`, `crate::interceptor::{FilterSpec, InterceptorShutdown, PacketInterceptor}`, `crate::methods::build_method`, `crate::proxy::{run_proxy, ActiveSniTarget, CONNECT_PORT}` (mirror the usage in `crates/zerodpi-core/src/proxy_tester.rs::test_candidate_full`).
- Produces: `pub async fn run_method_tests<F, I>(config: Arc<Config>, target: MethodScanTarget, methods: Vec<String>, interface_ip: std::net::Ipv4Addr, progress_tx: Option<tokio::sync::mpsc::UnboundedSender<MethodScanEvent>>, interceptor_factory: F) -> anyhow::Result<Vec<MethodScanEntry>>` where `F: Fn(FilterSpec) -> anyhow::Result<I> + Send + 'static`, `I: PacketInterceptor` (consumed by Task 5).

- [ ] **Step 1: Add the implementation**

Add imports at the top of `crates/zerodpi-core/src/method_scanner.rs`:

```rust
use tokio::sync::mpsc;
use tracing::warn;

use crate::flow::{new_flow_table, FlowController, LocalFlowController};
use crate::handler::Handler;
use crate::interceptor::{FilterSpec, InterceptorShutdown, PacketInterceptor};
use crate::methods::build_method;
use crate::proxy::{run_proxy, ActiveSniTarget, CONNECT_PORT};
```

Add after `direct_probe`:

```rust
// ---------------------------------------------------------------------------
// Engine loop
// ---------------------------------------------------------------------------

/// Run every method in `methods` against `target` and return ranked entries.
///
/// Each method gets a fresh engine (proxy task + interceptor when the method
/// needs one) and `METHOD_SCAN_SAMPLES` probes spaced by
/// `METHOD_SCAN_INTERVAL_MS`. `interceptor_factory` opens the platform
/// interceptor exactly like `proxy_tester::test_candidate_full` expects.
pub async fn run_method_tests<F, I>(
    config: Arc<Config>,
    target: MethodScanTarget,
    methods: Vec<String>,
    interface_ip: std::net::Ipv4Addr,
    progress_tx: Option<mpsc::UnboundedSender<MethodScanEvent>>,
    interceptor_factory: F,
) -> anyhow::Result<Vec<MethodScanEntry>>
where
    F: Fn(FilterSpec) -> anyhow::Result<I> + Send + 'static,
    I: PacketInterceptor,
{
    let listen_addr: SocketAddr = format!("{}:{}", config.LISTEN_HOST, config.LISTEN_PORT)
        .parse()
        .context("invalid LISTEN_HOST/LISTEN_PORT")?;
    let connect_addr = if listen_addr.ip().is_unspecified() {
        SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, listen_addr.port()))
    } else {
        listen_addr
    };

    let mut entries = Vec::with_capacity(methods.len());
    for (index, method) in methods.iter().enumerate() {
        let entry = run_one_method(
            &config,
            &target,
            method,
            index,
            interface_ip,
            progress_tx.as_ref(),
            connect_addr,
            &interceptor_factory,
        )
        .await;
        entries.push(entry);
        // Small gap so the previous interceptor thread can exit before the
        // next one opens (same rationale as proxy_scan).
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(rank_entries(entries))
}

/// One method: engine up, `METHOD_SCAN_SAMPLES` probes, engine down.
async fn run_one_method<F, I>(
    config: &Arc<Config>,
    target: &MethodScanTarget,
    method: &str,
    method_index: usize,
    interface_ip: std::net::Ipv4Addr,
    progress_tx: Option<&mpsc::UnboundedSender<MethodScanEvent>>,
    connect_addr: SocketAddr,
    interceptor_factory: &F,
) -> MethodScanEntry
where
    F: Fn(FilterSpec) -> anyhow::Result<I> + Send + 'static,
    I: PacketInterceptor,
{
    let cfg = cfg_with_method(config, method);
    let samples_total = cfg.METHOD_SCAN_SAMPLES;
    let interval = Duration::from_millis(cfg.METHOD_SCAN_INTERVAL_MS);
    let timeout = Duration::from_secs(cfg.METHOD_SCAN_TIMEOUT_SECS);

    let active_target = Arc::new(std::sync::RwLock::new(ActiveSniTarget::new(
        target.sni.clone(),
        target.ip,
        target.score,
    )));

    let flows = new_flow_table();
    let flow_controller: Arc<dyn FlowController> = Arc::new(LocalFlowController::new(flows.clone()));

    // Packet interceptor — only when this method needs one.
    let mut interceptor_guard: Option<(InterceptorShutdown, tokio::sync::oneshot::Receiver<()>)> =
        None;
    if !cfg.BYPASS_METHOD.is_socket_only() {
        let method_box = match build_method(&cfg) {
            Some(m) => m,
            None => {
                warn!(method, "build_method returned None — marking all samples failed");
                return failed_entry(method, samples_total, "build_method returned None".to_owned());
            }
        };
        let method_arc: Arc<dyn crate::methods::BypassMethod> = Arc::from(method_box);
        let filter = FilterSpec {
            interface_ip,
            remote_ip: Some(target.ip),
            remote_port: CONNECT_PORT,
            queue_num: cfg.NFQUEUE_NUM,
            linux_firewall_backend: cfg.linux_firewall_backend(),
            firewall_owner: None,
        };
        let interceptor = match interceptor_factory(filter) {
            Ok(i) => i,
            Err(e) => {
                warn!(method, error = %e, "failed to open packet interceptor — marking all samples failed");
                return failed_entry(method, samples_total, format!("interceptor open failed: {e}"));
            }
        };
        let handler = Handler::new(flows.clone(), method_arc);
        let shutdown = InterceptorShutdown::default();
        let thread_shutdown = shutdown.clone();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let _thread = std::thread::Builder::new()
            .name(format!("zerodpi-method-scan-{method}"))
            .spawn(move || {
                if let Err(e) = interceptor.run_until(handler, thread_shutdown) {
                    debug!(error = %e, method, "method-scan intercept thread ended");
                }
                let _ = done_tx.send(());
            });
        interceptor_guard = Some((shutdown, done_rx));
    }

    // Proxy task on LISTEN_HOST:LISTEN_PORT relaying to the target.
    let proxy_cfg = cfg.clone();
    let proxy_target = active_target.clone();
    let proxy_fc = flow_controller.clone();
    let proxy_task = tokio::spawn(async move {
        let _ = run_proxy(proxy_cfg, proxy_target, interface_ip, proxy_fc, None).await;
    });
    // Give the listener a moment to bind before connecting.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Samples.
    let mut samples = Vec::with_capacity(samples_total);
    for i in 0..samples_total {
        if i > 0 && interval > Duration::ZERO {
            tokio::time::sleep(interval).await;
        }
        let result = direct_probe(&cfg, connect_addr, &target.sni, target.http_path, timeout).await;
        if let Some(tx) = progress_tx {
            let _ = tx.send(MethodScanEvent::SampleDone {
                method: method.to_owned(),
                sample: i + 1,
                ok: result.ok,
            });
        }
        samples.push(result);
    }

    // Teardown.
    proxy_task.abort();
    if let Some((shutdown, done_rx)) = interceptor_guard {
        shutdown.request();
        let _ = tokio::time::timeout(Duration::from_secs(2), done_rx).await;
    }

    let entry = entry_from_samples(method, &samples);
    if let Some(tx) = progress_tx {
        let _ = tx.send(MethodScanEvent::MethodDone {
            method: method.to_owned(),
            completed: method_index + 1,
            entry: entry.clone(),
        });
    }
    entry
}

/// Entry for a method whose engine could not start: every sample failed.
fn failed_entry(method: &str, samples_total: usize, error: String) -> MethodScanEntry {
    MethodScanEntry {
        method: method.to_owned(),
        samples_total,
        samples_ok: 0,
        success_rate: 0.0,
        avg_ttfb_ms: None,
        min_ttfb_ms: None,
        max_ttfb_ms: None,
        avg_tls_ms: None,
        http_status: None,
        last_error: Some(error),
    }
}
```

- [ ] **Step 2: Build and run all core tests**

Run: `cargo test -p zerodpi-core`
Expected: all tests PASS. (The engine loop itself is not unit-tested — it needs a live interceptor; the pure pieces from Tasks 2–3 are.)

- [ ] **Step 3: Commit**

```bash
git add crates/zerodpi-core/src/method_scanner.rs
git commit -m "feat: add per-method engine loop with sample interval"
```

---

### Task 5: Wire the modes into `main.rs`

**Files:**
- Modify: `crates/zerodpi/src/main.rs`

**Interfaces:**
- Consumes: `run_method_tests`, `rank_entries`, `MethodScanTarget`, `MethodScanEvent`, `MethodScanReport` (Tasks 2–4); existing `scan_sni_list`, `count_hostnames`, `scan_sni_list_headless`, `load_ip_list`, `scan_ip_list`, `SniProbeEntry`, `IpScanEvent`, `default_interface_ipv4`, `DefaultInterceptor`, `ScanKind`, `RuntimeEvent`, `tui::run_scan_progress`, `tui::run_ip_scan_progress` (all already in `main.rs`).
- Produces: two new mode entry points `sni_method_scan_main` / `ip_method_scan_main`, a shared `method_scan_phase1` helper, `resolve_method_output_path`, `save_method_report`, `print_method_scan_report`. (Consumed by Task 6 for the TUI view names.)

- [ ] **Step 1: Add imports**

Add to the existing `use zerodpi_core::...` block at the top of `crates/zerodpi/src/main.rs`:

```rust
use zerodpi_core::method_scanner::{
    rank_entries, run_method_tests, MethodScanEvent, MethodScanReport, MethodScanTarget,
};
```

Ensure `IpAddr` is imported (`use std::net::{IpAddr, Ipv4Addr, ...}` — extend the existing `std::net` import if `IpAddr` is not already listed).

- [ ] **Step 2: Add the mode dispatch branches**

In `main()`, immediately after the `if cfg.MODE == "proxy_scan" { ... }` branch (near line 361), add:

```rust
    if cfg.MODE == "sni_method_scan" {
        let cfg_clone = cfg.clone();
        let cfg_path_clone = cfg_path.clone();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return sni_method_scan_main(cfg_clone, cfg_path_clone, rt, no_tui, events);
    }
    if cfg.MODE == "ip_method_scan" {
        let cfg_clone = cfg.clone();
        let cfg_path_clone = cfg_path.clone();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return ip_method_scan_main(cfg_clone, cfg_path_clone, rt, no_tui, events);
    }
```

- [ ] **Step 3: Add the two entry points and Phase 1 helper**

Insert after `ip_scan_main` (before the "Scan result persistence helpers" section, near line 2490):

```rust
// ---------------------------------------------------------------------------
// sni_method_scan / ip_method_scan modes
// ---------------------------------------------------------------------------

/// `sni_method_scan`: Phase 0 scans the SNI list, then Phase 1 tests every
/// configured bypass method against the top candidate.
fn sni_method_scan_main(
    cfg: Arc<Config>,
    cfg_path: PathBuf,
    rt: tokio::runtime::Runtime,
    no_tui: bool,
    events: RuntimeEventEmitter,
) -> Result<()> {
    let sni_list_path = {
        let raw = PathBuf::from(&cfg.SNI_LIST);
        if raw.is_absolute() {
            raw
        } else {
            cfg_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(raw)
        }
    };

    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);
    info!(path = %sni_list_path.display(), "sni_method_scan: Phase 0 — scanning SNI list");

    let sorted = if no_tui {
        rt.block_on(scan_sni_list_headless(
            cfg.clone(),
            &sni_list_path,
            scan_timeout,
            &events,
            ScanKind::Sni,
        ))?
    } else {
        let total_hostnames = count_hostnames(&sni_list_path);
        let (tx, mut rx) = mpsc::unbounded_channel::<SniProbeEntry>();
        let scan_handle = rt.spawn(async move {
            scan_sni_list(&sni_list_path, scan_timeout, cfg.clone(), Some(tx)).await
        });

        let mut terminal = tui::enter_tui()?;
        let (arrived, aborted) = tui::run_scan_progress(&mut terminal, &mut rx, total_hostnames)?;
        tui::leave_tui(terminal)?;

        if scan_handle.is_finished() {
            rt.block_on(scan_handle)
                .context("scanner task panicked")??
        } else {
            scan_handle.abort();
            if aborted {
                info!(
                    "sni_method_scan: Phase 0 aborted — using {} results collected so far",
                    arrived.len()
                );
            }
            let mut e = arrived;
            e.sort_by(|a, b| {
                b.score.cmp(&a.score).then(
                    a.tcp_latency_ms
                        .unwrap_or(u64::MAX)
                        .cmp(&b.tcp_latency_ms.unwrap_or(u64::MAX)),
                )
            });
            e
        }
    };

    let top = sorted.into_iter().next().ok_or_else(|| {
        anyhow::anyhow!("sni_method_scan: no SNI candidates — cannot test bypass methods")
    })?;
    info!(
        sni = %top.sni,
        ip = %top.ip,
        score = top.score,
        "sni_method_scan: top candidate selected"
    );

    let target = MethodScanTarget {
        sni: top.sni.clone(),
        ip: top.ip,
        score: top.score,
        http_path: "/",
    };
    method_scan_phase1(cfg, &cfg_path, &rt, no_tui, &events, target, "sni_method_scan")
}

/// `ip_method_scan`: Phase 0 scans the IP list, then Phase 1 tests every
/// configured bypass method against the top IPv4 candidate (TLS SNI =
/// `IP_SCAN_SNI`, matching `ip_scan`).
fn ip_method_scan_main(
    cfg: Arc<Config>,
    cfg_path: PathBuf,
    rt: tokio::runtime::Runtime,
    no_tui: bool,
    events: RuntimeEventEmitter,
) -> Result<()> {
    let ip_list_path = {
        let raw = PathBuf::from(&cfg.IP_LIST);
        if raw.is_absolute() {
            raw
        } else {
            cfg_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(raw)
        }
    };

    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);
    let ips = load_ip_list(&ip_list_path, cfg.IPV6_MAX_HOSTS)
        .with_context(|| format!("loading ip_list from '{}'", ip_list_path.display()))?;
    if ips.is_empty() {
        anyhow::bail!(
            "ip_list '{}' is empty — add at least one IP or CIDR",
            ip_list_path.display()
        );
    }
    let total_ips = ips.len();
    info!(total_ips, "ip_method_scan: Phase 0 — scanning IP list");

    let scan_sni: Arc<str> = Arc::from(cfg.IP_SCAN_SNI.as_str());
    let cfg_clone = cfg.clone();
    let sorted = if no_tui {
        rt.block_on(scan_ip_list_headless(
            ips,
            scan_sni,
            scan_timeout,
            cfg_clone,
            &events,
            Some(&ip_list_path),
        ))
    } else {
        let (tx, mut rx) = mpsc::unbounded_channel::<IpScanEvent>();
        let scan_handle = rt.spawn(async move {
            scan_ip_list(ips, scan_sni, scan_timeout, cfg_clone, Some(tx)).await
        });

        let mut terminal = tui::enter_tui()?;
        let (arrived, aborted) = tui::run_ip_scan_progress(&mut terminal, &mut rx, total_ips)?;
        tui::leave_tui(terminal)?;

        if scan_handle.is_finished() {
            rt.block_on(scan_handle).context("scanner task panicked")?
        } else {
            scan_handle.abort();
            if aborted {
                info!(
                    "ip_method_scan: Phase 0 aborted — using {} results collected so far",
                    arrived.len()
                );
            }
            let mut e = arrived;
            e.sort_by(|a, b| {
                b.score.cmp(&a.score).then(
                    a.tcp_latency_ms
                        .unwrap_or(u64::MAX)
                        .cmp(&b.tcp_latency_ms.unwrap_or(u64::MAX)),
                )
            });
            e
        }
    };

    let top = sorted
        .iter()
        .find(|e| e.ip.is_ipv4())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "ip_method_scan: no IPv4 candidate in scan results — method testing requires an IPv4 target"
            )
        })?;
    let target_ip = match top.ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => unreachable!("filtered by is_ipv4 above"),
    };
    info!(
        ip = %target_ip,
        sni = %cfg.IP_SCAN_SNI,
        score = top.score,
        "ip_method_scan: top IPv4 candidate selected"
    );

    let target = MethodScanTarget {
        sni: cfg.IP_SCAN_SNI.clone(),
        ip: target_ip,
        score: top.score,
        http_path: "/cdn-cgi/trace",
    };
    method_scan_phase1(cfg, &cfg_path, &rt, no_tui, &events, target, "ip_method_scan")
}

/// Phase 1 shared by both method-scan modes: test every method in
/// `METHOD_SCAN_METHODS` against `target`, then report.
fn method_scan_phase1(
    cfg: Arc<Config>,
    cfg_path: &Path,
    rt: &tokio::runtime::Runtime,
    no_tui: bool,
    events: &RuntimeEventEmitter,
    target: MethodScanTarget,
    mode_name: &str,
) -> Result<()> {
    let interface_ip = default_interface_ipv4(target.ip)
        .context("method scan: could not determine local interface IP")?;

    let methods: Vec<String> = cfg.METHOD_SCAN_METHODS.iter().map(str::to_owned).collect();
    let total_methods = methods.len();
    info!(
        methods = ?methods,
        samples = cfg.METHOD_SCAN_SAMPLES,
        interval_ms = cfg.METHOD_SCAN_INTERVAL_MS,
        "{mode_name}: Phase 1 — testing bypass methods"
    );

    let (tx, rx) = mpsc::unbounded_channel::<MethodScanEvent>();
    let cfg_for_phase1 = cfg.clone();
    let target_for_phase1 = target.clone();
    let methods_for_phase1 = methods.clone();

    // Each method spins up an OS thread (WinDivert/NFQUEUE), so run the
    // loop inside spawn_blocking like proxy_scan does.
    let phase_handle = rt.spawn_blocking(move || {
        let rt2 = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("method scan: failed to build Phase 1 runtime");
        rt2.block_on(async move {
            run_method_tests(
                cfg_for_phase1,
                target_for_phase1,
                methods_for_phase1,
                interface_ip,
                Some(tx),
                |filter| DefaultInterceptor::open(filter),
            )
            .await
        })
    });

    let entries = if no_tui {
        events.emit(RuntimeEvent::ScanStarted {
            scan: ScanKind::Proxy,
            path: None,
            total: Some(total_methods),
        });
        let progress_events = events.clone();
        let mut rx = rx;
        let progress_handle = rt.spawn(async move {
            let mut completed = 0usize;
            while let Some(ev) = rx.recv().await {
                if let MethodScanEvent::MethodDone { entry, .. } = ev {
                    completed += 1;
                    progress_events.emit(RuntimeEvent::ScanProgress {
                        scan: ScanKind::Proxy,
                        phase: Some("method_test".to_owned()),
                        completed,
                        total: Some(total_methods),
                        sni: Some(target.sni.clone()),
                        ip: Some(target.ip.to_string()),
                        score: Some(entry.success_rate.round() as u8),
                    });
                }
            }
        });
        let results = rt
            .block_on(phase_handle)
            .context("method scan Phase 1 task panicked")?;
        let _ = rt.block_on(progress_handle);
        events.emit(RuntimeEvent::ScanCompleted {
            scan: ScanKind::Proxy,
            results: results.len(),
        });
        results
    } else {
        let mut rx = rx;
        let mut terminal = tui::enter_tui()?;
        let (arrived, aborted) = tui::run_method_scan_progress(
            &mut terminal,
            &mut rx,
            total_methods,
            cfg.METHOD_SCAN_SAMPLES,
        )?;
        tui::leave_tui(terminal)?;

        if phase_handle.is_finished() {
            rt.block_on(phase_handle)
                .context("method scan Phase 1 task panicked")?
        } else {
            phase_handle.abort();
            if aborted {
                info!(
                    "{mode_name}: Phase 1 aborted — using {} results collected so far",
                    arrived.len()
                );
            }
            rank_entries(arrived)
        }
    };

    let report = MethodScanReport {
        mode: mode_name.to_owned(),
        target_sni: target.sni.clone(),
        target_ip: target.ip,
        target_score: target.score,
        samples_per_method: cfg.METHOD_SCAN_SAMPLES,
        interval_ms: cfg.METHOD_SCAN_INTERVAL_MS,
        methods: entries,
    };

    info!(
        "{mode_name} complete — {} methods tested",
        report.methods.len()
    );
    for e in &report.methods {
        info!("{}", e.summary_line());
    }

    let output_path = resolve_method_output_path(&cfg, cfg_path);
    let saved_path_str: Option<String> = if let Some(ref p) = output_path {
        save_method_report(p, &report)?;
        Some(p.display().to_string())
    } else {
        None
    };

    if no_tui {
        print_method_scan_report(&report);
    } else {
        let mut terminal = tui::enter_tui()?;
        tui::run_method_results_view(&mut terminal, &report, saved_path_str.as_deref())?;
        tui::leave_tui(terminal)?;
    }

    Ok(())
}

/// Resolve `METHOD_SCAN_OUTPUT` relative to the config file directory.
fn resolve_method_output_path(cfg: &Config, cfg_path: &Path) -> Option<PathBuf> {
    let raw = cfg.METHOD_SCAN_OUTPUT.as_deref()?;
    let raw_path = PathBuf::from(raw);
    if raw_path.is_absolute() {
        Some(raw_path)
    } else {
        Some(
            cfg_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(raw_path),
        )
    }
}

fn save_method_report(path: &Path, report: &MethodScanReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report).context("serialising method-scan report")?;
    std::fs::write(path, json)
        .with_context(|| format!("writing method-scan report to '{}'", path.display()))?;
    info!(path = %path.display(), "method scan: report saved");
    Ok(())
}

/// Print the ranked report to stdout — the headless on-screen display.
fn print_method_scan_report(report: &MethodScanReport) {
    println!(
        "method scan complete — {} methods tested against {} ({}), {} samples each, {} ms interval",
        report.methods.len(),
        report.target_sni,
        report.target_ip,
        report.samples_per_method,
        report.interval_ms,
    );
    for (rank, e) in report.methods.iter().enumerate() {
        println!("  #{:<3} {}", rank + 1, e.summary_line());
    }
}
```

Note: `scan_sni_list_headless` and `scan_ip_list_headless` take `&events` / `&RuntimeEventEmitter`; if the existing signatures take ownership, pass `events` (they already take `&RuntimeEventEmitter` — verify with the compiler).

- [ ] **Step 4: Build**

Run: `cargo build` — this will fail until Task 6 because `tui::run_method_scan_progress` and `tui::run_method_results_view` don't exist yet. Confirm the *only* errors are those two missing functions, then proceed directly to Task 6 before committing (Tasks 5+6 are one reviewable unit).

---

### Task 6: TUI progress and results views

**Files:**
- Modify: `crates/zerodpi/src/tui.rs`

**Interfaces:**
- Consumes: `MethodScanEntry`, `MethodScanEvent`, `MethodScanReport` (Tasks 2); existing ratatui imports already in `tui.rs` (`Layout`, `Direction`, `Constraint`, `Paragraph`, `Block`, `Borders`, `Style`, `Color`, `Modifier`, `Gauge`, `Table`, `Row`, `Cell`, `TableState`, `Frame`, `Term`, `event`, `Event`, `KeyCode`, `KeyEventKind`).
- Produces:
  - `pub fn run_method_scan_progress(terminal: &mut Term, rx: &mut tokio::sync::mpsc::UnboundedReceiver<MethodScanEvent>, total_methods: usize, samples_per_method: usize) -> anyhow::Result<(Vec<MethodScanEntry>, bool)>`
  - `pub fn run_method_results_view(terminal: &mut Term, report: &MethodScanReport, output_path: Option<&str>) -> anyhow::Result<()>`

- [ ] **Step 1: Add the import**

Add to the existing `use zerodpi_core::...` imports in `crates/zerodpi/src/tui.rs`:

```rust
use zerodpi_core::method_scanner::{MethodScanEntry, MethodScanEvent, MethodScanReport};
```

- [ ] **Step 2: Add the progress view**

Append to `crates/zerodpi/src/tui.rs` (modeled on the existing `run_scan_progress`):

```rust
// ---------------------------------------------------------------------------
// Method-scan Phase 1 progress view
// ---------------------------------------------------------------------------

/// Live progress view for method-scan Phase 1. Returns entries collected so
/// far and whether the user aborted.
pub fn run_method_scan_progress(
    terminal: &mut Term,
    rx: &mut mpsc::UnboundedReceiver<MethodScanEvent>,
    total_methods: usize,
    samples_per_method: usize,
) -> anyhow::Result<(Vec<MethodScanEntry>, bool)> {
    let mut state = MethodScanProgressState {
        done: Vec::new(),
        current_method: None,
        current_sample: 0,
        ok_in_current: 0,
    };

    loop {
        // Drain all currently available events.
        loop {
            match rx.try_recv() {
                Ok(MethodScanEvent::SampleDone { method, sample, ok }) => {
                    state.current_method = Some(method);
                    state.current_sample = sample;
                    if ok {
                        state.ok_in_current += 1;
                    }
                }
                Ok(MethodScanEvent::MethodDone { entry, .. }) => {
                    state.done.push(entry);
                    state.current_method = None;
                    state.current_sample = 0;
                    state.ok_in_current = 0;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Engine finished – draw one final frame and return.
                    draw_method_scan_progress(terminal, &state, total_methods, samples_per_method)?;
                    return Ok((state.done, false));
                }
            }
        }

        draw_method_scan_progress(terminal, &state, total_methods, samples_per_method)?;

        // Poll for user input (Ctrl-C / q to abort).
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press
                    && (matches!(k.code, KeyCode::Char('q') | KeyCode::Char('Q'))
                        || k.code == KeyCode::Esc)
                {
                    return Ok((state.done, true));
                }
            }
        }
    }
}

struct MethodScanProgressState {
    done: Vec<MethodScanEntry>,
    current_method: Option<String>,
    current_sample: usize,
    ok_in_current: usize,
}

fn draw_method_scan_progress(
    terminal: &mut Term,
    state: &MethodScanProgressState,
    total_methods: usize,
    samples_per_method: usize,
) -> anyhow::Result<()> {
    let completed = state.done.len();
    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // header
                Constraint::Length(3), // methods gauge
                Constraint::Length(3), // current sample line
                Constraint::Min(5),    // results so far
            ])
            .split(area);

        let header = Paragraph::new("ZeroDPI — Testing Bypass Methods…")
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(header, chunks[0]);

        let ratio = if total_methods == 0 {
            0.0
        } else {
            (completed as f64 / total_methods as f64).min(1.0)
        };
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" Methods "))
            .gauge_style(Style::default().fg(Color::Green))
            .ratio(ratio)
            .label(format!("{completed}/{total_methods} methods tested"));
        frame.render_widget(gauge, chunks[1]);

        let current_line = match &state.current_method {
            Some(m) => format!(
                "Testing {m}: sample {}/{samples_per_method} ({} ok so far)",
                state.current_sample, state.ok_in_current
            ),
            None => "—".to_owned(),
        };
        let current = Paragraph::new(current_line)
            .block(Block::default().borders(Borders::ALL).title(" Current "));
        frame.render_widget(current, chunks[2]);

        let rows: Vec<Row> = state
            .done
            .iter()
            .rev()
            .take(8)
            .map(|e| {
                Row::new(vec![
                    Cell::from(format!("{:.1}%", e.success_rate)),
                    Cell::from(e.method.clone()),
                    Cell::from(format!("{}/{}", e.samples_ok, e.samples_total)),
                    Cell::from(
                        e.avg_ttfb_ms
                            .map(|v| format!("{v:.0}ms"))
                            .unwrap_or_else(|| "—".into()),
                    ),
                    Cell::from(e.last_error.clone().unwrap_or_default()),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(8),
            Constraint::Length(24),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Min(20),
        ];
        let table = Table::new(rows, widths)
            .header(
                Row::new(vec!["Rate", "Method", "OK", "Avg TTFB", "Error"])
                    .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL).title(" Results so far "));
        frame.render_widget(table, chunks[3]);
    })?;
    Ok(())
}
```

(Verify `mpsc` is imported in `tui.rs` — it already is, since `run_scan_progress` takes `mpsc::UnboundedReceiver`.)

- [ ] **Step 3: Add the results view**

Append after the progress view:

```rust
// ---------------------------------------------------------------------------
// Method-scan results view
// ---------------------------------------------------------------------------

/// Interactive results table: ranked methods with the best on top.
pub fn run_method_results_view(
    terminal: &mut Term,
    report: &MethodScanReport,
    output_path: Option<&str>,
) -> anyhow::Result<()> {
    if report.methods.is_empty() {
        return Ok(());
    }

    let mut state = TableState::default();
    state.select(Some(0));

    loop {
        terminal.draw(|frame| draw_method_results_view(frame, report, &mut state, output_path))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some(i.saturating_sub(1)));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some((i + 1).min(report.methods.len() - 1)));
                    }
                    _ => return Ok(()),
                }
            }
        }
    }
}

fn draw_method_results_view(
    frame: &mut Frame,
    report: &MethodScanReport,
    state: &mut TableState,
    output_path: Option<&str>,
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(2), // sub-header
            Constraint::Min(5),    // table
            Constraint::Length(1), // footer
        ])
        .split(area);

    let header = Paragraph::new(format!(
        "ZeroDPI — Best bypass method for {} ({})",
        report.target_sni, report.target_ip
    ))
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let sub = Paragraph::new(format!(
        "{} methods × {} samples, interval {} ms — ranked by success rate, then avg TTFB",
        report.methods.len(),
        report.samples_per_method,
        report.interval_ms
    ));
    frame.render_widget(sub, chunks[1]);

    let rows: Vec<Row> = report
        .methods
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let rate_style = if e.success_rate >= 100.0 {
                Style::default().fg(Color::Green)
            } else if e.success_rate >= 50.0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Red)
            };
            Row::new(vec![
                Cell::from((i + 1).to_string()),
                Cell::from(e.method.clone()).style(if i == 0 {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                }),
                Cell::from(format!("{}/{}", e.samples_ok, e.samples_total)),
                Cell::from(format!("{:.1}%", e.success_rate)).style(rate_style),
                Cell::from(
                    e.avg_ttfb_ms
                        .map(|v| format!("{v:.0}ms"))
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(
                    e.min_ttfb_ms
                        .map(|v| format!("{v}ms"))
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(
                    e.max_ttfb_ms
                        .map(|v| format!("{v}ms"))
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(
                    e.avg_tls_ms
                        .map(|v| format!("{v:.0}ms"))
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(
                    e.http_status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(e.last_error.clone().unwrap_or_default()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(24),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Min(20),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Method", "OK", "Rate", "Avg TTFB", "Min", "Max", "Avg TLS", "HTTP",
                "Error",
            ])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    frame.render_stateful_widget(table, chunks[2], state);

    let footer = Paragraph::new(match output_path {
        Some(p) => format!("Report saved to {p} — press any key to exit"),
        None => "METHOD_SCAN_OUTPUT not set — press any key to exit".to_owned(),
    });
    frame.render_widget(footer, chunks[3]);
}
```

(Check `tui.rs` already imports `mpsc`, `Term`, `TableState`, `Frame`; it does — `run_scan_progress` and `draw_sni_results_view` use them.)

- [ ] **Step 4: Build the whole workspace**

Run: `cargo build --workspace`
Expected: compiles cleanly (Task 5's two missing-function errors are now resolved).

- [ ] **Step 5: Run all checks**

Run:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

Expected: all pass. If clippy flags the new code, fix inline and re-run before committing.

- [ ] **Step 6: Commit**

```bash
git add crates/zerodpi/src/main.rs crates/zerodpi/src/tui.rs
git commit -m "feat: wire sni_method_scan and ip_method_scan modes"
```

---

### Task 7: Documentation — `config.toml` and `README.md`

**Files:**
- Modify: `config.toml`
- Modify: `README.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Document the new config fields in `config.toml`**

After the `SCAN_OUTPUT` block in `config.toml`, add:

```toml
# ---------------------------------------------------------------------------
# Method Scan Modes
# ---------------------------------------------------------------------------
# These settings apply when MODE = "sni_method_scan" or "ip_method_scan".
# These modes first run the normal scan internally (sni_scan / ip_scan),
# pick the single top-scoring candidate, then test every bypass method
# against it to find which method works best. Method parameters are taken
# from this config file unchanged.

# Bypass methods to test, in any order. Defaults to every base method;
# trim the list to test only a subset.
#METHOD_SCAN_METHODS = ["wrong_seq", "tls_frag"]

# Number of probe samples per method. Must be >= 1. Default: 10.
METHOD_SCAN_SAMPLES = 10

# Interval between samples in milliseconds. 0 = back-to-back.
# Default: 1000.
METHOD_SCAN_INTERVAL_MS = 1000

# Per-sample probe timeout in seconds (TCP + TLS + HTTP). Must be > 0.
# Default: 10.
METHOD_SCAN_TIMEOUT_SECS = 10

# Optional path to write the method-scan report as a JSON file.
# Relative paths are resolved from the directory containing config.toml.
# Leave as an empty string ("") to disable saving.
METHOD_SCAN_OUTPUT = ""
```

- [ ] **Step 2: Update the MODE documentation in `config.toml`**

In the `MODE` comment block, extend the valid-values list and add two bullet lines after the `proxy_scan` bullet:

```toml
# - "sni_method_scan" — scan sni_list.txt, pick the top candidate, then test
#                       every METHOD_SCAN_METHODS bypass method against it
#                       and report which works best; then exit.
# - "ip_method_scan"   — scan ip_list.txt, pick the top IPv4 candidate, then
#                       test every METHOD_SCAN_METHODS bypass method against
#                       it (TLS SNI = IP_SCAN_SNI) and report; then exit.
```

- [ ] **Step 3: Update `README.md`**

Add a "Method Scan Modes" subsection under the scan-modes documentation (wherever `sni_scan`/`ip_scan`/`proxy_scan` are described) covering:
- What the two modes do (Phase 0 target scan, Phase 1 per-method testing, ranking by success rate then avg TTFB).
- The five new config fields with defaults (`METHOD_SCAN_SAMPLES = 10`, `METHOD_SCAN_INTERVAL_MS = 1000`, `METHOD_SCAN_TIMEOUT_SECS = 10`, `METHOD_SCAN_METHODS` = all base methods, `METHOD_SCAN_OUTPUT` = `""`).
- The JSON report structure (`mode`, `target_sni`, `target_ip`, `target_score`, `samples_per_method`, `interval_ms`, `methods[]` with `success_rate`, `avg_ttfb_ms`, `last_error`, …).
- Note that interceptor-based methods need Admin/root (Linux/Windows) and fail with `last_error` otherwise; socket-only methods work without.
- Note the platform impact line: no changes to NFQUEUE/WinDivert behavior; method scans open the interceptor per method, same as `proxy_scan`.

- [ ] **Step 4: Commit**

```bash
git add config.toml README.md
git commit -m "docs: document method-scan modes and config fields"
```

---

## Self-Review Notes (already applied)

- Spec coverage: config surface (Task 1), types/ranking/report (Task 2), direct probe (Task 3), engine loop + interval (Task 4), mode wiring + save/print (Task 5), TUI views (Task 6), docs (Task 7). The spec's "no root → per-method failure" behavior is `run_one_method`'s interceptor-open error path; IPv6 skip is `ip_method_scan_main`'s `find(is_ipv4)`; the 200 ms inter-method gap is in `run_method_tests`.
- Type consistency: `MethodScanTarget.http_path` is `&'static str` and both call sites pass `"/"` and `"/cdn-cgi/trace"`; `run_method_tests` takes `interceptor_factory: F` by value and `run_one_method` takes `&F`; `MethodScanEvent::MethodDone.completed` is `method_index + 1`; `rank_entries` is used by both the engine loop and the TUI-abort path in `main.rs`.
- Placeholders: none — all steps contain full code.
