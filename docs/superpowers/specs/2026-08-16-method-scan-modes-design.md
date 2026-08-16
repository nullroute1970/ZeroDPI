# Method-Scan Modes Design (`sni_method_scan` / `ip_method_scan`)

**Date:** 2026-08-16
**Status:** Approved design (implementation plan in `docs/superpowers/plans/2026-08-16-method-scan-modes.md`)

## Goal

The existing `sni_scan` and `ip_scan` modes find the best *target* (SNI hostname or relay IP). The new `sni_method_scan` and `ip_method_scan` modes keep the target fixed and instead find the best *bypass method* for it: they run every configured bypass method end-to-end through ZeroDPI's full engine (proxy + packet interceptor) and rank methods by how reliably they get real application data through.

## Decisions (agreed with user)

1. **Target selection (option B):** each mode first runs its normal scan internally (`sni_scan` / `ip_scan`), picks the single top-scoring candidate, then tests all methods against it. No config override for the target in v1.
2. **Method list (option B):** new config field `METHOD_SCAN_METHODS`, a list that defaults to all 16 base bypass methods. Users can trim it.
3. **Success criterion (option B, refined):** a sample succeeds when the TLS handshake completes through the engine **and** an HTTP response arrives with at least one body byte. *Refinement of the approved "HTTP 200":* any received status proves the relay carries application data; requiring exactly 200 would fail entire methods on hosts that redirect `/`. The probe paths are chosen so 200 is typical (`/` for SNI mode, `/cdn-cgi/trace` for IP mode), and the status code is recorded per method in the report. Ranking: success rate desc, then average TTFB asc (methods with no TTFB sort last on ties).
4. **Report (option A):** JSON file via new `METHOD_SCAN_OUTPUT` field, a TUI results table (interactive mode), and a plain-text table printed to stdout for `--no-tui` runs.

## Config surface (new fields, all optional)

| Field | Type | Default | Validation |
|---|---|---|---|
| `METHOD_SCAN_METHODS` | `BypassMethodList` (string or array) | all 16 `BASE_BYPASS_METHODS` | non-empty, entries in `BASE_BYPASS_METHODS`, no duplicates |
| `METHOD_SCAN_SAMPLES` | `usize` | `10` | `>= 1` |
| `METHOD_SCAN_INTERVAL_MS` | `u64` | `1000` | any (`0` = back-to-back) |
| `METHOD_SCAN_TIMEOUT_SECS` | `u64` | `10` | `> 0` (per-sample probe timeout) |
| `METHOD_SCAN_OUTPUT` | `Option<String>` | `""` (disabled) | path resolved relative to config dir |

`MODE` accepts two new values: `"sni_method_scan"`, `"ip_method_scan"`.

Method parameters are **not** changed during a scan: each method runs with its existing config values (e.g. `low_ttl` uses `LOW_TTL_VALUE`, with `LOW_TTL_DISCOVER` never invoked during method scans).

## Flow

**Phase 0 — target scan (identical to existing scan modes):**
- `sni_method_scan`: load `SNI_LIST`, run `scan_sni_list` (TUI progress view if interactive), take the single top-scoring `SniProbeEntry` (already IPv4).
- `ip_method_scan`: load `IP_LIST`, run `scan_ip_list`, take the top-scoring **IPv4** `IpProbeEntry` (skip IPv6 — the engine and interceptor filter are IPv4-only; bail if no IPv4 candidate). Probe SNI is `IP_SCAN_SNI` and probe path `/cdn-cgi/trace`, matching `ip_scan`.

**Phase 1 — method testing:** for each method in `METHOD_SCAN_METHODS`, in order:
1. Clone the config with `BYPASS_METHOD = [method]` (via `BypassMethodList::from_delimited`).
2. Open the engine once for the method: the proxy task on `LISTEN_HOST:LISTEN_PORT` relaying to the target, plus the packet interceptor when the method is not socket-only (same wiring as `proxy_tester::test_candidate_full`: `FilterSpec` on the target IP:443, `Handler`, `DefaultInterceptor` opened by a factory closure passed from `main.rs`).
3. Run `METHOD_SCAN_SAMPLES` direct probes. Between samples sleep `METHOD_SCAN_INTERVAL_MS` (no sleep before the first sample).
4. Teardown (abort proxy task, request interceptor shutdown with 2 s grace), wait a 200 ms gap, next method.

**Direct probe (per sample):** TCP connect to `LISTEN_HOST:LISTEN_PORT` (127.0.0.1 when host is unspecified) → TLS handshake with the target SNI (`tokio-rustls`, reusing `sni_scanner::make_tls_connector`, made `pub`) → `GET <http_path> HTTP/1.1` with `Host` header → read up to `SCAN_DOWNLOAD_CAP` bytes. Whole probe bounded by `METHOD_SCAN_TIMEOUT_SECS`. Records: `ok`, TLS handshake ms, TTFB ms, speed B/s, HTTP status, error string.

**Failure handling:** per-sample failure (timeout, connect error, handshake failure, no response) is a failed sample — never fatal. Per-method failure to open the interceptor (no root/Admin, driver missing) marks all of that method's samples failed with an explanatory `last_error`; socket-only methods still test fine without root. Empty Phase 0 results bail before Phase 1. TUI abort (`q`/Esc) during Phase 1 keeps the partial results, ranked the same way.

## Report

`MethodScanReport` (serde `Serialize`) written as pretty JSON to `METHOD_SCAN_OUTPUT`:

```
mode, target_sni, target_ip, target_score,
samples_per_method, interval_ms,
methods: [ MethodScanEntry ... ]
```

`MethodScanEntry`: `method`, `samples_total`, `samples_ok`, `success_rate` (0–100, f64), `avg_ttfb_ms`, `min_ttfb_ms`, `max_ttfb_ms`, `avg_tls_ms`, `http_status`, `last_error`.

**Screen:** interactive mode shows a live progress view (current method, sample n/N, OK count, cumulative gauge) then a results table (rank, method, ok/total, rate %, avg TTFB, avg TLS, HTTP, error). `--no-tui` prints the ranked table to stdout via `println!` so it is always visible.

## Scope notes (v1)

- The Android root-helper path (`RemoteHelperClient`) is not wired into method scans; interceptor methods fail per-method with a clear error there, socket-only methods work.
- `mode_requires_packet_interception` is unchanged: method-scan modes do not trigger the startup root gate; failures surface per method in the report.
- Runtime events: Phase 0 emits the existing `ScanKind::Sni` / `ScanKind::Ip` events; Phase 1 emits `ScanKind::Proxy` events like `proxy_scan`. `ScanKind` is not extended.
- No new dependencies. Platform requirements unchanged.

## Files touched

- `crates/zerodpi-core/src/config.rs` — 5 fields, 4 default fns, validation, MODE whitelist.
- `crates/zerodpi-core/src/sni_scanner.rs` — make `make_tls_connector` `pub` (1 line).
- `crates/zerodpi-core/src/method_scanner.rs` — **new**: types, ranking, direct probe, engine loop.
- `crates/zerodpi-core/src/lib.rs` — export the new module.
- `crates/zerodpi/src/main.rs` — mode dispatch, `sni_method_scan_main`, `ip_method_scan_main`, report save + stdout table.
- `crates/zerodpi/src/tui.rs` — Phase 1 progress view, results table view.
- `config.toml`, `README.md` — document new modes and fields.

## Testing

- Config: defaults, custom values, rejection of zero samples, unknown/duplicate methods, new modes validate.
- `method_scanner`: sample aggregation, ranking (rate desc, avg-TTFB asc, None-last), JSON serialization, HTTP status parsing, response reading against a local mock TCP listener, probe failure path against a closed port.
- Engine loop and TUI views are exercised via `cargo build`/`clippy` and a manual `--no-tui` run; they are not unit-tested (need a live interceptor).
