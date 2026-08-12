# TUI Running & State Panel Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrich the live proxy dashboard's "Running & State" area (header + stats bar + connection log) with peak connections, target-switch tracking, last-error reporting, rescan result summaries, throughput sparklines, and per-connection outbound target IPs.

**Architecture:** Extend two `ProxyEvent` variants in `zerodpi-core` so the proxy reports each connection's outbound target IP and each background rescan's outcome summary. The `zerodpi` CLI emits the richer rescan events, and the ratatui dashboard accumulates the new state in `DashboardState`, renders it in the existing header/stats/log layout (header gains conditional lines, stats becomes two content lines, a new throughput strip with ratatui `Sparkline`s, and the log table gains a "Target" column).

**Tech Stack:** Rust 2021 workspace; ratatui 0.29 (`Sparkline`, `RenderDirection`, `Paragraph`); crossterm 0.28; tokio mpsc channels; `zerodpi-core` `ProxyEvent` enum.

**Spec:** Inline "Requirements" section below — agreed in brainstorming (user selected Options 1, 2, and 3). No separate design doc exists.

## Requirements (agreed design)

- **Option 1 (TUI-only stats):**
  - Peak concurrent connections (`peak_active`) shown in the stats bar.
  - Target hot-swap counter (`target_switches`) + "how long ago" shown in the header for all modes.
  - Aggregate throughput sparklines (down + up, last 60 s) in a new strip between the stats bar and the connection log.
  - Rescan counter + last-rescan summary (found / best score / duration / switched-or-kept) shown in the rescan status line.
- **Option 2 (use data core already emits):**
  - `ConnectionError`'s `error` string becomes a red "Last error" line in the header (with src port + wall-clock time).
  - `IpTargetChanged`'s `score` is displayed next to the active IP.
  - `ListenerStarted`'s bound address replaces the cfg-derived "Listen" value once known.
- **Option 3 (new data from core):**
  - `ConnectionAccepted` gains `target_ip: IpAddr`; the connection log gains a "Target" column.
  - Per-connection setup time remains visible for free: the existing "Duration" column shows time-since-accept while a row is `Connecting`, which *is* the bypass/connect duration. No new column needed.
  - `RescanFinished` gains `found: usize`, `best_score: Option<u8>`, `duration_ms: u64`, `switched: bool`.

## Global Constraints

- Runtime event contract must NOT change: `RuntimeEvent` variants and `CONTRACT_VERSION = 1` stay exactly as-is (`crates/zerodpi/src/runtime_events.rs` is untouched).
- No new `config.toml` options; no new TUI keybindings (help bar unchanged).
- All code must pass `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- 4-space indentation, `snake_case` functions/variables, `PascalCase` types (existing codebase style).
- Commits use conventional prefixes (`feat:`, `refactor:`, `docs:`).
- Task 1 intentionally leaves the workspace uncompilable for the `zerodpi` crate — verify only with `cargo test -p zerodpi-core`. From Task 2 onward the full workspace must compile and pass.
- Tests live in inline `#[cfg(test)]` modules beside the code they cover, named by behavior (existing pattern in `tui.rs` and `proxy.rs`).

---

### Task 1: Extend `ProxyEvent` in zerodpi-core (target IP + rescan summary)

**Files:**
- Modify: `crates/zerodpi-core/src/proxy.rs` (enum def ~line 79, emit sites at ~555, ~900, ~1294, tests ~1555)

**Interfaces:**
- Produces (for later tasks):
  - `ProxyEvent::ConnectionAccepted { peer: SocketAddr, src_port: u16, target_ip: IpAddr }`
  - `ProxyEvent::RescanFinished { kind: RescanKind, found: usize, best_score: Option<u8>, duration_ms: u64, switched: bool }`
  - `RescanKind` unchanged.

- [x] **Step 1: Write the failing test**

In `crates/zerodpi-core/src/proxy.rs`, in the existing `#[cfg(test)] mod tests`, update `rescan_events_construct_with_kind_and_interval` and add one new test.

Find:
```rust
        let finished = ProxyEvent::RescanFinished {
            kind: RescanKind::Ip,
        };
        let scheduled = ProxyEvent::NextRescanScheduled {
            kind: RescanKind::Sni,
            interval_secs: 300,
        };
        assert_eq!(format!("{started:?}"), "RescanStarted { kind: Sni }");
        assert_eq!(format!("{finished:?}"), "RescanFinished { kind: Ip }");
```

Replace with:
```rust
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
```

Append this test to the module (before the closing `}` of `mod tests`):

```rust
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
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core`
Expected: FAIL — compile error: `ConnectionAccepted` lacks `target_ip`, `RescanFinished` lacks the new fields.

- [x] **Step 3: Update the enum definitions**

In `crates/zerodpi-core/src/proxy.rs`, find:
```rust
    /// A new inbound connection was accepted and the outbound source port is known.
    ConnectionAccepted { peer: SocketAddr, src_port: u16 },
```
Replace with:
```rust
    /// A new inbound connection was accepted and the outbound source port is known.
    ConnectionAccepted {
        peer: SocketAddr,
        src_port: u16,
        /// The outbound IP this connection relays to (snapshot at accept time).
        target_ip: IpAddr,
    },
```

Find:
```rust
    /// A periodic background rescan finished (success, empty result, or failure).
    RescanFinished { kind: RescanKind },
```
Replace with:
```rust
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
```

- [x] **Step 4: Update the three emit sites**

All three sites look like:
```rust
    emit(&event_tx, ProxyEvent::ConnectionAccepted { peer, src_port });
```
Update each one:

1. In `handle_intercept_connection` (the `let src_port = local.port();` site) — `connect_ip` is `Ipv4Addr` there:
```rust
    emit(
        &event_tx,
        ProxyEvent::ConnectionAccepted {
            peer,
            src_port,
            target_ip: IpAddr::V4(connect_ip),
        },
    );
```
2. In `handle_tcp_seg_connection_with_ip` (`let src_port = peer.port();` site) — `connect_ip` is `Ipv4Addr` there:
```rust
    emit(
        &event_tx,
        ProxyEvent::ConnectionAccepted {
            peer,
            src_port,
            target_ip: IpAddr::V4(connect_ip),
        },
    );
```
3. In `handle_ip_bypass_connection` (`emit(&event_tx, ProxyEvent::ConnectionAccepted { peer, src_port });` after `let connect_addr = ...`) — `connect_ip` is `IpAddr` there:
```rust
    emit(
        &event_tx,
        ProxyEvent::ConnectionAccepted {
            peer,
            src_port,
            target_ip: connect_ip,
        },
    );
```

Note: `IpAddr` is already in scope in `proxy.rs` (used by `IpTargetChanged` and `run_ip_bypass_plus_proxy`).

- [x] **Step 5: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core`
Expected: PASS (the `zerodpi` crate will NOT compile yet — expected, fixed in Task 2).

- [x] **Step 6: Commit**

```bash
git add crates/zerodpi-core/src/proxy.rs
git commit -m "feat: extend proxy events with target ip and rescan summary"
```

---

### Task 2: Thread new fields through main.rs and restore compilation

**Files:**
- Modify: `crates/zerodpi/src/main.rs` (rescan emits ~1050–1190, ~2100–2210; `log_headless_proxy_events` ~1469–1590)
- Modify: `crates/zerodpi/src/tui.rs` (`ConnectionRecord` struct, `apply_event` `ConnectionAccepted` arm ~1009, tests ~2100 and ~2200)

**Interfaces:**
- Consumes: Task 1's new `ProxyEvent` shapes.
- Produces: working workspace build; `ConnectionRecord.target_ip: IpAddr` field (displayed in Task 7).

- [x] **Step 1: SNI background rescan emits real summary**

In `background_rescan`, find (after the `RescanStarted` send):
```rust
        send_rescan_event(
            &event_tx,
            ProxyEvent::RescanStarted {
                kind: RescanKind::Sni,
            },
        );
        let cfg_clone = cfg.clone();
        match scan_sni_list(&path, scan_timeout, cfg_clone, None).await {
            Ok(entries) => {
```
Replace with:
```rust
        send_rescan_event(
            &event_tx,
            ProxyEvent::RescanStarted {
                kind: RescanKind::Sni,
            },
        );
        let scan_started = std::time::Instant::now();
        let mut switched = false;
        let mut scan_summary: Option<(usize, Option<u8>)> = None;
        let cfg_clone = cfg.clone();
        match scan_sni_list(&path, scan_timeout, cfg_clone, None).await {
            Ok(entries) => {
                scan_summary = Some((entries.len(), entries.first().map(|e| e.score)));
```

Find the hot-swap event send (inside the `Some(next)` arm):
```rust
                                if let Some(ref tx) = event_tx {
                                    let _ = tx.send(ProxyEvent::SniTargetChanged {
                                        sni: next.sni.to_string(),
                                        ip: next.ip,
                                        score: next.score,
                                    });
                                    if let Some(value) = discovered {
                                        let _ = tx.send(ProxyEvent::LowTtlDiscovered { value });
                                    }
                                }
```
Add one line after this block:
```rust
                                switched = true;
```

Find the final emit of the loop iteration:
```rust
        send_rescan_event(
            &event_tx,
            ProxyEvent::RescanFinished {
                kind: RescanKind::Sni,
            },
        );
    }
}
```
Replace with:
```rust
        let (found, best_score) = scan_summary.unwrap_or((0, None));
        send_rescan_event(
            &event_tx,
            ProxyEvent::RescanFinished {
                kind: RescanKind::Sni,
                found,
                best_score,
                duration_ms: scan_started.elapsed().as_millis() as u64,
                switched,
            },
        );
    }
}
```

- [x] **Step 2: IP background rescan emits real summary**

In `background_ip_rescan`, find:
```rust
        send_rescan_event(
            &event_tx,
            ProxyEvent::RescanStarted {
                kind: RescanKind::Ip,
            },
        );
```
Replace with:
```rust
        send_rescan_event(
            &event_tx,
            ProxyEvent::RescanStarted {
                kind: RescanKind::Ip,
            },
        );
        let scan_started = std::time::Instant::now();
```

Update the three failure-path emits (load failed / ipv6 rejected / empty entries) — each currently reads:
```rust
                send_rescan_event(
                    &event_tx,
                    ProxyEvent::RescanFinished {
                        kind: RescanKind::Ip,
                    },
                );
```
Replace each with:
```rust
                send_rescan_event(
                    &event_tx,
                    ProxyEvent::RescanFinished {
                        kind: RescanKind::Ip,
                        found: 0,
                        best_score: None,
                        duration_ms: scan_started.elapsed().as_millis() as u64,
                        switched: false,
                    },
                );
```

Find the success path:
```rust
        let current = *active_ip.read().unwrap();
        if best.ip != current {
            *active_ip.write().unwrap() = best.ip;
            if let Some(ref tx) = event_tx {
                let _ = tx.send(ProxyEvent::IpTargetChanged {
                    ip: best.ip,
                    score: best.score,
                });
            }
            info!(mode = policy.mode_label, old = %current, new = %best.ip, "hot-swapped active IP");
        }
        send_rescan_event(
            &event_tx,
            ProxyEvent::RescanFinished {
                kind: RescanKind::Ip,
            },
        );
```
Replace with:
```rust
        let current = *active_ip.read().unwrap();
        let switched = best.ip != current;
        if switched {
            *active_ip.write().unwrap() = best.ip;
            if let Some(ref tx) = event_tx {
                let _ = tx.send(ProxyEvent::IpTargetChanged {
                    ip: best.ip,
                    score: best.score,
                });
            }
            info!(mode = policy.mode_label, old = %current, new = %best.ip, "hot-swapped active IP");
        }
        send_rescan_event(
            &event_tx,
            ProxyEvent::RescanFinished {
                kind: RescanKind::Ip,
                found: entries.len(),
                best_score: Some(best.score),
                duration_ms: scan_started.elapsed().as_millis() as u64,
                switched,
            },
        );
```

- [x] **Step 3: Update the headless event logger**

In `log_headless_proxy_events`, find:
```rust
            ProxyEvent::ConnectionAccepted { peer, src_port } => {
                events.emit(RuntimeEvent::ConnectionAccepted {
                    peer: peer.to_string(),
                    src_port,
                });
                info!(%peer, src_port, "accepted proxy connection");
            }
```
Replace with:
```rust
            ProxyEvent::ConnectionAccepted {
                peer,
                src_port,
                target_ip,
            } => {
                events.emit(RuntimeEvent::ConnectionAccepted {
                    peer: peer.to_string(),
                    src_port,
                });
                info!(%peer, src_port, %target_ip, "accepted proxy connection");
            }
```

Find:
```rust
            ProxyEvent::RescanFinished { kind } => {
                debug!(?kind, "background rescan finished");
            }
```
Replace with:
```rust
            ProxyEvent::RescanFinished {
                kind,
                found,
                best_score,
                duration_ms,
                switched,
            } => {
                debug!(
                    ?kind,
                    found,
                    ?best_score,
                    duration_ms,
                    switched,
                    "background rescan finished"
                );
            }
```

- [x] **Step 4: Minimal tui.rs compile fixes (behavior added in later tasks)**

In `crates/zerodpi/src/tui.rs`:

1. `ConnectionRecord` struct — find:
```rust
    /// Address of the client that opened the inbound connection.
    peer: SocketAddr,
```
Replace with:
```rust
    /// Address of the client that opened the inbound connection.
    peer: SocketAddr,
    /// Outbound target IP this connection relays to (from ConnectionAccepted).
    target_ip: IpAddr,
```
(`IpAddr` is already imported at the top of `tui.rs`.)

2. `apply_event` — find:
```rust
        ProxyEvent::ConnectionAccepted { peer, src_port } => {
            state.total += 1;
            state.active += 1;
            let now = Instant::now();
            let rec = ConnectionRecord {
                started_at: SystemTime::now(),
                start_instant: now,
                end_instant: None,
                src_port,
                peer,
```
Replace with:
```rust
        ProxyEvent::ConnectionAccepted {
            peer,
            src_port,
            target_ip,
        } => {
            state.total += 1;
            state.active += 1;
            let now = Instant::now();
            let rec = ConnectionRecord {
                started_at: SystemTime::now(),
                start_instant: now,
                end_instant: None,
                src_port,
                peer,
                target_ip,
```

3. Test helper `record(...)` — find:
```rust
            src_port: 443,
            peer: "127.0.0.1:12345".parse().unwrap(),
            status,
```
Replace with:
```rust
            src_port: 443,
            peer: "127.0.0.1:12345".parse().unwrap(),
            target_ip: "203.0.113.1".parse().unwrap(),
            status,
```

4. Test `apply_event_keeps_active_connections_when_log_is_full` — find:
```rust
            ProxyEvent::ConnectionAccepted {
                peer: "127.0.0.1:22222".parse().unwrap(),
                src_port: new_active_port,
            },
```
Replace with:
```rust
            ProxyEvent::ConnectionAccepted {
                peer: "127.0.0.1:22222".parse().unwrap(),
                src_port: new_active_port,
                target_ip: "203.0.113.2".parse().unwrap(),
            },
```

5. Test `apply_event_tracks_rescan_running_state` — find both occurrences of:
```rust
            ProxyEvent::RescanFinished {
                kind: RescanKind::Ip,
            },
```
Replace each with:
```rust
            ProxyEvent::RescanFinished {
                kind: RescanKind::Ip,
                found: 0,
                best_score: None,
                duration_ms: 0,
                switched: false,
            },
```

- [x] **Step 5: Verify the whole workspace compiles and tests pass**

Run: `cargo test --workspace`
Expected: PASS (all pre-existing tests, now with the updated event shapes).

- [x] **Step 6: Commit**

```bash
git add crates/zerodpi/src/main.rs crates/zerodpi/src/tui.rs
git commit -m "feat: report rescan summary and per-connection target ip to dashboard"
```

---

### Task 3: New dashboard state (peak, switches, errors, rescan summary)

**Files:**
- Modify: `crates/zerodpi/src/tui.rs` (`DashboardState`, `run_dashboard` init, `apply_event`, test helpers)

**Interfaces:**
- Consumes: Task 2's event shapes.
- Produces (used by Tasks 4–6):
  - `RescanSummary { found: usize, best_score: Option<u8>, duration_ms: u64, switched: bool }` (`Debug, Clone, Copy, PartialEq, Eq`)
  - `LastError { src_port: u16, message: String, at: SystemTime }` (`Debug, Clone`)
  - `ThroughputSample { at: Instant, up_bps: f64, down_bps: f64 }` (`Debug, Clone, Copy`)
  - `DashboardState` fields: `peak_active: u64`, `target_switches: u64`, `last_switch_at: Option<Instant>`, `rescan_count: u64`, `last_rescan: Option<RescanSummary>`, `rescan_started_at: Option<Instant>`, `last_error: Option<LastError>`, `active_ip_score: Option<u8>`, `listener: Option<(String, SocketAddr)>`, `throughput_history: VecDeque<ThroughputSample>`

- [x] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` in `tui.rs` (before its closing brace):

```rust
    #[test]
    fn apply_event_tracks_peak_active_connections() {
        let mut state = dashboard_state(vec![]);
        for port in [1000u16, 2000, 3000] {
            apply_event(
                ProxyEvent::ConnectionAccepted {
                    peer: "127.0.0.1:11111".parse().unwrap(),
                    src_port: port,
                    target_ip: "203.0.113.1".parse().unwrap(),
                },
                &mut state,
            );
        }
        assert_eq!(state.active, 3);
        assert_eq!(state.peak_active, 3);

        apply_event(
            ProxyEvent::RelayFinished {
                src_port: 2000,
                c2s_bytes: 0,
                s2c_bytes: 0,
                reason: RelayEndReason::Completed,
            },
            &mut state,
        );
        assert_eq!(state.active, 2);
        assert_eq!(state.peak_active, 3);
    }

    #[test]
    fn apply_event_counts_target_switches() {
        let mut state = dashboard_state(vec![]);
        apply_event(
            ProxyEvent::SniTargetChanged {
                sni: "example.com".into(),
                ip: "203.0.113.1".parse().unwrap(),
                score: 80,
            },
            &mut state,
        );
        apply_event(
            ProxyEvent::IpTargetChanged {
                ip: "203.0.113.2".parse().unwrap(),
                score: 70,
            },
            &mut state,
        );
        assert_eq!(state.target_switches, 2);
        assert!(state.last_switch_at.is_some());
        assert_eq!(state.active_ip_score, Some(70));
    }

    #[test]
    fn apply_event_records_last_connection_error() {
        let mut state = dashboard_state(vec![]);
        apply_event(
            ProxyEvent::ConnectionError {
                src_port: 99,
                error: "connection refused".into(),
            },
            &mut state,
        );
        let err = state.last_error.as_ref().expect("last_error should be set");
        assert_eq!(err.src_port, 99);
        assert_eq!(err.message, "connection refused");
    }

    #[test]
    fn apply_event_stores_rescan_summary() {
        let mut state = dashboard_state(vec![]);
        apply_event(
            ProxyEvent::RescanStarted {
                kind: RescanKind::Sni,
            },
            &mut state,
        );
        assert!(state.rescan_running);
        apply_event(
            ProxyEvent::RescanFinished {
                kind: RescanKind::Sni,
                found: 3,
                best_score: Some(88),
                duration_ms: 2100,
                switched: true,
            },
            &mut state,
        );
        assert!(!state.rescan_running);
        assert_eq!(state.rescan_count, 1);
        assert_eq!(
            state.last_rescan,
            Some(RescanSummary {
                found: 3,
                best_score: Some(88),
                duration_ms: 2100,
                switched: true,
            })
        );
    }

    #[test]
    fn apply_event_stores_target_ip_on_accept() {
        let mut state = dashboard_state(vec![]);
        apply_event(
            ProxyEvent::ConnectionAccepted {
                peer: "127.0.0.1:12345".parse().unwrap(),
                src_port: 777,
                target_ip: "203.0.113.7".parse().unwrap(),
            },
            &mut state,
        );
        let rec = state.records.front().expect("record should exist");
        assert_eq!(rec.target_ip, "203.0.113.7".parse::<IpAddr>().unwrap());
    }
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi apply_event_`
Expected: FAIL — compile error: `RescanSummary`, `LastError`, `ThroughputSample` undefined; new `DashboardState` fields missing.

- [x] **Step 3: Add the new types**

Insert after the `FilterStatus` impl block (before `/// Per-connection record kept in the dashboard log.`):

```rust
/// Summary of the most recently completed background rescan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RescanSummary {
    found: usize,
    best_score: Option<u8>,
    duration_ms: u64,
    switched: bool,
}

/// The most recent fatal connection error, shown in the header.
#[derive(Debug, Clone)]
struct LastError {
    src_port: u16,
    message: String,
    at: SystemTime,
}

/// One aggregate-throughput sample for the sparkline strip.
#[derive(Debug, Clone, Copy)]
struct ThroughputSample {
    at: Instant,
    up_bps: f64,
    down_bps: f64,
}
```

- [x] **Step 4: Add the new `DashboardState` fields**

Find:
```rust
    rescan_running: bool,
    /// Deadline for the next rescan cycle, set from `NextRescanScheduled`.
    next_rescan_at: Option<Instant>,
```
Replace with:
```rust
    rescan_running: bool,
    /// Deadline for the next rescan cycle, set from `NextRescanScheduled`.
    next_rescan_at: Option<Instant>,
    /// Highest number of simultaneously active connections seen so far.
    peak_active: u64,
    /// How many times the active target has been hot-swapped by a rescan.
    target_switches: u64,
    /// When the most recent target switch happened (for "Xs ago" display).
    last_switch_at: Option<Instant>,
    /// Number of completed background rescans.
    rescan_count: u64,
    /// Summary of the most recently completed rescan.
    last_rescan: Option<RescanSummary>,
    /// When the current rescan started (shown while running).
    rescan_started_at: Option<Instant>,
    /// Most recent ConnectionError, shown as a header line.
    last_error: Option<LastError>,
    /// Score of the active IP target (from `IpTargetChanged`).
    active_ip_score: Option<u8>,
    /// (mode, bound address) reported by `ListenerStarted`.
    listener: Option<(String, SocketAddr)>,
    /// Rolling aggregate throughput samples for the sparklines.
    throughput_history: VecDeque<ThroughputSample>,
```

- [x] **Step 5: Initialize the fields in `run_dashboard`**

Find:
```rust
        rescan_running: false,
        next_rescan_at: None,
        start: Instant::now(),
        channel_closed: false,
    };
```
Replace with:
```rust
        rescan_running: false,
        next_rescan_at: None,
        peak_active: 0,
        target_switches: 0,
        last_switch_at: None,
        rescan_count: 0,
        last_rescan: None,
        rescan_started_at: None,
        last_error: None,
        active_ip_score: None,
        listener: None,
        throughput_history: VecDeque::new(),
        start: Instant::now(),
        channel_closed: false,
    };
```
(`VecDeque::new()` is temporary — Task 6 Step 4 switches it to `VecDeque::with_capacity(THROUGHPUT_MAX_SAMPLES)`.)

- [x] **Step 6: Update `apply_event`**

Find:
```rust
        ProxyEvent::ListenerStarted { .. } => {}
```
Replace with:
```rust
        ProxyEvent::ListenerStarted { mode, listen_addr } => {
            state.listener = Some((mode, listen_addr));
        }
```

Find (Task 2's version):
```rust
        } => {
            state.total += 1;
            state.active += 1;
```
Replace with:
```rust
        } => {
            state.total += 1;
            state.active += 1;
            state.peak_active = state.peak_active.max(state.active);
```

Find:
```rust
        ProxyEvent::ConnectionError { src_port, .. } => {
            state.bypasses_failed += 1;
```
Replace with:
```rust
        ProxyEvent::ConnectionError { src_port, error } => {
            state.last_error = Some(LastError {
                src_port,
                message: error,
                at: SystemTime::now(),
            });
            state.bypasses_failed += 1;
```

Find:
```rust
        ProxyEvent::SniTargetChanged { sni, ip, score } => {
            state.active_sni = Some((sni, ip, score));
        }
        ProxyEvent::IpTargetChanged { ip, .. } => {
            state.active_ip = Some(ip);
        }
```
Replace with:
```rust
        ProxyEvent::SniTargetChanged { sni, ip, score } => {
            state.active_sni = Some((sni, ip, score));
            state.target_switches += 1;
            state.last_switch_at = Some(Instant::now());
        }
        ProxyEvent::IpTargetChanged { ip, score } => {
            state.active_ip = Some(ip);
            state.active_ip_score = Some(score);
            state.target_switches += 1;
            state.last_switch_at = Some(Instant::now());
        }
```

Find:
```rust
        ProxyEvent::RescanStarted { .. } => {
            state.rescan_running = true;
        }
        ProxyEvent::RescanFinished { .. } => {
            state.rescan_running = false;
        }
```
Replace with:
```rust
        ProxyEvent::RescanStarted { .. } => {
            state.rescan_running = true;
            state.rescan_started_at = Some(Instant::now());
        }
        ProxyEvent::RescanFinished {
            found,
            best_score,
            duration_ms,
            switched,
            ..
        } => {
            state.rescan_running = false;
            state.rescan_started_at = None;
            state.rescan_count += 1;
            state.last_rescan = Some(RescanSummary {
                found,
                best_score,
                duration_ms,
                switched,
            });
        }
```

- [x] **Step 7: Update the `dashboard_state(...)` test helper**

Find:
```rust
            active_sni: None,
            active_ip: None,
            low_ttl: None,
            rescan_running: false,
            next_rescan_at: None,
            start: Instant::now(),
            channel_closed: false,
        }
```
Replace with:
```rust
            active_sni: None,
            active_ip: None,
            low_ttl: None,
            rescan_running: false,
            next_rescan_at: None,
            peak_active: 0,
            target_switches: 0,
            last_switch_at: None,
            rescan_count: 0,
            last_rescan: None,
            rescan_started_at: None,
            last_error: None,
            active_ip_score: None,
            listener: None,
            throughput_history: VecDeque::new(),
            start: Instant::now(),
            channel_closed: false,
        }
```

- [x] **Step 8: Run tests to verify they pass**

Run: `cargo test -p zerodpi`
Expected: PASS (new tests + all existing).

- [x] **Step 9: Commit**

```bash
git add crates/zerodpi/src/tui.rs
git commit -m "feat: track peak, switches, errors, and rescan summary in dashboard state"
```

---

### Task 4: Richer header (switches, IP score, last error, rescan results)

**Files:**
- Modify: `crates/zerodpi/src/tui.rs` (`fmt_ago` helper, `rescan_status_line`, `header_content_rows`, `draw_dashboard` header section, tests)

**Interfaces:**
- Consumes: Task 3's `DashboardState` fields.
- Produces: `fn header_content_rows(state: &DashboardState, now: Instant) -> usize` (used by Tasks 5/6 layout + scroll math), `fn fmt_ago(d: Duration) -> String`.

- [x] **Step 1: Write the failing tests**

Append to the tests module in `tui.rs`:

```rust
    #[test]
    fn fmt_ago_formats_seconds_minutes_hours() {
        assert_eq!(fmt_ago(Duration::from_secs(9)), "9s ago");
        assert_eq!(fmt_ago(Duration::from_secs(90)), "1m ago");
        assert_eq!(fmt_ago(Duration::from_secs(7200)), "2h ago");
    }

    #[test]
    fn rescan_status_line_shows_elapsed_while_running() {
        let mut state = dashboard_state(vec![]);
        state.rescan_running = true;
        state.rescan_started_at = Some(Instant::now() - Duration::from_secs(3));
        let line = rescan_status_line(&state, Instant::now()).expect("line should be present");
        assert_eq!(line.spans[1].content, "running… 3s");
    }

    #[test]
    fn rescan_status_line_includes_last_rescan_summary() {
        let mut state = dashboard_state(vec![]);
        let now = Instant::now();
        state.next_rescan_at = Some(now + Duration::from_secs(300));
        state.rescan_count = 2;
        state.last_rescan = Some(RescanSummary {
            found: 3,
            best_score: Some(88),
            duration_ms: 2100,
            switched: true,
        });
        let line = rescan_status_line(&state, now).expect("line should be present");
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("rescan #2: 3 found, best 88, 2.1s, switched"));
    }

    #[test]
    fn header_content_rows_counts_error_and_rescan_lines() {
        let mut state = dashboard_state(vec![]);
        let now = Instant::now();
        assert_eq!(header_content_rows(&state, now), 2);
        state.last_error = Some(LastError {
            src_port: 1,
            message: "boom".into(),
            at: SystemTime::now(),
        });
        assert_eq!(header_content_rows(&state, now), 3);
        state.next_rescan_at = Some(now + Duration::from_secs(60));
        assert_eq!(header_content_rows(&state, now), 4);
    }
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi header_content_rows rescan_status_line_shows_elapsed fmt_ago`
Expected: FAIL — compile error: `fmt_ago`, `header_content_rows` undefined.

- [x] **Step 3: Add `fmt_ago`**

After `fn fmt_uptime(...)` add:
```rust
/// Compact "how long ago" label for target switches.
fn fmt_ago(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h ago", secs / 3600)
    }
}
```

- [x] **Step 4: Extend `rescan_status_line` and add `header_content_rows`**

Find:
```rust
fn rescan_status_line(state: &DashboardState, now: Instant) -> Option<Line<'static>> {
    if state.rescan_running {
        return Some(Line::from(vec![
            Span::styled("Rescan: ", label_style()),
            Span::styled(
                "running…",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    }
    let next_at = state.next_rescan_at?;
    let remaining = next_at.saturating_duration_since(now);
    Some(Line::from(vec![
        Span::styled("Next rescan in: ", label_style()),
        Span::styled(fmt_uptime(remaining), Style::default().fg(Color::White)),
    ]))
}
```
Replace with:
```rust
fn rescan_status_line(state: &DashboardState, now: Instant) -> Option<Line<'static>> {
    if state.rescan_running {
        let elapsed = state
            .rescan_started_at
            .map(|t| format!(" {}", fmt_uptime(now.saturating_duration_since(t))))
            .unwrap_or_default();
        return Some(Line::from(vec![
            Span::styled("Rescan: ", label_style()),
            Span::styled(
                format!("running…{elapsed}"),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    }
    let next_at = state.next_rescan_at?;
    let remaining = next_at.saturating_duration_since(now);
    let mut spans = vec![
        Span::styled("Next rescan in: ", label_style()),
        Span::styled(fmt_uptime(remaining), Style::default().fg(Color::White)),
    ];
    if let Some(last) = &state.last_rescan {
        let score = last
            .best_score
            .map(|s| s.to_string())
            .unwrap_or_else(|| "—".into());
        let verdict = if last.switched { "switched" } else { "kept" };
        spans.push(Span::styled(
            format!(
                "   · rescan #{}: {} found, best {}, {:.1}s, {}",
                state.rescan_count,
                last.found,
                score,
                last.duration_ms as f64 / 1000.0,
                verdict,
            ),
            Style::default().fg(Color::Gray),
        ));
    }
    Some(Line::from(spans))
}

/// Number of text lines the dashboard header renders, excluding borders.
fn header_content_rows(state: &DashboardState, now: Instant) -> usize {
    2 + usize::from(rescan_status_line(state, now).is_some())
        + usize::from(state.last_error.is_some())
}
```

- [x] **Step 5: Header height from the helper; hoist `now`**

In `draw_dashboard`, find:
```rust
    terminal.draw(|frame| {
        let area = frame.area();
        let rescan_line = rescan_status_line(state, Instant::now());
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(if rescan_line.is_some() { 7 } else { 5 }), // header (2 or 3 info lines + borders)
```
Replace with:
```rust
    terminal.draw(|frame| {
        let area = frame.area();
        let now = Instant::now();
        let rescan_line = rescan_status_line(state, now);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length((header_content_rows(state, now) + 3) as u16), // header lines + borders + slack
```

Later in the same function, find (connection log section):
```rust
        // ── Connection log ───────────────────────────────────────────────────
        let now = Instant::now();
```
Replace with:
```rust
        // ── Connection log ───────────────────────────────────────────────────
```

- [x] **Step 6: SNI mode header — switches + listener + last-error line**

Find the SniSpoof first line:
```rust
                    Line::from(vec![
                        Span::styled("SNI: ", label_style()),
                        Span::styled(
                            sni.clone(),
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw("   "),
                        Span::styled("IP: ", label_style()),
                        Span::styled(ip.to_string(), Style::default().fg(Color::White)),
                        Span::raw("   "),
                        Span::styled("Score: ", label_style()),
                        Span::styled(score.to_string(), score_style(*score)),
                    ]),
```
Replace with:
```rust
                    {
                        let mut spans = vec![
                            Span::styled("SNI: ", label_style()),
                            Span::styled(
                                sni.clone(),
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::raw("   "),
                            Span::styled("IP: ", label_style()),
                            Span::styled(ip.to_string(), Style::default().fg(Color::White)),
                            Span::raw("   "),
                            Span::styled("Score: ", label_style()),
                            Span::styled(score.to_string(), score_style(*score)),
                            Span::raw("   "),
                            Span::styled("Switches: ", label_style()),
                            Span::styled(
                                state.target_switches.to_string(),
                                Style::default().fg(Color::White),
                            ),
                        ];
                        if let Some(at) = state.last_switch_at {
                            spans.push(Span::styled(
                                format!(" ({})", fmt_ago(now.saturating_duration_since(at))),
                                label_style(),
                            ));
                        }
                        Line::from(spans)
                    },
```

In the SNI second line, find:
```rust
                            Span::styled("Listen: ", label_style()),
                            Span::styled(
                                format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT),
                                Style::default().fg(Color::White),
                            ),
```
Replace with:
```rust
                            Span::styled("Listen: ", label_style()),
                            Span::styled(
                                state
                                    .listener
                                    .as_ref()
                                    .map(|(_, addr)| addr.to_string())
                                    .unwrap_or_else(|| {
                                        format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
                                    }),
                                Style::default().fg(Color::White),
                            ),
```

- [x] **Step 7: IP modes header — score, switches, listener**

Find the IP-mode first line:
```rust
                vec![
                    Line::from(vec![
                        Span::styled("Mode: ", label_style()),
                        Span::styled(
                            mode_label,
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw("   "),
                        Span::styled("Active IP: ", label_style()),
                        Span::styled(ip.to_string(), Style::default().fg(Color::White)),
                        Span::raw("   "),
                        Span::styled("Listen: ", label_style()),
                        Span::styled(
                            format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT),
                            Style::default().fg(Color::White),
                        ),
                    ]),
                    status_line,
                ]
```
Replace with:
```rust
                vec![
                    {
                        let mut spans = vec![
                            Span::styled("Mode: ", label_style()),
                            Span::styled(
                                mode_label,
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::raw("   "),
                            Span::styled("Active IP: ", label_style()),
                            Span::styled(ip.to_string(), Style::default().fg(Color::White)),
                        ];
                        if let Some(score) = state.active_ip_score {
                            spans.push(Span::raw("  "));
                            spans.push(Span::styled("Score: ", label_style()));
                            spans.push(Span::styled(score.to_string(), score_style(score)));
                        }
                        spans.push(Span::raw("  "));
                        spans.push(Span::styled("Switches: ", label_style()));
                        spans.push(Span::styled(
                            state.target_switches.to_string(),
                            Style::default().fg(Color::White),
                        ));
                        if let Some(at) = state.last_switch_at {
                            spans.push(Span::styled(
                                format!(" ({})", fmt_ago(now.saturating_duration_since(at))),
                                label_style(),
                            ));
                        }
                        spans.push(Span::raw("   "));
                        spans.push(Span::styled("Listen: ", label_style()));
                        spans.push(Span::styled(
                            state
                                .listener
                                .as_ref()
                                .map(|(_, addr)| addr.to_string())
                                .unwrap_or_else(|| {
                                    format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
                                }),
                            Style::default().fg(Color::White),
                        ));
                        Line::from(spans)
                    },
                    status_line,
                ]
```

- [x] **Step 8: Last-error header line (both modes)**

Find:
```rust
        if let Some(line) = rescan_line {
            header_lines.push(line);
        }
```
Replace with:
```rust
        if let Some(line) = rescan_line {
            header_lines.push(line);
        }
        if let Some(err) = &state.last_error {
            header_lines.push(Line::from(vec![
                Span::styled(
                    "Last error: ",
                    Style::default()
                        .fg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("[{}] {}", err.src_port, err.message),
                    Style::default().fg(Color::Red),
                ),
                Span::styled(format!("  {}", fmt_time(err.at)), label_style()),
            ]));
        }
```

- [x] **Step 9: Run tests to verify they pass**

Run: `cargo test -p zerodpi`
Expected: PASS (existing `rescan_status_line_shows_running_indicator` still passes because its test state has no `rescan_started_at`; countdown test unchanged).

- [x] **Step 10: Commit**

```bash
git add crates/zerodpi/src/tui.rs
git commit -m "feat: show switches, last error, and rescan results in dashboard header"
```

---

### Task 5: Stats bar — two lines + Peak

**Files:**
- Modify: `crates/zerodpi/src/tui.rs` (`aggregate_throughput` helper, `draw_dashboard` stats section, `fixed_dashboard_rows`, tests)

**Interfaces:**
- Consumes: Task 3's `peak_active`, Task 4's `header_content_rows`.
- Produces: `fn aggregate_throughput(records: &VecDeque<ConnectionRecord>) -> (f64, f64)` returning `(c2s_bps, s2c_bps)` (reused by Task 6).

- [x] **Step 1: Write the failing test**

Append to the tests module:

```rust
    #[test]
    fn aggregate_throughput_sums_only_relaying_connections() {
        let mut up = record(ConnStatus::Relaying, ACTIVE_RATE_BPS, 0.0);
        up.src_port = 1;
        let mut down = record(ConnStatus::Relaying, 0.0, ACTIVE_RATE_BPS * 2.0);
        down.src_port = 2;
        let mut done = record(ConnStatus::Done, 999.0, 999.0);
        done.src_port = 3;
        let state = dashboard_state(vec![up, down, done]);
        let (c2s, s2c) = aggregate_throughput(&state.records);
        assert_eq!(c2s, ACTIVE_RATE_BPS);
        assert_eq!(s2c, ACTIVE_RATE_BPS * 2.0);
    }
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p zerodpi aggregate_throughput`
Expected: FAIL — compile error: `aggregate_throughput` undefined.

- [x] **Step 3: Add the helper**

After `fn live_transfer_totals(...)` add:
```rust
/// Sum the instantaneous rates of all relaying connections:
/// returns `(c2s_bps, s2c_bps)`.
fn aggregate_throughput(records: &VecDeque<ConnectionRecord>) -> (f64, f64) {
    let mut c2s = 0.0f64;
    let mut s2c = 0.0f64;
    for record in records
        .iter()
        .filter(|r| matches!(r.status, ConnStatus::Relaying))
    {
        c2s += record.rate_c2s_bps;
        s2c += record.rate_s2c_bps;
    }
    (c2s, s2c)
}
```

- [x] **Step 4: Rewrite the stats section in `draw_dashboard`**

Find:
```rust
        // ── Stats bar ────────────────────────────────────────────────────────
        let ok_pct = state
            .bypasses_ok
            .saturating_mul(100)
            .checked_div(state.total)
            .map_or_else(String::new, |pct| format!("({pct}%)"));
        // Aggregate instantaneous throughput from all relaying connections.
        let agg_c2s_bps: f64 = state
            .records
            .iter()
            .filter(|r| matches!(r.status, ConnStatus::Relaying))
            .map(|r| r.rate_c2s_bps)
            .sum();
        let agg_s2c_bps: f64 = state
            .records
            .iter()
            .filter(|r| matches!(r.status, ConnStatus::Relaying))
            .map(|r| r.rate_s2c_bps)
            .sum();
        let (total_upload, total_download) = live_transfer_totals(state);
        let stats_line = Line::from(vec![
```
Replace with:
```rust
        // ── Stats bar ────────────────────────────────────────────────────────
        let ok_pct = state
            .bypasses_ok
            .saturating_mul(100)
            .checked_div(state.total)
            .map_or_else(String::new, |pct| format!("({pct}%)"));
        // Aggregate instantaneous throughput from all relaying connections.
        let (agg_c2s_bps, agg_s2c_bps) = aggregate_throughput(&state.records);
        let (total_upload, total_download) = live_transfer_totals(state);
        let stats_line = Line::from(vec![
```

Find (right after the `Failed` span block):
```rust
            Span::styled("Active: ", label_style()),
            Span::styled(
                state.active.to_string(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("Download: ", label_style()),
```
Replace with:
```rust
            Span::styled("Active: ", label_style()),
            Span::styled(
                state.active.to_string(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("Peak: ", label_style()),
            Span::styled(
                state.peak_active.to_string(),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);
        let stats_line2 = Line::from(vec![
            Span::styled("Download: ", label_style()),
```

- [x] **Step 5: Render two lines and grow the stats block**

Find:
```rust
            Span::raw(" "),
        ]);
        let stats = Paragraph::new(stats_line)
            .block(Block::default().borders(Borders::ALL).title(" Stats "));
        frame.render_widget(stats, chunks[1]);
```
Replace with:
```rust
            Span::raw(" "),
        ]);
        let stats = Paragraph::new(vec![stats_line, stats_line2])
            .block(Block::default().borders(Borders::ALL).title(" Stats "));
        frame.render_widget(stats, chunks[1]);
```

In the layout constraints, find:
```rust
                Constraint::Length(3),                                         // stats bar
```
Replace with:
```rust
                Constraint::Length(4),                                         // stats bar (2 content lines + borders)
```

- [x] **Step 6: Update `fixed_dashboard_rows`**

Find:
```rust
fn fixed_dashboard_rows(state: &DashboardState) -> usize {
    if state.rescan_running || state.next_rescan_at.is_some() {
        16
    } else {
        14
    }
}
```
Replace with:
```rust
fn fixed_dashboard_rows(state: &DashboardState) -> usize {
    // header (content lines + borders + slack) + stats(4) + help(3)
    // + table header(1) + table borders(2)
    header_content_rows(state, Instant::now()) + 3 + 4 + 3 + 1 + 2
}
```

Find the test:
```rust
    #[test]
    fn fixed_dashboard_rows_grows_when_status_line_visible() {
        let mut state = dashboard_state(vec![]);
        assert_eq!(fixed_dashboard_rows(&state), 14);
        state.next_rescan_at = Some(Instant::now() + Duration::from_secs(60));
        assert_eq!(fixed_dashboard_rows(&state), 16);
        state.next_rescan_at = None;
        state.rescan_running = true;
        assert_eq!(fixed_dashboard_rows(&state), 16);
    }
```
Replace with:
```rust
    #[test]
    fn fixed_dashboard_rows_grows_when_status_line_visible() {
        let mut state = dashboard_state(vec![]);
        assert_eq!(fixed_dashboard_rows(&state), 15);
        state.next_rescan_at = Some(Instant::now() + Duration::from_secs(60));
        assert_eq!(fixed_dashboard_rows(&state), 16);
        state.next_rescan_at = None;
        state.rescan_running = true;
        assert_eq!(fixed_dashboard_rows(&state), 16);
    }
```

- [x] **Step 7: Run tests to verify they pass**

Run: `cargo test -p zerodpi`
Expected: PASS.

- [x] **Step 8: Commit**

```bash
git add crates/zerodpi/src/tui.rs
git commit -m "feat: add peak connections and split dashboard stats bar"
```

---

### Task 6: Throughput sparkline strip

**Files:**
- Modify: `crates/zerodpi/src/tui.rs` (imports, constants, `sample_throughput`, `run_dashboard` loop, `draw_dashboard` layout + strip, `fixed_dashboard_rows` + tests, `run_dashboard` init)

**Interfaces:**
- Consumes: `aggregate_throughput` (Task 5), `ThroughputSample` + `throughput_history` (Task 3).
- Produces: `const THROUGHPUT_WINDOW: Duration`, `const THROUGHPUT_MAX_SAMPLES: usize`, `fn sample_throughput(state: &mut DashboardState)`.

- [x] **Step 1: Write the failing tests**

Append to the tests module:

```rust
    #[test]
    fn sample_throughput_prunes_samples_older_than_window() {
        let mut state = dashboard_state(vec![]);
        state.throughput_history.push_back(ThroughputSample {
            at: Instant::now() - THROUGHPUT_WINDOW - Duration::from_secs(1),
            up_bps: 5.0,
            down_bps: 6.0,
        });
        sample_throughput(&mut state);
        assert_eq!(state.throughput_history.len(), 1);
        let sample = state.throughput_history.front().unwrap();
        assert_eq!(sample.up_bps, 0.0);
        assert_eq!(sample.down_bps, 0.0);
    }

    #[test]
    fn sample_throughput_records_current_aggregate_rates() {
        let mut relaying = record(ConnStatus::Relaying, 100.0, 200.0);
        relaying.src_port = 1;
        let mut state = dashboard_state(vec![relaying]);
        sample_throughput(&mut state);
        let sample = state.throughput_history.front().unwrap();
        assert_eq!(sample.up_bps, 100.0);
        assert_eq!(sample.down_bps, 200.0);
    }
```

- [x] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi sample_throughput`
Expected: FAIL — compile error: `THROUGHPUT_WINDOW`, `sample_throughput` undefined.

- [x] **Step 3: Constants + sampling function**

After `const NON_RELAYING_TOP_GRACE: Duration = Duration::from_secs(4);` add:
```rust
const THROUGHPUT_WINDOW: Duration = Duration::from_secs(60);
const THROUGHPUT_MAX_SAMPLES: usize = 300;
const THROUGHPUT_MIN_MAX: u64 = 1024;
```

After `fn aggregate_throughput(...)` add:
```rust
/// Append one aggregate-throughput sample and drop samples older than
/// [`THROUGHPUT_WINDOW`] (or beyond [`THROUGHPUT_MAX_SAMPLES`]).
fn sample_throughput(state: &mut DashboardState) {
    let (up_bps, down_bps) = aggregate_throughput(&state.records);
    let now = Instant::now();
    state.throughput_history.push_back(ThroughputSample {
        at: now,
        up_bps,
        down_bps,
    });
    while state.throughput_history.len() > THROUGHPUT_MAX_SAMPLES
        || state
            .throughput_history
            .front()
            .map_or(false, |s| now.saturating_duration_since(s.at) > THROUGHPUT_WINDOW)
    {
        state.throughput_history.pop_front();
    }
}
```

- [x] **Step 4: Call it each loop iteration**

In `run_dashboard`, find:
```rust
        if state.auto_scroll && got_event {
            state.scroll_offset = 0;
        }

        draw_dashboard(terminal, &state, info, cfg)?;
```
Replace with:
```rust
        if state.auto_scroll && got_event {
            state.scroll_offset = 0;
        }

        sample_throughput(&mut state);
        draw_dashboard(terminal, &state, info, cfg)?;
```

Also switch the `run_dashboard` init from Task 3's temporary `VecDeque::new()` (the one inside `run_dashboard`, not the `dashboard_state` test helper). Find:
```rust
        last_error: None,
        active_ip_score: None,
        listener: None,
        throughput_history: VecDeque::new(),
        start: Instant::now(),
```
Replace with:
```rust
        last_error: None,
        active_ip_score: None,
        listener: None,
        throughput_history: VecDeque::with_capacity(THROUGHPUT_MAX_SAMPLES),
        start: Instant::now(),
```

- [x] **Step 5: Add imports**

Find:
```rust
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState};
```
Replace with:
```rust
use ratatui::widgets::{
    Block, Borders, Cell, Gauge, Paragraph, RenderDirection, Row, Sparkline, Table, TableState,
};
```

- [x] **Step 6: Layout + strip rendering**

In `draw_dashboard`, find:
```rust
            .constraints([
                Constraint::Length((header_content_rows(state, now) + 3) as u16), // header lines + borders + slack
                Constraint::Length(4),                                         // stats bar (2 content lines + borders)
                Constraint::Min(5),                                            // connection log
                Constraint::Length(3),                                         // help bar
            ])
```
Replace with:
```rust
            .constraints([
                Constraint::Length((header_content_rows(state, now) + 3) as u16), // header lines + borders + slack
                Constraint::Length(4),                                         // stats bar (2 content lines + borders)
                Constraint::Length(3),                                         // throughput strip
                Constraint::Min(5),                                            // connection log
                Constraint::Length(3),                                         // help bar
            ])
```

Find:
```rust
        frame.render_widget(stats, chunks[1]);

        // ── Connection log ───────────────────────────────────────────────────
```
Replace with:
```rust
        frame.render_widget(stats, chunks[1]);

        // ── Throughput strip ─────────────────────────────────────────────────
        let down_data: Vec<u64> = state
            .throughput_history
            .iter()
            .map(|s| s.down_bps.max(0.0) as u64)
            .collect();
        let up_data: Vec<u64> = state
            .throughput_history
            .iter()
            .map(|s| s.up_bps.max(0.0) as u64)
            .collect();
        let spark_max = down_data
            .iter()
            .chain(up_data.iter())
            .copied()
            .max()
            .unwrap_or(0)
            .max(THROUGHPUT_MIN_MAX);
        let strip = Block::default()
            .borders(Borders::ALL)
            .title(" Throughput — last 60s (B/s) ");
        frame.render_widget(&strip, chunks[2]);
        let inner = strip.inner(chunks[2]);
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(9),
                Constraint::Min(10),
                Constraint::Length(9),
                Constraint::Min(10),
            ])
            .split(inner);
        frame.render_widget(Paragraph::new(" ▼ Down"), cols[0]);
        frame.render_widget(
            Sparkline::default()
                .data(&down_data)
                .max(spark_max)
                .direction(RenderDirection::RightToLeft)
                .style(Style::default().fg(Color::Cyan)),
            cols[1],
        );
        frame.render_widget(Paragraph::new(" ▲ Up"), cols[2]);
        frame.render_widget(
            Sparkline::default()
                .data(&up_data)
                .max(spark_max)
                .direction(RenderDirection::RightToLeft)
                .style(Style::default().fg(Color::Green)),
            cols[3],
        );

        // ── Connection log ───────────────────────────────────────────────────
```

Then update the log table and help bar chunk indices. Find:
```rust
        frame.render_widget(log_table, chunks[2]);
```
Replace with:
```rust
        frame.render_widget(log_table, chunks[3]);
```
Find:
```rust
        frame.render_widget(help, chunks[3]);
```
Replace with:
```rust
        frame.render_widget(help, chunks[4]);
```

- [x] **Step 7: Update `fixed_dashboard_rows` + test**

Find:
```rust
    header_content_rows(state, Instant::now()) + 3 + 4 + 3 + 1 + 2
```
Replace with:
```rust
    header_content_rows(state, Instant::now()) + 3 + 4 + 3 + 3 + 1 + 2
```
(header slack 3, stats 4, throughput strip 3, help 3, table header 1, table borders 2.)

Also update the stale page-size comment in `run_dashboard`. Find:
```rust
        // Page size: terminal height minus the fixed widget rows (header=5 or 7,
        // stats=3, help=3, table header=1, table borders=2 → 14 or 16 fixed rows).
```
Replace with:
```rust
        // Page size: terminal height minus the fixed widget rows (computed by
        // fixed_dashboard_rows: header, stats, throughput strip, help,
        // table header, and table borders).
```

Update the test:
```rust
    #[test]
    fn fixed_dashboard_rows_grows_when_status_line_visible() {
        let mut state = dashboard_state(vec![]);
        assert_eq!(fixed_dashboard_rows(&state), 18);
        state.next_rescan_at = Some(Instant::now() + Duration::from_secs(60));
        assert_eq!(fixed_dashboard_rows(&state), 19);
        state.next_rescan_at = None;
        state.rescan_running = true;
        assert_eq!(fixed_dashboard_rows(&state), 19);
    }
```

- [x] **Step 8: Run tests to verify they pass**

Run: `cargo test -p zerodpi`
Expected: PASS.

- [x] **Step 9: Commit**

```bash
git add crates/zerodpi/src/tui.rs
git commit -m "feat: add throughput sparklines to dashboard"
```

---

### Task 7: Target column in the connection log

**Files:**
- Modify: `crates/zerodpi/src/tui.rs` (`draw_dashboard` connection-log table)

**Interfaces:**
- Consumes: `ConnectionRecord.target_ip` (Task 2).

- [x] **Step 1: Add the cell**

In the log-table row builder, find:
```rust
                Row::new(vec![
                    Cell::from(fmt_time(r.started_at)),
                    Cell::from(r.peer.to_string()),
                    Cell::from(r.status.label()).style(r.status.style()),
```
Replace with:
```rust
                Row::new(vec![
                    Cell::from(fmt_time(r.started_at)),
                    Cell::from(r.peer.to_string()),
                    Cell::from(r.target_ip.to_string()),
                    Cell::from(r.status.label()).style(r.status.style()),
```

- [x] **Step 2: Add the column widths + header**

Find:
```rust
        let widths = [
            Constraint::Length(8),  // Time
            Constraint::Length(21), // Peer
            Constraint::Length(11), // Status
```
Replace with:
```rust
        let widths = [
            Constraint::Length(8),  // Time
            Constraint::Length(18), // Peer
            Constraint::Length(16), // Target
            Constraint::Length(11), // Status
```

Find:
```rust
                Row::new(vec![
                    "Time",
                    "Peer",
                    "Status",
```
Replace with:
```rust
                Row::new(vec![
                    "Time",
                    "Peer",
                    "Target",
                    "Status",
```

- [x] **Step 3: Run tests and lint**

Run: `cargo test -p zerodpi && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: all PASS.

- [x] **Step 4: Commit**

```bash
git add crates/zerodpi/src/tui.rs
git commit -m "feat: show per-connection target ip in dashboard log"
```

---

### Task 8: Docs and final verification

**Files:**
- Modify: `README.md` (~lines 104–108)

**Interfaces:** none.

- [x] **Step 1: Update the dashboard description in README**

Find:
```markdown
The running dashboard confirms the active SNI/IP pair, current bypass method, local listener, uptime, connection state, byte counters, and recent relay activity. This is the main view for interactive desktop runs.
```
Replace with:
```markdown
The running dashboard confirms the active SNI/IP pair (with score and hot-swap count), current bypass method, local listener, uptime, connection state, byte counters, peak concurrency, the latest connection error, background-rescan results, a 60-second throughput graph, and recent relay activity including each connection's outbound target IP. This is the main view for interactive desktop runs.
```

- [x] **Step 2: Full verification suite**

Run, in order:
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```
Expected: all commands exit 0.

- [x] **Step 3: Manual smoke test (interactive)**

Run: `cargo run --bin zerodpi -- --config ./config.toml`
Check, in the live dashboard:
- Stats bar shows two lines including `Peak`.
- Throughput strip between stats and log renders two sparklines; generate traffic to see bars.
- Header shows `Switches: 0` initially and a switch timestamp after a background rescan hot-swaps the target (set a small `RESCAN_INTERVAL_SECS` temporarily to observe).
- Rescan status line shows `rescan #N: … found, best …, …s, switched|kept` after the first rescan.
- Connection log shows a `Target` column with the outbound IP.
- To see the `Last error` line, temporarily point the target at an unreachable IP (e.g. an entry in `ip_list.txt`) and open a connection — the header shows the red error; revert the file afterwards.
- Verify headless mode logs still work: run with `--no-tui` briefly and confirm the new `debug!` rescan-finished line (visible at `RUST_LOG=debug`).

- [x] **Step 4: Update screenshot (optional, manual)**

`images/tui-dashboard.png` is now stale. If desired, capture a new screenshot of the enriched dashboard and replace the file. No code changes.

- [x] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: update dashboard description with new state panel fields"
```

---

## Self-Review Notes

- Spec coverage: Option 1 (peak ✓ Task 5, switches ✓ Task 4, sparklines ✓ Task 6, rescan summary ✓ Tasks 1–4), Option 2 (last error ✓ Tasks 3–4, IP score ✓ Tasks 3–4, listener addr ✓ Tasks 3–4), Option 3 (target IP ✓ Tasks 1–2 + 7, setup time via existing Duration column — documented in Requirements, rescan summary ✓ Tasks 1–2).
- Type consistency: `RescanSummary` fields used identically in Tasks 3 and 4; `header_content_rows` signature consistent in Tasks 4–6; `aggregate_throughput` returns `(f64, f64)` = `(c2s, s2c)` consumed in Tasks 5 and 6.
- Known intentional state: Task 1 leaves the `zerodpi` crate uncompilable until Task 2 (documented in Global Constraints).
