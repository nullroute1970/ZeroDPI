# TUI Rescan Status (Running Indicator + Next-Rescan Countdown) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show on the live TUI dashboard when a background rescan is running and how much time remains until the next one, in all three modes (`sni_spoof`, `ip_bypass`, `ip_bypass_plus`).

**Architecture:** The background rescan loops in `crates/zerodpi/src/main.rs` already own an optional `ProxyEvent` channel to the TUI. We add three new `ProxyEvent` variants (`RescanStarted`, `RescanFinished`, `NextRescanScheduled`) plus a `RescanKind` enum in `zerodpi-core/src/proxy.rs`, emit them from both rescan loops, and handle them in the TUI dashboard state (`crates/zerodpi/src/tui.rs`), which renders a third header line and re-computes the countdown on its existing 200 ms redraw tick.

**Tech Stack:** Rust 2021 workspace, tokio, ratatui, tracing.

**Spec:** Requirements were approved in chat on 2026-08-12 (bounded change, no separate spec doc). Approved requirements, reproduced verbatim:

1. Placement: a third line in the dashboard header block.
2. When `RESCAN_INTERVAL_SECS == 0` (rescan disabled): hide the line entirely.
3. Content: minimal — running indicator while rescanning + countdown otherwise. No last-result text (a hot-swap is already visible because the header SNI/IP changes).
4. Countdown format: `4m 32s` style, reusing the existing `fmt_uptime`.
5. Coverage: all three modes (`sni_spoof`, `ip_bypass`, `ip_bypass_plus`).

## Global Constraints

- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` must all pass.
- 4-space indentation, `rustfmt` style, `snake_case` functions, `PascalCase` types.
- Keep routine rescan log output below `info` while the TUI owns the terminal (existing convention in `background_rescan`).
- Conventional commits, `feat:` prefix.
- No new `config.toml` options — no README changes required.
- Every task leaves the workspace compiling and all tests green (TDD: failing test first, then implementation).

---

### Task 1: Rescan event plumbing (enum variants → TUI state + headless logger)

**Files:**
- Modify: `crates/zerodpi-core/src/proxy.rs` (enum `ProxyEvent` ends ~line 121 with the `LowTtlDiscovered` arm; `mod tests` starts at line 1321)
- Modify: `crates/zerodpi/src/tui.rs` (import at line 40, `DashboardState` at ~line 724, init in `run_dashboard` at ~line 858, `apply_event` at ~line 963, tests `dashboard_state` helper at ~line 2020)
- Modify: `crates/zerodpi/src/main.rs` (`log_headless_proxy_events` at ~line 1442, match ends ~line 1541)

**Interfaces:**
- Produces (proxy.rs): `pub enum RescanKind { Sni, Ip }` with derives `Debug, Clone, Copy, PartialEq, Eq`; `ProxyEvent::RescanStarted { kind: RescanKind }`; `ProxyEvent::RescanFinished { kind: RescanKind }`; `ProxyEvent::NextRescanScheduled { kind: RescanKind, interval_secs: u64 }`.
- Produces (tui.rs): `DashboardState.rescan_running: bool` and `DashboardState.next_rescan_at: Option<Instant>`.
- Consumes: nothing new.

- [ ] **Step 1: Write the failing tests**

In `crates/zerodpi-core/src/proxy.rs`, append to the existing `mod tests`:

```rust
    #[test]
    fn rescan_events_construct_with_kind_and_interval() {
        let started = ProxyEvent::RescanStarted { kind: RescanKind::Sni };
        let finished = ProxyEvent::RescanFinished { kind: RescanKind::Ip };
        let scheduled = ProxyEvent::NextRescanScheduled { kind: RescanKind::Sni, interval_secs: 300 };
        assert_eq!(format!("{started:?}"), "RescanStarted { kind: Sni }");
        assert_eq!(format!("{finished:?}"), "RescanFinished { kind: Ip }");
        assert_eq!(format!("{scheduled:?}"), "NextRescanScheduled { kind: Sni, interval_secs: 300 }");
    }
```

In `crates/zerodpi/src/tui.rs`, append to the existing `mod tests`:

```rust
    #[test]
    fn apply_event_schedules_next_rescan_deadline() {
        let mut state = dashboard_state(vec![]);
        let before = Instant::now();
        apply_event(
            ProxyEvent::NextRescanScheduled {
                kind: RescanKind::Sni,
                interval_secs: 300,
            },
            &mut state,
        );
        let after = Instant::now();
        let at = state.next_rescan_at.expect("deadline should be set");
        assert!(at >= before + Duration::from_secs(300));
        assert!(at <= after + Duration::from_secs(300));
    }

    #[test]
    fn apply_event_tracks_rescan_running_state() {
        let mut state = dashboard_state(vec![]);
        apply_event(ProxyEvent::RescanStarted { kind: RescanKind::Ip }, &mut state);
        assert!(state.rescan_running);
        apply_event(ProxyEvent::RescanFinished { kind: RescanKind::Ip }, &mut state);
        assert!(!state.rescan_running);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core rescan_events_construct --no-fail-fast`
Expected: compilation FAIL — `cannot find enum variant 'RescanStarted' in enum 'ProxyEvent'` / `cannot find type 'RescanKind'`.

Run: `cargo test -p zerodpi apply_event_schedules --no-fail-fast`
Expected: compilation FAIL — same missing variants plus `no field 'next_rescan_at' on type 'DashboardState'`.

- [ ] **Step 3: Implement the new events in proxy.rs**

Change the end of the `ProxyEvent` enum from:

```rust
    /// `LOW_TTL_DISCOVER` found a working TTL and applied it.
    LowTtlDiscovered { value: u8 },
}
```

to:

```rust
    /// `LOW_TTL_DISCOVER` found a working TTL and applied it.
    LowTtlDiscovered { value: u8 },
    /// A periodic background rescan started (includes any TTL discovery
    /// probe run before a potential hot-swap).
    RescanStarted { kind: RescanKind },
    /// A periodic background rescan finished (success, empty result, or failure).
    RescanFinished { kind: RescanKind },
    /// A new rescan cycle was scheduled; the TUI uses this for its countdown.
    NextRescanScheduled { kind: RescanKind, interval_secs: u64 },
}

/// Which background rescan produced a [`ProxyEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RescanKind {
    /// `sni_spoof` mode background SNI rescan.
    Sni,
    /// `ip_bypass` / `ip_bypass_plus` mode background IP rescan.
    Ip,
}
```

- [ ] **Step 4: Implement TUI state fields, init, and event handling in tui.rs**

Import — change line 40 from:

```rust
use zerodpi_core::proxy::{ProxyEvent, RelayEndReason};
```

to:

```rust
use zerodpi_core::proxy::{ProxyEvent, RelayEndReason, RescanKind};
```

`DashboardState` — after `low_ttl: Option<u8>,` add:

```rust
    /// `true` while a periodic background rescan is running.
    rescan_running: bool,
    /// Deadline for the next rescan cycle, set from `NextRescanScheduled`.
    next_rescan_at: Option<Instant>,
```

`run_dashboard` state init — after `low_ttl: None,` add:

```rust
        rescan_running: false,
        next_rescan_at: None,
```

`apply_event` — after the `LowTtlDiscovered` arm add:

```rust
        ProxyEvent::NextRescanScheduled { interval_secs, .. } => {
            state.next_rescan_at = Some(Instant::now() + Duration::from_secs(interval_secs));
        }
        ProxyEvent::RescanStarted { .. } => {
            state.rescan_running = true;
        }
        ProxyEvent::RescanFinished { .. } => {
            state.rescan_running = false;
        }
```

Tests `dashboard_state` helper — after `low_ttl: None,` add:

```rust
            rescan_running: false,
            next_rescan_at: None,
```

- [ ] **Step 5: Implement headless logger arms in main.rs**

In `log_headless_proxy_events`, after the `LowTtlDiscovered` arm add:

```rust
            ProxyEvent::NextRescanScheduled { .. } => {
                // Rescan tasks emit RuntimeEvent::NextScanScheduled directly.
            }
            ProxyEvent::RescanStarted { kind } => {
                debug!(?kind, "background rescan started");
            }
            ProxyEvent::RescanFinished { kind } => {
                debug!(?kind, "background rescan finished");
            }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core rescan_events_construct` → PASS
Run: `cargo test -p zerodpi apply_event_schedules_next_rescan_deadline apply_event_tracks_rescan_running_state` → PASS
Run: `cargo test --workspace` → all PASS

- [ ] **Step 7: Commit**

```bash
git add crates/zerodpi-core/src/proxy.rs crates/zerodpi/src/tui.rs crates/zerodpi/src/main.rs
git commit -m "feat: add rescan status proxy events and TUI state tracking"
```

---

### Task 2: Render rescan status line in the dashboard header

**Files:**
- Modify: `crates/zerodpi/src/tui.rs` (formatting helpers end ~line 780; `draw_dashboard` at ~line 1077; `run_dashboard` visible-rows math at ~line 897; `mod tests`)

**Interfaces:**
- Produces: `fn rescan_status_line(state: &DashboardState, now: Instant) -> Option<Line<'static>>` — the header line: `Rescan: running…` while running, `Next rescan in: 4m 32s` otherwise; `None` when no rescan was ever scheduled (line hidden).
- Produces: `fn fixed_dashboard_rows(state: &DashboardState) -> usize` — 14 normally, 16 when the rescan status line is visible.
- Consumes: `DashboardState.rescan_running`, `DashboardState.next_rescan_at` from Task 1; existing `label_style()`, `fmt_uptime()`.

- [ ] **Step 1: Write the failing tests**

Append to the `mod tests` in `crates/zerodpi/src/tui.rs`:

```rust
    #[test]
    fn rescan_status_line_hidden_without_schedule() {
        let state = dashboard_state(vec![]);
        assert!(rescan_status_line(&state, Instant::now()).is_none());
    }

    #[test]
    fn rescan_status_line_shows_running_indicator() {
        let mut state = dashboard_state(vec![]);
        state.rescan_running = true;
        let line = rescan_status_line(&state, Instant::now()).expect("line should be present");
        assert_eq!(line.spans.len(), 2);
        assert_eq!(line.spans[0].content, "Rescan: ");
        assert_eq!(line.spans[1].content, "running…");
    }

    #[test]
    fn rescan_status_line_shows_countdown_to_next_rescan() {
        let mut state = dashboard_state(vec![]);
        let now = Instant::now();
        state.next_rescan_at = Some(now + Duration::from_secs(272)); // 4m 32s
        let line = rescan_status_line(&state, now).expect("line should be present");
        assert_eq!(line.spans[0].content, "Next rescan in: ");
        assert_eq!(line.spans[1].content, "4m 32s");
    }

    #[test]
    fn rescan_status_line_prefers_running_over_countdown() {
        let mut state = dashboard_state(vec![]);
        let now = Instant::now();
        state.next_rescan_at = Some(now + Duration::from_secs(60));
        state.rescan_running = true;
        let line = rescan_status_line(&state, now).expect("line should be present");
        assert_eq!(line.spans[1].content, "running…");
    }

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

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi rescan_status_line --no-fail-fast`
Expected: compilation FAIL — `cannot find function 'rescan_status_line'` / `cannot find function 'fixed_dashboard_rows'`.

- [ ] **Step 3: Implement the helpers**

Place both helpers after `fmt_uptime` (end of the formatting-helpers section):

```rust
/// Status line for the dashboard header: shows a running indicator while a
/// background rescan is in progress, otherwise the countdown to the next
/// scheduled rescan. Returns `None` when no rescan is configured or has
/// ever been scheduled, so the line can be hidden entirely.
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

/// Fixed rows consumed by the dashboard outside the connection table
/// (header, stats, help, table header, borders). The header is two rows
/// taller when the rescan status line is visible.
fn fixed_dashboard_rows(state: &DashboardState) -> usize {
    if state.rescan_running || state.next_rescan_at.is_some() {
        16
    } else {
        14
    }
}
```

- [ ] **Step 4: Wire the line into draw_dashboard**

Change the top of the `terminal.draw` closure from:

```rust
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5), // header (2 info lines + borders)
```

to:

```rust
        let area = frame.area();
        let rescan_line = rescan_status_line(state, Instant::now());
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(if rescan_line.is_some() { 7 } else { 5 }), // header (2 or 3 info lines + borders)
```

Change `let header_lines = match info {` to `let mut header_lines = match info {`, and insert between the end of that `match` and the `let header = Paragraph::new(header_lines)...` line:

```rust
        if let Some(line) = rescan_line {
            header_lines.push(line);
        }
```

- [ ] **Step 5: Update page-size math in run_dashboard**

Replace the visible-rows computation (including its comment) with:

```rust
        // Page size: terminal height minus the fixed widget rows (header=5 or 7,
        // stats=3, help=3, table header=1, table borders=2 → 14 or 16 fixed rows).
        let visible_rows = terminal
            .size()
            .map(|s| (s.height as usize).saturating_sub(fixed_dashboard_rows(&state)))
            .unwrap_or(10)
            .max(1);
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p zerodpi rescan_status_line fixed_dashboard_rows` → PASS (5 tests)
Run: `cargo test --workspace` → all PASS

- [ ] **Step 7: Commit**

```bash
git add crates/zerodpi/src/tui.rs
git commit -m "feat: show rescan status and next-rescan countdown in dashboard header"
```

---

### Task 3: Emit rescan events from the SNI background rescan

**Files:**
- Modify: `crates/zerodpi/src/main.rs` (import at lines 42-45; `background_rescan` at ~line 1023; `mod tests` at line 2664)

**Interfaces:**
- Produces: `fn send_rescan_event(tx: &Option<ProxyEventSender>, event: ProxyEvent)` — module-private helper in main.rs.
- Consumes: `ProxyEvent` variants and `RescanKind` from Task 1; `ProxyEventSender` already imported.

- [ ] **Step 1: Write the failing test**

Append to the `mod tests` in `crates/zerodpi/src/main.rs`:

```rust
    #[test]
    fn rescan_event_sender_forwards_and_ignores_when_absent() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        send_rescan_event(&Some(tx), ProxyEvent::RescanStarted { kind: RescanKind::Sni });
        assert!(matches!(
            rx.try_recv().unwrap(),
            ProxyEvent::RescanStarted { kind: RescanKind::Sni }
        ));
        send_rescan_event(&None, ProxyEvent::RescanStarted { kind: RescanKind::Sni });
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p zerodpi rescan_event_sender --no-fail-fast`
Expected: compilation FAIL — `cannot find function 'send_rescan_event'` / `cannot find enum variant or struct 'RescanKind'`.

- [ ] **Step 3: Implement the helper and import RescanKind**

Import — change:

```rust
use zerodpi_core::proxy::{
    run_ip_bypass_plus_proxy, run_ip_bypass_proxy, run_proxy, ActiveSniTarget, ProxyEvent,
    ProxyEventSender, RelayEndReason, CONNECT_PORT,
};
```

to add `RescanKind` after `RelayEndReason`:

```rust
use zerodpi_core::proxy::{
    run_ip_bypass_plus_proxy, run_ip_bypass_proxy, run_proxy, ActiveSniTarget, ProxyEvent,
    ProxyEventSender, RelayEndReason, RescanKind, CONNECT_PORT,
};
```

Place the helper directly above `background_rescan`:

```rust
/// Forward a [`ProxyEvent`] to the dashboard channel when one is configured
/// (`None` when running fully headless without runtime events).
fn send_rescan_event(tx: &Option<ProxyEventSender>, event: ProxyEvent) {
    if let Some(tx) = tx {
        let _ = tx.send(event);
    }
}
```

- [ ] **Step 4: Emit from the three points in background_rescan**

Point 1 — after the existing `events.emit(RuntimeEvent::NextScanScheduled { ... });` block, before `tokio::time::sleep(interval).await;`:

```rust
        send_rescan_event(
            &event_tx,
            ProxyEvent::NextRescanScheduled {
                kind: RescanKind::Sni,
                interval_secs,
            },
        );
```

Point 2 — after the headless/else `"background rescan starting"` log block, before `let cfg_clone = cfg.clone();`:

```rust
        send_rescan_event(&event_tx, ProxyEvent::RescanStarted { kind: RescanKind::Sni });
```

Point 3 — after the `match scan_sni_list(...)` block ends (after the `Err(e) => { warn!(...) }` arm's closing `}` and before the loop's closing `}`):

```rust
        send_rescan_event(&event_tx, ProxyEvent::RescanFinished { kind: RescanKind::Sni });
```

This single placement covers every path (empty results, no switch, discovery failure, hot-swap) because the loop has no early `continue`.

- [ ] **Step 5: Run tests and lints**

Run: `cargo test -p zerodpi rescan_event_sender` → PASS
Run: `cargo test --workspace` → all PASS
Run: `cargo clippy --workspace --all-targets -- -D warnings` → clean

- [ ] **Step 6: Commit**

```bash
git add crates/zerodpi/src/main.rs
git commit -m "feat: emit rescan status events from SNI background rescan"
```

---

### Task 4: Emit rescan events from the IP background rescan

**Files:**
- Modify: `crates/zerodpi/src/main.rs` (`background_ip_rescan` at ~line 2061)

**Interfaces:**
- Consumes: `send_rescan_event` from Task 3; `RescanKind::Ip`.

No new tests: the helper is already unit-tested in Task 3; this task is pure wiring verified by compile, clippy, and the manual smoke in Task 5.

- [ ] **Step 1: Emit schedule + started events at loop top**

After the existing `events.emit(RuntimeEvent::NextScanScheduled { scan: ScanKind::Ip, ... });` block add:

```rust
        send_rescan_event(
            &event_tx,
            ProxyEvent::NextRescanScheduled {
                kind: RescanKind::Ip,
                interval_secs,
            },
        );
```

After the headless/else `"background IP rescan starting"` log block add:

```rust
        send_rescan_event(&event_tx, ProxyEvent::RescanStarted { kind: RescanKind::Ip });
```

- [ ] **Step 2: Emit finished on every exit path**

`background_ip_rescan` has three early `continue`s plus the natural loop end — add one `send_rescan_event(... RescanFinished ...)` immediately before each `continue` and one after the hot-swap block at loop end:

1. In the `Err(e)` arm of the `load_ip_list` match, after the existing `warn!(...)`:

```rust
                send_rescan_event(&event_tx, ProxyEvent::RescanFinished { kind: RescanKind::Ip });
                continue;
```

2. In the `if let Err(e) = reject_ipv6_ip_candidates(...)` block, after the existing `warn!(...)`:

```rust
                send_rescan_event(&event_tx, ProxyEvent::RescanFinished { kind: RescanKind::Ip });
                continue;
```

3. After the `warn!(... "background IP rescan found no working IPs" ...)` inside the `entries.is_empty()` check:

```rust
            send_rescan_event(&event_tx, ProxyEvent::RescanFinished { kind: RescanKind::Ip });
            continue;
```

4. After the `if best.ip != current { ... }` hot-swap block, as the last statement of the loop body:

```rust
        send_rescan_event(&event_tx, ProxyEvent::RescanFinished { kind: RescanKind::Ip });
```

- [ ] **Step 3: Verify**

Run: `cargo fmt --all -- --check` → clean
Run: `cargo clippy --workspace --all-targets -- -D warnings` → clean
Run: `cargo test --workspace` → all PASS

- [ ] **Step 4: Commit**

```bash
git add crates/zerodpi/src/main.rs
git commit -m "feat: emit rescan status events from IP background rescan"
```

---

### Task 5: Full verification and manual smoke test

**Files:** none expected; fix anything this surfaces.

- [ ] **Step 1: Full automated verification**

Run: `cargo fmt --all -- --check` → clean
Run: `cargo clippy --workspace --all-targets -- -D warnings` → clean
Run: `cargo test --workspace` → all PASS
Run: `cargo build --workspace --release` → succeeds

- [ ] **Step 2: Manual TUI smoke — countdown + running indicator**

Set `RESCAN_INTERVAL_SECS = 30` in a scratch config (do not commit it), then:

Run: `cargo run --bin zerodpi -- --config ./config.toml` (needs root/NFQUEUE on Linux, WinDivert on Windows; `ip_bypass` mode needs neither — see `BYPASS_MODE`).

Expected, in order:
1. Header shows a third line `Next rescan in: 30s` that ticks down (29s, 28s, …) on the 200 ms redraw.
2. At 0 the line changes to `Rescan: running…` (yellow) for the duration of the scan.
3. When the scan ends the countdown restarts at `30s`.
4. If a hot-swap occurs, the header SNI/IP/score line updates as before.
5. Verify with `RESCAN_INTERVAL_SECS = 0`: the third header line is absent entirely, and the layout looks exactly as before the change (header still 5 rows).

- [ ] **Step 3: Manual headless smoke**

Run: `cargo run --bin zerodpi -- --config ./config.toml --no-tui` with `RESCAN_INTERVAL_SECS = 30`.

Expected: existing headless logs unchanged (`background SNI rescan starting/complete`, runtime JSON `next_scan_scheduled` events still emitted); new `debug!` lines only visible with debug logging enabled; no new warnings/errors.

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -m "fix: address review findings from rescan status verification"
```

If nothing needed fixing, skip this step.

---

## Self-Review Notes (checked by the plan author)

- Spec coverage: all 5 approved requirements map to Task 2 (placement/format/hiding) and Tasks 3-4 (event sources for all three modes — SNI rescan, IP rescan with `ipv4_only` false and true). ✓
- Type consistency: `RescanKind`, the three `ProxyEvent` variants, `rescan_status_line`, `fixed_dashboard_rows`, and `send_rescan_event` are defined in Task 1-3 and used with identical names/signatures in later tasks. ✓
- Exhaustive matches: `apply_event` (tui.rs) and `log_headless_proxy_events` (main.rs) both updated in Task 1, so the workspace compiles after every task. ✓
- The countdown deadline semantics match the real loop behavior (schedule emitted at cycle top, before the sleep). ✓
