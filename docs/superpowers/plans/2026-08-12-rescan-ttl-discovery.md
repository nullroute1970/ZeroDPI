# Rescan-Time TTL Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run `LOW_TTL_DISCOVER` again when a background rescan switches the active SNI/IP target — but only on a target switch, without mutating the live TTL during probing, without dropping or disrupting existing connections, and with the target hot-swap delayed until discovery succeeds. This supersedes the startup-only policy documented in `docs/superpowers/specs/2026-08-12-startup-only-ttl-discovery-design.md`.

**Architecture:** Stop probing TTL candidates by mutating the global live handle (the startup mechanism, which is safe only because no traffic exists yet). Instead, give each probe flow a **per-flow TTL override** carried in its `FlowState`: the `low_ttl` method prefers the flow's override and falls back to the shared handle. Discovery probes therefore never touch the handle, live connections are unaffected, and the discovered value is applied exactly once — atomically, together with the target switch. This also fixes the known latent issue (noted in the startup-only spec) where the probe loop leaves the live handle at the first failing candidate.

**Tech Stack:** Rust 2021, Tokio, `dashmap`/`parking_lot` flow table, inline `#[cfg(test)]` unit tests, serde_json-framed helper IPC, TOML configuration, Markdown documentation.

## Agreed behavior (user decisions)

1. Discovery runs at rescan time **only when the rescan would switch targets** (best candidate qualifies via `SNI_SWITCH_MIN_SCORE`). Unchanged targets are not re-probed.
2. The rescan **delays the target hot-swap until discovery succeeds**; the new target and the new TTL become active together.
3. If rescan discovery finds no working TTL, **stay on the current target and keep the current TTL** (no switch, no TTL change).
4. **Reuse `LOW_TTL_DISCOVER`** as the gate for both startup and rescan discovery. No new config flag.
5. Acceptable that a rescan cycle takes up to `LOW_TTL_DISCOVER_MAX × LOW_TTL_DISCOVER_TIMEOUT_MS` longer. Discovery runs inline in the single rescan loop, so no concurrent discoveries can overlap.

## Global Constraints

- Existing connections during discovery must be completely unaffected: probes use per-flow overrides; the global handle (local `Arc<AtomicU8>` or remote `SetLowTtlValue`) is updated only once per successful discovery, immediately before the target switch.
- New connections arriving during discovery continue to use the current target with the current TTL (the switch has not happened yet).
- When `LOW_TTL_DISCOVER` is disabled or discovery was skipped at startup (`decide_low_ttl_discovery` is not `Run`), rescan switching behaves exactly as today (immediate hot-swap, no probing).
- Preserve the existing gates: `LOW_TTL_COMPLETE_IMMEDIATELY = true` and `low_ttl` in `BYPASS_METHOD` are still required for discovery.
- Preserve the remote root-helper (Android) path end-to-end: the override travels in the `RegisterFlow` IPC message; `SetLowTtlValue` remains the final-apply mechanism.
- Keep `rustfmt` formatting and 4-space indentation; keep documentation synchronized across `config.toml`, `android/app/src/main/assets/zerodpi/config.toml`, and `README.md`.
- Protocol: bump `PROTOCOL_MINOR` (2 → 3) for the additive `RegisterFlow` field; keep old-app compatibility via `#[serde(default)]`.

## Design summary

### Per-flow TTL override (core + platform-neutral)

- `FlowState` gains `low_ttl_override: Option<u8>`; `FlowState::new` and `FlowEntry::new` take it.
- `FlowController::register_flow` gains a `low_ttl_override: Option<u8>` parameter (trait + all impls + all call sites).
- New `FlowController::flow_exists(&self, key: FlowKey) -> bool` so probes can skip registration if their 4-tuple already belongs to a live flow (prevents clobbering a user flow locally and prevents the helper's duplicate-flow-key `HelperFatal` remotely).
- `LowTtl::on_handshake_complete_ack` stamps `flow.low_ttl_override.unwrap_or_else(|| self.ttl())`.

### Discovery (core)

- `discover_low_ttl` drops the `set_ttl` closure entirely. Each probe registers its flow **with the candidate TTL as the override** (via a small `register_probe_flow` helper that first checks `flow_exists`; a collision counts as probe failure).
- `discover_low_ttl` returns the discovered value; it no longer has any global side effect.
- `LowTtlDiscoveryState::run` (main.rs) now calls `discover_low_ttl`, then applies the result **once** through `LowTtlApplier::apply`. Startup behavior is unchanged except that the handle now ends at the discovered value instead of the first failing candidate (latent bug fix).

### Rescan (zerodpi app)

- `background_rescan` regains an optional discovery state. When the best candidate qualifies for a switch: run discovery against the **candidate's** `(sni, ip)`; on `Some(value)` hot-swap the target and emit `SniTargetChanged` plus `LowTtlDiscovered` (TUI already tracks "startup or rescan"); on `None` warn and keep the current target and TTL. No discovery when the target is unchanged or discovery is not configured.

### Helper protocol (Android)

- `Message::RegisterFlow` gains `low_ttl_override: Option<u8>` with `#[serde(default)]`; validation requires `Some(v)` to be `1..=64` (mirroring `SetLowTtlValue`). `PROTOCOL_MINOR` becomes 3.
- `RemoteHelperClient::register_flow` forwards the field; its `flow_exists` checks `inner.flow_ids`.
- Root helper (`zerodpi-root-helper/src/unix.rs`) passes the field into `FlowEntry::new`. No other helper changes: the helper's `LowTtl` method already reads `FlowState`, so the override works there automatically.

---

### Task 1: Protocol — `RegisterFlow.low_ttl_override` and minor bump

**Files:**
- Modify: `crates/zerodpi-helper-protocol/src/lib.rs` (message enum, `validate`, `PROTOCOL_MINOR`, tests).

**Interfaces:**
- Consumes: existing `Message::RegisterFlow { flow_id, key, fake_data }`, `Message::validate`, serde derive.
- Produces: `RegisterFlow` with `low_ttl_override: Option<u8>`; protocol minor 3; validation and round-trip tests.

- [ ] **Step 1: Add the field and bump the version**

Add `low_ttl_override: Option<u8>` to `Message::RegisterFlow` with `#[serde(default)]` so a minor-2 app's registration still deserializes. Change `PROTOCOL_MINOR` from `2` to `3`. In `validate`, reject `Some(0)` and `Some(> 64)`.

- [ ] **Step 2: Write protocol tests**

Add tests: `RegisterFlow` with `Some(9)` round-trips through `write_frame`/`read_frame`; `Some(0)` and `Some(65)` fail validation; a JSON payload without the field (minor-2 shape) deserializes with `low_ttl_override: None`; `SetLowTtlValue` round-trip tests remain untouched.

- [ ] **Step 3: Run the focused tests**

Run:

```powershell
cargo test -p zerodpi-helper-protocol
```

Expected: all protocol tests pass; `PROTOCOL_MAJOR` unchanged, `PROTOCOL_MINOR == 3`.

---

### Task 2: Core flow plumbing — override field, `register_flow` signature, `flow_exists`

**Files:**
- Modify: `crates/zerodpi-core/src/flow.rs` (`FlowState`, `FlowEntry`, trait, `LocalFlowController`, tests).
- Modify: `crates/zerodpi-core/src/proxy.rs` (one `register_flow` call site → pass `None`).
- Modify: `crates/zerodpi-core/src/low_ttl_discover.rs` (probe registration, see Task 4).
- Modify: `crates/zerodpi-core/src/handler.rs` (all `FlowEntry::new` test call sites, mechanical `, None`).
- Modify: `crates/zerodpi/src/helper_client.rs` (both `FlowController` impls and the mock).

**Interfaces:**
- Consumes: current `FlowController` trait and `FlowEntry`/`FlowState` constructors.
- Produces: `FlowState::new(fake_data, low_ttl_override)`, `FlowEntry::new(fake_data, low_ttl_override)`, `register_flow(key, fake_data, low_ttl_override)`, `flow_exists(&self, key) -> bool`.

- [ ] **Step 1: Add the field and update constructors**

Add `pub low_ttl_override: Option<u8>` to `FlowState`; thread it through `FlowState::new` and `FlowEntry::new`. Update the trait: `fn register_flow(&self, key: FlowKey, fake_data: Vec<u8>, low_ttl_override: Option<u8>) -> FlowRegistrationFuture<'_>;` and add `fn flow_exists(&self, key: FlowKey) -> bool;` with doc comments stating that the override is used by `low_ttl` discovery probes.

- [ ] **Step 2: Update implementations and call sites**

`LocalFlowController`: pass the override into `FlowEntry::new`; `flow_exists` = `self.flows.contains_key(&key)`.
`RemoteHelperClient`: pass the override into the local notification `FlowEntry` and into the `RegisterFlow` wire message; `flow_exists` = check the `flow_ids` lock for the key.
Mock impl in `helper_client.rs`: update signature, return a flow entry (used by tests).
`proxy.rs`: pass `None` at the user-flow registration.
`handler.rs` test helpers: mechanical `, None` additions (14 sites).

- [ ] **Step 3: Write flow-table tests**

In `flow.rs`: a `FlowEntry::new(fake, Some(7))` has `state.low_ttl_override == Some(7)` and default `None` otherwise; `LocalFlowController::flow_exists` returns `true` after registration and `false` after `remove_flow`.

- [ ] **Step 4: Compile and test the core**

Run:

```powershell
cargo test -p zerodpi-core
```

Expected: compiles with the new signatures and all tests pass.

---

### Task 3: `low_ttl` method — override precedence

**Files:**
- Modify: `crates/zerodpi-core/src/methods/low_ttl.rs`.

**Interfaces:**
- Consumes: `FlowState.low_ttl_override`, existing `Arc<AtomicU8>` handle.
- Produces: emission-time TTL = `flow.low_ttl_override.unwrap_or_else(|| self.ttl())`.

- [ ] **Step 1: Write the failing precedence test**

Add a test: method created with default TTL `5`; a `FlowState` with `low_ttl_override = Some(7)`; `on_handshake_complete_ack` must stamp `new_ipv4_ttl = Some(7)` and leave the handle at `5`. Also update the existing tests to construct `FlowState` with `None`.

- [ ] **Step 2: Implement precedence and run the tests**

Change the `ttl` binding in `on_handshake_complete_ack` to prefer the flow override. Run:

```powershell
cargo test -p zerodpi-core low_ttl
```

Expected: precedence test passes; handle-sharing tests still pass.

---

### Task 4: Discovery — per-candidate override registration, no global mutation, final apply once

**Files:**
- Modify: `crates/zerodpi-core/src/low_ttl_discover.rs` (drop `set_ttl`, add `register_probe_flow`, collision guard, tests).
- Modify: `crates/zerodpi/src/main.rs` (`LowTtlDiscoveryState::run`, startup block).

**Interfaces:**
- Consumes: `FlowController::{register_flow, flow_exists}`, `LowTtlApplier::apply`.
- Produces: `discover_low_ttl(discovery, sni, connect_ip, interface_ip, flow_controller, connector) -> Option<u8>` with no side effects; `LowTtlDiscoveryState::run` that applies the result exactly once and returns it.

- [ ] **Step 1: Write the failing tests**

In `low_ttl_discover.rs`:
- A test double `FlowController` whose `register_flow` records each `(key, override)` pair and whose `flow_exists` returns `false`; assert that a `discover_low_ttl` run registers each probed candidate with the candidate TTL as the override (probe I/O can be stubbed at the new `register_probe_flow` seam; see Step 2).
- A collision test: with `flow_exists` returning `true`, the probe fails (returns `false`) without registering.

- [ ] **Step 2: Implement**

Extract `register_probe_flow(flow_controller, key, fake_data, low_ttl_override) -> Result<FlowEntry>`: return `Err` if `flow_exists(key)`, otherwise `register_flow(key, fake_data, low_ttl_override)`. `probe_ttl` takes the candidate TTL, uses `register_probe_flow`, and treats `Err` as probe failure. Remove the `set_ttl` parameter from `discover_low_ttl`; the scan closure no longer applies anything. Update the module doc comment (probing no longer mutates the live handle). Update `LowTtlDiscoveryState::run` in `main.rs`:

```rust
async fn run(&self, sni: &str, connect_ip: Ipv4Addr) -> Option<u8> {
    let found = discover_low_ttl(self.settings, sni, connect_ip, self.interface_ip,
                                 self.flow_controller.clone(), self.connector.clone()).await?;
    if self.applier.apply(found).await { Some(found) } else { None }
}
```

- [ ] **Step 3: Update the startup call site**

In `main.rs`, the startup block already treats the returned value as the applied TTL; keep the logging and `LowTtlDiscovered` emission, remove nothing else. Verify the applier no longer receives a `set_ttl` closure (it is now used exactly once, after the scan — this fixes the latent "handle left at failing candidate" issue).

- [ ] **Step 4: Run the focused tests**

Run:

```powershell
cargo test -p zerodpi-core low_ttl_discover
cargo test -p zerodpi low_ttl_discover
```

Expected: discovery tests pass; `scan_ttl` tests unchanged and passing.

---

### Task 5: Rescan — delayed, discovery-gated target switch

**Files:**
- Modify: `crates/zerodpi/src/main.rs` (`background_rescan` signature and body, rescan spawn site, pure helpers, tests).
- Modify: `crates/zerodpi/src/tui.rs` only if the `LowTtlDiscovered` handling needs no change (verify the existing comment "startup or rescan" is now accurate — it is).

**Interfaces:**
- Consumes: `LowTtlDiscoveryState`, `select_rescan_target`, `should_switch_sni_target`, existing event emission.
- Produces: `background_rescan(..., rescan_discovery: Option<LowTtlDiscoveryState>, ...)`; pure helper `discovery_gated_switch(discovered: Option<u8>, current, candidate, min_score) -> Option<ActiveSniTarget>`.

- [ ] **Step 1: Write the failing policy test**

Add a test for `discovery_gated_switch`: with `discovered = Some(9)` and a qualifying candidate it returns the candidate target; with `discovered = None` it returns `None` (stay on current target) regardless of score. Reuse the existing `current(...)`/`candidate(...)` test helpers.

- [ ] **Step 2: Implement the rescan policy**

In `background_rescan`, after `select_rescan_target` yields `next`:
- If `rescan_discovery` is `Some(state)`, run `state.run(&next.sni, next.ip).await` against the **candidate** target.
- `discovery_gated_switch(discovered, &current, best, cfg.SNI_SWITCH_MIN_SCORE)` decides the switch: `None` (discovery configured but failed) → log a warning and keep the current target and TTL; `Some(...)` → hot-swap, emit `SniTargetChanged`, and when discovery actually ran also emit `ProxyEvent::LowTtlDiscovered { value }`.
- If `rescan_discovery` is `None` (discovery disabled/skipped), switch immediately exactly as today.
- No discovery runs when the best candidate does not qualify for a switch (unchanged target ⇒ no probing).
- Keep routine logging below `info` in TUI mode, mirroring the existing headless/TUI split.

Re-add the `LowTtlDiscoveryState` argument at the `background_rescan` spawn site (clone of the startup state). Update the function's doc comment: discovery runs on target switches and the switch is gated on discovery success.

- [ ] **Step 3: Run the focused tests**

Run:

```powershell
cargo test -p zerodpi rescan
cargo test -p zerodpi discovery_gated_switch
```

Expected: the new policy test passes and existing `select_rescan_target`/`should_switch_sni_target` tests still pass.

---

### Task 6: Root helper and remote client wiring

**Files:**
- Modify: `crates/zerodpi-root-helper/src/unix.rs` (`Message::RegisterFlow` handler: pass `low_ttl_override` into `FlowEntry::new`).
- Verify: `crates/zerodpi/src/helper_client.rs` remote impl already updated in Task 2.

**Interfaces:**
- Consumes: protocol field from Task 1; `FlowEntry::new` signature from Task 2.
- Produces: helper-side probe flows carry the override so the helper's `LowTtl` stamps the candidate TTL.

- [ ] **Step 1: Thread the field through the helper**

In the `RegisterFlow` match arm, construct `FlowEntry::new(fake_data, low_ttl_override)`. No other helper changes (the helper's `LowTtl` method reads `FlowState.low_ttl_override` via Task 3). Keep the duplicate-flow-key rejection as-is — the data plane's `flow_exists` guard prevents probe collisions from ever reaching it.

- [ ] **Step 2: Build the helper**

Run:

```powershell
cargo build -p zerodpi-root-helper
```

Expected: compiles cleanly; helper protocol minor version reported as 3.

---

### Task 7: Documentation and comments

**Files:**
- Modify: `crates/zerodpi/src/main.rs` comments (rescan/discovery docs).
- Modify: `crates/zerodpi-core/src/low_ttl_discover.rs` module doc.
- Modify: `crates/zerodpi-core/src/methods/mod.rs` (`low_ttl_handle` doc: handle is updated only by the final apply, not per probe).
- Modify: `config.toml` and `android/app/src/main/assets/zerodpi/config.toml` `LOW_TTL_DISCOVER*` comments.
- Modify: `README.md` (discovery now runs at startup **and** on rescan target switches, gated on success).

**Interfaces:**
- Consumes: this plan's agreed behavior.
- Produces: consistent docs stating: probing uses per-flow overrides; live connections are never disturbed; a target switch happens only after discovery succeeds; on failure the current target and TTL are kept.

- [ ] **Step 1: Update wording**

Replace "startup-only"/"rescans do not run TTL discovery" wording with the new policy. Document that rescan cycles can take longer (`LOW_TTL_DISCOVER_MAX × LOW_TTL_DISCOVER_TIMEOUT_MS` worst case) and that probe traffic is a few TLS handshakes against the candidate target.

- [ ] **Step 2: Check documentation consistency**

Run:

```powershell
rg -n "startup-only|startup only|do not run TTL discovery|rediscover" config.toml android/app/src/main/assets/zerodpi/config.toml README.md crates/zerodpi/src/main.rs crates/zerodpi-core/src
```

Expected: no stale claims remain, except historical spec/plan files under `docs/superpowers/`.

---

### Task 8: Verify the complete change

**Files:**
- Verify: all modified Rust, TOML, Markdown, and plan files.

- [ ] **Step 1: Formatting and lint**

Run:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
git diff --check
```

Expected: all exit successfully.

- [ ] **Step 2: Workspace tests**

Run:

```powershell
cargo test -p zerodpi-helper-protocol
cargo test -p zerodpi-core
cargo test -p zerodpi
cargo test --workspace
```

Expected: every command exits 0 with zero failed tests.

- [ ] **Step 3: Review the final diff**

Confirm: probing never writes the global handle; the handle is written exactly once per successful discovery; a rescan switch is gated on discovery success; existing flows and flows to the current target are untouched during discovery; Android/helper path carries the override end-to-end; `config.toml`, the Android asset config, and `README.md` agree.

## Platform impact

- **Linux/NFQUEUE, Windows/WinDivert:** no platform-backend changes; the override rides in `FlowState` and `PacketView.new_ipv4_ttl` is set by `LowTtl` exactly as before.
- **Android (root helper):** `RegisterFlow` gains one additive serde field with a protocol minor bump (2 → 3); old data planes remain wire-compatible (`#[serde(default)]`), new data planes require the new helper.
- **Termux:** same as Linux.

## Out of scope

- Probing unchanged targets every rescan (explicitly rejected by decision 1).
- Re-running discovery after a switch for the same target on later cycles.
- Any change to `LOW_TTL_DISCOVER_MAX`/`LOW_TTL_DISCOVER_TIMEOUT_MS` semantics.
- Probe-traffic throttling beyond the existing per-candidate timeout.
