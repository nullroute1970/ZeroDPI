# Startup-Only TTL Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run `LOW_TTL_DISCOVER` once before the proxy listener starts, then let background rescans switch SNI/IP targets without changing the discovered TTL.

**Architecture:** Keep the existing startup discovery state and execution in `crates/zerodpi/src/main.rs`. Remove discovery state from the background rescan API and extract the rescan target-selection operation into a pure helper whose return value contains only the next target, making the no-rediscovery policy explicit and testable. Update repository and Android configuration comments plus README text to describe startup-only discovery.

**Tech Stack:** Rust 2021, Tokio, inline `#[cfg(test)]` unit tests, TOML configuration, Markdown documentation.

## Global Constraints

- Preserve SNI/IP target hot-swapping for new connections during background rescans.
- Preserve existing startup `LOW_TTL_DISCOVER` gates and startup probe behavior.
- Do not add a configuration flag for rescan discovery; discovery is startup-only.
- Do not change the separate issue where the discovery probe loop may leave its final candidate in the live TTL handle.
- Use `rustfmt` formatting and keep documentation synchronized across `config.toml`, `android/app/src/main/assets/zerodpi/config.toml`, and `README.md`.

---

### Task 1: Lock the rescan policy with a focused regression test

**Files:**
- Modify: `crates/zerodpi/src/main.rs` in the inline test module near the existing `should_switch_sni_target` tests.

**Interfaces:**
- Consumes: the existing `current(score)` and `candidate(sni, ip, score)` test helpers, plus `ActiveSniTarget` and `SniProbeEntry`.
- Produces: a test for a new pure helper `select_rescan_target(&ActiveSniTarget, &SniProbeEntry, u8) -> Option<ActiveSniTarget>`.

- [ ] **Step 1: Write the failing test**

Add this test. It asserts that a qualifying rescan produces only the candidate target data; no TTL discovery state or callback is part of the rescan target-selection boundary.

```rust
#[test]
fn rescan_target_selection_only_returns_target_update() {
    let c = candidate("new.example.com", Ipv4Addr::new(2, 2, 2, 2), 61);

    let next = select_rescan_target(&current(50), &c, 1).expect("candidate should qualify");

    assert_eq!(next.sni.as_ref(), "new.example.com");
    assert_eq!(next.ip, Ipv4Addr::new(2, 2, 2, 2));
    assert_eq!(next.score, 61);
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```powershell
cargo test -p zerodpi rescan_target_selection_only_returns_target_update
```

Expected: compilation fails because `select_rescan_target` does not yet exist. This confirms the test is exercising the new target-selection boundary rather than existing behavior.

### Task 2: Remove rescan-time TTL discovery and implement the target-only helper

**Files:**
- Modify: `crates/zerodpi/src/main.rs` around startup discovery wiring, `background_rescan`, and the adjacent target-selection helpers.

**Interfaces:**
- Consumes: the existing startup `LowTtlDiscoveryState` and `background_rescan` target-switch logic.
- Produces: `select_rescan_target(...) -> Option<ActiveSniTarget>`; `background_rescan` no longer accepts or clones `LowTtlDiscoveryState`.

- [ ] **Step 1: Add the minimal helper and make the test pass**

Implement:

```rust
fn select_rescan_target(
    current: &ActiveSniTarget,
    candidate: &SniProbeEntry,
    min_score: u8,
) -> Option<ActiveSniTarget> {
    should_switch_sni_target(current, candidate, min_score)
        .then(|| ActiveSniTarget::new(candidate.sni.clone(), candidate.ip, candidate.score))
}
```

Refactor the `background_rescan` branch so it calls this helper, writes the returned target, and emits the existing `SniTargetChanged` event. Remove:

- `let rescan_discovery = low_ttl_discovery_state.clone();`;
- the `low_ttl_discovery` argument at the `background_rescan` call site and function definition;
- the entire `LOW_TTL_DISCOVER: rediscovering for new target` block;
- discovery-specific rescan success/failure event emissions.

Leave the startup `low_ttl_discovery_state` construction and `rt.block_on(discovery_state.run(...))` block unchanged.

- [ ] **Step 2: Run the focused tests to verify they pass**

Run:

```powershell
cargo test -p zerodpi rescan_target_selection_only_returns_target_update low_ttl_discover
```

Expected: all matching `zerodpi` tests pass, including the existing startup discovery decision tests and the new rescan target-selection regression test.

### Task 3: Update startup-only documentation and comments

**Files:**
- Modify: `crates/zerodpi/src/main.rs` comments adjacent to `LowTtlDiscoveryState` and `background_rescan`.
- Modify: `config.toml` LOW-TTL discovery comments.
- Modify: `android/app/src/main/assets/zerodpi/config.toml` LOW-TTL discovery comments.
- Modify: `README.md` LOW-TTL discovery explanation and caveats.

**Interfaces:**
- Consumes: the approved design wording in `docs/superpowers/specs/2026-08-12-startup-only-ttl-discovery-design.md`.
- Produces: consistent documentation stating that discovery runs once before listening and the startup TTL remains active after target rescans.

- [ ] **Step 1: Replace rescan wording**

Change comments such as “again after every background rescan” and “rediscovering for new target” to state that background rescans only hot-swap the active target. In README caveats, remove the claim that discovery re-runs after target changes and explain that the startup-discovered TTL is retained for later targets.

- [ ] **Step 2: Check documentation consistency**

Run:

```powershell
rg -n "again after|rediscover|re-discover|startup-only|startup only|LOW_TTL_DISCOVER" config.toml android/app/src/main/assets/zerodpi/config.toml README.md crates/zerodpi/src/main.rs
```

Expected: no remaining documentation says that TTL discovery runs after a background rescan; startup discovery references remain present.

### Task 4: Verify the complete change

**Files:**
- Verify: all modified Rust, TOML, Markdown, and plan/spec files.

- [ ] **Step 1: Check formatting and diff hygiene**

Run:

```powershell
cargo fmt --all -- --check
git diff --check
git status --short
```

Expected: formatting and whitespace checks exit successfully; only the planned files are modified.

- [ ] **Step 2: Run focused and workspace tests**

Run:

```powershell
cargo test -p zerodpi
cargo test -p zerodpi-core
cargo test --workspace
```

Expected: every command exits with code 0 and reports zero failed tests.

- [ ] **Step 3: Review the final diff**

Confirm that startup discovery is still invoked before `run_proxy`, background rescans still update `active_target` and emit `SniTargetChanged`, and no rescan path can call `LowTtlDiscoveryState::run`.

