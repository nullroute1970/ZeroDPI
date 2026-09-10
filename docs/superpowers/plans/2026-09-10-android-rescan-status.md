# Android Background Rescan Status Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Android dashboard report the real background-rescan state instead of treating an expired schedule deadline as proof that scanning is active.

**Architecture:** Extend the existing JSON runtime-event protocol with explicit `rescan_started` and `rescan_finished` events emitted by both native background-rescan loops. Parse those events into the Android runner model, store an explicit boolean in `ZeroDpiServiceState`, and make the Home screen render `Scanning…` only from that boolean. Keep the existing schedule event as a countdown source and show `Due` when its deadline has passed but no scan-start event has arrived.

**Spec:** `docs/superpowers/specs/2026-09-10-android-rescan-status-design.md`

### Task 1: Add a failing Android regression test

**Files:**

- Modify: `android/app/src/androidTest/java/dev/zerodpi/android/ui/DashboardScreenTest.kt`

- [x] Add a test with an elapsed `nextScanAtElapsedRealtimeMs` and assert the Home screen shows `Due` rather than `Scanning…`.
- [x] Run the focused parser regression before implementation and confirm it fails against the current implementation; compile the UI regression target after implementation.

### Task 2: Add the runtime event contract and native emissions

**Files:**

- Modify: `crates/zerodpi/src/runtime_events.rs`
- Modify: `crates/zerodpi/src/main.rs`

- [x] Add `RescanStarted { scan }` and `RescanFinished { scan, found, best_score, duration_ms, switched }` to `RuntimeEvent`.
- [x] Add serialization coverage for both event shapes.
- [x] Emit start and finish events around the SNI background scan.
- [x] Emit start and finish events around every IP background-scan exit path, including load/rejection errors and empty results.
- [x] Run the focused Rust tests and confirm they pass.

### Task 3: Parse events and update Android service state

**Files:**

- Modify: `android/app/src/main/java/dev/zerodpi/android/runtime/ZeroDpiRunner.kt`
- Modify: `android/app/src/main/java/dev/zerodpi/android/runtime/RuntimeEventLineParser.kt`
- Modify: `android/app/src/test/java/dev/zerodpi/android/runtime/RuntimeEventLineParserTest.kt`
- Modify: `android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt`

- [x] Add runner event data classes and parser cases for start/finish events.
- [x] Test scan kind and finish summary fields.
- [x] Add `rescanInProgress` to service state and update it only from explicit start/finish events.
- [x] Clear it whenever a runtime run is initialized, restarted, stopped, or fails.

### Task 4: Correct dashboard rendering and add UI coverage

**Files:**

- Modify: `android/app/src/main/java/dev/zerodpi/android/ui/HomeScreen.kt`
- Modify: `android/app/src/main/res/values/strings.xml`
- Modify: `android/app/src/androidTest/java/dev/zerodpi/android/ui/DashboardScreenTest.kt`

- [x] Pass explicit rescan state into the countdown renderer.
- [x] Render `Scanning…` only for an active rescan; render `Due` for an expired inactive deadline.
- [x] Cover both inactive-expired and active-expired cases.

### Task 5: Verify the complete change

- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo test --workspace`.
- [x] Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] Run the Android JVM test suite and compile the Android instrumentation test target.
- [x] Run `cargo build --workspace --release`.
- [x] Review the diff for unrelated changes and report any environment-limited verification explicitly.

The connected Android instrumentation suite could not execute because `adb devices`
reported no connected devices; the instrumentation sources compile successfully.
