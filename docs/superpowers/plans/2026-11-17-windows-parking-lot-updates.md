# Windows and Parking Lot Updates Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade windows first, then parking_lot, preserving packet handling, shutdown, and synchronization behavior.

**Architecture:** Keep WinDivert's published ABI and introduce explicit typed conversions between the application's current Windows bindings and WinDivert's legacy bindings. Store its opaque handle value as an integer, preserving existing thread-safety without adding unsafe Send/Sync implementations. Upgrade the application's parking_lot dependency separately; upstream consumers may retain their own compatible older version.

**Tech Stack:** Rust 1.100.0, Windows 0.62.2, WinDivert 0.6/0.10, parking_lot 0.13.0.

**Spec:** User request in the conversation: upgrade windows first, then parking_lot, without breaking the program.

## Constraints and Review Focus

- Do not rewrite native WinDivert bindings, vendor its crates, or change driver configuration.
- Retain windows 0.48 only for the explicit compatibility boundary required by published WinDivert crates.
- Preserve invalid-handle checks, pointer-width handle bits, concurrent shutdown/receive/send, and close-once ownership.
- Audit parking_lot uses for raw, recursive, mapped-guard, condition-variable, and fairness-sensitive operations before updating.
- Keep existing Windows, Linux, and Android behavior tests green, and inspect available relay performance measurements.
- Leave these new changes uncommitted for review unless the user requests a commit.

## Tasks

- [x] Verify the clean baseline and inspect published source/API changes.
- [x] Upgrade windows and add focused compatibility tests; run Windows workspace tests and Clippy before proceeding.
- [x] Audit and upgrade parking_lot; run workspace and concurrency regressions (release performance comparison follows in final validation).
- [x] Validate formatting, Clippy, release builds, Linux tests, Android builds, and advisory results; review the final diff and record limitations.

## Validation Notes

Logs and downloaded reference source live under target/windows-parking-update/.

- Baseline: 749 Windows tests passed, 2 ignored.
- Windows stage: 752 tests passed, 2 ignored, and Clippy passed with -D warnings. Three new tests cover full-width handle bits, invalid sentinels, and Send/Sync requirements. The legacy Windows dependency is an explicit alias for WinDivert FFI only; no native bindings or driver behavior changed.
- parking_lot audit: application code uses ordinary Mutex guards for flow state, target selection, and progress registration. No raw locks, recursive reads, condition variables, mapped guards, or explicit fairness operations were found. Current critical sections contain no await.
- parking_lot stage: 753 Windows tests passed, 2 ignored. A focused contention regression passed before and after the update: four threads acquire 2048 target leases while 512 rescans/snapshots run, preserving exact traffic totals and returning the active-connection count to zero.
- The application's parking_lot dependency is 0.13.0; Hickory, Crossterm, and Moka retain their own required 0.12.5 dependency. The old Windows package similarly remains required by published WinDivert crates.
- Final platform validation: 753 Windows tests passed (2 ignored), 763 Linux tests passed (1 ignored). Windows and Linux Clippy with -D warnings passed. Release builds passed for Windows MSVC, Linux x86_64 GNU, Android ARMv7, and Android ARM64 with Rust 1.100.0. Release --help/--version smoke checks passed on Windows and Linux.
- The new target-pool contention regression passed 20 independent executions in the optimized test executable.
- OSV queried all 342 registry package versions and returned no matching advisories.
- The first release relay comparison alternated before/after executables over 72 runs (1/32/128 connections, progress off/on, TCP_NODELAY off/on). Median configuration throughput change was +0.03%; individual medians ranged from -3.37% to +22.08%. Short latency measurements varied; they do not establish a latency improvement or a hard performance guarantee.
- A follow-up 128-connection benchmark hit its external 60-second timeout after completing the first configuration. Its original harness did not identify the timed-out version or retain child output. Diagnostic runs then recorded each version/configuration and child output: six targeted runs and a full 16-run 128-connection matrix all passed, using both pre-update and post-update executables. The timeout was not reproduced and its cause remains undetermined; these results do not prove that an intermittent issue is impossible. Current TCP counts did not establish temporary-port exhaustion.
- The explicitly ignored native WinDivert idle-shutdown test was also run separately with Administrator privileges and the bundled DLL/driver: passed. Its filter is false, so it captures no packets. This exercises native handle creation, concurrent receive shutdown, and cleanup with the compatibility adapter.
- Final review: self-review (no subagent tool available). Checked native token bit width and invalid sentinels, retained WinDivert close/shutdown ownership, absence of unsafe Send/Sync or transmute additions, short lock scopes, target accounting under concurrent rescans, and dependency alias/version resolution. No unresolved code findings.
- Runtime limits: the driver test and loopback benchmark remain ignored during normal unit tests, but were exercised separately as recorded above. No real VPN session or Android device runtime test was performed.
