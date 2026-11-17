# Dependency Updates Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the dependency updates approved in the conversation while preserving ZeroDPI behavior on Windows, Linux, and Android.

**Architecture:** Update and verify dependency groups sequentially. Keep the existing Windows bindings and parking_lot versions. Adapt only APIs changed by upstream libraries, retaining the current DNS fallback and terminal behavior.

**Tech Stack:** Rust 2021 workspace, Tokio, Rustls, Hickory, Ratatui/Crossterm, NFQUEUE/WinDivert.

**Spec:** The dependency review and implementation order approved by the user in this conversation on 2026-11-17.

## Global Constraints

- Preserve windows 0.48, windows-sys 0.61, parking_lot 0.12, and WinDivert dependencies.
- Prefer Tokio 1.53 LTS and etherparse 0.20.3 over their newest minor releases.
- Preserve explicit custom DNS server order, independent timeouts, IPv4-only results, UDP-to-TCP fallback, and exclusion of system DNS and hosts files in custom mode.
- Develop and review on codex/dependency-updates; the user subsequently requested committing the completed changes on master.
- Reconcile the documented Rust minimum with the final resolved dependency graph.

## Review Focus

- Custom DNS must not silently use system DNS or the hosts file.
- DNS truncation, failures, and cancellation must preserve existing scanner behavior.
- Terminal navigation, rendering, and cleanup must continue to work with matching backend versions.
- NFQUEUE must retain file-descriptor polling and safe shutdown after replacing the local patch.
- WinDivert must retain compatible HANDLE types and existing packet/checksum behavior.

## Tasks

- [x] Establish the existing workspace test baseline.
- [x] Update TLS, trust roots, anyhow, and Tokio LTS; verify workspace tests.
- [x] Migrate Hickory to 0.26.3; run existing DNS/scanner regression tests and add focused coverage for any newly identified behavior gap.
- [x] Update Ratatui/Crossterm together; verify TUI tests and compilation.
- [x] Replace vendored nfq with 0.2.6 after checking local changes; verify Linux compilation and available tests (Android verification follows below).
- [x] Update ordinary dependencies, etherparse 0.20.3, and TOML; reconcile Rust minimum and documentation.
- [x] Run formatting, clippy, workspace tests, release build, cross-platform checks, dependency advisory review, and final diff review.

## Validation and Execution Notes

Logs and scratch artifacts live under target/dependency-update-review/.
Existing behavior tests are the regression contract for dependency-only changes; add tests when behavior needs new coverage, rather than mirroring version numbers.
Record unavailable runtime/platform validation explicitly in the delivery notes.

- Baseline and TLS stage: 749 tests passed, 2 ignored; Tokio 1.53.3, Rustls 0.23.46, Tokio-rustls 0.26.6, WebPKI 0.103.17, roots 1.0.12, anyhow 1.0.104.
- DNS stage: 749 tests passed, 2 ignored. Migrated the resolver builder and explicit UDP/TCP ports. Preserved the old EDNS setting and cache bound. Fixed a malformed truncated-response test fixture to retain the matching question required by upstream security checks.
- TUI stage: 749 tests passed, 2 ignored. Ratatui 0.30.2/Crossterm 0.29.0 require explicit Send/Sync/static bounds for generic backend errors passed to anyhow; rendering and navigation tests remain green.
- NFQUEUE stage: published nfq 0.2.6 replaces both local modifications (descriptor access and hardware-address handling). The complete Linux workspace tests passed, including 37 platform tests for polling, packet handling, and firewall command construction. Actual privileged packet interception remains outside these unit tests.
- Toolchain scope: user additionally requested the latest stable Rust; update both installed Windows stable hosts and the WSL stable toolchain before final validation.
- Rust minimum and project toolchain: after the user's clarification, set the workspace minimum to 1.100 and pin Rust 1.100.0 in rust-toolchain.toml and all release CI jobs. The earlier successful 1.89 compatibility check is historical evidence, not the final project policy.
- Ordinary dependencies/TOML stage: all existing Windows tests passed. Updated rustix to 1.1.6 as part of the transitive advisory fixes.
- Rust 1.100 lint compatibility: use equivalent standard-library methods for byte pairs, divisibility checks, and repeated test bytes. Move the CLI's libc dependency to its actual Linux/Android targets and remove unused workspace metadata.
- Final dependency advisory check: OSV queried all 328 registry packages in Cargo.lock and returned no matching advisories; this is a dependency/version check, not a claim that the application has no vulnerabilities.
- Final review: self-review (no subagent tool available). Checked DNS port/transport configuration, hosts/system-DNS exclusion, truncation fixture validity, backend error propagation, checksum odd-byte handling, and NFQUEUE descriptor access. No unresolved code findings.
- Additional configurations: --no-default-features checks passed on Windows and Linux. Cargo 1.100 emits a nonblocking unused etherparse dependency warning for the Linux configuration without packet interception; the default configuration's Clippy check is clean.

## Final Validation

- Project-selected toolchain: Rust/Cargo 1.100.0 on Windows MSVC and Linux GNU; confirmed rustup selects rust-toolchain.toml in both environments.
- Windows: cargo test --workspace --locked passed (749 tests, 2 ignored); cargo clippy --workspace --all-targets --locked -- -D warnings passed; cargo build --workspace --release --locked passed.
- Linux: the same test command passed (762 tests, 1 ignored); Clippy with -D warnings and the release build passed under WSL using the pinned project toolchain.
- Android: release builds passed for aarch64-linux-android and armv7-linux-androideabi using Rust 1.100.0 and NDK API 23. ELF machine types were verified for both outputs. Device runtime testing was not performed.
- Formatting passed on Windows and Linux. git diff --check passed. Build-helper --help and Windows release --help/--version smoke checks passed.
- Existing ignored tests: loopback performance benchmark, plus the Windows driver shutdown test requiring Administrator and WinDivert.dll/sys. No actual VPN or privileged interception session was started.
- The user requested transferring the reviewed changes to master and committing them after final verification.
