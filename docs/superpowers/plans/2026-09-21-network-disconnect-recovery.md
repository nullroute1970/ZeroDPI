# Network Disconnect Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the ZeroDPI core recover in place when the network changes or drops: detect the change, rebuild interception against the new interface address, clear stale flows, verify the active target, and report status — without restarting the process or the run.

**Architecture:** A platform `netmon` module detects routing changes (netlink on Linux/Android, IP Helper notifications on Windows, 10 s poll safety net) and emits settled change events. Core gains a shared `InterfaceIp` watch handle and `FlowController::reset`. A CLI `DataPlaneController` owns the live interceptor and can rebuild it for a new address (local NFQUEUE/WinDivert or root helper). A CLI `RecoveryCoordinator` owns the policy: probe, rebuild with backoff, verify, rescan only when allowed. Android consumes the new runtime events instead of restarting the run.

**Tech Stack:** Rust 2021 (tokio, anyhow, thiserror, serde, tracing, libc), `windows-sys` 0.61 for IP Helper notifications, Kotlin/AndroidX for the app-side changes.

**Spec:** `docs/superpowers/specs/2026-09-21-network-disconnect-recovery-design.md`

## Global Constraints

- Rust edition 2021, `rust-version = 1.75`, 4-space indentation; run `cargo fmt --all -- --check` before every commit.
- `cargo clippy --workspace --all-targets -- -D warnings` must pass; `cargo test --workspace` must pass.
- No new `config.toml` keys. Tunables are internal constants with the exact values in the spec: 1 s settle, 10 s poll, 1 s → 60 s rebuild backoff, 10 s connect timeout, 60 s recovery-rescan rate limit.
- Runtime events are additive only; `CONTRACT_VERSION` stays `1`; unknown events must keep falling back to `Log` in the Android parser.
- `windows-sys` is a Windows-only target dependency; Linux/Android builds must not reference it.
- The `packet-interception = false` build (`zerodpi-platform` default-features off) must keep compiling: new `FlowController` methods need stub implementations there.
- `anyhow` at application boundaries, `thiserror` inside reusable crates.
- Tests are inline `#[cfg(test)]` modules named by behavior (for example `rebuilds_when_interface_changes`).
- Platform code compiles under `cargo check -p zerodpi-platform --no-default-features` and (on Linux) `cargo check -p zerodpi-platform`.

## Review Focus

1. **Flapping network (change every few seconds).** Expected: one rebuild per settled change, bounded retries, at most one recovery-triggered rescan per 60 s — not a firewall-rule churn storm. Pinned by `a_new_event_resets_the_backoff` and `rescan_is_gated_and_rate_limited` (Task 9).
2. **IPv6-only `ip_bypass` target.** Expected: the monitor probes a fixed IPv4 anchor instead of panicking or silently disabling detection. Pinned by `monitor_probe_target_falls_back_to_anchor_for_ipv6` (Task 14).
3. **Windows sleep/resume.** Expected: notification callbacks wake the monitor once and shutdown joins the notifier thread without deadlock. Pinned by `notifier_shutdown_is_prompt` (Task 4, Windows-only test).
4. **Android app receiving recover events.** Expected: the service logs/surfaces them and never restarts the run. Pinned by `networkEventsDoNotRestartRun` (Task 16).
5. **Rebuild impossible (permissions lost mid-run).** Expected: repeated `Recovering`/`Unavailable` statuses and continued retries, never a silent wedge; the app/supervisor can see the state. Pinned by `retries_rebuild_with_backoff_until_success` and `marks_unavailable_when_probe_fails` (Task 9).

## File Structure

Created:

- `crates/zerodpi-platform/src/netmon/mod.rs` — network change detection: types, settle state, monitor thread, platform sources.
- `crates/zerodpi/src/data_plane.rs` — `DataPlane` trait and `DataPlaneController` (local/remote/none), moved interceptor lifecycle types.
- `crates/zerodpi/src/network_recovery.rs` — `RecoveryCoordinator`, `RecoveryEnv`, `NetworkStatus`, `RescanOutcome`, backoff policy.
- `docs/superpowers/plans/2026-09-21-network-disconnect-recovery.md` — this plan.

Modified (Rust): `crates/zerodpi-core/src/net.rs`, `flow.rs`, `proxy.rs`, `sni_scanner.rs`, `ip_scanner.rs`, `low_ttl_discover.rs`; `crates/zerodpi-platform/src/lib.rs`, `Cargo.toml`; `crates/zerodpi/src/main.rs`, `runtime_events.rs`, `helper_client.rs`, `tui.rs`.

Modified (Android): `android/app/src/main/java/dev/zerodpi/android/runtime/ZeroDpiRunner.kt` (`ZeroDpiRunnerEvent`), `runtime/RuntimeEventLineParser.kt`, `service/ZeroDpiService.kt`, `android/app/src/test/java/dev/zerodpi/android/runtime/RuntimeEventLineParserTest.kt`, `android/app/src/androidTest/java/dev/zerodpi/android/service/ZeroDpiServiceInstrumentedTest.kt`, `android/app/src/androidTest/java/dev/zerodpi/android/service/TargetPickServiceInstrumentedTest.kt`. Deleted: `service/DefaultNetworkMonitor.kt`, `android/app/src/test/java/dev/zerodpi/android/service/NetworkChangeTrackerTest.kt`.

Modified (docs): `README.md`, `android/README.md`.

---

### Task 1: Core shared network types (`NetworkChangeSource`, `InterfaceIp`)

**Files:**
- Modify: `crates/zerodpi-core/src/net.rs`
- Test: `crates/zerodpi-core/src/net.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `zerodpi_core::net::NetworkChangeSource { Address, Route, Link, Poll }` (serde `snake_case`).
  - `zerodpi_core::net::InterfaceIp` with `current() -> Ipv4Addr`, `fixed(Ipv4Addr)`, `changed() -> Result<(), watch::error::RecvError>`.
  - `zerodpi_core::net::InterfaceIpHandle` with `set(Ipv4Addr)` and `receiver() -> InterfaceIp`.
  - `zerodpi_core::net::interface_ip_channel(Ipv4Addr) -> (InterfaceIpHandle, InterfaceIp)`.

- [ ] **Step 1: Write the failing tests**

Append to `crates/zerodpi-core/src/net.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_ip_channel_reads_latest_value() {
        let (handle, rx) = interface_ip_channel(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(rx.current(), Ipv4Addr::new(10, 0, 0, 1));
        handle.set(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(rx.current(), Ipv4Addr::new(10, 0, 0, 2));
    }

    #[tokio::test]
    async fn interface_ip_watch_notifies_on_set() {
        let (handle, mut rx) = interface_ip_channel(Ipv4Addr::LOCALHOST);
        handle.set(Ipv4Addr::new(192, 0, 2, 10));
        rx.changed().await.unwrap();
        assert_eq!(rx.current(), Ipv4Addr::new(192, 0, 2, 10));
    }

    #[test]
    fn interface_ip_fixed_is_usable_without_a_sender() {
        let rx = InterfaceIp::fixed(Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(rx.current(), Ipv4Addr::new(203, 0, 113, 7));
    }

    #[test]
    fn network_change_source_serializes_snake_case() {
        let json = serde_json::to_string(&NetworkChangeSource::Address).unwrap();
        assert_eq!(json, "\"address\"");
        let json = serde_json::to_string(&NetworkChangeSource::Poll).unwrap();
        assert_eq!(json, "\"poll\"");
    }
}
```

`tokio` is already a dependency with the `time`/`sync` features; `serde_json` is a dev-dependency of the crate.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-core net::tests -v`
Expected: FAIL — `InterfaceIp`, `InterfaceIpHandle`, `interface_ip_channel`, `NetworkChangeSource` not found.

- [ ] **Step 3: Implement the types**

At the top of `crates/zerodpi-core/src/net.rs`, extend the imports and add the new items after `default_interface_ipv4`:

```rust
use tokio::sync::watch;

/// Which kind of platform event produced a network change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkChangeSource {
    /// An interface address was added, removed, or changed.
    Address,
    /// A route was added, removed, or changed.
    Route,
    /// A link went up or down.
    Link,
    /// The periodic safety-net probe observed a difference.
    Poll,
}

/// Read-only handle to the current outbound interface address.
///
/// Clone it into tasks that need the address at use time (proxy connections,
/// LOW_TTL discovery). The value is swapped by the recovery coordinator after
/// a rebuild succeeds.
#[derive(Clone, Debug)]
pub struct InterfaceIp {
    rx: watch::Receiver<Ipv4Addr>,
}

impl InterfaceIp {
    /// The current interface address.
    pub fn current(&self) -> Ipv4Addr {
        *self.rx.borrow()
    }

    /// A handle that never changes. Used by scanners and tests.
    pub fn fixed(ip: Ipv4Addr) -> Self {
        let (_tx, rx) = watch::channel(ip);
        Self { rx }
    }

    /// Resolves when the value changes. A fixed handle resolves only when its
    /// internal sender is dropped.
    pub async fn changed(
        &mut self,
    ) -> Result<(), tokio::sync::watch::error::RecvError> {
        self.rx.changed().await
    }
}

/// Write side of [`InterfaceIp`], owned by the recovery coordinator.
#[derive(Clone, Debug)]
pub struct InterfaceIpHandle {
    tx: watch::Sender<Ipv4Addr>,
}

impl InterfaceIpHandle {
    /// Store a new interface address. Never fails; receivers may simply be gone.
    pub fn set(&self, ip: Ipv4Addr) {
        self.tx.send_replace(ip);
    }

    /// A read handle for tasks.
    pub fn receiver(&self) -> InterfaceIp {
        InterfaceIp {
            rx: self.tx.subscribe(),
        }
    }
}

/// Create the shared interface-address channel.
pub fn interface_ip_channel(initial: Ipv4Addr) -> (InterfaceIpHandle, InterfaceIp) {
    let (tx, rx) = watch::channel(initial);
    (InterfaceIpHandle { tx }, InterfaceIp { rx })
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core net::tests -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/net.rs
git commit -m "feat(core): add shared interface IP handle and network change source"
```

---

### Task 2: Platform monitor core (types, settle state, monitor thread)

**Files:**
- Create: `crates/zerodpi-platform/src/netmon/mod.rs`
- Modify: `crates/zerodpi-platform/src/lib.rs`
- Test: `crates/zerodpi-platform/src/netmon/mod.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: `zerodpi_core::net::NetworkChangeSource` (Task 1); `zerodpi_core::net::default_interface_ipv4`.
- Produces:
  - `zerodpi_platform::netmon::NetworkEvent { Changed { source: NetworkChangeSource } }`.
  - `zerodpi_platform::netmon::NetworkMonitor::start(probe_target: Arc<AtomicU32>, initial: Option<Ipv4Addr>, settle: Duration, poll_interval: Duration) -> anyhow::Result<Self>`.
  - `NetworkMonitor::events() -> broadcast::Receiver<NetworkEvent>`, `NetworkMonitor::shutdown()`.
  - Internal seams used by later tasks: `SettleState`, `ChangeFilter`, `NetworkSource`, `NetworkWaker`, `SourceParts`, `run_loop`.

- [ ] **Step 1: Write the failing tests**

Create `crates/zerodpi-platform/src/netmon/mod.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use zerodpi_core::net::NetworkChangeSource;

    #[test]
    fn settle_waits_for_the_window_to_elapse() {
        let mut settle = SettleState::new(Duration::from_secs(1));
        settle.record(NetworkChangeSource::Address, Duration::from_secs(10));
        assert_eq!(settle.due(Duration::from_millis(10_999)), None);
        assert_eq!(
            settle.due(Duration::from_secs(11)),
            Some(NetworkChangeSource::Address)
        );
        // The pending change is consumed exactly once.
        assert_eq!(settle.due(Duration::from_secs(12)), None);
    }

    #[test]
    fn a_newer_tick_resets_the_deadline_and_keeps_the_latest_source() {
        let mut settle = SettleState::new(Duration::from_secs(1));
        settle.record(NetworkChangeSource::Address, Duration::from_secs(10));
        settle.record(NetworkChangeSource::Route, Duration::from_millis(10_500));
        assert_eq!(settle.due(Duration::from_secs(11)), None);
        assert_eq!(
            settle.due(Duration::from_millis(11_500)),
            Some(NetworkChangeSource::Route)
        );
    }

    #[test]
    fn timeout_reports_the_remaining_window() {
        let mut settle = SettleState::new(Duration::from_secs(2));
        assert_eq!(settle.timeout(Duration::ZERO), None);
        settle.record(NetworkChangeSource::Link, Duration::from_secs(5));
        assert_eq!(
            settle.timeout(Duration::from_millis(5_500)),
            Some(Duration::from_millis(1_500))
        );
    }

    #[test]
    fn change_filter_reports_only_real_changes() {
        let mut filter = ChangeFilter::default();
        filter.seed(None);
        assert!(!filter.observe(None));
        assert!(filter.observe(Some("10.0.0.1".parse().unwrap())));
        assert!(!filter.observe(Some("10.0.0.1".parse().unwrap())));
        assert!(filter.observe(None));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-platform netmon::tests -v`
Expected: FAIL — module `netmon` does not exist.

- [ ] **Step 3: Implement the monitor skeleton**

Prepend to the same file (above the tests):

```rust
//! Network change detection.
//!
//! The monitor answers one question: did the local routing situation change?
//! The canonical new address is discovered by the caller with
//! `default_interface_ipv4`, so platform event payloads are deliberately
//! ignored — only the event kind matters.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::broadcast;
use zerodpi_core::net::{default_interface_ipv4, NetworkChangeSource};

/// A settled, routing-relevant change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEvent {
    Changed { source: NetworkChangeSource },
}

/// Coalesces raw platform ticks into settled change notifications.
#[derive(Debug)]
pub struct SettleState {
    settle: Duration,
    pending: Option<(NetworkChangeSource, Duration)>,
}

impl SettleState {
    pub fn new(settle: Duration) -> Self {
        Self {
            settle,
            pending: None,
        }
    }

    /// Record a raw tick; a newer tick replaces the pending deadline.
    pub fn record(&mut self, source: NetworkChangeSource, now: Duration) {
        self.pending = Some((source, now.saturating_add(self.settle)));
    }

    /// Time until the pending tick settles, or `None` when nothing is pending.
    pub fn timeout(&self, now: Duration) -> Option<Duration> {
        self.pending
            .as_ref()
            .map(|(_, deadline)| deadline.saturating_sub(now))
    }

    /// Take the settled tick when its deadline has passed.
    pub fn due(&mut self, now: Duration) -> Option<NetworkChangeSource> {
        match self.pending {
            Some((source, deadline)) if now >= deadline => {
                self.pending = None;
                Some(source)
            }
            _ => None,
        }
    }
}

/// Emits `true` once per real address/up-state transition.
#[derive(Debug, Default)]
pub struct ChangeFilter {
    last: Option<Ipv4Addr>,
}

impl ChangeFilter {
    pub fn seed(&mut self, value: Option<Ipv4Addr>) {
        self.last = value;
    }

    pub fn observe(&mut self, value: Option<Ipv4Addr>) -> bool {
        if value != self.last {
            self.last = value;
            true
        } else {
            false
        }
    }
}

/// What a platform source reports while the monitor waits.
#[derive(Debug)]
pub(crate) enum SourceEvent {
    Change(NetworkChangeSource),
    Timeout,
    Shutdown,
}

/// Blocking platform event source.
pub(crate) trait NetworkSource: Send {
    /// Block for at most `timeout`.
    fn wait(&mut self, timeout: Duration) -> SourceEvent;
}

/// Wake handle used to interrupt [`NetworkSource::wait`] at shutdown.
pub(crate) trait NetworkWaker: Send + Sync {
    fn wake(&self);
}

pub(crate) struct SourceParts<S: NetworkSource> {
    pub source: S,
    pub waker: Arc<dyn NetworkWaker>,
}

/// One monitor iteration. Exposed for platform wiring and tests.
pub(crate) fn run_loop<S: NetworkSource>(
    mut source: S,
    probe: impl Fn() -> Option<Ipv4Addr>,
    settle: Duration,
    poll_interval: Duration,
    should_run: impl Fn() -> bool,
    emit: impl Fn(NetworkEvent),
) {
    let mut settle_state = SettleState::new(settle);
    let mut filter = ChangeFilter::default();
    filter.seed(probe());
    let start = std::time::Instant::now();
    loop {
        if !should_run() {
            break;
        }
        let now = start.elapsed();
        let timeout = settle_state.timeout(now).unwrap_or(poll_interval);
        match source.wait(timeout) {
            SourceEvent::Change(kind) => settle_state.record(kind, start.elapsed()),
            SourceEvent::Shutdown => break,
            SourceEvent::Timeout => {
                let now = start.elapsed();
                if let Some(kind) = settle_state.due(now) {
                    if filter.observe(probe()) {
                        emit(NetworkEvent::Changed { source: kind });
                    }
                } else if filter.observe(probe()) {
                    emit(NetworkEvent::Changed {
                        source: NetworkChangeSource::Poll,
                    });
                }
            }
        }
    }
}

/// Owns the platform detection thread and its event channel.
pub struct NetworkMonitor {
    stop: Arc<AtomicBool>,
    waker: Arc<dyn NetworkWaker>,
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    tx: broadcast::Sender<NetworkEvent>,
}

impl NetworkMonitor {
    /// Start detection.
    ///
    /// `probe_target` is the active relay IPv4 address (0 = unknown); the
    /// canonical interface address is discovered with
    /// `default_interface_ipv4`. `initial` is the address probed at startup.
    pub fn start(
        probe_target: Arc<AtomicU32>,
        initial: Option<Ipv4Addr>,
        settle: Duration,
        poll_interval: Duration,
    ) -> Result<Self> {
        let (tx, _rx) = broadcast::channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let parts = platform_source()?;
        let waker = parts.waker.clone();
        let emit_tx = tx.clone();
        let thread_stop = stop.clone();
        let probe = move || {
            let raw = probe_target.load(Ordering::SeqCst);
            if raw == 0 {
                return None;
            }
            default_interface_ipv4(Ipv4Addr::from(raw)).ok()
        };
        let handle = std::thread::Builder::new()
            .name("zerodpi-netmon".into())
            .spawn(move || {
                run_loop(
                    parts.source,
                    probe,
                    settle,
                    poll_interval,
                    || !thread_stop.load(Ordering::SeqCst),
                    |event| {
                        let _ = emit_tx.send(event);
                    },
                );
            })?;
        Ok(Self {
            stop,
            waker,
            handle: Mutex::new(Some(handle)),
            tx,
        })
    }

    pub fn events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.tx.subscribe()
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.waker.wake();
        let handle = self.handle.lock().expect("netmon handle poisoned").take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }

    #[cfg(test)]
    pub(crate) fn start_for_test(
        source: impl NetworkSource + 'static,
        waker: Arc<dyn NetworkWaker>,
        initial: Option<Ipv4Addr>,
        settle: Duration,
        poll_interval: Duration,
    ) -> Self {
        let (tx, _rx) = broadcast::channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let emit_tx = tx.clone();
        let thread_stop = stop.clone();
        let handle = std::thread::Builder::new()
            .name("zerodpi-netmon-test".into())
            .spawn(move || {
                run_loop(
                    source,
                    move || initial,
                    settle,
                    poll_interval,
                    || !thread_stop.load(Ordering::SeqCst),
                    |event| {
                        let _ = emit_tx.send(event);
                    },
                );
            })
            .expect("spawn test monitor");
        Self {
            stop,
            waker,
            handle: Mutex::new(Some(handle)),
            tx,
        }
    }
}
```

For this task, stub `platform_source` (replaced by Tasks 3 and 4):

```rust
#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
fn platform_source() -> Result<SourceParts<PollOnlySource>> {
    Ok(SourceParts {
        source: PollOnlySource,
        waker: Arc::new(NoopWaker),
    })
}

/// Source used on unsupported platforms and as the fallback path.
pub(crate) struct PollOnlySource;

impl NetworkSource for PollOnlySource {
    fn wait(&mut self, timeout: Duration) -> SourceEvent {
        std::thread::sleep(timeout);
        SourceEvent::Timeout
    }
}

pub(crate) struct NoopWaker;

impl NetworkWaker for NoopWaker {
    fn wake(&self) {}
}

#[cfg(any(target_os = "linux", target_os = "android", windows))]
fn platform_source() -> Result<SourceParts<impl NetworkSource>> {
    platform::source()
}
```

Add a `mod platform;` gate and a temporary `platform` module in a new file:

`crates/zerodpi-platform/src/netmon/platform.rs`:

```rust
//! Native event sources. Fleshed out in the Linux and Windows tasks.

use super::*;

pub(crate) fn source() -> Result<SourceParts<PollOnlySource>> {
    Ok(SourceParts {
        source: PollOnlySource,
        waker: Arc::new(NoopWaker),
    })
}
```

- [ ] **Step 4: Register the module**

In `crates/zerodpi-platform/src/lib.rs`, add near the other modules:

```rust
pub mod netmon;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-platform netmon::tests -v`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
git add crates/zerodpi-platform/src/netmon crates/zerodpi-platform/src/lib.rs
git commit -m "feat(platform): add network monitor core with settle logic"
```

---

### Task 3: Linux/Android netlink event source

**Files:**
- Modify: `crates/zerodpi-platform/src/netmon/platform.rs`
- Modify: `crates/zerodpi-platform/src/netmon/mod.rs` (only if the platform fn signature changes)
- Test: `crates/zerodpi-platform/src/netmon/platform.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: `SourceParts`, `NetworkSource`, `NetworkWaker`, `SourceEvent`, `NetworkChangeSource` (Task 2).
- Produces: `platform::source()` on Linux/Android returning a netlink-backed source; `classify_nlmsg(u16) -> Option<NetworkChangeSource>`.

- [ ] **Step 1: Write the failing classifier test**

Append to `crates/zerodpi-platform/src/netmon/platform.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_netlink_message_types() {
        assert_eq!(classify_nlmsg(RTM_NEWADDR), Some(NetworkChangeSource::Address));
        assert_eq!(classify_nlmsg(RTM_DELADDR), Some(NetworkChangeSource::Address));
        assert_eq!(classify_nlmsg(RTM_NEWROUTE), Some(NetworkChangeSource::Route));
        assert_eq!(classify_nlmsg(RTM_DELROUTE), Some(NetworkChangeSource::Route));
        assert_eq!(classify_nlmsg(RTM_NEWLINK), Some(NetworkChangeSource::Link));
        assert_eq!(classify_nlmsg(RTM_DELLINK), Some(NetworkChangeSource::Link));
        assert_eq!(classify_nlmsg(0xffff), None);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p zerodpi-platform netmon::platform::tests -v`
Expected: FAIL — `classify_nlmsg` and the `RTM_*` constants are not defined.

- [ ] **Step 3: Implement the netlink source**

Replace `platform.rs` with the following (Linux/Android body; other platforms keep the poll-only fallback):

```rust
//! Native event sources.

use super::*;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::{classify_nlmsg, source};

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn source() -> Result<SourceParts<PollOnlySource>> {
    Ok(SourceParts {
        source: PollOnlySource,
        waker: Arc::new(NoopWaker),
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    const NETLINK_ROUTE: i32 = 0;
    const RTM_NEWADDR: u16 = 20;
    const RTM_DELADDR: u16 = 21;
    const RTM_NEWROUTE: u16 = 24;
    const RTM_DELROUTE: u16 = 25;
    const RTM_NEWLINK: u16 = 16;
    const RTM_DELLINK: u16 = 17;
    const RTMGRP_LINK: u32 = 1;
    const RTMGRP_IPV4_IFADDR: u32 = 0x10;
    const RTMGRP_IPV4_ROUTE: u32 = 0x40;

    /// Map a netlink message type to the change kind it represents.
    pub(crate) fn classify_nlmsg(msg_type: u16) -> Option<NetworkChangeSource> {
        match msg_type {
            RTM_NEWADDR | RTM_DELADDR => Some(NetworkChangeSource::Address),
            RTM_NEWROUTE | RTM_DELROUTE => Some(NetworkChangeSource::Route),
            RTM_NEWLINK | RTM_DELLINK => Some(NetworkChangeSource::Link),
            _ => None,
        }
    }

    pub(crate) fn source() -> Result<SourceParts<NetlinkSource>> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("open netlink route socket");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
        let bind_result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bind_result < 0 {
            return Err(io::Error::last_os_error()).context("bind netlink route socket");
        }

        let (wake_read, wake_write) = wake_pipe()?;
        let stop = Arc::new(AtomicBool::new(false));
        Ok(SourceParts {
            source: NetlinkSource {
                fd,
                wake_read,
                stop: stop.clone(),
            },
            waker: Arc::new(PipeWaker { fd: wake_write, stop }),
        })
    }

    fn wake_pipe() -> Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0 as RawFd; 2];
        let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if result < 0 {
            return Err(io::Error::last_os_error()).context("create netmon wake pipe");
        }
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Ok((read, write))
    }

    pub(crate) struct NetlinkSource {
        fd: OwnedFd,
        wake_read: OwnedFd,
        stop: Arc<AtomicBool>,
    }

    impl NetworkSource for NetlinkSource {
        fn wait(&mut self, timeout: Duration) -> SourceEvent {
            if self.stop.load(Ordering::SeqCst) {
                return SourceEvent::Shutdown;
            }
            let mut fds = [
                libc::pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.wake_read.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
            let polled = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    return SourceEvent::Timeout;
                }
                debug!(%error, "netlink poll failed");
                return SourceEvent::Timeout;
            }
            if fds[1].revents != 0 {
                let mut byte = [0u8; 1];
                unsafe {
                    libc::read(
                        self.wake_read.as_raw_fd(),
                        byte.as_mut_ptr() as *mut libc::c_void,
                        1,
                    )
                };
                return SourceEvent::Shutdown;
            }
            if fds[0].revents & libc::POLLIN == 0 {
                return SourceEvent::Timeout;
            }
            self.drain()
        }
    }

    impl NetlinkSource {
        fn drain(&mut self) -> SourceEvent {
            let mut buf = [0u8; 8192];
            loop {
                let read = unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                if read <= 0 {
                    return SourceEvent::Timeout;
                }
                let mut offset = 0usize;
                let total = read as usize;
                while offset + 16 <= total {
                    let msg_type = u16::from_ne_bytes([buf[offset + 4], buf[offset + 5]]);
                    if let Some(kind) = classify_nlmsg(msg_type) {
                        return SourceEvent::Change(kind);
                    }
                    let len = u32::from_ne_bytes([
                        buf[offset],
                        buf[offset + 1],
                        buf[offset + 2],
                        buf[offset + 3],
                    ]) as usize;
                    if len < 16 || offset + len > total {
                        break;
                    }
                    offset += len;
                }
            }
        }
    }

    struct PipeWaker {
        fd: OwnedFd,
        stop: Arc<AtomicBool>,
    }

    impl NetworkWaker for PipeWaker {
        fn wake(&self) {
            self.stop.store(true, Ordering::SeqCst);
            let byte = [1u8; 1];
            unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    byte.as_ptr() as *const libc::c_void,
                    1,
                )
            };
        }
    }
}
```

Add `use tracing::debug;` to `netmon/mod.rs` imports.

- [ ] **Step 4: Run the classifier test and a compile check**

Run: `cargo test -p zerodpi-platform netmon -v && cargo check -p zerodpi-platform`
Expected: PASS (5 tests), clean check.

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-platform/src/netmon
git commit -m "feat(platform): add netlink network change source for linux"
```

---

### Task 4: Windows IP Helper notification source

**Files:**
- Modify: `crates/zerodpi-platform/Cargo.toml`
- Modify: `crates/zerodpi-platform/src/netmon/platform.rs`
- Test: `crates/zerodpi-platform/src/netmon/platform.rs` (Windows-only test)

**Interfaces:**
- Consumes: `SourceParts`, `NetworkSource`, `NetworkWaker`, `SourceEvent`, `NetworkChangeSource` (Task 2).
- Produces: `platform::source()` on Windows; same behavior as the Linux source (one `Change` per raw event, `Shutdown` on wake).

- [ ] **Step 1: Add the dependency**

In `crates/zerodpi-platform/Cargo.toml`, replace the existing Windows dependency block with:

```toml
[target.'cfg(windows)'.dependencies]
windivert = "0.6"
windivert-sys = "0.10"
windows-sys = { version = "0.61", features = [
    "Win32_Foundation",
    "Win32_NetworkManagement_IpHelper",
] }
```

- [ ] **Step 2: Write the failing tests (Windows-only)**

Append to `platform.rs`:

```rust
#[cfg(all(test, windows))]
mod windows_tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn notifier_shutdown_is_prompt() {
        let parts = source().expect("start windows notification source");
        let mut source = parts.source;
        // Wait briefly so registration is live before shutdown.
        std::thread::sleep(Duration::from_millis(50));
        parts.waker.wake();
        let started = std::time::Instant::now();
        let event = source.wait(Duration::from_secs(5));
        assert!(matches!(event, SourceEvent::Shutdown));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
```

- [ ] **Step 3: Implement the Windows source**

Add to `platform.rs`:

```rust
#[cfg(windows)]
pub(crate) use windows_impl::source;

#[cfg(windows)]
mod windows_impl {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
    use std::sync::Mutex;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, NotifyIpInterfaceChange, NotifyRouteChange2, MIB_IPFORWARD_ROW2,
        MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
    };
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetMessageW, PostThreadMessageW, MSG, WM_APP, WM_QUIT,
    };

    use super::*;

    const AF_INET: u32 = 2;

    /// Raw callback pushed onto the notifier thread's message queue.
    const WM_NET_CHANGE: u32 = WM_APP + 1;

    pub(crate) fn source() -> Result<SourceParts<WindowsSource>> {
        let (raw_tx, raw_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<u32>>();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();

        let notifier = std::thread::Builder::new()
            .name("zerodpi-netmon-win".into())
            .spawn(move || notifier_thread(raw_tx, ready_tx, thread_stop))?;

        let thread_id = match ready_rx.recv() {
            Ok(Ok(thread_id)) => thread_id,
            Ok(Err(_)) | Err(_) => {
                stop.store(true, Ordering::SeqCst);
                let _ = notifier.join();
                anyhow::bail!("windows network notification registration failed");
            }
        };

        Ok(SourceParts {
            source: WindowsSource {
                rx: raw_rx,
                thread_id,
            },
            waker: Arc::new(WindowsWaker { thread_id, stop }),
        })
    }

    fn notifier_thread(
        tx: Sender<NetworkChangeSource>,
        ready_tx: Sender<Result<u32>>,
        stop: Arc<AtomicBool>,
    ) {
        let context = Box::into_raw(Box::new(NotifyContext {
            tx: Mutex::new(tx),
        }));
        let mut handles: [HANDLE; 3] = [std::ptr::null_mut(); 3];

        let ip_result = unsafe {
            NotifyIpInterfaceChange(
                AF_INET,
                Some(on_interface_change),
                context as *const core::ffi::c_void,
                0,
                &mut handles[0],
            )
        };
        let route_result = unsafe {
            NotifyRouteChange2(
                0,
                Some(on_route_change),
                context as *const core::ffi::c_void,
                0,
                &mut handles[1],
            )
        };
        if ip_result != 0 || route_result != 0 {
            for handle in handles.iter_mut() {
                if !handle.is_null() {
                    unsafe { CancelMibChangeNotify2(*handle) };
                    *handle = std::ptr::null_mut();
                }
            }
            unsafe { drop(Box::from_raw(context)) };
            let _ = ready_tx.send(Err(1));
            return;
        }

        let thread_id = unsafe { GetCurrentThreadId() };
        let _ = ready_tx.send(Ok(thread_id));

        let mut msg: MSG = unsafe { std::mem::zeroed() };
        loop {
            let result = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
            if result <= 0 {
                break;
            }
            if msg.message == WM_NET_CHANGE {
                let source = if msg.lParam == 0 {
                    NetworkChangeSource::Address
                } else {
                    NetworkChangeSource::Route
                };
                let context = unsafe { &*(msg.wParam as *const NotifyContext) };
                if let Ok(tx) = context.tx.lock() {
                    let _ = tx.send(source);
                }
            }
            if stop.load(Ordering::SeqCst) {
                let _ = unsafe { PostThreadMessageW(thread_id, WM_QUIT, 0, 0) };
            }
        }

        for handle in handles.iter_mut() {
            if !handle.is_null() {
                unsafe { CancelMibChangeNotify2(*handle) };
            }
        }
        unsafe { drop(Box::from_raw(context)) };
    }

    struct NotifyContext {
        tx: Mutex<Sender<NetworkChangeSource>>,
    }

    unsafe extern "system" fn on_interface_change(
        caller_context: *const core::ffi::c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        if notification_type == 3 {
            return; // MibInitialNotification
        }
        let context = unsafe { &*(caller_context as *const NotifyContext) };
        if let Ok(tx) = context.tx.lock() {
            let _ = tx.send(NetworkChangeSource::Address);
        }
        // The monitor thread is woken by the source channel timeout; the
        // message queue exists only to keep callbacks alive on this thread.
        let thread_id = CURRENT_THREAD_ID.load(Ordering::SeqCst);
        if thread_id != 0 {
            unsafe { PostThreadMessageW(thread_id, WM_NET_CHANGE, 0, 0) };
        }
    }

    unsafe extern "system" fn on_route_change(
        caller_context: *const core::ffi::c_void,
        _row: *const MIB_IPFORWARD_ROW2,
        notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        if notification_type == 3 {
            return;
        }
        let context = unsafe { &*(caller_context as *const NotifyContext) };
        if let Ok(tx) = context.tx.lock() {
            let _ = tx.send(NetworkChangeSource::Route);
        }
        let thread_id = CURRENT_THREAD_ID.load(Ordering::SeqCst);
        if thread_id != 0 {
            unsafe { PostThreadMessageW(thread_id, WM_NET_CHANGE, 0, 0) };
        }
    }

    static CURRENT_THREAD_ID: AtomicU32 = AtomicU32::new(0);

    pub(crate) struct WindowsSource {
        rx: Receiver<NetworkChangeSource>,
        thread_id: u32,
    }

    impl NetworkSource for WindowsSource {
        fn wait(&mut self, timeout: Duration) -> SourceEvent {
            CURRENT_THREAD_ID.store(self.thread_id, Ordering::SeqCst);
            match self.rx.recv_timeout(timeout) {
                Ok(kind) => SourceEvent::Change(kind),
                Err(RecvTimeoutError::Timeout) => SourceEvent::Timeout,
                Err(RecvTimeoutError::Disconnected) => SourceEvent::Shutdown,
            }
        }
    }

    struct WindowsWaker {
        thread_id: u32,
        stop: Arc<AtomicBool>,
    }

    impl NetworkWaker for WindowsWaker {
        fn wake(&self) {
            self.stop.store(true, Ordering::SeqCst);
            unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0) };
        }
    }
}
```

The implementer must adjust raw-signature details (`HANDLE` mutability, `MIB_NOTIFICATION_TYPE` comparison, `PostThreadMessageW` argument types) to the exact `windows-sys` 0.61 bindings; the compile step below is the gate. Keep the structure: register on a dedicated thread, push raw events into an `mpsc` channel, `wait` uses `recv_timeout`, `wake` posts `WM_QUIT`.

- [ ] **Step 4: Compile-check both targets**

Run on Linux: `cargo check -p zerodpi-platform && cargo test -p zerodpi-platform netmon -v`
Run on Windows (or cross): `cargo check -p zerodpi-platform --target x86_64-pc-windows-gnu`
Run the Windows test on Windows: `cargo test -p zerodpi-platform netmon::platform::windows_tests -v`
Expected: PASS on the host; Windows target compiles; Windows-only test passes on Windows.

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-platform/Cargo.toml crates/zerodpi-platform/src/netmon/platform.rs
git commit -m "feat(platform): add windows IP helper network change source"
```

---

### Task 5: `FlowController::reset` for stale flow cleanup

**Files:**
- Modify: `crates/zerodpi-core/src/flow.rs`
- Modify: `crates/zerodpi-core/src/low_ttl_discover.rs` (test `RecordingController`)
- Modify: `crates/zerodpi/src/helper_client.rs`
- Test: `crates/zerodpi-core/src/flow.rs` (inline)

**Interfaces:**
- Consumes: `FlowController` trait (existing), `BypassOutcome::UnexpectedClose` (existing).
- Produces: `FlowController::reset(&self)` — drops all flows and wakes waiters. Implemented by `LocalFlowController`, `RemoteHelperClient` (both cfg variants), and the test `RecordingController`.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/zerodpi-core/src/flow.rs`:

```rust
    #[tokio::test]
    async fn reset_finishes_and_drops_every_flow() {
        let controller = LocalFlowController::new(new_flow_table());
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 1234,
            dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            dst_port: 443,
        };
        let entry = controller
            .register_flow(key, vec![1], None)
            .await
            .unwrap();
        controller.reset();
        assert!(!controller.flow_exists(key));
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::UnexpectedClose)
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p zerodpi-core flow::tests::reset -v`
Expected: FAIL — `FlowController::reset` not found.

- [ ] **Step 3: Add the trait method and implementations**

In `crates/zerodpi-core/src/flow.rs`, add to the `FlowController` trait after `remove_flow`:

```rust
    /// Drop every tracked flow after the data plane was rebuilt for a new
    /// interface address. Implementations must wake flow waiters with
    /// [`BypassOutcome::UnexpectedClose`].
    fn reset(&self);
```

Add to `impl FlowController for LocalFlowController`:

```rust
    fn reset(&self) {
        for entry in self.flows.iter() {
            entry.value().finish(BypassOutcome::UnexpectedClose);
        }
        self.flows.clear();
    }
```

In `crates/zerodpi-core/src/low_ttl_discover.rs`, add to `impl FlowController for RecordingController`:

```rust
        fn reset(&self) {}
```

In `crates/zerodpi/src/helper_client.rs`, add to the Linux/Android `impl FlowController for RemoteHelperClient` (near `remove_flow`):

```rust
        fn reset(&self) {
            let mut flows = self.inner.flows.lock().expect("flows mutex poisoned");
            for entry in flows.values() {
                entry.finish(BypassOutcome::UnexpectedClose);
            }
            flows.clear();
            self.inner
                .flow_ids
                .lock()
                .expect("flow IDs mutex poisoned")
                .clear();
        }
```

Add to the non-Linux/Android stub impl:

```rust
    fn reset(&self) {}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core flow::tests -v && cargo check --workspace`
Expected: PASS, clean check (the stub impl is required for the workspace to compile on Windows).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/flow.rs crates/zerodpi-core/src/low_ttl_discover.rs crates/zerodpi/src/helper_client.rs
git commit -m "feat: reset stale flows after data plane rebuild"
```

---


### Task 6: Bounded upstream connect and honest relay end reasons

**Files:**
- Modify: `crates/zerodpi-core/src/proxy.rs`
- Modify: `crates/zerodpi/src/main.rs` (log arm only)
- Modify: `crates/zerodpi/src/tui.rs` (status mapping only)
- Test: `crates/zerodpi-core/src/proxy.rs` (inline)

**Interfaces:**
- Consumes: existing proxy connection handlers.
- Produces:
  - `RelayEndReason::NetworkError` variant.
  - `const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10)`.
  - `async fn connect_with_timeout<F>(Duration, F) -> anyhow::Result<TcpStream>` (private).
  - `copy_counting*` helpers return `(u64, bool)` (`bool` = ended on an I/O error).

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/zerodpi-core/src/proxy.rs`:

```rust
    #[tokio::test]
    async fn connect_timeout_fires_on_a_stalled_connect() {
        let pending = std::future::pending::<std::io::Result<TcpStream>>();
        let started = std::time::Instant::now();
        let error = connect_with_timeout(std::time::Duration::from_millis(50), pending)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(started.elapsed() >= std::time::Duration::from_millis(40));
    }

    #[test]
    fn io_error_is_not_clean_eof() {
        let error: std::io::Result<usize> = Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ));
        assert!(io_end_error(&error));
        assert!(!io_end_error(&Ok(0)));
        assert!(!io_end_error(&Ok(64)));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-core proxy::tests -v`
Expected: FAIL — `connect_with_timeout`, `io_end_error`, `RelayEndReason::NetworkError` not found.

- [ ] **Step 3: Implement the timeout helper**

In `crates/zerodpi-core/src/proxy.rs`, near `configured_relay_max_lifetime`, add:

```rust
/// Bound on a single upstream connect attempt. The TCP stack can otherwise
/// keep a SYN attempt alive for minutes while the network is down.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

async fn connect_with_timeout<F>(
    timeout: Duration,
    connect: F,
) -> anyhow::Result<TcpStream>
where
    F: std::future::Future<Output = std::io::Result<TcpStream>>,
{
    match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => anyhow::bail!("upstream connect timed out after {timeout:?}"),
    }
}

fn io_end_error(result: &std::io::Result<usize>) -> bool {
    matches!(result, Err(_))
}
```

Replace the three connect sites:

1. `handle_intercept_connection` upstream connect becomes:

```rust
    let mut outgoing = match connect_with_timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        socket.connect(SocketAddr::from((connect_ip, connect_port))),
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            entry.finish(BypassOutcome::UnexpectedClose);
            emit(
                &event_tx,
                ProxyEvent::ConnectionError {
                    src_port,
                    error: error.to_string(),
                },
            );
            return Err(error).context("connect upstream");
        }
    };
```

2. `handle_tcp_seg_connection_with_ip`:

```rust
    let mut outgoing = match connect_with_timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect(connect_addr),
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            emit(
                &event_tx,
                ProxyEvent::ConnectionError {
                    src_port,
                    error: error.to_string(),
                },
            );
            return Err(error).context("tls_frag: connect upstream");
        }
    };
```

3. `handle_ip_bypass_connection`:

```rust
    let outgoing = match connect_with_timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect(connect_addr),
    )
    .await
    {
        Ok(stream) => {
            emit(
                &event_tx,
                ProxyEvent::BypassComplete {
                    src_port,
                    outcome: crate::flow::BypassOutcome::FakeDataAcked,
                },
            );
            stream
        }
        Err(error) => {
            emit(
                &event_tx,
                ProxyEvent::ConnectionError {
                    src_port,
                    error: error.to_string(),
                },
            );
            return Err(error).context("ip_bypass: connect upstream");
        }
    };
```

- [ ] **Step 4: Add the relay reason variant and error propagation**

In `enum RelayEndReason`, add:

```rust
    /// A relay direction ended on an I/O error (for example, the network
    /// disappeared mid-session) rather than a clean close.
    NetworkError,
```

Change the two copy helpers to return `(u64, bool)`. `copy_counting_client_to_server`:

```rust
async fn copy_counting_client_to_server(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    counter: Arc<AtomicU64>,
    client_fragmentation: Option<(TcpSegmentation, u32)>,
) -> (u64, bool) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    let mut write_index = client_fragmentation.map(|(_, index)| index).unwrap_or(0);
    let segmentation = client_fragmentation.map(|(segmentation, _)| segmentation);

    loop {
        let read = reader.read(&mut buf).await;
        if io_end_error(&read) {
            let _ = writer.shutdown().await;
            return (total, true);
        }
        let n = match read {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };

        write_index = write_index.saturating_add(1);
        let write_result = if let Some(segmentation) = segmentation {
            write_client_data(&mut writer, &buf[..n], segmentation, write_index).await
        } else {
            writer.write_all(&buf[..n]).await.map_err(anyhow::Error::from)
        };

        if write_result.is_err() {
            let _ = writer.shutdown().await;
            return (total, true);
        }
        total += n as u64;
        counter.store(total, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
    (total, false)
}
```

`copy_counting`:

```rust
async fn copy_counting(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    counter: Arc<AtomicU64>,
) -> (u64, bool) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buf).await;
        if io_end_error(&read) {
            let _ = writer.shutdown().await;
            return (total, true);
        }
        let n = match read {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            let _ = writer.shutdown().await;
            return (total, true);
        }
        total += n as u64;
        counter.store(total, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
    (total, false)
}
```

In `counting_relay_with_client_fragmentation`, change the max-lifetime bookkeeping to `Option<(u64, bool)>` and classify the joined result:

```rust
    let result = if let Some(max_lifetime) = max_lifetime {
        let mut c2s_done: Option<(u64, bool)> = None;
        let mut s2c_done: Option<(u64, bool)> = None;
        let deadline = tokio::time::sleep(max_lifetime);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = &mut deadline => {
                    if c2s_done.is_none() {
                        c2s_task.abort();
                    }
                    if s2c_done.is_none() {
                        s2c_task.abort();
                    }
                    break RelayResult {
                        c2s_bytes: c2s_done.map(|(bytes, _)| bytes).unwrap_or_else(|| c2s_atomic.load(Ordering::Relaxed)),
                        s2c_bytes: s2c_done.map(|(bytes, _)| bytes).unwrap_or_else(|| s2c_atomic.load(Ordering::Relaxed)),
                        reason: RelayEndReason::MaxLifetime,
                    };
                }
                c2s_result = &mut c2s_task, if c2s_done.is_none() => {
                    c2s_done = Some(c2s_result.unwrap_or((0, false)));
                    if let (Some((c2s_bytes, c2s_err)), Some((s2c_bytes, s2c_err))) = (c2s_done, s2c_done) {
                        break RelayResult {
                            c2s_bytes,
                            s2c_bytes,
                            reason: if c2s_err || s2c_err { RelayEndReason::NetworkError } else { RelayEndReason::Completed },
                        };
                    }
                }
                s2c_result = &mut s2c_task, if s2c_done.is_none() => {
                    s2c_done = Some(s2c_result.unwrap_or((0, false)));
                    if let (Some((c2s_bytes, c2s_err)), Some((s2c_bytes, s2c_err))) = (c2s_done, s2c_done) {
                        break RelayResult {
                            c2s_bytes,
                            s2c_bytes,
                            reason: if c2s_err || s2c_err { RelayEndReason::NetworkError } else { RelayEndReason::Completed },
                        };
                    }
                }
            }
        }
    } else {
        let (c2s_result, s2c_result) = tokio::join!(c2s_task, s2c_task);
        let (c2s_bytes, c2s_err) = c2s_result.unwrap_or((0, false));
        let (s2c_bytes, s2c_err) = s2c_result.unwrap_or((0, false));
        RelayResult {
            c2s_bytes,
            s2c_bytes,
            reason: if c2s_err || s2c_err {
                RelayEndReason::NetworkError
            } else {
                RelayEndReason::Completed
            },
        }
    };
```

- [ ] **Step 5: Update exhaustive matches**

In `crates/zerodpi/src/tui.rs` (around the `RelayFinished` handler):

```rust
                    RelayEndReason::Completed => ConnStatus::Done,
                    RelayEndReason::MaxLifetime => ConnStatus::Rotated,
                    RelayEndReason::NetworkError => ConnStatus::Failed,
```

In `crates/zerodpi/src/main.rs` (the `RelayFinished` match in `log_headless_proxy_events`), add an arm that logs a warning, mirroring the `Completed` arm:

```rust
                RelayEndReason::NetworkError => {
                    warn!(src_port, c2s_bytes, s2c_bytes, "relay ended on a network error");
                }
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core proxy::tests -v && cargo test --workspace --no-run && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, no remaining `RelayEndReason` match errors.

- [ ] **Step 7: Commit**

```bash
git add crates/zerodpi-core/src/proxy.rs crates/zerodpi/src/main.rs crates/zerodpi/src/tui.rs
git commit -m "feat: bound upstream connects and classify relay network errors"
```

---

### Task 7: Single-candidate probe wrappers

**Files:**
- Modify: `crates/zerodpi-core/src/sni_scanner.rs`
- Modify: `crates/zerodpi-core/src/ip_scanner.rs`
- Test: both files (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: private `probe_sni_ip` (sni), private `probe_tls_ttfb`/`compute_score` (ip).
- Produces:
  - `zerodpi_core::sni_scanner::probe_sni_candidate(sni: &str, ip: Ipv4Addr, timeout: Duration, config: Arc<Config>) -> SniProbeEntry`.
  - `zerodpi_core::ip_scanner::probe_ip_candidate(ip: IpAddr, scan_sni: Arc<str>, timeout: Duration, config: Arc<Config>) -> IpProbeEntry`.

- [ ] **Step 1: Write the failing tests**

Add a `#[cfg(test)] mod candidate_tests` to `crates/zerodpi-core/src/sni_scanner.rs`:

```rust
#[cfg(test)]
mod candidate_tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn candidate_probe_returns_an_entry_for_a_closed_port() {
        let cfg = crate::config::tests::minimal_config();
        let entry = probe_sni_candidate(
            "example.com",
            "127.0.0.1".parse().unwrap(),
            std::time::Duration::from_millis(200),
            Arc::new(cfg),
        )
        .await;
        assert_eq!(entry.sni, "example.com");
        assert_eq!(entry.ip, "127.0.0.1".parse().unwrap());
    }
}
```

The probe connects to `127.0.0.1:443`, which CI/dev machines are not expected to serve; the identity assertions are deterministic either way and the test is primarily a no-panic/entry-shape check.

Add a helper to `crates/zerodpi-core/src/config.rs` tests:

```rust
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Minimal config used by scanner probe tests.
    pub(crate) fn minimal_config() -> Config {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"MODE = "sni_spoof"
BYPASS_METHOD = ["wrong_seq"]
"#,
        )
        .expect("write config");
        let cfg = Config::from_file(&path).expect("parse config");
        drop(dir);
        cfg
    }
}
```

Add a `#[cfg(test)] mod candidate_tests` to `crates/zerodpi-core/src/ip_scanner.rs`:

```rust
#[cfg(test)]
mod candidate_tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn candidate_probe_returns_an_entry_for_a_closed_port() {
        let cfg = crate::config::tests::minimal_config();
        let entry = probe_ip_candidate(
            "127.0.0.1".parse().unwrap(),
            Arc::from("example.com"),
            std::time::Duration::from_millis(200),
            Arc::new(cfg),
        )
        .await;
        assert_eq!(entry.ip, "127.0.0.1".parse().unwrap());
        assert!(!entry.tls_ok);
    }
}
```

This is deterministic when nothing listens on `127.0.0.1:443`; if something does, the assertion `!entry.tls_ok` may still hold only if the listener is not TLS. Keep the identity assertion as the primary check and drop the `tls_ok` assertion if the environment is unruly.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-core candidate_tests -v`
Expected: FAIL — `probe_sni_candidate` / `probe_ip_candidate` not found.

- [ ] **Step 3: Implement the wrappers**

In `crates/zerodpi-core/src/sni_scanner.rs`, after `probe_sni_ip`:

```rust
/// Probe one `(sni, ip)` pair without DNS resolution.
///
/// Used by network-recovery target verification.
pub async fn probe_sni_candidate(
    sni: &str,
    ip: Ipv4Addr,
    timeout: Duration,
    config: Arc<crate::config::Config>,
) -> SniProbeEntry {
    let connector = Arc::new(make_tls_connector());
    probe_sni_ip(sni.to_owned(), ip, timeout, config, connector).await
}
```

In `crates/zerodpi-core/src/ip_scanner.rs`, after `probe_tls_ttfb`:

```rust
/// Probe one IP without the full scan pipeline.
///
/// Used by network-recovery target verification.
pub async fn probe_ip_candidate(
    ip: IpAddr,
    scan_sni: Arc<str>,
    timeout: Duration,
    config: Arc<crate::config::Config>,
) -> IpProbeEntry {
    let addr = SocketAddr::new(ip, SCAN_PORT);
    let start = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => {
            let tcp_ms = start.elapsed().as_millis() as u64;
            probe_tls_ttfb(ip, tcp_ms, &scan_sni, timeout, config).await
        }
        _ => {
            let mut entry = IpProbeEntry {
                ip,
                tcp_latency_ms: None,
                tls_ok: false,
                tls_latency_ms: None,
                cert_valid: false,
                ttfb_ms: None,
                download_bps: None,
                upload_bps: None,
                http_status: None,
                score: 0,
            };
            entry.score = compute_score(&entry, &config);
            entry
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core candidate_tests -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/sni_scanner.rs crates/zerodpi-core/src/ip_scanner.rs crates/zerodpi-core/src/config.rs
git commit -m "feat(core): add single-candidate probe wrappers for recovery verification"
```

---

### Task 8: `DataPlane` trait and `DataPlaneController`

**Files:**
- Create: `crates/zerodpi/src/data_plane.rs`
- Modify: `crates/zerodpi/src/main.rs` (register module; move `InterceptorRuntime`, `stop_interceptor`, `spawn_interceptor_report`, `wait_for_interceptor_shutdown`, `INTERCEPTOR_SHUTDOWN_TIMEOUT` out when Task 12 lands)
- Modify: `crates/zerodpi/src/helper_client.rs` (`is_disconnected`)
- Test: `crates/zerodpi/src/data_plane.rs` (inline)

**Interfaces:**
- Consumes: `FlowController::reset` (Task 5), `Handler`, `BypassMethod`, `DefaultInterceptor`, `interceptor_config`, `RemoteHelperClient`.
- Produces:
  - `data_plane::BoxFuture<'a, T>`.
  - `data_plane::DataPlane` trait with `rebuild`, `stop`, `remote_disconnected`, `wait_fatal`.
  - `data_plane::DataPlaneController` with `local(cfg, flows, method) -> Result<Self>`, `remote(cfg, helper, flow_controller, interface_ip).await -> Result<Self>`, `none() -> Self`; implements `DataPlane`.
  - `data_plane::interceptor_filter(cfg, interface_ip) -> FilterSpec` (pure, tested).
  - `RemoteHelperClient::is_disconnected() -> bool`.

- [ ] **Step 1: Write the failing test**

Create `crates/zerodpi/src/data_plane.rs` with the test first:

```rust
#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn interceptor_filter_matches_the_legacy_shape() {
        let cfg = Arc::new(crate::config_for_tests());
        let filter = interceptor_filter(&cfg, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(filter.interface_ip, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(filter.remote_ip, None);
        assert_eq!(filter.remote_port, zerodpi_core::proxy::CONNECT_PORT);
        assert_eq!(filter.queue_num, cfg.NFQUEUE_NUM);
        assert_eq!(filter.firewall_owner, None);
    }

    #[tokio::test]
    async fn none_plane_rebuild_and_stop_are_noops() {
        let plane = DataPlaneController::none();
        plane.rebuild(Ipv4Addr::LOCALHOST).await.unwrap();
        plane.stop().await.unwrap();
        assert!(!plane.remote_disconnected());
    }
}
```

Add a test-only config constructor in `crates/zerodpi/src/main.rs`:

```rust
#[cfg(test)]
fn config_for_tests() -> Config {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        r#"MODE = "sni_spoof"
BYPASS_METHOD = ["wrong_seq"]
"#,
    )
    .expect("write config");
    let cfg = Config::from_file(&path).expect("parse config");
    drop(dir);
    cfg
}
```

Add to `[dev-dependencies]` in `crates/zerodpi/Cargo.toml`:

```toml
tempfile.workspace = true
tokio = { workspace = true, features = ["test-util"] }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p zerodpi data_plane::tests -v`
Expected: FAIL — module `data_plane` does not exist.

- [ ] **Step 3: Implement the controller**

Prepend to `crates/zerodpi/src/data_plane.rs`:

```rust
//! Ownership and in-place rebuild of the live packet-interception plane.

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{oneshot, Mutex};
use tracing::{error, info};

use zerodpi_core::config::Config;
use zerodpi_core::flow::{FlowController, FlowTable, LocalFlowController};
use zerodpi_core::handler::Handler;
use zerodpi_core::interceptor::{FilterSpec, InterceptorShutdown, PacketInterceptor};
use zerodpi_core::methods::BypassMethod;
use zerodpi_core::proxy::CONNECT_PORT;
use zerodpi_platform::DefaultInterceptor;

use crate::helper_client::{interceptor_config, RemoteHelperClient};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A live data plane that can be rebuilt for a new interface address.
pub trait DataPlane: Send + Sync {
    fn rebuild<'a>(&'a self, interface_ip: Ipv4Addr) -> BoxFuture<'a, Result<()>>;
    fn stop<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
    /// True when the remote root helper is gone and no rebuild can succeed.
    fn remote_disconnected(&self) -> bool {
        false
    }
    /// Resolves with a fatal reason when the plane can never recover.
    /// Default planes wait forever.
    fn wait_fatal(&self) -> BoxFuture<'static, String> {
        Box::pin(std::future::pending())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
const INTERCEPTOR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the local filter used by every intercept mode.
pub fn interceptor_filter(cfg: &Config, interface_ip: Ipv4Addr) -> FilterSpec {
    FilterSpec {
        interface_ip,
        remote_ip: None,
        remote_port: CONNECT_PORT,
        queue_num: cfg.NFQUEUE_NUM,
        linux_firewall_backend: cfg.linux_firewall_backend(),
        firewall_owner: None,
    }
}

enum Inner {
    Local(LocalPlane),
    Remote(RemotePlane),
    None,
}

struct LocalPlane {
    cfg: Arc<Config>,
    flows: FlowTable,
    flow_controller: Arc<dyn FlowController>,
    method: Arc<dyn BypassMethod>,
    shutdown: Option<InterceptorShutdown>,
    done_rx: Option<oneshot::Receiver<Result<()>>>,
}

struct RemotePlane {
    cfg: Arc<Config>,
    helper: RemoteHelperClient,
    flow_controller: Arc<dyn FlowController>,
}

/// Owns the live interceptor and rebuilds it for a new address.
pub struct DataPlaneController {
    inner: Mutex<Inner>,
    remote_helper: Option<RemoteHelperClient>,
}

impl DataPlaneController {
    /// Open a local interceptor immediately.
    pub fn local(
        cfg: Arc<Config>,
        flows: FlowTable,
        method: Arc<dyn BypassMethod>,
        interface_ip: Ipv4Addr,
    ) -> Result<Self> {
        let flow_controller: Arc<dyn FlowController> =
            Arc::new(LocalFlowController::new(flows.clone()));
        let mut plane = LocalPlane {
            cfg,
            flows,
            flow_controller,
            method,
            shutdown: None,
            done_rx: None,
        };
        plane.open(interface_ip)?;
        Ok(Self {
            inner: Mutex::new(Inner::Local(plane)),
            remote_helper: None,
        })
    }

    /// Configure and open the root-helper interceptor immediately.
    pub async fn remote(
        cfg: Arc<Config>,
        helper: RemoteHelperClient,
        flow_controller: Arc<dyn FlowController>,
        interface_ip: Ipv4Addr,
    ) -> Result<Self> {
        helper
            .configure(interceptor_config(&cfg, interface_ip, None, CONNECT_PORT))
            .await
            .context("configure root helper interceptor")?;
        helper.open().await.context("open root helper interceptor")?;
        Ok(Self {
            inner: Mutex::new(Inner::Remote(RemotePlane {
                cfg,
                helper: helper.clone(),
                flow_controller,
            })),
            remote_helper: Some(helper),
        })
    }

    /// A plane for modes without interception (`ip_bypass`, socket-only).
    pub fn none() -> Self {
        Self {
            inner: Mutex::new(Inner::None),
            remote_helper: None,
        }
    }
}

impl DataPlane for DataPlaneController {
    fn rebuild<'a>(&'a self, interface_ip: Ipv4Addr) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut inner = self.inner.lock().await;
            match &mut *inner {
                Inner::Local(plane) => {
                    stop_local(plane).await?;
                    plane.flow_controller.reset();
                    plane.open(interface_ip)?;
                    Ok(())
                }
                Inner::Remote(plane) => {
                    plane.helper.close().await.context("close root helper interceptor")?;
                    plane.flow_controller.reset();
                    plane
                        .helper
                        .configure(interceptor_config(
                            &plane.cfg,
                            interface_ip,
                            None,
                            CONNECT_PORT,
                        ))
                        .await
                        .context("reconfigure root helper interceptor")?;
                    plane.helper.open().await.context("reopen root helper interceptor")
                }
                Inner::None => Ok(()),
            }
        })
    }

    fn stop<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut inner = self.inner.lock().await;
            match &mut *inner {
                Inner::Local(plane) => stop_local(plane).await,
                Inner::Remote(plane) => {
                    plane.helper.close().await?;
                    plane.helper.shutdown().await
                }
                Inner::None => Ok(()),
            }
        })
    }

    fn remote_disconnected(&self) -> bool {
        self.remote_helper
            .as_ref()
            .map(RemoteHelperClient::is_disconnected)
            .unwrap_or(false)
    }

    fn wait_fatal(&self) -> BoxFuture<'static, String> {
        match self.remote_helper.clone() {
            Some(helper) => Box::pin(async move {
                helper.wait_disconnected().await;
                "root helper disconnected while interception was active".to_owned()
            }),
            None => Box::pin(std::future::pending()),
        }
    }
}

impl LocalPlane {
    fn open(&mut self, interface_ip: Ipv4Addr) -> Result<()> {
        let filter = interceptor_filter(&self.cfg, interface_ip);
        let interceptor =
            DefaultInterceptor::open(filter).context("open packet interceptor")?;
        let handler = Handler::new(self.flows.clone(), self.method.clone());
        let (done_tx, done_rx) = oneshot::channel();
        let shutdown = InterceptorShutdown::default();
        let thread_shutdown = shutdown.clone();
        std::thread::Builder::new()
            .name("zerodpi-intercept".into())
            .spawn(move || {
                let result = interceptor.run_until(handler, thread_shutdown);
                if let Err(ref error) = result {
                    error!(%error, "intercept loop ended with error");
                }
                let _ = done_tx.send(result);
            })
            .context("spawn intercept thread")?;
        self.shutdown = Some(shutdown);
        self.done_rx = Some(done_rx);
        info!(%interface_ip, "packet interceptor rebuilt");
        Ok(())
    }
}

async fn stop_local(plane: &mut LocalPlane) -> Result<()> {
    if let Some(shutdown) = plane.shutdown.take() {
        shutdown.request();
    }
    if let Some(done_rx) = plane.done_rx.take() {
        let mut report_rx = spawn_interceptor_report(done_rx);
        wait_for_interceptor_shutdown(&mut report_rx).await?;
    }
    Ok(())
}

fn spawn_interceptor_report(
    done_rx: oneshot::Receiver<Result<()>>,
) -> tokio::sync::mpsc::UnboundedReceiver<Result<()>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let result = match done_rx.await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "packet interceptor thread stopped before reporting a result"
            )),
        };
        let _ = tx.send(result);
    });
    rx
}

#[cfg(any(target_os = "linux", target_os = "android"))]
async fn wait_for_interceptor_shutdown(
    report_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Result<()>>,
) -> Result<()> {
    match tokio::time::timeout(INTERCEPTOR_SHUTDOWN_TIMEOUT, report_rx.recv()).await {
        Ok(Some(Ok(()))) => Ok(()),
        Ok(Some(Err(error))) => Err(error.context("packet interceptor stopped during shutdown")),
        Ok(None) => Err(anyhow::anyhow!(
            "packet interceptor thread stopped before reporting a result"
        )),
        Err(_) => Err(anyhow::anyhow!(
            "packet interceptor did not stop within {} seconds",
            INTERCEPTOR_SHUTDOWN_TIMEOUT.as_secs()
        )),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
async fn wait_for_interceptor_shutdown(
    report_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Result<()>>,
) -> Result<()> {
    let _ = tokio::time::timeout(Duration::from_millis(100), report_rx.recv()).await;
    Ok(())
}
```

`DefaultInterceptor::open` only exists with the `packet-interception` feature. Guard `LocalPlane::open` with `#[cfg(feature = "packet-interception")]` and provide a fallback implementation that returns `anyhow::bail!("packet interception is not compiled in")`. Keep `DataPlaneController::local` compiling either way.

- [ ] **Step 4: Add `RemoteHelperClient::is_disconnected`**

In `crates/zerodpi/src/helper_client.rs`, Linux/Android impl:

```rust
        pub fn is_disconnected(&self) -> bool {
            self.inner.disconnected.load(Ordering::SeqCst)
        }
```

Non-Linux/Android stub impl:

```rust
    pub fn is_disconnected(&self) -> bool {
        false
    }
```

- [ ] **Step 5: Register the module**

In `crates/zerodpi/src/main.rs`, add `mod data_plane;` next to the other module declarations. Leave the old `InterceptorRuntime` code in place for now; Task 12 moves the call sites and deletes it.

- [ ] **Step 6: Run the tests**

Run: `cargo test -p zerodpi data_plane::tests -v && cargo check --workspace`
Expected: PASS for both new tests; the workspace still compiles with the old `InterceptorRuntime` code present.

- [ ] **Step 7: Commit**

```bash
git add crates/zerodpi/src/data_plane.rs crates/zerodpi/src/helper_client.rs crates/zerodpi/src/main.rs crates/zerodpi/Cargo.toml
git commit -m "feat: add DataPlane controller with in-place rebuild"
```

---

### Task 9: `RecoveryCoordinator` policy

**Files:**
- Create: `crates/zerodpi/src/network_recovery.rs`
- Modify: `crates/zerodpi/src/main.rs` (register module)
- Test: `crates/zerodpi/src/network_recovery.rs` (inline)

**Interfaces:**
- Consumes: `zerodpi_platform::netmon::NetworkEvent` (Tasks 2–4), `DataPlane` (Task 8).
- Produces:
  - `network_recovery::NetworkStatus` (five variants).
  - `network_recovery::RescanOutcome { found: usize, switched: bool }`.
  - `network_recovery::RecoveryEnv` trait.
  - `network_recovery::RecoveryCoordinator<E: RecoveryEnv>::new(env, probe_target, auto_select, initial) -> Self` and `run(rx)`.
  - Constants `SETTLE`, `POLL_INTERVAL`, `BACKOFF_INITIAL`, `BACKOFF_MAX`, `RECOVERY_RESCAN_MIN_INTERVAL`.

- [ ] **Step 1: Write the failing tests**

Create `crates/zerodpi/src/network_recovery.rs` with the tests first:

```rust
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use zerodpi_core::net::NetworkChangeSource;

    use super::*;

    #[derive(Default)]
    struct FakeEnv {
        probe_result: Mutex<anyhow::Result<Ipv4Addr>>,
        probe_calls: AtomicUsize,
        fail_rebuilds: AtomicUsize,
        rebuilds: Mutex<Vec<Ipv4Addr>>,
        verify_ok: AtomicBool,
        rescans: AtomicUsize,
        rescan_switched: AtomicBool,
        statuses: Mutex<Vec<NetworkStatus>>,
        applied: Mutex<Vec<Ipv4Addr>>,
        disconnected: AtomicBool,
    }

    impl FakeEnv {
        fn arc() -> Arc<Self> {
            Arc::new(Self {
                probe_result: Mutex::new(Ok(Ipv4Addr::new(10, 0, 0, 2))),
                verify_ok: AtomicBool::new(true),
                ..Default::default()
            })
        }

        fn statuses(&self) -> Vec<NetworkStatus> {
            self.statuses.lock().unwrap().clone()
        }
    }

    impl RecoveryEnv for FakeEnv {
        fn probe(&self, _target: Ipv4Addr) -> anyhow::Result<Ipv4Addr> {
            self.probe_calls.fetch_add(1, Ordering::SeqCst);
            match &*self.probe_result.lock().unwrap() {
                Ok(ip) => Ok(*ip),
                Err(error) => Err(anyhow::anyhow!("{error}")),
            }
        }

        fn rebuild<'a>(&'a self, interface_ip: Ipv4Addr) -> BoxFuture<'a, anyhow::Result<()>> {
            Box::pin(async move {
                self.rebuilds.lock().unwrap().push(interface_ip);
                if self.fail_rebuilds.load(Ordering::SeqCst) > 0 {
                    self.fail_rebuilds.fetch_sub(1, Ordering::SeqCst);
                    anyhow::bail!("rebuild failed");
                }
                Ok(())
            })
        }

        fn verify<'a>(&'a self) -> BoxFuture<'a, bool> {
            Box::pin(async move { self.verify_ok.load(Ordering::SeqCst) })
        }

        fn rescan<'a>(&'a self) -> BoxFuture<'a, RescanOutcome> {
            Box::pin(async move {
                self.rescans.fetch_add(1, Ordering::SeqCst);
                RescanOutcome {
                    found: 1,
                    switched: self.rescan_switched.load(Ordering::SeqCst),
                }
            })
        }

        fn apply_interface_ip(&self, interface_ip: Ipv4Addr) {
            self.applied.lock().unwrap().push(interface_ip);
        }

        fn remote_disconnected(&self) -> bool {
            self.disconnected.load(Ordering::SeqCst)
        }

        fn publish(&self, status: NetworkStatus) {
            self.statuses.lock().unwrap().push(status);
        }
    }

    fn event() -> NetworkEvent {
        NetworkEvent::Changed {
            source: NetworkChangeSource::Address,
        }
    }

    fn probe_target() -> Arc<AtomicU32> {
        Arc::new(AtomicU32::new(u32::from(Ipv4Addr::new(1, 1, 1, 1))))
    }

    async fn run_once(coordinator: RecoveryCoordinator<FakeEnv>, rx: &mut broadcast::Receiver<NetworkEvent>) {
        coordinator.handle_change(rx).await;
    }

    #[tokio::test(start_paused = true)]
    async fn rebuilds_when_interface_changes() {
        let env = FakeEnv::arc();
        let mut rx = broadcast::channel(8).1;
        let coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(coordinator, &mut rx).await;
        assert_eq!(
            env.rebuilds.lock().unwrap().as_slice(),
            &[Ipv4Addr::new(10, 0, 0, 2)]
        );
        assert_eq!(
            env.applied.lock().unwrap().as_slice(),
            &[Ipv4Addr::new(10, 0, 0, 2)]
        );
        assert!(env.statuses().iter().any(|status| matches!(
            status,
            NetworkStatus::Recovered {
                target_verified: true,
                target_switched: false,
                ..
            }
        )));
    }

    #[tokio::test(start_paused = true)]
    async fn ignores_unchanged_address() {
        let env = FakeEnv::arc();
        *env.probe_result.lock().unwrap() = Ok(Ipv4Addr::new(10, 0, 0, 1));
        let mut rx = broadcast::channel(8).1;
        let coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(coordinator, &mut rx).await;
        assert!(env.rebuilds.lock().unwrap().is_empty());
        assert!(matches!(env.statuses().last(), Some(NetworkStatus::Online { .. })));
    }

    #[tokio::test(start_paused = true)]
    async fn marks_unavailable_when_probe_fails() {
        let env = FakeEnv::arc();
        *env.probe_result.lock().unwrap() = Err(anyhow::anyhow!("no route"));
        let mut rx = broadcast::channel(8).1;
        let coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(coordinator, &mut rx).await;
        assert!(env.rebuilds.lock().unwrap().is_empty());
        assert!(matches!(
            env.statuses().last(),
            Some(NetworkStatus::Unavailable { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn retries_rebuild_with_backoff_until_success() {
        let env = FakeEnv::arc();
        env.fail_rebuilds.store(2, Ordering::SeqCst);
        let mut rx = broadcast::channel(8).1;
        let coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(coordinator, &mut rx).await;
        assert_eq!(env.rebuilds.lock().unwrap().len(), 3);
        let retries: Vec<u64> = env
            .statuses()
            .iter()
            .filter_map(|status| match status {
                NetworkStatus::Recovering { next_retry_ms, .. } => Some(*next_retry_ms),
                _ => None,
            })
            .collect();
        assert_eq!(retries, vec![1_000, 2_000]);
        assert!(env
            .statuses()
            .iter()
            .any(|status| matches!(status, NetworkStatus::Recovered { .. })));
    }

    #[tokio::test(start_paused = true)]
    async fn rescan_is_gated_and_rate_limited() {
        let env = FakeEnv::arc();
        env.verify_ok.store(false, Ordering::SeqCst);
        let mut rx = broadcast::channel(8).1;
        let coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(coordinator, &mut rx).await;
        assert_eq!(env.rescans.load(Ordering::SeqCst), 1);

        *env.probe_result.lock().unwrap() = Ok(Ipv4Addr::new(10, 0, 0, 3));
        run_once(coordinator, &mut rx).await;
        assert_eq!(env.rescans.load(Ordering::SeqCst), 1, "rate limit must hold");

        let env = FakeEnv::arc();
        env.verify_ok.store(false, Ordering::SeqCst);
        let mut rx = broadcast::channel(8).1;
        let coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            false,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(coordinator, &mut rx).await;
        assert_eq!(env.rescans.load(Ordering::SeqCst), 0, "pinned mode never scans");
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_event_resets_the_backoff() {
        let env = FakeEnv::arc();
        env.fail_rebuilds.store(10, Ordering::SeqCst);
        let (tx, mut rx) = broadcast::channel(8);
        let coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        tokio::spawn(async move {
            coordinator.handle_change(&mut rx).await;
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(500)).await;
        tx.send(event()).unwrap();
        tokio::task::yield_now().await;
        assert!(env.rebuilds.lock().unwrap().len() >= 2);
        let last_retry = env
            .statuses()
            .iter()
            .rev()
            .find_map(|status| match status {
                NetworkStatus::Recovering { next_retry_ms, .. } => Some(*next_retry_ms),
                _ => None,
            })
            .expect("retry status");
        assert_eq!(last_retry, 1_000, "backoff must reset after a new event");
    }

    #[tokio::test(start_paused = true)]
    async fn a_disconnected_helper_stops_recovery() {
        let env = FakeEnv::arc();
        env.disconnected.store(true, Ordering::SeqCst);
        let mut rx = broadcast::channel(8).1;
        let coordinator = RecoveryCoordinator::new(
            env.clone(),
            probe_target(),
            true,
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        );
        run_once(coordinator, &mut rx).await;
        assert!(env.rebuilds.lock().unwrap().is_empty());
        assert!(matches!(
            env.statuses().last(),
            Some(NetworkStatus::Unavailable { .. })
        ));
    }
}
```

`tokio`'s `test-util` feature is added in Task 8; `start_paused` needs it.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi network_recovery::tests -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the coordinator**

Prepend the implementation:

```rust
//! In-place network recovery policy.
//!
//! The coordinator reacts to settled network changes, rebuilds the data plane
//! with the new interface address, verifies the active target, and only then
//! asks for a rescan when the selection policy allows it.

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;

use zerodpi_platform::netmon::NetworkEvent;

/// Settle window handed to `NetworkMonitor::start`.
pub const SETTLE: Duration = Duration::from_secs(1);
/// Poll safety-net interval handed to `NetworkMonitor::start`.
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
pub const RECOVERY_RESCAN_MIN_INTERVAL: Duration = Duration::from_secs(60);

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One status update produced by recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkStatus {
    Online {
        interface_ip: Ipv4Addr,
    },
    Unavailable {
        message: String,
    },
    Changing {
        interface_ip: Ipv4Addr,
    },
    Recovering {
        attempt: u32,
        next_retry_ms: u64,
        message: String,
    },
    Recovered {
        interface_ip: Ipv4Addr,
        target_verified: bool,
        target_switched: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RescanOutcome {
    pub found: usize,
    pub switched: bool,
}

/// Everything the coordinator needs from the running mode.
pub trait RecoveryEnv: Send + Sync + 'static {
    /// Probe the canonical interface address for `target`.
    fn probe(&self, target: Ipv4Addr) -> anyhow::Result<Ipv4Addr>;
    fn rebuild<'a>(&'a self, interface_ip: Ipv4Addr) -> BoxFuture<'a, anyhow::Result<()>>;
    fn verify<'a>(&'a self) -> BoxFuture<'a, bool>;
    fn rescan<'a>(&'a self) -> BoxFuture<'a, RescanOutcome>;
    fn apply_interface_ip(&self, interface_ip: Ipv4Addr);
    fn remote_disconnected(&self) -> bool {
        false
    }
    fn publish(&self, status: NetworkStatus);
}

pub struct RecoveryCoordinator<E: RecoveryEnv> {
    env: Arc<E>,
    probe_target: Arc<AtomicU32>,
    auto_select: bool,
    current: Option<Ipv4Addr>,
    last_rescan: Option<tokio::time::Instant>,
}

impl<E: RecoveryEnv> RecoveryCoordinator<E> {
    pub fn new(
        env: Arc<E>,
        probe_target: Arc<AtomicU32>,
        auto_select: bool,
        initial: Option<Ipv4Addr>,
    ) -> Self {
        Self {
            env,
            probe_target,
            auto_select,
            current: initial,
            last_rescan: None,
        }
    }

    /// Run until the monitor channel closes.
    pub async fn run(mut self, mut rx: broadcast::Receiver<NetworkEvent>) {
        if let Some(interface_ip) = self.current {
            self.env.publish(NetworkStatus::Online { interface_ip });
        }
        loop {
            match rx.recv().await {
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
            self.handle_change(&mut rx).await;
        }
    }

    /// Process one settled change until a stable outcome is published.
    pub(crate) async fn handle_change(&mut self, rx: &mut broadcast::Receiver<NetworkEvent>) {
        loop {
            if self.env.remote_disconnected() {
                self.current = None;
                self.env.publish(NetworkStatus::Unavailable {
                    message: "root helper disconnected".to_owned(),
                });
                return;
            }
            let target = match self.probe_target.load(Ordering::SeqCst) {
                0 => {
                    self.env.publish(NetworkStatus::Unavailable {
                        message: "no active target to probe".to_owned(),
                    });
                    return;
                }
                raw => Ipv4Addr::from(raw),
            };
            match self.env.probe(target) {
                Err(error) => {
                    self.current = None;
                    self.env.publish(NetworkStatus::Unavailable {
                        message: error.to_string(),
                    });
                    return;
                }
                Ok(ip) if Some(ip) == self.current => {
                    self.env.publish(NetworkStatus::Online { interface_ip: ip });
                    return;
                }
                Ok(ip) => {
                    self.env.publish(NetworkStatus::Changing { interface_ip: ip });
                    if !self.rebuild_with_retry(ip, rx).await {
                        continue;
                    }
                    self.current = Some(ip);
                    self.env.apply_interface_ip(ip);
                    let target_verified = self.env.verify().await;
                    let mut target_switched = false;
                    if !target_verified && self.auto_select && self.rescan_allowed() {
                        let outcome = self.env.rescan().await;
                        target_switched = outcome.switched;
                        self.last_rescan = Some(tokio::time::Instant::now());
                        if outcome.found == 0 {
                            self.env.publish(NetworkStatus::Unavailable {
                                message: "recovery rescan found no reachable target".to_owned(),
                            });
                        }
                    }
                    self.env.publish(NetworkStatus::Recovered {
                        interface_ip: ip,
                        target_verified,
                        target_switched,
                    });
                    return;
                }
            }
        }
    }

    /// Rebuild once, then retry with exponential backoff. Returns `false`
    /// when a newer network event arrived and the caller should re-probe.
    async fn rebuild_with_retry(
        &mut self,
        interface_ip: Ipv4Addr,
        rx: &mut broadcast::Receiver<NetworkEvent>,
    ) -> bool {
        let mut delay = BACKOFF_INITIAL;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match self.env.rebuild(interface_ip).await {
                Ok(()) => return true,
                Err(error) => {
                    self.env.publish(NetworkStatus::Recovering {
                        attempt,
                        next_retry_ms: delay.as_millis() as u64,
                        message: error.to_string(),
                    });
                    let newer_event = tokio::select! {
                        _ = tokio::time::sleep(delay) => false,
                        received = rx.recv() => !matches!(
                            received,
                            Err(broadcast::error::RecvError::Closed)
                        ),
                    };
                    if newer_event {
                        return false;
                    }
                    delay = (delay * 2).min(BACKOFF_MAX);
                }
            }
        }
    }

    fn rescan_allowed(&self) -> bool {
        match self.last_rescan {
            None => true,
            Some(at) => at.elapsed() >= RECOVERY_RESCAN_MIN_INTERVAL,
        }
    }
}
```

Register the module in `crates/zerodpi/src/main.rs`: `mod network_recovery;`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p zerodpi network_recovery::tests -v`
Expected: PASS (7 tests). If `a_new_event_resets_the_backoff` proves timing-sensitive, keep the coverage by testing `rebuild_with_retry` directly with a scripted receiver; do not delete the test.

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi/src/network_recovery.rs crates/zerodpi/src/main.rs
git commit -m "feat: add network recovery coordinator policy"
```

---

### Task 10: Runtime events, `ProxyEvent::NetworkStatus`, TUI status line

**Files:**
- Modify: `crates/zerodpi/src/runtime_events.rs`
- Modify: `crates/zerodpi-core/src/proxy.rs` (`NetworkStatus` + `ProxyEvent` variant)
- Modify: `crates/zerodpi/src/tui.rs`
- Test: `crates/zerodpi/src/runtime_events.rs` (inline)

**Interfaces:**
- Consumes: `zerodpi_core::net::NetworkChangeSource` (Task 1); `network_recovery::NetworkStatus` (Task 9, mapped by the wiring tasks).
- Produces:
  - `RuntimeEvent::{NetworkUnavailable, NetworkChanged, NetworkRecoveryFailed, NetworkRecovered}`.
  - `zerodpi_core::proxy::NetworkStatus` UI enum and `ProxyEvent::NetworkStatus { status }`.
  - TUI header network line.

- [ ] **Step 1: Write the failing serialization tests**

Add to `crates/zerodpi/src/runtime_events.rs` tests:

```rust
    #[test]
    fn serializes_network_unavailable() {
        let json = serde_json::to_string(&RuntimeEvent::NetworkUnavailable {
            message: "no route".to_owned(),
        })
        .unwrap();
        assert_eq!(json, r#"{"event":"network_unavailable","message":"no route"}"#);
    }

    #[test]
    fn serializes_network_changed() {
        let json = serde_json::to_string(&RuntimeEvent::NetworkChanged {
            source: zerodpi_core::net::NetworkChangeSource::Address,
            interface_ip: "192.0.2.10".to_owned(),
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"event":"network_changed","source":"address","interface_ip":"192.0.2.10"}"#
        );
    }

    #[test]
    fn serializes_network_recovery_failed() {
        let json = serde_json::to_string(&RuntimeEvent::NetworkRecoveryFailed {
            attempt: 2,
            next_retry_ms: 4_000,
            message: "open packet interceptor".to_owned(),
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"event":"network_recovery_failed","attempt":2,"next_retry_ms":4000,"message":"open packet interceptor"}"#
        );
    }

    #[test]
    fn serializes_network_recovered() {
        let json = serde_json::to_string(&RuntimeEvent::NetworkRecovered {
            interface_ip: "192.0.2.10".to_owned(),
            target_verified: true,
            target_switched: false,
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"event":"network_recovered","interface_ip":"192.0.2.10","target_verified":true,"target_switched":false}"#
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi runtime_events::tests -v`
Expected: FAIL — variants not found.

- [ ] **Step 3: Add the runtime events**

In `enum RuntimeEvent`, before `FatalError`:

```rust
    NetworkUnavailable {
        message: String,
    },
    NetworkChanged {
        source: zerodpi_core::net::NetworkChangeSource,
        interface_ip: String,
    },
    NetworkRecoveryFailed {
        attempt: u32,
        next_retry_ms: u64,
        message: String,
    },
    NetworkRecovered {
        interface_ip: String,
        target_verified: bool,
        target_switched: bool,
    },
```

- [ ] **Step 4: Add the UI proxy event**

In `crates/zerodpi-core/src/proxy.rs`, near `ProxyEvent`:

```rust
/// Dashboard-facing network recovery state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkStatus {
    Online { interface_ip: Ipv4Addr },
    Recovering { attempt: u32 },
    Unavailable { message: String },
}
```

Add to `enum ProxyEvent`:

```rust
    /// Network recovery status for the dashboard.
    NetworkStatus { status: NetworkStatus },
```

- [ ] **Step 5: Render the status line**

In `crates/zerodpi/src/tui.rs`:

1. Add to `DashboardState` near `last_error`:

```rust
    /// Most recent network recovery status, shown as a header line.
    network_status: Option<String>,
```

2. Initialize `network_status: None` everywhere `DashboardState` is constructed (`rg -n "last_error:" crates/zerodpi/src/tui.rs` lists the sites, including tests).

3. Handle the event next to `ProxyEvent::ConnectionError`:

```rust
        ProxyEvent::NetworkStatus { status } => {
            state.network_status = Some(match status {
                zerodpi_core::proxy::NetworkStatus::Online { interface_ip } => {
                    format!("Network: {interface_ip}")
                }
                zerodpi_core::proxy::NetworkStatus::Recovering { attempt } => {
                    format!("Network: recovering (attempt {attempt})")
                }
                zerodpi_core::proxy::NetworkStatus::Unavailable { message } => {
                    format!("Network: unavailable ({message})")
                }
            });
        }
```

4. Count the line in `header_content_rows`:

```rust
fn header_content_rows(state: &DashboardState, now: Instant) -> usize {
    2 + usize::from(rescan_status_line(state, now).is_some())
        + usize::from(state.network_status.is_some())
        + usize::from(state.last_error.is_some())
}
```

5. Push the line in the header builder, immediately before the `last_error` block:

```rust
        if let Some(status) = &state.network_status {
            header_lines.push(Line::from(vec![
                Span::styled(
                    "Network: ",
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Span::styled(status.clone(), label_style()),
            ]));
        }
```

Check the existing header builder for the exact variable name (`header_lines`) and adapt if it differs.

- [ ] **Step 6: Run the tests**

Run: `cargo test -p zerodpi runtime_events::tests -v && cargo check --workspace && cargo test -p zerodpi tui -v`
Expected: PASS; TUI tests that construct `DashboardState` compile after the new field.

- [ ] **Step 7: Commit**

```bash
git add crates/zerodpi/src/runtime_events.rs crates/zerodpi-core/src/proxy.rs crates/zerodpi/src/tui.rs
git commit -m "feat: add network recovery runtime events and TUI status"
```

---

### Task 11: Extract one-shot rescan helpers

**Files:**
- Modify: `crates/zerodpi/src/main.rs`
- Test: `crates/zerodpi/src/main.rs` (inline)

**Interfaces:**
- Consumes: `network_recovery::RescanOutcome` (Task 9), existing `scan_sni_list`, `scan_ip_list`, `select_rescan_target`, `IpRescanPolicy`.
- Produces:
  - `async fn rescan_sni_once(cfg: Arc<Config>, path: PathBuf, rescan_discovery: Option<LowTtlDiscoveryState>, active_target: Arc<std::sync::RwLock<ActiveSniTarget>>, event_tx: Option<ProxyEventSender>, events: RuntimeEventEmitter, headless: bool) -> RescanOutcome`
  - `async fn rescan_ip_once(cfg: Arc<Config>, path: PathBuf, active_ip: Arc<std::sync::RwLock<std::net::IpAddr>>, event_tx: Option<ProxyEventSender>, events: RuntimeEventEmitter, headless: bool, policy: IpRescanPolicy) -> RescanOutcome`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/zerodpi/src/main.rs`:

```rust
    #[tokio::test]
    async fn rescan_sni_once_reports_failure_for_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sni_list.txt");
        std::fs::write(&path, "").unwrap();
        let cfg = Arc::new(config_for_tests());
        let active = Arc::new(std::sync::RwLock::new(ActiveSniTarget::new(
            "example.com",
            "1.1.1.1".parse().unwrap(),
            50,
        )));
        let outcome = rescan_sni_once(
            cfg,
            path,
            None,
            active,
            None,
            RuntimeEventEmitter::default(),
            true,
        )
        .await;
        assert_eq!(outcome.found, 0);
        assert!(!outcome.switched);
    }
```

Note: `config_for_tests` is defined in Task 8; if Task 8 landed the helper under `#[cfg(test)]`, reuse it. `RuntimeEventEmitter::default()` disables output.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p zerodpi rescan_sni_once -v`
Expected: FAIL — function not found.

- [ ] **Step 3: Extract `rescan_sni_once`**

Move the body of the `background_rescan` loop after the `sleep(interval)` — everything from `events.emit(RuntimeEvent::RescanStarted ...)` through the summary emission — into:

```rust
#[allow(clippy::too_many_arguments)]
async fn rescan_sni_once(
    cfg: Arc<Config>,
    path: PathBuf,
    rescan_discovery: Option<LowTtlDiscoveryState>,
    active_target: Arc<std::sync::RwLock<ActiveSniTarget>>,
    event_tx: Option<ProxyEventSender>,
    events: RuntimeEventEmitter,
    headless: bool,
) -> RescanOutcome {
    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);
    events.emit(RuntimeEvent::RescanStarted {
        scan: ScanKind::Sni,
    });
    if headless {
        info!(path = %path.display(), "background SNI rescan starting");
    } else {
        debug!("background rescan starting");
    }
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
            if headless {
                info!(
                    "background SNI rescan complete — {} (SNI, IP) pairs",
                    entries.len()
                );
                log_sni_scan_top("background SNI rescan top candidates", &entries);
            } else {
                debug!(
                    "background rescan complete — {} (SNI, IP) pairs",
                    entries.len()
                );
            }
            if let Some(best) = entries.first() {
                let current = active_target.read().unwrap().clone();
                if let Some(next) = select_rescan_target(&current, best, cfg.SNI_SWITCH_MIN_SCORE) {
                    let (switch, discovered) = match rescan_discovery.as_ref() {
                        Some(state) => {
                            let discovered = state.run(&next.sni, next.ip).await;
                            (
                                discovery_gated_switch(
                                    discovered,
                                    &current,
                                    best,
                                    cfg.SNI_SWITCH_MIN_SCORE,
                                ),
                                discovered,
                            )
                        }
                        None => (Some(next), None),
                    };
                    if let Some(next) = switch {
                        *active_target.write().unwrap() = next.clone();
                        info!(
                            old_sni = %current.sni,
                            old_ip = %current.ip,
                            new_sni = %next.sni,
                            new_ip = %next.ip,
                            "hot-swapped active SNI target"
                        );
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
                        switched = true;
                    }
                }
            }
        }
        Err(error) => {
            warn!(error = %error, "background rescan failed");
        }
    }
    let (found, best_score) = scan_summary.unwrap_or((0, None));
    let duration_ms = scan_started.elapsed().as_millis() as u64;
    events.emit(RuntimeEvent::RescanFinished {
        scan: ScanKind::Sni,
        found,
        best_score,
        duration_ms,
        switched,
    });
    send_rescan_event(
        &event_tx,
        ProxyEvent::RescanFinished {
            kind: RescanKind::Sni,
            found,
            best_score,
            duration_ms,
            switched,
        },
    );
    RescanOutcome { found, switched }
}
```

`background_rescan` keeps the scheduling loop and calls `rescan_sni_once(...)` after `sleep(interval)`, discarding the returned outcome (the events are already emitted inside).

- [ ] **Step 4: Extract `rescan_ip_once`**

Mirror the extraction for `background_ip_rescan`: move the scan/select/emit body into

```rust
#[allow(clippy::too_many_arguments)]
async fn rescan_ip_once(
    cfg: Arc<Config>,
    path: PathBuf,
    active_ip: Arc<std::sync::RwLock<std::net::IpAddr>>,
    event_tx: Option<ProxyEventSender>,
    events: RuntimeEventEmitter,
    headless: bool,
    policy: IpRescanPolicy,
) -> RescanOutcome
```

Returning `RescanOutcome { found, switched }`, and have `background_ip_rescan` call it after its `sleep`.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p zerodpi rescan_sni_once -v && cargo test -p zerodpi should_switch -v && cargo test --workspace`
Expected: PASS, including the existing target-selection tests.

- [ ] **Step 6: Commit**

```bash
git add crates/zerodpi/src/main.rs
git commit -m "refactor: extract one-shot SNI and IP rescan helpers"
```

---

### Task 12: Wire `sni_spoof` end to end

**Files:**
- Modify: `crates/zerodpi/src/network_recovery.rs` (concrete env + mapping)
- Modify: `crates/zerodpi-core/src/proxy.rs` (`run_proxy`, `run_ip_bypass_plus_proxy` take `InterfaceIp`)
- Modify: `crates/zerodpi-core/src/method_scanner.rs`, `crates/zerodpi-core/src/proxy_tester.rs` (callers)
- Modify: `crates/zerodpi/src/main.rs`
- Test: `crates/zerodpi/src/network_recovery.rs` (mapping tests)

**Interfaces:**
- Consumes: everything from Tasks 1–11.
- Produces:
  - `network_recovery::MainRecoveryEnv` implementing `RecoveryEnv`, with `new(probe_target, interface_ip_handle, data_plane, callbacks, events, proxy_events)`.
  - `network_recovery::runtime_event_for(&NetworkStatus) -> Option<RuntimeEvent>`.
  - `network_recovery::proxy_status_for(&NetworkStatus) -> Option<ProxyNetworkStatus>`.
  - `run_proxy(cfg, active_target, interface_ip: InterfaceIp, flow_controller, event_tx)`.
  - `run_ip_bypass_plus_proxy(cfg, active_ip, interface_ip: InterfaceIp, flow_controller, event_tx)`.
  - `run_headless_proxy(proxy_handle, event_rx, data_plane: Arc<dyn DataPlane>, events)`.

- [ ] **Step 1: Write the failing mapping tests**

Add to `network_recovery::tests`:

```rust
    #[test]
    fn maps_changing_status_to_network_changed_event() {
        let status = NetworkStatus::Changing {
            interface_ip: Ipv4Addr::new(192, 0, 2, 10),
            source: NetworkChangeSource::Route,
        };
        let event = runtime_event_for(&status).expect("runtime event");
        assert!(matches!(
            event,
            crate::runtime_events::RuntimeEvent::NetworkChanged {
                interface_ip,
                ..
            } if interface_ip == "192.0.2.10"
        ));
        let proxy = proxy_status_for(&status).expect("proxy status");
        assert!(matches!(
            proxy,
            zerodpi_core::proxy::NetworkStatus::Recovering { .. }
                | zerodpi_core::proxy::NetworkStatus::Online { .. }
                | zerodpi_core::proxy::NetworkStatus::Unavailable { .. }
                | zerodpi_core::proxy::NetworkStatus::Changing { .. }
        ));
    }

    #[test]
    fn maps_recovered_status_to_runtime_and_proxy_events() {
        let status = NetworkStatus::Recovered {
            interface_ip: Ipv4Addr::new(192, 0, 2, 10),
            target_verified: false,
            target_switched: true,
        };
        assert!(matches!(
            runtime_event_for(&status),
            Some(crate::runtime_events::RuntimeEvent::NetworkRecovered {
                target_switched: true,
                ..
            })
        ));
        assert!(proxy_status_for(&status).is_some());
    }

    #[test]
    fn online_status_has_no_runtime_event() {
        let status = NetworkStatus::Online {
            interface_ip: Ipv4Addr::LOCALHOST,
        };
        assert!(runtime_event_for(&status).is_none());
        assert!(proxy_status_for(&status).is_some());
    }
```

`NetworkStatus::Changing` needs a `source` field and `ProxyNetworkStatus` needs a `Changing` variant; add both in Step 2–3.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi network_recovery::tests -v`
Expected: FAIL — `runtime_event_for`, `proxy_status_for`, `Changing` field not found.

- [ ] **Step 3: Add the concrete env and mapping helpers**

In `crates/zerodpi/src/network_recovery.rs`:

Change the status variant:

```rust
    Changing {
        interface_ip: Ipv4Addr,
        source: zerodpi_core::net::NetworkChangeSource,
    },
```

Change `handle_change` to take the source and include it:

```rust
    pub(crate) async fn handle_change(
        &mut self,
        source: zerodpi_core::net::NetworkChangeSource,
        rx: &mut broadcast::Receiver<NetworkEvent>,
    ) {
        ...
                Ok(ip) => {
                    self.env.publish(NetworkStatus::Changing {
                        interface_ip: ip,
                        source,
                    });
```

In `run`:

```rust
    pub async fn run(mut self, mut rx: broadcast::Receiver<NetworkEvent>) {
        if let Some(interface_ip) = self.current {
            self.env.publish(NetworkStatus::Online { interface_ip });
        }
        loop {
            let source = match rx.recv().await {
                Ok(NetworkEvent::Changed { source }) => source,
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    zerodpi_core::net::NetworkChangeSource::Poll
                }
                Err(broadcast::error::RecvError::Closed) => break,
            };
            self.handle_change(source, &mut rx).await;
        }
    }
```

Update the test helper:

```rust
    async fn run_once(
        coordinator: RecoveryCoordinator<FakeEnv>,
        rx: &mut broadcast::Receiver<NetworkEvent>,
    ) {
        coordinator
            .handle_change(NetworkChangeSource::Address, rx)
            .await;
    }
```

Add the mapping helpers and the concrete env:

```rust
use zerodpi_core::net::InterfaceIpHandle;
use zerodpi_core::proxy::{NetworkStatus as ProxyNetworkStatus, ProxyEvent, ProxyEventSender};

use crate::data_plane::DataPlane;
use crate::runtime_events::{RuntimeEvent, RuntimeEventEmitter};

/// Runtime event for a status, when the contract defines one.
pub(crate) fn runtime_event_for(status: &NetworkStatus) -> Option<RuntimeEvent> {
    match status {
        NetworkStatus::Online { .. } => None,
        NetworkStatus::Unavailable { message } => Some(RuntimeEvent::NetworkUnavailable {
            message: message.clone(),
        }),
        NetworkStatus::Changing {
            interface_ip,
            source,
        } => Some(RuntimeEvent::NetworkChanged {
            source: *source,
            interface_ip: interface_ip.to_string(),
        }),
        NetworkStatus::Recovering {
            attempt,
            next_retry_ms,
            message,
        } => Some(RuntimeEvent::NetworkRecoveryFailed {
            attempt: *attempt,
            next_retry_ms: *next_retry_ms,
            message: message.clone(),
        }),
        NetworkStatus::Recovered {
            interface_ip,
            target_verified,
            target_switched,
        } => Some(RuntimeEvent::NetworkRecovered {
            interface_ip: interface_ip.to_string(),
            target_verified: *target_verified,
            target_switched: *target_switched,
        }),
    }
}

/// Dashboard event for a status.
pub(crate) fn proxy_status_for(status: &NetworkStatus) -> Option<ProxyNetworkStatus> {
    match status {
        NetworkStatus::Online { interface_ip } => Some(ProxyNetworkStatus::Online {
            interface_ip: *interface_ip,
        }),
        NetworkStatus::Unavailable { message } => Some(ProxyNetworkStatus::Unavailable {
            message: message.clone(),
        }),
        NetworkStatus::Changing { interface_ip, .. } => Some(ProxyNetworkStatus::Online {
            interface_ip: *interface_ip,
        }),
        NetworkStatus::Recovering { attempt, .. } => Some(ProxyNetworkStatus::Recovering {
            attempt: *attempt,
        }),
        NetworkStatus::Recovered { interface_ip, .. } => Some(ProxyNetworkStatus::Online {
            interface_ip: *interface_ip,
        }),
    }
}

/// Callbacks the running mode supplies to recovery.
pub struct RecoveryCallbacks {
    pub verify: Arc<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync>,
    pub rescan: Arc<dyn Fn() -> BoxFuture<'static, RescanOutcome> + Send + Sync>,
}

/// Concrete [`RecoveryEnv`] used by the CLI.
pub struct MainRecoveryEnv {
    probe_target: Arc<AtomicU32>,
    interface_ip_handle: InterfaceIpHandle,
    data_plane: Arc<dyn DataPlane>,
    callbacks: RecoveryCallbacks,
    events: RuntimeEventEmitter,
    proxy_events: Option<ProxyEventSender>,
}

impl MainRecoveryEnv {
    pub fn new(
        probe_target: Arc<AtomicU32>,
        interface_ip_handle: InterfaceIpHandle,
        data_plane: Arc<dyn DataPlane>,
        callbacks: RecoveryCallbacks,
        events: RuntimeEventEmitter,
        proxy_events: Option<ProxyEventSender>,
    ) -> Self {
        Self {
            probe_target,
            interface_ip_handle,
            data_plane,
            callbacks,
            events,
            proxy_events,
        }
    }
}

impl RecoveryEnv for MainRecoveryEnv {
    fn probe(&self, target: Ipv4Addr) -> anyhow::Result<Ipv4Addr> {
        zerodpi_core::net::default_interface_ipv4(target)
    }

    fn rebuild<'a>(&'a self, interface_ip: Ipv4Addr) -> BoxFuture<'a, anyhow::Result<()>> {
        self.data_plane.rebuild(interface_ip)
    }

    fn verify<'a>(&'a self) -> BoxFuture<'a, bool> {
        (self.callbacks.verify)()
    }

    fn rescan<'a>(&'a self) -> BoxFuture<'a, RescanOutcome> {
        (self.callbacks.rescan)()
    }

    fn apply_interface_ip(&self, interface_ip: Ipv4Addr) {
        self.interface_ip_handle.set(interface_ip);
    }

    fn remote_disconnected(&self) -> bool {
        self.data_plane.remote_disconnected()
    }

    fn publish(&self, status: NetworkStatus) {
        if let Some(event) = runtime_event_for(&status) {
            self.events.emit(event);
        }
        if let (Some(tx), Some(proxy_status)) = (&self.proxy_events, proxy_status_for(&status)) {
            let _ = tx.send(ProxyEvent::NetworkStatus {
                status: proxy_status,
            });
        }
    }
}
```

Add `Changing { interface_ip: Ipv4Addr, source: NetworkChangeSource }` to `zerodpi_core::proxy::NetworkStatus` and handle it in the TUI like `Online`.

- [ ] **Step 4: Change the proxy signatures**

In `crates/zerodpi-core/src/proxy.rs`:

- Import `use crate::net::InterfaceIp;`.
- `run_proxy(..., interface_ip: InterfaceIp, ...)`: read the value once per accepted connection, before spawning:

```rust
        let target = active_target.read().unwrap().clone();
        let flow_controller = flow_controller.clone();
        let event_tx = event_tx.clone();
        let current_interface_ip = interface_ip.current();
        let connection_settings = ConnectionSettings::from_config(&cfg);
```

and pass `interface_ip: current_interface_ip` in `InterceptConnectionTarget`.

- `run_ip_bypass_plus_proxy(..., interface_ip: InterfaceIp, ...)`: same pattern, read inside the loop.

- Tests that call `run_proxy` or `run_ip_bypass_plus_proxy` pass `InterfaceIp::fixed(ip)`.

In `crates/zerodpi-core/src/method_scanner.rs` and `crates/zerodpi-core/src/proxy_tester.rs`, replace each `run_proxy(..., interface_ip, ...)` call with `run_proxy(..., zerodpi_core::net::InterfaceIp::fixed(interface_ip), ...)`.

- [ ] **Step 5: Change `LowTtlDiscoveryState`**

In `crates/zerodpi/src/main.rs`, change the field `interface_ip: Ipv4Addr` to `interface_ip: zerodpi_core::net::InterfaceIp`, and read it inside `run` (or wherever the probe engine is constructed) with `self.interface_ip.current()` instead of using the field directly.

- [ ] **Step 6: Replace `run_headless_proxy` and wire the mode**

Replace `run_headless_proxy` with:

```rust
async fn run_headless_proxy(
    proxy_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    event_rx: mpsc::UnboundedReceiver<ProxyEvent>,
    data_plane: Arc<dyn data_plane::DataPlane>,
    events: RuntimeEventEmitter,
) -> anyhow::Result<()> {
    log_headless_proxy_start();
    let mut proxy_handle = proxy_handle;
    let event_log_handle = tokio::spawn(log_headless_proxy_events(event_rx, events.clone()));
    let fatal = data_plane.wait_fatal();
    tokio::pin!(fatal);

    tokio::select! {
        signal = shutdown_signal() => {
            let reason = signal?;
            proxy_handle.abort();
            let result = data_plane.stop().await;
            if result.is_ok() {
                events.emit(RuntimeEvent::GracefulShutdown { reason });
            }
            event_log_handle.abort();
            result
        }
        result = &mut proxy_handle => {
            let proxy_result = result.context("proxy task panicked")?;
            let stop_result = data_plane.stop().await;
            event_log_handle.abort();
            proxy_result?;
            stop_result
        }
        reason = &mut fatal => {
            proxy_handle.abort();
            event_log_handle.abort();
            Err(anyhow::anyhow!(reason))
        }
    }
}
```

Delete `enum InterceptorRuntime`, `stop_interceptor`, `spawn_interceptor_report`, `wait_for_interceptor_shutdown`, and `INTERCEPTOR_SHUTDOWN_TIMEOUT` from `main.rs` (they now live in `data_plane.rs`).

In the `sni_spoof` branch of `run(args)`:

1. After the interface probe, create the channel:

```rust
    let (interface_ip_handle, interface_ip) = zerodpi_core::net::interface_ip_channel(interface_ip);
```

2. Replace the `(flow_controller, interceptor_runtime)` block with `(flow_controller, data_plane)`:

```rust
    let (flow_controller, data_plane_controller): (Arc<dyn FlowController>, Arc<dyn data_plane::DataPlane>) =
        if cfg.BYPASS_METHOD.is_socket_only() {
            (
                Arc::new(LocalFlowController::new(new_flow_table())),
                Arc::new(data_plane::DataPlaneController::none()),
            )
        } else if let Some(helper) = remote_helper.as_ref() {
            let controller = rt
                .block_on(data_plane::DataPlaneController::remote(
                    cfg.clone(),
                    helper.clone(),
                    Arc::new(helper.clone()),
                    interface_ip.current(),
                ))
                .context("prepare root helper interceptor")?;
            (Arc::new(helper.clone()), Arc::new(controller))
        } else {
            let flows = new_flow_table();
            let method_box = build_method(&cfg)
                .with_context(|| format!("unknown BYPASS_METHOD '{}'", cfg.BYPASS_METHOD))?;
            let method: Arc<dyn zerodpi_core::methods::BypassMethod> = Arc::from(method_box);
            low_ttl_handle = method.low_ttl_handle();
            let controller = data_plane::DataPlaneController::local(
                cfg.clone(),
                flows.clone(),
                method,
                interface_ip.current(),
            )
            .context("open packet interceptor")?;
            (Arc::new(LocalFlowController::new(flows)), Arc::new(controller))
        };
```

3. Start the monitor and coordinator after the proxy target is known:

```rust
    let probe_target = Arc::new(std::sync::atomic::AtomicU32::new(u32::from(connect_ip)));
    let monitor = zerodpi_platform::netmon::NetworkMonitor::start(
        probe_target.clone(),
        Some(interface_ip.current()),
        network_recovery::SETTLE,
        network_recovery::POLL_INTERVAL,
    )
    .context("start network monitor")?;

    let cfg_verify = cfg.clone();
    let verify_target = active_target.clone();
    let verify: Arc<dyn Fn() -> network_recovery::BoxFuture<'static, bool> + Send + Sync> =
        Arc::new(move || {
            let cfg = cfg_verify.clone();
            let (sni, ip) = {
                let target = verify_target.read().unwrap();
                (target.sni.to_string(), target.ip)
            };
            Box::pin(async move {
                zerodpi_core::sni_scanner::probe_sni_candidate(
                    &sni,
                    ip,
                    Duration::from_secs(cfg.SCAN_TIMEOUT_SECS),
                    cfg,
                )
                .await
                .tls_ok
            })
        });

    let cfg_rescan = cfg.clone();
    let rescan_path = sni_list_path.clone();
    let rescan_target = active_target.clone();
    let rescan_discovery = low_ttl_discovery_state.clone();
    let rescan_event_tx = event_tx.clone();
    let rescan_events = events.clone();
    let rescan: Arc<
        dyn Fn() -> network_recovery::BoxFuture<'static, network_recovery::RescanOutcome>
            + Send
            + Sync,
    > = Arc::new(move || {
        let cfg = cfg_rescan.clone();
        let path = rescan_path.clone();
        let target = rescan_target.clone();
        let discovery = rescan_discovery.clone();
        let tx = Some(rescan_event_tx.clone());
        let events = rescan_events.clone();
        Box::pin(async move {
            rescan_sni_once(cfg, path, discovery, target, tx, events, no_tui).await
        })
    });

    let recovery_env = Arc::new(network_recovery::MainRecoveryEnv::new(
        probe_target.clone(),
        interface_ip_handle.clone(),
        data_plane_controller.clone(),
        network_recovery::RecoveryCallbacks { verify, rescan },
        events.clone(),
        Some(event_tx.clone()),
    ));
    let coordinator = network_recovery::RecoveryCoordinator::new(
        recovery_env,
        probe_target,
        cfg.AUTO_SELECT && cfg.SELECTED_SNI.is_none(),
        Some(interface_ip.current()),
    );
    let recovery_handle = rt.spawn(coordinator.run(monitor.events()));
```

`probe_target` is the single shared atomic: the monitor holds a clone, the environment holds a clone, and the coordinator takes the original.

4. Pass `interface_ip.clone()` to `run_proxy`, and `data_plane_controller` to `run_headless_proxy`.

5. On shutdown (`no_tui` path is inside `run_headless_proxy`; TUI path):

```rust
    proxy_handle.abort();
    monitor.shutdown();
    recovery_handle.abort();
    rt.block_on(data_plane_controller.stop())?;
    info!("shutting down");
```

6. When a rescan hot-swaps the target, the monitor probe target must follow. Inside `rescan_sni_once`, after `*active_target.write().unwrap() = next.clone();`, the caller of `rescan_sni_once` cannot see it. Add a dedicated update where the coordinator's env applies the interface IP only. The simplest correct hook: pass the `probe_target` atomic into the rescan closure and store `next.ip` after `rescan_sni_once` returns `switched`:

```rust
        Box::pin(async move {
            let outcome = rescan_sni_once(cfg, path, discovery, target, tx, events, no_tui).await;
            if outcome.switched {
                let ip = target.read().unwrap().ip;
                probe_target_atomic.store(u32::from(ip), std::sync::atomic::Ordering::SeqCst);
            }
            outcome
        })
```

(`probe_target_atomic` is a clone of the same `Arc<AtomicU32>`.)

- [ ] **Step 7: Run the tests and the full check**

Run: `cargo test -p zerodpi network_recovery::tests -v && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS. Fix any remaining `run_proxy`/`run_headless_proxy` call-site mismatches the compiler reports (`method_scanner.rs`, `proxy_tester.rs`, `ip_bypass_plus` wiring can temporarily pass `InterfaceIp::fixed` until Task 13).

- [ ] **Step 8: Commit**

```bash
git add crates/zerodpi/src/main.rs crates/zerodpi/src/network_recovery.rs crates/zerodpi-core/src/proxy.rs crates/zerodpi-core/src/method_scanner.rs crates/zerodpi-core/src/proxy_tester.rs
git commit -m "feat: recover sni_spoof in place on network changes"
```

---

### Task 13: Wire `ip_bypass_plus`

**Files:**
- Modify: `crates/zerodpi/src/main.rs`
- Test: none new; the mode is covered by the shared coordinator tests and the full check

**Interfaces:**
- Consumes: Task 12's `MainRecoveryEnv`, `run_headless_proxy`, and `InterfaceIp`-aware `run_ip_bypass_plus_proxy`.
- Produces: `ip_bypass_plus` recovery with IP-target verification and optional on-demand IP rescan.

- [ ] **Step 1: Wrap the interface handle**

After `let interface_ip = default_interface_ipv4(active_v4)...`, add:

```rust
    let (interface_ip_handle, interface_ip) =
        zerodpi_core::net::interface_ip_channel(interface_ip);
```

Replace the `interceptor_config(&cfg, interface_ip, ...)` and local `FilterSpec` construction with the controller, exactly as Task 12:

```rust
    let (flow_controller, data_plane_controller): (Arc<dyn FlowController>, Arc<dyn data_plane::DataPlane>) =
        if cfg.BYPASS_METHOD.is_socket_only() {
            (
                Arc::new(LocalFlowController::new(new_flow_table())),
                Arc::new(data_plane::DataPlaneController::none()),
            )
        } else if let Some(helper) = remote_helper {
            let controller = rt
                .block_on(data_plane::DataPlaneController::remote(
                    cfg.clone(),
                    helper.clone(),
                    Arc::new(helper.clone()),
                    interface_ip.current(),
                ))
                .context("prepare root helper interceptor")?;
            (Arc::new(helper.clone()), Arc::new(controller))
        } else {
            let flows = new_flow_table();
            let method_box = build_method(&cfg)
                .with_context(|| format!("unknown BYPASS_METHOD '{}'", cfg.BYPASS_METHOD))?;
            let method: Arc<dyn zerodpi_core::methods::BypassMethod> = Arc::from(method_box);
            let controller = data_plane::DataPlaneController::local(
                cfg.clone(),
                flows.clone(),
                method,
                interface_ip.current(),
            )
            .context("open packet interceptor")?;
            (Arc::new(LocalFlowController::new(flows)), Arc::new(controller))
        };
```

Pass `interface_ip.clone()` to `run_ip_bypass_plus_proxy` and `data_plane_controller` to `run_headless_proxy` / the TUI shutdown path (with `monitor.shutdown()` and `recovery_handle.abort()`).

- [ ] **Step 2: Start the monitor and coordinator**

After the proxy task is spawned (the target is known before that):

```rust
    let probe_target = Arc::new(std::sync::atomic::AtomicU32::new(0));
    if let IpAddr::V4(ip) = active_ip {
        probe_target.store(u32::from(ip), std::sync::atomic::Ordering::SeqCst);
    }
    let monitor = zerodpi_platform::netmon::NetworkMonitor::start(
        probe_target.clone(),
        default_interface_ipv4(active_v4).ok(),
        network_recovery::SETTLE,
        network_recovery::POLL_INTERVAL,
    )
    .context("start network monitor")?;

    let cfg_verify = cfg.clone();
    let verify_active = active_ip_arc.clone();
    let verify: Arc<dyn Fn() -> network_recovery::BoxFuture<'static, bool> + Send + Sync> =
        Arc::new(move || {
            let cfg = cfg_verify.clone();
            let ip = *verify_active.read().unwrap();
            Box::pin(async move {
                zerodpi_core::ip_scanner::probe_ip_candidate(
                    ip,
                    Arc::from(cfg.IP_SCAN_SNI.as_str()),
                    Duration::from_secs(cfg.SCAN_TIMEOUT_SECS),
                    cfg,
                )
                .await
                .tls_ok
            })
        });

    let cfg_rescan = cfg.clone();
    let rescan_path = ip_list_path.clone();
    let rescan_active = active_ip_arc.clone();
    let rescan_event_tx = event_tx.clone();
    let rescan_events = events.clone();
    let rescan_probe_target = probe_target.clone();
    let rescan: Arc<
        dyn Fn() -> network_recovery::BoxFuture<'static, network_recovery::RescanOutcome>
            + Send
            + Sync,
    > = Arc::new(move || {
        let cfg = cfg_rescan.clone();
        let path = rescan_path.clone();
        let active = rescan_active.clone();
        let tx = Some(rescan_event_tx.clone());
        let events = rescan_events.clone();
        let probe_target = rescan_probe_target.clone();
        Box::pin(async move {
            let outcome = rescan_ip_once(
                cfg,
                path,
                active.clone(),
                tx,
                events,
                no_tui,
                IpRescanPolicy {
                    mode_label: "ip_bypass_plus",
                    ipv4_only: true,
                },
            )
            .await;
            if outcome.switched {
                if let IpAddr::V4(ip) = *active.read().unwrap() {
                    probe_target.store(u32::from(ip), std::sync::atomic::Ordering::SeqCst);
                }
            }
            outcome
        })
    });

    let recovery_env = Arc::new(network_recovery::MainRecoveryEnv::new(
        probe_target.clone(),
        interface_ip_handle.clone(),
        data_plane_controller.clone(),
        network_recovery::RecoveryCallbacks { verify, rescan },
        events.clone(),
        Some(event_tx.clone()),
    ));
    let coordinator = network_recovery::RecoveryCoordinator::new(
        recovery_env,
        probe_target,
        cfg.AUTO_SELECT && cfg.SELECTED_IP.is_none(),
        Some(interface_ip.current()),
    );
    let recovery_handle = rt.spawn(coordinator.run(monitor.events()));
```

`active_ip` is the selected target's `IpAddr`; `active_v4` the IPv4 requirement value; keep the variable names that exist in `ip_bypass_plus_main`.

- [ ] **Step 3: Run the checks**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, no unused-import warnings from the removed filter construction.

- [ ] **Step 4: Commit**

```bash
git add crates/zerodpi/src/main.rs
git commit -m "feat: recover ip_bypass_plus in place on network changes"
```

---

### Task 14: Wire `ip_bypass` (no interception, IPv6-safe probe anchor)

**Files:**
- Modify: `crates/zerodpi/src/main.rs`
- Test: `crates/zerodpi/src/main.rs` (inline, pure helper)

**Interfaces:**
- Consumes: Task 12's `MainRecoveryEnv`, `run_headless_proxy`, `rescan_ip_once`.
- Produces:
  - `fn monitor_probe_target(active: IpAddr) -> Ipv4Addr` — the active IPv4 target, or the fixed anchor `1.1.1.1` when the target is IPv6.
  - `ip_bypass` recovery with target verification and optional rescan; data plane is `DataPlaneController::none()`.

- [ ] **Step 1: Write the failing test**

Add to `crates/zerodpi/src/main.rs` tests:

```rust
    #[test]
    fn monitor_probe_target_falls_back_to_anchor_for_ipv6() {
        let v4: std::net::IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(
            monitor_probe_target(v4),
            std::net::Ipv4Addr::new(198, 51, 100, 7)
        );
        let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(monitor_probe_target(v6), std::net::Ipv4Addr::new(1, 1, 1, 1));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p zerodpi monitor_probe_target -v`
Expected: FAIL — function not found.

- [ ] **Step 3: Implement the helper and wire the mode**

```rust
/// IPv4 address the network monitor probes with. `ip_bypass` may hold an IPv6
/// target, which cannot detect the local IPv4 route, so it falls back to a
/// stable anchor.
fn monitor_probe_target(active: IpAddr) -> Ipv4Addr {
    match active {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => Ipv4Addr::new(1, 1, 1, 1),
    }
}
```

Ensure `main.rs` imports `std::net::Ipv4Addr` (it already imports `IpAddr` for the IP modes).

In `ip_bypass_main`, after `active_ip_arc` is created:

```rust
    let probe_target = Arc::new(std::sync::atomic::AtomicU32::new(u32::from(
        monitor_probe_target(active_ip),
    )));
    let monitor = zerodpi_platform::netmon::NetworkMonitor::start(
        probe_target.clone(),
        Some(monitor_probe_target(active_ip)),
        network_recovery::SETTLE,
        network_recovery::POLL_INTERVAL,
    )
    .context("start network monitor")?;

    let cfg_verify = cfg.clone();
    let verify_active = active_ip_arc.clone();
    let verify: Arc<dyn Fn() -> network_recovery::BoxFuture<'static, bool> + Send + Sync> =
        Arc::new(move || {
            let cfg = cfg_verify.clone();
            let ip = *verify_active.read().unwrap();
            Box::pin(async move {
                zerodpi_core::ip_scanner::probe_ip_candidate(
                    ip,
                    Arc::from(cfg.IP_SCAN_SNI.as_str()),
                    Duration::from_secs(cfg.SCAN_TIMEOUT_SECS),
                    cfg,
                )
                .await
                .tls_ok
            })
        });

    let cfg_rescan = cfg.clone();
    let rescan_path = ip_list_path.clone();
    let rescan_active = active_ip_arc.clone();
    let rescan_event_tx = event_tx.clone();
    let rescan_events = events.clone();
    let rescan_probe_target = probe_target.clone();
    let rescan: Arc<
        dyn Fn() -> network_recovery::BoxFuture<'static, network_recovery::RescanOutcome>
            + Send
            + Sync,
    > = Arc::new(move || {
        let cfg = cfg_rescan.clone();
        let path = rescan_path.clone();
        let active = rescan_active.clone();
        let tx = Some(rescan_event_tx.clone());
        let events = rescan_events.clone();
        let probe_target = rescan_probe_target.clone();
        Box::pin(async move {
            let outcome = rescan_ip_once(
                cfg,
                path,
                active.clone(),
                tx,
                events,
                no_tui,
                IpRescanPolicy {
                    mode_label: "ip_bypass",
                    ipv4_only: false,
                },
            )
            .await;
            if outcome.switched {
                let ip = *active.read().unwrap();
                probe_target.store(
                    u32::from(monitor_probe_target(ip)),
                    std::sync::atomic::Ordering::SeqCst,
                );
            }
            outcome
        })
    });

    let recovery_env = Arc::new(network_recovery::MainRecoveryEnv::new(
        probe_target.clone(),
        zerodpi_core::net::interface_ip_channel(zerodpi_core::net::default_interface_ipv4(
            monitor_probe_target(active_ip),
        )
        .unwrap_or(Ipv4Addr::UNSPECIFIED))
        .0,
        Arc::new(data_plane::DataPlaneController::none()),
        network_recovery::RecoveryCallbacks { verify, rescan },
        events.clone(),
        Some(event_tx.clone()),
    ));
    let coordinator = network_recovery::RecoveryCoordinator::new(
        recovery_env,
        probe_target,
        cfg.AUTO_SELECT && cfg.SELECTED_IP.is_none(),
        zerodpi_core::net::default_interface_ipv4(monitor_probe_target(active_ip)).ok(),
    );
    let recovery_handle = rt.spawn(coordinator.run(monitor.events()));
```

`ip_bypass` never intercepts, so the interface-IP handle is created only to satisfy `MainRecoveryEnv`; it is seeded with the current probe result and the coordinator updates it, which is harmless.

On shutdown, mirror Task 12: `monitor.shutdown(); recovery_handle.abort();` before the TUI/headless cleanup. `ip_bypass_main` calls `run_headless_proxy(proxy_handle, event_rx, Arc::new(DataPlaneController::none()), events)`.

- [ ] **Step 4: Run the checks**

Run: `cargo test -p zerodpi monitor_probe_target -v && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi/src/main.rs
git commit -m "feat: recover ip_bypass in place on network changes"
```

---

### Task 15: Android parses the new network events

**Files:**
- Modify: `android/app/src/main/java/dev/zerodpi/android/runtime/ZeroDpiRunner.kt`
- Modify: `android/app/src/main/java/dev/zerodpi/android/runtime/RuntimeEventLineParser.kt`
- Modify: `android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt`
- Test: `android/app/src/test/java/dev/zerodpi/android/runtime/RuntimeEventLineParserTest.kt`

**Interfaces:**
- Consumes: the four new runtime events from Task 10.
- Produces: `ZeroDpiRunnerEvent.{NetworkUnavailable, NetworkChanged, NetworkRecoveryFailed, NetworkRecovered}`; service logging/surfacing without restart.

- [ ] **Step 1: Write the failing parser tests**

Append to `RuntimeEventLineParserTest`:

```kotlin
    @Test
    fun parsesNetworkUnavailable() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"network_unavailable","message":"no route"}""",
        )
        val unavailable = event as ZeroDpiRunnerEvent.NetworkUnavailable
        assertEquals("no route", unavailable.message)
    }

    @Test
    fun parsesNetworkChanged() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"network_changed","source":"address","interface_ip":"192.0.2.10"}""",
        )
        val changed = event as ZeroDpiRunnerEvent.NetworkChanged
        assertEquals("address", changed.source)
        assertEquals("192.0.2.10", changed.interfaceIp)
    }

    @Test
    fun parsesNetworkRecoveryFailed() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"network_recovery_failed","attempt":2,"next_retry_ms":4000,"message":"open packet interceptor"}""",
        )
        val failed = event as ZeroDpiRunnerEvent.NetworkRecoveryFailed
        assertEquals(2, failed.attempt)
        assertEquals(4_000L, failed.nextRetryMs)
        assertEquals("open packet interceptor", failed.message)
    }

    @Test
    fun parsesNetworkRecovered() {
        val event = RuntimeEventLineParser.parse(
            """{"event":"network_recovered","interface_ip":"192.0.2.10","target_verified":true,"target_switched":false}""",
        )
        val recovered = event as ZeroDpiRunnerEvent.NetworkRecovered
        assertEquals("192.0.2.10", recovered.interfaceIp)
        assertEquals(true, recovered.targetVerified)
        assertEquals(false, recovered.targetSwitched)
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run (from `android/`): `./gradlew :app:testDebugUnitTest --tests "dev.zerodpi.android.runtime.RuntimeEventLineParserTest"` (Windows: `gradlew.bat`).
Expected: FAIL — unresolved references.

- [ ] **Step 3: Add the runner events and parser cases**

In `ZeroDpiRunnerEvent`, next to `ActiveTargetChanged`:

```kotlin
    data class NetworkUnavailable(val message: String) : ZeroDpiRunnerEvent
    data class NetworkChanged(val source: String, val interfaceIp: String) : ZeroDpiRunnerEvent
    data class NetworkRecoveryFailed(
        val attempt: Int,
        val nextRetryMs: Long,
        val message: String,
    ) : ZeroDpiRunnerEvent
    data class NetworkRecovered(
        val interfaceIp: String,
        val targetVerified: Boolean,
        val targetSwitched: Boolean,
    ) : ZeroDpiRunnerEvent
```

In `RuntimeEventLineParser`, next to `"active_target_changed"`:

```kotlin
            "network_unavailable" -> ZeroDpiRunnerEvent.NetworkUnavailable(
                message = stringValue(json, "message").orEmpty(),
            )
            "network_changed" -> ZeroDpiRunnerEvent.NetworkChanged(
                source = stringValue(json, "source").orEmpty(),
                interfaceIp = stringValue(json, "interface_ip").orEmpty(),
            )
            "network_recovery_failed" -> ZeroDpiRunnerEvent.NetworkRecoveryFailed(
                attempt = longValue(json, "attempt")?.toInt() ?: 0,
                nextRetryMs = longValue(json, "next_retry_ms") ?: 0L,
                message = stringValue(json, "message").orEmpty(),
            )
            "network_recovered" -> ZeroDpiRunnerEvent.NetworkRecovered(
                interfaceIp = stringValue(json, "interface_ip").orEmpty(),
                targetVerified = boolValue(json, "target_verified") ?: false,
                targetSwitched = boolValue(json, "target_switched") ?: false,
            )
```

- [ ] **Step 4: Surface the events in the service**

In the service's runner-event `when`, next to `ActiveTargetChanged`:

```kotlin
            is ZeroDpiRunnerEvent.NetworkChanged -> {
                appendLog("Network changed (${event.source}) — rebuilding interception.")
            }
            is ZeroDpiRunnerEvent.NetworkRecovered -> {
                appendLog(
                    "Network recovered on ${event.interfaceIp}" +
                        if (event.targetSwitched) " with a new target." else ".",
                )
            }
            is ZeroDpiRunnerEvent.NetworkUnavailable -> {
                appendLog("Network unavailable: ${event.message}")
            }
            is ZeroDpiRunnerEvent.NetworkRecoveryFailed -> {
                appendLog(
                    "Network recovery attempt ${event.attempt} failed: ${event.message} " +
                        "(retrying in ${event.nextRetryMs} ms)",
                )
                updateState { it.copy(lastError = event.message) }
            }
```

Match the local helper names used by the surrounding branches (`appendLog`, state update) — copy the shape from `ActiveTargetChanged` and `FatalError`. No branch may call a restart.

- [ ] **Step 5: Run the parser tests**

Run: `./gradlew :app:testDebugUnitTest --tests "dev.zerodpi.android.runtime.RuntimeEventLineParserTest"`
Expected: PASS (existing plus four new tests).

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/java/dev/zerodpi/android/runtime/ZeroDpiRunner.kt android/app/src/main/java/dev/zerodpi/android/runtime/RuntimeEventLineParser.kt android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt android/app/src/test/java/dev/zerodpi/android/runtime/RuntimeEventLineParserTest.kt
git commit -m "feat(android): parse network recovery events"
```

---

### Task 16: Android stops restarting runs on network change

**Files:**
- Delete: `android/app/src/main/java/dev/zerodpi/android/service/DefaultNetworkMonitor.kt`
- Delete: `android/app/src/test/java/dev/zerodpi/android/service/NetworkChangeTrackerTest.kt`
- Modify: `android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt`
- Modify: `android/app/src/androidTest/java/dev/zerodpi/android/service/ZeroDpiServiceInstrumentedTest.kt`
- Modify: `android/app/src/androidTest/java/dev/zerodpi/android/service/TargetPickServiceInstrumentedTest.kt`

**Interfaces:**
- Consumes: Task 15's events.
- Produces: core-owned recovery on Android; the app keeps process-exit supervision and the startup watchdog.

- [ ] **Step 1: Find every network-restart reference**

Run:

```bash
rg -n "DefaultNetworkMonitor|NetworkChangeTracker|networkMonitor|startNetworkMonitoring|stopNetworkMonitoring" android/app/src
```

Expected sites in `ZeroDpiService.kt`: the field declaration, every `networkMonitor?.stop()` / `= null`, `startNetworkMonitoring()`, and the method body; plus any instrumented tests that drive the monitor.

- [ ] **Step 2: Remove the monitor**

In `ZeroDpiService.kt`:

1. Delete `private var networkMonitor: DefaultNetworkMonitor? = null`.
2. Delete every `networkMonitor?.stop()` and `networkMonitor = null` statement the search found (including the service teardown blocks).
3. Delete `startNetworkMonitoring()` and its call.
4. Delete `DefaultNetworkMonitor.kt` and `NetworkChangeTrackerTest.kt`.

Keep `requestAutomaticRestart(...)`: it still serves the error-restart path (`"Restarting after error (attempt n)."`). Keep `networkRestartableStatuses`: it still guards that method. Remove the default `restartMessage = "Restarting after network change."` parameter only if no caller relies on the default; the error call site passes an explicit message, so change the default to `"Restarting automatically."`.

- [ ] **Step 3: Rewrite the instrumented tests**

Run:

```bash
rg -n "NetworkRestart|networkRestart|stableNetwork|DefaultNetworkMonitor" android/app/src/androidTest
```

For each hit, replace the test with behavior that asserts the new contract. Delete tests whose entire purpose was monitor-driven restart, specifically:

- `autoSelectOffPinnedRunNetworkRestartKeepsPinnedTargetWithoutScan`
- `autoSelectOffClearedPinNetworkRestartStopsInsteadOfScanning`

Add to `ZeroDpiServiceInstrumentedTest`:

```kotlin
    @Test
    fun networkEventsDoNotRestartRun() = runBlocking {
        configureRootlessSupervisedSessionMode()
        val service = bindZeroDpiService()
        service.startZeroDpi()
        service.waitForState { it.status == RuntimeStatus.Running }

        val runsBefore = fakeRunner.startCount
        fakeRunner.emit(ZeroDpiRunnerEvent.NetworkChanged(source = "address", interfaceIp = "192.0.2.10"))
        fakeRunner.emit(
            ZeroDpiRunnerEvent.NetworkRecoveryFailed(
                attempt = 1,
                nextRetryMs = 1_000,
                message = "open packet interceptor",
            ),
        )
        fakeRunner.emit(
            ZeroDpiRunnerEvent.NetworkRecovered(
                interfaceIp = "192.0.2.10",
                targetVerified = true,
                targetSwitched = false,
            ),
        )

        service.waitForState { it.status == RuntimeStatus.Running }
        assertEquals(runsBefore, fakeRunner.startCount)
        service.ensureSessionStopped()
    }
```

Adapt the helper names to the harness in the file (`bindZeroDpiService`, `fakeRunner`, `configureRootlessSupervisedSessionMode`, `withFastAutoRestartPolicy` are the ones used by the neighbouring tests); the assertion is the contract: no new runner start and the status stays `Running`.

- [ ] **Step 4: Run the Android tests**

Run: `./gradlew :app:testDebugUnitTest` and, on a device/emulator, `./gradlew :app:connectedDebugAndroidTest`.
Expected: PASS. The startup watchdog, auto-restart policy, and target-pick tests keep passing; only the removed network-restart tests are gone.

- [ ] **Step 5: Commit**

```bash
git add android/app/src
git commit -m "feat(android): let the core own network recovery"
```

---

### Task 17: Documentation

**Files:**
- Modify: `README.md`
- Modify: `android/README.md`

**Interfaces:**
- Consumes: the shipped behavior from Tasks 1–16.
- Produces: documented recovery behavior, events, and troubleshooting.

- [ ] **Step 1: Update the README run-supervision section**

Find the paragraph starting with "The app supervises every run it starts." (added by the Android watchdog work) and add, before it:

```markdown
ZeroDPI recovers from network changes in place. When the default interface
address changes (Wi-Fi to cellular, DHCP lease change, sleep/wake, adapter
reset), the core detects it from OS notifications with a 10-second polling
safety net, rebuilds packet interception against the new address, drops stale
flow state, and verifies the active target. If the target no longer works and
`AUTO_SELECT = true`, it runs one rescan (at most once per minute) and
hot-swaps; a pinned target (`AUTO_SELECT = false` or `SELECTED_SNI`/`SELECTED_IP`)
is never replaced automatically. Rebuild failures retry with a 1 s to 60 s
backoff, reset by the next network event. Existing connections still break on
a network change; only new connections recover.
```

- [ ] **Step 2: Update the troubleshooting table**

In the troubleshooting table, add:

```markdown
| ZeroDPI reports `network_recovery_failed` or stays on `Network: recovering` | The data plane cannot be rebuilt on the new address. Check that interception permissions still hold (root helper alive, iptables/nftables available) and read the event's `message`. Recovery retries automatically; a dead root helper stays fatal and the supervisor restarts the run. |
| `AUTO_SELECT = false` and the pinned target stopped working after a network change | Pinned targets are never replaced automatically. Run a scan and pick a target, or clear the pin. |
```

- [ ] **Step 3: Update `android/README.md`**

Replace the "Run supervision" paragraph's claim that a network change restarts the run with:

```markdown
Network changes are recovered by the native core, not by the app: the service
keeps the run alive and surfaces the `network_changed`, `network_recovered`,
`network_unavailable`, and `network_recovery_failed` events in the log and in
`lastError`. The service still restarts a run that exits unexpectedly (1 s to
60 s backoff) and still recovers a run that goes silent during startup.
```

- [ ] **Step 4: Verify docs build references**

Run: `rg -n "network_recovery_failed|restarting on network change" README.md android/README.md`
Expected: the new rows/paragraphs only; no stale claim that a network change restarts the run.

- [ ] **Step 5: Commit**

```bash
git add README.md android/README.md
git commit -m "docs: document in-place network recovery"
```

---

## Execution notes

- Run `cargo fmt --all` before each commit; the format check is part of every task's gate.
- Tasks 1–11 are independent of Tasks 12–14 except for names; Tasks 12–14 must land in order because they share `main.rs`.
- Tasks 15–16 depend on Task 10's event names. Task 17 depends on 1–16.
- If any task's gate fails, fix the task before moving on; do not batch fixes across tasks.
