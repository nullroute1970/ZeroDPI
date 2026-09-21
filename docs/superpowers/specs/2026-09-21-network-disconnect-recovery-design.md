# Network Disconnect Recovery (Core)

## Problem

ZeroDPI discovers the outbound interface IPv4 address once at startup
(`default_interface_ipv4`, `crates/zerodpi-core/src/net.rs`) and bakes it into
everything that matters for interception:

- the outbound socket bind in `handle_intercept_connection`
  (`crates/zerodpi-core/src/proxy.rs`),
- the interceptor `FilterSpec` — iptables/nftables rules matching
  `-s <ip>`/`-d <ip>` on Linux and the WinDivert filter string on Windows,
- flow keys (`FlowKey { src_ip: interface_ip, .. }`),
- `LOW_TTL_DISCOVER` probes.

When the network changes (Wi-Fi → cellular, DHCP lease change, sleep/wake,
adapter reset), the address of the default interface changes. The process
stays alive but:

- the outbound bind fails with `EADDRNOTAVAIL`, so every new connection fails;
- the firewall rules and WinDivert filter still reference the old address, so
  even a successful bind would not be intercepted;
- flow keys never match packets from the new address.

There is no re-detection, no rule rebuild, and no exit — a permanent wedge
until the user restarts ZeroDPI by hand. On Android the app's
`DefaultNetworkMonitor` masks this by restarting the whole run on a stable
default-network change, which kills the process and re-runs the scan. Desktop
(Linux/Windows) has no equivalent recovery.

Two smaller gaps compound the problem:

- relay copy errors are swallowed as `RelayEndReason::Completed`
  (`Ok(0) | Err(_) => break`), so a network drop is indistinguishable from a
  clean close;
- there is no runtime event that tells a supervisor or the UI that the network
  changed or that recovery is in progress.

## Goals

1. Recover in place on network changes without restarting the process: detect
   the change, re-detect the interface address, rebuild interception, clear
   stale flow state, and serve new connections again.
2. Detect changes from OS events on Linux/Android (netlink) and Windows
   (`NotifyIpInterfaceChange` + `NotifyRouteChange2`), with a debounce and a
   polling safety net.
3. Retry a failed rebuild indefinitely with exponential backoff; a newer
   network event resets the backoff.
4. After a successful rebuild, verify the active target once. Re-scan only if
   verification fails and the selection policy allows it; a pinned target is
   never replaced by an automatic scan.
5. Report network state honestly through runtime events, TUI status, and the
   Android app, and stop the Android app from restarting the run on network
   change.
6. Bound how long a connection can hang while the network is down.

## Non-goals

- Re-binding the proxy listener when `LISTEN_HOST` is a concrete interface
  address that changes. Default `127.0.0.1` and `0.0.0.0` are unaffected; a
  concrete-address listener keeps the v1 limitation.
- Saving connections that were already open when the network dropped. Only new
  connections recover.
- Re-spawning a dead root helper. A helper disconnection remains fatal; the
  supervisor relaunches the process.
- Automatic re-scan when the target is pinned (`AUTO_SELECT = false` or
  `SELECTED_SNI` set). Pinned targets are kept and reported.
- Changes to scanner scoring, candidate lists, or bypass methods.
- Windows service/installer supervision.

## Requirements

1. `zerodpi-platform` exposes a `NetworkMonitor` that emits settled
   address/route/link change ticks: netlink on Linux/Android, IP Helper
   notifications on Windows, and a polling safety net on every platform.
2. The monitor debounces events into a 1-second settle window and only
   signals; it never mutates proxy or firewall state.
3. `zerodpi-core` exposes a shared, swappable interface address (`InterfaceIp`)
   that the proxy, socket-only path, and `LOW_TTL_DISCOVER` read at use time
   instead of capturing a startup constant.
4. `FlowController` gains `reset()`. Local reset drops all entries; the remote
   client clears its map (the helper's table is recreated on re-open).
5. A new CLI `DataPlaneController` owns the live interceptor and can rebuild it
   in place for a new address, for both the local and root-helper paths.
6. A new CLI `RecoveryCoordinator` owns the policy: probe, compare, single-
   flight rebuild, indefinite retry with backoff, target verification, and
   on-demand rescan.
7. Target verification uses the existing probe semantics for one candidate and
   is rate-limited to at most one recovery-triggered rescan per 60 seconds.
8. Upstream connects are bounded by a 10-second timeout.
9. New additive `RuntimeEvent`s report network state; `ProxyEvent`/TUI show
   the same state; the Android parser consumes the new events.
10. Android stops restarting the run on a stable network change. Process-exit
    supervision and the run-startup watchdog are unchanged.
11. No new `config.toml` keys. Tunables are internal constants.
12. `ip_bypass` (no interception) still gets change detection and target
    verification; its data-plane rebuild is a no-op.
13. Existing behavior, tests, and the JSON event contract version remain
    compatible; the new events are additive.

## Design

### Components

#### `zerodpi-platform::netmon` (new)

```rust
pub enum NetworkChangeSource { Address, Route, Link, Poll }

pub enum NetworkEvent {
    /// A routing-relevant change settled after the debounce window.
    Changed { source: NetworkChangeSource },
}

pub struct NetworkMonitor;

impl NetworkMonitor {
    /// `probe_target` is the active relay IP used for the canonical re-probe.
    pub fn start(
        probe_target: std::sync::Arc<std::sync::atomic::AtomicU32>,
        initial: Option<std::net::Ipv4Addr>,
        settle: std::time::Duration,
        poll_interval: std::time::Duration,
    ) -> anyhow::Result<Self>;
    pub fn events(&self) -> tokio::sync::broadcast::Receiver<NetworkEvent>;
    pub fn shutdown(&self);
}
```

- **Linux/Android**: a dedicated thread reads a `NETLINK_ROUTE` socket bound to
  `RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_LINK`. Only `nlmsghdr`
  type/flags are classified; the payload is ignored because the canonical
  address comes from `default_interface_ipv4(probe_target)`. Raw sockets via
  `libc` (already a dependency). A wake pipe makes `poll()` shutdown
  deterministic.
- **Windows**: a dedicated thread runs a message loop, registers
  `NotifyIpInterfaceChange` and `NotifyRouteChange2`, and forwards ticks
  through the same broadcast channel. `CancelMibChangeNotify2` on shutdown.
  Uses `windows-sys` (version already present in `Cargo.lock`; feature
  `Win32_NetworkManagement_IpHelper` plus `Win32_Foundation`).
- **Polling safety net (all platforms)**: every 10 seconds the monitor probes
  `default_interface_ipv4(probe_target)` and emits `Changed { source: Poll }`
  only when the result differs from the last observed value (including
  transitions to/from "no route").
- On any raw tick, the monitor waits for the settle window to elapse without a
  newer tick, then probes once and emits at most one `Changed`.
- The probe target is an `AtomicU32` (0 = unknown) so a hot-swapped target
  updates detection without restarting the monitor. For an IPv6-only
  `ip_bypass` target the monitor probes with a fixed IPv4 anchor (the
  `ip_bypass` path never intercepts, so only the local IPv4 route matters).

#### `zerodpi-core` changes

- `net::InterfaceIp`: a `tokio::sync::watch` pair created at startup.

  ```rust
  #[derive(Clone, Debug)]
  pub struct InterfaceIp(tokio::sync::watch::Receiver<Ipv4Addr>);
  impl InterfaceIp {
      pub fn current(&self) -> Ipv4Addr;
      pub async fn changed(
          &mut self,
      ) -> Result<(), tokio::sync::watch::error::RecvError>;
  }
  pub fn interface_ip_channel(initial: Ipv4Addr) -> (watch::Sender<Ipv4Addr>, InterfaceIp);
  ```

  `run_proxy`, `run_ip_bypass_plus_proxy`, `handle_intercept_connection`,
  `handle_tcp_seg_connection_with_ip`, and `LowTtlDiscoveryState` take
  `InterfaceIp` and read `current()` per connection or per probe.
- `FlowController::reset()`:
  - `LocalFlowController`: drains the `DashMap`, calling
    `FlowEntry::finish(UnexpectedClose)` so waiters wake.
  - `RemoteHelperClient`: clears the client-side flow map. The helper builds a
    fresh flow table in `OpenInterceptor`, so no protocol change is required.
- Single-candidate verification entry points, extracted from the scanners:
  - `sni_scanner`: expose one `(sni, ip)` probe equivalent to `probe_sni`
    (TCP + TLS + HTTP checks).
  - `ip_scanner`: expose one IP probe equivalent to the Phase 1→3 pipeline.

#### CLI `DataPlaneController` (new module `crates/zerodpi/src/data_plane.rs`)

Owns the live interceptor and rebuilds it:

- **Local**: preserves the same `Arc<dyn BypassMethod>` and `FlowTable` across
  rebuilds (the `low_ttl` handle survives), so `rebuild(new_ip)` is:
  request old shutdown → wait for the report → `flow_controller.reset()` →
  `DefaultInterceptor::open(new FilterSpec)` → spawn a new intercept thread.
- **Remote**: `helper.close()` → `flow_controller.reset()` →
  `helper.configure(interceptor_config(cfg, new_ip, ..))` → `helper.open()`.
  The helper protocol already supports close → configure → open.
- **None**: socket-only and `ip_bypass` modes; `rebuild` is a no-op.
- `stop()` terminates the current plane for shutdown. `run_headless_proxy` and
  the TUI cleanup path call it instead of `stop_interceptor(...)`.
- The controller also surfaces "interceptor ended without a shutdown request",
  which today only the headless path notices; the coordinator handles it via
  the same rebuild path with the current address.

#### CLI `RecoveryCoordinator` (new module `crates/zerodpi/src/network_recovery.rs`)

Subscribes to the monitor and owns all policy. It runs as a spawned task and
is stopped during shutdown.

### Recovery flow

1. **Startup**: probe `default_interface_ipv4(active_target)`, seed
   `InterfaceIp`, start `NetworkMonitor` with the active target, wrap the
   already-opened interceptor in `DataPlaneController`, spawn the coordinator.
2. **Steady state**: proxy tasks read `InterfaceIp` per connection; the
   monitor watches; the poll safety net re-checks every 10 seconds.
3. **On `NetworkEvent::Changed`** (single-flight; a newer event while busy sets
   a "run again" flag):
   1. Probe `default_interface_ipv4(active_target)`.
      - `Err` (no route): mark state unavailable, emit `network_unavailable`,
        do not rebuild, keep the target, wait for the next event.
      - `Ok(ip)` with `ip == current`: no rebuild (route flap without address
        change); remain online.
      - `Ok(ip)` with `ip != current`: continue.
   2. Emit `network_changed { source, interface_ip }` and start the rebuild.
   3. `DataPlaneController::rebuild(new_ip)`:
      - success: update `InterfaceIp`, update the monitor probe target, emit
        `network_recovered { interface_ip, target_verified, target_switched }`
        (verification outcome filled in step 4);
      - failure: emit `network_recovery_failed { attempt, next_retry_ms,
        message }`, sleep the backoff, retry indefinitely. Backoff starts at
        1 second, doubles, caps at 60 seconds, and resets on any new network
        event (which also re-probes immediately).
   4. **Target verification** (after rebuild success): probe the active target
      once with the scanner-equivalent probe.
      - pass: done.
      - fail and `AUTO_SELECT = true`: run one on-demand rescan (extracted
        from `background_rescan`/`background_ip_rescan`), rate-limited to one
        per 60 seconds. If the existing selection rules pick a better target,
        hot-swap `active_target` (existing `ActiveTargetChanged` event) and
        update the monitor probe target; otherwise keep the current target.
      - fail and pinned (`AUTO_SELECT = false` or `SELECTED_SNI` set): keep the
        target, log a warning, emit the recovery event with
        `target_verified: false`.
4. **Interceptor death without a network event**: same rebuild path with the
   current address. Local failures retry forever with backoff. A remote helper
   disconnection is unrecoverable (the CLI cannot spawn a helper) and stays
   fatal: the coordinator reports it as fatal instead of retrying, the
   existing `wait_disconnected` select in `run_headless_proxy` aborts the
   proxy, and the process exits with `fatal_error`, as today.
5. **Shutdown**: stop the coordinator, then `DataPlaneController::stop()`.

### Failure handling summary

| Situation | Behavior |
|---|---|
| No route at probe time | `network_unavailable`; no rebuild; wait for next event |
| Address unchanged after event | Ignore; remain online |
| Rebuild open/configure failure | Retry forever, 1 s → 60 s backoff, reset on new event |
| Verify fails, `AUTO_SELECT = true` | One rate-limited rescan; hot-swap on existing rules |
| Verify fails, pinned target | Keep target; warn + event |
| Interceptor thread exits | Rebuild with current address (same backoff) |
| Root helper disconnected | Fatal; process exits; supervisor restarts |
| Network down during rebuild | Retry loop absorbs it; probe repeats each attempt |

### Connect timeout

Every upstream connect (`handle_intercept_connection`, the socket-only path,
`ip_bypass`, `ip_bypass_plus`) is wrapped in a 10-second timeout. On timeout
the flow guard removes the flow entry and the handler emits
`ConnectionError`. This bounds task and flow-table buildup while the network
is down.

### Relay error classification

Relay copy tasks report whether they ended on clean EOF or an I/O error.
A non-EOF error produces `RelayEndReason::NetworkError` instead of
`Completed`. Max-lifetime rotation stays `MaxLifetime`. The existing proxy
event carries the enum, so no new event is needed.

## Observability

New additive `RuntimeEvent` variants (snake_case `event` tags, contract
version unchanged):

```json
{"event":"network_unavailable","message":"..."}
{"event":"network_changed","source":"address","interface_ip":"192.0.2.10"}
{"event":"network_recovery_failed","attempt":2,"next_retry_ms":4000,"message":"..."}
{"event":"network_recovered","interface_ip":"192.0.2.10","target_verified":true,"target_switched":false}
```

- `source` serializes as `address` | `route` | `link` | `poll`.
- The Android parser already falls back to `Log` for unknown event names, so
  these additions are forward-compatible with older app builds.
- The TUI dashboard shows a network line updated from a new
  `ProxyEvent::NetworkStatus { state }` with
  `NetworkStatus::Online { interface_ip }`,
  `NetworkStatus::Recovering { attempt }`, or
  `NetworkStatus::Unavailable { message }`.
- Headless logging: `info` on change/recovery, `warn` on unavailable/failed
  attempts.

## Android app changes

- Remove `DefaultNetworkMonitor` and `NetworkChangeTracker` (and their JVM
  test), plus the service wiring, `networkRestartableStatuses`, and the
  restart-on-network-change path. The core now owns recovery.
- Keep process-exit supervision (1 s → 60 s backoff) and the run-startup
  watchdog unchanged.
- `RuntimeEventLineParser` + `ZeroDpiRunnerEvent`: parse the four new events;
  the service records them in the session log and surfaces
  `network_recovery_failed` in `lastError`, but never restarts for them.
- Rewrite/remove the instrumented tests that assert restart-on-network-change
  (`autoSelectOffPinnedRunNetworkRestartKeepsPinnedTargetWithoutScan`,
  `autoSelectOffClearedPinNetworkRestartStopsInsteadOfScanning`, and any
  monitor-driven restart tests); add parser/service tests that the new events
  are surfaced without restarting.
- Update `README.md` (run supervision and troubleshooting rows) and
  `android/README.md` (run supervision section).

## Configuration

No new `config.toml` keys. Internal constants:

| Constant | Value | Purpose |
|---|---|---|
| settle window | 1 s | Coalesce event storms before probing |
| poll interval | 10 s | Safety net for missed events |
| rebuild backoff | 1 s → 60 s | Retry cap, reset on new event |
| connect timeout | 10 s | Bound hung connects |
| recovery rescan min interval | 60 s | Prevent scan storms on flapping networks |

## Verification

- Rust unit tests:
  - monitor settle/debounce state machine with an injected clock;
  - netlink message classification (pure function over `nlmsghdr` type);
  - coordinator policy: probe outcomes (down/unchanged/changed), single-flight
    + re-run, backoff sequence and reset, verify→rescan gating for
    `AUTO_SELECT`/pinned, rescan rate limit, using fake monitor/controller;
  - `InterfaceIp` current-value reads and `FlowController::reset` wake/drain
    behavior;
  - runtime event serialization for the four new variants;
  - connect timeout fires and cleans up the flow.
- Android: JVM parser tests for the new events; instrumented tests rewritten
  to assert no restart on network change and event surfacing; startup watchdog
  and exit-supervision tests keep passing.
- Commands: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo build --workspace --release`, plus the
  Android Gradle test tasks used in this repository.
- Manual platform checks:
  - Linux: `ip link set dev <iface> down/up`, change the address
    (`ip addr change`), toggle hotspot; confirm rules move to the new address
    (`iptables -L`/`nft list ruleset`) and a new connection succeeds after
    restore.
  - Windows: disable/enable the adapter and switch Wi-Fi networks; confirm the
    WinDivert filter is re-created (debug log) and connections recover.
  - Android: Wi-Fi ↔ cellular switch; confirm the run is not restarted, new
    events appear, and connections recover.

## Risks

- **Netlink/Windows API quirks.** Mitigated by probing the canonical address
  rather than parsing event payloads, plus the 10-second poll safety net.
- **Rebuild gap.** During local rebuild the old rules are removed before the
  new ones are installed; new connections in that window fail and the VPN
  client retries. The window is milliseconds to a few seconds. Stale-rule
  recovery (`recover_stale_firewall_state`) already guards crash leftovers.
- **Rule churn on flapping networks.** Settle window, single-flight, backoff,
  and the rescan rate limit bound the churn.
- **Windows callback lifetime.** The notifier thread must be joined and
  `CancelMibChangeNotify2` called before unload; covered by shutdown tests and
  careful ownership.
- **Android test churn.** Several instrumented tests assert the removed
  behavior and must be rewritten; this is expected scope, not a hidden
  surprise.
- **Helper re-open semantics.** The helper already models
  `Configured → OpenInterceptor`; a client-side unit test covers repeated
  close/configure/open cycles.

## Implementation order (for the plan)

1. `netmon`: Linux/Android netlink + polling + settle logic + tests.
2. `netmon`: Windows notifier.
3. Core: `InterfaceIp`, `FlowController::reset`, connect timeout, relay error
   classification, single-candidate probe wrappers.
4. CLI: `DataPlaneController`, `RecoveryCoordinator`, rescan extraction,
   events, TUI status.
5. Wiring for `sni_spoof`, `ip_bypass_plus`, and `ip_bypass`.
6. Android: remove network restart, parse events, update tests and docs.
7. Docs: `README.md` run-supervision/troubleshooting and `android/README.md`.
   No `config.toml` or README configuration-table changes (no new keys).
