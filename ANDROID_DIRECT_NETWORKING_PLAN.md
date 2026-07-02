# Android Direct Networking Plan

Status: plan only. No implementation has been started in this document.

## Goal

Make ZeroDPI's Android upstream internet connections leave through the real
network when the user excludes the ZeroDPI app from VPN clients such as Happ or
v2rayNG.

This must work for rootless modes and should eventually work for root-required
packet interception modes.

## Current Problem

ZeroDPI's Android app is not an Android `VpnService`. It is a controller that
starts the native `zerodpi` executable.

For root-required modes, the Android runner currently starts the whole native
runtime through `su`. That means the process that opens upstream sockets is no
longer owned by the Android app UID. Android VPN per-app exclusion is normally
matched by UID/package, so excluding the ZeroDPI app does not necessarily
exclude a root child process.

Relevant current code:

- `android/app/src/main/java/dev/zerodpi/android/runtime/ProcessZeroDpiRunner.kt`
  starts the runtime as root when `request.useRoot` is true.
- `android/app/src/main/java/dev/zerodpi/android/runtime/RootManager.kt`
  launches root commands with `su -c`.
- `crates/zerodpi-core/src/proxy.rs` opens the upstream TCP sockets.
- `crates/zerodpi-platform/src/linux.rs` installs iptables/nftables rules and
  binds NFQUEUE on Android/Linux.

## Non-Goals

- Do not make the first fix depend on rewriting Happ, v2rayNG, or other
  upstream VPN profiles.
- Do not attempt to bypass Android Always-on VPN lockdown. If lockdown blocks
  non-VPN traffic, show a clear error.
- Do not make ZeroDPI a full replacement VPN client in the first implementation.
  Android generally allows one active `VpnService` per user, so a ZeroDPI VPN
  service would conflict with Happ/v2rayNG running as the active VPN.
- Do not change desktop Windows/Linux behavior except through shared
  abstractions that preserve the current path.

## Desired End State

The preferred architecture is:

1. The normal ZeroDPI Android runtime runs under the ZeroDPI app UID.
2. The app UID process owns the local listener, scanner sockets, and upstream
   relay sockets.
3. Root is used only by a small helper process for root-only tasks:
   firewall rule installation, firewall cleanup, and NFQUEUE packet handling.
4. The app UID runtime and root helper communicate through a local authenticated
   IPC channel.
5. The root helper never opens upstream internet sockets.
6. Optional explicit Android network routing can bind outbound sockets to a
   physical network when the user requests "direct network required".

This makes VPN app exclusion meaningful again because upstream sockets are
created by the ZeroDPI Android app UID.

## Implementation Strategy

Implement this in two tracks:

- Track A: split root-only interception from app-owned sockets. This should fix
  the common Happ/v2rayNG exclusion case.
- Track B: add explicit Android network routing for cases where per-app
  exclusion is not enough or the user wants direct physical network selection.

Track A should land first. Track B can be added after Track A proves that the
native runtime can keep socket ownership under the app UID.

## Phase 0: Prove The Current Behavior

Steps:

- [ ] Add a temporary Android diagnostic action that records:
  - [ ] app process PID and UID,
  - [ ] native ZeroDPI process PID and UID,
  - [ ] effective capabilities from `/proc/<pid>/status`,
  - [ ] whether ZeroDPI was started through `su`,
  - [ ] selected `MODE` and `BYPASS_METHOD`,
  - [ ] active VPN package if Android exposes it safely.
- [ ] Add native startup log fields:
  - [ ] `pid`,
  - [ ] effective UID,
  - [ ] effective capabilities,
  - [ ] whether packet interception is enabled.
- [ ] Add a support-bundle section for these diagnostics.
- [ ] Test current root-required mode while ZeroDPI is excluded in Happ/v2rayNG.

Acceptance criteria:

- [ ] Logs clearly show that current root-required starts run the upstream socket
  owner as UID 0.
- [ ] Logs clearly show that rootless starts run under the ZeroDPI app UID.
- [ ] The diagnostic output is safe to share and does not include private SNI
  lists, proxy credentials, or tokens.

## Phase 1: Add A Runtime Networking Mode Model

Add an Android-facing model before changing process ownership.

Suggested Kotlin model:

```kotlin
enum class AndroidNetworkMode {
    SystemDefault,
    VpnAppExclusionExpected,
    DirectPhysicalPreferred,
    DirectPhysicalRequired,
}
```

Meaning:

- `SystemDefault`: keep current Android routing.
- `VpnAppExclusionExpected`: keep sockets under the app UID and rely on the user
  excluding ZeroDPI in the active VPN app.
- `DirectPhysicalPreferred`: try to bind sockets to a non-VPN network, but fall
  back to system routing with a warning.
- `DirectPhysicalRequired`: fail startup if a non-VPN network cannot be selected
  or Android lockdown prevents direct traffic.

Steps:

- [ ] Add the model to the Android runtime request path.
- [ ] Add UI copy in settings explaining that VPN lockdown can still block
  direct traffic.
- [ ] Save the setting in app/profile state if profiles should control it.
- [ ] Pass the selected mode into `ZeroDpiRunRequest`.
- [ ] Emit it in startup logs and support bundles.

Acceptance criteria:

- [ ] The setting is visible in logs.
- [ ] No routing behavior changes yet.
- [ ] Existing rootless and root-required starts still behave as before.

## Phase 2: Split Process Responsibilities

Change the Android launcher so root-required mode does not start the whole
ZeroDPI runtime as root.

New process roles:

- Main runtime process:
  - runs under the ZeroDPI app UID,
  - owns local listener sockets,
  - owns upstream TCP sockets,
  - performs scanning,
  - maintains high-level flow lifecycle,
  - talks to root helper when packet interception is needed.
- Root helper process:
  - runs as root through `su`,
  - installs/removes firewall rules,
  - binds NFQUEUE,
  - handles packet modification for registered flows,
  - exits when the main runtime exits or the app asks it to stop.

Steps:

- [ ] Introduce a root-helper launch mode in the native binary, for example:

```text
zerodpi --android-root-helper \
  --helper-socket <socket-name-or-path> \
  --helper-token <random-session-token> \
  --json-events
```

- [ ] Change `ProcessZeroDpiRunner` root-required startup to:
  - [ ] generate a random one-time helper token,
  - [ ] choose an IPC socket name/path,
  - [ ] start the main runtime normally under the app UID,
  - [ ] start the root helper through `RootManager.runAsRoot(...)`,
  - [ ] monitor both processes,
  - [ ] stop both processes during graceful stop,
  - [ ] force stop both processes on timeout.
- [ ] Keep the old "run entire runtime as root" path behind a temporary
  developer fallback flag until the split path is stable.

Acceptance criteria:

- [ ] In root-required mode, logs show the main runtime UID is the app UID.
- [ ] Logs show only the helper process UID is root.
- [ ] Stop cleans up both processes and firewall rules.
- [ ] If helper launch fails, main runtime exits cleanly and the UI shows the
  helper failure.

## Phase 3: Define The Main Runtime To Helper IPC

Use IPC so the app-owned runtime can register flows and the root helper can
perform packet interception without owning upstream sockets.

Recommended transport:

- Unix domain socket where possible.
- Use an abstract namespace socket or an app-private filesystem socket after
  validating Android API 23+ behavior on real devices.
- Authenticate each session with a random token generated by the Android app.
- Never log the token.

Suggested protocol messages:

```text
hello {
  protocol_version,
  token,
  runtime_pid,
  app_uid
}

install_filter {
  interface_ip,
  remote_ip_optional,
  remote_port,
  queue_num,
  firewall_backend,
  app_uid
}

register_flow {
  src_ip,
  src_port,
  dst_ip,
  dst_port,
  bypass_method,
  method_config,
  fake_client_hello
}

unregister_flow {
  src_ip,
  src_port,
  dst_ip,
  dst_port
}

shutdown {}

event {
  type,
  source_port,
  status,
  message
}
```

Steps:

- [ ] Add a small versioned protocol crate or module shared by the main runtime
  and helper.
- [ ] Use structured serialization such as JSON lines first for easier
  diagnostics. Switch to a binary format later only if needed.
- [ ] Add protocol version negotiation.
- [ ] Add request IDs so startup failures can be matched to commands.
- [ ] Add timeouts for helper handshake, filter install, and shutdown.
- [ ] Add integration tests for protocol parsing and invalid-token rejection.

Acceptance criteria:

- [ ] Helper refuses connections with a missing or wrong token.
- [ ] Helper refuses incompatible protocol versions with a clear error.
- [ ] Main runtime fails startup if helper handshake or filter install fails.
- [ ] Helper exits when the IPC channel closes unexpectedly.

## Phase 4: Refactor Rust Interception Boundaries

The current in-process design shares flow state between proxy code and the
NFQUEUE interceptor. Split that boundary without changing bypass behavior.

Steps:

- [ ] Identify the current shared state between:
  - [ ] `crates/zerodpi-core/src/proxy.rs`,
  - [ ] flow table code,
  - [ ] bypass method implementations,
  - [ ] `crates/zerodpi-platform/src/linux.rs`.
- [ ] Add an abstraction for interception control, for example:

```rust
trait InterceptionController {
    async fn start(&self, filter: FilterSpec) -> anyhow::Result<()>;
    async fn register_flow(&self, flow: FlowRegistration) -> anyhow::Result<()>;
    async fn unregister_flow(&self, key: FlowKey) -> anyhow::Result<()>;
    async fn stop(&self) -> anyhow::Result<()>;
}
```

- [ ] Implement `LocalInterceptionController` for the current desktop/Linux
  in-process path.
- [ ] Implement `RemoteInterceptionController` for Android split-root mode.
- [ ] Keep bypass method behavior in shared Rust code so the helper and local
  controller do not diverge.
- [ ] Move only the minimum needed flow data into `FlowRegistration`.
- [ ] Ensure `tls_frag` still bypasses packet interception and does not start
  the helper.

Acceptance criteria:

- [ ] Desktop/Linux in-process behavior is unchanged.
- [ ] Android root-required mode can select the remote controller.
- [ ] Flow registration occurs before the app-owned socket connects upstream.
- [ ] Flow cleanup occurs on connection failure, relay completion, and timeout.

## Phase 5: Make Firewall Rules App-Scoped Where Possible

Current Linux/Android rules are broad enough to catch TCP packets by local IP
and port. Android split-root mode should avoid intercepting unrelated app or VPN
traffic where possible.

Steps:

- [ ] Add `app_uid: Option<u32>` to the Android/Linux filter model.
- [ ] For iptables OUTPUT rules on Android, prefer owner matching:

```text
-m owner --uid-owner <app_uid>
```

- [ ] Investigate nftables equivalent owner/socket UID matching on target
  Android versions.
- [ ] Investigate connmark-based INPUT matching:
  - [ ] mark outbound app-owned connections,
  - [ ] restore connmark on inbound packets,
  - [ ] send only marked packets to NFQUEUE.
- [ ] Keep a compatibility fallback that accepts broad NFQUEUE capture but
  filters unknown flows inside the helper.
- [ ] Add logs that state whether rules are app-scoped or broad fallback.

Acceptance criteria:

- [ ] On supported devices, OUTPUT capture is limited to ZeroDPI app UID.
- [ ] Inbound packets for registered flows still reach NFQUEUE.
- [ ] Unknown packets are accepted untouched.
- [ ] If app-scoped rules are unavailable, the UI/support logs show that broad
  fallback is active.

## Phase 6: Preserve App UID Socket Ownership

The central fix is that upstream sockets must be created by the app-owned main
runtime, not by the root helper.

Steps:

- [ ] Start the main native process without `su` even when root-required bypass
  methods are selected.
- [ ] Ensure all scan sockets and relay sockets are opened by the main runtime.
- [ ] Ensure the root helper does not call `TcpStream::connect`,
  `TcpSocket::connect`, scanner connect paths, DNS resolution for upstream
  sockets, or proxy tester connect paths.
- [ ] Add a debug assertion or diagnostic event when the helper attempts to open
  an outbound TCP socket.
- [ ] Add Android support-bundle output showing main runtime UID and helper UID.

Acceptance criteria:

- [ ] With root-required mode active, `/proc/<main-pid>/status` shows the app UID.
- [ ] `/proc/<helper-pid>/status` shows root.
- [ ] `ss` or equivalent diagnostics show upstream sockets associated with the
  app-owned process where Android exposes process ownership.
- [ ] Happ/v2rayNG app exclusion routes ZeroDPI upstream sockets direct on a
  non-lockdown VPN setup.

## Phase 7: Add Explicit Physical Network Selection

This phase is optional after the UID split, but it gives users a stronger
"direct internet" mode.

Android-side network selector:

- [ ] Use `ConnectivityManager` to enumerate networks.
- [ ] Ignore networks with VPN transport.
- [ ] Prefer networks with:
  - [ ] `NET_CAPABILITY_INTERNET`,
  - [ ] `NET_CAPABILITY_VALIDATED` when available,
  - [ ] Wi-Fi, cellular, or Ethernet transport.
- [ ] Detect when no non-VPN internet network is available.
- [ ] Detect likely lockdown behavior and report it clearly.

Socket binding options, in preferred order:

1. App/JNI socket broker:
   - Kotlin selects a physical `Network`.
   - Kotlin opens or binds sockets with public Android APIs.
   - File descriptors are passed to Rust/JNI code.
   - Rust relays over those descriptors.
2. JNI networking shim:
   - Rust asks a small Android/JNI layer to create connected sockets for a
     target address.
   - The shim binds each socket to the selected `Network`.
3. Process-level binding:
   - Test whether binding the Android service process affects the spawned
     native child process on target Android versions.
   - Use only if verified; do not assume inheritance.

Important constraint:

- `VpnService.protect()` should be treated as a separate research item. Using a
  ZeroDPI `VpnService` can conflict with Happ/v2rayNG because Android normally
  has one active VPN service. Prefer `ConnectivityManager.Network` binding for
  coexistence with another VPN app.

Acceptance criteria:

- [ ] `DirectPhysicalPreferred` selects a non-VPN network when available.
- [ ] `DirectPhysicalRequired` fails startup if no non-VPN network is usable.
- [ ] Direct mode fails clearly when Android lockdown blocks non-VPN traffic.
- [ ] Rootless and split-root modes can both use the selected routing path.

## Phase 8: Android UI And UX

Steps:

- [ ] Add a "Direct networking" setting near Android/root settings.
- [ ] Show current mode:
  - [ ] system default,
  - [ ] rely on VPN app exclusion,
  - [ ] prefer physical network,
  - [ ] require physical network.
- [ ] Show a runtime warning when:
  - [ ] active VPN lockdown is detected,
  - [ ] ZeroDPI is not excluded in the active VPN app and the selected mode
        expects exclusion,
  - [ ] app-scoped firewall rules are unavailable and broad fallback is active.
- [ ] Add a diagnostic button:
  - [ ] show process UID split,
  - [ ] show selected physical network,
  - [ ] show active VPN package when available,
  - [ ] show whether direct network test succeeded.
- [ ] Add troubleshooting text:
  - [ ] "Exclude ZeroDPI in your VPN app for app-UID routing."
  - [ ] "Disable Always-on VPN lockdown if direct traffic is required."
  - [ ] "Root-required modes use a root helper, but upstream sockets stay under
        the ZeroDPI app UID."

Acceptance criteria:

- [ ] Users can tell which direct networking mode is active.
- [ ] Startup failures explain whether the problem is root, helper launch,
  VPN lockdown, missing physical network, or firewall support.
- [ ] Support bundles include enough routing diagnostics for bug reports.

## Phase 9: Tests

Rust tests:

- [ ] IPC protocol parse/serialize round trip.
- [ ] Invalid helper token is rejected.
- [ ] Incompatible protocol version is rejected.
- [ ] Remote controller registers and unregisters flows in the correct order.
- [ ] Helper accepts unknown packets untouched.
- [ ] Existing bypass method unit tests still pass.

Android unit tests:

- [ ] `ZeroDpiRunRequest` carries `AndroidNetworkMode`.
- [ ] Root-required start launches main runtime without root and helper with
  root in split mode.
- [ ] Root helper failure produces a clear UI state.
- [ ] Stop and force stop target both main runtime and helper.
- [ ] Direct-network diagnostics redact tokens and private config data.

Instrumented/device tests:

- [ ] Rootless `tls_frag` with Happ/v2rayNG exclusion.
- [ ] Root-required method with split-root helper and Happ/v2rayNG exclusion.
- [ ] Same root-required method without exclusion, to confirm expected behavior.
- [ ] Always-on VPN lockdown enabled, expecting clear failure for direct-required
  mode.
- [ ] Wi-Fi direct network.
- [ ] Cellular direct network.
- [ ] Network switch while ZeroDPI is running.
- [ ] Root denial.
- [ ] Missing iptables/nftables/NFQUEUE support.

Acceptance criteria:

- [ ] Existing Android tests still pass.
- [ ] Desktop `cargo test --workspace` still passes.
- [ ] Device tests prove that root-required upstream sockets can be routed direct
  by app exclusion after the UID split.

## Phase 10: Rollout Plan

Steps:

- [ ] Ship the split-root path behind an experimental setting first.
- [ ] Keep the previous root launch path as a hidden fallback for one release.
- [ ] Log which path is active on every start.
- [ ] Ask testers to submit support bundles from:
  - [ ] Magisk-rooted devices,
  - [ ] KernelSU/APatch-rooted devices,
  - [ ] Android 6 to current supported versions,
  - [ ] Happ,
  - [ ] v2rayNG,
  - [ ] VPN lockdown on/off.
- [ ] Make split-root the default after device reports show stable cleanup and
  direct routing.
- [ ] Remove the old full-root runtime path only after one release where the
  fallback was not needed for supported devices.

Acceptance criteria:

- [ ] Users can opt out during the experimental release.
- [ ] Support bundles clearly identify old full-root mode versus new split-root
  mode.
- [ ] The default path eventually keeps upstream sockets under the app UID.

## Risks And Mitigations

Risk: IPC adds complexity to bypass timing.

Mitigation:

- Keep packet handling inside the root helper after flow registration. Do not
  send every packet over IPC.

Risk: firewall rules may still be broad on some Android devices.

Mitigation:

- Filter unknown flows in the helper and log whether app-scoped rules were
  available.

Risk: root helper cleanup fails and leaves firewall rules installed.

Mitigation:

- Use RAII-style cleanup in the helper, Android stop hooks, startup cleanup of
  stale ZeroDPI rules, and support-bundle diagnostics.

Risk: process-level Android network binding may not affect native child
processes.

Mitigation:

- Prefer per-socket binding through JNI/socket broker. Treat process binding as
  valid only after device tests prove it.

Risk: VPN lockdown blocks direct traffic even with correct UID ownership.

Mitigation:

- Detect and report lockdown. Do not present it as a ZeroDPI routing bug.

## Definition Of Done

- [ ] Root-required Android modes no longer require starting the whole ZeroDPI
  runtime as root.
- [ ] The root helper performs only root-only interception work.
- [ ] Upstream internet sockets are created by the ZeroDPI app UID.
- [ ] Happ/v2rayNG exclusion can route ZeroDPI upstream sockets direct on
  non-lockdown VPN setups.
- [ ] Direct-required mode fails clearly when Android cannot provide a physical
  non-VPN network.
- [ ] Existing desktop and rootless Android behavior remains intact.
- [ ] Documentation explains the difference between app exclusion, physical
  network binding, and VPN lockdown.
