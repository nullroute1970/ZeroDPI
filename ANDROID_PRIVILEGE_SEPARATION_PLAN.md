# ZeroDPI Android Privilege-Separation Implementation Plan

This document is a planning artifact only. It does not implement privilege
separation or change runtime behavior. Use it as a phased checklist for fixing
Android VPN per-app exclusion in root-required ZeroDPI modes.

## Status and Decision

- Plan date: 2026-07-17.
- Selected direction: keep all Internet-facing ZeroDPI networking in a native
  process owned by the Android application UID, and move only privileged
  firewall/NFQUEUE work into a separate root helper.
- Recommended helper model: the root helper owns the Linux/Android packet
  interceptor, firewall-rule lifetime, packet handler, and the helper-side
  flow table. The app-UID runtime owns scanning, DNS, listeners, upstream TCP
  and UDP sockets, and relaying.
- ZeroDPI remains a controller/local proxy and does not become an Android
  `VpnService`.
- The old behavior, which executes the complete native runtime through `su`,
  must not remain as an automatic fallback after this work is enabled.

## Problem Being Fixed

The Android app currently makes a root decision in `ZeroDpiService`, constructs
a `ZeroDpiRunRequest` with `useRoot = true`, and asks
`ProcessZeroDpiRunner` to launch the complete native command through
`SuRootManager.runAsRoot`. `SuRootManager` runs `su -c` followed by `exec`, so
the native process that creates upstream sockets normally runs as UID 0.

Android per-app VPN inclusion and exclusion is based on the UID resolved from
an installed package. Excluding `dev.zerodpi.android` therefore excludes the
app UID, not the UID 0 process created by `su`. A root-owned ZeroDPI upstream
socket can consequently be routed back through the upstream VPN, causing a
routing loop, connection failure, or VPN-dependent behavior.

Current root-required Android combinations are determined by
`ZeroDpiConfigToml.requiresPacketInterception`:

- `MODE = "sni_spoof"` with a bypass method other than `tls_frag`.
- `MODE = "proxy_scan"` with a bypass method other than `tls_frag`.
- `MODE = "ip_bypass_plus"` with a bypass method other than `tls_frag`.

Rootless modes already launch the executable as the app UID and must continue
to work without a helper.

## Scope

### In scope

- A dedicated root-helper process for Android full-runtime builds.
- An app-UID native data-plane process for every mode, including root-required
  modes.
- A versioned, authenticated local IPC protocol between those processes.
- Moving Android NFQUEUE and firewall ownership into the root helper.
- Synchronizing flow registration and bypass progress between the app-UID
  proxy and the root helper.
- Correct startup, normal shutdown, forced shutdown, crash cleanup, stale-rule
  recovery, and app restart behavior.
- Packaging both native executables in full Android APKs.
- Unit, integration, rooted-device, VPN-routing, failure-injection, and
  regression testing.
- Diagnostics that prove which UID owns the data plane and which process owns
  privileged interception.

### Out of scope

- Implementing an Android `VpnService` in ZeroDPI.
- Calling `VpnService.protect()` from ZeroDPI; only the prepared upstream VPN
  service can reliably protect sockets.
- Globally bypassing the VPN for UID 0.
- Adding custom Android policy-routing or socket-mark workarounds.
- Replacing NFQUEUE with a TUN implementation.
- Changing Windows WinDivert behavior.
- Requiring Termux for the Android app.
- General remote administration of the root helper.

## Success Definition

The change is complete only when all of the following statements are true:

1. The packaged ZeroDPI data-plane process always runs with the Android app
   UID, even for root-required modes.
2. Every Internet-facing TCP and UDP socket used by ZeroDPI is created by the
   app-UID process. This includes scanners, DNS-related sockets, relay
   connections, proxy tests, interface-discovery sockets, update-related
   native networking, and future connection factories.
3. The root helper opens no Internet-facing socket. Its permitted socket
   families are limited to local IPC and the netlink/NFQUEUE facilities needed
   for interception.
4. Excluding the ZeroDPI package from a normal per-app upstream VPN causes
   ZeroDPI upstream traffic to use the underlying network rather than the VPN
   tunnel.
5. Root-required bypass behavior remains functionally equivalent to the
   current in-process implementation.
6. Rootless Android behavior, Linux behavior, Termux behavior, and Windows
   behavior do not regress.
7. No ZeroDPI firewall rules or nftables tables remain after normal stop,
   force stop, helper failure, data-plane failure, app restart, or an
   explicitly tested recoverable crash scenario.
8. A helper/data-plane protocol mismatch fails closed before rules are
   installed or upstream sockets are opened.
9. The app reports a clear error instead of silently falling back to running
   the complete runtime as root.

Android VPN lockdown is a separate constraint. A VPN configured to block all
non-VPN traffic may intentionally block excluded applications. This design
must report that condition clearly, but it cannot override upstream VPN or
device-owner policy.

## Current Code Boundaries to Preserve or Refactor

The implementation should begin by confirming these current boundaries in the
latest code before editing:

- `android/app/src/main/java/dev/zerodpi/android/service/ZeroDpiService.kt`
  decides whether the selected configuration requires root and creates the run
  request.
- `android/app/src/main/java/dev/zerodpi/android/runtime/ProcessZeroDpiRunner.kt`
  currently chooses between app-UID launch and complete-runtime root launch,
  reads JSON events, tracks PIDs, and implements stop/force-stop behavior.
- `android/app/src/main/java/dev/zerodpi/android/runtime/RootManager.kt`
  currently provides root checks, arbitrary command launch through `su`, root
  diagnostics, and PID-based stopping.
- `crates/zerodpi/src/main.rs` currently checks for packet-interception access,
  opens `DefaultInterceptor`, creates the shared flow table, starts the
  interceptor thread, and starts the proxy.
- `crates/zerodpi-core/src/proxy.rs` registers `FlowKey`/`FlowEntry` state before
  opening an upstream connection and removes it when the connection ends.
- `crates/zerodpi-core/src/flow.rs` defines the flow state shared by the proxy
  and packet handler in the current single-process architecture.
- `crates/zerodpi-core/src/handler.rs` and the bypass-method modules transform
  intercepted packets by consulting the flow table.
- `crates/zerodpi-platform/src/linux.rs` currently installs firewall rules,
  opens/binds NFQUEUE, holds rule guards, processes verdicts, and deletes rules
  when the guard is dropped.
- `build.py` and `android/app/build.gradle.kts` package the native executable as
  an extracted executable-looking `.so` in the app native-library directory.

Do not refactor all platforms around Android-specific IPC. Introduce an
abstraction that lets desktop Linux/Termux retain the existing in-process
interceptor unless there is a separately justified reason to change them.

## Target Architecture

```text
Android UI / ZeroDpiService (app UID)
            |
            | starts and supervises
            v
zerodpi data-plane executable (app UID)
  - config parsing
  - SNI/IP scanning and DNS
  - local listener
  - upstream sockets
  - relay and runtime JSON events
            |
            | authenticated AF_UNIX IPC
            | flow lifecycle + helper control + progress
            v
zerodpi root helper (UID 0 through su)
  - validates peer UID and session
  - installs/removes iptables or nftables state
  - opens/binds NFQUEUE
  - owns helper-side FlowTable and Handler
  - processes packet verdicts
  - never performs Internet networking
```

### Why the helper should initially own the packet handler

The current proxy and interceptor share mutable `FlowEntry` state in one
address space. The least ambiguous first design is to put the helper-side
`FlowTable`, `Handler`, bypass method, and NFQUEUE loop together, then expose a
small flow-control protocol to the app-UID runtime. This avoids sending every
captured packet to the app process and back.

The app-UID runtime must register a flow and receive an acknowledgement before
calling `connect`, so the helper knows about the flow before the kernel emits
the SYN. The helper reports bypass progress back to the data plane so existing
timeouts and state transitions remain correct.

This helper is larger than an ideal capability-only process, but it still
removes all application parsing, scanning, TLS, proxying, and external socket
creation from UID 0. A later hardening phase may move packet transformation
out of the helper after the first architecture is stable.

## Security and Correctness Invariants

Treat these as design rules and test assertions, not optional guidance:

- The data-plane effective, real, and saved UID must be the Android app UID.
- The helper must verify it is running as UID 0 before privileged setup.
- The helper must accept exactly one authenticated data-plane peer per session.
- The helper must verify the peer UID using kernel-provided Unix-socket peer
  credentials. Do not trust an app-supplied UID field by itself.
- Use a fresh, cryptographically random session identifier to prevent stale
  processes from attaching to a new helper session.
- Do not place a secret session token in logs, JSON runtime events, support
  bundles, command-line diagnostics, or process titles.
- IPC must be local-only. Do not use a TCP listener, externally accessible
  Binder service, or filesystem socket outside app-private/abstract local
  scope.
- The helper must not accept arbitrary commands, shell fragments, paths, rule
  arguments, or executable names from IPC.
- Convert a validated, typed helper configuration into firewall arguments.
  Never concatenate untrusted configuration into a shell command.
- Bound every IPC message length, collection count, string length, packet
  payload length, and outstanding request count.
- Reject unknown protocol versions, message types, enum values, duplicate
  session starts, and illegal lifecycle transitions.
- Install firewall state only after authentication and complete configuration
  validation.
- Do not let the data plane open a root-required upstream connection until the
  helper has acknowledged both interceptor readiness and flow registration.
- On helper loss, abort affected upstream connections and stop the root-required
  runtime. Continuing without interception is not a safe fallback.
- Cleanup operations must be idempotent and must target only state created by
  the current or a proven-stale ZeroDPI session.
- Rootless modes must never launch the helper.
- Production builds must not fall back to the old all-root runtime.

## IPC Protocol Design

Complete the protocol design before implementing either endpoint.

### Transport decision

1. Prefer an Android-supported Unix-domain socket.
2. Evaluate `SOCK_SEQPACKET` first because it preserves message boundaries. If
   device/kernel support is insufficient, use `SOCK_STREAM` with an explicit
   fixed-size header and length-prefixed framing.
3. Prefer an abstract-namespace socket if it simplifies ownership and stale
   filesystem cleanup. If a filesystem socket is used, place it beneath the
   app-private runtime directory and verify directory and socket ownership and
   modes before connecting.
4. The helper should be the server and validate the connecting app UID using
   peer credentials. Pass the expected app UID as a non-secret launch argument
   and verify it against the actual peer credential.
5. Add a connection deadline. A helper that does not receive an authenticated
   peer promptly must exit without installing rules.
6. Decide how the random session identifier reaches both processes without
   appearing in logs. A protected app-private file with strict ownership, an
   inherited pipe, or a one-time stdin handshake are acceptable candidates.
   Document the selected threat model before implementation.

### Framing

Define a small header containing at least:

- Magic value identifying the ZeroDPI helper protocol.
- Protocol major and minor version.
- Message type.
- Request or correlation ID.
- Payload length.
- Optional flags reserved for compatible extensions.

Requirements:

- Use a fixed byte order.
- Enforce a conservative maximum frame size before allocation.
- Treat partial headers, truncated payloads, oversized frames, and unexpected
  EOF as fatal session errors.
- Do not use Rust memory-layout serialization or deserialize directly into
  types containing platform pointers, atomics, locks, or file descriptors.
- Fuzz the frame decoder and all externally supplied payload decoders.

### Minimum message set

The exact names may change, but the first protocol should cover these concepts:

Data plane to helper:

- `Hello`: protocol version, session identifier/proof, data-plane PID, and
  build/version metadata.
- `ConfigureInterceptor`: validated filter specification, queue number,
  firewall backend, bypass-method identifier, and only the method parameters
  the helper needs.
- `OpenInterceptor`: create one active interceptor instance.
- `CloseInterceptor`: close the active instance and remove its rules.
- `RegisterFlow`: flow identifier, complete `FlowKey`, fake ClientHello data or
  other per-flow initialization, and required method state.
- `RemoveFlow`: remove one flow idempotently.
- `Shutdown`: request cleanup and helper exit.
- `Ping`: heartbeat/liveness request.

Helper to data plane:

- `HelloAccepted`: confirmed peer UID, helper PID/UID, negotiated protocol
  version, and capabilities.
- `InterceptorReady`: acknowledgement sent only after rules are installed and
  NFQUEUE is bound/configured.
- `InterceptorClosed`: acknowledgement sent only after the queue is closed and
  cleanup has been attempted.
- `FlowRegistered`: acknowledgement that must precede the upstream `connect`.
- `FlowProgress`: typed bypass progress needed by current proxy state machines.
- `FlowRemoved`: idempotent removal acknowledgement.
- `HelperWarning`: non-fatal, sanitized diagnostic.
- `HelperFatal`: fatal reason followed by cleanup and process exit.
- `Pong`: heartbeat response.
- `ShutdownComplete`: final cleanup result.

### Lifecycle state machine

Write and test a strict helper state machine:

```text
Created
  -> Authenticated
  -> Configured
  -> InterceptorOpen
  -> Configured              (after CloseInterceptor)
  -> ShuttingDown
  -> Exited
```

Rules:

- Reject `RegisterFlow` unless an interceptor is open.
- Reject `OpenInterceptor` while another interceptor is open unless the
  protocol explicitly supports an atomic replacement operation.
- Permit repeated `RemoveFlow`, `CloseInterceptor`, and `Shutdown` requests to
  make cleanup retries safe.
- Limit the number of live flows and expire abandoned flows after a bounded
  interval.
- Use monotonically increasing request IDs and define behavior after wraparound
  or reconnect.
- A disconnected control socket triggers immediate interceptor shutdown and
  firewall cleanup.

## Phase 0: Record the Baseline and Reproduce the Bug

Do this before making functional changes.

### Tasks

- Build the current full Android debug APK for each supported test ABI.
- Install it on at least one rooted physical device.
- Configure an upstream `VpnService` client to exclude the ZeroDPI package.
- Run one rootless mode and one root-required mode.
- Record the Android app UID with `dumpsys package` or `pm`.
- Record the controller, native runtime, and `su` process identities using
  `ps` and `/proc/<pid>/status`.
- Map the native runtime's upstream socket descriptors to `/proc/net/tcp*` or
  an equivalent rooted diagnostic.
- Capture traffic on the VPN interface and physical interface, noting where
  the ZeroDPI upstream connection appears.
- Record `ip rule`, relevant route tables, VPN state, Android version, kernel,
  root manager, firewall backend, and upstream VPN version.
- Save a sanitized reproduction log that contains no private endpoints or SNI
  lists.
- Run the existing workspace and Android tests to establish a green baseline.

### Exit criteria

- The rootless native runtime is proven to use the app UID.
- The root-required native runtime is proven to use UID 0 or the root manager's
  privileged UID.
- The difference in routing behavior is observable or the device-specific
  reason it cannot be observed is documented.
- Baseline test results are recorded in the eventual pull request.

## Phase 1: Write the Architecture Decision and Threat Model

### Tasks

- Confirm that the first implementation uses a root-owned NFQUEUE/handler
  sidecar rather than descriptor passing.
- Document the process trust boundaries and all permitted communication paths.
- List the exact privileged operations required by the helper:
  - Execute validated `iptables` or `nft` operations.
  - Open and configure NFQUEUE/netlink.
  - Submit packet verdicts.
  - Remove only its own firewall state.
- List explicitly forbidden helper behavior:
  - DNS resolution.
  - Internet TCP or UDP sockets.
  - Reading arbitrary app/user files.
  - Downloading configuration.
  - Launching arbitrary commands.
- Decide whether method construction remains in the helper and define the
  serializable configuration subset for each interception-based method.
- Decide the IPC transport, authentication, framing, maximum sizes, heartbeat,
  and timeout values.
- Decide how the helper detects parent/data-plane death.
- Decide how a new session proves previous firewall state is stale before
  cleaning it.
- Add an ADR or a final architecture section to this plan before coding.

### Exit criteria

- The protocol and state machine can be reviewed without referring to
  implementation code.
- Every root privilege and every accepted input is enumerated.
- Crash cleanup and stale-state ownership are explicitly specified.
- There are no unresolved choices that would change the process boundary.

## Phase 2: Introduce Shared Protocol Types Without Changing Behavior

### Tasks

- Create a platform-neutral Rust module or small crate for helper protocol
  types and framing. Keep it independent of Android/Kotlin when possible.
- Define versioned wire types separate from internal `FlowEntry`, `Config`, and
  packet-handler types.
- Add explicit conversion and validation from wire types to internal types.
- Add typed error codes suitable for user-facing diagnostics without exposing
  secrets.
- Add frame encode/decode tests for:
  - Every message type.
  - Minimum and maximum legal payloads.
  - Unknown versions and message types.
  - Truncated frames.
  - Oversized declared lengths.
  - Invalid addresses, ports, queue numbers, and method parameters.
  - Duplicate and out-of-order lifecycle messages.
- Add fuzz targets for framing and payload validation if the repository's test
  infrastructure permits them. Otherwise, add property-based tests and record
  fuzzing as a release gate.
- Ensure protocol types contain no credentials, private config paths, or
  arbitrary shell strings.

### Exit criteria

- Protocol tests pass on the host without root.
- No production launch path uses the protocol yet.
- The protocol crate/module has no dependency that would pull the full CLI,
  scanner, TLS, or UI into the helper unnecessarily.

## Phase 3: Extract Interceptor and Flow-Control Abstractions

This phase prepares the single-process code for a remote helper while
preserving existing behavior.

### Tasks

- Introduce an interceptor-control abstraction used by the CLI/runtime rather
  than calling `DefaultInterceptor::open` directly at each call site.
- Provide an in-process implementation wrapping the current
  `DefaultInterceptor`, `Handler`, and shared `FlowTable` behavior.
- Define a flow-control abstraction with operations equivalent to:
  - Open/configure an interceptor.
  - Register a flow and await acknowledgement/readiness.
  - Observe typed bypass progress.
  - Remove a flow idempotently.
  - Close an interceptor.
- Refactor `handle_intercept_connection` and any other interception-aware proxy
  paths to use the abstraction instead of inserting directly into a concrete
  local flow table.
- Preserve the critical ordering:
  1. Bind the outbound socket and learn its source port.
  2. Build the complete `FlowKey`.
  3. Register the flow.
  4. Await registration acknowledgement.
  5. Connect the upstream socket.
  6. Relay and observe progress.
  7. Remove the flow on every exit path.
- Preserve scope-guard cleanup when tasks are cancelled or errors occur.
- Adapt `proxy_scan` so sequential candidate interceptors can be represented by
  repeated open/close operations without assuming local ownership.
- Keep desktop Linux, Termux, and Windows on the in-process implementation.
- Add tests with a fake flow controller to verify ordering, cancellation,
  timeout, duplicate cleanup, and helper-failure propagation.

### Exit criteria

- All existing modes behave the same with the in-process controller.
- Existing workspace tests pass.
- New tests prove `connect` cannot occur before flow-registration success.
- No Android process-launch behavior has changed yet.

## Phase 4: Create the Dedicated Root-Helper Executable

### Suggested location

Prefer a dedicated workspace crate such as `crates/zerodpi-root-helper/` or a
clearly isolated binary target. Do not add the helper entry point to the UI or
make it a general shell runner.

### Tasks

- Add the smallest practical binary dependency graph.
- Implement strict command-line parsing for non-secret bootstrap fields only:
  socket identifier, expected app UID, session metadata location or inherited
  channel, parent PID where useful, and diagnostic mode.
- Refuse to run unless the real/effective privilege state satisfies the
  platform's NFQUEUE/firewall requirements.
- Create the local IPC listener and authenticate the app-UID peer before
  installing rules.
- Implement the protocol state machine and bounded request handling.
- Convert validated interceptor configuration into `FilterSpec` and validated
  method configuration.
- Construct the helper-side `FlowTable`, bypass method, and `Handler` only
  after configuration succeeds.
- Open `NfqInterceptor` only in response to a valid `OpenInterceptor` message.
- Send `InterceptorReady` only after firewall installation and NFQUEUE binding
  are both complete.
- Register/remove helper-side flow entries through typed protocol messages.
- Forward only the bypass progress/events needed by the data plane.
- On EOF, timeout, invalid protocol, parent death, signal, or internal failure:
  - Stop receiving new requests.
  - Stop the NFQUEUE loop.
  - Drop/close flow state.
  - Remove firewall state.
  - Emit one sanitized terminal diagnostic.
  - Exit nonzero for abnormal failure.
- Make shutdown idempotent so the controller can retry after a lost
  acknowledgement.
- Add a test-only/mock interceptor backend so helper lifecycle tests do not
  require root.

### Root-helper hardening tasks

- Audit all dependencies for code that can create external sockets.
- Avoid initializing DNS, HTTP, TLS, scanner, TUI, or update components.
- Use absolute executable paths where an external `iptables`/`nft` command is
  unavoidable; validate the Android environment during diagnostics.
- Clear or strictly control inherited environment variables.
- Set a restrictive umask before creating filesystem state.
- Close all unexpected inherited file descriptors.
- Set process-death behavior where supported, but do not rely on it as the only
  cleanup mechanism.
- Use bounded worker/thread counts.
- Do not write secrets or raw packet contents to normal logs.
- Evaluate a seccomp filter or additional capability reduction only after the
  required Android syscalls are measured. Do not add an untested filter that
  breaks vendor kernels.

### Exit criteria

- The helper lifecycle passes host tests with a mock interceptor.
- Authentication failure exits before any mock rule installation.
- Abrupt IPC disconnect triggers cleanup.
- Static/runtime audits show no helper-created Internet sockets.

## Phase 5: Make Firewall Ownership Explicit and Recoverable

Current cleanup depends on Rust guard destruction. Preserve that normal path,
but add ownership identifiers and recovery for process crashes.

### Tasks

- Choose an unambiguous per-session firewall ownership scheme.
- For iptables, evaluate a dedicated ZeroDPI chain plus a narrowly scoped jump
  rule. Do not assume the `comment` module exists on every Android device
  without testing it.
- For nftables, continue using a uniquely named per-session table, but make the
  name derivation bounded and collision-resistant.
- Persist minimal session metadata in app-private storage:
  protocol version, backend, queue number, rule/table identifiers, helper PID,
  app UID, session creation time, and clean/unclean termination state.
- Never persist private endpoints, SNI lists, tokens, raw packets, or arbitrary
  command arguments.
- At helper startup, inspect only identifiers in ZeroDPI's namespace.
- Prove a previous session is stale before deleting its state. PID reuse means
  a PID alone is insufficient; combine it with session metadata and process
  start information where available.
- Make deletion idempotent and tolerant of already-removed rules.
- Ensure partial installation rolls back all successfully installed pieces.
- Ensure an iptables failure cannot trigger broad deletion of similar rules.
- Serialize helper sessions so two app actions cannot use the same NFQUEUE
  number or race rule cleanup.
- Add diagnostics that list ZeroDPI-owned rule identifiers without dumping
  unrelated firewall configuration.

### Crash limitation to document

No userspace process can execute cleanup after an immediate kernel panic or
power loss. The required behavior is therefore:

- Normal stop and catchable failures clean immediately.
- App/data-plane/helper crashes are detected and cleaned by the surviving
  supervisor where possible.
- The next helper start safely detects and removes proven-stale ZeroDPI state.
- Rules use NFQUEUE bypass/failure behavior chosen to avoid permanently
  blackholing traffic when no queue consumer exists, while preserving the
  security semantics required by the bypass method.

### Exit criteria

- Normal, partial-start, forced-stop, helper-crash, data-plane-crash, and stale
  startup tests leave no owned state behind.
- Unrelated firewall rules remain byte-for-byte unchanged in tests.

## Phase 6: Implement the App-UID Remote Interceptor Client

### Tasks

- Implement the remote interceptor/flow controller behind the abstraction from
  Phase 3.
- Connect using the negotiated Unix-socket transport.
- Authenticate the helper response and verify helper PID/UID/capabilities.
- Enforce connection, hello, configuration, open, flow registration, close,
  and shutdown deadlines.
- Translate helper flow-progress messages into the same internal state/events
  used by the current in-process handler.
- Treat helper EOF or `HelperFatal` as fatal for a root-required session.
- Cancel all outstanding waits when the helper disconnects.
- Remove flows idempotently on connection error, cancellation, timeout, and
  normal relay completion.
- Support repeated interceptor open/close cycles for `proxy_scan` candidates.
- Apply backpressure and bound pending messages so a slow helper cannot exhaust
  app memory.
- Do not reconnect transparently during an active intercepted flow. Stop the
  affected runtime and require a clean new session.
- Add a fake protocol server for deterministic tests.

### Exit criteria

- Remote-client tests cover all valid and invalid state transitions.
- Proxy tests prove registration acknowledgement precedes upstream connect.
- Helper loss reliably terminates root-required work without falling back to
  unmodified relaying.

## Phase 7: Split Android Process Launch and Supervision

This phase removes the problematic all-root launch.

### Android-side tasks

- Replace the conceptual `runAsRoot(zerodpi command)` operation with a narrow
  operation that launches only the packaged root-helper executable.
- Keep `requestRootFor` and diagnostics, but do not expose a general arbitrary
  root command API to new production code.
- Extend runner state to track two independent process handles/PIDs:
  - App-UID data-plane process.
  - Root-helper process.
- For a root-required request, use this startup sequence:
  1. Validate config and packaged artifacts.
  2. Generate a unique session identifier and protected bootstrap state.
  3. Request root authorization.
  4. Launch only the helper through `su`.
  5. Wait for helper bootstrap/listener readiness with a deadline.
  6. Launch the normal `zerodpi` executable through
     `SystemZeroDpiProcessLauncher`, not through `su`.
  7. Pass the IPC/session reference to the data plane without logging secrets.
  8. Wait for the data plane to authenticate/configure the helper.
  9. Report runtime started only after both processes are ready.
- For a rootless request, retain the existing single app-UID process path and
  never launch the helper.
- Preserve native JSON event parsing and add explicit helper lifecycle events.
- Verify the data-plane UID at startup and fail if it differs from the Android
  app UID.
- Verify the helper reports the expected privileged identity.

### Shutdown ordering

Normal stop should follow this order:

1. Tell the data plane to stop accepting new local connections.
2. Let it close active flows and remove them from the helper.
3. Ask it to close the active interceptor.
4. Wait for `InterceptorClosed`/cleanup acknowledgement.
5. Stop the data-plane process.
6. Ask the helper to shut down and wait for `ShutdownComplete`.
7. Escalate to helper termination only after a bounded timeout.
8. Verify no ZeroDPI-owned firewall state remains before reporting a clean
   stop where diagnostics have permission to perform the check.

Forced stop should:

1. Terminate the data plane.
2. Signal the helper to clean up.
3. Wait a short bounded interval.
4. Terminate the helper if necessary.
5. Mark the session unclean so the next start performs targeted recovery.

### Failure behavior

- Helper start failure: do not start the data plane for a root-required mode.
- Data-plane start failure after helper start: shut down the helper and clean
  rules.
- Helper exits while data plane runs: stop the data plane and report failure.
- Data plane exits while helper runs: request immediate helper cleanup.
- Android service destruction: perform the same bounded cleanup sequence and
  persist unclean state if completion cannot be confirmed.
- Root denial: show existing rootless alternatives and start nothing.
- Protocol mismatch: show an APK/native artifact mismatch error and clean up.

### Exit criteria

- No root-required launch path calls `su -c` with the data-plane executable.
- Unit tests assert the helper starts before the data plane and that the data
  plane uses the ordinary process launcher.
- Stop and force-stop tests assert both processes are handled in the correct
  order.
- There is no silent legacy fallback.

## Phase 8: Adapt Native Runtime Startup and Mode Handling

### Tasks

- Add an explicit Android external-helper mode selected only by the Android
  controller/bootstrap data.
- Do not weaken `ensure_packet_interception_access` globally. Instead:
  - Desktop/Termux in-process interception continues to require local
    privilege.
  - Android external-helper interception proves access by completing the
    authenticated helper handshake and `InterceptorReady` sequence.
- Emit startup identity diagnostics containing data-plane PID and UID, but no
  tokens or private paths.
- Ensure all SNI/IP scan phases execute in the app-UID data plane.
- For normal `sni_spoof`/`ip_bypass_plus`, open one remote interceptor session
  and keep it active for the proxy lifetime.
- For `proxy_scan`, explicitly open/configure/close the helper interceptor for
  each candidate or design a validated reconfiguration operation. Do not leave
  rules for the previous candidate active while testing the next candidate.
- Ensure candidate gaps and queue shutdown are acknowledged rather than based
  only on fixed sleeps.
- Keep `tls_frag` and other socket-only paths helper-free.
- Treat a helper requirement derived by Rust as authoritative and compare it
  with the Android config analysis. A mismatch should fail with a diagnostic,
  not choose the less privileged interpretation silently.
- Preserve runtime JSON events expected by the Android UI.

### Exit criteria

- Each root-required mode reaches the same functional outcomes as before.
- Rootless and `tls_frag` modes never connect to or launch a helper.
- `proxy_scan` can complete multiple candidates without stale rules or queue
  collisions.

## Phase 9: Audit Every Outbound Socket

The UID fix is incomplete if even one external socket is opened by the helper.

### Tasks

- Inventory all production uses of:
  - `TcpStream::connect` and `TcpSocket::connect`.
  - `UdpSocket` creation/connect/send operations.
  - DNS resolvers and libraries that create sockets internally.
  - SOCKS/HTTP proxy tests.
  - SNI/IP scanning and upload probes.
  - Default-interface discovery sockets.
  - Any telemetry, update, or support networking linked into the native
    runtime.
- Classify each socket as local IPC, local listener/client, NFQUEUE/netlink, or
  Internet-facing.
- Add a documented ownership assertion for each Internet-facing path: it must
  be reachable only in the app-UID executable.
- Add debug-only socket-audit logging that reports PID, UID, address family,
  and destination category without leaking private hostnames or addresses.
- On a rooted test device, inspect `/proc/<helper-pid>/fd` and prove the helper
  has no Internet TCP/UDP socket descriptors during scans and relays.
- Repeat the audit whenever a new networking dependency or mode is added.

### Exit criteria

- The audit table is complete and reviewed.
- Runtime device evidence shows all external sockets under the app-UID PID.
- The helper has only expected IPC/netlink descriptors.

## Phase 10: Package the Helper in Android Full Builds

### Tasks

- Add the helper binary to the Rust workspace and Android build helper.
- Produce it for every supported full-runtime Android ABI.
- Package it using an Android-compatible extracted-native-library name distinct
  from `libzerodpi_exec.so`, for example
  `libzerodpi_root_helper_exec.so`, after confirming Gradle/APK extraction
  behavior.
- Ensure the ordinary data-plane executable remains packaged and executable as
  the app UID.
- Full builds include both artifacts.
- Rootless builds omit the helper or include a deliberately unusable stub only
  if build-system constraints require it; omission is preferred.
- Add build-time checks that fail when a required artifact is missing, built
  for the wrong ABI, or accidentally identical to the data-plane binary.
- Ensure release signing and APK output naming remain unchanged except where
  intentionally documented.
- Update packaging tests and `build.py` dry-run/validation tests.
- Verify native symbols/dependencies do not cause the helper to load scanner,
  TLS, TUI, or unrelated platform code.

### Exit criteria

- Full APKs contain both correct ABI artifacts.
- Rootless APKs cannot start a root helper.
- Release and debug packaging validations pass.

## Phase 11: Diagnostics, UI, and User Guidance

### Runtime events

Add typed, sanitized events for at least:

- Data-plane process started with PID and UID.
- Root helper requested/starting.
- Root helper authenticated with PID and UID.
- Interceptor configuring/ready/closed.
- Helper warning or fatal failure.
- Firewall cleanup complete/incomplete.
- Stale ZeroDPI state detected and recovered.
- App-UID verification failure.
- VPN-lockdown or direct-network-connectivity warning when detectable.

### UI behavior

- Continue showing root as required only for interception-based combinations.
- Distinguish root authorization from helper readiness.
- Do not report the runtime as running while only one of the two processes is
  ready.
- Explain that users must still exclude the ZeroDPI package in the upstream
  VPN's per-app settings.
- Explain that Android's block-without-VPN/lockdown setting may block excluded
  apps.
- Offer rootless alternatives on helper failures where the selected method has
  a supported alternative.
- Never suggest excluding UID 0 as the normal solution.

### Support bundle

Include:

- Protocol version and negotiated helper capabilities.
- Data-plane/helper PIDs and UIDs at startup.
- Firewall backend and queue number.
- Clean/unclean termination status.
- Sanitized helper lifecycle errors.

Exclude:

- Session secrets.
- Raw IPC frames.
- Raw packets.
- Private proxy endpoints/SNI lists.
- Unfiltered firewall dumps.

### Exit criteria

- A user can distinguish root denial, helper startup failure, IPC mismatch,
  interceptor failure, routing/lockdown failure, and native data-plane failure.
- Support information is sufficient to diagnose lifecycle problems without
  exposing sensitive configuration.

## Phase 12: Automated Test Plan

### Rust protocol tests

- Round-trip every message type.
- Version negotiation, compatible minor versions, and rejected major versions.
- Framing fragmentation/coalescing for stream transport.
- Oversized, truncated, malformed, duplicated, and reordered messages.
- Maximum live-flow and pending-request limits.
- Random invalid input/property tests and fuzzing.

### Rust flow-controller tests

- Flow registration is acknowledged before `connect` is invoked.
- Registration failure prevents `connect`.
- Flow cleanup runs on success, connect failure, relay failure, timeout,
  cancellation, and helper loss.
- Duplicate removal is harmless.
- Bypass progress reaches existing waiters correctly.
- `proxy_scan` open/close cycles are ordered and acknowledged.

### Helper lifecycle tests with a mock interceptor

- Wrong peer UID is rejected before setup.
- Wrong session proof is rejected before setup.
- Invalid config is rejected before setup.
- Partial setup rolls back.
- EOF and heartbeat timeout clean up.
- Graceful shutdown cleans up exactly once.
- Forced termination leaves recoverable metadata.
- Startup recovery removes only proven-stale owned state.
- Two simultaneous sessions are rejected or serialized as designed.

### Android JVM tests

Extend tests around `ProcessZeroDpiRunner`, `SuRootManager`, and service startup:

- Rootless start launches only the app-UID data plane.
- Root-required start launches the helper through root management and the data
  plane through the normal launcher.
- Helper readiness is required before data-plane startup/ready reporting.
- Helper failure prevents data-plane launch.
- Data-plane failure triggers helper shutdown.
- Stop, force stop, timeout, and service destruction handle both processes.
- Protocol mismatch and missing helper artifact produce clear failures.
- No test expects the complete `zerodpi` command to be passed to
  `runAsRoot` after migration.

### Android instrumented tests without root

- Rootless modes remain functional.
- Root-required mode reports root unavailable/denied without starting either
  executable incorrectly.
- Packaged artifact discovery works for each build variant.
- UI state reflects two-stage startup and cleanup failure.

### Opt-in rooted-device tests

- Helper UID is 0 and data-plane UID equals the package UID.
- iptables backend installs and removes only expected state.
- nftables backend installs and removes only expected state where supported.
- Normal stop, notification stop, force stop, app swipe-away/service kill,
  data-plane kill, helper kill, and repeated start/stop are tested.
- Stale state is recovered after an intentionally unclean test.
- `sni_spoof`, `ip_bypass_plus`, and multi-candidate `proxy_scan` are exercised.
- Rootless modes do not launch the helper on a rooted device.

### Workspace regression tests

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Relevant Gradle JVM tests.
- Relevant Android instrumented tests.
- Android full and rootless APK packaging for supported ABIs.
- Linux NFQUEUE smoke test.
- Windows build/test checks sufficient to prove WinDivert was not coupled to
  Android IPC.

## Phase 13: VPN Routing Acceptance Matrix

Run routing tests on physical devices; emulator-only testing is insufficient.

### Minimum matrix dimensions

- Android versions: oldest supported API on available hardware, one middle
  release, and the newest supported/current release.
- ABI: arm64-v8a, plus armeabi-v7a where hardware remains supported.
- Root manager: at least the primary supported solution and one alternative if
  the project claims compatibility.
- Firewall backend: iptables and nftables where present.
- Upstream VPN: at least two clients that support per-app exclusion.
- Network: Wi-Fi, mobile data where available, and Wi-Fi/mobile handover.
- IP family: IPv4 and IPv6 where the mode supports them.
- VPN mode: normal split-tunnel exclusion and block-without-VPN/lockdown.

### Required scenarios

1. VPN disconnected, rootless mode.
2. VPN connected, ZeroDPI excluded, rootless mode.
3. VPN connected, ZeroDPI excluded, each root-required mode.
4. VPN connected, ZeroDPI not excluded, demonstrating the expected loop/fail
   condition or warning rather than claiming automatic protection.
5. VPN reconnect while ZeroDPI is stopped.
6. VPN disconnect/reconnect during an active ZeroDPI session.
7. Wi-Fi/mobile handover during an active session.
8. Lockdown enabled, confirming that blocked excluded traffic is reported and
   not mistaken for a helper failure.

### Evidence to collect

- App UID and both process UIDs.
- Process tree.
- Socket ownership mapping.
- Packet captures or counters on VPN and physical interfaces.
- Firewall state before, during, and after the session.
- Runtime and helper lifecycle events.
- Final cleanup state.

### Acceptance criteria

- With ZeroDPI excluded and lockdown disabled, its upstream connection appears
  on the underlying network and not as app traffic entering the VPN tunnel.
- The upstream VPN continues sending its local client traffic to ZeroDPI's
  listener.
- No recursive upstream connection is observed.
- Lockdown failure is explicit and does not cause a broad routing bypass.

## Phase 14: Failure-Injection and Security Review

### Failure injection

Test failures at every startup boundary:

- Root denied.
- Helper artifact missing or not executable.
- Helper crashes before socket creation.
- Authentication failure.
- Protocol mismatch.
- Invalid interceptor configuration.
- Firewall install partially succeeds.
- NFQUEUE bind fails or queue number is busy.
- Data-plane executable fails before connecting.
- Data plane connects and then exits before opening an interceptor.
- Flow registration times out.
- Helper exits after rules are installed.
- Data plane is killed with active flows.
- Android service is killed during shutdown.
- Cleanup command fails once and succeeds on retry.
- Device restarts with a recorded unclean session.

For each injection, specify expected process state, user-visible error, rule
state, retry behavior, and whether the next start is allowed.

### Security review checklist

- Peer UID authentication cannot be bypassed with a user-supplied field.
- Session identifiers are unpredictable and not logged.
- IPC parser is memory-safe, bounded, and fuzzed.
- The helper accepts no arbitrary shell input.
- Firewall identifiers cannot escape the ZeroDPI namespace.
- Symlink and path-replacement attacks are prevented for filesystem IPC or
  metadata.
- PID reuse cannot authorize stale cleanup incorrectly.
- Support bundles contain no secrets or raw traffic.
- Root helper dependencies and syscalls are documented.
- The helper cannot be triggered by another package UID.
- Release builds disable test-only backends and debug bypasses.
- There is no automatic all-root-runtime fallback.

### Exit criteria

- All high-severity findings are fixed.
- Remaining limitations are documented with explicit product decisions.
- Failure tests demonstrate safe cleanup or safe next-start recovery.

## Phase 15: Rollout and Removal of Legacy Root Launch

### Tasks

- Introduce the new architecture behind an explicit development/build flag
  while tests are incomplete.
- Do not expose the legacy all-root launch as a normal user fallback.
- During development, require an explicit debug-only opt-in if legacy behavior
  is temporarily retained for comparison.
- Validate the new architecture on the routing matrix.
- Make the helper architecture the only production path for root-required
  Android modes.
- Remove or narrow `RootManager.runAsRoot` so production code cannot launch the
  complete ZeroDPI runtime accidentally.
- Update tests that currently assert root launch of the packaged runtime.
- Update `android/README.md`, `android/TESTING.md`, root diagnostics, support
  guidance, build documentation, and release notes.
- Document the minimum compatible full APK version as a unit: controller,
  data-plane binary, helper binary, and protocol version must match.
- Monitor early releases for helper startup failures, stale-rule recovery,
  root-manager incompatibilities, and VPN lockdown confusion.

### Exit criteria

- Release code has one root-required Android architecture: app-UID data plane
  plus root helper.
- The old complete-runtime `su` path is absent from production code.
- Documentation and diagnostics describe actual behavior.
- The final routing and cleanup acceptance matrix is green.

## Suggested Implementation Sequence by Pull Request

Keep changes reviewable and avoid combining the entire migration in one pull
request.

1. **ADR and baseline evidence**
   - Record reproduction, architecture decision, protocol choice, and threat
     model.
2. **Protocol types and tests**
   - Add versioned messages, framing, validation, and fuzz/property tests with
     no runtime integration.
3. **In-process abstractions**
   - Introduce interceptor/flow-control interfaces while preserving all
     existing behavior.
4. **Mock helper and remote client**
   - Implement the state machines against a fake interceptor and fake process
     supervision.
5. **Root-helper executable**
   - Add real NFQUEUE/firewall ownership, authentication, cleanup, and host
     lifecycle tests.
6. **Android build packaging**
   - Package the helper in full builds with artifact validation.
7. **Android dual-process runner**
   - Launch helper as root and data plane normally; implement coordinated
     lifecycle and JVM tests.
8. **Native remote-interceptor integration**
   - Enable root-required modes through the helper, including `proxy_scan`.
9. **Diagnostics and documentation**
   - Add UID/helper events, support bundle fields, UI messages, and testing
     guidance.
10. **Rooted-device routing and failure matrix**
    - Add evidence, fix compatibility issues, and make the new path production
      default.
11. **Legacy removal and hardening**
    - Delete production all-root launch, complete security review, and close
      documented gaps.

Each pull request should list the exact tests run and should preserve a usable
rootless build. Do not merge a production-enabled intermediate state that can
install rules without reliable cleanup.

## Final Definition of Done

Before closing the issue, verify every item:

- [ ] Root-required Android modes launch the data plane as the app UID.
- [ ] Only the helper is launched through `su`.
- [ ] The helper authenticates the app-UID peer using kernel credentials.
- [ ] The protocol is versioned, bounded, validated, and fuzz/property tested.
- [ ] Flow registration is acknowledged before upstream `connect`.
- [ ] The helper owns NFQUEUE and its firewall lifetime.
- [ ] The helper creates no Internet-facing sockets.
- [ ] All scanners, DNS, probes, relays, and tests run under the app UID.
- [ ] `sni_spoof`, `ip_bypass_plus`, and `proxy_scan` pass rooted-device tests.
- [ ] Rootless and `tls_frag` paths never launch the helper.
- [ ] Normal stop, force stop, process death, app death, and stale startup clean
      or safely recover ZeroDPI-owned firewall state.
- [ ] Excluding the ZeroDPI package routes its upstream sockets outside a normal
      upstream VPN.
- [ ] VPN lockdown limitations are detected or clearly documented.
- [ ] Linux, Termux, Windows, packaging, and workspace regression tests pass.
- [ ] Production code contains no silent all-root-runtime fallback.
- [ ] Android README, testing documentation, diagnostics, and release notes are
      updated.

Only after this checklist is complete should the UID-routing issue be
considered fully fixed for normal Android per-app VPN exclusion.
