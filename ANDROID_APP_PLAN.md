# ZeroDPI Native Android App Plan

This document is a planning artifact only. It does not implement the Android
app. Use it as a phased checklist for building a separate native Android UI
that controls ZeroDPI on Android.

## Confirmed Product Scope

Phase 0 is confirmed as of 2026-06-27. This is the scope record to use before
any Android app scaffolding starts.

First version scope:

- Distribution is sideload-only APK releases from GitHub.
- The initial Android `minSdk` is Android 6.0 / API 23.
- First public release ABIs are `arm64-v8a` and `armeabi-v7a`.
- `x86_64` is allowed for debug and emulator builds, but it is not required for
  the first public sideload release.
- The MVP runtime uses a process-wrapper/root-helper runner that starts a
  headless `zerodpi` executable.
- The runner must remain replaceable so a JNI/native-library runner can be added
  later without rewriting the Android UI.
- The app manages ZeroDPI configuration and runtime files in app-private
  storage.
- Users must configure their upstream VPN app to connect to
  `127.0.0.1:LISTEN_PORT`.
- A raw TOML editor is required from day one, even if structured settings are
  incomplete.
- Root is requested only when the selected mode and bypass method require
  packet interception.
- Non-root settings, list editing, scan-only, plain relay, and socket-only
  `tls_frag` workflows remain usable on non-root devices where the underlying
  ZeroDPI mode supports them.

Explicit first-version non-goals:

- The app is not a standalone Android VPN client.
- The app will not implement Android `VpnService`.
- The first version is not Play Store compatible.
- The first version will not deep-link into, rewrite, or automatically manage
  upstream VPN app profiles.
- The normal APK workflow will not require Termux.
- The MVP will not start with a JNI/native-library refactor unless the
  process-wrapper approach is proven unworkable.

## Goals

- Build a separate native Android app that acts as a UI and controller for
  ZeroDPI.
- Let users edit, validate, save, import, and export the full `config.toml`
  surface.
- Let users edit and save `sni_list.txt` and `ip_list.txt`.
- Let users start and stop ZeroDPI from the app.
- Ask for root only when the selected mode and bypass method require packet
  interception.
- Keep non-root features usable on non-root devices.
- Avoid turning the app into a full VPN client in the first version. ZeroDPI
  remains a local TCP proxy that an upstream VPN client connects to.

## Working Assumptions

- The Android app will live in a separate top-level directory such as
  `android/`, while the Rust workspace remains under `crates/`.
- The first production-grade UI stack should be Kotlin, Jetpack Compose, and
  Material 3.
- The app should run a headless ZeroDPI runtime, not the ratatui TUI.
- Runtime files should live under the app's private storage:
  `config.toml`, `sni_list.txt`, `ip_list.txt`, logs, and scan outputs.
- Root is not an Android runtime permission. The app should request root by
  invoking `su` only when a root-required action is started.
- Rootless operation should remain available for socket-only and scan-only
  workflows.

## Product Decisions

- Distribution: sideload-only APK releases from GitHub.
- Minimum Android target for the first implementation: Android 6.0 / API 23.
  This matches the repository's current Android build helper default. API 21
  can be investigated later as a compatibility experiment, but API 23 is the
  lowest practical first target without changing the existing Rust/NDK baseline.
- First public ABIs: `arm64-v8a` and `armeabi-v7a`.
  - `arm64-v8a` covers modern Android phones.
  - `armeabi-v7a` keeps older 32-bit ARM devices in scope.
  - `x86_64` can be added for emulator/debug builds, but is not required for
    the first sideload release.
- The app will not use Android `VpnService`. Upstream apps such as v2rayNG or
  HAPP will provide the VPN service and should be configured to connect to
  ZeroDPI's local listener.
- A raw TOML editor is required from day one, alongside or before the structured
  settings UI.
- Rooted Android support should be a standalone APK feature using generic
  `su`. Do not require Termux for the app's normal rooted workflow. Existing
  Termux usage remains a separate/manual path.

## Runtime Implementation Decision

1. **First implementation: process-wrapper/root-helper**
   - Build an Android-targeted `zerodpi` executable and have the app start it
     with `--no-tui`.
   - For root-required modes, ask the device's root manager through `su` and
     run ZeroDPI directly as root from the app workflow.
   - Do not require Termux for normal app operation.
   - This is the fastest path to a usable UI and matches the existing ZeroDPI
     CLI.
   - Main Android compatibility risk: modern Android restricts
     executing code from writable app data. This path must be validated on the
     target SDK and Android versions before relying on it.

2. **Deferred option: JNI/native library runtime**
   - Refactor the CLI runtime into a reusable Rust library with a small JNI
     boundary.
   - The Android service calls Rust functions directly instead of spawning a
     child process.
   - Consider this later only if the process-wrapper approach causes lifecycle,
     packaging, validation, or rootless integration problems.

Keep the runner behind an interface so a JNI runner can be added later without
rewriting the UI.

## Root And Feature Matrix

The app should compute this from `MODE` and `BYPASS_METHOD` before Start.

| Feature | Root needed | Notes |
| --- | --- | --- |
| Edit settings | No | Always available. |
| Edit `sni_list.txt` | No | Always available. |
| Edit `ip_list.txt` | No | Always available. |
| `MODE = "sni_scan"` | No | Scan only, no packet interceptor. |
| `MODE = "ip_scan"` | No | Scan only, no packet interceptor. |
| `MODE = "ip_bypass"` | No | Plain TCP relay, no packet interceptor. |
| `MODE = "sni_spoof"` and `BYPASS_METHOD = "tls_frag"` | No | Socket-based fragmentation. |
| `MODE = "ip_bypass_plus"` and `BYPASS_METHOD = "tls_frag"` | No | Socket-based real-SNI fragmentation. |
| `MODE = "proxy_scan"` and `BYPASS_METHOD = "tls_frag"` | No | Still requires a reachable local SOCKS5 proxy if configured that way. |
| `MODE = "sni_spoof"` and any non-`tls_frag` method | Yes | Uses NFQUEUE packet interception on Android/Linux. |
| `MODE = "ip_bypass_plus"` and `BYPASS_METHOD = "tls_record_frag"` | Yes | Uses NFQUEUE packet interception. |
| `MODE = "proxy_scan"` and any non-`tls_frag` method | Yes | Current privilege check treats it as interception-required. |

Root-required startup should also check:

- `su` exists and returns UID 0 with `su -c id -u`.
- The selected firewall backend command exists: `iptables` or `nft`.
- The kernel/userspace path supports NFQUEUE on the device.
- ZeroDPI can clean up firewall rules on graceful shutdown.

## Phase 0: Confirm Product Scope

Status: complete. The confirmed scope record is the
[Confirmed Product Scope](#confirmed-product-scope) section above.

Completed decisions:

- [x] Use sideload-only GitHub APK releases as the initial distribution model.
- [x] Use Android 6.0 / API 23 as the initial `minSdk`.
- [x] Build first for `arm64-v8a` and `armeabi-v7a`.
- [x] Keep `x86_64` as an optional debug/emulator ABI.
- [x] Prioritize the process-wrapper/root-helper MVP first, while keeping the
  runner replaceable.
- [x] Do not implement Android `VpnService`.
- [x] Instruct users to point their upstream VPN app at
  `127.0.0.1:LISTEN_PORT`.
- [x] Do not try to deep-link or rewrite upstream VPN profiles in the first
  version.
- [x] Include a raw TOML editor from day one.

Acceptance criteria:

- [x] Product scope is recorded before app scaffolding starts.
- [x] Non-goals are explicit, especially "not a standalone Android VPN client"
  and "not Play Store compatible" for the first version.

## Phase 1: Define Android-Facing ZeroDPI Contract

Status: complete. Implemented in the CLI as of 2026-06-27.

Create a small, stable control contract between Android and ZeroDPI before UI
work gets deep.

Steps:

- [x] Add a headless run mode contract for Android:
  - command shape: `zerodpi --config <path> --no-tui --auto-select`,
  - stop shape: send SIGTERM and wait for graceful cleanup,
  - fallback stop: kill only after timeout.
- [x] Define machine-readable runtime status:
  - minimum acceptable MVP: parse headless logs,
  - implemented preferred path: add `--json-events` to stream structured
    newline-delimited JSON events on stdout while logs remain on stderr.
- [x] Define events the app needs:
  - startup,
  - config loaded,
  - scan started,
  - scan progress,
  - selected SNI or IP,
  - listener started,
  - connection accepted,
  - bypass completed or failed,
  - relay bytes,
  - active target changed,
  - fatal error,
  - graceful shutdown.
- [x] Define process exit semantics:
  - exit code `0`: stopped or scan completed,
  - non-zero: show error and retain logs,
  - root denial: show root-required explanation and rootless alternatives.

Acceptance criteria:

- [x] The Android side can start ZeroDPI without the TUI.
- [x] The Android side can stop ZeroDPI gracefully.
- [x] Logs or JSON events are enough to show useful dashboard state.

## Phase 2: Build Android ZeroDPI Runtime Artifacts

Steps:

- Reuse the existing Android/Termux Rust target knowledge in `build.py`.
- Produce ABI-specific artifacts for app packaging.
- Validate whether the existing `nfq` dependency works on Android app builds:
  - if it requires unavailable shared libraries, rootless modes can still ship
    first,
  - rooted NFQUEUE support may need either bundled native dependencies or a
    Rust/netlink implementation that avoids external `libnetfilter_queue`.
- For process-wrapper MVP:
  - verify where Android allows the executable to live for the chosen
    `targetSdk`,
  - do not depend on executing files copied into writable app data unless it is
    proven on target devices,
  - consider packaging ABI-specific executables as extracted native artifacts
    only if compatible with Android policy.
- For JNI:
  - create a Rust `cdylib` wrapper around reusable ZeroDPI runtime functions,
  - expose start, stop, validate config, and event callback APIs,
  - keep CLI support intact for desktop and Termux.

Acceptance criteria:

- `arm64-v8a` and `armeabi-v7a` artifacts can start on physical Android
  devices, or `armeabi-v7a` is explicitly deferred with a known blocker.
- Rootless mode can bind the configured local listener.
- Root-required mode fails clearly when root or NFQUEUE support is missing.
- The process-wrapper/root-helper runner is validated on real Android 6.0+
  devices.

## Phase 3: Scaffold The Separate Android App

Status: complete. Implemented under `android/` as of 2026-06-27.

Future file layout:

```text
android/
  settings.gradle.kts
  build.gradle.kts
  app/
    build.gradle.kts
    src/main/AndroidManifest.xml
    src/main/java/.../
```

Steps:

- [x] Create a Kotlin Android app module.
- [x] Use Jetpack Compose for UI.
- [x] Use a foreground service for running ZeroDPI because the proxy must continue
  while the user leaves the UI.
- [x] Add required Android permissions:
  - `INTERNET`,
  - foreground service permission(s),
  - notification permission flow for Android 13+ if notifications are shown.
- [x] Add one service-owned runtime controller:
  - `ZeroDpiRunner` interface,
  - `ProcessZeroDpiRunner` implementation for MVP,
  - later `JniZeroDpiRunner`.
- [x] Keep UI state in a ViewModel that observes service state.

Acceptance criteria:

- [x] App launches to the dashboard.
- [x] Service can be bound from the UI.
- [x] Fake runner can drive UI without a real ZeroDPI binary.

## Phase 4: Runtime Storage Model

Status: complete. Implemented under `android/` as of 2026-06-27.

Steps:

- [x] Create an app-private runtime directory:
  - `files/zerodpi/config.toml`,
  - `files/zerodpi/sni_list.txt`,
  - `files/zerodpi/ip_list.txt`,
  - `files/zerodpi/logs/`,
  - `files/zerodpi/scan_results/`.
- [x] On first launch:
  - copy default config/list templates,
  - preserve user edits on upgrades,
  - add "Reset to defaults" actions.
- [x] Save files atomically:
  - write to temp file,
  - fsync where practical,
  - rename into place.
- [x] Keep simple backups:
  - `config.toml.bak`,
  - previous `sni_list.txt`,
  - previous `ip_list.txt`.
- [x] Resolve relative paths in config to the runtime directory.

Acceptance criteria:

- [x] Users can edit config and lists, close the app, reopen, and see saved
  data.
- [x] Corrupt saves do not destroy the last known good config.

## Phase 5: Full Config Settings UI

Use a typed config model plus a schema so the UI covers every field in
`config.toml`. The schema should include field name, type, default, section,
validation rule, root impact, and help text.

Recommended guard against drift:

- Add a test or script that compares Android schema field names to Rust
  `Config` fields.
- Keep a raw TOML editor/import/export view as an escape hatch.
- The raw TOML editor is required in the first usable build, even if the
  structured settings UI is still incomplete.
- Validate by calling the same Rust validation logic when JNI exists, or by
  running `zerodpi --validate-config <path>` if a CLI validation command is
  added later.

Settings sections and field coverage:

| Section | Fields |
| --- | --- |
| Proxy listener | `LISTEN_HOST`, `LISTEN_PORT` |
| Operating mode | `MODE`, `AUTO_SELECT`, `SELECTED_SNI`, `SELECTED_IP` |
| Input files | `SNI_LIST`, `IP_LIST` |
| Scan behavior | `SCAN_TIMEOUT_SECS`, `RESCAN_INTERVAL_SECS`, `SNI_SWITCH_MIN_SCORE`, `SCAN_OUTPUT` |
| Scanner tuning | `SNI_MAX_CONCURRENT`, `IP_MAX_P1_CONCURRENT`, `IP_MAX_P2_CONCURRENT`, `SCAN_DOWNLOAD_CAP`, `SCAN_UPLOAD_CAP`, `SCAN_UPLOAD_PATH`, `IP_SCAN_SNI`, `IPV6_MAX_HOSTS` |
| Scoring | `TCP_LATENCY_CAP_MS`, `TLS_LATENCY_CAP_MS`, `TTFB_CAP_MS`, `SPEED_CAP_BPS`, `UPLOAD_SPEED_CAP_BPS` |
| Bypass engine | `BYPASS_METHOD`, `BYPASS_TIMEOUT_SECS`, `RELAY_MAX_LIFETIME_SECS` |
| Android/Linux interception | `NFQUEUE_NUM`, `LINUX_FIREWALL_BACKEND` |
| `wrong_seq` | `WRONG_SEQ_EXTRA_OFFSET`, `WRONG_SEQ_SET_PSH`, `WRONG_SEQ_BUMP_IP_IDENT` |
| `wrong_checksum` | `WRONG_CHECKSUM_DELTA`, `WRONG_CHECKSUM_SET_PSH`, `WRONG_CHECKSUM_BUMP_IP_IDENT`, `WRONG_CHECKSUM_COMPLETE_IMMEDIATELY` |
| `wrong_md5` | `WRONG_MD5_SET_PSH`, `WRONG_MD5_BUMP_IP_IDENT`, `WRONG_MD5_COMPLETE_IMMEDIATELY` |
| `wrong_ack` | `WRONG_ACK_OFFSET`, `WRONG_ACK_SET_PSH`, `WRONG_ACK_BUMP_IP_IDENT`, `WRONG_ACK_COMPLETE_IMMEDIATELY` |
| `wrong_timestamp` | `WRONG_TIMESTAMP_OFFSET`, `WRONG_TIMESTAMP_SET_PSH`, `WRONG_TIMESTAMP_BUMP_IP_IDENT`, `WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY` |
| `tls_record_frag` | `TLS_RECORD_FRAG_SIZE`, `TLS_RECORD_FRAG_SET_PSH`, `TLS_RECORD_FRAG_BUMP_IP_IDENT` |
| `tls_frag` | `TLS_FRAG_PACKETS`, `TLS_FRAG_LENGTH`, `TLS_FRAG_INTERVAL_MS`, `TCP_SEG_SIZE`, `TCP_SEG_NODELAY` |
| Proxy scan | `PROXY_TEST_MIN_SNI_SCORE`, `PROXY_TEST_TOP_N`, `PROXY_TEST_SOCKS5_HOST`, `PROXY_TEST_SOCKS5_PORT`, `PROXY_TEST_URL`, `PROXY_TEST_TIMEOUT_SECS`, `PROXY_TEST_SNI_WEIGHT`, `PROXY_TEST_LATENCY_CAP_MS`, `PROXY_TEST_TTFB_CAP_MS`, `PROXY_TEST_SPEED_CAP_BPS` |

Validation rules to mirror:

- `SCAN_TIMEOUT_SECS > 0`.
- `BYPASS_TIMEOUT_SECS > 0`.
- `SNI_SWITCH_MIN_SCORE <= 100`.
- `SCAN_DOWNLOAD_CAP > 0`.
- `SCAN_UPLOAD_CAP > 0`.
- `SCAN_UPLOAD_PATH` must be non-empty, start with `/`, and contain no CR/LF.
- `SPEED_CAP_BPS` and `UPLOAD_SPEED_CAP_BPS` must be finite and greater than
  `0`.
- `SELECTED_SNI` must not exceed the Rust SNI maximum.
- `BYPASS_METHOD` must be one of the supported method strings.
- `WRONG_CHECKSUM_DELTA >= 1`.
- `WRONG_ACK_OFFSET >= 1`.
- `WRONG_TIMESTAMP_OFFSET >= 1`.
- `TLS_RECORD_FRAG_SIZE >= 1`.
- `TCP_SEG_SIZE >= 1` and `TCP_SEG_SIZE <= i32::MAX`.
- `TLS_FRAG_PACKETS` must be `tlshello`, a 1-based index, or a 1-based range
  whose end is not lower than start.
- `TLS_FRAG_LENGTH` must be an integer or inclusive range with minimum `>= 1`.
- `TLS_FRAG_INTERVAL_MS` must be an integer or inclusive range with minimum
  `>= 0`.
- `LINUX_FIREWALL_BACKEND` must be `iptables` or `nftables`.
- `MODE` must be one of `sni_spoof`, `ip_bypass`, `ip_bypass_plus`,
  `sni_scan`, `ip_scan`, `proxy_scan`.
- `MODE = "ip_bypass_plus"` supports only `BYPASS_METHOD = "tls_record_frag"`
  or `BYPASS_METHOD = "tls_frag"`.
- `PROXY_TEST_SNI_WEIGHT` must be in `[0.0, 1.0]`.
- `PROXY_TEST_TIMEOUT_SECS > 0`.
- `SELECTED_IP`, when set, must parse as an IP address.
- `MODE = "ip_bypass_plus"` rejects IPv6 `SELECTED_IP`.

Acceptance criteria:

- Every Rust `Config` field has a UI control or raw advanced editor coverage.
- Invalid configs cannot be started.
- The app explains root impact before asking for root.

## Phase 6: List Editors

Steps:

- Add an SNI list page:
  - multiline editor,
  - one hostname per line,
  - preserve comments and blank lines if practical,
  - validate obvious invalid hostnames,
  - import from text file,
  - export/share as text.
- Add an IP list page:
  - multiline editor,
  - one IP or CIDR per line,
  - preserve comments and blank lines if practical,
  - validate IPv4, IPv6, and CIDR syntax,
  - warn that `ip_bypass_plus` is IPv4-only,
  - import/export/share.
- Add "test scan" actions:
  - run `sni_scan`,
  - run `ip_scan`,
  - save results to `SCAN_OUTPUT` if configured.

Acceptance criteria:

- Users can edit and save both lists.
- Invalid entries are highlighted before start where possible.
- Scan-only workflows work without root.

## Phase 7: Dashboard And Start/Stop Flow

Dashboard content:

- Current status: stopped, starting, scanning, running, stopping, failed.
- Root status: not needed, needed, granted, denied, unsupported.
- Current mode and bypass method.
- Listener address: `LISTEN_HOST:LISTEN_PORT`.
- Active SNI/IP and score when known.
- Connection count and relay byte counters when available.
- Last error and recent logs.
- Primary action: Start or Stop.

Start sequence:

1. Load typed settings from UI state.
2. Validate settings.
3. Save `config.toml`, `sni_list.txt`, and `ip_list.txt`.
4. Determine whether root is required.
5. If root is required, show explanation and request root with `su`.
6. Start foreground service.
7. Start ZeroDPI with the selected runner.
8. Stream status and logs into the dashboard.

Stop sequence:

1. Disable Start until stop completes.
2. Send graceful termination.
3. Wait for ZeroDPI to exit and clean up firewall rules.
4. If timeout expires, offer force stop.
5. Store final logs.

Acceptance criteria:

- Start works for at least one rootless mode.
- Stop returns the app to a clean stopped state.
- Root denial does not block rootless features.

## Phase 8: Root Manager

Steps:

- Build a `RootManager` abstraction:
  - `isRootAvailable()`,
  - `requestRootFor(reason)`,
  - `runAsRoot(command)`,
  - `stopRootProcess(pid)`.
- Trigger root prompt only from a user action:
  - starting root-required mode,
  - running root diagnostics.
- Show root explanation before invoking `su`:
  - why root is needed,
  - which mode/method needs it,
  - which non-root alternatives are available.
- Invoke the device root manager directly via `su`; do not shell out through
  Termux and do not require Termux to be installed.
- Cache root state only for the app session.
- Do not hide root failure. Surface `su` stderr and exit status in diagnostics.
- Add diagnostics:
  - `id -u`,
  - `which iptables`,
  - `which nft`,
  - kernel/NFQUEUE checks where possible,
  - ZeroDPI dry startup if a validation command exists later.

Acceptance criteria:

- Root is never requested for rootless actions.
- Root-required starts fail with actionable errors.
- The app can run rootless workflows after root was denied.

## Phase 9: Logs, Diagnostics, And Support Bundle

Steps:

- Capture stdout/stderr or JSON events from ZeroDPI.
- Keep current session logs in memory.
- Persist recent logs under `files/zerodpi/logs/`.
- Add a diagnostics page:
  - app version,
  - ZeroDPI version,
  - ABI,
  - Android version,
  - root status,
  - firewall backend availability,
  - config validation result,
  - last exit code.
- Add "export support bundle":
  - config with sensitive fields reviewed,
  - logs,
  - device diagnostics,
  - no private production lists unless user explicitly includes them.

Acceptance criteria:

- A failed start leaves enough information to debug.
- Export does not silently leak private SNI/IP lists.

## Phase 10: Testing Plan

Rust tests:

- Keep running `cargo fmt --all -- --check`.
- Keep running `cargo clippy --workspace --all-targets -- -D warnings`.
- Keep running `cargo test --workspace`.
- Add tests for any new CLI validation or JSON event mode.

Android unit tests:

- Config TOML round-trip.
- Schema covers all Rust `Config` fields.
- Root requirement matrix.
- Root manager with fake `su`.
- Process runner with fake ZeroDPI executable.

Android instrumented tests:

- Settings edit/save/reopen.
- SNI and IP list edit/save/reopen.
- Dashboard state transitions with fake runner.
- Foreground service lifecycle.
- Notification stop action.

Device tests:

- Non-root emulator or phone:
  - settings,
  - list editors,
  - `sni_scan`,
  - `ip_scan`,
  - `ip_bypass`,
  - `sni_spoof` with `tls_frag`.
- Rooted physical device:
  - `su` grant and deny paths,
  - supported `su` implementation behavior,
  - `iptables` backend,
  - `nftables` backend if available,
  - NFQUEUE startup and cleanup,
  - graceful stop after app backgrounding.
- Android version compatibility:
  - executable/JNI packaging behavior,
  - foreground service behavior,
  - notification permission behavior.

Acceptance criteria:

- Rootless regression tests pass without root.
- Root-specific tests are isolated and clearly skipped when root is absent.

## Phase 11: Documentation

App documentation should include:

- What ZeroDPI does and does not do.
- How to configure the upstream VPN client:
  - set server/address to `127.0.0.1`,
  - set port to `LISTEN_PORT`,
  - keep the VPN profile's real SNI/server name where appropriate.
- Which modes require root.
- Which modes work without root.
- How to choose `tls_frag` for rootless usage.
- How to restore default config and lists.
- How to export logs safely.

Repository documentation should include:

- Android build prerequisites.
- ABI build commands.
- Debug install command.
- Release signing notes.
- Rooted device test notes.

## Suggested Milestones

1. **M1: Contract and schema**
   - Config schema exists.
   - Root requirement matrix exists in code/tests.
   - ZeroDPI has a mobile-friendly validation/status contract planned or added.

2. **M2: UI shell**
   - Native Android app opens.
   - Dashboard, settings, SNI list, IP list, logs pages exist with fake data.

3. **M3: Config and list persistence**
   - Full config editing works.
   - TOML save/load works.
   - SNI/IP list editing works.

4. **M4: Rootless runtime**
   - App starts/stops a rootless ZeroDPI mode.
   - Foreground service and logs work.

5. **M5: Rooted runtime**
   - App requests root only when needed.
   - NFQUEUE modes can start/stop on rooted devices.
   - Firewall cleanup is verified.

6. **M6: Polish and release**
   - Diagnostics and support bundle.
   - Import/export.
   - Device compatibility matrix.
   - Signed APK build.

## References Checked

- Android foreground services:
  <https://developer.android.com/develop/background-work/services/foreground-services>
- Android foreground service declaration and types:
  <https://developer.android.com/develop/background-work/services/fgs/declare>
- Android NDK guides:
  <https://developer.android.com/ndk/guides>
- Add native code to Android projects:
  <https://developer.android.com/studio/projects/add-native-code>
- Android 10 behavior changes:
  <https://developer.android.com/about/versions/10/behavior-changes-10>
