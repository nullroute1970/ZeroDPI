# ZeroDPI Android Testing

Run JVM tests from `android/`:

```powershell
.\gradlew.bat testDebugUnitTest
```

Build the instrumented test APK:

```powershell
.\gradlew.bat assembleDebugAndroidTest
```

Run rootless instrumented tests on an emulator or phone:

```powershell
.\gradlew.bat connectedDebugAndroidTest
```

Rooted-device diagnostics are isolated behind an explicit instrumentation
argument so normal CI and non-root devices skip them clearly:

```powershell
.\gradlew.bat connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.zerodpi.runRootTests=true
```

Device coverage checklist:

- Non-root device: settings save/reopen, SNI/IP list save/reopen, `sni_scan`,
  `ip_scan`, `ip_bypass`, and `sni_spoof` with `tls_frag`.
- Rooted device: `su` grant and deny behavior, `iptables`, `nftables` when
  available, NFQUEUE startup and cleanup, graceful/forced stop, helper or data
  plane kill, repeated start/stop, and stale-state recovery.
- Android compatibility: executable/JNI packaging behavior, foreground service
  behavior, and Android 13+ notification permission behavior.

## Privilege-separation acceptance

Build a full APK and verify both artifacts are present:

```powershell
python build.py --platform android-app --android-app-runtime full --android-app-abi arm64-v8a --android-app-build-type debug
```

On a rooted physical device, record the package UID, helper PID/UID, and data
plane PID/UID from the app log and `ps`. The helper must be UID 0; all three
data-plane UIDs reported by native startup must equal the package UID. Inspect
`/proc/<helper-pid>/fd` during scanning and relay traffic: only local Unix IPC
and netlink/NFQUEUE descriptors are expected, never Internet TCP or UDP.

For both iptables and nftables where available, capture firewall state before,
during, and after these cases: normal stop, notification stop, forced stop,
data-plane kill, helper kill, service destruction, and repeated start/stop.
After an intentional helper SIGKILL, the next start must report targeted stale
state recovery and leave no `zerodpi-<pid>` rule or
`zerodpi_<pid>_<counter>` table after stopping.

Connect an upstream VPN that supports per-app exclusion, exclude
`dev.zerodpi.android`, and exercise interception-based `sni_spoof`,
`ip_bypass_plus`, and a multi-candidate `proxy_scan`. With lockdown disabled,
map the data-plane sockets through `/proc` and capture the VPN and physical
interfaces: the ZeroDPI upstream connection must be owned by the package UID
and use the underlying network. Repeat once with lockdown enabled and confirm
the expected blocked-excluded-app condition is reported rather than treated
as a helper or root failure.
