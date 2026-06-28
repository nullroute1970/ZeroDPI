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
  available, NFQUEUE startup and cleanup, and graceful stop after backgrounding.
- Android compatibility: executable/JNI packaging behavior, foreground service
  behavior, and Android 13+ notification permission behavior.
