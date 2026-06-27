# ZeroDPI Android App

This is the separate native Android app scaffold for ZeroDPI.

Current Phase 4 scope:

- Kotlin Android application module under `android/app`.
- Jetpack Compose dashboard UI.
- Bound foreground service for the ZeroDPI runtime.
- Service-owned `ZeroDpiRunner` interface.
- `FakeZeroDpiRunner` for UI and service lifecycle testing without a native binary.
- `ProcessZeroDpiRunner` placeholder for the process-wrapper MVP once
  `dist/android-app/<runtime>/jniLibs/<abi>/libzerodpi_exec.so` is packaged
  into the APK.
- App-private runtime storage under `files/zerodpi/`.
- First-launch defaults copied from packaged assets:
  `config.toml`, `sni_list.txt`, and `ip_list.txt`.
- Raw runtime file editor with Save and Reset to defaults actions.
- Atomic runtime file saves with `.bak` backups.
- `logs/` and `scan_results/` runtime directories.
- AndroidX dependencies are pinned to the AGP 8.13 / compileSdk 36 generation.

Build the APK from the repository root:

```powershell
python build.py --platform android
```

The APK is copied to `dist/android-app/<runtime>/zerodpi-android-<runtime>-debug.apk`.
Pass `--android-app-build-type release` to assemble the release variant.

The first run uses the fake runner unless an extracted native artifact named
`libzerodpi_exec.so` exists in the app native library directory.
