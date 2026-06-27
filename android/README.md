# ZeroDPI Android App

This is the separate native Android app scaffold for ZeroDPI.

Current Phase 3 scope:

- Kotlin Android application module under `android/app`.
- Jetpack Compose dashboard UI.
- Bound foreground service for the ZeroDPI runtime.
- Service-owned `ZeroDpiRunner` interface.
- `FakeZeroDpiRunner` for UI and service lifecycle testing without a native binary.
- `ProcessZeroDpiRunner` placeholder for the process-wrapper MVP once
  `dist/android-app/<runtime>/jniLibs/<abi>/libzerodpi_exec.so` is copied into
  the app module.
- AndroidX dependencies are pinned to the AGP 8.13 / compileSdk 36 generation.

Build from this directory with Android Studio or an installed Gradle:

```powershell
cd android
gradle :app:assembleDebug
```

The first run uses the fake runner unless an extracted native artifact named
`libzerodpi_exec.so` exists in the app native library directory.
