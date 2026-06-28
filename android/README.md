# ZeroDPI Android App

This is the native Android controller for ZeroDPI. The app prepares
app-private runtime files, starts the packaged ZeroDPI executable, displays
JSON runtime events, and provides config/list editing, import/export, reset to
defaults, logs, scan results, and support bundle export.

The app does not implement an Android `VpnService`. Point the upstream VPN
client at the local ZeroDPI listener from `config.toml`, usually
`127.0.0.1:44444`.

## Runtime Modes

- Rootless builds package the ZeroDPI CLI and run modes that do not need packet
  interception, such as `ip_bypass`, scan modes, and supported `tls_frag`
  workflows.
- Full builds package the same app with root-capable runtime assets. Modes that
  use Android/Linux packet interception request `su` and use the configured
  firewall backend.
- Debug app builds may use `FakeZeroDpiRunner` when no native artifact is
  packaged, so UI and service tests can run from Gradle alone. Release builds
  fail loudly if the native artifact is missing.

The native executable is packaged as `libzerodpi_exec.so` under
`jniLibs/<abi>/` and is extracted to the app native library directory at
install time.

## Build

From the repository root:

```powershell
python build.py --platform android
```

Useful options:

```powershell
python build.py --platform android --android-app-runtime rootless
python build.py --platform android --android-app-runtime full
python build.py --platform android --android-app-abi x86_64 --android-app-build-type debug
```

The APK is copied to:

```text
dist/android-app/<runtime>/zerodpi-android-<runtime>-<build-type>.apk
```

The default public ABIs are `arm64-v8a` and `armeabi-v7a`. Use `x86_64` for
emulator smoke tests.

## Install And Smoke Test

```powershell
adb install -r dist/android-app/rootless/zerodpi-android-rootless-debug.apk
adb shell am start -n dev.zerodpi.android/.MainActivity
```

After pressing Start, the session log should show `Loaded ... config` and
`Listening on ...`. It should not show `Using fake ZeroDPI runner` when the APK
was built through `build.py` with native runtime artifacts.
