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
- Full builds package an app-UID data plane plus a dedicated root helper.
  Interception-based modes start only the helper through `su`; scanners,
  listeners, upstream sockets, and relays remain owned by the Android app UID.
  The app fails closed if helper authentication or setup fails and never
  falls back to running the complete runtime as root.
- Debug app builds may use `FakeZeroDpiRunner` when no native artifact is
  packaged, so UI and service tests can run from Gradle alone. Release builds
  fail loudly if the native artifact is missing.

The data-plane executable is packaged as `libzerodpi_exec.so` under
`jniLibs/<abi>/`. Full builds also package
`libzerodpi_root_helper_exec.so`; rootless builds omit it. Both are extracted
to the app native library directory at install time. The security boundary
and protocol are documented in [PRIVILEGE_SEPARATION.md](PRIVILEGE_SEPARATION.md).

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

Release builds require signing. `build.py` reads the local signing properties
from:

```text
Windows: C:\Drive\Projects\ZeroDPI\zerodpi-release-signing.properties
Linux: /home/mahmood/Drive/Projects/ZeroDPI/zerodpi-release-signing.properties
```

That file points at the existing release keystore:

```text
Windows: C:\Drive\Projects\ZeroDPI\zerodpi-release.jks
Linux: /home/mahmood/Drive/Projects/ZeroDPI/zerodpi-release.jks
```

You can override the local file with `ZERODPI_RELEASE_SIGNING_PROPERTIES`, or
provide these Gradle properties or environment variables before building
`--android-app-build-type release`:

```text
ZERODPI_RELEASE_STORE_FILE_WINDOWS=C:\Drive\Projects\ZeroDPI\zerodpi-release.jks
ZERODPI_RELEASE_STORE_FILE_LINUX=/home/mahmood/Drive/Projects/ZeroDPI/zerodpi-release.jks
ZERODPI_RELEASE_STORE_PASSWORD=...
ZERODPI_RELEASE_KEY_ALIAS=...
ZERODPI_RELEASE_KEY_PASSWORD=...
```

`ZERODPI_RELEASE_STORE_FILE` is still supported as a single-path fallback.
`ZERODPI_RELEASE_KEY_PASSWORD` is optional when it matches the store password.
Use debug builds for local rooted-device smoke tests when no release key is
configured.

If release signing is not configured, `build.py` stops before running Gradle
instead of copying an unsigned release APK. The script does not generate or
rotate signing keys.

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

For a root-required mode, the log must show the root helper at UID 0 and the
data plane at the package UID. Exclude the ZeroDPI package—not UID 0—in the
upstream VPN client's per-app settings. Android block-without-VPN/lockdown may
intentionally block excluded applications; ZeroDPI cannot override that
device or VPN policy.

## Profiles

The Android app keeps runtime files in app-private profiles. Each profile has
its own editable `config.toml`, `sni_list.txt`, `ip_list.txt`, remote update
settings, and last update status. Starting ZeroDPI uses only the active profile.
Relative config paths such as `SNI_LIST = "sni_list.txt"` resolve inside the
active profile directory.

Fresh installs create one `Default` profile. Upgrades migrate the previous
single app-private runtime file set into `Default`.

The Home destination shows the active profile beside runtime readiness and the
primary Start/Stop action. Open Profiles to select another profile. If the
current profile has unsaved edits, choose `Save`, `Discard`, or `Cancel` before
the app switches.

The Profiles destination provides:

- `Create` adds a profile from the packaged default files.
- `Duplicate` copies the active profile's files and remote settings.
- `Rename` changes the active profile name.
- `Delete` removes the active profile's local config and list files. The last
  profile cannot be deleted.

Stop ZeroDPI before switching, deleting, or remotely updating profiles. The app
disables those actions while ZeroDPI is starting, scanning, running, or
stopping so the running process keeps using a stable file set.

## Local Edits

The Configure destination edits the active profile. Basic contains the common
listener, mode, input, and DNS fields; Advanced contains scanner tuning and
bypass controls. The SNI and IP summary cards open their dedicated list
editors. `Save` writes only that profile's file. `Reset to defaults` replaces
only the selected file in the active profile. Import, export, share, and test
scan actions also use the active profile.

Local edits remain local until you save, discard, reset, delete the profile, or
apply a successful remote update. Switching profiles reloads text from the new
active profile, so edits in profile A do not mutate profile B.

## Remote Profile Updates

Each profile can fetch a complete replacement file set from remote URLs. Open
Profiles and expand `Remote update`:

- `config.toml URL` points to the replacement config.
- `sni_list.txt URL` points to the replacement SNI list.
- `ip_list.txt URL` points to the replacement IP list.
- `Automatic update` enables background updates for this profile.
- `Automatic update interval hours` controls how often this profile becomes due
  for automatic update. The scheduler enforces a minimum interval of 1 hour.
- `Update now` runs a manual update.

All three URLs are required before a manual or automatic update can run. URLs
must be absolute `http://` or `https://` URLs. Prefer HTTPS. HTTP is accepted
but shown with a warning because it is not encrypted.

Remote update is all-or-nothing. The app downloads all three files, validates
`config.toml`, validates both lists, and then atomically replaces the profile's
local files. If any download, validation, or apply step fails, the previous
local files remain in place.

Manual update is user-triggered with `Update now`. If the active profile has
unsaved edits, the confirmation dialog warns that those edits will be
discarded. After a successful manual update, the editor reloads the remote
contents and you can edit locally again.

Automatic update is background WorkManager work. It uses the same validation
and all-or-nothing apply path as manual update, requires network connectivity,
and is deferred when Android reports low battery. If ZeroDPI is running when an
automatic update is due, the app records a skipped update instead of changing
files underneath the active runtime.

Remote updates overwrite local files after each successful update. A local edit
made after an update remains until the next successful manual or automatic
remote update for that profile.

Remote URLs can contain credentials or access tokens in query strings. Treat
the full URL as secret. Support bundles redact URL query strings, but
screenshots and copied profile metadata may not.

## Profile Update Troubleshooting

The `Remote update` panel shows `Last attempt`, `Last success`, `Last update`,
and the latest status message for the active profile. For support, open Support
and use `Export bundle`; the bundle includes profile id/name, sanitized remote
URLs, auto update settings, and last remote update status.

Common failures:

| Message or Symptom | What to Check |
|--------------------|---------------|
| `Configure all three valid URLs before updating.` | Fill `config.toml URL`, `sni_list.txt URL`, and `ip_list.txt URL`. A partial URL set is rejected. |
| `Remote URL must be an absolute http or https URL.` | Use a full URL with scheme and host, for example `https://example.com/zerodpi/config.toml`. |
| `HTTP <status> while downloading ...` | Check the remote server, path, authentication token, and whether the URL requires redirects or cookies. |
| Redirect errors | The app rejects missing redirect locations, unsupported redirect schemes, too many redirects, and redirects that change between HTTP and HTTPS. Use the final direct file URL when possible. |
| Empty or too-large response | The remote file must be non-empty. `config.toml` is limited to 512 KiB; each list is limited to 5 MiB. |
| `config.toml validation failed ...` | Fix the remote config. It must parse and pass the Android config validator before any profile file is overwritten. |
| `sni_list.txt validation failed ...` or `ip_list.txt validation failed ...` | Fix the remote list syntax. SNI lists use one hostname per line; IP lists use IP addresses or CIDR ranges. |
| Automatic update skipped because ZeroDPI is running | Stop ZeroDPI and run `Update now`, or wait for the next automatic interval after the runtime stops. |

To recover from a bad remote source, disable `Automatic update`, fix or clear
the URL fields, then edit the active profile locally or use `Reset to defaults`
on the affected config/list file.
