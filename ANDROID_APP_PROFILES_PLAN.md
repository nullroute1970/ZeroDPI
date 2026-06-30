# Android Profiles And Remote Update Plan

This document is a planning artifact only. It does not implement the feature.
Use it as a phased checklist for adding Android-only ZeroDPI profiles where
each profile owns its own `config.toml`, `sni_list.txt`, and `ip_list.txt`.

## Goal

Add multiple editable Android app profiles. Each profile must have:

- one editable `config.toml`,
- one editable `sni_list.txt`,
- one editable `ip_list.txt`,
- one remote URL for each of those three files,
- manual remote update,
- optional automatic remote update,
- easy switching between profiles.

Remote updates intentionally overwrite that profile's local config and lists.
After an update, users can edit the files locally again, but the next successful
remote update overwrites those local edits.

## Scope

Android-only scope:

- Change the native Android app under `android/`.
- Keep the Rust runtime and desktop/CLI behavior unchanged unless a later
  implementation discovers a strict runtime contract gap.
- Keep ZeroDPI start/stop behavior based on app-private files.

First implementation non-goals:

- No profile sync between devices.
- No authenticated remote sources unless a URL embeds credentials or tokens.
- No merge/conflict resolution between remote files and local edits.
- No hot profile switching while ZeroDPI is running.
- No live config reload of a running ZeroDPI process.

## Current Android Baseline

The current Android app has one app-private runtime file set:

- `files/zerodpi/config.toml`
- `files/zerodpi/sni_list.txt`
- `files/zerodpi/ip_list.txt`

Relevant existing code:

- `RuntimeStorage` seeds, reads, writes, resets, and prepares runtime files.
- `MainViewModel` mirrors one active runtime file set into `RuntimeFilesUiState`.
- `DashboardScreen` exposes the settings page and runtime list editors.
- `ZeroDpiService.startZeroDpi()` calls `RuntimeStorage.prepareRunConfig()` and
  starts ZeroDPI with the prepared config path and working directory.

The profile feature should be built by adding a profile layer under this flow,
not by changing how ZeroDPI reads config/list files.

## Proposed Storage Layout

Move runtime files into per-profile directories:

```text
files/zerodpi/
  profiles/
    index.json
    <profile-id>/
      config.toml
      config.toml.bak
      sni_list.txt
      sni_list.txt.bak
      ip_list.txt
      ip_list.txt.bak
      scan_results/
  logs/
```

Keep logs global at first. Keep scan results profile-local because config paths
and test scans are profile-specific.

Recommended profile id:

- generate a UUID or stable slug at creation time,
- never derive storage paths directly from editable profile names,
- validate ids before using them in paths.

Recommended `index.json` shape:

```json
{
  "schemaVersion": 1,
  "activeProfileId": "default",
  "profiles": [
    {
      "id": "default",
      "name": "Default",
      "createdAtEpochMs": 0,
      "updatedAtEpochMs": 0,
      "remote": {
        "configUrl": "",
        "sniListUrl": "",
        "ipListUrl": "",
        "autoUpdateEnabled": false,
        "autoUpdateIntervalHours": 24,
        "lastUpdateAttemptEpochMs": null,
        "lastSuccessfulUpdateEpochMs": null,
        "lastUpdateStatus": null
      }
    }
  ]
}
```

Use atomic writes for `index.json` and profile files, using the same durability
style as existing `RuntimeStorage`.

## Open Product Decisions

These are not blockers for writing the first implementation, but they should be
confirmed before final UI polish:

- Minimum automatic update interval: recommended default is 24 hours, with a
  lower bound of 6 hours to avoid abusive polling.
- Remote URL policy: recommended default is allow `https://` and `http://`, but
  show a warning for `http://`.
- Partial update policy: recommended default is all-or-nothing. Apply no files
  unless all three remote downloads succeed and pass validation.
- Running update policy: recommended default is defer remote updates while
  ZeroDPI is running, then let the user update manually after stop.
- Delete policy: recommended default is do not allow deleting the last profile.

## Phase 1: Add Profile Domain Model

Steps:

- Add Android profile model classes, likely under a new package:
  `dev.zerodpi.android.profile`.
- Define:
  - `ZeroDpiProfile`
  - `ProfileRemoteSettings`
  - `ProfileIndex`
  - `ProfileUpdateStatus`
  - `ProfileUpdateMode` for manual vs automatic update reporting.
- Add profile name validation:
  - non-empty,
  - trimmed,
  - reasonable max length such as 64 characters,
  - duplicate names allowed only if the UI can distinguish them; otherwise
    reject duplicates.
- Add remote URL validation:
  - blank means not configured,
  - configured profile update requires all three URLs,
  - accept only valid absolute `http` or `https` URLs,
  - warn on `http`.
- Add unit tests for model validation and JSON round trips.

Acceptance criteria:

- Profiles can be represented without touching existing runtime behavior.
- Profile metadata can be serialized and deserialized.
- Invalid ids or paths cannot escape the profile directory.

## Phase 2: Add Profile Repository And Migration

Steps:

- Add `ProfileRepository` responsible for:
  - loading `profiles/index.json`,
  - creating the default profile when no index exists,
  - creating, renaming, duplicating, deleting, and selecting profiles,
  - reading and writing profile metadata atomically,
  - returning file paths for a profile id.
- Add migration from the current single-profile layout:
  - if `profiles/index.json` is missing, create a `Default` profile,
  - if legacy `files/zerodpi/config.toml`, `sni_list.txt`, or `ip_list.txt`
    exist, copy them into the default profile,
  - otherwise seed default files from packaged assets,
  - leave legacy files untouched after a successful copy for one release, or
    move them into a `legacy_backup/` directory after explicit testing.
- Refactor reusable file helpers out of `RuntimeStorage` if needed:
  - atomic write,
  - backup path creation,
  - asset seeding,
  - directory fsync.
- Add repository-level locking so UI saves, service startup, and remote updates
  do not write the same profile concurrently.

Acceptance criteria:

- Existing Android users keep their current config/lists after upgrading.
- Fresh installs get one default profile.
- Profile metadata and files survive app restart.
- A corrupted `index.json` produces a recoverable error and does not delete
  profile files.

## Phase 3: Make RuntimeStorage Profile-Aware

Steps:

- Change `RuntimeStorage` APIs to accept a profile id or active profile handle:
  - `readAll(profileId)`
  - `save(profileId, kind, content)`
  - `saveAll(profileId, configText, sniListText, ipListText)`
  - `resetToDefaults(profileId, kind)`
  - `prepareRunConfig(profileId, modeOverride)`
  - `prepareConfiguredDirectories(profileId)`
  - `exportSupportBundle(profileId, ...)`
- Update `RuntimeStorageFiles` so `runtimeDir` points at the selected profile
  directory.
- Ensure relative config paths such as `SNI_LIST = "sni_list.txt"` resolve
  inside the selected profile directory.
- Keep temporary mode override configs inside the selected profile directory.
- Include profile name/id in support bundle metadata, but redact remote URL query
  strings because they may contain tokens.

Acceptance criteria:

- Starting ZeroDPI uses the selected profile's `config.toml`.
- SNI/IP relative paths resolve to the selected profile's files.
- Resetting defaults affects only the selected profile.
- Support bundles do not silently leak secret-bearing remote URLs.

## Phase 4: Add Profile State To MainViewModel

Steps:

- Add a UI state model for profile list and active profile:
  - `profiles`
  - `activeProfileId`
  - `activeProfileName`
  - `profileRemoteSettings`
  - `isProfileLoading`
  - `isProfileSwitching`
  - `isRemoteUpdating`
  - `lastProfileError`
- Update `loadRuntimeFiles()` to load the active profile from
  `ProfileRepository`, then read that profile through `RuntimeStorage`.
- Update all existing save/reset/import/export/test-scan paths to pass the
  active profile id.
- Add actions:
  - create profile from defaults,
  - duplicate active profile,
  - rename profile,
  - delete profile,
  - select profile,
  - update remote URL fields,
  - toggle auto update,
  - run manual remote update.
- Handle unsaved edits on profile switch:
  - if `dirtyFiles` is empty, switch immediately,
  - if dirty, require user choice: save, discard, or cancel.
- Disable profile switching and remote updates while ZeroDPI is running for the
  first implementation. Offer "Stop first" messaging rather than changing files
  under an active process.

Acceptance criteria:

- The UI state always points to exactly one active profile.
- Editing one profile does not mutate another profile.
- Profile switching reloads config and lists from the selected profile.
- Dirty local edits are not lost without an explicit user action, except when
  the user explicitly runs a remote update.

## Phase 5: Build Profile UI

Steps:

- Add an active profile selector near the top of the dashboard/top bar:
  - show current profile name,
  - open profile menu,
  - switch profiles in one or two taps.
- Add a profile management panel on the Settings page:
  - create,
  - duplicate,
  - rename,
  - delete,
  - show profile storage status.
- Add a remote update panel per active profile:
  - `config.toml` URL input,
  - `sni_list.txt` URL input,
  - `ip_list.txt` URL input,
  - auto update toggle,
  - interval selector,
  - "Update now" action,
  - last attempt,
  - last success,
  - last error.
- Keep existing config settings and list editors below the active profile
  controls. They should continue editing local files for the active profile.
- Show clear overwrite copy before manual update:
  - remote update replaces local `config.toml`, `sni_list.txt`, and
    `ip_list.txt` for this profile.
- Show a smaller persistent warning when auto update is enabled and local files
  are dirty:
  - local edits can be overwritten by the next successful auto update.

Acceptance criteria:

- Users can create and switch profiles without visiting file import/export.
- Users can edit all three files per profile.
- Users can configure three separate remote URLs per profile.
- Users understand that remote update overwrites local profile files.

## Phase 6: Implement Remote Download Client

Steps:

- Add `ProfileRemoteClient` with a small interface so tests can use fakes.
- Use `HttpURLConnection` first unless another HTTP client is already added for
  a separate reason.
- Configure network behavior:
  - run only on `Dispatchers.IO`,
  - connect/read timeouts,
  - follow redirects only for `http` to `http` or `https` to `https` unless
    explicitly allowed later,
  - reject unsupported schemes,
  - reject empty responses for required files,
  - enforce max download sizes.
- Recommended size limits:
  - `config.toml`: 512 KiB,
  - `sni_list.txt`: 5 MiB,
  - `ip_list.txt`: 5 MiB.
- Return a structured result per file:
  - status code,
  - final URL,
  - content text,
  - response headers,
  - error message.
- Optionally store `ETag` and `Last-Modified` per URL later. Do not make this
  required for the first implementation.

Acceptance criteria:

- Remote downloads happen off the main thread.
- Failed downloads produce actionable errors.
- Very large responses cannot exhaust app memory.
- Tests can exercise update behavior without real network access.

## Phase 7: Apply Remote Updates All-Or-Nothing

Steps:

- Add `ProfileUpdateManager` that coordinates:
  - URL validation,
  - download all three files,
  - config analysis,
  - SNI list validation,
  - IP list validation,
  - atomic apply.
- Recommended validation before apply:
  - `ZeroDpiConfigToml.analyze(remoteConfig).issues` must be empty,
  - `RuntimeListValidator.validate(SniList, remoteSniList, mode)` must pass for
    relevant modes,
  - `RuntimeListValidator.validate(IpList, remoteIpList, mode)` must pass for
    relevant modes,
  - at minimum, reject clearly invalid SNI/IP list syntax even if the selected
    mode does not currently use that list.
- Apply update in this order:
  1. download into memory or temp files,
  2. validate all three contents,
  3. acquire the profile write lock,
  4. write all three files atomically with backups,
  5. update profile metadata timestamps/status,
  6. reload UI state if the updated profile is active.
- If any step fails, leave the previous local files in place and record
  `lastUpdateStatus`.
- If update succeeds, clear dirty flags for those three files because local UI
  state now matches disk.

Acceptance criteria:

- A successful update overwrites all three local profile files.
- A failed or partial update overwrites none of them.
- After update, users can immediately edit and save local changes again.
- A later successful update overwrites those local changes.

## Phase 8: Add Manual Update Flow

Steps:

- Add `MainViewModel.updateActiveProfileFromRemote()`.
- Before manual update:
  - verify all three URLs are configured,
  - if local files are dirty, show a confirmation dialog that update discards
    unsaved local edits,
  - block if ZeroDPI is running.
- During update:
  - disable profile switching and file save actions for that profile,
  - show progress state,
  - keep existing editor text visible until update succeeds.
- On success:
  - reload active profile text,
  - re-run config/list validation,
  - show timestamp and success status.
- On failure:
  - keep existing editor text and dirty state,
  - show the failed file and reason.

Acceptance criteria:

- Manual update is user-triggered and predictable.
- Dirty local edits require confirmation before remote overwrite.
- Failed manual update does not destroy local files or editor text.

## Phase 9: Add Automatic Updates

Steps:

- Add AndroidX WorkManager dependency.
- Create `ProfileAutoUpdateWorker`.
- Schedule periodic work only when at least one profile has auto update enabled.
- Use constraints:
  - network connected,
  - battery not low if practical.
- Worker behavior:
  - load profile index,
  - find profiles due for update,
  - skip profiles with incomplete URLs,
  - skip or defer if ZeroDPI is running,
  - call the same `ProfileUpdateManager` used by manual updates,
  - write per-profile status.
- On app launch/resume, read latest profile status from disk and refresh UI.
- If the active profile was auto-updated while the app UI was not visible,
  reload active editor text on next foreground.
- If auto update fails, do not notify loudly in the first implementation; show
  status in the profile panel. Add notifications later only if users need them.

Acceptance criteria:

- Auto update uses the same all-or-nothing apply path as manual update.
- Auto update never modifies files while ZeroDPI is actively running.
- Users can disable auto update per profile.
- Auto update status is visible per profile.

## Phase 10: Service And Running-State Integration

Steps:

- Pass the active profile id from `MainViewModel.startService()` to
  `ZeroDpiService.startZeroDpi(profileId, modeOverride)`, or make the service
  read a stable active profile snapshot before prepare.
- Prefer passing the profile id explicitly so the service starts exactly the
  profile selected in the UI.
- Update `ZeroDpiService` logs:
  - log active profile name/id,
  - log profile runtime directory.
- Add a lightweight running marker if the auto-update worker cannot reliably
  observe service state:
  - create marker on runtime start,
  - remove marker on graceful or failed stop,
  - treat stale marker as non-running only after a conservative timeout and no
    foreground service is active.
- Keep profile switch/update blocked while runtime status is active:
  - `Starting`,
  - `Scanning`,
  - `Running`,
  - `Stopping`.

Acceptance criteria:

- Start uses the profile the user selected.
- Background auto update cannot race with service startup.
- Logs and support bundles identify which profile was used.

## Phase 11: Update Tests

Android unit tests:

- Profile JSON read/write round trip.
- Default profile creation on fresh install.
- Legacy single-profile migration preserves current config and lists.
- Create, rename, duplicate, delete, and select profile.
- Cannot delete the last profile.
- RuntimeStorage reads/writes only the selected profile.
- Relative config paths resolve inside selected profile directory.
- Remote URL validation.
- Remote update success overwrites all three files.
- Remote update failure overwrites no files.
- Dirty flags clear after successful remote update.
- Auto update due-profile selection.
- Support bundle redacts remote URL query strings.

Android instrumented tests:

- Save profile A, switch to profile B, verify profile A content remains.
- Save and reopen app with multiple profiles.
- Manual update reloads editor content.
- Unsaved edit profile-switch confirmation works.
- Start flow passes selected profile to fake runner.

Device tests:

- Manual update from real HTTPS URLs.
- Auto update while app is backgrounded.
- Auto update is deferred while ZeroDPI is running.
- Rootless start still works after switching profiles.
- Root-required start still requests root only when required by the selected
  profile config.

Acceptance criteria:

- Existing Android tests still pass.
- New tests cover migration, overwrite semantics, and profile isolation.

## Phase 12: Documentation

Update Android documentation with:

- what profiles are,
- how to create, duplicate, rename, delete, and switch profiles,
- how local edits work,
- how remote overwrite works,
- how to configure the three remote URLs,
- how manual update differs from auto update,
- why updates may be deferred while ZeroDPI is running,
- warning that URL query strings can contain secrets.

Update support/troubleshooting docs with:

- how to inspect last remote update status,
- common HTTP failures,
- invalid remote config/list failures,
- how to recover by disabling auto update or resetting a profile to defaults.

Acceptance criteria:

- Users can understand the overwrite behavior before enabling remote update.
- Troubleshooting docs explain why an update did not apply.

## Suggested Implementation Order

1. Add profile models and repository with tests.
2. Add migration from current single-profile storage.
3. Make `RuntimeStorage` profile-aware.
4. Add profile state/actions to `MainViewModel`.
5. Add profile selector and management UI.
6. Add remote URL fields and manual update.
7. Add all-or-nothing remote apply and validation.
8. Pass selected profile into `ZeroDpiService`.
9. Add WorkManager auto update.
10. Expand tests and documentation.

## Key Risks

- Migration must not lose existing user config/list files.
- Auto update can race with runtime start unless updates are locked or deferred.
- Remote URLs may contain credentials or tokens; avoid leaking them in logs,
  support bundles, and screenshots.
- Invalid remote files could break start if applied blindly; validate before
  overwriting local files.
- Profile switching with dirty edits needs explicit user choice to avoid silent
  data loss.
