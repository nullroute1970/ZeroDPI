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

## Phase 1: Add Profile Domain Model (Completed)

Steps:

- [x] Add Android profile model classes, likely under a new package:
  `dev.zerodpi.android.profile`.
- [x] Define:
  - [x] `ZeroDpiProfile`
  - [x] `ProfileRemoteSettings`
  - [x] `ProfileIndex`
  - [x] `ProfileUpdateStatus`
  - [x] `ProfileUpdateMode` for manual vs automatic update reporting.
- [x] Add profile name validation:
  - [x] non-empty,
  - [x] trimmed,
  - [x] reasonable max length such as 64 characters,
  - [x] duplicate names allowed only if the UI can distinguish them; otherwise
    reject duplicates.
- [x] Add remote URL validation:
  - [x] blank means not configured,
  - [x] configured profile update requires all three URLs,
  - [x] accept only valid absolute `http` or `https` URLs,
  - [x] warn on `http`.
- [x] Add unit tests for model validation and JSON round trips.

Acceptance criteria:

- [x] Profiles can be represented without touching existing runtime behavior.
- [x] Profile metadata can be serialized and deserialized.
- [x] Invalid ids or paths cannot escape the profile directory.

## Phase 2: Add Profile Repository And Migration (Completed)

Steps:

- [x] Add `ProfileRepository` responsible for:
  - [x] loading `profiles/index.json`,
  - [x] creating the default profile when no index exists,
  - [x] creating, renaming, duplicating, deleting, and selecting profiles,
  - [x] reading and writing profile metadata atomically,
  - [x] returning file paths for a profile id.
- [x] Add migration from the current single-profile layout:
  - [x] if `profiles/index.json` is missing, create a `Default` profile,
  - [x] if legacy `files/zerodpi/config.toml`, `sni_list.txt`, or `ip_list.txt`
    exist, copy them into the default profile,
  - [x] otherwise seed default files from packaged assets,
  - [x] leave legacy files untouched after a successful copy for one release, or
    move them into a `legacy_backup/` directory after explicit testing.
- [x] Refactor reusable file helpers out of `RuntimeStorage` if needed:
  - [x] atomic write,
  - [x] backup path creation,
  - [x] asset seeding,
  - [x] directory fsync.
- [x] Add repository-level locking so UI saves, service startup, and remote updates
  do not write the same profile concurrently.

Acceptance criteria:

- [x] Existing Android users keep their current config/lists after upgrading.
- [x] Fresh installs get one default profile.
- [x] Profile metadata and files survive app restart.
- [x] A corrupted `index.json` produces a recoverable error and does not delete
  profile files.

## Phase 3: Make RuntimeStorage Profile-Aware (Completed)

Steps:

- [x] Change `RuntimeStorage` APIs to accept a profile id or active profile handle:
  - [x] `readAll(profileId)`
  - [x] `save(profileId, kind, content)`
  - [x] `saveAll(profileId, configText, sniListText, ipListText)`
  - [x] `resetToDefaults(profileId, kind)`
  - [x] `prepareRunConfig(profileId, modeOverride)`
  - [x] `prepareConfiguredDirectories(profileId)`
  - [x] `exportSupportBundle(profileId, ...)`
- [x] Update `RuntimeStorageFiles` so `runtimeDir` points at the selected profile
  directory.
- [x] Ensure relative config paths such as `SNI_LIST = "sni_list.txt"` resolve
  inside the selected profile directory.
- [x] Keep temporary mode override configs inside the selected profile directory.
- [x] Include profile name/id in support bundle metadata, but redact remote URL query
  strings because they may contain tokens.

Acceptance criteria:

- [x] Starting ZeroDPI uses the selected profile's `config.toml`.
- [x] SNI/IP relative paths resolve to the selected profile's files.
- [x] Resetting defaults affects only the selected profile.
- [x] Support bundles do not silently leak secret-bearing remote URLs.

## Phase 4: Add Profile State To MainViewModel (Completed)

Steps:

- [x] Add a UI state model for profile list and active profile:
  - [x] `profiles`
  - [x] `activeProfileId`
  - [x] `activeProfileName`
  - [x] `profileRemoteSettings`
  - [x] `isProfileLoading`
  - [x] `isProfileSwitching`
  - [x] `isRemoteUpdating`
  - [x] `lastProfileError`
- [x] Update `loadRuntimeFiles()` to load the active profile from
  `ProfileRepository`, then read that profile through `RuntimeStorage`.
- [x] Update all existing save/reset/import/export/test-scan paths to pass the
  active profile id.
- [x] Add actions:
  - [x] create profile from defaults,
  - [x] duplicate active profile,
  - [x] rename profile,
  - [x] delete profile,
  - [x] select profile,
  - [x] update remote URL fields,
  - [x] toggle auto update,
  - [x] run manual remote update.
- [x] Handle unsaved edits on profile switch:
  - [x] if `dirtyFiles` is empty, switch immediately,
  - [x] if dirty, require user choice: save, discard, or cancel.
- [x] Disable profile switching and remote updates while ZeroDPI is running for the
  first implementation. Offer "Stop first" messaging rather than changing files
  under an active process.

Acceptance criteria:

- [x] The UI state always points to exactly one active profile.
- [x] Editing one profile does not mutate another profile.
- [x] Profile switching reloads config and lists from the selected profile.
- [x] Dirty local edits are not lost without an explicit user action, except when
  the user explicitly runs a remote update.

## Phase 5: Build Profile UI (Completed)

Steps:

- [x] Add an active profile selector near the top of the dashboard/top bar:
  - [x] show current profile name,
  - [x] open profile menu,
  - [x] switch profiles in one or two taps.
- [x] Add a profile management panel on the Settings page:
  - [x] create,
  - [x] duplicate,
  - [x] rename,
  - [x] delete,
  - [x] show profile storage status.
- [x] Add a remote update panel per active profile:
  - [x] `config.toml` URL input,
  - [x] `sni_list.txt` URL input,
  - [x] `ip_list.txt` URL input,
  - [x] auto update toggle,
  - [x] interval selector,
  - [x] "Update now" action,
  - [x] last attempt,
  - [x] last success,
  - [x] last error.
- [x] Keep existing config settings and list editors below the active profile
  controls. They should continue editing local files for the active profile.
- [x] Show clear overwrite copy before manual update:
  - [x] remote update replaces local `config.toml`, `sni_list.txt`, and
    `ip_list.txt` for this profile.
- [x] Show a smaller persistent warning when auto update is enabled and local files
  are dirty:
  - [x] local edits can be overwritten by the next successful auto update.

Acceptance criteria:

- [x] Users can create and switch profiles without visiting file import/export.
- [x] Users can edit all three files per profile.
- [x] Users can configure three separate remote URLs per profile.
- [x] Users understand that remote update overwrites local profile files.

## Phase 6: Implement Remote Download Client (Completed)

Steps:

- [x] Add `ProfileRemoteClient` with a small interface so tests can use fakes.
- [x] Use `HttpURLConnection` first unless another HTTP client is already added for
  a separate reason.
- [x] Configure network behavior:
  - [x] run only on `Dispatchers.IO`,
  - [x] connect/read timeouts,
  - [x] follow redirects only for `http` to `http` or `https` to `https` unless
    explicitly allowed later,
  - [x] reject unsupported schemes,
  - [x] reject empty responses for required files,
  - [x] enforce max download sizes.
- [x] Recommended size limits:
  - [x] `config.toml`: 512 KiB,
  - [x] `sni_list.txt`: 5 MiB,
  - [x] `ip_list.txt`: 5 MiB.
- [x] Return a structured result per file:
  - [x] status code,
  - [x] final URL,
  - [x] content text,
  - [x] response headers,
  - [x] error message.
- [x] Optionally store `ETag` and `Last-Modified` per URL later. Do not make this
  required for the first implementation.

Acceptance criteria:

- [x] Remote downloads happen off the main thread.
- [x] Failed downloads produce actionable errors.
- [x] Very large responses cannot exhaust app memory.
- [x] Tests can exercise update behavior without real network access.

## Phase 7: Apply Remote Updates All-Or-Nothing (Completed)

Steps:

- [x] Add `ProfileUpdateManager` that coordinates:
  - [x] URL validation,
  - [x] download all three files,
  - [x] config analysis,
  - [x] SNI list validation,
  - [x] IP list validation,
  - [x] atomic apply.
- Recommended validation before apply:
  - [x] `ZeroDpiConfigToml.analyze(remoteConfig).issues` must be empty,
  - [x] `RuntimeListValidator.validate(SniList, remoteSniList, mode)` must pass for
    relevant modes,
  - [x] `RuntimeListValidator.validate(IpList, remoteIpList, mode)` must pass for
    relevant modes,
  - [x] at minimum, reject clearly invalid SNI/IP list syntax even if the selected
    mode does not currently use that list.
- Apply update in this order:
  1. [x] download into memory or temp files,
  2. [x] validate all three contents,
  3. [x] acquire the profile write lock,
  4. [x] write all three files atomically with backups,
  5. [x] update profile metadata timestamps/status,
  6. [x] reload UI state if the updated profile is active.
- [x] If any step fails, leave the previous local files in place and record
  `lastUpdateStatus`.
- [x] If update succeeds, clear dirty flags for those three files because local UI
  state now matches disk.

Acceptance criteria:

- [x] A successful update overwrites all three local profile files.
- [x] A failed or partial update overwrites none of them.
- [x] After update, users can immediately edit and save local changes again.
- [x] A later successful update overwrites those local changes.

## Phase 8: Add Manual Update Flow

Steps:

- [x] Add `MainViewModel.updateActiveProfileFromRemote()`.
- [x] Before manual update:
  - [x] verify all three URLs are configured,
  - [x] if local files are dirty, show a confirmation dialog that update discards
    unsaved local edits,
  - [x] block if ZeroDPI is running.
- [x] During update:
  - [x] disable profile switching and file save actions for that profile,
  - [x] show progress state,
  - [x] keep existing editor text visible until update succeeds.
- [x] On success:
  - [x] reload active profile text,
  - [x] re-run config/list validation,
  - [x] show timestamp and success status.
- [x] On failure:
  - [x] keep existing editor text and dirty state,
  - [x] show the failed file and reason.

Acceptance criteria:

- [x] Manual update is user-triggered and predictable.
- [x] Dirty local edits require confirmation before remote overwrite.
- [x] Failed manual update does not destroy local files or editor text.

## Phase 9: Add Automatic Updates (Completed)

Steps:

- [x] Add AndroidX WorkManager dependency.
- [x] Create `ProfileAutoUpdateWorker`.
- [x] Schedule periodic work only when at least one profile has auto update enabled.
- [x] Use constraints:
  - [x] network connected,
  - [x] battery not low if practical.
- [x] Worker behavior:
  - [x] load profile index,
  - [x] find profiles due for update,
  - [x] skip profiles with incomplete URLs,
  - [x] skip or defer if ZeroDPI is running,
  - [x] call the same `ProfileUpdateManager` used by manual updates,
  - [x] write per-profile status.
- [x] On app launch/resume, read latest profile status from disk and refresh UI.
- [x] If the active profile was auto-updated while the app UI was not visible,
  reload active editor text on next foreground.
- [x] If auto update fails, do not notify loudly in the first implementation; show
  status in the profile panel. Add notifications later only if users need them.

Acceptance criteria:

- [x] Auto update uses the same all-or-nothing apply path as manual update.
- [x] Auto update never modifies files while ZeroDPI is actively running.
- [x] Users can disable auto update per profile.
- [x] Auto update status is visible per profile.

## Phase 10: Service And Running-State Integration (Completed)

Steps:

- [x] Pass the active profile id from `MainViewModel.startService()` to
  `ZeroDpiService.startZeroDpi(profileId, modeOverride)`, or make the service
  read a stable active profile snapshot before prepare.
- [x] Prefer passing the profile id explicitly so the service starts exactly the
  profile selected in the UI.
- [x] Update `ZeroDpiService` logs:
  - [x] log active profile name/id,
  - [x] log profile runtime directory.
- [x] Add a lightweight running marker if the auto-update worker cannot reliably
  observe service state:
  - [x] create marker on runtime start,
  - [x] remove marker on graceful or failed stop,
  - [x] treat stale marker as non-running only after a conservative timeout and no
    foreground service is active.
- [x] Keep profile switch/update blocked while runtime status is active:
  - [x] `Starting`,
  - [x] `Scanning`,
  - [x] `Running`,
  - [x] `Stopping`.

Acceptance criteria:

- [x] Start uses the profile the user selected.
- [x] Background auto update cannot race with service startup.
- [x] Logs and support bundles identify which profile was used.

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
- [x] Auto update due-profile selection.
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
