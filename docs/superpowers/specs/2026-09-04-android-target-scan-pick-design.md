# Android Target Scan & Pick Design

**Date:** 2026-09-04
**Status:** Approved in chat on 2026-09-04
**Scope:** Android app only. No Rust / zerodpi-core changes.

## Goal

Port the desktop CLI's "select an SNI or IP after scan" feature (the ratatui
selection table shown when `AUTO_SELECT = false` and no `SELECTED_SNI` /
`SELECTED_IP` is set) to the Android app, plus an easy on-demand re-scan entry
point from the Home tab.

The Android runner currently always launches the binary with
`--no-tui --auto-select --json-events`, so headless runs always auto-pick
rank 1. The binary has no interactive table in headless mode, and we will not
add one (no Rust changes). Instead the app orchestrates the desktop behavior
in two phases using existing binary modes and config mechanisms:

1. **Scan phase:** run the binary in `sni_scan` / `ip_scan` mode against the
   active profile's SNI/IP list, with `SCAN_OUTPUT` patched into an ephemeral
   config so the binary writes the full ranked results JSON.
2. **Run phase:** persist the user's pick app-side and inject it at launch by
   patching `SELECTED_SNI` / `SELECTED_IP` into an ephemeral run config passed
   as `--config`. The user's `config.toml` is never modified.

## Behavior Model (approved)

| Context | Behavior |
|---|---|
| **Start** tapped; mode ∈ `sni_spoof`, `ip_bypass`, `ip_bypass_plus`; config `AUTO_SELECT = false`; config `SELECTED_SNI`/`SELECTED_IP` blank; no stored app pin of the mode-matching kind | Intercept start → scan-only pass → picker shows ranked results → user picks → pin stored app-side → run **auto-starts** with the pin injected |
| **Start** with a stored app pin of the mode-matching kind | Run starts normally; pin injected via ephemeral run config; binary skips scanning |
| **Home "Scan & choose"** while runtime is running | Graceful stop (existing restart machinery) → scan → pick → pin replaced → **auto-relaunch** (new pin picked up at launch); cancel → relaunch as before (previous pin, or unpinned) |
| **Home "Scan & choose"** while runtime is stopped | Scan → pick → pin saved only; no auto-start |
| Picker dismissed / cancelled during the Start gate | Start aborted, stays Stopped, log entry explains why |
| Scan fails or returns no usable results | Failed state with inline message; pin unchanged; previous run resumed (mid-run case) or start aborted (gate case) |

Rules:

- The **"Scan & choose"** control is visible only when the config's
  `AUTO_SELECT = false` (the feature gate) and the mode is one of
  `sni_spoof`, `ip_bypass`, `ip_bypass_plus`.
- Scan kind by mode: `sni_spoof` → SNI list scan (`sni_scan`); `ip_bypass`
  and `ip_bypass_plus` → IP list scan (`ip_scan`).
- **Clear pin** affects future launches only: the running session keeps its
  current target until stopped/restarted (the launched process already has its
  own config). After clearing, the next Start with `AUTO_SELECT = false` scans
  and asks again. Clearing while stopped needs no further action.
- The runner keeps passing `--auto-select`; once `SELECTED_SNI`/`SELECTED_IP`
  is present in the run config the binary skips scanning, so the flag is
  harmless. The picked SNI is re-resolved via DNS by the binary at run start
  (existing `SELECTED_SNI` semantics — accepted; no IP pinning field).
- One selection mechanism at a time: when the user saves a config that
  contains a non-empty `SELECTED_SNI` or `SELECTED_IP` (manual pin, visible
  in the editor), the stored app pin of that kind is **cleared**. The stored
  pin only applies while the config's own field for that kind is blank.
- A stored pin whose kind does not match the current mode (e.g. sni pin while
  `MODE = "ip_bypass"`) is ignored; the Start gate applies for the mode's
  scan kind.

## Architecture

All work is in the Kotlin app (`android/app`). Components:

### 1. Pin storage — `TargetPinStore` (new)

- Per-profile JSON file `target_pin.json` in the profile runtime dir
  (`android/app/src/main/java/dev/zerodpi/android/storage/` next to the
  other storage classes).
- Shape (kotlinx-serialization JSON, already a dependency):

```json
{ "kind": "sni" | "ip", "sni": "..." | null, "ip": "1.2.3.4",
  "score": 95 | null, "picked_at_ms": 1757000000000 }
```

- API: `read(profileId): TargetPin?`, `write(profileId, pin)`, `clear(profileId)`.
- Excluded from SupportBundle; not carried by profile import/export.

### 2. Ephemeral run config + pin injection — `RuntimeStorage.prepareRunConfig`

- Extend `prepareRunConfig(profileId, modeOverride, pin: TargetPin? = null)`:
  - When `modeOverride != null` (scan / method-scan / test runs): never
    inject a pin; behavior unchanged.
  - When `modeOverride == null` and a mode-matching `pin` exists: create an
    ephemeral run config file (`.run_config.toml` in the runtime dir — same
    pattern as the existing `.${mode}_config.toml`) whose text is the stored
    config with `SELECTED_SNI` (sni pin) or `SELECTED_IP` (ip pin) patched via
    the existing `replaceOrAppendField` helper. Pass that file as `--config`.
  - The user's `config.toml` is never written by pin logic.
- Scan-phase configs are prepared exactly like today's test scans, plus
  `SCAN_OUTPUT` patched to `pick_scan_results.json` (relative path resolves
  into the runtime dir because the ephemeral config lives there).
- Add `readScanOutput(profileId, configText)` mirroring the existing
  `readMethodScanOutput`.

### 3. Results parsing — `ScanReportParser` (new)

- Mirrors `MethodScanReportParser`: parses the ranked JSON arrays the binary
  already writes (`save_sni_results` / `save_ip_results` → `SniProbeEntry` /
  `IpProbeEntry` arrays: sni, ip, score, latency fields as serialized).
- Model types for rows: rank, sni (SNI scans), ip, score, tcp latency,
  selectable = score > 0 (failed rows disabled in UI).

### 4. Orchestration — `ZeroDpiService` + `MainViewModel`

- `ZeroDpiService` gains an "interactive pick session" concept layered on the
  existing single-process launch machinery (one data-plane process at a time;
  a concurrent scan is impossible, so mid-run re-scan = stop → scan → pick →
  relaunch):
  - Start gate: when Start is requested with a pick-eligible config, launch a
    pick scan instead of the runtime run; remember no resume spec (nothing was
    running).
  - Mid-run "Scan & choose": run the existing graceful-stop/restart machinery
    (same as network-change restart), but relaunch the pick scan instead of
    the run; remember the pre-scan `activeRunSpec` for resume.
  - After the pick scan exits, the ViewModel reads `pick_scan_results.json`
    and advances the picker card to Choose.
  - Apply pick: `TargetPinStore.write(...)`, then:
    - gate case → `startZeroDpi(profileId)` (launch reads the pin);
    - mid-run case → relaunch the remembered run spec (`isAutomaticRestart`);
    - stopped case → nothing further (saved only).
  - Cancel semantics: gate case → stay Stopped + log; mid-run case → relaunch
    the remembered run spec (pin untouched).
- `MainViewModel` owns a `TargetPickUiState` StateFlow modeled on the existing
  `MethodScanUiState`:
  `Hidden → Idle → Scanning → Choose(results) → Picked → Applied/Saved → Hidden`
  plus `Failed(message)` and `Cancelled`. Attach config-save hooks in the
  existing sync path for the pin-clear policy and card refresh on profile
  switch / mode change.
- `FakeZeroDpiRunner` extended so debug builds and UI tests can drive pick
  sessions (scan events + exit).

### 5. UI — Home tab target-picker card (new composable)

- `TargetPickerCard.kt` beside `MethodScanCard.kt`, wired into `HomeScreen`
  like the method-scan card. Card states:
  - **Idle:** current pin summary ("Pinned target …") or "No pinned target —
    starts will scan and ask"; actions **Scan & choose** (visible only when
    `AUTO_SELECT = false` and mode eligible) and **Clear pin** (small action
    when a pin exists).
  - **Scanning:** live progress from existing scan events + **Cancel scan**.
  - **Choose:** ranked rows (rank, sni/ip, score, latency), failed rows
    (score 0) disabled, tap row = pick; **Cancel** action.
  - Transient Applied / Saved / Failed states with inline messages.
- Strings in `res/values/strings.xml`; testTags on interactive controls;
  `internal` visibility for composables (repo style).

## Data Flow

1. Scan phase: ViewModel → service launches scan run with ephemeral
   `MODE=sni_scan|ip_scan` + `SCAN_OUTPUT` config → binary streams scan events
   (live progress) → writes ranked JSON → exits 0 → `Exited` event.
2. Choose phase: ViewModel reads JSON via `readScanOutput`, parses with
   `ScanReportParser`, card renders ranked list.
3. Apply phase: tap row → `TargetPinStore.write` → service continues/relaunches
   per the behavior table → binary reads ephemeral run config containing
   `SELECTED_SNI`/`SELECTED_IP` → skips scan, starts listener, emits normal
   runtime events.

## Error Handling

- Scan run exits non-zero or scan fails → `Failed(message)`, pin unchanged,
  resume/abort per behavior table.
- Empty results or no selectable rows → Failed state with guidance to check
  the list file / connectivity.
- Root: pick scans are rootless (`sni_scan`/`ip_scan` never need root). The
  follow-up run's root requirement is unchanged from today.
- Runtime already running when a pick scan is requested → always stop first;
  if stop times out, existing force-stop/`StopTimedOut` handling applies and
  the pick session aborts with an error.

## Testing

- Rust workspace untouched; `cargo fmt/clippy/test` unaffected.
- Unit tests (JUnit4, `android/app/src/test`):
  - `TargetPinStore` round-trip, overwrite, clear, corrupt-file handling.
  - Pin injection: correct `SELECTED_SNI`/`SELECTED_IP` patching, replace vs
    append, never injected when `modeOverride != null`, kind/mode gating.
  - Pick eligibility rules (mode set, `AUTO_SELECT` false, config
    `SELECTED_*` blank, no pin).
  - Config-save pin-clear policy.
  - `ScanReportParser` fixtures for sni and ip JSON.
  - ViewModel pick state machine transitions with fake service/runner.
- Compose androidTest: card states, row selection, disabled failed rows,
  cancel/resume behaviors.
- Manual QA checklist in the plan: rootless + full builds, Start gate,
  mid-run re-scan cancel/resume, profile switch, config-save clear, support
  bundle contents.

## Out of Scope

- No Rust / core / platform crate changes (binary behavior untouched).
- No changes to background `RESCAN_INTERVAL_SECS` hot-swap semantics.
- No VpnService changes.
- No exact scanned-IP pinning for SNI picks (DNS re-resolution at run start;
  accepted in chat on 2026-09-04).
