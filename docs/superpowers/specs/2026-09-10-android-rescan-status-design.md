# Android Background Rescan Status

## Problem

The Android dashboard currently interprets an expired `next_scan_scheduled`
deadline as `Scanning…`. The native runtime schedules the next cycle before
sleeping, so an expired deadline is not proof that a scan is running. The UI
therefore commonly remains stuck on a false scanning status even while the
proxy continues relaying traffic.

## Requirements

1. The native runtime must emit explicit JSON events when a periodic SNI or IP
   rescan starts and finishes.
2. A finish event must be emitted for successful scans, empty results, and
   recoverable scan failures.
3. Android must parse those events and keep an explicit `rescanInProgress`
   state, rather than inferring activity from the schedule deadline.
4. The dashboard must show `Scanning…` only while that explicit state is true.
   An expired deadline without a start event must be shown as due/pending, not
   as an active scan.
5. Starting, stopping, restarting, or failing a runtime must clear the
   background-rescan state so a previous process cannot leave stale status in
   the dashboard.
6. Existing startup scan progress, target selection, traffic relay, TUI
   events, and headless behavior must remain unchanged.

## Verification

- Rust serialization tests cover the new runtime event contract.
- Android parser tests cover start and finish events, including result fields.
- Android UI tests cover the distinction between an expired inactive schedule
  and an explicitly active rescan.
- Run Android JVM tests plus Rust formatting, tests, clippy, and build checks.
