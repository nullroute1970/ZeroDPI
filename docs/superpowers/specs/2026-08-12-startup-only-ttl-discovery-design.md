# Design: startup-only `LOW_TTL_DISCOVER`

Date: 2026-08-12
Status: Approved (design review)

## Summary

Run `LOW_TTL_DISCOVER` once, after the initial SNI/IP target has been selected
and the packet interceptor is ready, but before the proxy listener starts.
Keep the discovered TTL in the live `low_ttl` method for the lifetime of the
process.

Background SNI rescans continue to run at the configured interval and continue
to hot-swap the active SNI/IP target for new connections. They no longer carry
or invoke TTL discovery state. A target change therefore behaves like target
changes for other bypass methods: existing connections are unaffected, and new
connections use the already-configured live bypass method and startup TTL.

## Runtime data flow

1. Build the interceptor and obtain the live `low_ttl` handle.
2. If discovery is enabled and applicable, probe the initially selected target
   exactly once and apply the resulting TTL before listening.
3. Start the background rescan task without a discovery argument or state.
4. When a rescan finds a better target, update `active_target` and emit the
   existing target-change event only. Do not change the TTL handle.

The startup discovery behavior and its existing configuration gates remain
unchanged. This design intentionally does not solve the separate issue where
the discovery probe loop may leave its final candidate in the live TTL handle;
that is outside the requested rescan behavior change and should be handled as a
separate fix.

## Implementation scope

- Remove the `low_ttl_discovery` parameter from `background_rescan`.
- Remove the rescan-time `discovery_state.run(...)` block and its discovery
  event emissions.
- Stop cloning discovery state when spawning the background rescan.
- Update source comments, `config.toml`, the Android asset config, and
  `README.md` to describe startup-only discovery.
- Preserve all SNI rescan target selection, target-change events, and other
  bypass-method behavior.

## Testing

- Keep the existing startup discovery decision tests.
- Add a focused regression test for the rescan policy: a background target
  switch has no TTL-discovery action and leaves the startup TTL policy intact.
- Run the focused `zerodpi` tests, `zerodpi-core` tests, formatting, and the
  workspace test suite before completion.

