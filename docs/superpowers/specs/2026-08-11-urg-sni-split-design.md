# Design: `urg_sni_split` bypass method

Date: 2026-08-11
Status: Approved (design review)

## Summary

Add a new DPI bypass method, `urg_sni_split`, to ZeroDPI. It rewrites the real
ClientHello as it passes through the interceptor: a 1-byte dummy payload is
injected into the middle of the SNI domain string, and the TCP header of that
packet is modified to set the URG (urgent) flag and an urgent pointer that
marks the dummy byte as out-of-band data.

The destination OS (BSD-style urgent semantics) extracts the urgent byte from
the stream, so the server's TLS stack sees the original, correct SNI with all
length fields intact. Stateless DPI middleboxes that read the raw byte stream
sequentially and ignore the urgent pointer see a mangled SNI that no longer
matches the blacklist.

## Mechanism

- `on_handshake_complete_ack` returns `PassThrough`. The handler sets
  `waiting_for_data` and the proxy task writes the real ClientHello.
- `on_first_data_packet` parses `pkt.payload` for the SNI:
  - **SNI found**: stage `new_payload` (original payload + 1 dummy byte at the
    insertion point), `new_flags` (original flags + `urg = true`),
    `new_urgent_pointer = Some(insert_offset_within_payload + 1)` (RFC 793:
    pointer is the offset from the segment's sequence number, one byte past the
    urgent data). Return `emit_and_complete()`.
  - **SNI not found / truncated**: return `PassThrough`. Existing handler logic
    (handler.rs first-data-packet branch) leaves `waiting_for_data` and
    `first_data_modified` untouched on `PassThrough`, so the method keeps being
    offered subsequent data packets until one is modified.
- Backends rebuild the packet with fresh IPv4 total length and IP/TCP
  checksums; the +1 payload byte flows through the generic rebuild.
- TLS length fields (record length, handshake length, extension length, name
  length) are deliberately NOT adjusted: after the server strips the urgent
  byte, its byte stream is identical to the original unmodified ClientHello.

## Architecture decisions (from design review)

| Decision | Choice | Rationale |
| --- | --- | --- |
| Injection stage | Real first data packet | Only way the destination server accepts the handshake; fake-CH at a wrong seq is rejected by the server. |
| SNI location | Parse ClientHello structure | Self-contained in zerodpi-core; no FlowController/IPC plumbing; testable. |
| Multi-packet scope | Scan until SNI found | `PassThrough` already keeps the scan alive; no handler change needed. |
| Insertion position | `SNI_SPLIT_POSITION` config (`middle` default) | Covers common cases with one small field. |
| Dummy byte | `SNI_SPLIT_DUMMY_BYTE` config, default `0x00` | Classic null-byte choice; server strips it via URG. |
| Method name | `urg_sni_split` | Fits existing naming style. |

## Changes

### zerodpi-core

New file `crates/zerodpi-core/src/methods/urg_sni_split.rs`:

- `UrgSniSplit { dummy_byte: u8, position: SniSplitPosition }` implementing
  `BypassMethod` (`name()` returns `"urg_sni_split"`).
- Private pure functions with unit tests:
  - `find_sni_range(payload: &[u8]) -> Option<(usize, usize)>` — TLS parser:
    TLS record header (content type 0x16) → handshake header (type 0x01,
    3-byte length) → skip version/random/session id/cipher suites/compression →
    extensions walk → `server_name` extension (type 0x0000) → host_name entry
    (name type 0) → `(name_start, name_len)`. Returns `None` on any truncation
    or mismatch.
  - `resolve_insert_position(name_len: usize, pos: &SniSplitPosition) -> usize`
    — `Middle` → `len / 2`, `Start` → 0, `End` → `len - 1`, `Index(n)` → `n`
    clamped to `[0, len - 1]`.
  - `insert_dummy(payload: &[u8], at: usize, byte: u8) -> Vec<u8>`.

`crates/zerodpi-core/src/interceptor.rs`:

- `TcpFlags`: add `pub urg: bool` (struct already derives `Default`).
- `PacketView`: add staged mutation
  `pub new_urgent_pointer: Option<u16>` (RFC 793 one-past semantics).

`crates/zerodpi-core/src/methods/mod.rs`:

- `mod urg_sni_split;` and a `build_method` arm for `"urg_sni_split"`.

`crates/zerodpi-core/src/config.rs`:

- New serde fields with defaults:
  - `SNI_SPLIT_DUMMY_BYTE: u8`, default `0`.
  - `SNI_SPLIT_POSITION: SniSplitPosition`, default `Middle`.
- New `#[serde(untagged)]` enum `SniSplitPosition` (mirrors `Int32Range`
  style): `Middle | Start | End | Index(u16)`; accepts `"middle"`, `"start"`,
  `"end"`, or an integer.
- Add `"urg_sni_split"` to the `BYPASS_METHOD` whitelist in `Config::validate()`
  and the doc comment listing valid values.

### zerodpi-platform

`crates/zerodpi-platform/src/linux.rs` and `crates/zerodpi-platform/src/windows.rs`
(identical changes in each):

- `parse_view`: set `flags.urg` from the wire (`TcpHeaderSlice::urg()`).
- `build_modified`: in the `new_flags` application block add
  `tcp_hdr.urg = flags.urg;`; afterwards apply
  `if let Some(ptr) = view.new_urgent_pointer { tcp_hdr.urgent_pointer = ptr; }`.

### Config files and docs

- Repo `config.toml`: documented `BYPASS_METHOD = "urg_sni_split"`,
  `SNI_SPLIT_DUMMY_BYTE`, `SNI_SPLIT_POSITION` entries.
- Android bundled copy `android/app/src/main/assets/zerodpi/config.toml`: same
  entries.
- `README.md`: document the method and new options (AGENTS.md requirement).

### No changes

- `flow.rs`, `FlowController`, remote-helper IPC, `handler.rs` state machine
  (`PassThrough` scan semantics already exist).
- Android root helper reuses `Handler` + `build_method`, so the method works on
  all platforms automatically.

## Testing

Inline `#[cfg(test)]` modules:

- Parser: fake CH from `build_client_hello` → SNI found at expected offset;
  truncations at record/handshake/extension/name boundaries → `None`; no
  server_name extension → `None`.
- Position: `middle`/`start`/`end`/index/clamping; 1-char SNI.
- Method hooks: ACK → `PassThrough`; data with SNI → staged payload +1 byte at
  position, `flags.urg`, `new_urgent_pointer == insert_offset + 1`,
  `emit_and_complete()`; data without SNI → `PassThrough`.
- Handler integration: SYN → SYN-ACK → bare ACK (`Accept`) → data packet with
  CH → `AcceptModified` with staged fields → completion; scan test (first data
  packet without SNI → `Accept`, second with SNI → `AcceptModified`).
- Backend round-trip (`linux.rs`/`windows.rs`): rebuilt header parses back with
  URG set and correct urgent pointer.
- Config: minimal-TOML defaults; `validate()` accepts `"urg_sni_split"`,
  rejects invalid `SNI_SPLIT_POSITION` values.

Verification commands: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`.

## Out of scope

- Combining with other methods (e.g. `wrong_seq` + `urg_sni_split` combos).
- Handling SNI split across a packet boundary mid-string.
- Socket-side variants (cannot set TCP URG from a userspace socket).
