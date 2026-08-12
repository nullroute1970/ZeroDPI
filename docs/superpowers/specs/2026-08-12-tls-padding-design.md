# TLS ClientHello Padding Expansion (`tls_padding`) — Design Spec

Date: 2026-08-12

## Goal

Add a new bypass method, `tls_padding`, that inflates the real TLS ClientHello
record with an RFC 7685 padding extension. The padding pushes the SNI payload
past the DPI's maximum inspection window (typically 512 / 1024 / 1460 bytes),
so byte-window-limited DPI engines never see the SNI, while the destination
server still parses the full record normally (unknown extensions are skipped).

Scope: core Rust crate (`zerodpi-core`) plus CLI/docs touch points. No changes
to the packet interceptor itself, no changes to the fake-ClientHello template.

## Mechanism

`tls_padding` is a socket-side method like `tls_frag`: it operates inside the
proxy task on the client's **real** ClientHello (never the injected fake one —
the fake ClientHello is a decoy built from `tls_template.rs` and is not
padded).

Per connection:

1. Read exactly one complete TLS record (the ClientHello) from the client.
2. Parse it generically (not template-based):
   - 5-byte record header (type must be `0x16`, handshake),
   - 4-byte handshake header (type must be `0x01`, ClientHello),
   - body walk: `version(2) | random(32) | sid_len(1) | session_id |
     cipher_len(2) | cipher_suites | comp_len(1) | compression |
     ext_len(2) | extensions`.
3. Sample a padding size from `TLS_PADDING_SIZE` (an `Int32Range`) per
   connection, then clamp so the final record length ≤ 16383 (TLS record-layer
   maximum).
4. Build a padding extension (`type = 0x0015`, 2-byte length, zero bytes) and
   insert it:
   - `TLS_PADDING_POSITION = "before"` (default): immediately before the SNI
     extension (`type = 0x0000`), which moves the SNI to
     `original_sni_offset + 4 + pad_len`.
   - `"after"`: appended at the end of the extension list (canonical RFC 7685
     placement; relies on DPI bailing on oversized record-length claims).
   - No SNI extension found: append at the end in both cases.
5. Recompute the extensions-block length, handshake length, and record length
   (each +`4 + pad_len`).
6. Write the padded record to the upstream socket (whole, or fragmented first
   when `tls_frag` is also in the list).

**Fail-open:** any malformed/unparseable structure returns `None` and the
proxy forwards the original record unchanged.

## Configuration

New `Config` fields (defaults follow existing conventions; documented as
commented-out entries in `config.toml`):

| Key | Type | Default | Validation |
|-----|------|---------|------------|
| `TLS_PADDING_SIZE` | `Int32Range` | `"1500-2500"` | `min >= 1`, `max <= 16000` |
| `TLS_PADDING_POSITION` | `String` | `"before"` | must parse to `before` or `after` |

`TLS_PADDING_SIZE` values are sampled fresh per connection (randomness avoids
a fingerprintable constant size). `"1500-2500"` pushes the SNI (typical offset
100–300 bytes) to byte offset ~1600–2800, past all three common inspection
windows, while keeping the record well under 16383 and spanning 2+ TCP
segments at typical 1460-byte MSS.

## Method-list integration

- `BASE_BYPASS_METHODS` in `config.rs` gains `"tls_padding"`.
- `BypassMethodList::is_socket_only()` becomes: all listed methods ∈
  {`tls_frag`, `tls_padding`}. This keeps `["tls_frag"]`, `["tls_padding"]`,
  and the stacked `["tls_frag", "tls_padding"]` interceptor-free.
- `BypassMethodList::requires_interceptor()` becomes: any listed method ∉
  {`tls_frag`, `tls_padding`}.
- `Config::validate`:
  - Unknown/duplicate-method error messages list `tls_padding` implicitly via
    `BASE_BYPASS_METHODS`.
  - `MODE = "ip_bypass_plus"` allowed set becomes {`tls_record_frag`,
    `tls_frag`, `tls_padding`} (all real-SNI-preserving).
  - `TLS_PADDING_SIZE` validated via `validate_at_least(1)` and an upper-bound
    check (≤ 16000).
  - `TLS_PADDING_POSITION` must parse as `"before"` or `"after"`.
- `methods/mod.rs::build_method` returns `None` for socket-only lists
  (unchanged behavior; `tls_padding` is socket-only).

## Proxy wiring (`proxy.rs`)

New helper module `crates/zerodpi-core/src/methods/tls_padding.rs` exposing:

- `enum PaddingPosition { Before, After }` with `parse(&str) -> Result<Self, String>`.
- `struct TlsPadding { size: Int32Range, position: PaddingPosition }` with
  `TlsPadding::new(&cfg)` (mirrors `TcpSegmentation::new`).
- `impl TlsPadding { fn apply(&self, record: &[u8]) -> Option<Vec<u8>> }`.

Wiring points:

1. **Socket path** (`handle_tcp_seg_connection_with_ip`): when
   `BYPASS_METHOD.contains("tls_padding")`, read exactly one TLS record from
   the client, apply `TlsPadding::apply`, and write it upstream **before** the
   mode dispatch — regardless of `TLS_FRAG_PACKETS` mode:
   - `TlsHello` mode: the padded record is fragmented via `write_fragmented`
     (or written whole when `tls_frag` is not listed).
   - `WriteRange` mode: the padded record is written whole, then the relay
     fragments selected later client writes. The `TLS_FRAG_PACKETS` indices
     then refer to writes **after** the already-forwarded ClientHello (the
     relay already starts counting at index 1).
2. **Intercept path** (`handle_intercept_connection`, `ReadyForData` branch):
   `ConnectionSettings` gains `pad_first_client_hello: bool` set from
   `BYPASS_METHOD.contains("tls_padding")`. Apply `TlsPadding::apply` to the
   read ClientHello before the existing write / `write_fragmented` step. In
   the `WriteRange` sub-branch the first client write may be a partial record:
   attempt to parse it as a complete ClientHello and pad only on success,
   otherwise forward unchanged (fail-open). Combos like
   `["wrong_seq", "tls_padding"]` and
   `["wrong_seq", "tls_frag", "tls_padding"]` work through this path.

## CLI / helper touch points

- `crates/zerodpi/src/main.rs`:
  - Interceptor-skip log messages (socket-only branches in `sni_spoof` and
    `ip_bypass_plus` setups) mention `tls_padding` alongside `tls_frag`.
  - `rootless_alternatives()` gains a `tls_padding` entry.
- `crates/zerodpi-helper-protocol/src/lib.rs`: `SUPPORTED` method list gains
  `"tls_padding"` (same treatment as `tls_frag`; harmless for a socket-only
  method).

## Documentation

- `config.toml`:
  - New commented section with `TLS_PADDING_SIZE` and `TLS_PADDING_POSITION`
    (defaults, meaning, examples).
  - `BYPASS_METHOD` comment block: add `"tls_padding"` to the method list,
    combination notes, and the `ip_bypass_plus` allowed set.
- `README.md`:
  - Method-count badge 9 → 10.
  - Bypass-methods table: new `tls_padding` row (interceptor: ❌ No).
  - Combining-rules section: `ip_bypass_plus` allowed set, socket-only list
    definition (`tls_frag` / `tls_padding` / both).
  - "How it works" note for `tls_padding` (RFC 7685 padding pushes SNI past
    the DPI inspection window; `before` vs `after` placement).

## Testing

Unit tests (inline `#[cfg(test)]`):

- `tls_padding.rs`:
  - Uses the 517-byte ClientHello from `tls_template.rs` as realistic input.
  - `before`: SNI offset increases by exactly `4 + pad_len`; SNI bytes
    preserved; extensions/handshake/record lengths correct.
  - `after`: SNI offset unchanged; padding at end of extensions.
  - No-SNI input: padding appended at end (both positions).
  - Malformed input (truncated, wrong record type, wrong handshake type):
    returns `None`.
  - Clamping: oversized requested padding clamps so record ≤ 16383.
  - Round-trip parse of the padded output succeeds.
- `config.rs`:
  - `TLS_PADDING_SIZE` / `TLS_PADDING_POSITION` parse and default.
  - Validation errors (size < 1, size > 16000, bad position).
  - `is_socket_only()` for `["tls_padding"]` and `["tls_frag",
    "tls_padding"]`; `requires_interceptor()` false for those lists.
  - `ip_bypass_plus` accepts `tls_padding`.
- `proxy.rs`: existing tests updated where method lists/messages are asserted
  (e.g. `tls_frag_in_list_segments_first_client_hello` gains a
  `pad_first_client_hello` sibling).

## Out of scope (v1)

- Padding the fake injected ClientHello (`tls_template.rs`) — decoy only.
- New combo aliases (e.g. `wrong_seq_tls_padding`) — users can write
  `["wrong_seq", "tls_padding"]` directly.
- Interceptor-side padding — the method is socket-side by design.
