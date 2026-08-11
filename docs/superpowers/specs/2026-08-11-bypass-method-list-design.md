# Design: `BYPASS_METHOD` as a configurable method list

Date: 2026-08-11
Status: Approved (design review)

## Summary

Make `BYPASS_METHOD` accept either a single method name or a TOML array of
method names, e.g. `BYPASS_METHOD = ["wrong_seq", "low_ttl", "tls_frag"]`.
Combining methods is no longer hard-coded: the existing combo names
(`wrong_seq_tls_frag`, `wrong_md5_tls_frag`, `wrong_seq_tls_record_frag`,
`wrong_seq_wrong_md5`) remain valid as aliases that expand into their stage
lists, and a new generic `CompositeMethod` composes arbitrary method lists at
runtime.

Why this is possible: every handshake-stage method injects the *same* fake
ClientHello (`flow.fake_data`) and then applies its own twist through distinct
`PacketView` fields (rewound seq / rewound ack / checksum-corrupt delta /
TCP-MD5 option / low TTL / timestamp option). Combining two handshake methods
therefore merges their twists onto one fake packet without conflict; this is
exactly how `wrong_seq_wrong_md5` already works.

## Method stages

| Stage | Member | Behavior |
| --- | --- | --- |
| Handshake | `wrong_seq`, `wrong_ack`, `wrong_checksum`, `wrong_md5`, `wrong_timestamp`, `low_ttl`, `urg_sni_split` | Mutate the first outbound bare ACK after the handshake (fake injection). |
| Data (interceptor) | `tls_record_frag` | Mutates the first outbound data packet inside the interceptor. |
| Socket | `tls_frag` | No interceptor involvement; the proxy splits writes via `TLS_FRAG_*` settings. |

Base names (9): `wrong_seq, wrong_ack, wrong_checksum, wrong_md5,
wrong_timestamp, low_ttl, tls_record_frag, tls_frag, urg_sni_split`.

## Config parsing

`crates/zerodpi-core/src/config.rs` gains:

```rust
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BypassMethodList(Vec<String>);
```

- Custom `Deserialize` (string or array of strings), plus accessors
  `contains(&self, &str) -> bool`, `iter()`, `as_slice()`, `is_empty()`,
  `len()`, and a `Display` impl joining with `" + "` (e.g.
  `wrong_seq + tls_frag`).
- `Config::BYPASS_METHOD` field type changes from `String` to
  `BypassMethodList`. Call sites that compared `== "x"` become
  `.contains("x")`; clone/display uses keep working through the wrapper.

## Alias expansion and validation (in `Config::validate`)

Combo names expand to stage lists:

| Alias | Expands to |
| --- | --- |
| `wrong_seq_wrong_md5` | `["wrong_seq", "wrong_md5"]` |
| `wrong_seq_tls_frag` | `["wrong_seq", "tls_frag"]` |
| `wrong_md5_tls_frag` | `["wrong_md5", "tls_frag"]` |
| `wrong_seq_tls_record_frag` | `["wrong_seq", "tls_record_frag"]` |

Validation on the expanded list (these limitations are also documented in
`config.toml` and `README.md`):

1. Empty list → error.
2. Unknown name → error (message lists the 9 base names and 4 aliases).
3. Duplicates after expansion → error.
4. `urg_sni_split` may only appear alone or with `tls_frag` / `tls_record_frag`
   (not with other handshake-stage methods).
5. `MODE = "ip_bypass_plus"` → every element must be `tls_record_frag` or
   `tls_frag` (replaces the current exact-match check).
6. `LOW_TTL_DISCOVER` requires `low_ttl` in the list.
7. New helpers on `BypassMethodList`:
   - `requires_interceptor()` — any element other than `tls_frag`.
   - `is_socket_only()` — list is exactly `["tls_frag"]`.

## Composite method

New file `crates/zerodpi-core/src/methods/composite.rs`:

```rust
pub struct CompositeMethod {
    handshake_methods: Vec<Box<dyn BypassMethod>>,
    data_method: Option<Box<dyn BypassMethod>>, // tls_record_frag
    segments_first_client_hello: bool,          // tls_frag present
}
```

- `name()` — joins member names with `" + "`.
- `low_ttl_handle()` — forwards the contained `LowTtl` handle so
  `LOW_TTL_DISCOVER` runtime updates keep working.
- `on_handshake_complete_ack`:
  1. Run each handshake method in config order, staging mutations onto the
     same `PacketView`.
  2. Precedence rules (provably reproduce the four existing combos):
     - PSH / IP-ident come from the **first** handshake method (restored after
       all members have run).
     - Completion action comes from the **last** handshake method
       (`wait_for_ack` vs `complete`), which honors e.g.
       `WRONG_MD5_COMPLETE_IMMEDIATELY` exactly as `wrong_seq_wrong_md5`
       does today.
     - A member's `AbortAndAccept` is honored only if no member has staged
       anything yet; otherwise it is skipped.
  3. If `data_method` or `segments_first_client_hello` → return
     `emit_and_wait_for_data()`. Otherwise return the resolved action.
- `on_first_data_packet`: delegate to `tls_record_frag` when present;
  otherwise `complete_and_accept()` (matches current `wrong_seq_tls_frag` /
  `wrong_md5_tls_frag` behavior when only socket segmentation is active).

`methods/mod.rs`:

- `build_method()` builds the composite from `cfg.BYPASS_METHOD` (returns
  `None` when the list is socket-only, preserving the current `tls_frag`
  contract).
- Delete `wrong_seq_tls_frag.rs`, `wrong_md5_tls_frag.rs`,
  `wrong_seq_tls_record_frag.rs`, `wrong_seq_wrong_md5.rs`; move
  `tcp_md5_signature_option()` to `wrong_md5.rs` (pub(crate), it is used by
  tests). Their tests are replaced by composite tests asserting identical
  behavior via list configs.

## Proxy wiring

`crates/zerodpi-core/src/proxy.rs`:

- `ConnectionSettings::from_config`:
  `segment_first_client_hello = cfg.BYPASS_METHOD.contains("tls_frag")`.
- Delete `method_segments_first_client_hello` and its tests.
- `if cfg.BYPASS_METHOD == "tls_frag"` (two sites) →
  `if cfg.BYPASS_METHOD.is_socket_only()`.

`crates/zerodpi-core/src/proxy_tester.rs`:

- `if config.BYPASS_METHOD == "tls_frag"` (socket-only probe vs interceptor
  probe) → `is_socket_only()`.

## App, TUI, helper protocol

`crates/zerodpi/src/main.rs`:

- `--method` CLI flag accepts `"wrong_seq"` or `"wrong_seq,tls_frag"` and
  populates the list.
- `mode_requires_packet_interception` takes `&BypassMethodList`;
  `LOW_TTL_DISCOVER` gating uses `contains("low_ttl")`;
  `build_method` error contexts use the joined display string.

`crates/zerodpi/src/tui.rs` and `runtime_events.rs`:

- Display and events use `BypassMethodList`'s `Display` join
  (`wrong_seq + tls_frag`).

`crates/zerodpi-helper-protocol/src/lib.rs`:

- `MethodConfig.name: String` → `methods: Vec<String>`.
- `MethodConfig::validate()` whitelists the 9 base names (aliases are already
  expanded by `Config::validate` before the wire is built; the protocol crate
  is standalone and only sees base names).
- Bump `PROTOCOL_MINOR` 1 → 2 (`crates/zerodpi-helper-protocol/src/lib.rs`,
  line 15): the `MethodConfig` frame layout changes.

`crates/zerodpi-root-helper/src/unix.rs`:

- `build_wire_method` sets `cfg.BYPASS_METHOD` from the wire `methods` list,
  then `build_method` → composite.

`crates/zerodpi-platform/src/lib.rs`:

- Doc-comment updates for the new syntax (no behavior change).

## Docs and config file (limitations documented)

`config.toml`:

- Replace the BYPASS_METHOD comment block with: list syntax, base names,
  alias table, and the limitations listed above.

`README.md`:

- `BYPASS_METHOD` config-table row: string-or-list.
- New "Combining bypass methods" section listing the limitations.
- Combo method descriptions updated to say they are aliases; example configs
  may keep using aliases (still valid).

## Testing

- Config: string and array parsing; alias expansion; rejection of
  empty/unknown/duplicate lists, `urg_sni_split` + handshake combos,
  `ip_bypass_plus` violations.
- Composite: `["wrong_seq", "tls_frag"]` ≡ old `wrong_seq_tls_frag`;
  `["wrong_seq", "wrong_md5"]` ≡ old `wrong_seq_wrong_md5`
  (PSH from first, action from last incl. `COMPLETE_IMMEDIATELY`);
  `["wrong_seq", "low_ttl"]` stages seq rewind and low TTL on one packet;
  `low_ttl_handle` forwarding; `tls_record_frag` delegation on first data
  packet; abort-skip rule.
- Proxy: `segment_first_client_hello` true for lists containing `tls_frag`.
- CLI/protocol: `--method` list parsing; wire `methods` validation.

## Files

New: `crates/zerodpi-core/src/methods/composite.rs`.

Deleted: `crates/zerodpi-core/src/methods/wrong_seq_tls_frag.rs`,
`wrong_md5_tls_frag.rs`, `wrong_seq_tls_record_frag.rs`,
`wrong_seq_wrong_md5.rs`.

Modified: `crates/zerodpi-core/src/config.rs`, `methods/mod.rs`,
`methods/wrong_md5.rs`, `proxy.rs`, `proxy_tester.rs`,
`crates/zerodpi/src/main.rs`, `tui.rs`, `runtime_events.rs`,
`helper_client.rs`, `crates/zerodpi-helper-protocol/src/lib.rs`,
`crates/zerodpi-root-helper/src/unix.rs`,
`crates/zerodpi-platform/src/lib.rs`, `config.toml`, `README.md`.

Docs: `docs/superpowers/specs/2026-08-11-bypass-method-list-design.md`.
