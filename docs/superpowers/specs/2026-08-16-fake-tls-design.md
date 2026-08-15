# Decoy TLS Record Injection (`fake_tls`) — Design Spec

Date: 2026-08-16
Source: `docs/bypass-methods-candidates.md` §4.1 (variant A), refined through
chat design review.

## Goal

Add a new interceptor-based bypass method, `fake_tls`, that injects a decoy
TLS record containing a ClientHello with the whitelisted SNI as the *first
record the DPI parses on the data stage*, while the upstream TLS server
processes the genuine ClientHello. It targets DPIs that track TCP sequence
numbers correctly but only parse TLS records (where `wrong_seq`'s bare
ACK-stage injection is ignored), and is ByeDPI's most effective mode.

Two emission modes, selected by config:

- `FAKE_TLS_FORWARD_REAL = true` (default): the decoy packet is emitted and
  the original first data packet (real ClientHello) is forwarded immediately
  after — no added latency. Requires the new dual-packet-emission plumbing.
- `FAKE_TLS_FORWARD_REAL = false`: the first data packet itself is rewritten
  into the decoy with an out-of-window sequence number; the real ClientHello
  reaches the server via TCP retransmission (~1 RTO ≈ 200 ms). No new
  plumbing.

## Mechanism

New module `crates/zerodpi-core/src/methods/fake_tls.rs` implementing
`BypassMethod`:

- `on_handshake_complete_ack` returns `MethodAction::PassThrough` — the
  handler puts the flow into `waiting_for_data` mode (same as
  `tls_record_frag`).
- `on_first_data_packet` stages the decoy on the captured first data packet:
  - **Payload**: `flow.fake_data` used as-is. The template already is a
    complete, well-formed TLS record (`16 03 01 02 00` header + 512-byte
    ClientHello body, 517 bytes total). Record version `0x0301` matches what
    Chrome/OpenSSL send for the first ClientHello under TLS 1.3 compatibility
    rules, so no record-version knob is needed.
  - **Sequence number**: `syn_seq + 1 - payload_len - FAKE_TLS_EXTRA_OFFSET`
    (wrapping `u32` arithmetic), placing the decoy behind the server's
    receive window exactly like `WrongSeq`. The server discards the segment
    as old/duplicate; a record-parsing DPI inspects it as the first record.
  - **Flags**: `new_flags` with PSH per `FAKE_TLS_SET_PSH`;
    `bump_ipv4_ident` per `FAKE_TLS_BUMP_IP_IDENT`.
  - **Completion**: returns
    `MethodAction::EmitFakeAndAccept { complete_immediately: FAKE_TLS_COMPLETE_IMMEDIATELY, continue_with_data: false }`.
  - **Dual emission**: when `FAKE_TLS_FORWARD_REAL`, set
    `pkt.emit_original_after = true` (new `PacketView` field, Phase 2).

## Handler changes (`crates/zerodpi-core/src/handler.rs`)

`FlowState` gains `waiting_for_first_data_ack: bool` (default `false`). The
data-stage branch sets it when a data-stage method returns
`EmitFakeAndAccept { complete_immediately: false, .. }`.

While set:

- Outbound packets pass through (`Verdict::Accept`) instead of triggering the
  "unexpected outbound packet" path — the retransmitted/forwarded real
  ClientHello must not close the flow.
- Inbound bare ACKs: if `seq == syn_ack_seq + 1` and
  `ack.wrapping_sub(syn_seq + 1) > 0` (the server acknowledged at least one
  byte of the first data packet), finish with `BypassOutcome::FakeDataAcked`
  and clear the flag. ACKs that do not advance (the dup-ACK the server sends
  for the discarded decoy) pass through and keep waiting.

This path is required for `FAKE_TLS_COMPLETE_IMMEDIATELY = false` to be
meaningful; today only `fake_sent` flows have an inbound-ACK completion path
and a data-stage method with `complete_immediately = false` would otherwise
end in `UnexpectedClose`. `tls_record_frag` is not modified by this project.

## Platform plumbing (Phase 2)

- `PacketView` gains `emit_original_after: bool` (default `false`). All
  existing constructors/tests across the workspace are updated mechanically.
- **Windows** (`zerodpi-platform/src/windows.rs`): when the verdict is
  `AcceptModified` and the flag is set, send the modified packet
  (`build_modified`) then send the original captured packet, in that order.
  WinDivert supports sending arbitrary packets.
- **Linux/Android** (`zerodpi-platform/src/linux.rs`): NFQUEUE can only
  verdict the one queued packet, so dual emission injects the decoy through a
  raw socket first, then verdicts the original `Accept`. The decoy bytes come
  from `build_modified`; the raw socket is opened in
  `PacketInterceptor::open` (runs as root; Android: inside
  `zerodpi-root-helper`, which has `CAP_NET_RAW`). The queue holds the
  original packet until the verdict, so the decoy is guaranteed to hit the
  wire first.
- **Fallback**: if the raw socket cannot be opened, log a warning once and
  treat `emit_original_after` as unset (single modified emission — i.e. the
  `FAKE_TLS_FORWARD_REAL = false` behavior). A connection must never be
  broken by plumbing failure.
- The flag is only meaningful with `AcceptModified`; backends ignore it for
  other verdicts.

## Configuration

New `Config` fields (defaults follow existing conventions; documented in
`config.toml` with a `fake_tls method parameters` section):

| Key | Type | Default | Validation |
|-----|------|---------|------------|
| `FAKE_TLS_EXTRA_OFFSET` | u32 | `0` | none (mirror of `WRONG_SEQ_EXTRA_OFFSET`) |
| `FAKE_TLS_SET_PSH` | bool | `true` | — |
| `FAKE_TLS_BUMP_IP_IDENT` | bool | `true` | — |
| `FAKE_TLS_COMPLETE_IMMEDIATELY` | bool | `true` | — |
| `FAKE_TLS_FORWARD_REAL` | bool | `true` | — (Phase 2) |

No `FAKE_TLS_DECOY_SNI` (rejected in review; the active scan target's SNI is
always used).

## Registration & validation

- `BASE_BYPASS_METHODS` += `"fake_tls"`.
- `BypassMethodList::requires_interceptor` includes it automatically (it is
  not in the socket-side exclusion list); `is_socket_only` unchanged.
- `methods::build_method`: `"fake_tls" => data = Some(Box::new(FakeTls::new(cfg)))`.
- `CompositeMethod` name joins with `" + "` (existing generic path).
- `Config::validate`:
  - Reject `["fake_tls", "tls_record_frag"]` and
    `["fake_tls", "urg_sni_split"]` in any order — all three own the first
    data packet. Error message follows the existing `urg_sni_split` style.
  - Combos with handshake fake methods (`wrong_seq`, `wrong_ack`,
    `wrong_checksum`, `wrong_md5`, `wrong_timestamp`, `low_ttl`) are allowed:
    the ACK-stage decoy fires first, then `fake_tls` at the data stage.
  - Combos with socket-side methods (`tls_frag`, `tls_padding`,
    `mixed_case_sni`, `sni_boundary_frag`) are allowed; socket transforms run
    before the write and `fake_tls` intercepts the first data packet
    regardless of content.
  - `MODE = "ip_bypass_plus"` keeps its existing explicit allowlist — no
    change needed; add a test asserting `fake_tls` is rejected there.
- TUI renders the method name generically; `--json-events` emits
  `bypass_finished` generically. No TUI work.

## Testing

- `fake_tls.rs`: staging math (`new_seq`, wraparound with small ISN,
  extra-offset), PSH/ident knobs, `complete_immediately` action selection,
  `emit_original_after` staging, payload is the 517-byte template record
  unchanged.
- `handler.rs`: data-stage emission paths; `waiting_for_first_data_ack`
  pass-through of outbound data; inbound ACK completion (advancing ack
  finishes with `FakeDataAcked`, non-advancing dup-ACK keeps waiting).
- `config.rs`: defaults parse; unknown-method rejection still passes; new
  combo rejections; `ip_bypass_plus` rejection.
- `methods/mod.rs` / `composite.rs`: `build_method("fake_tls")` returns the
  method; composite name `"wrong_seq + fake_tls"`; data-slot delegation.
- `zerodpi-platform`: unit tests for `build_modified`-based decoy crafting
  (checksums, header fields); backend dual-emission paths covered by existing
  test style where feasible (WinDivert/NFQUEUE loops are integration-tested
  manually per platform).
- Final gates: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`.

## Documentation

- `config.toml`: new `fake_tls method parameters` section (all five keys,
  Phase 2 adds `FAKE_TLS_FORWARD_REAL`).
- `README.md`: methods table row, combining rules (exclusive with
  `tls_record_frag`/`urg_sni_split`), platform notes (admin/root, IPv4-only,
  raw-socket fallback on Linux, latency note for `FORWARD_REAL = false`).
- `docs/bypass-methods-candidates.md`: mark §4.1 variant A implemented;
  variant B remains a not-implemented follow-up candidate.

## Risks

- `FAKE_TLS_FORWARD_REAL = false` inherits the `wrong_seq` assumption that
  the DPI accepts out-of-window segments; where the DPI is strict, the method
  degrades to no-op (safe, not harmful).
- Raw-socket injection on Linux/Android can fail in restricted environments
  (SELinux, unusual kernels) — the fallback path covers it.
- Adds ~200 ms per connection only in the fallback / `FORWARD_REAL = false`
  path.
- Interceptor methods are IPv4-only and require Administrator/root, as
  documented for the existing family.

## Phasing

- **Phase 1** (shippable alone): `fake_tls.rs`, handler ACK-completion path,
  four config keys (no `FAKE_TLS_FORWARD_REAL`), registration, validation,
  docs. Behavior equals plumbing-off variant A.
- **Phase 2**: `PacketView.emit_original_after`, Windows dual send, Linux
  raw-socket injection + fallback, `FAKE_TLS_FORWARD_REAL` config key
  (default `true`) wired into `FakeTls`, doc updates.

Both phases end with the workspace verification gates.
