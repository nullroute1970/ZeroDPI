# Candidate Bypass Methods for ZeroDPI

> **Status:** research / landscape note (spike findings, 2026-08-16).
> This document is **not** an approved design. It describes bypass methods that
> ZeroDPI does *not* currently implement, how each would fit the existing
> architecture, what it would cost, and what risks it carries. Any method
> pursued from this list needs its own design doc and implementation plan
> before code is written.

---

## 1. Purpose and scope

ZeroDPI currently ships 12 combinable bypass methods (see §3). This document
surveys the remaining techniques used by comparable open-source tools
(ByeDPI, GoodbyeDPI, zapret) plus a few standards-backed ideas that those
tools do not use, and assesses each one against ZeroDPI's two plugin
surfaces (§2).

The goal is a ranked shortlist so that the next bypass method to build is
chosen deliberately instead of by availability bias.

---

## 2. Architecture primer — the two plugin surfaces

ZeroDPI has exactly two places a bypass method can live. Every candidate in
this document maps onto one of them.

### 2.1 Interceptor-based methods (`BypassMethod` trait)

Live in `crates/zerodpi-core/src/methods/`, hook into the WinDivert /
NFQUEUE packet pipeline, and are driven by two hooks:

| Hook | Fires on | Used by |
|---|---|---|
| `on_handshake_complete_ack` | first outbound bare ACK after the TCP handshake | `wrong_seq`, `wrong_ack`, `wrong_checksum`, `wrong_md5`, `wrong_timestamp`, `low_ttl`, `urg_sni_split` |
| `on_first_data_packet` | first outbound packet carrying data | `tls_record_frag` |

The hook returns a `MethodAction`:

- `EmitFakeAndAccept { complete_immediately, continue_with_data }` — stage
  mutations on the `PacketView` and emit; optionally keep watching for an
  inbound ACK or a later data packet.
- `CompleteAndAccept` / `PassThrough` / `AbortAndAccept` — forward
  unchanged with varying completion semantics.

Mutations are staged on `PacketView` fields: `new_seq`, `new_ack`,
`new_flags`, `new_payload`, `replace_tcp_options`, `append_tcp_options`,
`bump_ipv4_ident`, `corrupt_tcp_checksum_delta`, `new_ipv4_ttl`,
`new_urgent_pointer`. **A hook currently emits exactly one packet.**

Registration happens in `methods::build_method`; combos are built as a
`CompositeMethod` (chained handshake methods + optional data method +
socket-side flags). Interceptor methods require Administrator/root
(WinDivert / NFQUEUE) and are IPv4-only today.

### 2.2 Socket-based methods (no interception)

Operate directly on the proxy's upstream `TcpStream` in `proxy.rs`. They do
**not** implement `BypassMethod`, the flow is never registered in the
`FlowTable`, and they need no packet interception at all (no admin/root on
Windows, no NFQUEUE on Linux). Current members: `tls_frag`, `tls_padding`,
`mixed_case_sni`, `sni_boundary_frag`.

### 2.3 Conventions a new method must follow

- Config key group in `SCREAMING_SNAKE_CASE` (e.g. `WRONG_SEQ_EXTRA_OFFSET`),
  parsed into `Config`, documented in `README.md`, validated in
  `Config::validate` (unknown names must fail, combos must be checked).
- Method names join with `_` in config and `" + "` in display names
  (`wrong_seq + tls_frag`).
- Inline `#[cfg(test)]` modules, tests named by behavior
  (`stages_payload_and_wrong_seq`).
- TUI dashboard shows the method name; `--json-events` emits
  `bypass_finished`.

---

## 3. Existing coverage (what is already built)

| Method | Surface | Mechanism |
|---|---|---|
| `wrong_seq` | interceptor, ACK stage | inject fake ClientHello (whitelisted SNI) behind server receive window; DPI inspects it, server discards it |
| `wrong_ack` | interceptor, ACK stage | same desync using a wrong ACK number |
| `wrong_checksum` | interceptor, ACK stage | fake packet with corrupted TCP checksum |
| `wrong_md5` | interceptor, ACK stage | fake packet carrying a TCP-MD5 option |
| `wrong_timestamp` | interceptor, ACK stage | fake packet with an invalid TCP timestamp |
| `low_ttl` | interceptor, ACK stage | fake packet whose TTL expires between DPI and server; includes `LOW_TTL_DISCOVER` probing |
| `urg_sni_split` | interceptor, ACK stage | URG pointer tricks to mislead payload-offset parsing |
| `tls_record_frag` | interceptor, data stage | fragment the TLS record stream (server reassembles, DPI misses SNI) |
| `tls_frag` | socket | write ClientHello in small chunks with `TCP_NODELAY` |
| `tls_padding` | socket | RFC 7685 ClientHello padding extension pushes SNI past DPI inspection windows |
| `mixed_case_sni` | socket | randomize SNI letter case (servers lowercase per RFC 6066, case-sensitive DPI misses) |
| `sni_boundary_frag` | socket | split first record into two TCP segments cut at the SNI extension boundary, with delay |
| `ccs_prefix` | socket | dummy ChangeCipherSpec record before the ClientHello; first-record DPIs see no SNI (RFC 8446 §4.1.3) |

Composites: `wrong_seq_wrong_md5`, `wrong_seq_tls_frag`,
`wrong_md5_tls_frag`, `wrong_seq_tls_record_frag`, `wrong_seq_tls_padding`,
`wrong_seq_sni_boundary_frag`, and any list form in
`BYPASS_METHOD = [...]`.

**Gap summary:** the fake-packet injection family (ByeDPI `--wrong-seq`
etc.) is fully covered; TCP segmentation (`tls_frag`), padding, and
boundary splitting are covered. What is missing versus the comparable tools
is `fake_tls` variant B (socket-side forged record length), out-of-order
delivery (`disorder`), and record-level tricks such as `tls_record_split`
and `tcp_opt_pad`.

---

## 4. Ranked candidates

Ranking weighs value (how often the technique wins where existing methods
lose) against implementation cost in ZeroDPI's architecture.

---

### 4.1 `fake_tls` — decoy TLS record injection *(high value, medium effort)*

**Status (2026-08-16):** Variant A implemented (`fake_tls`, interceptor,
data stage, dual-packet emission with `FAKE_TLS_FORWARD_REAL`). Variant B
remains a not-implemented follow-up candidate.

**Overview.** Inject a decoy TLS record containing a ClientHello with a
whitelisted/benign SNI so that the DPI keys its classification on the decoy,
while the upstream server processes the genuine ClientHello. This is
ByeDPI's most effective mode and the largest missing weapon in ZeroDPI.

**Why it evades.** `wrong_seq` already injects a bare fake ClientHello at
the ACK stage, but that only fools DPIs that are lax about TCP sequence
numbers. `fake_tls` targets DPIs that *do* track the stream correctly but
only parse TLS records — the decoy is a well-formed TLS record, so a
record-parsing DPI sees a complete, benign ClientHello as the first record
and never inspects the real one. The server, however, ends up processing
the genuine ClientHello (variant A) or is spec-tolerated into ignoring the
decoy (variant B), so the VPN handshake succeeds.

**Two implementation variants.**

- **Variant A — interceptor, out-of-window decoy (recommended).** At
  `on_first_data_packet`, stage the existing fake ClientHello
  (`flow.fake_data`, already built by the TLS template with a whitelisted
  SNI) wrapped in a valid TLS record header (`0x16`, record version from
  the template, length = payload len), emitted with a sequence number
  behind the server's receive window exactly like `WrongSeq`:
  `syn_seq + 1 - payload_len - extra_offset`. The DPI parses the decoy
  record; the server discards the segment as old/duplicate; the real
  ClientHello follows untouched. Reuses the entire `wrong_seq` staging
  pattern — the only new code is the TLS record wrapper and hooking the
  data stage.
- **Variant B — socket-side, forged record length (ByeDPI-style).** Write
  the decoy record ahead of the real ClientHello with a forged length
  field spanning decoy + real bytes, so the DPI's record parser sees only
  the decoy while the server's parser lands on the genuine ClientHello.
  This is how ByeDPI does it, but the exact byte-crafting must be validated
  empirically against real TLS stacks (OpenSSL/BoringSSL behavior
  differs); it should not be implemented from a description alone. Treat
  this variant as follow-up work after variant A proves the concept.

**Proposed config.** `FAKE_TLS_EXTRA_OFFSET` (extra bytes subtracted from
the decoy seq, default 0), `FAKE_TLS_SET_PSH` (bool), `FAKE_TLS_DECOY_SNI`
(optional override; default reuses the template's whitelisted SNI).

**Platform.** Interceptor variant: WinDivert/NFQUEUE, IPv4, admin/root.
Socket variant: anywhere.

**Risks.** Variant A inherits the wrong_seq assumption that the DPI
accepts out-of-window segments for inspection; on networks where the DPI
is strict about seq validation, it degrades to no-op (safe, not harmful).
Variant B risks breaking the handshake on strict servers — needs a
`complete_immediately`-style escape hatch and abort-on-failure handling.

**Effort.** Medium. ~150–250 LOC plus tests. The TLS record wrapper and
payload reuse are trivial; the work is hooking the data stage, config, and
validation.

**References.** ByeDPI (`fake_tls` desync mode).

---

### 4.2 `ip_frag` — IP-layer fragmentation *(high value, medium effort)*

**Status (2026-08-15):** Implemented (`ip_frag`, interceptor, data stage,
multi-fragment emission via raw socket on Linux/Android NFQUEUE and
WinDivert on Windows, with fragment-all mode via
`IP_FRAG_ONLY_FIRST_PACKET = false`; requires the shared multi-packet
emission plumbing, which `disorder` can now reuse).

**Overview.** Fragment the first outbound data packet (the one carrying the
ClientHello) at the IP layer into small fragments (e.g. 8–32 bytes).

**Why it evades.** This attacks a completely different axis than every
existing method: IP-layer reassembly. The destination's kernel reassembles
fragments before delivering to the TLS stack, so the handshake succeeds
normally. Many inline DPIs do not reassemble IP fragments at all (or give
up after a short reassembly budget), so they never see a complete
ClientHello and cannot extract the SNI. GoodbyeDPI ships this as
`--frag-by-ip`; zapret ships it as `ipfrag`.

**ZeroDPI integration.** Interceptor-side, data stage. Requires a
prerequisite the pipeline does not have today: **multi-packet emission**
from a single hook. `PacketView` currently stages mutations for exactly one
outbound packet; fragmenting means emitting N fragments (split IP payload,
set fragment offsets and the MF bit, clear DF, recompute checksums, bump
IP ident). This is a small but real interceptor infrastructure change
(apply staged fragments in the interceptor after the handler runs), after
which the method itself is straightforward. Fragment size is a config knob;
a middle ground is fragmenting only the first packet so the rest of the
stream is untouched.

**Proposed config.** `IP_FRAG_SIZE` (payload bytes per fragment, default
e.g. 24), `IP_FRAG_ONLY_FIRST_PACKET` (bool, default true).

**Platform.** WinDivert/NFQUEUE, IPv4, admin/root. (IPv4 fragmentation is
the well-trodden path; IPv6 fragment headers would be follow-up.)

**Risks.** Some middleboxes drop all IP fragments (then the handshake
fails — recoverable by aborting the bypass and letting the raw stream
through); fragmented packets can be rate-limited on some paths; fragment
storms from the first packet only, so impact is bounded. PMTU: must clear
the DF bit for fragmentation to be legal.

**Effort.** Medium. Most of the cost is the multi-packet emission
plumbing; the fragmentation math itself is ~100 LOC plus tests.

**References.** GoodbyeDPI `--frag-by-ip`, zapret `ipfrag`.

---

### 4.3 `ccs_prefix` — TLS 1.3 middlebox-compat ChangeCipherSpec *(moderate value, trivial effort)*

**Status (2026-08-16):** Implemented (`ccs_prefix`, socket-side, writes the
dummy CCS record `14 03 03 00 01 01` as the first upstream bytes, version
configurable via `CCS_PREFIX_RECORD_VERSION`).

**Overview.** Write a dummy ChangeCipherSpec record
(`14 03 03 00 01 01`) as the very first bytes of the upstream stream,
immediately before the real ClientHello.

**Why it evades.** RFC 8446 §5.5 requires TLS 1.3 servers to treat a
ChangeCipherSpec received before their first Finished message as a no-op
(middlebox compatibility mode, RFC 8446 §4.1.3). Many DPIs that parse TLS
records key their classification on the *first* record; the first record is
now a CCS, not a ClientHello, so there is no SNI to find and the flow is
classified benign. The genuine ClientHello arrives as record two and the
server ignores the CCS per the spec.

**ZeroDPI integration.** Socket-side, a few lines in `proxy.rs`: prepend
the 6-byte CCS record to the first write (only the first write — the
ClientHello may be fragmented by `tls_frag`, in which case the CCS still
precedes the first chunk). No `BypassMethod` impl needed; wire it like
`tls_padding` as a socket-side flag on the composite, so it composes with
handshake-stage methods (`BYPASS_METHOD = ["wrong_seq", "ccs_prefix"]`).

**Proposed config.** `CCS_PREFIX_ENABLED` is implicit via the method name;
a `CCS_PREFIX_RECORD_VERSION` knob (default `0x0303`) if we ever want to
vary the record version field.

**Platform.** Everywhere — pure socket transform, no admin/root needed.
This makes it one of the few new methods that works on Termux/Android
without NFQUEUE.

**Risks.** TLS 1.2 servers are not required to tolerate a pre-ClientHello
CCS (RFC 5246 treats unexpected CCS as an error, though many
implementations ignore it). Modern CDN/VPN endpoints are TLS 1.3 and
fine; document the TLS 1.2 caveat. DPIs that scan *every* record still
catch the real ClientHello — this is a cheap trick that wins against
first-record-only DPIs, not a universal bypass.

**Effort.** Small. ~30–50 LOC plus tests and README documentation.

**References.** RFC 8446 §4.1.3 (middlebox compatibility mode), §5.5
(server MUST treat early CCS as no-op).

---

### 4.4 `disorder` — out-of-order TCP segmentation *(moderate value, higher effort)*

**Overview.** Split the ClientHello into two or three TCP segments and
emit them in reverse order (with correct sequence numbers), optionally with
delays between them.

**Why it evades.** The destination kernel reassembles out-of-order segments
before the TLS stack sees them, so the handshake is unaffected. DPIs that
reassemble per-flow state (or that inspect the first segment they see)
either choke on the non-monotonic sequence numbers or classify on a
garbage-order fragment and miss the SNI. ByeDPI (`disorder`), GoodbyeDPI
(`--disorder`), and zapret all ship this.

**ZeroDPI integration.** Interceptor-side, data stage. Like `ip_frag` (§4.2)
this needs **multi-packet emission** from the hook: buffer the first data
packet, re-chunk its payload into segments with correct seq/length fields,
and emit them in non-monotonic order. The kernel at the far end
reassembles; the DPI sees the later segment first. A socket-side variant
is not possible (a `TcpStream` always emits bytes in order — reordering
requires control of the wire, i.e. the interceptor).

**Proposed config.** `DISORDER_SEGMENTS` (2 or 3), `DISORDER_DELAY_MS`
(delay between segments, default 0), `DISORDER_REVERSE` (bool, default
true).

**Platform.** WinDivert/NFQUEUE, IPv4, admin/root.

**Risks.** Same middlebox-fragility family as `ip_frag`; a few strict
networks drop non-monotonic segments (bounded, recoverable). More
aggressive variants (delays + reorder) add connection-setup latency,
which the README already warns about for small fragments.

**Effort.** Medium-to-large. Multi-packet emission plumbing plus the
reorder logic; more invasive than `ip_frag` because the payload must be
re-chunked across packet boundaries, not just re-fragmented.

**References.** ByeDPI `disorder`, GoodbyeDPI `--disorder`, zapret.

---

### 4.5 `tls_record_split` — ClientHello across two TLS records *(moderate value, low effort)*

**Overview.** Re-frame the ClientHello so it spans two TLS records:
record 1 carries the handshake header and every extension up to (but not
including) the SNI extension; record 2 carries the SNI extension and the
rest of the message.

**Why it evades.** The TLS record layer explicitly permits handshake
messages to span multiple records (RFC 8446 §5.1, RFC 5246 §6.2.1), so a
compliant server reassembles the message and the handshake proceeds. DPIs
that inspect only the first record (or that assume the ClientHello is
always record 1) find no SNI in record 1 and classify benign. This is the
record-level sibling of `sni_boundary_frag` (which splits one record
across TCP segments) and is distinct from `tls_record_frag` (which
fragments records after the handshake).

**ZeroDPI integration.** Socket-side, like `sni_boundary_frag`: reuse its
ClientHello parser to locate the SNI extension, then re-encode the first
record as two records split at an extension boundary. Compose as a
socket-side composite flag. Note the split must fall on an *extension*
boundary — never mid-extension — or the server rejects the message.

**Proposed config.** `TLS_RECORD_SPLIT_POINT` (split before the SNI
extension by default; allow "before extension N" or byte offsets that the
parser snaps to the nearest extension boundary).

**Platform.** Everywhere — pure socket transform.

**Risks.** Some server implementations (historically a few TLS 1.2
stacks) reject fragmented ClientHellos; TLS 1.3 implementations are
required to handle message fragmentation across records. Middleboxes
that expect the ClientHello in record 1 are precisely the target — but
some *drop* such connections, so keep the existing
`PassThrough`/abort-on-failure pattern so the raw stream can be forwarded
if the split fails validation.

**Effort.** Small-to-medium. ~100–150 LOC reusing the `sni_boundary_frag`
parser, plus tests.

**References.** RFC 8446 §5.1, RFC 5246 §6.2.1.

---

### 4.6 `tcp_opt_pad` — junk/duplicated TCP options on the first data packet *(low effort, low reliability)*

**Overview.** Append bogus or duplicated TCP options (unknown option
numbers, repeated timestamps) to the first outbound data packet so the
DPI's TCP option parser misaligns or its payload-offset computation lands
in the wrong place.

**Why it evades.** Cheap DPIs that compute the TCP payload offset by
walking options can be confused by options they do not recognize, causing
them to misread where the ClientHello starts. Robust DPIs skip unknown
options correctly, so this is a low-probability trick — but it costs
almost nothing.

**ZeroDPI integration.** Interceptor-side, data stage, and unusually easy:
`PacketView` already carries `append_tcp_options`, so staging the junk
options is a one-field mutation with no new infrastructure.

**Proposed config.** `TCP_OPT_PAD_COUNT` (number of padding/junk options,
default e.g. 4), `TCP_OPT_PAD_REPEAT_TS` (bool — duplicate the timestamp
option if negotiated).

**Platform.** WinDivert/NFQUEUE, IPv4, admin/root.

**Risks.** Over-long option blocks (>40 bytes) make the header invalid;
must stay within TCP header limits. Some middleboxes drop packets with
unknown options. Low expected hit rate — treat as a cheap extra tool in
composite lists, not a headline method.

**Effort.** Small. ~50 LOC plus tests.

**References.** zapret TCP-option manipulation modes.

---

## 5. Marginal candidates (not recommended)

| Candidate | Why not |
|---|---|
| `fake_rst` — inject a fake RST with an out-of-window seq so the DPI thinks the connection died | DPIs that track connections re-sync on the next packet; unreliable against modern DPIs, and a mis-crafted RST can kill the real connection. |
| `mss_clamp` — rewrite the MSS option on the SYN so the server sends smaller segments | Only affects the server→proxy direction *after* the handshake; the ClientHello/SNI inspection happens in the client→server direction. It cannot help the SNI bypass. |
| `split2` / fixed-offset split variants | Already covered by `tls_frag` (chunked writes) and `sni_boundary_frag` (two-segment boundary split with delay). A fixed-offset variant adds no new evasion axis. |
| `wrong_ip_checksum` — fake packet with corrupted IP checksum | The wrong_checksum family already covers the checksum axis; IP-checksum corruption is ignored by too many stacks to justify a new method. |

---

## 6. Not implementable as ZeroDPI methods

| Idea | Why it cannot be a relay method |
|---|---|
| **ECH (Encrypted ClientHello)** | ECH requires the *VPN client* to perform the ECH key exchange and encrypt its own ClientHello. ZeroDPI relays an opaque byte stream; it cannot rewrite the client's ClientHello because it does not hold the client's keys. If ECH is wanted, it belongs in the VPN client, not in ZeroDPI. |
| **QUIC / HTTP/3 interception** | ZeroDPI is a TCP relay (VPN clients speak TLS-over-TCP). QUIC bypass would be a different product. |
| **HTTP-layer tricks** (CONNECT splitting, HTTP/2 prior-knowledge games) | The upstream traffic is a TLS stream, not HTTP; there is no HTTP surface to desync. |
| **SNI removal** | For `ip_bypass` the server needs a name to route on; removing the SNI only works where the target serves the site on the IP directly, which is what the existing IP-scanning modes already exploit. |

---

## 7. Comparison table

| Method | Category | Surface | Platform | Effort | Value |
|---|---|---|---|---|---|
| `fake_tls` (variant A) | decoy record injection | interceptor, data stage | WinDivert/NFQUEUE, IPv4 | medium | high |
| `ip_frag` | IP-layer fragmentation | interceptor, data stage | WinDivert/NFQUEUE, IPv4 | medium* | high |
| `ccs_prefix` | TLS middlebox compat | socket | everywhere | small — ✅ implemented | moderate |
| `disorder` | out-of-order segmentation | interceptor, data stage | WinDivert/NFQUEUE, IPv4 | medium–large* | moderate |
| `tls_record_split` | record-level handshake split | socket | everywhere | small–medium | moderate |
| `tcp_opt_pad` | TCP option junk | interceptor, data stage | WinDivert/NFQUEUE, IPv4 | small | low |

\* Requires the multi-packet emission infrastructure change in the
interceptor (prerequisite shared by `ip_frag` and `disorder`).

---

## 8. Recommendation

Build in this order:

1. **`fake_tls` (variant A)** — ✅ implemented. Variant B (socket-side forged
   length) remains follow-up work, validated empirically against real TLS
   stacks.
2. **`ccs_prefix`** — ✅ implemented.
3. **`ip_frag`** — ✅ implemented, including the multi-packet emission
   plumbing, so `disorder` (4) becomes cheap follow-up.
4. **`disorder`** — reuse the emission plumbing.
5. **`tls_record_split`** / **`tcp_opt_pad`** — cheap additions once the
   pattern for socket-side and option-staging methods is established.

Skip §5 entirely. Do not attempt §6.

---

## 9. Implementation checklist (when a method is approved)

Per repository guidelines (`AGENTS.md`) and §2.3, each approved method needs:

- [ ] Design doc under `docs/superpowers/specs/` + implementation plan under
      `docs/superpowers/plans/`
- [ ] `BypassMethod` trait impl (interceptor) **or** socket-side wiring in
      `proxy.rs` + composite flag (socket)
- [ ] Registration in `methods::build_method` (and `" + "`-joined display
      name for composites)
- [ ] Config group in `SCREAMING_SNAKE_CASE`, parsed into `Config` with
      defaults, documented in `README.md` (config table + combining rules)
- [ ] `Config::validate` updates: accept the new name, enforce combo rules,
      keep `rejects_unknown_bypass_method` passing
- [ ] Inline `#[cfg(test)]` tests named by behavior (staging math, record
      building, split boundaries, fragment offsets, validation)
- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
      -- -D warnings`, `cargo test --workspace`
- [ ] Platform notes in README (admin/root requirements, IPv4-only
      interceptor caveat, Termux guidance)
- [ ] TUI/`--json-events` display check for the new method name

---

## 10. References

- ByeDPI — `fake_tls`, `disorder`, `--wrong-seq`/`--wrong-ack`/etc.
  (the desync family ZeroDPI's interceptor methods are modeled on)
- GoodbyeDPI — `--frag-by-ip`, `--disorder`, `--wrong-chksum`
- zapret — `ipfrag`, TCP-option manipulation, fake TLS desync
- RFC 7685 — ClientHello padding extension (basis of `tls_padding`)
- RFC 6066 — SNI definition (basis of `mixed_case_sni`)
- RFC 8446 §4.1.3, §5.5 — middlebox compatibility mode (basis of
  `ccs_prefix`); §5.1 — handshake messages may span records (basis of
  `tls_record_split`)
- RFC 5246 §6.2.1 — record-layer fragmentation of handshake messages
