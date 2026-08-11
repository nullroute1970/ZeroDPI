# urg_sni_split Bypass Method Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new `urg_sni_split` bypass method that injects a 1-byte dummy payload into the middle of the SNI inside the real ClientHello and marks it with the TCP URG flag, so the destination server strips the byte (BSD urgent semantics) while byte-scanning DPI sees a mangled SNI.

**Architecture:** A data-stage interceptor method (like `tls_record_frag`): `on_handshake_complete_ack` returns `PassThrough`, and `on_first_data_packet` parses the payload for the SNI, stages `new_payload` (+1 byte), `new_flags` (`urg = true`), and `new_urgent_pointer`, then returns `emit_and_complete()`. Returning `PassThrough` when the SNI isn't found keeps the existing handler scan alive across subsequent data packets. `PacketView` gains an urgent-pointer mutation slot and both platform backends apply it.

**Tech Stack:** Rust 2021 workspace, etherparse 0.20.1 (TCP header `urg` / `urgent_pointer` fields), serde with untagged enum deserializers (existing `Int32Range` pattern), inline `#[cfg(test)]` unit tests, anyhow.

## Global Constraints

- Config key names are `SCREAMING_SNAKE_CASE`; serde defaults via `#[serde(default = "fn")]`.
- New config keys: `SNI_SPLIT_DUMMY_BYTE: u8` default `0`; `SNI_SPLIT_POSITION` default `"middle"`, accepting `"middle" | "start" | "end" | <int>`.
- New `BYPASS_METHOD` value: `"urg_sni_split"` (must be added to `Config::validate()` whitelist, `build_method()`, and the `BYPASS_METHOD` doc comment).
- Urgent pointer value = byte offset of the dummy byte within the TCP payload + 1 (RFC 793 one-past semantics).
- TLS length fields must NOT be adjusted anywhere — the server's post-URG-strip stream must be byte-identical to the original.
- No changes to `flow.rs`, `FlowController`, the Android remote-helper IPC, `handler.rs` state-machine logic, or `proxy.rs`.
- Code style: rustfmt (4-space indent), no comments beyond normal doc comments, no `todo!()`/`unimplemented!()`.
- Verification (final task): `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Commits use conventional prefixes: `feat:`, `test:`, `docs:`.

---

### Task 1: Config — `SniSplitPosition` enum, two new fields, method whitelist

**Files:**
- Modify: `crates/zerodpi-core/src/config.rs`

**Interfaces:**
- Consumes: nothing (works alone).
- Produces:
  - `pub enum SniSplitPosition { Middle, Start, End, Index(u16) }` with `Debug, Clone, Copy, PartialEq, Eq` and a custom `Deserialize` impl accepting `"middle" | "start" | "end"` or an integer (case-insensitive).
  - `fn default_sni_split_position() -> SniSplitPosition` returning `Middle`.
  - `fn default_sni_split_dummy_byte() -> u8` returning `0`.
  - `Config.SNI_SPLIT_DUMMY_BYTE: u8` (`#[serde(default = "default_sni_split_dummy_byte")]`).
  - `Config.SNI_SPLIT_POSITION: SniSplitPosition` (`#[serde(default = "default_sni_split_position")]`).
  - `Config::validate()` accepts `"urg_sni_split"` in the `BYPASS_METHOD` whitelist.

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `crates/zerodpi-core/src/config.rs`:

```rust
#[test]
fn sni_split_defaults() {
    let toml_str = r#"
        LISTEN_HOST = "0.0.0.0"
        LISTEN_PORT = 40443
    "#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.SNI_SPLIT_DUMMY_BYTE, 0);
    assert_eq!(cfg.SNI_SPLIT_POSITION, SniSplitPosition::Middle);
}

#[test]
fn sni_split_position_parsing() {
    for (toml_value, expected) in [
        ("\"middle\"", SniSplitPosition::Middle),
        ("\"MIDDLE\"", SniSplitPosition::Middle),
        ("\"start\"", SniSplitPosition::Start),
        ("\"end\"", SniSplitPosition::End),
        ("3", SniSplitPosition::Index(3)),
        ("0", SniSplitPosition::Index(0)),
    ] {
        let toml_str = format!(
            r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            SNI_SPLIT_POSITION = {toml_value}
        "#
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg.SNI_SPLIT_POSITION, expected);
    }
}

#[test]
fn invalid_sni_split_position_rejected() {
    let toml_str = r#"
        LISTEN_HOST = "0.0.0.0"
        LISTEN_PORT = 40443
        SNI_SPLIT_POSITION = "sideways"
    "#;
    assert!(toml::from_str::<Config>(toml_str).is_err());
}

#[test]
fn urg_sni_split_is_a_valid_method() {
    let toml_str = r#"
        LISTEN_HOST = "0.0.0.0"
        LISTEN_PORT = 40443
        BYPASS_METHOD = "urg_sni_split"
    "#;
    let cfg: Config = toml::from_str(toml_str).unwrap();
    cfg.validate().unwrap();
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core config::tests::sni_split_defaults config::tests::sni_split_position_parsing config::tests::invalid_sni_split_position_rejected config::tests::urg_sni_split_is_a_valid_method`
Expected: FAIL — `Config` has no fields `SNI_SPLIT_DUMMY_BYTE`/`SNI_SPLIT_POSITION`, `SniSplitPosition` undefined, and `validate()` rejects `urg_sni_split`.

- [ ] **Step 3: Implement**

In `crates/zerodpi-core/src/config.rs`, after the `TlsFragPackets` impl block (after line 120):

```rust
/// Where inside the SNI domain string `urg_sni_split` inserts its dummy byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniSplitPosition {
    /// Exact middle of the name (`len / 2`).
    Middle,
    /// Before the first name byte.
    Start,
    /// Before the last name byte.
    End,
    /// 0-based index, clamped to `[0, len - 1]`.
    Index(u16),
}

impl<'de> Deserialize<'de> for SniSplitPosition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Int(u16),
            Text(String),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Int(value) => Ok(Self::Index(value)),
            Repr::Text(value) => match value.to_ascii_lowercase().as_str() {
                "middle" => Ok(Self::Middle),
                "start" => Ok(Self::Start),
                "end" => Ok(Self::End),
                _ => Err(de::Error::custom(format!(
                    "'{value}' is not a valid SNI_SPLIT_POSITION; valid values: \"middle\", \"start\", \"end\", or an integer"
                ))),
            },
        }
    }
}
```

Add the two fields to the `Config` struct. Place them after the `TLS_RECORD_FRAG_BUMP_IP_IDENT` field (after line 451), under a new comment banner:

```rust
    // -----------------------------------------------------------------------
    // urg_sni_split method parameters
    // -----------------------------------------------------------------------
    /// The 1-byte dummy payload `urg_sni_split` inserts into the middle of the
    /// SNI domain string. The destination server's TCP stack extracts this
    /// byte as urgent data, so its TLS stream is unaffected; DPI middleboxes
    /// that read the raw byte stream see the mangled name.
    /// Default: `0`.
    #[serde(default = "default_sni_split_dummy_byte")]
    pub SNI_SPLIT_DUMMY_BYTE: u8,

    /// Where `urg_sni_split` inserts the dummy byte inside the SNI domain
    /// string. Supported values: `"middle"` (default), `"start"`, `"end"`,
    /// or a 0-based integer index (clamped to the last byte).
    #[serde(default = "default_sni_split_position")]
    pub SNI_SPLIT_POSITION: SniSplitPosition,
```

Add the default fns next to the other defaults (after `default_tls_frag_size` at line 728-730):

```rust
fn default_sni_split_dummy_byte() -> u8 {
    0
}
fn default_sni_split_position() -> SniSplitPosition {
    SniSplitPosition::Middle
}
```

Add `"urg_sni_split"` to the `BYPASS_METHOD` whitelist in `Config::validate()` (lines 875-894): add `| "urg_sni_split"` after `"tls_frag"` in the `matches!` list AND add `\"urg_sni_split\"` to the error-message string.

Add a bullet to the `BYPASS_METHOD` doc comment (after the `"tls_frag"` bullet at line 226-230):

```rust
    /// - `"urg_sni_split"` — injects a 1-byte dummy payload into the middle of
    ///   the SNI inside the real ClientHello and sets the TCP URG flag so the
    ///   destination server strips the byte while byte-scanning DPI sees a
    ///   mangled SNI. No fake packet is injected; the server reassembles the
    ///   original handshake via BSD urgent-data semantics.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core config::tests`
Expected: PASS (all four new tests; existing config tests still pass).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/config.rs
git commit -m "feat: add SNI_SPLIT_* config options and urg_sni_split whitelist entry"
```

---

### Task 2: Core plumbing — `TcpFlags.urg` and `PacketView.new_urgent_pointer`

**Files:**
- Modify: `crates/zerodpi-core/src/interceptor.rs` (TcpFlags at line 25, PacketView at lines 40-84)
- Modify (mechanical, compile-driven): every `TcpFlags { ... }` and `PacketView { ... }` struct literal across the workspace that lists all fields explicitly.

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `TcpFlags.urg: bool` (derived `Default` keeps `..Default::default()` spreads working).
  - `PacketView.new_urgent_pointer: Option<u16>` — staged mutation; value is the urgent-pointer offset relative to the segment's sequence number (RFC 793 one-past semantics).

- [ ] **Step 1: Write the failing test**

Add to `crates/zerodpi-core/src/interceptor.rs` (new `#[cfg(test)]` module at end of file):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_flags_has_urg_and_defaults_to_false() {
        let flags = TcpFlags::default();
        assert!(!flags.urg);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p zerodpi-core interceptor`
Expected: FAIL — `TcpFlags` has no field `urg`.

- [ ] **Step 3: Implement**

In `crates/zerodpi-core/src/interceptor.rs`:

1. Add to `TcpFlags` (line 25-31):

```rust
    pub urg: bool,
```

2. Add to `PacketView` staged mutations, after `new_flags` (line 62):

```rust
    /// Override the TCP urgent pointer (RFC 793: offset from the segment's
    /// sequence number, one byte past the urgent data). Only meaningful when
    /// `new_flags` sets `urg`.
    pub new_urgent_pointer: Option<u16>,
```

3. Fix every struct literal that the compiler flags as missing fields:
   - `TcpFlags` literals that list all 5 fields: add `urg: false,` (e.g. `parse_view` in both backends, test helpers in `handler.rs` tests, method test files like `wrong_seq.rs`, `tls_record_frag.rs`).
   - `TcpFlags` literals using `..Default::default()`: no change needed.
   - `PacketView` literals: add `new_urgent_pointer: None,` (test helpers in `handler.rs` (`pkt_with_payload`), `tls_record_frag.rs` (`data_pkt`), other method test files, and the platform `make_view()` helpers in `linux.rs` / `windows.rs`).

   Drive this by running the build and fixing each error — do not guess locations:
   Run: `cargo build --workspace --all-targets` and fix every "missing field" error.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core`
Expected: PASS (new test + existing).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/interceptor.rs crates/zerodpi-core/src crates/zerodpi-platform/src
git commit -m "feat: add urg flag and urgent pointer to packet view"
```

---

### Task 3: Platform backends — parse and apply URG + urgent pointer

**Files:**
- Modify: `crates/zerodpi-platform/src/linux.rs` (parse_view lines 183-189, build_modified lines 230-236)
- Modify: `crates/zerodpi-platform/src/windows.rs` (parse_view lines 155-161, build_modified lines 202-208)

**Interfaces:**
- Consumes: `TcpFlags.urg`, `PacketView.new_urgent_pointer` from Task 2.
- Produces: rebuilt packets carrying the URG flag and urgent pointer; `parse_view` populates `flags.urg` from the wire. Round-trip tests prove it.

- [ ] **Step 1: Write the failing tests**

Add to the tests module in `crates/zerodpi-platform/src/linux.rs` (after `round_trip_modified_packet_parses_back`, line 1067):

```rust
#[test]
fn urgent_flag_and_pointer_survive_rebuild() {
    let payload = [0x16, 0x03, 0x03, 0x00, 0x01, 0xAA];
    let buf = data_packet(&payload);
    let (mut view, layout) = parse_view(Direction::Outbound, &buf).unwrap();
    view.new_flags = Some(TcpFlags {
        ack: true,
        psh: true,
        urg: true,
        ..Default::default()
    });
    view.new_urgent_pointer = Some(40);
    let modified = build_modified(&buf, &layout, &view).unwrap();

    let ip2 = Ipv4HeaderSlice::from_slice(&modified).unwrap();
    let tcp2 = TcpHeaderSlice::from_slice(&modified[ip2.slice().len()..]).unwrap();
    assert!(tcp2.urg());
    assert_eq!(tcp2.urgent_pointer(), 40);
    let calculated = tcp2
        .to_header()
        .calc_checksum_ipv4(&ip2.to_header(), &modified[40..])
        .unwrap();
    assert_eq!(tcp2.checksum(), calculated);
}

#[test]
fn parse_view_reads_urg_flag() {
    use etherparse::TcpHeader;
    let mut buf = data_packet(&[]);
    let mut tcp = TcpHeader::from_slice(&buf[20..40]).unwrap().0;
    tcp.urg = true;
    let mut out = Vec::with_capacity(buf.len());
    out.extend_from_slice(&buf[..20]);
    etherparse::Ipv4Header::from_slice(&buf[..20])
        .unwrap()
        .0
        .write(&mut out)
        .unwrap();
    tcp.write(&mut out).unwrap();
    let (view, _) = parse_view(Direction::Outbound, &out).unwrap();
    assert!(view.flags.urg);
}
```

Add the same two tests to the tests module in `crates/zerodpi-platform/src/windows.rs` (after `round_trip_modified_packet_parses_back`, line 413). The code is identical — use the `data_packet` helper already present in windows.rs instead of inlining the packet construction:

```rust
#[test]
fn urgent_flag_and_pointer_survive_rebuild() {
    let payload = [0x16, 0x03, 0x03, 0x00, 0x01, 0xAA];
    let buf = data_packet(&payload);
    let layout = PacketLayout {
        ip_hdr_len: 20,
        tcp_hdr_len: 20,
        payload_off: 40,
        total_len: 40 + payload.len(),
    };
    let (mut view, _) = parse_view(Direction::Outbound, &buf).unwrap();
    view.new_flags = Some(TcpFlags {
        ack: true,
        psh: true,
        urg: true,
        ..Default::default()
    });
    view.new_urgent_pointer = Some(40);
    let modified = build_modified(&buf, &layout, &view).unwrap();

    let ip2 = Ipv4HeaderSlice::from_slice(&modified).unwrap();
    let tcp2 = TcpHeaderSlice::from_slice(&modified[ip2.slice().len()..]).unwrap();
    assert!(tcp2.urg());
    assert_eq!(tcp2.urgent_pointer(), 40);
    let calculated = tcp2
        .to_header()
        .calc_checksum_ipv4(&ip2.to_header(), &modified[40..])
        .unwrap();
    assert_eq!(tcp2.checksum(), calculated);
}

#[test]
fn parse_view_reads_urg_flag() {
    let mut buf = data_packet(&[]);
    use etherparse::TcpHeader;
    let mut tcp = TcpHeader::from_slice(&buf[20..40]).unwrap().0;
    tcp.urg = true;
    let mut out = Vec::with_capacity(buf.len());
    out.extend_from_slice(&buf[..20]);
    etherparse::Ipv4Header::from_slice(&buf[..20]).unwrap().0.write(&mut out).unwrap();
    tcp.write(&mut out).unwrap();
    let (view, _) = parse_view(Direction::Outbound, &out).unwrap();
    assert!(view.flags.urg);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-platform`
Expected: FAIL — `urg` is never set on the rebuilt header and `parse_view` never reads it (assertions `tcp2.urg()`, `tcp2.urgent_pointer()`, `view.flags.urg` fail).

- [ ] **Step 3: Implement**

In `crates/zerodpi-platform/src/linux.rs`:

1. `parse_view` flags block (lines 183-189) — add:

```rust
            urg: tcp.urg(),
```

2. `build_modified` `new_flags` block (lines 230-236) — add after `tcp_hdr.fin = flags.fin;`:

```rust
        tcp_hdr.urg = flags.urg;
```

3. `build_modified`, after the `new_flags` block (after line 236) — add:

```rust
    if let Some(ptr) = view.new_urgent_pointer {
        tcp_hdr.urgent_pointer = ptr;
    }
```

In `crates/zerodpi-platform/src/windows.rs`: apply the identical three changes (flags block at lines 155-161, `new_flags` block at lines 202-208, urgent pointer after line 208).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-platform`
Expected: PASS (all four new tests + existing).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-platform/src/linux.rs crates/zerodpi-platform/src/windows.rs
git commit -m "feat: apply TCP urgent flag and pointer in packet backends"
```

---

### Task 4: SNI parser — `find_sni_range`

**Files:**
- Create: `crates/zerodpi-core/src/methods/urg_sni_split.rs` (this task adds the parser function + its tests; the file grows in Tasks 5-6)

**Interfaces:**
- Consumes: `crate::tls_template::build_client_hello` (existing, for tests).
- Produces: `fn find_sni_range(data: &[u8]) -> Option<(usize, usize)>` — `(start, len)` of the host_name bytes inside `data`, or `None` if the payload is not a complete ClientHello containing a `server_name` extension with a non-empty host_name.

- [ ] **Step 1: Write the failing tests**

Create `crates/zerodpi-core/src/methods/urg_sni_split.rs`:

```rust
//! `urg_sni_split` bypass: injects a 1-byte dummy payload into the middle of
//! the SNI inside the real ClientHello and marks it with the TCP URG flag.
//!
//! ## How it works
//!
//! BSD-style TCP stacks treat the byte at the urgent pointer as out-of-band
//! data: it is extracted from the normal stream, so the destination server's
//! TLS parser receives the original ClientHello byte-for-byte. Stateless DPI
//! middleboxes that ignore the urgent pointer and read the raw byte stream
//! sequentially instead see the SNI with an extra byte spliced into the middle
//! of the domain string, so their blacklist match fails.
//!
//! The method operates on the real first data packet (the ClientHello written
//! by the proxy), never on a fake packet: the server must actually accept and
//! process the handshake. If the SNI cannot be found in a data packet, the
//! method passes it through; the handler keeps offering subsequent data
//! packets until one is rewritten.

use super::{BypassMethod, MethodAction};
use crate::config::{Config, SniSplitPosition};
use crate::flow::FlowState;
use crate::interceptor::PacketView;

/// Find the host_name (SNI) bytes inside a TLS ClientHello payload.
///
/// Walks the TLS record header, handshake header, fixed ClientHello fields,
/// and the extension list to locate the `server_name` extension (type
/// `0x0000`) and its `host_name` entry (name type `0`). Returns `(start, len)`
/// of the name bytes within `data`, or `None` if the payload is not a complete
/// ClientHello containing a valid non-empty host_name.
fn find_sni_range(data: &[u8]) -> Option<(usize, usize)> {
    // TLS record layer: content_type(1) version(2) length(2)
    let record_header = data.get(..5)?;
    if record_header[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
    let record_body = data.get(5..5 + record_len)?;

    // Handshake layer: type(1) length(3)
    if record_body.first() != Some(&0x01) {
        return None;
    }
    let hs_len = ((record_body[1] as usize) << 16)
        | ((record_body[2] as usize) << 8)
        | record_body[3] as usize;
    let body = record_body.get(4..4 + hs_len)?;

    // Fixed ClientHello fields: version(2) random(32) session_id_len(1) session_id
    let mut off = 2 + 32 + 1;
    let sid_len = *body.get(off - 1)? as usize;
    off += sid_len;

    // Cipher suites: len(2) suites
    let cs_pair = body.get(off..off + 2)?;
    let cs_len = u16::from_be_bytes([cs_pair[0], cs_pair[1]]) as usize;
    off += 2 + cs_len;

    // Compression methods: len(1) methods
    let cm_len = *body.get(off)? as usize;
    off += 1 + cm_len;

    // Extensions: total len(2) then the list
    let ext_pair = body.get(off..off + 2)?;
    let ext_total = u16::from_be_bytes([ext_pair[0], ext_pair[1]]) as usize;
    let mut p = off + 2;
    let extensions = body.get(p..p + ext_total)?;

    let mut e = 0;
    while e + 4 <= extensions.len() {
        let ext_len = u16::from_be_bytes([extensions[e + 2], extensions[e + 3]]) as usize;
        let ext_data = extensions.get(e + 4..e + 4 + ext_len)?;
        let ext_type = u16::from_be_bytes([extensions[e], extensions[e + 1]]);
        if ext_type == 0x0000 {
            // server_name: list_len(2) then entries: name_type(1) name_len(2) name
            let list_pair = ext_data.get(..2)?;
            let list_len = u16::from_be_bytes([list_pair[0], list_pair[1]]) as usize;
            let list = ext_data.get(2..2 + list_len)?;
            if list.first() != Some(&0x00) {
                return None;
            }
            let name_pair = list.get(1..3)?;
            let name_len = u16::from_be_bytes([name_pair[0], name_pair[1]]) as usize;
            if name_len == 0 {
                return None;
            }
            list.get(3..3 + name_len)?;
            // name start within `body`: extension list starts at `p`, each
            // extension entry has a 4-byte header, then list_len(2) +
            // name_type(1) + name_len(2) precede the name bytes.
            let name_start_in_body = p + 4 + 2 + 1 + 2;
            // `body` starts 9 bytes into `data` (5 record header + 4
            // handshake header).
            return Some((9 + name_start_in_body, name_len));
        }
        e += 4 + ext_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_template::build_client_hello;

    fn client_hello(sni: &[u8]) -> Vec<u8> {
        build_client_hello(&[0u8; 32], &[0u8; 32], sni, &[0u8; 32])
    }

    #[test]
    fn finds_sni_in_built_client_hello() {
        for sni in [b"auth.vercel.com", b"mci.ir", b"a"] {
            let ch = client_hello(sni);
            assert_eq!(find_sni_range(&ch), Some((127, sni.len())), "sni={sni:?}");
        }
    }

    #[test]
    fn finds_sni_in_an_extension_after_leading_extensions() {
        // Rebuild by splicing: the built CH has the server_name extension
        // first (type 0x0000 at data offset 118). Insert a fake 4-byte
        // extension before it and bump the extensions-total-length field
        // (data offset 116..118) so the structure stays consistent.
        let mut ch = client_hello(b"example.com");
        let mut extended = Vec::with_capacity(ch.len() + 4);
        extended.extend_from_slice(&ch[..118]);
        extended.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // ext type 0x0017, len 0
        extended.extend_from_slice(&ch[118..]);
        let total = u16::from_be_bytes([extended[116], extended[117]]) + 4;
        extended[116] = (total >> 8) as u8;
        extended[117] = total as u8;
        assert_eq!(find_sni_range(&extended), Some((127 + 4, 11)));
    }

    #[test]
    fn rejects_non_handshake_payloads() {
        assert_eq!(find_sni_range(b"GET / HTTP/1.1"), None);
        assert_eq!(find_sni_range(&[]), None);
    }

    #[test]
    fn rejects_truncated_records() {
        let ch = client_hello(b"example.com");
        for cut in [4usize, 10, 100, ch.len() - 1] {
            assert_eq!(find_sni_range(&ch[..cut]), None, "cut={cut}");
        }
    }

    #[test]
    fn rejects_client_hello_without_server_name_extension() {
        let mut ch = client_hello(b"example.com");
        // blank the extension type bytes at data offset 118..120
        ch[118] = 0x00;
        ch[119] = 0x0b;
        assert_eq!(find_sni_range(&ch), None);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core methods::urg_sni_split`
Expected: FAIL — file does not exist / `find_sni_range` not found. (Register the module first: add `pub mod urg_sni_split;` to `crates/zerodpi-core/src/methods/mod.rs` after line 38 `pub mod wrong_ack;` — alphabetically it goes between `tcp_segmentation` and `tls_record_frag`.)

- [ ] **Step 3: Run tests again after wiring the module**

Run: `cargo test -p zerodpi-core methods::urg_sni_split`
Expected: FAIL — `find_sni_range` does not exist in the new module. Then implement the function exactly as written in Step 1's file skeleton.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core methods::urg_sni_split`
Expected: PASS (all five tests). Note: `finds_sni_in_an_extension_after_leading_extensions` and the golden offsets pin the parser to the byte-exact template layout (`server_name` extension type at data offset 118, SNI at 127) — if any offset is wrong the tests fail and the arithmetic in `find_sni_range` must be corrected.

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/methods/urg_sni_split.rs crates/zerodpi-core/src/methods/mod.rs
git commit -m "feat: add ClientHello SNI parser for urg_sni_split"
```

---

### Task 5: Insert helpers — `resolve_insert_position` and `insert_dummy`

**Files:**
- Modify: `crates/zerodpi-core/src/methods/urg_sni_split.rs`

**Interfaces:**
- Consumes: `SniSplitPosition` from Task 1.
- Produces:
  - `fn resolve_insert_position(name_len: usize, pos: SniSplitPosition) -> usize` — 0-based insertion index into the name: `Middle` → `len / 2`, `Start` → 0, `End` → `len - 1`, `Index(n)` → `n` clamped to `[0, len - 1]` (empty name → 0).
  - `fn insert_dummy(payload: &[u8], at: usize, byte: u8) -> Vec<u8>` — `payload` with `byte` spliced in at index `at`.

- [ ] **Step 1: Write the failing tests**

Add to the tests module in `crates/zerodpi-core/src/methods/urg_sni_split.rs`:

```rust
    #[test]
    fn middle_inserts_at_len_div_two() {
        assert_eq!(resolve_insert_position(11, SniSplitPosition::Middle), 5);
        assert_eq!(resolve_insert_position(6, SniSplitPosition::Middle), 3);
        assert_eq!(resolve_insert_position(1, SniSplitPosition::Middle), 0);
    }

    #[test]
    fn start_and_end_are_clamped_into_the_name() {
        assert_eq!(resolve_insert_position(11, SniSplitPosition::Start), 0);
        assert_eq!(resolve_insert_position(11, SniSplitPosition::End), 10);
        assert_eq!(resolve_insert_position(1, SniSplitPosition::End), 0);
    }

    #[test]
    fn index_is_clamped_to_last_byte() {
        assert_eq!(resolve_insert_position(11, SniSplitPosition::Index(3)), 3);
        assert_eq!(resolve_insert_position(11, SniSplitPosition::Index(0)), 0);
        assert_eq!(resolve_insert_position(11, SniSplitPosition::Index(999)), 10);
        assert_eq!(resolve_insert_position(11, SniSplitPosition::Index(10)), 10);
    }

    #[test]
    fn insert_dummy_splices_a_single_byte() {
        let payload = b"0123456789";
        let out = insert_dummy(payload, 4, 0x00);
        assert_eq!(out.len(), payload.len() + 1);
        assert_eq!(&out[..4], b"0123");
        assert_eq!(out[4], 0x00);
        assert_eq!(&out[5..], b"456789");
        assert_eq!(out, [b"0123".as_slice(), &[0x00], b"456789"].concat());
    }

    #[test]
    fn insert_dummy_at_zero_and_end() {
        assert_eq!(insert_dummy(b"ab", 0, 0x00), vec![0x00, b'a', b'b']);
        assert_eq!(insert_dummy(b"ab", 2, 0x00), vec![b'a', b'b', 0x00]);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core methods::urg_sni_split`
Expected: FAIL — `resolve_insert_position` and `insert_dummy` not found.

- [ ] **Step 3: Implement**

Add after `find_sni_range` in `crates/zerodpi-core/src/methods/urg_sni_split.rs`:

```rust
/// Resolve the config position to a 0-based insertion index inside a name of
/// `name_len` bytes. The index always lands inside the name (or at 0 for an
/// empty name).
fn resolve_insert_position(name_len: usize, pos: SniSplitPosition) -> usize {
    if name_len == 0 {
        return 0;
    }
    let idx = match pos {
        SniSplitPosition::Middle => name_len / 2,
        SniSplitPosition::Start => 0,
        SniSplitPosition::End => name_len - 1,
        SniSplitPosition::Index(n) => n as usize,
    };
    idx.min(name_len - 1)
}

/// Return `payload` with `byte` spliced in at index `at`.
fn insert_dummy(payload: &[u8], at: usize, byte: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 1);
    out.extend_from_slice(&payload[..at]);
    out.push(byte);
    out.extend_from_slice(&payload[at..]);
    out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core methods::urg_sni_split`
Expected: PASS (5 existing + 5 new tests).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/methods/urg_sni_split.rs
git commit -m "feat: add SNI insertion helpers for urg_sni_split"
```

---

### Task 6: `UrgSniSplit` method — struct, hooks, factory registration

**Files:**
- Modify: `crates/zerodpi-core/src/methods/urg_sni_split.rs`
- Modify: `crates/zerodpi-core/src/methods/mod.rs` (factory `build_method` line 163-181, tests)

**Interfaces:**
- Consumes: `find_sni_range`, `resolve_insert_position`, `insert_dummy` (Tasks 4-5), `Config.SNI_SPLIT_DUMMY_BYTE` / `Config.SNI_SPLIT_POSITION` (Task 1), `PacketView.new_urgent_pointer` (Task 2).
- Produces:
  - `pub struct UrgSniSplit { dummy_byte: u8, position: SniSplitPosition }`
  - `impl UrgSniSplit { pub fn new(cfg: &Config) -> Self }`
  - `impl BypassMethod for UrgSniSplit` — `name()` → `"urg_sni_split"`; ACK hook → `MethodAction::PassThrough`; data hook → staged mutations + `emit_and_complete()`, or `PassThrough` when the SNI isn't found.

- [ ] **Step 1: Write the failing tests**

Add to the tests module in `crates/zerodpi-core/src/methods/urg_sni_split.rs` (extend the existing `use` statements with `std::net::Ipv4Addr`, `FlowState`, `Direction`, `PacketView`, `TcpFlags`, and `crate::tls_template::build_client_hello`):

```rust
    fn default_cfg() -> Config {
        toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap()
    }

    fn data_pkt(payload: &'static [u8]) -> PacketView<'static> {
        let payload_len = payload.len();
        PacketView {
            direction: Direction::Outbound,
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            src_port: 12345,
            dst_port: 443,
            seq: 1001,
            ack: 5001,
            flags: TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            },
            payload_len,
            payload,
            tcp_options: &[],
            new_seq: None,
            new_ack: None,
            new_flags: None,
            new_payload: None,
            replace_tcp_options: None,
            append_tcp_options: Vec::new(),
            bump_ipv4_ident: false,
            corrupt_tcp_checksum_delta: None,
            new_ipv4_ttl: None,
            new_urgent_pointer: None,
        }
    }

    #[test]
    fn on_handshake_complete_ack_is_passthrough() {
        let method = UrgSniSplit::new(&default_cfg());
        let state = FlowState::new(vec![]);
        let mut pkt = data_pkt(&[]);
        assert_eq!(
            method.on_handshake_complete_ack(&state, &mut pkt),
            MethodAction::PassThrough
        );
    }

    #[test]
    fn on_first_data_packet_splits_sni_and_sets_urg() {
        let method = UrgSniSplit::new(&default_cfg());
        let state = FlowState::new(vec![]);
        let sni = b"auth.vercel.com";
        let ch = build_client_hello(&[0u8; 32], &[0u8; 32], sni, &[0u8; 32]);
        let payload: &'static [u8] = Box::leak(ch.into_boxed_slice());
        let mut pkt = data_pkt(payload);

        let action = method.on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        let new_payload = pkt.new_payload.as_ref().unwrap();
        assert_eq!(new_payload.len(), payload.len() + 1);
        // "auth.vercel.com" is 15 bytes; middle = index 7; SNI starts at 127.
        let insert_at = 127 + 7;
        assert_eq!(new_payload[insert_at], 0); // default dummy byte
        assert_eq!(&new_payload[..insert_at], &payload[..insert_at]);
        assert_eq!(&new_payload[insert_at + 1..], &payload[insert_at..]);
        let flags = pkt.new_flags.unwrap();
        assert!(flags.urg);
        assert!(flags.ack);
        assert!(flags.psh);
        assert_eq!(pkt.new_urgent_pointer, Some((insert_at + 1) as u16));
    }

    #[test]
    fn configurable_byte_and_position() {
        let mut cfg = default_cfg();
        cfg.SNI_SPLIT_DUMMY_BYTE = b'X';
        cfg.SNI_SPLIT_POSITION = SniSplitPosition::Start;
        let method = UrgSniSplit::new(&cfg);
        let state = FlowState::new(vec![]);
        let ch = build_client_hello(&[0u8; 32], &[0u8; 32], b"mci.ir", &[0u8; 32]);
        let payload: &'static [u8] = Box::leak(ch.into_boxed_slice());
        let mut pkt = data_pkt(payload);

        let action = method.on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        let new_payload = pkt.new_payload.as_ref().unwrap();
        assert_eq!(new_payload[127], b'X');
        assert_eq!(new_payload[128], b'm');
        assert_eq!(pkt.new_urgent_pointer, Some(128));
    }

    #[test]
    fn passes_through_when_sni_not_found() {
        let method = UrgSniSplit::new(&default_cfg());
        let state = FlowState::new(vec![]);
        let mut pkt = data_pkt(b"GET / HTTP/1.1");
        let action = method.on_first_data_packet(&state, &mut pkt);
        assert_eq!(action, MethodAction::PassThrough);
        assert!(pkt.new_payload.is_none());
        assert!(pkt.new_flags.is_none());
        assert!(pkt.new_urgent_pointer.is_none());
    }
```

Also add the factory dispatch test to `mod tests` in `crates/zerodpi-core/src/methods/mod.rs` (after `build_wrong_seq_tls_frag_method`):

```rust
    #[test]
    fn build_urg_sni_split_method() {
        let cfg = cfg_with_method("urg_sni_split");
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "urg_sni_split");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core methods`
Expected: FAIL — `UrgSniSplit` not found; factory returns `None` for `urg_sni_split`.

- [ ] **Step 3: Implement**

Add to `crates/zerodpi-core/src/methods/urg_sni_split.rs` (after `insert_dummy`):

```rust
/// `urg_sni_split` bypass method.
pub struct UrgSniSplit {
    dummy_byte: u8,
    position: SniSplitPosition,
}

impl UrgSniSplit {
    pub fn new(cfg: &Config) -> Self {
        Self {
            dummy_byte: cfg.SNI_SPLIT_DUMMY_BYTE,
            position: cfg.SNI_SPLIT_POSITION,
        }
    }
}

impl BypassMethod for UrgSniSplit {
    fn name(&self) -> &'static str {
        "urg_sni_split"
    }

    /// Returns `PassThrough` — this method operates on the first data packet,
    /// not the handshake-complete ACK. The handler sets `waiting_for_data` and
    /// calls [`on_first_data_packet`] instead.
    ///
    /// [`on_first_data_packet`]: UrgSniSplit::on_first_data_packet
    fn on_handshake_complete_ack(
        &self,
        _flow: &FlowState,
        _pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        MethodAction::PassThrough
    }

    /// Splices the dummy byte into the middle of the SNI and stages the URG
    /// flag and urgent pointer, then returns `EmitFakeAndAccept` to signal
    /// bypass completion. When the payload does not contain a parseable
    /// ClientHello with an SNI, returns `PassThrough` so the handler keeps
    /// offering subsequent data packets.
    fn on_first_data_packet(&self, _flow: &FlowState, pkt: &mut PacketView<'_>) -> MethodAction {
        let Some((name_start, name_len)) = find_sni_range(pkt.payload) else {
            return MethodAction::PassThrough;
        };
        let insert_at = name_start + resolve_insert_position(name_len, self.position);
        let new_payload = insert_dummy(pkt.payload, insert_at, self.dummy_byte);

        let mut flags = pkt.flags;
        flags.urg = true;

        // RFC 793: the urgent pointer is the offset from this segment's
        // sequence number, one byte past the urgent data.
        let urgent_pointer = u16::try_from(insert_at + 1).unwrap_or(u16::MAX);

        pkt.new_payload = Some(new_payload);
        pkt.new_flags = Some(flags);
        pkt.new_urgent_pointer = Some(urgent_pointer);

        MethodAction::emit_and_complete()
    }
}
```

In `crates/zerodpi-core/src/methods/mod.rs`:
1. Add `pub mod urg_sni_split;` to the module list (alphabetically after `pub mod tcp_segmentation;`).
2. Add to `build_method` (after the `wrong_seq_tls_record_frag` arm):

```rust
        "urg_sni_split" => Some(Box::new(urg_sni_split::UrgSniSplit::new(cfg))),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core methods`
Expected: PASS (all new tests + existing dispatch tests).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/methods/urg_sni_split.rs crates/zerodpi-core/src/methods/mod.rs
git commit -m "feat: add urg_sni_split bypass method"
```

---

### Task 7: Handler integration tests

**Files:**
- Modify: `crates/zerodpi-core/src/handler.rs` (tests module, after `tls_record_frag_waits_for_first_data_packet` at line 934)

**Interfaces:**
- Consumes: `UrgSniSplit::new(&cfg)` (Task 6), `build_client_hello` (existing), the existing test helpers `default_cfg`, `pkt`, `pkt_with_payload`.
- Produces: state-machine-level proof that the method stages mutations through `Handler::on_packet` and that the scan continues across data packets.

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `crates/zerodpi-core/src/handler.rs`:

1. Add imports after line 314 (`use crate::methods::wrong_timestamp::WrongTimestamp;`):

```rust
    use crate::methods::urg_sni_split::UrgSniSplit;
    use crate::tls_template::build_client_hello;
```

2. Add a helper after `tls_record` (line 393):

```rust
    fn client_hello(sni: &[u8]) -> &'static [u8] {
        Box::leak(build_client_hello(&[0u8; 32], &[0u8; 32], sni, &[0u8; 32]).into_boxed_slice())
    }
```

3. Add the tests after `tls_record_frag_waits_for_first_data_packet` (line 934):

```rust
    #[test]
    fn urg_sni_split_rewrites_first_data_packet() {
        let flows = new_flow_table();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            dst_port: 443,
        };
        let entry = FlowEntry::new(vec![0xAA; 517]);
        flows.insert(key, entry.clone());

        let mut cfg = default_cfg();
        cfg.BYPASS_METHOD = "urg_sni_split".into();
        let mut h = Handler::new(flows, Arc::new(UrgSniSplit::new(&cfg)));

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            1000,
            0,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            5000,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            1001,
            5001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);
        assert!(entry.state.lock().waiting_for_data);

        let payload = client_hello(b"auth.vercel.com");
        let mut p = pkt_with_payload(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            },
            1001,
            5001,
            payload,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::AcceptModified);
        assert_eq!(p.new_payload.as_ref().unwrap().len(), payload.len() + 1);
        // "auth.vercel.com" = 15 bytes, middle = index 7, SNI at 127.
        assert_eq!(p.new_payload.as_ref().unwrap()[127 + 7], 0);
        assert!(p.new_flags.unwrap().urg);
        assert_eq!(p.new_urgent_pointer, Some((127 + 7 + 1) as u16));
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::FakeDataAcked)
        );
    }

    #[test]
    fn urg_sni_split_scans_until_sni_found() {
        let flows = new_flow_table();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            dst_port: 443,
        };
        let entry = FlowEntry::new(vec![0xAA; 517]);
        flows.insert(key, entry.clone());

        let mut cfg = default_cfg();
        cfg.BYPASS_METHOD = "urg_sni_split".into();
        let mut h = Handler::new(flows, Arc::new(UrgSniSplit::new(&cfg)));

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            1000,
            0,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);
        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            5000,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);
        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            1001,
            5001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        // First data packet has no parseable SNI: passed through, scan alive.
        let mut p = pkt_with_payload(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            },
            1001,
            5001,
            b"NOT-TLS",
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);
        assert!(p.new_payload.is_none());
        assert!(entry.state.lock().waiting_for_data);

        // Second data packet carries the ClientHello: rewritten.
        let payload = client_hello(b"mci.ir");
        let mut p = pkt_with_payload(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            },
            1001,
            5001,
            payload,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::AcceptModified);
        assert_eq!(p.new_payload.as_ref().unwrap().len(), payload.len() + 1);
        assert!(p.new_flags.unwrap().urg);
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::FakeDataAcked)
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core handler::tests::urg_sni_split_rewrites_first_data_packet handler::tests::urg_sni_split_scans_until_sni_found`
Expected: FAIL — `UrgSniSplit` import fails (method not implemented yet).

- [ ] **Step 3: Run tests after Task 6 is complete**

If Tasks 4-6 are already done, the tests should pass immediately. If any assertion fails, the likely culprits are the golden offsets (127, 118) — verify against `crate::tls_template`'s `embeds_sni_at_expected_offset` test and the `find_sni_range` arithmetic from Task 4.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core handler`
Expected: PASS (all handler tests, including the two new ones).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/handler.rs
git commit -m "test: add handler integration tests for urg_sni_split"
```

---

### Task 8: Config files and README documentation

**Files:**
- Modify: `config.toml`
- Modify: `android/app/src/main/assets/zerodpi/config.toml`
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing at runtime; documents the Task 1 config keys and the method.

- [ ] **Step 1: Add config.toml documentation**

In `config.toml` (repo) and `android/app/src/main/assets/zerodpi/config.toml`, insert a new section after the `tls_record_frag` parameter block (after `TLS_RECORD_FRAG_BUMP_IP_IDENT = true`, which ends around line 555 in the repo file):

```toml
# ---------------------------------------------------------------------------
# urg_sni_split method parameters
# ---------------------------------------------------------------------------
# These settings apply when BYPASS_METHOD = "urg_sni_split".

# The 1-byte dummy payload inserted into the middle of the SNI domain string
# of the real ClientHello.  The packet's TCP URG flag marks this byte as
# urgent data: BSD-style destination stacks extract it from the stream, so the
# server still sees the original SNI, while DPI middleboxes that read the raw
# byte stream see a mangled name.  Default: 0.
SNI_SPLIT_DUMMY_BYTE = 0

# Where inside the SNI domain string the dummy byte is inserted.
#   "middle" — exact middle of the name (default)
#   "start"  — before the first name byte
#   "end"    — before the last name byte
#   N        — 0-based index into the name, clamped to the last byte
SNI_SPLIT_POSITION = "middle"
```

- [ ] **Step 2: Add README documentation**

In `README.md`:

1. Line 55: change `12 bypass methods` to `13 bypass methods` and append `, urg_sni_split` to the method list.
2. In the method table (after the `tls_record_frag` row at line 332):

```markdown
| `urg_sni_split` | Splicing a dummy byte into the middle of the real SNI and marking it with the TCP URG flag, so the server strips the byte while DPI reads a mangled name | ✅ Yes | Byte-scanning stateless DPI that ignores TCP urgent data |
```

3. In the "How methods work" bullet list (after the `tls_record_frag` bullet at line 363):

```markdown
- `urg_sni_split` rewrites the real first TLS record, splicing a configurable dummy byte into the middle of the SNI and setting the TCP URG flag. The destination server's TCP stack extracts the urgent byte, so its TLS stream is the original ClientHello; DPI that reads raw bytes sees a mangled SNI.
```

4. In the config reference table (line 600), append `, urg_sni_split` to the `BYPASS_METHOD` accepted values, and after the `tls_record_frag` Parameters section (ends around line 682), add:

```markdown
#### `urg_sni_split` Parameters

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `SNI_SPLIT_DUMMY_BYTE` | `u8` | `0` | Dummy byte spliced into the middle of the SNI domain string; extracted by the server as TCP urgent data. |
| `SNI_SPLIT_POSITION` | `string` or `int` | `"middle"` | Insertion point inside the SNI: `"middle"`, `"start"`, `"end"`, or a 0-based index (clamped). |
```

- [ ] **Step 3: Verify the two config.toml files parse**

Run: `cargo run --bin zerodpi -- --help` — skip if heavy; instead verify with the core config test:

Run: `cargo test -p zerodpi-core config::tests::urg_sni_split_is_a_valid_method`
Expected: PASS. Then validate the repo config.toml still loads:

Run: `cargo test -p zerodpi-core`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add config.toml android/app/src/main/assets/zerodpi/config.toml README.md
git commit -m "docs: document urg_sni_split method and SNI_SPLIT_* options"
```

---

### Task 9: Final verification

**Files:** none (verification only).

- [ ] **Step 1: Format check**

Run: `cargo fmt --all -- --check`
Expected: no output, exit 0. If it reports changes, run `cargo fmt --all` and re-check.

- [ ] **Step 2: Lint**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: exit 0, no warnings.

- [ ] **Step 3: Full test suite**

Run: `cargo test --workspace`
Expected: all tests pass.

- [ ] **Step 4: Manual smoke test (optional, needs root/WinDivert)**

Run: `cargo run --bin zerodpi -- --config ./config.toml` with `BYPASS_METHOD = "urg_sni_split"` and a real VPN client connection; capture the first data packet and confirm via Wireshark that the URG flag is set, the urgent pointer lands one byte past a dummy byte inside the SNI, and the handshake completes.

- [ ] **Step 5: Commit any leftover changes**

```bash
git status
git add -A
git commit -m "chore: final urg_sni_split polish"
```

---

## Self-Review Notes

- Spec coverage: parser (Task 4), position/insert helpers (Task 5), method hooks + factory (Task 6), URG plumbing core (Task 2) and backends (Task 3), config keys + whitelist (Task 1), config.toml ×2 + README (Task 8), handler integration incl. scan semantics (Task 7), verification (Task 9). No spec requirement left untasked.
- Out-of-scope items explicitly excluded: combos with other methods, MODE/`ip_bypass_plus` changes, socket-side variants, mid-boundary SNI splitting — none are implemented or wired.
- Type consistency: `SniSplitPosition` variants and `new_urgent_pointer: Option<u16>` names are identical across Tasks 1-7; `find_sni_range`/`resolve_insert_position`/`insert_dummy` signatures match their only consumer (Task 6).
