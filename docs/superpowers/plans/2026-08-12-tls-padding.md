# TLS ClientHello Padding Expansion (`tls_padding`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `tls_padding` bypass method that expands the real TLS ClientHello with an RFC 7685 padding extension, pushing the SNI past DPI inspection windows, usable standalone (socket-only) and combined with interceptor methods.

**Architecture:** A new pure parsing/rewriting module `crates/zerodpi-core/src/methods/tls_padding.rs` (`TlsPadding::apply`) rewrites the client's real ClientHello. `proxy.rs` calls it in the socket-only handler (`handle_tcp_seg_connection_with_ip`) and in the interceptor path's data stage (`handle_intercept_connection`). Config gains `TLS_PADDING_SIZE` / `TLS_PADDING_POSITION`; the method-list helpers (`is_socket_only`, `requires_interceptor`) treat `tls_padding` like `tls_frag`.

**Tech Stack:** Rust 2021 workspace, tokio, serde/toml config, anyhow. No new dependencies (RNG is the repo's inline splitmix64 pattern).

## Global Constraints

- Rust 2021 workspace; rustfmt with 4-space indent; `snake_case` files; `PascalCase` types, `snake_case` fns/vars, `SCREAMING_SNAKE_CASE` config fields.
- Tests are inline `#[cfg(test)]` modules named by behavior.
- Every task must leave the workspace compiling and its crate's tests green.
- Method name in config: exactly `"tls_padding"`. Config keys: `TLS_PADDING_SIZE` (Int32Range, default `"1500-2500"`, validated `>= 1` and `max <= 16000`), `TLS_PADDING_POSITION` (string, `"before"` default or `"after"`).
- Padding is fail-open: unparseable records are forwarded unchanged (`apply` returns `None`).
- Padding applies to the client's **real** ClientHello only — never the fake injected one from `tls_template.rs`.
- Final padded TLS record must never exceed 16383 bytes (TLS record-layer maximum); clamp at runtime.
- The fake packet stage is not affected: `build_method` treats `tls_padding` exactly like `tls_frag` (a no-op arm, socket side).
- Final gate (Task 5): `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo build --workspace --release` all pass.

---

### Task 1: Core `TlsPadding` module

**Files:**
- Create: `crates/zerodpi-core/src/methods/tls_padding.rs`
- Modify: `crates/zerodpi-core/src/methods/mod.rs` (add `pub mod tls_padding;`)

**Interfaces:**
- Consumes: `crate::config::Int32Range` (existing, has `min: i32`, `max: i32`, `parse(&str) -> Result<Self, String>`, `exact(i32)`, `Display`).
- Produces (later tasks rely on these exact names):
  - `pub enum PaddingPosition { Before, After }` — derives `Debug, Clone, Copy, PartialEq, Eq`; `pub fn parse(input: &str) -> Result<Self, String>` (accepts `"before"` / `"after"`, case-insensitive; error otherwise).
  - `pub struct TlsPadding { pub size: Int32Range, pub position: PaddingPosition }` — derives `Debug, Clone, Copy`; `pub fn exact(size: i32, position: PaddingPosition) -> Self`; `pub fn apply(&self, record: &[u8]) -> Option<Vec<u8>>`.
  - Private `struct ClientHelloLayout { ext_len_off: usize, ext_start: usize, sni_off: Option<usize> }` and `fn parse_client_hello(record: &[u8]) -> Option<ClientHelloLayout>` (module-internal, used by tests).
- Note: `TlsPadding::new(&Config)` is intentionally NOT added here — `Config` fields arrive in Task 2.

- [ ] **Step 1: Write the failing tests + module skeleton**

Create `crates/zerodpi-core/src/methods/tls_padding.rs` with the test module and minimal stub types (no `apply` implementation yet — return `None`):

```rust
//! `tls_padding` bypass: TLS ClientHello Padding Expansion (RFC 7685).
//!
//! ## How it works
//!
//! Many DPI middleboxes inspect only the first `N` bytes of a TLS stream
//! (typically 512, 1024, or 1460 bytes) to locate the SNI. This method
//! inserts an RFC 7685 padding extension (type `0x0015`) filled with zero
//! bytes into the client's real TLS ClientHello:
//!
//! - `PaddingPosition::Before` (default) inserts the padding immediately
//!   before the SNI extension, moving the SNI to byte offset
//!   `original_offset + 4 + pad_len` — past the DPI's inspection window.
//!   The destination server still parses the whole record; unknown
//!   extensions are skipped (RFC 5246 §7.4.1.4).
//! - `PaddingPosition::After` appends the padding at the end of the
//!   extension list (canonical RFC 7685 placement).
//!
//! This method does **not** inject fake packets and does **not** use
//! WinDivert/NFQUEUE interception; it operates entirely inside the proxy
//! task on the real ClientHello relayed to the upstream server.
//!
//! Parsing is generic (not template-based) and **fail-open**: any record
//! that does not parse as a TLS ClientHello is left untouched (`apply`
//! returns `None` and the caller forwards the original bytes).
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `TLS_PADDING_SIZE` | `Int32Range` | `"1500-2500"` | Zero-byte count of the padding extension, sampled per connection and clamped to the 16383-byte TLS record limit. |
//! | `TLS_PADDING_POSITION` | `"before"` / `"after"` | `"before"` | Where the padding extension is inserted. |

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Int32Range;

/// TLS record-layer maximum payload length (2^14 - 1).
const MAX_TLS_RECORD_BODY: usize = 16_383;

/// Where the RFC 7685 padding extension is inserted inside the ClientHello
/// extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingPosition {
    /// Immediately before the SNI extension: moves the SNI bytes past the
    /// DPI's inspection window.
    Before,
    /// At the end of the extension list (canonical RFC 7685 placement).
    After,
}

impl PaddingPosition {
    /// Parse a `TLS_PADDING_POSITION` config value.
    pub fn parse(input: &str) -> Result<Self, String> {
        match input.trim().to_ascii_lowercase().as_str() {
            "before" => Ok(Self::Before),
            "after" => Ok(Self::After),
            _ => Err(format!(
                "'{input}' is not a valid TLS_PADDING_POSITION; valid values: \"before\", \"after\""
            )),
        }
    }
}

/// Parameters for the `tls_padding` bypass method.
#[derive(Debug, Clone, Copy)]
pub struct TlsPadding {
    /// Zero-byte count of the padding extension, sampled per connection.
    pub size: Int32Range,
    /// Where the padding extension is inserted.
    pub position: PaddingPosition,
}

impl TlsPadding {
    /// Fixed-size constructor (used by tests and by callers that sample
    /// differently).
    pub fn exact(size: i32, position: PaddingPosition) -> Self {
        Self {
            size: Int32Range::exact(size),
            position,
        }
    }

    /// Insert a padding extension into `record`, returning the expanded
    /// record, or `None` when the record is not a parseable TLS ClientHello
    /// or no padding would fit (fail-open: forward unchanged).
    pub fn apply(&self, _record: &[u8]) -> Option<Vec<u8>> {
        None // implemented in Step 3
    }
}

/// Parsed offsets inside a ClientHello record.
struct ClientHelloLayout {
    /// Offset of the 2-byte extensions-block length field.
    ext_len_off: usize,
    /// Offset of the first extension's type field (right after the length
    /// field).
    ext_start: usize,
    /// Offset of the SNI extension's type field, when present.
    sni_off: Option<usize>,
}

fn parse_client_hello(_record: &[u8]) -> Option<ClientHelloLayout> {
    None // implemented in Step 3
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_template::build_client_hello;

    /// Hand-build a minimal TLS 1.2 ClientHello (null compression, one
    /// cipher suite, optional SNI extension) for tests that need a
    /// ClientHello without the template's fixed structure.
    fn minimal_client_hello(sni: Option<&[u8]>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        body.extend_from_slice(&[7u8; 32]);    // random
        body.push(0);                          // no session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[1, 0]);       // null compression
        let mut exts = Vec::new();
        if let Some(sni) = sni {
            let mut data = Vec::new();
            data.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes()); // list length
            data.push(0);                                                    // name type
            data.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            data.extend_from_slice(sni);
            exts.extend_from_slice(&[0x00, 0x00]); // server_name
            exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
            exts.extend_from_slice(&data);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x01]); // handshake record
        record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        record.push(0x01); // ClientHello
        record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // 3-byte length
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn before_placement_moves_sni_past_original_offset() {
        let record = build_client_hello(&[0u8; 32], &[0u8; 32], b"auth.vercel.com", &[0u8; 32]);
        let padded = TlsPadding::exact(1000, PaddingPosition::Before)
            .apply(&record)
            .expect("template ClientHello must parse");
        // record grew by 4 (extension header) + 1000 (zeros)
        assert_eq!(padded.len(), record.len() + 1004);
        // padding extension (type 0x0015, length 1000 = 0x03E8) sits right
        // before the SNI extension (whose type field is at offset 118 in the
        // template, 9 bytes before the SNI name at offset 127)
        assert_eq!(&padded[118..122], &[0x00, 0x15, 0x03, 0xE8]);
        assert!(padded[122..118 + 1004].iter().all(|&b| b == 0));
        // SNI name moved from offset 127 to 127 + 1004
        assert_eq!(&padded[127 + 1004..127 + 1004 + 15], b"auth.vercel.com");
        // length fields updated
        assert_eq!(u16::from_be_bytes([padded[3], padded[4]]), padded.len() as u16 - 5);
        let hs_len =
            ((padded[6] as usize) << 16) | ((padded[7] as usize) << 8) | padded[8] as usize;
        assert_eq!(hs_len, padded.len() - 9);
        // reparses with the SNI at the moved offset
        let layout = parse_client_hello(&padded).expect("padded record must reparse");
        assert_eq!(layout.sni_off, Some(118 + 1004));
    }

    #[test]
    fn after_placement_keeps_sni_offset_and_appends_padding() {
        let record = build_client_hello(&[0u8; 32], &[0u8; 32], b"auth.vercel.com", &[0u8; 32]);
        let padded = TlsPadding::exact(500, PaddingPosition::After)
            .apply(&record)
            .expect("template ClientHello must parse");
        assert_eq!(padded.len(), record.len() + 504);
        // SNI stays at its original offset
        assert_eq!(&padded[127..127 + 15], b"auth.vercel.com");
        // padding extension (type 0x0015, length 500 = 0x01F4) at the end
        let start = padded.len() - 504;
        assert_eq!(&padded[start..start + 4], &[0x00, 0x15, 0x01, 0xF4]);
        assert!(padded[start + 4..].iter().all(|&b| b == 0));
        let layout = parse_client_hello(&padded).expect("padded record must reparse");
        assert_eq!(layout.sni_off, Some(118));
    }

    #[test]
    fn no_sni_appends_padding_at_end() {
        let record = minimal_client_hello(None);
        let padded = TlsPadding::exact(64, PaddingPosition::Before)
            .apply(&record)
            .expect("minimal ClientHello must parse");
        assert_eq!(padded.len(), record.len() + 68);
        let layout = parse_client_hello(&padded).expect("padded record must reparse");
        assert_eq!(layout.sni_off, None);
        let start = padded.len() - 68;
        assert_eq!(&padded[start..start + 4], &[0x00, 0x15, 0x00, 0x40]);
        assert!(padded[start + 4..].iter().all(|&b| b == 0));
    }

    #[test]
    fn before_placement_with_minimal_client_hello() {
        let record = minimal_client_hello(Some(b"example.com"));
        let layout_orig = parse_client_hello(&record).expect("original must parse");
        let sni_off = layout_orig.sni_off.expect("SNI present");
        let padded = TlsPadding::exact(200, PaddingPosition::Before)
            .apply(&record)
            .expect("minimal ClientHello must parse");
        assert_eq!(padded.len(), record.len() + 204);
        let layout = parse_client_hello(&padded).expect("padded must reparse");
        assert_eq!(layout.sni_off, Some(sni_off + 204));
        let sni = layout.sni_off.unwrap();
        assert_eq!(&padded[sni + 4..sni + 9], &[0x00, 0x0E, 0x00, 0x00, 0x0B]);
        assert_eq!(&padded[sni + 9..sni + 9 + 11], b"example.com");
    }

    #[test]
    fn malformed_records_are_not_padded() {
        let record = build_client_hello(&[0u8; 32], &[0u8; 32], b"mci.ir", &[0u8; 32]);
        let padding = TlsPadding::exact(100, PaddingPosition::Before);
        // truncated record
        assert_eq!(padding.apply(&record[..10]), None);
        // wrong content type (application data, not handshake)
        let mut wrong_type = record.clone();
        wrong_type[0] = 0x17;
        assert_eq!(padding.apply(&wrong_type), None);
        // wrong handshake type (ServerHello)
        let mut wrong_hs = record.clone();
        wrong_hs[5] = 0x02;
        assert_eq!(padding.apply(&wrong_hs), None);
        // corrupted handshake length field
        let mut bad_len = record.clone();
        bad_len[8] = 0xFF;
        assert_eq!(padding.apply(&bad_len), None);
        // not a TLS record at all
        assert_eq!(padding.apply(b"hello world"), None);
    }

    #[test]
    fn clamps_padding_to_tls_record_limit() {
        let record = build_client_hello(&[0u8; 32], &[0u8; 32], b"mci.ir", &[0u8; 32]);
        // requested 20_000 zero bytes; record is 517 bytes; clamp so the
        // final record body is exactly 16383 bytes
        let padded = TlsPadding::exact(20_000, PaddingPosition::After)
            .apply(&record)
            .expect("template ClientHello must parse");
        assert_eq!(padded.len(), 16_383 + 5);
        assert_eq!(u16::from_be_bytes([padded[3], padded[4]]), 16_383);
        // record already at the limit: nothing fits, fail-open passthrough
        assert_eq!(TlsPadding::exact(16_383, PaddingPosition::After).apply(&padded), None);
    }

    #[test]
    fn samples_padding_size_within_configured_range() {
        let record = build_client_hello(&[0u8; 32], &[0u8; 32], b"mci.ir", &[0u8; 32]);
        let padding = TlsPadding {
            size: Int32Range::parse("1000-2000").unwrap(),
            position: PaddingPosition::Before,
        };
        for _ in 0..200 {
            let padded = padding.apply(&record).expect("must parse");
            let used = padded.len() - record.len() - 4;
            assert!((1000..=2000).contains(&used), "sampled {used} outside 1000-2000");
        }
    }

    #[test]
    fn parses_padding_position() {
        assert_eq!(
            PaddingPosition::parse("before").unwrap(),
            PaddingPosition::Before
        );
        assert_eq!(
            PaddingPosition::parse("after").unwrap(),
            PaddingPosition::After
        );
        assert_eq!(
            PaddingPosition::parse("BEFORE").unwrap(),
            PaddingPosition::Before
        );
        assert!(PaddingPosition::parse("middle").is_err());
        assert!(PaddingPosition::parse("").is_err());
    }
}
```

- [ ] **Step 2: Declare the module and run the tests to verify they fail**

In `crates/zerodpi-core/src/methods/mod.rs`, add the module declaration (alphabetically between `tcp_segmentation` and `tls_record_frag`):

```rust
pub mod tls_padding;
```

Run: `cargo test -p zerodpi-core tls_padding`
Expected: FAIL — the stub `apply` returns `None`, so `expect("...must parse")` panics ("fail-open stub").

- [ ] **Step 3: Implement parsing and padding**

Replace the stub `parse_client_hello` and `apply` in `crates/zerodpi-core/src/methods/tls_padding.rs`, and add the RNG below the `TlsPadding` impl:

```rust
    /// Insert a padding extension into `record`, returning the expanded
    /// record, or `None` when the record is not a parseable TLS ClientHello
    /// or no padding would fit (fail-open: forward unchanged).
    pub fn apply(&self, record: &[u8]) -> Option<Vec<u8>> {
        let layout = parse_client_hello(record)?;
        let pad_len = sample_size(self.size, &mut PaddingRng::new()) as usize;
        // Clamp so the final record body (record.len() - 5 + 4 + pad_len)
        // never exceeds the TLS record-layer maximum (2^14 - 1 = 16383).
        let max_pad = MAX_TLS_RECORD_BODY.saturating_sub(record.len() - 5 + 4);
        let pad_len = pad_len.min(max_pad);
        if pad_len == 0 {
            return None;
        }
        Some(build_padded(record, &layout, pad_len, self.position))
    }
```

```rust
fn parse_client_hello(record: &[u8]) -> Option<ClientHelloLayout> {
    // TLS record header: content type (5 bytes total).
    if record.len() < 9 || record[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() != 5 + record_len {
        return None;
    }
    // Handshake header: type must be ClientHello (0x01).
    if record[5] != 0x01 {
        return None;
    }
    let hs_len = ((record[6] as usize) << 16) | ((record[7] as usize) << 8) | record[8] as usize;
    if 4 + hs_len != record_len {
        return None;
    }
    let body = &record[9..];
    // version (2) + random (32)
    if body.len() < 34 {
        return None;
    }
    let mut p = 34;
    // session id
    if p >= body.len() {
        return None;
    }
    let sid_len = body[p] as usize;
    p += 1;
    if p + sid_len > body.len() {
        return None;
    }
    p += sid_len;
    // cipher suites
    if p + 2 > body.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if p + cipher_len > body.len() {
        return None;
    }
    p += cipher_len;
    // compression methods
    if p >= body.len() {
        return None;
    }
    let comp_len = body[p] as usize;
    p += 1;
    if p + comp_len > body.len() {
        return None;
    }
    p += comp_len;
    // extensions block (must be present and consume the rest of the body)
    if p + 2 > body.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if p + ext_len != body.len() {
        return None;
    }
    // scan extensions for the SNI extension (type 0x0000)
    let ext_start = p;
    let mut q = ext_start;
    let mut sni_off = None;
    while q < body.len() {
        if q + 4 > body.len() {
            return None;
        }
        let etype = u16::from_be_bytes([body[q], body[q + 1]]);
        let elen = u16::from_be_bytes([body[q + 2], body[q + 3]]) as usize;
        q += 4;
        if q + elen > body.len() {
            return None;
        }
        if etype == 0x0000 {
            sni_off = Some(q - 4);
        }
        q += elen;
    }
    Some(ClientHelloLayout {
        ext_len_off: 9 + p - 2,
        ext_start: 9 + ext_start,
        sni_off: sni_off.map(|off| off + 9),
    })
}

/// Build the expanded record: copy everything up to the extension block
/// length field, bump the three length fields by `4 + pad_len`, and insert
/// the padding extension at `position`.
fn build_padded(
    record: &[u8],
    layout: &ClientHelloLayout,
    pad_len: usize,
    position: PaddingPosition,
) -> Vec<u8> {
    let ext_end = record.len();
    let old_ext_len =
        u16::from_be_bytes([record[layout.ext_len_off], record[layout.ext_len_off + 1]]) as usize;
    let add = 4 + pad_len;
    let new_ext_len = old_ext_len + add;
    let new_hs_len = (((record[6] as usize) << 16)
        | ((record[7] as usize) << 8)
        | record[8] as usize)
        + add;

    let insert_at = match (position, layout.sni_off) {
        (PaddingPosition::Before, Some(sni_off)) => sni_off,
        _ => ext_end,
    };

    let mut out = Vec::with_capacity(record.len() + add);
    out.extend_from_slice(&record[..6]);
    out.extend_from_slice(&[
        (new_hs_len >> 16) as u8,
        (new_hs_len >> 8) as u8,
        new_hs_len as u8,
    ]);
    out.extend_from_slice(&record[9..layout.ext_len_off]);
    out.extend_from_slice(&(new_ext_len as u16).to_be_bytes());
    out.extend_from_slice(&record[layout.ext_start..insert_at]);
    // RFC 7685 padding extension: type 0x0015, u16 length, zero bytes.
    out.extend_from_slice(&[0x00, 0x15]);
    out.extend_from_slice(&(pad_len as u16).to_be_bytes());
    out.resize(out.len() + pad_len, 0);
    out.extend_from_slice(&record[insert_at..ext_end]);
    // record length field (bytes 3-4)
    let new_record_len = record.len() - 5 + add;
    out[3..5].copy_from_slice(&(new_record_len as u16).to_be_bytes());
    debug_assert_eq!(out.len(), record.len() + add);
    out
}
```

And the RNG (place below `parse_client_hello` / `build_padded`, above the test module — mirroring `tcp_segmentation.rs`):

```rust
static RNG_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Tiny splitmix64 RNG (same pattern as `tcp_segmentation.rs`) so sampling
/// does not pull in the `rand` crate.
#[derive(Debug, Clone, Copy)]
struct PaddingRng {
    state: u64,
}

impl PaddingRng {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            state: nanos
                ^ RNG_COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
                ^ 0xC0FF_EE00_DEAD_BEEF,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn sample_size(range: Int32Range, rng: &mut PaddingRng) -> i32 {
    if range.min == range.max {
        return range.min;
    }
    let width = (range.max as i64 - range.min as i64 + 1) as u64;
    range.min + (rng.next_u64() % width) as i32
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core tls_padding`
Expected: PASS (all 9 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/methods/tls_padding.rs crates/zerodpi-core/src/methods/mod.rs
git commit -m "feat: add RFC 7685 ClientHello padding core module"
```

---

### Task 2: Config integration (`config.rs`)

**Files:**
- Modify: `crates/zerodpi-core/src/config.rs` (method list, fields, defaults, validation, doc comments, tests)
- Modify: `crates/zerodpi-core/src/methods/tls_padding.rs` (add `TlsPadding::new(&Config)`)

**Interfaces:**
- Consumes: `crate::methods::tls_padding::PaddingPosition` (Task 1); `Int32Range`.
- Produces: `Config::TLS_PADDING_SIZE: Int32Range` (default `"1500-2500"`), `Config::TLS_PADDING_POSITION: String` (default `"before"`); `BYPASS_METHOD` list accepts `"tls_padding"`; `TlsPadding::new(cfg: &Config) -> TlsPadding`; `BypassMethodList::is_socket_only()`/`requires_interceptor()` treat `tls_padding` like `tls_frag`; `ip_bypass_plus` accepts `tls_padding`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` in `crates/zerodpi-core/src/config.rs`:

```rust
    #[test]
    fn socket_only_and_interceptor_helpers_include_tls_padding() {
        for name in ["tls_frag", "tls_padding"] {
            let list = BypassMethodList::from(name);
            assert!(list.is_socket_only(), "{name} should be socket-only");
            assert!(!list.requires_interceptor(), "{name} should not require interceptor");
        }
        let both = BypassMethodList::from_delimited("tls_frag, tls_padding");
        assert!(both.is_socket_only());
        assert!(!both.requires_interceptor());

        let combo = BypassMethodList::from_delimited("tls_padding, wrong_seq");
        assert!(!combo.is_socket_only());
        assert!(combo.requires_interceptor());
    }

    #[test]
    fn tls_padding_fields_parse_and_default() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap();
        assert_eq!(cfg.TLS_PADDING_SIZE, Int32Range::parse("1500-2500").unwrap());
        assert_eq!(cfg.TLS_PADDING_POSITION, "before");
        cfg.validate().unwrap();
    }

    #[test]
    fn parses_custom_tls_padding_values() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               TLS_PADDING_SIZE = "2000-3000"
               TLS_PADDING_POSITION = "after""#,
        )
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.TLS_PADDING_SIZE, Int32Range::parse("2000-3000").unwrap());
        assert_eq!(cfg.TLS_PADDING_POSITION, "after");
    }

    #[test]
    fn rejects_invalid_tls_padding_size() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               TLS_PADDING_SIZE = 0"#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_oversized_tls_padding_size() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               TLS_PADDING_SIZE = 20000"#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_invalid_tls_padding_position() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               TLS_PADDING_POSITION = "middle""#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn ip_bypass_plus_accepts_tls_padding() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               MODE = "ip_bypass_plus"
               BYPASS_METHOD = "tls_padding""#,
        )
        .unwrap();
        cfg.validate().unwrap();
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-core config::tests`
Expected: FAIL — `TLS_PADDING_SIZE`/`TLS_PADDING_POSITION` fields don't exist yet (compile error), and `is_socket_only()` returns false for `tls_padding`.

- [ ] **Step 3: Implement config changes**

In `crates/zerodpi-core/src/config.rs`:

(a) Import `PaddingPosition` next to the existing imports:

```rust
use crate::methods::tls_padding::PaddingPosition;
```

(b) Add `"tls_padding"` to `BASE_BYPASS_METHODS` (between `"tls_frag"` and `"urg_sni_split"`):

```rust
pub const BASE_BYPASS_METHODS: &[&str] = &[
    "wrong_seq",
    "wrong_ack",
    "wrong_checksum",
    "wrong_md5",
    "wrong_timestamp",
    "low_ttl",
    "tls_record_frag",
    "tls_frag",
    "tls_padding",
    "urg_sni_split",
];
```

(c) Replace `is_socket_only` and `requires_interceptor`:

```rust
    /// `true` when the list contains only socket-side methods
    /// (`["tls_frag"]`, `["tls_padding"]`, or both), which need no packet
    /// interceptor.
    pub fn is_socket_only(&self) -> bool {
        !self.0.is_empty()
            && self
                .0
                .iter()
                .all(|m| matches!(m.as_str(), "tls_frag" | "tls_padding"))
    }

    /// `true` when any listed method needs the WinDivert/NFQUEUE interceptor.
    pub fn requires_interceptor(&self) -> bool {
        self.0
            .iter()
            .any(|m| !matches!(m.as_str(), "tls_frag" | "tls_padding"))
    }
```

(d) Add the `tls_padding` bullet to the `BYPASS_METHOD` field doc comment (after the `"tls_frag"` bullet) and update its tail paragraph:

```rust
    /// - `"tls_padding"` — TLS ClientHello Padding Expansion (RFC 7685).
    ///   Inserts a padding extension (type `0x0015`) of `TLS_PADDING_SIZE`
    ///   zero bytes into the client's real ClientHello. With
    ///   `TLS_PADDING_POSITION = "before"` (default) the padding is inserted
    ///   immediately before the SNI extension, pushing the SNI past the DPI's
    ///   inspection window (typically 512–1460 bytes); `"after"` appends it
    ///   at the end of the extension list. Socket-side only: does not inject
    ///   fake packets or use WinDivert/NFQUEUE interception; operates inside
    ///   the proxy on the relayed ClientHello.
```

```rust
    /// packet. `tls_record_frag`, `tls_frag`, and `tls_padding` add the data
    /// stage. See the `BYPASS_METHOD` section of `config.toml` for the
    /// combination limits.
```

(e) Add the new config fields after the `TCP_SEG_NODELAY` field (end of the `tls_frag` section):

```rust
    // -----------------------------------------------------------------------
    // tls_padding method parameters
    // -----------------------------------------------------------------------
    /// Zero-byte count of the RFC 7685 padding extension inserted into the
    /// client's real TLS ClientHello. Accepts an integer or an inclusive
    /// range string; a fresh value is sampled per connection and clamped at
    /// runtime so the final TLS record never exceeds 16383 bytes.
    /// Must be `>= 1` and `<= 16000`.  Default: `"1500-2500"`.
    #[serde(default = "default_tls_padding_size")]
    pub TLS_PADDING_SIZE: Int32Range,

    /// Where the padding extension is inserted inside the ClientHello
    /// extensions:
    /// - `"before"` (default) — immediately before the SNI extension,
    ///   pushing the SNI bytes past the DPI's inspection window.
    /// - `"after"` — at the end of the extension list (canonical RFC 7685
    ///   placement).
    #[serde(default = "default_tls_padding_position")]
    pub TLS_PADDING_POSITION: String,
```

(f) Add default functions next to `default_tls_frag_interval_ms` (line ~973):

```rust
fn default_tls_padding_size() -> Int32Range {
    Int32Range::parse("1500-2500").expect("static default TLS_PADDING_SIZE")
}

fn default_tls_padding_position() -> String {
    "before".to_owned()
}
```

(g) Add validation in `Config::validate` (after the `TCP_SEG_SIZE` checks, before `let _ = self.tls_frag_packets()?;`):

```rust
        self.TLS_PADDING_SIZE
            .validate_at_least("TLS_PADDING_SIZE", 1)?;
        if self.TLS_PADDING_SIZE.max > 16000 {
            anyhow::bail!("TLS_PADDING_SIZE must be <= 16000");
        }
        PaddingPosition::parse(&self.TLS_PADDING_POSITION)
            .map_err(|e| anyhow::anyhow!("TLS_PADDING_POSITION is invalid: {e}"))?;
```

(h) Extend the `ip_bypass_plus` method whitelist:

```rust
        if self.MODE == "ip_bypass_plus"
            && !self
                .BYPASS_METHOD
                .iter()
                .all(|m| matches!(m, "tls_record_frag" | "tls_frag" | "tls_padding"))
        {
            anyhow::bail!(
                "MODE = \"ip_bypass_plus\" supports only real-SNI-preserving BYPASS_METHOD values: \"tls_record_frag\", \"tls_frag\", or \"tls_padding\""
            );
        }
```

In `crates/zerodpi-core/src/methods/tls_padding.rs`, add the config constructor to `impl TlsPadding` (after `exact`):

```rust
    /// Build parameters from the application config. Callers must run
    /// `Config::validate` first (it rejects invalid `TLS_PADDING_SIZE` /
    /// `TLS_PADDING_POSITION` values).
    pub fn new(cfg: &crate::config::Config) -> Self {
        Self {
            size: cfg.TLS_PADDING_SIZE,
            position: PaddingPosition::parse(&cfg.TLS_PADDING_POSITION)
                .expect("Config::validate should reject invalid TLS_PADDING_POSITION"),
        }
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core`
Expected: PASS (config tests + Task 1 module tests; the existing `socket_only_and_interceptor_helpers` test still passes since `["tls_frag"]` behavior is unchanged).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/config.rs crates/zerodpi-core/src/methods/tls_padding.rs
git commit -m "feat: add TLS_PADDING_SIZE and TLS_PADDING_POSITION config"
```

---

### Task 3: Proxy wiring (`proxy.rs`)

**Files:**
- Modify: `crates/zerodpi-core/src/proxy.rs` (`ConnectionSettings`, `handle_intercept_connection`, `handle_tcp_seg_connection_with_ip`, tests)

**Interfaces:**
- Consumes: `TlsPadding::new(&Config)`, `TlsPadding::apply(&[u8]) -> Option<Vec<u8>>` (Task 1/2); `read_one_tls_record` (existing, in `methods::tcp_segmentation`).
- Produces: `ConnectionSettings { ..., tls_padding: Option<TlsPadding> }` (struct is `Debug, Clone, Copy`; `TlsPadding` is `Copy`, so the struct stays `Copy`). Socket path pads the first TLS record when `tls_padding` is listed; intercept path pads the real ClientHello in the `ReadyForData` stage.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` in `crates/zerodpi-core/src/proxy.rs` (the existing `tls_frag_in_list_segments_first_client_hello` test stays unchanged):

```rust
    #[test]
    fn tls_padding_in_list_populates_settings() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["wrong_seq", "tls_padding"]
               TLS_PADDING_SIZE = "2000-3000"
               TLS_PADDING_POSITION = "after""#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        let padding = settings.tls_padding.expect("tls_padding is listed");
        assert_eq!(
            padding.size,
            crate::config::Int32Range::parse("2000-3000").unwrap()
        );
        assert_eq!(
            padding.position,
            crate::methods::tls_padding::PaddingPosition::After
        );
    }

    #[test]
    fn socket_only_lists_disable_padding_settings() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "tls_frag""#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(settings.tls_padding.is_none());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-core proxy::tests`
Expected: FAIL — `ConnectionSettings` has no `tls_padding` field (compile error).

- [ ] **Step 3: Implement the wiring**

In `crates/zerodpi-core/src/proxy.rs`:

(a) Add the import next to the existing `use crate::methods::tcp_segmentation::...` line:

```rust
use crate::methods::tls_padding::TlsPadding;
```

(b) Extend `ConnectionSettings` and its constructor:

```rust
#[derive(Debug, Clone, Copy)]
struct ConnectionSettings {
    bypass_timeout: Duration,
    max_lifetime: Option<Duration>,
    segment_first_client_hello: bool,
    tls_padding: Option<TlsPadding>,
    tcp_segmentation: TcpSegmentation,
}

impl ConnectionSettings {
    fn from_config(cfg: &Config) -> Self {
        let tcp_segmentation = TcpSegmentation::new(cfg);
        Self {
            bypass_timeout: Duration::from_secs(cfg.BYPASS_TIMEOUT_SECS),
            max_lifetime: configured_relay_max_lifetime(cfg),
            segment_first_client_hello: cfg.BYPASS_METHOD.contains("tls_frag"),
            tls_padding: cfg
                .BYPASS_METHOD
                .contains("tls_padding")
                .then(|| TlsPadding::new(cfg)),
            tcp_segmentation,
        }
    }
}
```

(c) In `handle_intercept_connection`, inside `Some(BypassProgress::ReadyForData)`, pad the real ClientHello wherever a complete record was read:

- In the `TlsFragPackets::TlsHello` arm, right after `read_client_tls_record_with_timeout` returns `client_hello` (before the `write_fragmented` call):

```rust
                        let client_hello = settings
                            .tls_padding
                            .and_then(|p| p.apply(&client_hello))
                            .unwrap_or(client_hello);
```

- In the `TlsFragPackets::WriteRange { .. }` arm, right after `read_client_write_with_timeout` returns `client_data` (fail-open: only padded when the write parses as a complete ClientHello):

```rust
                        let client_data = settings
                            .tls_padding
                            .and_then(|p| p.apply(&client_data))
                            .unwrap_or(client_data);
```

- In the non-segmented `else` branch, right after `read_client_tls_record_with_timeout` returns `client_hello` (before `outgoing.write_all`):

```rust
                let client_hello = settings
                    .tls_padding
                    .and_then(|p| p.apply(&client_hello))
                    .unwrap_or(client_hello);
```

(d) In `handle_tcp_seg_connection_with_ip`, replace the `let client_fragmentation = match method.packets { ... };` block with the padding-aware version. First, before the match, read and pad the first TLS record when `tls_padding` is listed:

```rust
    // When tls_padding is listed, read the first TLS record and expand it
    // with the RFC 7685 padding extension before any mode-specific handling.
    // Fail-open: unparseable records are forwarded unchanged.
    let padded_prefix = if cfg.BYPASS_METHOD.contains("tls_padding") {
        let record = read_one_tls_record(&mut incoming)
            .await
            .context("tls_padding: reading ClientHello from client")?;
        Some(TlsPadding::new(&cfg).apply(&record).unwrap_or(record))
    } else {
        None
    };
```

Then the mode dispatch:

```rust
    let client_fragmentation = match method.packets {
        TlsFragPackets::TlsHello if cfg.BYPASS_METHOD.contains("tls_frag") => {
            let client_hello = match padded_prefix {
                Some(record) => record,
                None => read_one_tls_record(&mut incoming)
                    .await
                    .context("tls_frag: reading ClientHello from client")?,
            };
            write_fragmented(
                &mut outgoing,
                &client_hello,
                method.length,
                method.interval_ms,
            )
            .await
            .context("tls_frag: writing fragmented ClientHello")?;
            debug!(
                length = %method.length,
                interval_ms = %method.interval_ms,
                nodelay = method.nodelay,
                total_bytes = client_hello.len(),
                "tls_frag: ClientHello written in fragments; handing off to relay"
            );
            None
        }
        _ => {
            if let Some(record) = padded_prefix {
                outgoing
                    .write_all(&record)
                    .await
                    .context("tls_padding: writing padded ClientHello")?;
                outgoing
                    .flush()
                    .await
                    .context("tls_padding: flushing padded ClientHello")?;
            }
            if cfg.BYPASS_METHOD.contains("tls_frag") {
                debug!(
                    packets = ?method.packets,
                    length = %method.length,
                    interval_ms = %method.interval_ms,
                    nodelay = method.nodelay,
                    "tls_frag: fragmenting selected client writes in relay"
                );
                Some((method, 0))
            } else {
                None
            }
        }
    };
```

Behavior summary (matches the spec):
- `tls_frag` alone + `tlshello`: same as before (read + fragment).
- `tls_frag` alone + `1-3`: same as before (relay fragments from index 1).
- `tls_padding` alone: read + pad + write whole; plain relay.
- `tls_frag` + `tls_padding` + `tlshello`: pad, then fragment.
- `tls_frag` + `tls_padding` + `1-3`: pad + write whole, then relay fragments selected later writes (indices now count writes after the padded ClientHello).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core`
Expected: PASS (new settings tests + all existing proxy tests).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/proxy.rs
git commit -m "feat: wire tls_padding into socket and intercept proxy paths"
```

---

### Task 4: Method registration, CLI, and helper protocol

**Files:**
- Modify: `crates/zerodpi-core/src/methods/mod.rs` (module docs, `build_method` arm, tests)
- Modify: `crates/zerodpi/src/main.rs` (log messages, rootless messages, `--method` help, tests)
- Modify: `crates/zerodpi-helper-protocol/src/lib.rs` (`SUPPORTED` list)

**Interfaces:**
- Consumes: config changes from Task 2 (list helpers), `BypassMethodList` methods.
- Produces: `build_method` returns a composite containing only the interceptor methods for lists like `["wrong_seq", "tls_padding"]` (name `"wrong_seq + tls_padding"`), `None` for pure-socket lists; helper accepts `"tls_padding"` in `MethodConfig.methods`; CLI messages mention `tls_padding`.

- [ ] **Step 1: Write the failing tests**

In `crates/zerodpi-core/src/methods/mod.rs` test module, add:

```rust
    #[test]
    fn build_wrong_seq_tls_padding_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["wrong_seq", "tls_padding"]"#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq + tls_padding");
    }

    #[test]
    fn socket_padding_method_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "tls_padding""#);
        assert!(build_method(&cfg).is_none());
    }
```

In `crates/zerodpi/src/main.rs` test module, extend the two interception tests:

In `non_interception_modes_do_not_require_packet_interception`, add:

```rust
        assert!(!mode_requires_packet_interception(
            "sni_spoof",
            &method_list("tls_padding")
        ));
```

In `ip_bypass_plus_requires_interception_only_for_tls_record_frag`, add:

```rust
        assert!(!mode_requires_packet_interception(
            "ip_bypass_plus",
            &method_list("tls_padding")
        ));
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-core methods:: && cargo test -p zerodpi normal_spoofing_requires_packet_interception`
Expected: `build_wrong_seq_tls_padding_method` FAILS (the `_ => return None` arm in `build_method` rejects `"tls_padding"`). The main.rs additions are regression coverage: after Task 2 they already pass, since `mode_requires_packet_interception` delegates to `is_socket_only` — that is expected.

- [ ] **Step 3: Implement**

In `crates/zerodpi-core/src/methods/mod.rs`:

(a) In the module doc comment's "Socket-based methods" section, extend the `tls_frag` bullet with:

```rust
//! - `tls_padding` — RFC 7685 ClientHello Padding Expansion. Reads the first
//!   TLS ClientHello record, inserts a padding extension of
//!   `TLS_PADDING_SIZE` zero bytes (before the SNI extension by default),
//!   and writes the expanded record to the upstream socket. The padding
//!   pushes the SNI past DPI inspection windows (typically 512-1460 bytes).
```

(b) In `build_method`, add the socket-side no-op arm next to `"tls_frag" => {}`:

```rust
            "tls_frag" => {} // socket side; handled directly in proxy.rs
            "tls_padding" => {} // socket side; handled directly in proxy.rs
```

(c) Update the `build_method` doc comment: replace `None for socket-only lists
(\`["tls_frag"]\`)` with `None for socket-only lists
(\`["tls_frag"]\`, \`["tls_padding"]\`, \`["tls_frag", "tls_padding"]\`)` in the
function's doc comment.

In `crates/zerodpi/src/main.rs`:

(d) Replace the two interceptor-skip log messages:
- Line ~471: `info!("tls_frag selected; skipping packet interceptor");` →
  `info!(method = %cfg.BYPASS_METHOD, "socket-only bypass method selected; skipping packet interceptor");`
- Line ~1818: `info!("ip_bypass_plus: tls_frag selected; skipping packet interceptor");` →
  `info!(method = %cfg.BYPASS_METHOD, "ip_bypass_plus: socket-only bypass method selected; skipping packet interceptor");`

(e) Update `root_required_message` (line ~1188): change the trailing alternative to mention both socket methods:

```rust
fn root_required_message(cfg: &Config) -> String {
    format!(
        "MODE = \"{}\" with BYPASS_METHOD = \"{}\" requires packet interception; on Android the app must start the packaged root helper while keeping the data plane under the app UID. Rootless alternatives are MODE = \"ip_bypass\", scan-only modes, or BYPASS_METHOD = \"tls_frag\" / \"tls_padding\" where supported.",
        cfg.MODE, cfg.BYPASS_METHOD
    )
}
```

(f) Update `rootless_alternatives` (line ~1198): add a `tls_padding` entry:

```rust
fn rootless_alternatives() -> Vec<String> {
    vec![
        "MODE = \"ip_bypass\"".to_owned(),
        "MODE = \"sni_scan\"".to_owned(),
        "MODE = \"ip_scan\"".to_owned(),
        "BYPASS_METHOD = \"tls_frag\" for supported relay modes".to_owned(),
        "BYPASS_METHOD = \"tls_padding\" for supported relay modes".to_owned(),
    ]
}
```

(g) Update the `--method` help text (line ~120) to mention the new name:

```rust
    /// (e.g. `wrong_seq,tls_frag` or `tls_padding`).
```

In `crates/zerodpi-helper-protocol/src/lib.rs`:

(h) Add `"tls_padding"` to the `SUPPORTED` list in `MethodConfig::validate` (next to `"tls_frag"`). This is required for combos like `["wrong_seq", "tls_padding"]`, whose full method list is sent to the root helper in `interceptor_config` (helper_client.rs).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core && cargo test -p zerodpi && cargo test -p zerodpi-helper-protocol`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/methods/mod.rs crates/zerodpi/src/main.rs crates/zerodpi-helper-protocol/src/lib.rs
git commit -m "feat: register tls_padding in build_method, CLI, and helper protocol"
```

---

### Task 5: Documentation (`config.toml`, `README.md`) and full verification

**Files:**
- Modify: `config.toml`
- Modify: `README.md`

**Interfaces:** None (docs only).

- [ ] **Step 1: Document the method in `config.toml`**

(a) In the `BYPASS_METHOD` comment block, add a base-method entry after the `"tls_frag"` block:

```toml
#   "tls_padding"
#     TLS ClientHello Padding Expansion (RFC 7685).  Does NOT inject fake
#     packets and does NOT use WinDivert or NFQUEUE packet interception.
#     Instead it inserts a padding extension (type 0x0015) filled with
#     TLS_PADDING_SIZE zero bytes into the client's real TLS ClientHello.
#     With TLS_PADDING_POSITION = "before" (default) the padding is inserted
#     immediately before the SNI extension, pushing the SNI bytes past the
#     DPI's inspection window (typically 512, 1024, or 1460 bytes); the
#     destination server still parses the full record and skips the unknown
#     extension.  "after" appends the padding at the end of the extension
#     list instead.
```

(b) Update the "Combining methods" bullets:

```toml
# - "tls_record_frag" and/or "tls_frag" add the data stage after the fake
#   packet: TLS-record fragmentation inside the interceptor and TCP-level
#   write segmentation inside the proxy respectively.  A list containing
#   "tls_frag" alongside other methods still uses packet interception.
# - "tls_padding" adds a socket-side data stage: the real ClientHello is
#   expanded with an RFC 7685 padding extension before it is written to the
#   upstream socket.  It combines with handshake-stage methods and with
#   "tls_frag" (pad first, then fragment).
# - A list containing only "tls_frag" and/or "tls_padding" skips the packet
#   interceptor entirely.
```

(c) Update the `ip_bypass_plus` limitation bullet:

```toml
# - MODE = "ip_bypass_plus" supports only "tls_record_frag", "tls_frag", or
#   "tls_padding" so the upstream VPN client's real SNI is preserved.
```

(d) Add a new parameters section after the `tls_frag method parameters` section (after `TCP_SEG_NODELAY = true`):

```toml
# ---------------------------------------------------------------------------
# tls_padding method parameters
# ---------------------------------------------------------------------------
# These settings apply when BYPASS_METHOD = "tls_padding" (alone or combined).

# Zero-byte count of the RFC 7685 padding extension inserted into the first
# TLS ClientHello record.
#
# Accepts either a fixed integer or an inclusive range string:
#   1500        — always insert 1500 zero bytes
#   "1500-2500" — randomly choose 1500 through 2500 bytes per connection
#
# A fresh value is chosen per connection.  The padding is clamped at runtime
# so the final TLS record never exceeds 16383 bytes (the TLS record-layer
# maximum).  Larger values push the SNI further past the DPI's inspection
# window (typically 512, 1024, or 1460 bytes).
#
# Must be >= 1 and <= 16000.  Default: "1500-2500".
TLS_PADDING_SIZE = "1500-2500"

# Where the padding extension is inserted inside the ClientHello extensions.
#   "before" — immediately before the SNI extension, pushing the SNI bytes
#              past the DPI's inspection window (default)
#   "after"  — at the end of the extension list (canonical RFC 7685 placement)
TLS_PADDING_POSITION = "before"
```

- [ ] **Step 2: Update `README.md`**

(a) Line ~55 badge: change `9 combinable bypass methods` to `10 combinable bypass methods` and append `tls_padding` to the inline list:

```markdown
| 🧩 **10 combinable bypass methods** | `wrong_seq`, `wrong_ack`, `wrong_checksum`, `wrong_md5`, `wrong_timestamp`, `low_ttl`, `tls_record_frag`, `tls_frag`, `tls_padding`, `urg_sni_split` — combinable via `BYPASS_METHOD = ["wrong_seq", "tls_frag"]` |
```

(b) Lines ~153/164/166 (privilege notes): append `tls_padding` wherever standalone `tls_frag` is called out:

- "except standalone `tls_frag`, plain `ip_bypass`..." → "except standalone `tls_frag` / `tls_padding`, plain `ip_bypass`..."
- "Standalone `tls_frag` does not open WinDivert..." → "Standalone `tls_frag` / `tls_padding` do not open WinDivert..."
- "Try `tls_frag` first if NFQUEUE support is uncertain." → "Try `tls_frag` or `tls_padding` first if NFQUEUE support is uncertain."

(c) Lines ~229/242/281 (`ip_bypass_plus` mentions): "supports only `tls_record_frag` or `tls_frag`" → "supports only `tls_record_frag`, `tls_frag`, or `tls_padding`".

(d) Line ~234: append `tls_padding` to the socket-only suggestion:

```markdown
Choose a bypass method separately with `BYPASS_METHOD`. If you cannot or do not want to use WinDivert/NFQUEUE packet interception, try `BYPASS_METHOD = "tls_frag"` or `BYPASS_METHOD = "tls_padding"` with `MODE = "sni_spoof"` or `MODE = "ip_bypass_plus"`.
```

(e) Bypass-methods table: add a row after the `tls_frag` row:

```markdown
| `tls_padding` | TLS ClientHello Padding Expansion: inserts an RFC 7685 padding extension into the real ClientHello so the SNI lands past the DPI's inspection window (before SNI by default) or the record exceeds its buffer (after) | ❌ No | DPI that inspects only the first N bytes of the stream |
```

(f) Combining-limits bullet: "`MODE = "ip_bypass_plus"` supports only `tls_record_frag` or `tls_frag`" → "supports only `tls_record_frag`, `tls_frag`, or `tls_padding`".

(g) How-combinations-behave bullet: extend the data-stage sentence and the socket-only definition:

```markdown
- `tls_record_frag` and/or `tls_frag` add the data stage after the fake
  packet. `tls_padding` adds a socket-side data stage that expands the real
  ClientHello with an RFC 7685 padding extension before it is written
  upstream. A list containing `tls_frag` alongside other methods still uses
  packet interception; a list containing only `tls_frag` and/or
  `tls_padding` skips the interceptor entirely.
```

(h) Choosing table: add a row after the `tls_record_frag` row:

```markdown
| DPI inspects only the first N bytes of the TLS stream | `tls_padding` |
```

And update the `ip_bypass_plus` row: "with `tls_record_frag` or `tls_frag`" → "with `tls_record_frag`, `tls_frag`, or `tls_padding`".

(i) Method-detail bullets: add after the `tls_frag` bullet:

```markdown
- `tls_padding` inserts an RFC 7685 padding extension (type `0x0015`) of
  `TLS_PADDING_SIZE` zero bytes into the client's real ClientHello. With
  `TLS_PADDING_POSITION = "before"` (default) the padding is placed
  immediately before the SNI extension so the SNI bytes land past the DPI's
  inspection window (typically 512–1460 bytes); `"after"` appends it at the
  end of the extension list. The server skips the unknown extension and
  parses the SNI normally. The padding size is sampled per connection and
  clamped so the record never exceeds 16383 bytes.
```

- [ ] **Step 3: Full verification**

Run all gates:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

Expected: all pass with no warnings.

- [ ] **Step 4: Commit**

```bash
git add config.toml README.md
git commit -m "docs: document tls_padding method and TLS_PADDING_* options"
```
