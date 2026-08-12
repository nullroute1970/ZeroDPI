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
    let new_hs_len =
        (((record[6] as usize) << 16) | ((record[7] as usize) << 8) | record[8] as usize) + add;

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
        body.extend_from_slice(&[7u8; 32]); // random
        body.push(0); // no session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[1, 0]); // null compression
        let mut exts = Vec::new();
        if let Some(sni) = sni {
            let mut data = Vec::new();
            data.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes()); // list length
            data.push(0); // name type
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
        assert_eq!(
            u16::from_be_bytes([padded[3], padded[4]]),
            padded.len() as u16 - 5
        );
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
        assert_eq!(
            TlsPadding::exact(16_383, PaddingPosition::After).apply(&padded),
            None
        );
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
            assert!(
                (1000..=2000).contains(&used),
                "sampled {used} outside 1000-2000"
            );
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
