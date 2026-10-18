//! `tls_record_split` bypass: split the TLS ClientHello across two TLS
//! records at the SNI boundary.
//!
//! ## How it works
//!
//! The TLS record layer explicitly permits a handshake message to span several
//! records (RFC 8446 §5.1, RFC 5246 §6.2.1), and real clients do exactly that
//! for large ClientHellos (post-quantum key shares routinely overflow one
//! record). This method parses the client's real ClientHello record down to the
//! `server_name` extension and re-frames it as **two** records cut at that
//! boundary:
//!
//! - record 1 carries the ClientHello prefix up to `TLS_RECORD_SPLIT_POINT`,
//! - record 2 carries the rest (the SNI extension body and everything after).
//!
//! A compliant server reassembles the handshake message across both records and
//! proceeds normally, while a DPI that inspects only the first record — or that
//! assumes the ClientHello is always record 1 — finds no SNI and classifies the
//! flow benign. Because the rewrite happens on the byte stream, this defeats
//! DPIs that reassemble TCP segments but parse only the first TLS record; that
//! is the gap left by `tls_frag` / `sni_boundary_frag`, which only split TCP
//! segments, and by `tls_record_frag`, which achieves the same record-level
//! evasion but needs WinDivert/NFQUEUE.
//!
//! This method does **not** inject fake packets, does **not** alter the
//! handshake bytes, and requires **no** packet interception: the two records
//! are written directly to the upstream socket. `TLS_RECORD_SPLIT_DELAY_MS`
//! separately flushes them so they leave as two TCP segments with a gap,
//! defeating reassembly buffers as well.
//!
//! Fail-open: when the first record is not a complete ClientHello containing a
//! valid `host_name`, or the resolved cut would leave one side empty, the
//! record is written unchanged.
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `TLS_RECORD_SPLIT_POINT` | string / int | `"extension_length"` | Where to cut the record: `"extension_length"`, `"middle"`, or a 0-based index into the domain string. |
//! | `TLS_RECORD_SPLIT_DELAY_MS` | `Int32Range` | `0` | Delay between the two records; a non-zero value makes them leave as separate TCP segments. |

use anyhow::Context;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::sni::find_sni_boundary;
use crate::config::{Config, Int32Range, SniBoundarySplitPoint};

/// Every TLS record starts with a 5-byte header
/// (`content_type(1) version(2) length(2)`).
const TLS_RECORD_HEADER_LEN: usize = 5;

/// Parameters for the `tls_record_split` bypass method.
#[derive(Debug, Clone, Copy)]
pub struct TlsRecordSplit {
    /// Where to cut the first ClientHello record.
    pub split_point: SniBoundarySplitPoint,
    /// Delay between the two records, in milliseconds.
    pub delay_ms: Int32Range,
}

impl TlsRecordSplit {
    pub fn new(cfg: &Config) -> Self {
        Self {
            split_point: cfg.TLS_RECORD_SPLIT_POINT,
            delay_ms: cfg.TLS_RECORD_SPLIT_DELAY_MS,
        }
    }

    /// Resolve the configured split point to a byte offset inside `record`.
    ///
    /// The returned offset is absolute within `record` (i.e. it includes the
    /// record header). `None` means the payload has no parseable SNI.
    pub fn cut_offset(&self, record: &[u8]) -> Option<usize> {
        let boundary = find_sni_boundary(record)?;
        Some(match self.split_point {
            SniBoundarySplitPoint::ExtensionLength => boundary.ext_len_field_end,
            SniBoundarySplitPoint::Middle => boundary.name_start + boundary.name_len / 2,
            SniBoundarySplitPoint::Index(n) => {
                boundary.name_start + (n as usize).min(boundary.name_len)
            }
        })
    }

    /// Re-frame the first TLS record in `data` as two records cut at the
    /// resolved boundary.
    ///
    /// `data` is expected to hold at least one complete record; anything after
    /// the first record is appended to the second part unchanged, so callers
    /// can hand it a coalesced client write.
    ///
    /// Returns `None` when the payload is not a complete ClientHello with a
    /// valid `host_name`, or when the resolved cut would not split the record
    /// body into two non-empty parts. Callers fail open by writing `data`
    /// unchanged.
    pub fn split(&self, data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let cut = self.cut_offset(data)?;
        let record_len = u16::from_be_bytes([*data.get(3)?, *data.get(4)?]) as usize;
        let body_start = TLS_RECORD_HEADER_LEN;
        let body_end = body_start.checked_add(record_len)?;
        if body_end > data.len() {
            return None;
        }
        // The cut must fall strictly inside the record body: the first record
        // needs a non-empty body, and so does the second one.
        if cut <= body_start || cut >= body_end {
            return None;
        }

        let record_header = &data[..3]; // content_type + legacy version
        let first_body = &data[body_start..cut];
        let second_body = &data[cut..body_end];
        let trailing = &data[body_end..];

        let first = build_record(record_header, first_body);
        let mut second = build_record(record_header, second_body);
        second.extend_from_slice(trailing);
        Some((first, second))
    }
}

/// Wrap `body` in a TLS record header using the original `record_header`
/// (content type and legacy version bytes).
fn build_record(record_header: &[u8], body: &[u8]) -> Vec<u8> {
    let len = body.len() as u16;
    let mut out = Vec::with_capacity(TLS_RECORD_HEADER_LEN + body.len());
    out.extend_from_slice(record_header);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Write the two records produced by [`TlsRecordSplit::split`].
///
/// Each record is flushed immediately; a non-zero delay makes the operating
/// system emit them as separate TCP segments with a gap between them (the
/// caller enables `TCP_NODELAY`). `delay_ms` must not be negative.
pub async fn write_record_split<W>(
    dst: &mut W,
    first: &[u8],
    second: &[u8],
    delay_ms: Int32Range,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    assert!(delay_ms.min >= 0, "delay range must be >= 0");

    dst.write_all(first)
        .await
        .context("writing first TLS record split")?;
    dst.flush()
        .await
        .context("flushing first TLS record split")?;

    let delay_ms = super::tcp_segmentation::sample_i32(
        delay_ms,
        &mut super::tcp_segmentation::FragmentRng::new(),
    )
    .max(0) as u64;
    if delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }

    dst.write_all(second)
        .await
        .context("writing second TLS record split")?;
    dst.flush()
        .await
        .context("flushing second TLS record split")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Int32Range, SniBoundarySplitPoint};
    use crate::tls_template::build_client_hello;

    fn cfg_with(extra: &str) -> Config {
        toml::from_str(&format!(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "tls_record_split"
               {extra}"#
        ))
        .unwrap()
    }

    fn default_cfg() -> Config {
        toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap()
    }

    fn client_hello(sni: &[u8]) -> Vec<u8> {
        build_client_hello(&[0u8; 32], &[0u8; 32], sni, &[0u8; 32])
    }

    /// Concatenate the bodies of every TLS record in `records`.
    fn record_bodies(records: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut offset = 0usize;
        while offset < records.len() {
            let len = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;
            body.extend_from_slice(&records[offset + 5..offset + 5 + len]);
            offset += TLS_RECORD_HEADER_LEN + len;
        }
        body
    }

    fn record_len(record: &[u8]) -> usize {
        u16::from_be_bytes([record[3], record[4]]) as usize
    }

    // -----------------------------------------------------------------------
    // split()
    // -----------------------------------------------------------------------

    #[test]
    fn splits_at_extension_length_by_default() {
        let cfg = default_cfg();
        let split = TlsRecordSplit::new(&cfg);
        let record = client_hello(b"auth.vercel.com");
        let (first, second) = split.split(&record).expect("must split");

        // extension_length cuts right after the server_name extension's length
        // field (record offset 122), so record 1's body is 117 bytes.
        assert_eq!(record[0], 0x16);
        assert_eq!(&first[..3], &record[..3]);
        assert_eq!(record_len(&first), 122 - TLS_RECORD_HEADER_LEN);
        assert_eq!(first.len(), 122);
        assert_eq!(second[0], 0x16);
        assert_eq!(second.len(), record.len() - 122 + TLS_RECORD_HEADER_LEN);

        // Only one extra record header is added to the stream.
        assert_eq!(
            first.len() + second.len(),
            record.len() + TLS_RECORD_HEADER_LEN
        );

        // Reassembling the two record bodies yields the original body.
        let mut joined = first.clone();
        joined.extend_from_slice(&second);
        assert_eq!(record_bodies(&joined), record_bodies(&record));
    }

    #[test]
    fn first_record_contains_no_sni_extension() {
        let cfg = default_cfg();
        let split = TlsRecordSplit::new(&cfg);
        let record = client_hello(b"auth.vercel.com");
        let (first, second) = split.split(&record).unwrap();

        // The whole point: the first record on the wire is not a parseable
        // ClientHello with an SNI.
        assert_eq!(find_sni_boundary(&first), None);

        // The full ClientHello bytes are still present across both records.
        let joined = [first, second].concat();
        assert_eq!(record_bodies(&joined), record_bodies(&record));
    }

    /// Handcraft a minimal ClientHello whose `server_name` extension is the
    /// only extension and the last bytes of the record, so a cut at the end of
    /// the domain string leaves nothing for record 2.
    fn minimal_hello_ending_in_sni(sni: &[u8]) -> Vec<u8> {
        let name_len = sni.len() as u16;
        let list_len = 3u16 + name_len;
        let ext_len = 5u16 + name_len;
        let ext_total = 4u16 + ext_len;
        // ClientHello body: version(2) random(32) session_id_len(1)
        // cipher_suites_len(2) compression_len(1) extensions_len(2) + extensions.
        let hs_body_len = 2 + 32 + 1 + 2 + 1 + 2 + ext_total as usize;
        let record_len = 4 + hs_body_len; // handshake header + body
        let mut rec = vec![
            0x16,
            0x03,
            0x03,
            (record_len >> 8) as u8,
            record_len as u8,
            0x01, // handshake type: ClientHello
            (hs_body_len >> 16) as u8,
            (hs_body_len >> 8) as u8,
            hs_body_len as u8,
            0x03,
            0x03, // client version
        ];
        rec.extend_from_slice(&[0u8; 32]); // random
        rec.push(0); // session id length
        rec.extend_from_slice(&[0x00, 0x00]); // cipher suites length
        rec.push(0); // compression methods length
        rec.extend_from_slice(&[(ext_total >> 8) as u8, ext_total as u8]);
        rec.extend_from_slice(&[0x00, 0x00, (ext_len >> 8) as u8, ext_len as u8]);
        rec.extend_from_slice(&[(list_len >> 8) as u8, list_len as u8]);
        rec.push(0x00); // name type: host_name
        rec.extend_from_slice(&[(name_len >> 8) as u8, name_len as u8]);
        rec.extend_from_slice(sni);
        rec
    }

    #[test]
    fn splits_mid_domain() {
        let mut cfg = default_cfg();
        cfg.TLS_RECORD_SPLIT_POINT = SniBoundarySplitPoint::Middle;
        let split = TlsRecordSplit::new(&cfg);
        let record = client_hello(b"auth.vercel.com");
        let (first, second) = split.split(&record).expect("must split");

        // "auth.vercel.com" is 15 bytes at offset 127 -> cut at 127 + 7.
        assert_eq!(first.len(), 134);
        assert_eq!(record_len(&first), 129);
        // The domain is split across the two records.
        assert!(record_bodies(&[first, second].concat())
            .windows(15)
            .any(|w| w == b"auth.vercel.com"));
    }

    #[test]
    fn splits_at_index_into_domain() {
        let mut cfg = default_cfg();
        cfg.TLS_RECORD_SPLIT_POINT = SniBoundarySplitPoint::Index(0);
        let split = TlsRecordSplit::new(&cfg);
        let record = client_hello(b"auth.vercel.com");
        let (first, _) = split.split(&record).expect("must split");

        // Index 0 puts the cut at the first name byte (record offset 127).
        assert_eq!(record_len(&first), 122);
    }

    #[test]
    fn preserves_legacy_version_bytes() {
        let cfg = default_cfg();
        let split = TlsRecordSplit::new(&cfg);
        let mut record = client_hello(b"example.com");
        record[1] = 0x03;
        record[2] = 0x01;

        let (first, second) = split.split(&record).unwrap();
        assert_eq!(&first[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(&second[..3], &[0x16, 0x03, 0x01]);
    }

    #[test]
    fn keeps_trailing_bytes_after_the_second_record() {
        let cfg = default_cfg();
        let split = TlsRecordSplit::new(&cfg);
        let record = client_hello(b"example.com");
        let mut data = record.clone();
        data.extend_from_slice(b"TRAILER");

        let (first, second) = split.split(&data).expect("must split");
        let expected_second = split.split(&record).unwrap().1;
        assert_eq!(
            first.len() + second.len(),
            data.len() + TLS_RECORD_HEADER_LEN
        );
        assert!(second.ends_with(b"TRAILER"));
        assert_eq!(&second[..second.len() - 7], &expected_second[..]);
    }

    #[test]
    fn fails_open_for_non_client_hello() {
        let cfg = default_cfg();
        let split = TlsRecordSplit::new(&cfg);
        assert_eq!(split.split(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(split.split(&[]), None);
        // Application data record (content type 0x17) is not a ClientHello.
        assert_eq!(split.split(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xAA]), None);
    }

    #[test]
    fn fails_open_when_cut_would_empty_a_record() {
        let mut cfg = default_cfg();
        // In this ClientHello the SNI is the last extension and ends the
        // record, so cutting after the domain leaves record 2 empty.
        cfg.TLS_RECORD_SPLIT_POINT = SniBoundarySplitPoint::Index(11);
        let split = TlsRecordSplit::new(&cfg);
        let record = minimal_hello_ending_in_sni(b"example.com");
        assert_eq!(split.split(&record), None);

        // Index 0 (start of the domain) still splits cleanly.
        cfg.TLS_RECORD_SPLIT_POINT = SniBoundarySplitPoint::Index(0);
        let split = TlsRecordSplit::new(&cfg);
        let (first, second) = split.split(&record).expect("index 0 must split");
        assert!(record_bodies(&[first, second].concat()).ends_with(b"example.com"));
    }

    #[test]
    fn split_point_defaults_to_extension_length() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap();
        assert_eq!(
            cfg.TLS_RECORD_SPLIT_POINT,
            SniBoundarySplitPoint::ExtensionLength
        );
        assert_eq!(cfg.TLS_RECORD_SPLIT_DELAY_MS, Int32Range::exact(0));
    }

    #[test]
    fn reads_split_point_and_delay_from_config() {
        let cfg = cfg_with(
            r#"TLS_RECORD_SPLIT_POINT = "middle"
               TLS_RECORD_SPLIT_DELAY_MS = "3-7""#,
        );
        let split = TlsRecordSplit::new(&cfg);
        assert_eq!(split.split_point, SniBoundarySplitPoint::Middle);
        assert_eq!(split.delay_ms, Int32Range { min: 3, max: 7 });
    }

    // -----------------------------------------------------------------------
    // write_record_split()
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn writes_both_records_in_order() {
        let cfg = default_cfg();
        let split = TlsRecordSplit::new(&cfg);
        let record = client_hello(b"example.com");
        let (first, second) = split.split(&record).unwrap();

        let mut sink: Vec<u8> = Vec::new();
        write_record_split(&mut sink, &first, &second, Int32Range::exact(0))
            .await
            .unwrap();

        assert_eq!(sink.len(), record.len() + TLS_RECORD_HEADER_LEN);
        assert_eq!(record_bodies(&sink), record_bodies(&record));
    }

    #[tokio::test]
    async fn zero_delay_does_not_sleep() {
        let start = std::time::Instant::now();
        let mut sink: Vec<u8> = Vec::new();
        write_record_split(&mut sink, b"first", b"second", Int32Range::exact(0))
            .await
            .unwrap();
        assert!(start.elapsed() < std::time::Duration::from_millis(100));
        assert_eq!(sink, b"firstsecond");
    }
}
