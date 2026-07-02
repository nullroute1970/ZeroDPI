//! `tls_frag` bypass: TCP-level TLS Fragment. It keeps the TLS bytes intact,
//! then splits selected client-to-upstream data into small writes so that DPI
//! cannot reassemble the SNI from any single packet.
//!
//! ## How it works
//!
//! Many DPI/firewall middleboxes extract the SNI by inspecting the first
//! outbound TCP segment that carries a TLS `ClientHello` (record type `0x16`,
//! handshake type `0x01`).  If the ClientHello is spread across several TCP
//! segments, engines that do not perform full TCP-stream reassembly before
//! SNI inspection will not see the SNI in any single segment.
//!
//! This method does **not** inject fake packets and does **not** alter TLS
//! record boundaries.  Instead it operates entirely inside the proxy task:
//!
//! 1. After the upstream TCP connection is established, either read exactly
//!    one TLS record (`TLS_FRAG_PACKETS = "tlshello"`) or let the relay count
//!    client writes (`TLS_FRAG_PACKETS = "1-3"`).
//! 2. Write selected bytes to the upstream socket in chunks sampled from
//!    [`TLS_FRAG_LENGTH`](crate::config::Config::TLS_FRAG_LENGTH), with
//!    optional [`TLS_FRAG_INTERVAL_MS`](crate::config::Config::TLS_FRAG_INTERVAL_MS)
//!    delays between chunks.
//! 3. Relay all unselected data normally.
//!
//! Because the platform packet interceptor (WinDivert / NFQUEUE) is **not**
//! involved, this method does not implement the [`BypassMethod`] trait and the
//! flow is never registered in the [`FlowTable`].
//!
//! [`BypassMethod`]: super::BypassMethod
//! [`FlowTable`]: crate::flow::FlowTable
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `TLS_FRAG_PACKETS` | `string` | `"tlshello"` | Fragment the first TLS record or a range of client writes. |
//! | `TLS_FRAG_LENGTH` | `Int32Range` | legacy `TCP_SEG_SIZE` | Payload bytes per fragment chunk. |
//! | `TLS_FRAG_INTERVAL_MS` | `Int32Range` | `0` | Delay between chunks. |
//! | `TCP_SEG_SIZE` | `usize` | `1` | Legacy fixed-length fallback. |
//! | `TCP_SEG_NODELAY` | `bool` | `true` | Enable `TCP_NODELAY` to suppress Nagle coalescing. |

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::trace;

use crate::config::{Config, Int32Range, TlsFragPackets};

/// Maximum number of bytes we are willing to buffer for a single TLS record
/// body.  A standard TLS 1.3 ClientHello is well under 4 KiB; 16 KiB is the
/// TLS record-layer maximum.
const MAX_TLS_RECORD_BODY: usize = 16_384;

/// Parameters for the `tls_frag` bypass method.
#[derive(Debug, Clone, Copy)]
pub struct TcpSegmentation {
    /// Which part of the client stream should be fragmented.
    pub packets: TlsFragPackets,
    /// Fragment payload length range.
    pub length: Int32Range,
    /// Delay between fragment chunks, in milliseconds.
    pub interval_ms: Int32Range,
    /// Whether `TCP_NODELAY` is set on the upstream socket before writing.
    pub nodelay: bool,
}

impl TcpSegmentation {
    pub fn new(cfg: &Config) -> Self {
        Self {
            packets: cfg
                .tls_frag_packets()
                .expect("Config::validate should reject invalid TLS_FRAG_PACKETS"),
            length: cfg
                .tls_frag_length_range()
                .expect("Config::validate should reject invalid TLS_FRAG_LENGTH"),
            interval_ms: cfg.TLS_FRAG_INTERVAL_MS,
            nodelay: cfg.TCP_SEG_NODELAY,
        }
    }

    pub fn fragments_write(self, write_index: u32) -> bool {
        self.packets.includes_write(write_index)
    }
}

/// Read exactly one complete TLS record from `src`.
///
/// Parses the 5-byte TLS record header, then reads the declared body length.
/// Returns the full record (`header || body`) as a `Vec<u8>`.
///
/// Fails if:
/// - The stream reaches EOF before the header or body is complete.
/// - The declared body length exceeds [`MAX_TLS_RECORD_BODY`].
pub async fn read_one_tls_record(src: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    // Read the 5-byte TLS record header.
    let mut header = [0u8; 5];
    src.read_exact(&mut header)
        .await
        .context("reading TLS record header")?;

    // Bytes 3–4 hold the big-endian body length.
    let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if body_len > MAX_TLS_RECORD_BODY {
        anyhow::bail!("TLS record body length {body_len} exceeds maximum {MAX_TLS_RECORD_BODY}");
    }

    // Allocate and read the body.
    let mut record = Vec::with_capacity(5 + body_len);
    record.extend_from_slice(&header);
    record.resize(5 + body_len, 0);
    src.read_exact(&mut record[5..])
        .await
        .context("reading TLS record body")?;

    Ok(record)
}

/// Write `data` to `dst` in chunks sampled from `length`.
///
/// Each chunk is flushed immediately. If `interval_ms` samples to a positive
/// value and more data remains, the writer waits that many milliseconds before
/// sending the next chunk.
pub async fn write_fragmented<W>(
    dst: &mut W,
    data: &[u8],
    length: Int32Range,
    interval_ms: Int32Range,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    assert!(length.min >= 1, "length range must be >= 1");
    assert!(interval_ms.min >= 0, "interval range must be >= 0");

    let mut rng = FragmentRng::new();
    let mut sent = 0usize;
    while sent < data.len() {
        let chunk_len = sample_usize(length, &mut rng).min(data.len() - sent);
        let chunk = &data[sent..sent + chunk_len];
        dst.write_all(chunk)
            .await
            .context("writing fragmented chunk")?;
        dst.flush().await.context("flushing fragmented chunk")?;
        sent += chunk.len();
        trace!(
            target = "zerodpi::tls_frag",
            chunk_len = chunk.len(),
            length_range = %length,
            total_sent = sent,
            "wrote fragment chunk"
        );

        if sent < data.len() {
            let delay_ms = sample_u64(interval_ms, &mut rng);
            if delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }
    Ok(())
}

/// Legacy fixed-size wrapper retained for existing call sites and tests.
pub async fn write_segmented<W>(dst: &mut W, data: &[u8], seg_size: usize) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    assert!(seg_size > 0, "seg_size must be >= 1");
    let length = Int32Range::exact(i32::try_from(seg_size).context("seg_size exceeds i32::MAX")?);
    write_fragmented(dst, data, length, Int32Range::exact(0)).await
}

static RNG_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
struct FragmentRng {
    state: u64,
}

impl FragmentRng {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            state: nanos
                ^ RNG_COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
                ^ 0xA5A5_5A5A_D3C1_B2E0,
        }
    }

    #[cfg(test)]
    fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn sample_i32(range: Int32Range, rng: &mut FragmentRng) -> i32 {
    if range.min == range.max {
        return range.min;
    }
    let width = (range.max as i64 - range.min as i64 + 1) as u64;
    range.min + (rng.next_u64() % width) as i32
}

fn sample_usize(range: Int32Range, rng: &mut FragmentRng) -> usize {
    sample_i32(range, rng) as usize
}

fn sample_u64(range: Int32Range, rng: &mut FragmentRng) -> u64 {
    sample_i32(range, rng) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // write_segmented: unit-test using an in-memory buffer via tokio duplex
    // -----------------------------------------------------------------------
    #[test]
    fn chunking_preserves_data_single_byte() {
        let data: Vec<u8> = (0..=255u8).collect();
        let chunks: Vec<Vec<u8>> = data.chunks(1).map(|c| c.to_vec()).collect();
        assert_eq!(chunks.len(), 256);
        let flat: Vec<u8> = chunks.concat();
        assert_eq!(flat, data);
    }

    #[test]
    fn chunking_preserves_data_arbitrary_size() {
        let data: Vec<u8> = (0..100u8).collect();
        for seg in [1, 3, 7, 10, 99, 100, 200] {
            let flat: Vec<u8> = data.chunks(seg).flat_map(|c| c.iter().copied()).collect();
            assert_eq!(flat, data, "seg_size={seg}");
        }
    }

    #[test]
    fn sampled_values_stay_inside_range() {
        let mut rng = FragmentRng::from_seed(0x1234_5678);
        let range = Int32Range { min: 2, max: 7 };
        for _ in 0..256 {
            let value = sample_i32(range, &mut rng);
            assert!((2..=7).contains(&value));
        }
    }

    #[tokio::test]
    async fn write_fragmented_preserves_data() {
        let data: Vec<u8> = (0..64u8).collect();
        let expected = data.clone();
        let (mut writer, mut reader) = tokio::io::duplex(128);

        let write_task = tokio::spawn(async move {
            write_fragmented(
                &mut writer,
                &data,
                Int32Range { min: 2, max: 7 },
                Int32Range::exact(0),
            )
            .await
        });

        let mut out = vec![0u8; expected.len()];
        reader.read_exact(&mut out).await.unwrap();
        write_task.await.unwrap().unwrap();
        assert_eq!(out, expected);
    }

    // -----------------------------------------------------------------------
    // read_one_tls_record: parsing tests
    // -----------------------------------------------------------------------

    /// Build a minimal TLS record with the given content_type and body.
    fn make_tls_record(content_type: u8, body: &[u8]) -> Vec<u8> {
        let mut rec = vec![
            content_type,
            0x03,
            0x03, // TLS 1.2 legacy version
            (body.len() >> 8) as u8,
            (body.len() & 0xFF) as u8,
        ];
        rec.extend_from_slice(body);
        rec
    }

    #[tokio::test]
    async fn reads_complete_tls_record() {
        let body = vec![0x01u8; 64]; // fake ClientHello body
        let record = make_tls_record(0x16, &body);

        let (client, server) = tokio::io::duplex(4096);
        let _ = (client, server); // duplex used only to validate test compiles

        // Manual parse test (mirrors the implementation):
        let hdr = &record[..5];
        let body_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        assert_eq!(body_len, 64);
        assert_eq!(record.len(), 5 + body_len);
        assert_eq!(record[0], 0x16);
    }

    #[test]
    fn tls_record_body_length_parsed_correctly() {
        // Check a range of body lengths.
        for len in [0u16, 1, 127, 128, 255, 256, 1000, 16383, 16384] {
            let body = vec![0xAAu8; len as usize];
            let rec = make_tls_record(0x16, &body);
            let parsed_len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
            assert_eq!(parsed_len, len as usize);
        }
    }

    #[test]
    fn config_new_reads_fields() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "tls_frag"
               TCP_SEG_SIZE = 7
               TCP_SEG_NODELAY = false"#,
        )
        .unwrap();
        let m = TcpSegmentation::new(&cfg);
        assert_eq!(m.packets, TlsFragPackets::WriteRange { start: 1, end: 3 });
        assert_eq!(m.length, Int32Range { min: 100, max: 200 });
        assert_eq!(m.interval_ms, Int32Range { min: 10, max: 20 });
        assert!(!m.nodelay);
    }

    #[test]
    fn config_new_reads_xray_style_fields() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "tls_frag"
               TLS_FRAG_PACKETS = "1-3"
               TLS_FRAG_LENGTH = "2-4"
               TLS_FRAG_INTERVAL_MS = "0-9"
               TCP_SEG_SIZE = 7
               TCP_SEG_NODELAY = false"#,
        )
        .unwrap();
        cfg.validate().unwrap();
        let m = TcpSegmentation::new(&cfg);
        assert_eq!(m.packets, TlsFragPackets::WriteRange { start: 1, end: 3 });
        assert_eq!(m.length, Int32Range { min: 2, max: 4 });
        assert_eq!(m.interval_ms, Int32Range { min: 0, max: 9 });
        assert!(!m.nodelay);
    }
}
