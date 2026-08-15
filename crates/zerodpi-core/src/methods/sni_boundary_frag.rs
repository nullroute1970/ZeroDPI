//! `sni_boundary_frag` bypass: SNI Extension Boundary Fragmentation.
//!
//! ## How it works
//!
//! Rather than splitting TCP packets at random byte positions, this method
//! parses the TLS ClientHello down to the extension array, calculates the
//! exact byte offset of the SNI extension, and cuts the first ClientHello
//! TCP write there. The record is sent as two TCP segments — e.g. segment 1
//! ends right after the server_name extension's length field (or mid-domain,
//! `you` / `tube.com`) — with a configurable millisecond delay
//! (`SNI_BOUNDARY_FRAG_DELAY_MS`, default 5–10 ms) between them, so inline
//! DPI reassembly buffers do not stitch the two segments back together.
//!
//! This method does **not** inject fake packets and does **not** alter the
//! TLS bytes. It operates entirely inside the proxy task:
//!
//! 1. Read exactly one TLS record from the client.
//! 2. Locate the server_name extension (see [`super::sni::find_sni_boundary`]).
//! 3. Resolve the split byte offset from
//!    [`SniBoundarySplitPoint`](crate::config::SniBoundarySplitPoint).
//! 4. Write `record[..split]`, flush, sleep the sampled delay, write
//!    `record[split..]`, flush. `TCP_NODELAY` is enabled on the upstream
//!    socket so each write leaves as its own TCP segment.
//! 5. Fail open: when the record has no parseable ClientHello with an SNI,
//!    or the resolved offset would not split the record into two non-empty
//!    parts, the record is written whole.
//!
//! Because the platform packet interceptor (WinDivert / NFQUEUE) is **not**
//! involved, this method does not implement the [`BypassMethod`] trait and
//! the flow is never registered in the [`FlowTable`].
//!
//! [`BypassMethod`]: super::BypassMethod
//! [`FlowTable`]: crate::flow::FlowTable
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `SNI_BOUNDARY_FRAG_SPLIT_POINT` | string / int | `"extension_length"` | Where to cut: `"extension_length"`, `"middle"`, or a 0-based index into the domain string. |
//! | `SNI_BOUNDARY_FRAG_DELAY_MS` | `Int32Range` | `"5-10"` | Delay between the two segments. |

use anyhow::Context;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::sni::find_sni_boundary;
use crate::config::{Config, Int32Range, SniBoundarySplitPoint};

/// Parameters for the `sni_boundary_frag` bypass method.
#[derive(Debug, Clone, Copy)]
pub struct SniBoundaryFrag {
    /// Where to cut the first ClientHello TCP write.
    pub split_point: SniBoundarySplitPoint,
    /// Delay between the two TCP segments, in milliseconds.
    pub delay_ms: Int32Range,
}

impl SniBoundaryFrag {
    pub fn new(cfg: &Config) -> Self {
        Self {
            split_point: cfg.SNI_BOUNDARY_FRAG_SPLIT_POINT,
            delay_ms: cfg.SNI_BOUNDARY_FRAG_DELAY_MS,
        }
    }

    /// Resolve the configured split point to a byte offset inside `record`.
    ///
    /// Returns `None` when the record contains no parseable ClientHello with
    /// an SNI, or when the resolved offset would not split the record into
    /// two non-empty parts (offset `0` or `record.len()`). Callers fail open
    /// by writing the record whole.
    pub fn split_offset(&self, record: &[u8]) -> Option<usize> {
        let boundary = find_sni_boundary(record)?;
        let offset = match self.split_point {
            SniBoundarySplitPoint::ExtensionLength => boundary.ext_len_field_end,
            SniBoundarySplitPoint::Middle => boundary.name_start + boundary.name_len / 2,
            SniBoundarySplitPoint::Index(n) => {
                boundary.name_start + (n as usize).min(boundary.name_len)
            }
        };
        (offset > 0 && offset < record.len()).then_some(offset)
    }
}

/// Write `data` to `dst` in two parts: `data[..split]`, then — after a delay
/// sampled from `delay_ms` — `data[split..]`.
///
/// Each part is flushed immediately so the OS emits it as its own TCP
/// segment. `split` must produce two non-empty parts.
pub async fn write_boundary_split<W>(
    dst: &mut W,
    data: &[u8],
    split: usize,
    delay_ms: Int32Range,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    assert!(
        split > 0 && split < data.len(),
        "split must produce two non-empty parts"
    );
    assert!(delay_ms.min >= 0, "delay range must be >= 0");

    dst.write_all(&data[..split])
        .await
        .context("writing first boundary segment")?;
    dst.flush()
        .await
        .context("flushing first boundary segment")?;

    let delay_ms = super::tcp_segmentation::sample_i32(
        delay_ms,
        &mut super::tcp_segmentation::FragmentRng::new(),
    )
    .max(0) as u64;
    if delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }

    dst.write_all(&data[split..])
        .await
        .context("writing second boundary segment")?;
    dst.flush()
        .await
        .context("flushing second boundary segment")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Int32Range, SniBoundarySplitPoint};
    use crate::tls_template::build_client_hello;
    use tokio::io::AsyncReadExt;

    fn cfg_with(extra: &str) -> Config {
        toml::from_str(&format!(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "sni_boundary_frag"
               {extra}"#
        ))
        .unwrap()
    }

    fn client_hello(sni: &[u8]) -> Vec<u8> {
        build_client_hello(&[0u8; 32], &[0u8; 32], sni, &[0u8; 32])
    }

    /// Handcraft a minimal ClientHello whose server_name extension is the
    /// only extension and the last bytes of the record, so split offsets at
    /// the record end can be exercised.
    fn minimal_hello_ending_in_sni(sni: &[u8]) -> Vec<u8> {
        let name_len = sni.len() as u16;
        let list_len = 3u16 + name_len;
        let ext_len = 5u16 + name_len;
        let ext_total = 4u16 + ext_len;
        let body_len = 2usize + 32 + 1 + 2 + 1 + 2 + ext_total as usize;
        let hs_len = 4usize + body_len;
        let mut rec = vec![
            0x16,
            0x03,
            0x03, // record header: handshake, version
            ((5 + hs_len) >> 8) as u8,
            (5 + hs_len) as u8, // record length
            0x01,               // handshake type: ClientHello
            (hs_len >> 16) as u8,
            (hs_len >> 8) as u8,
            hs_len as u8, // handshake length
            0x03,
            0x03, // client version
        ];
        rec.extend_from_slice(&[0u8; 32]); // random
        rec.push(0); // session id length
        rec.extend_from_slice(&[0x00, 0x00]); // cipher suites length
        rec.push(0); // compression methods length
        rec.extend_from_slice(&[(ext_total >> 8) as u8, ext_total as u8]); // extensions total
        rec.extend_from_slice(&[0x00, 0x00, (ext_len >> 8) as u8, ext_len as u8]); // ext header
        rec.extend_from_slice(&[(list_len >> 8) as u8, list_len as u8]); // server_name list len
        rec.push(0x00); // name type: host_name
        rec.extend_from_slice(&[(name_len >> 8) as u8, name_len as u8]); // name len
        rec.extend_from_slice(sni);
        rec
    }

    #[test]
    fn extension_length_split_is_right_after_ext_len_field() {
        let method = SniBoundaryFrag::new(&cfg_with(""));
        let ch = client_hello(b"auth.vercel.com");
        // ext header at 118, length field at 120..122 (see sni.rs tests).
        assert_eq!(method.split_offset(&ch), Some(122));
    }

    #[test]
    fn middle_split_lands_inside_domain() {
        let method = SniBoundaryFrag::new(&cfg_with(r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = "middle""#));
        let ch = client_hello(b"auth.vercel.com"); // name at 127, len 15
        assert_eq!(method.split_offset(&ch), Some(127 + 7));
    }

    #[test]
    fn index_split_is_clamped_to_domain_length() {
        let method = SniBoundaryFrag::new(&cfg_with(r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = 3"#));
        let ch = client_hello(b"auth.vercel.com");
        assert_eq!(method.split_offset(&ch), Some(127 + 3));

        let method = SniBoundaryFrag::new(&cfg_with(r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = 999"#));
        // clamped to name_len (15): offset 127 + 15, which is inside the
        // record (trailing extensions follow), so a split is returned.
        assert_eq!(method.split_offset(&ch), Some(127 + 15));
    }

    #[test]
    fn split_at_record_end_returns_none() {
        // "mci.ir" is 6 bytes and is the last 6 bytes of this record;
        // splitting after all 6 name bytes lands at the record end and must
        // fail open (no split).
        let method = SniBoundaryFrag::new(&cfg_with(r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = 6"#));
        assert_eq!(
            method.split_offset(&minimal_hello_ending_in_sni(b"mci.ir")),
            None
        );
    }

    #[test]
    fn missing_sni_fails_open() {
        let method = SniBoundaryFrag::new(&cfg_with(""));
        assert_eq!(method.split_offset(b"GET / HTTP/1.1"), None);
        assert_eq!(method.split_offset(&[]), None);
        let ch = client_hello(b"example.com");
        assert_eq!(method.split_offset(&ch[..ch.len() - 1]), None);
    }

    #[test]
    fn config_values_reach_the_method() {
        let method = SniBoundaryFrag::new(&cfg_with(
            r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = "middle"
               SNI_BOUNDARY_FRAG_DELAY_MS = "7-9""#,
        ));
        assert_eq!(method.split_point, SniBoundarySplitPoint::Middle);
        assert_eq!(method.delay_ms, Int32Range { min: 7, max: 9 });
    }

    #[tokio::test]
    async fn write_boundary_split_preserves_bytes_in_order() {
        let data: Vec<u8> = (0..64u8).collect();
        let expected = data.clone();
        let (mut writer, mut reader) = tokio::io::duplex(128);

        let write_task = tokio::spawn(async move {
            write_boundary_split(&mut writer, &data, 20, Int32Range::exact(0)).await
        });

        let mut out = vec![0u8; expected.len()];
        reader.read_exact(&mut out).await.unwrap();
        write_task.await.unwrap().unwrap();
        assert_eq!(out, expected);
    }

    #[tokio::test]
    async fn write_boundary_split_delays_the_second_part() {
        let data = b"0123456789abcdef";
        let (mut writer, mut reader) = tokio::io::duplex(64);

        let write_task = tokio::spawn(async move {
            write_boundary_split(&mut writer, data, 8, Int32Range::exact(150)).await
        });

        // First part arrives immediately.
        let mut first = [0u8; 8];
        reader.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"01234567");

        // Second part must NOT arrive before the 150 ms delay elapses.
        let mut early = [0u8; 8];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                reader.read_exact(&mut early)
            )
            .await
            .is_err(),
            "second segment must be delayed"
        );

        // After the delay it arrives.
        reader.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"89abcdef");
        write_task.await.unwrap().unwrap();
    }
}
