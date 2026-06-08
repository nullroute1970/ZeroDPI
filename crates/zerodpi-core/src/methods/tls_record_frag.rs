//! `tls_record_frag` bypass: splits the real TLS ClientHello into multiple
//! small TLS record-layer fragments before forwarding to the upstream server.
//!
//! ## How it works
//!
//! Many DPI/firewall middleboxes inspect TLS traffic by parsing TLS records
//! and extracting the SNI from the first `ClientHello` (record type `0x16`,
//! handshake type `0x01`).  If the ClientHello is spread across several TLS
//! records, engines that only reassemble up to a fixed depth (or none at all)
//! will not see the SNI in any single record and will classify the flow as
//! non-TLS or pass it through.
//!
//! This method intercepts the first outbound *data* packet (the real
//! ClientHello), parses the TLS record header, splits the record body into
//! chunks of at most `TLS_RECORD_FRAG_SIZE` bytes, wraps each body chunk in a
//! new TLS record header, and stages the concatenated result as the
//! replacement payload.  The upstream server receives all fragments in order
//! and reassembles them identically to an unfragmented ClientHello.
//!
//! Because no fake packet is injected, the bypass is signalled complete
//! immediately after the fragmented packet is emitted — no inbound ACK
//! confirmation is needed.
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `TLS_RECORD_FRAG_SIZE` | `usize` | `1` | Max body bytes per TLS record. |
//! | `TLS_RECORD_FRAG_SET_PSH` | `bool` | `true` | Set PSH on the modified packet. |
//! | `TLS_RECORD_FRAG_BUMP_IP_IDENT` | `bool` | `true` | Increment IPv4 ID. |

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

const TLS_RECORD_HEADER_LEN: usize = 5;

pub struct TlsRecordFrag {
    /// Maximum bytes of payload placed in each TLS record fragment.
    frag_size: usize,
    /// Whether to set the TCP PSH flag on the modified packet.
    set_psh: bool,
    /// Whether to increment the IPv4 Identification field on the modified packet.
    bump_ip_ident: bool,
}

impl TlsRecordFrag {
    pub fn new(cfg: &Config) -> Self {
        Self {
            frag_size: cfg.TLS_RECORD_FRAG_SIZE,
            set_psh: cfg.TLS_RECORD_FRAG_SET_PSH,
            bump_ip_ident: cfg.TLS_RECORD_FRAG_BUMP_IP_IDENT,
        }
    }
}

impl BypassMethod for TlsRecordFrag {
    fn name(&self) -> &'static str {
        "tls_record_frag"
    }

    /// Returns `PassThrough` — this method operates on the first data packet,
    /// not the handshake-complete ACK.  The handler will set `waiting_for_data`
    /// on the flow and call [`on_first_data_packet`] instead.
    ///
    /// [`on_first_data_packet`]: TlsRecordFrag::on_first_data_packet
    fn on_handshake_complete_ack(
        &self,
        _flow: &FlowState,
        _pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        MethodAction::PassThrough
    }

    /// Fragments the packet payload into multiple TLS records and stages the
    /// result, then returns `EmitFakeAndAccept` to signal bypass completion.
    fn on_first_data_packet(&self, _flow: &FlowState, pkt: &mut PacketView<'_>) -> MethodAction {
        let Some(fragmented) = fragment_payload(pkt.payload, self.frag_size) else {
            trace!(
                target = "zerodpi::tls_record_frag",
                frag_size = self.frag_size,
                orig_len = pkt.payload_len,
                "first data packet is not a complete TLS record; passing through"
            );
            return MethodAction::complete_and_accept();
        };

        let mut flags = pkt.flags;
        flags.psh = self.set_psh;

        pkt.new_flags = Some(flags);
        pkt.new_payload = Some(fragmented);
        pkt.bump_ipv4_ident = self.bump_ip_ident;

        trace!(
            target = "zerodpi::tls_record_frag",
            frag_size = self.frag_size,
            orig_len = pkt.payload_len,
            set_psh = self.set_psh,
            bump_ip_ident = self.bump_ip_ident,
            "staged fragmented ClientHello"
        );

        MethodAction::emit_and_complete()
    }
}

/// Split one or more complete TLS records into smaller TLS records.
///
/// The input must be a sequence of complete TLS records.  For each record, the
/// TLS content type and legacy version bytes are preserved, and only the
/// record body is split into chunks of at most `frag_size` bytes.  If the input
/// is empty, an empty `Vec` is returned.  If any record header or body is
/// incomplete, `None` is returned so the caller can pass the packet through
/// unchanged.
///
/// # Panics
/// Panics if `frag_size == 0`.
pub fn fragment_payload(data: &[u8], frag_size: usize) -> Option<Vec<u8>> {
    assert!(frag_size > 0, "frag_size must be >= 1");
    if data.is_empty() {
        return Some(Vec::new());
    }

    let mut out = Vec::with_capacity(data.len());
    let mut offset = 0usize;

    while offset < data.len() {
        if data.len() - offset < TLS_RECORD_HEADER_LEN {
            return None;
        }

        let header = &data[offset..offset + TLS_RECORD_HEADER_LEN];
        let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let body_start = offset + TLS_RECORD_HEADER_LEN;
        let body_end = body_start.checked_add(body_len)?;
        if body_end > data.len() {
            return None;
        }

        let body = &data[body_start..body_end];
        if body.is_empty() {
            out.extend_from_slice(header);
        } else {
            for chunk in body.chunks(frag_size) {
                let len = chunk.len() as u16;
                out.extend_from_slice(&header[..3]);
                out.push((len >> 8) as u8);
                out.push(len as u8);
                out.extend_from_slice(chunk);
            }
        }

        offset = body_end;
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::flow::FlowState;
    use crate::interceptor::{Direction, PacketView, TcpFlags};

    fn default_cfg() -> Config {
        toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap()
    }

    fn data_pkt(payload: &[u8]) -> PacketView<'_> {
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
            new_seq: None,
            new_ack: None,
            new_flags: None,
            new_payload: None,
            bump_ipv4_ident: false,
            corrupt_tcp_checksum_delta: None,
        }
    }

    // -----------------------------------------------------------------------
    // fragment_payload unit tests
    // -----------------------------------------------------------------------

    fn make_tls_record(content_type: u8, version: [u8; 2], body: &[u8]) -> Vec<u8> {
        let body_len = body.len();
        let mut record = vec![
            content_type,
            version[0],
            version[1],
            (body_len >> 8) as u8,
            body_len as u8,
        ];
        record.extend_from_slice(body);
        record
    }

    fn reassembled_body(records: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut offset = 0usize;
        while offset < records.len() {
            let len = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;
            body.extend_from_slice(&records[offset + 5..offset + 5 + len]);
            offset += TLS_RECORD_HEADER_LEN + len;
        }
        body
    }

    #[test]
    fn empty_data_returns_empty() {
        assert_eq!(fragment_payload(&[], 1), Some(Vec::new()));
    }

    #[test]
    fn single_byte_frag_size_produces_one_record_per_body_byte() {
        let body = [0x01, 0xAA, 0xBB];
        let data = make_tls_record(0x16, [0x03, 0x03], &body);
        let out = fragment_payload(&data, 1).unwrap();

        assert_eq!(out.len(), body.len() * (TLS_RECORD_HEADER_LEN + 1));
        assert_eq!(out[0], 0x16); // content_type preserved
        assert_eq!(out[1], 0x03);
        assert_eq!(out[2], 0x03);
        assert_eq!(&out[3..5], &[0x00, 0x01]); // length = 1
        assert_eq!(out[5], 0x01); // first ClientHello body byte
        assert_eq!(out[6], 0x16);
        assert_eq!(&out[9..11], &[0x00, 0x01]);
        assert_eq!(out[11], 0xAA);
        assert_eq!(reassembled_body(&out), body.to_vec());
    }

    #[test]
    fn frag_size_larger_than_body_produces_one_record() {
        let body = [0xA5; 10];
        let data = make_tls_record(0x16, [0x03, 0x03], &body);
        let out = fragment_payload(&data, 100).unwrap();

        assert_eq!(out.len(), TLS_RECORD_HEADER_LEN + body.len());
        assert_eq!(out[0], 0x16);
        assert_eq!(out[1], 0x03);
        assert_eq!(out[2], 0x03);
        assert_eq!(&out[3..5], &[0x00, 0x0A]); // length = 10
        assert_eq!(reassembled_body(&out), body.to_vec());
    }

    #[test]
    fn frag_size_exactly_divides_body() {
        let body = [1, 2, 3, 4, 5, 6];
        let data = make_tls_record(0x17, [0x03, 0x04], &body);
        let out = fragment_payload(&data, 2).unwrap();

        assert_eq!(out.len(), 3 * 7); // 5 header + 2 payload × 3
        for i in 0..3 {
            let off = i * 7;
            assert_eq!(out[off], 0x17);
            assert_eq!(out[off + 1], 0x03);
            assert_eq!(out[off + 2], 0x04);
            assert_eq!(&out[off + 3..off + 5], &[0x00, 0x02]);
        }
        assert_eq!(reassembled_body(&out), body.to_vec());
    }

    #[test]
    fn frag_size_does_not_divide_evenly() {
        let body = [0x16; 7];
        let data = make_tls_record(0x16, [0x03, 0x03], &body);
        let out = fragment_payload(&data, 3).unwrap();

        // (5+3) + (5+3) + (5+1) = 22
        assert_eq!(out.len(), 22);
        // Last record starts at byte 16: 2 × (5-hdr + 3-payload) = 16.
        // Its length field is at offset 16+3 = 19.
        let last_hdr_off = (5 + 3) * 2; // = 16
        assert_eq!(&out[last_hdr_off + 3..last_hdr_off + 5], &[0x00, 0x01]);
        assert_eq!(reassembled_body(&out), body.to_vec());
    }

    #[test]
    fn content_type_and_version_are_preserved() {
        let body = [0xAB; 10];
        let data = make_tls_record(0x17, [0x03, 0x04], &body);
        let out = fragment_payload(&data, 4).unwrap();

        let mut offset = 0usize;
        while offset < out.len() {
            assert_eq!(out[offset], 0x17);
            assert_eq!(out[offset + 1], 0x03);
            assert_eq!(out[offset + 2], 0x04);
            let len = u16::from_be_bytes([out[offset + 3], out[offset + 4]]) as usize;
            offset += TLS_RECORD_HEADER_LEN + len;
        }
    }

    #[test]
    fn multiple_complete_records_are_fragmented_independently() {
        let first_body = [0x01, 0x02, 0x03];
        let second_body = [0xAA, 0xBB];
        let mut data = make_tls_record(0x16, [0x03, 0x03], &first_body);
        data.extend_from_slice(&make_tls_record(0x17, [0x03, 0x03], &second_body));

        let out = fragment_payload(&data, 2).unwrap();

        assert_eq!(
            reassembled_body(&out),
            [first_body.as_slice(), second_body.as_slice()].concat()
        );
        assert_eq!(out[0], 0x16);
        let first_record_end = TLS_RECORD_HEADER_LEN + 2;
        let second_fragment_off = first_record_end;
        assert_eq!(out[second_fragment_off], 0x16);
        let third_fragment_off = second_fragment_off + TLS_RECORD_HEADER_LEN + 1;
        assert_eq!(out[third_fragment_off], 0x17);
    }

    #[test]
    fn incomplete_header_returns_none() {
        assert_eq!(fragment_payload(&[0x16, 0x03, 0x03], 1), None);
    }

    #[test]
    fn incomplete_body_returns_none() {
        let mut data = make_tls_record(0x16, [0x03, 0x03], &[0x01, 0x02, 0x03]);
        data.truncate(data.len() - 1);

        assert_eq!(fragment_payload(&data, 1), None);
    }

    #[test]
    fn zero_length_record_is_preserved() {
        let data = make_tls_record(0x16, [0x03, 0x03], &[]);

        assert_eq!(fragment_payload(&data, 1).unwrap(), data);
    }

    // -----------------------------------------------------------------------
    // BypassMethod integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn on_handshake_complete_ack_is_passthrough() {
        let cfg = default_cfg();
        let method = TlsRecordFrag::new(&cfg);
        let state = FlowState::new(vec![]);
        let mut pkt = data_pkt(&[]);
        let action = method.on_handshake_complete_ack(&state, &mut pkt);
        assert_eq!(action, MethodAction::PassThrough);
    }

    #[test]
    fn on_first_data_packet_fragments_and_emits() {
        let cfg = default_cfg(); // TLS_RECORD_FRAG_SIZE = 1 by default
        let method = TlsRecordFrag::new(&cfg);
        let state = FlowState::new(vec![]);

        let body = vec![0x01u8; 12]; // fake ClientHello body
        let payload = make_tls_record(0x16, [0x03, 0x03], &body);
        let mut pkt = data_pkt(&payload);
        let action = method.on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        let new_payload = pkt.new_payload.as_ref().unwrap();
        // 12 body bytes → 12 records of 1 byte each, each with 5-byte header.
        assert_eq!(new_payload.len(), body.len() * (TLS_RECORD_HEADER_LEN + 1));
        // Verify each record header
        for i in 0..body.len() {
            let off = i * 6;
            assert_eq!(new_payload[off], 0x16);
            assert_eq!(new_payload[off + 1], 0x03);
            assert_eq!(new_payload[off + 2], 0x03);
            assert_eq!(&new_payload[off + 3..off + 5], &[0x00, 0x01]);
            assert_eq!(new_payload[off + 5], 0x01);
        }
        assert_eq!(reassembled_body(new_payload), body);
        assert!(pkt.new_flags.unwrap().psh); // default SET_PSH = true
        assert!(pkt.bump_ipv4_ident); // default BUMP_IP_IDENT = true
    }

    #[test]
    fn configurable_frag_size() {
        let mut cfg = default_cfg();
        cfg.TLS_RECORD_FRAG_SIZE = 5;
        let method = TlsRecordFrag::new(&cfg);
        let state = FlowState::new(vec![]);

        // 10-byte body → 2 records of 5 bytes each.
        let payload = make_tls_record(0x16, [0x03, 0x03], &[0x01; 10]);
        let mut pkt = data_pkt(&payload);
        method.on_first_data_packet(&state, &mut pkt);
        let new_payload = pkt.new_payload.unwrap();
        assert_eq!(new_payload.len(), 2 * (5 + 5)); // 2 × (5-hdr + 5-payload)
    }

    #[test]
    fn set_psh_false() {
        let mut cfg = default_cfg();
        cfg.TLS_RECORD_FRAG_SET_PSH = false;
        let method = TlsRecordFrag::new(&cfg);
        let state = FlowState::new(vec![]);
        let payload = make_tls_record(0x16, [0x03, 0x03], &[0x01; 4]);
        let mut pkt = data_pkt(&payload);
        method.on_first_data_packet(&state, &mut pkt);
        assert!(!pkt.new_flags.unwrap().psh);
    }

    #[test]
    fn bump_ip_ident_false() {
        let mut cfg = default_cfg();
        cfg.TLS_RECORD_FRAG_BUMP_IP_IDENT = false;
        let method = TlsRecordFrag::new(&cfg);
        let state = FlowState::new(vec![]);
        let payload = make_tls_record(0x16, [0x03, 0x03], &[0x01; 4]);
        let mut pkt = data_pkt(&payload);
        method.on_first_data_packet(&state, &mut pkt);
        assert!(!pkt.bump_ipv4_ident);
    }

    #[test]
    fn malformed_first_data_packet_completes_without_rewrite() {
        let cfg = default_cfg();
        let method = TlsRecordFrag::new(&cfg);
        let state = FlowState::new(vec![]);
        let payload = [0x16, 0x03, 0x03];
        let mut pkt = data_pkt(&payload);

        let action = method.on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::complete_and_accept());
        assert!(pkt.new_payload.is_none());
        assert!(pkt.new_flags.is_none());
        assert!(!pkt.bump_ipv4_ident);
    }
}
