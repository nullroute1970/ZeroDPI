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

use super::sni::find_sni_range;
use super::{BypassMethod, MethodAction};
use crate::config::{Config, SniSplitPosition};
use crate::flow::FlowState;
use crate::interceptor::PacketView;

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
    fn name(&self) -> String {
        "urg_sni_split".into()
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::flow::FlowState;
    use crate::interceptor::{Direction, PacketView, TcpFlags};
    use crate::tls_template::build_client_hello;

    fn client_hello(sni: &[u8]) -> Vec<u8> {
        build_client_hello(&[0u8; 32], &[0u8; 32], sni, &[0u8; 32])
    }

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
            emit_original_after: false,
            new_ipv4_ttl: None,
            new_urgent_pointer: None,
        }
    }

    #[test]
    fn finds_sni_in_built_client_hello() {
        for sni in ["auth.vercel.com", "mci.ir", "a"] {
            let ch = client_hello(sni.as_bytes());
            assert_eq!(find_sni_range(&ch), Some((127, sni.len())), "sni={sni:?}");
        }
    }

    #[test]
    fn finds_sni_in_an_extension_after_leading_extensions() {
        // Rebuild by splicing: the built CH has the server_name extension
        // first (type 0x0000 at data offset 118). Insert a fake 4-byte
        // extension before it and bump the extensions-total-length field
        // (data offset 116..118) so the structure stays consistent.
        let ch = client_hello(b"example.com");
        let mut extended = Vec::with_capacity(ch.len() + 4);
        extended.extend_from_slice(&ch[..118]);
        extended.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // ext type 0x0017, len 0
        extended.extend_from_slice(&ch[118..]);
        // Bump the TLS record length (data offset 3..5), the handshake length
        // (data offset 6..8), and the extensions-total-length field (data
        // offset 116..118) so the structure stays consistent after the 4-byte
        // splice.
        let record_len = u16::from_be_bytes([extended[3], extended[4]]) + 4;
        extended[3] = (record_len >> 8) as u8;
        extended[4] = record_len as u8;
        let hs_len = u32::from_be_bytes([0, extended[6], extended[7], extended[8]]) + 4;
        extended[6] = (hs_len >> 16) as u8;
        extended[7] = (hs_len >> 8) as u8;
        extended[8] = hs_len as u8;
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
        assert_eq!(
            resolve_insert_position(11, SniSplitPosition::Index(999)),
            10
        );
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

    #[test]
    fn on_handshake_complete_ack_is_passthrough() {
        let method = UrgSniSplit::new(&default_cfg());
        let state = FlowState::new(vec![], None);
        let mut pkt = data_pkt(&[]);
        assert_eq!(
            method.on_handshake_complete_ack(&state, &mut pkt),
            MethodAction::PassThrough
        );
    }

    #[test]
    fn on_first_data_packet_splits_sni_and_sets_urg() {
        let method = UrgSniSplit::new(&default_cfg());
        let state = FlowState::new(vec![], None);
        let sni = b"auth.vercel.com";
        let ch = client_hello(sni);
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
        let state = FlowState::new(vec![], None);
        let ch = client_hello(b"mci.ir");
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
        let state = FlowState::new(vec![], None);
        let mut pkt = data_pkt(b"GET / HTTP/1.1");
        let action = method.on_first_data_packet(&state, &mut pkt);
        assert_eq!(action, MethodAction::PassThrough);
        assert!(pkt.new_payload.is_none());
        assert!(pkt.new_flags.is_none());
        assert!(pkt.new_urgent_pointer.is_none());
    }
}
