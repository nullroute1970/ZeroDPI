//! Combined `wrong_seq` + `tls_record_frag` bypass.
//!
//! This method targets layered DPI paths.  The first stage injects a fake
//! ClientHello with an old TCP sequence number so the first DPI layer can be
//! desynchronized.  The second stage fragments the real ClientHello into small
//! TLS records so downstream DPI layers that never saw the fake packet still
//! have to reassemble the real stream.

use tracing::trace;

use super::tls_record_frag::TlsRecordFrag;
use super::wrong_seq::WrongSeq;
use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub struct WrongSeqTlsRecordFrag {
    wrong_seq: WrongSeq,
    tls_record_frag: TlsRecordFrag,
}

impl WrongSeqTlsRecordFrag {
    pub fn new(cfg: &Config) -> Self {
        Self {
            wrong_seq: WrongSeq::new(cfg),
            tls_record_frag: TlsRecordFrag::new(cfg),
        }
    }
}

impl BypassMethod for WrongSeqTlsRecordFrag {
    fn name(&self) -> &'static str {
        "wrong_seq_tls_record_frag"
    }

    fn on_handshake_complete_ack(
        &self,
        flow: &FlowState,
        pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        let _ = self.wrong_seq.on_handshake_complete_ack(flow, pkt);
        trace!(
            target = "zerodpi::wrong_seq_tls_record_frag",
            "staged wrong_seq fake; waiting for TLS record fragmentation"
        );
        MethodAction::emit_and_wait_for_data()
    }

    fn on_first_data_packet(&self, flow: &FlowState, pkt: &mut PacketView<'_>) -> MethodAction {
        trace!(
            target = "zerodpi::wrong_seq_tls_record_frag",
            "staging TLS record fragmentation for real ClientHello"
        );
        self.tls_record_frag.on_first_data_packet(flow, pkt)
    }
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
               LISTEN_PORT = 44444
               BYPASS_METHOD = "wrong_seq_tls_record_frag""#,
        )
        .unwrap()
    }

    fn pkt(payload: &'static [u8], payload_len: usize) -> PacketView<'static> {
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
                psh: payload_len > 0,
                ..Default::default()
            },
            payload_len,
            payload,
            new_seq: None,
            new_ack: None,
            new_flags: None,
            new_payload: None,
            append_tcp_options: Vec::new(),
            bump_ipv4_ident: false,
            corrupt_tcp_checksum_delta: None,
        }
    }

    #[test]
    fn handshake_stage_emits_wrong_seq_and_waits_for_data() {
        let mut state = FlowState::new(vec![0xAB; 517]);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(5000);

        let mut packet = pkt(&[], 0);
        let action = WrongSeqTlsRecordFrag::new(&default_cfg())
            .on_handshake_complete_ack(&state, &mut packet);

        assert_eq!(action, MethodAction::emit_and_wait_for_data());
        assert_eq!(packet.new_payload.as_ref().unwrap().len(), 517);
        assert_eq!(packet.new_seq, Some(1001u32.wrapping_sub(517)));
        assert!(packet.new_flags.unwrap().psh);
        assert!(packet.bump_ipv4_ident);
    }

    #[test]
    fn first_data_stage_fragments_real_payload() {
        let state = FlowState::new(vec![]);
        let payload: &'static [u8] = &[0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03];
        let mut packet = pkt(payload, payload.len());

        let action =
            WrongSeqTlsRecordFrag::new(&default_cfg()).on_first_data_packet(&state, &mut packet);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(packet.new_payload.as_ref().unwrap().len(), 18);
        assert!(packet.new_flags.unwrap().psh);
        assert!(packet.bump_ipv4_ident);
    }
}
