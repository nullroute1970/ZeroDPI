//! Combined `wrong_seq` + TCP-level TLS Fragment bypass.
//!
//! This method targets layered DPI paths.  The first stage injects a fake
//! ClientHello with an old TCP sequence number so the first DPI layer can be
//! desynchronized.  The second stage lets the proxy write the intact real
//! ClientHello as small TCP segments so downstream DPI layers that never saw
//! the fake packet still have to reassemble the real TCP stream.

use tracing::trace;

use super::wrong_seq::WrongSeq;
use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub struct WrongSeqTlsFrag {
    wrong_seq: WrongSeq,
}

impl WrongSeqTlsFrag {
    pub fn new(cfg: &Config) -> Self {
        Self {
            wrong_seq: WrongSeq::new(cfg),
        }
    }
}

impl BypassMethod for WrongSeqTlsFrag {
    fn name(&self) -> &'static str {
        "wrong_seq_tls_frag"
    }

    fn on_handshake_complete_ack(
        &self,
        flow: &FlowState,
        pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        let _ = self.wrong_seq.on_handshake_complete_ack(flow, pkt);
        trace!(
            target = "zerodpi::wrong_seq_tls_frag",
            "staged wrong_seq fake; waiting for TCP-segmented first data packet"
        );
        MethodAction::emit_and_wait_for_data()
    }

    fn on_first_data_packet(&self, _flow: &FlowState, _pkt: &mut PacketView<'_>) -> MethodAction {
        trace!(
            target = "zerodpi::wrong_seq_tls_frag",
            "first TCP-segmented ClientHello data observed; completing bypass"
        );
        MethodAction::complete_and_accept()
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
               BYPASS_METHOD = "wrong_seq_tls_frag""#,
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
        let action =
            WrongSeqTlsFrag::new(&default_cfg()).on_handshake_complete_ack(&state, &mut packet);

        assert_eq!(action, MethodAction::emit_and_wait_for_data());
        assert_eq!(packet.new_payload.as_ref().unwrap().len(), 517);
        assert_eq!(packet.new_seq, Some(1001u32.wrapping_sub(517)));
        assert!(packet.new_flags.unwrap().psh);
        assert!(packet.bump_ipv4_ident);
    }

    #[test]
    fn first_data_stage_completes_without_rewrite() {
        let state = FlowState::new(vec![]);
        let payload: &'static [u8] = &[0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03];
        let mut packet = pkt(payload, payload.len());

        let action = WrongSeqTlsFrag::new(&default_cfg()).on_first_data_packet(&state, &mut packet);

        assert_eq!(action, MethodAction::complete_and_accept());
        assert!(packet.new_payload.is_none());
        assert!(packet.new_flags.is_none());
        assert!(!packet.bump_ipv4_ident);
    }
}
