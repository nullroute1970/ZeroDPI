//! Combined `wrong_seq` + `wrong_md5` bypass.
//!
//! This method injects one fake ClientHello on the first outbound handshake
//! ACK with both desynchronization tricks applied: an old TCP sequence number
//! and a TCP-MD5 Signature option. DPI devices can inspect the fake SNI, while
//! the upstream server should reject the segment because it is out of window
//! and carries an unnegotiated TCP-MD5 option.

use tracing::trace;

use super::wrong_md5::tcp_md5_signature_option;
use super::wrong_seq::WrongSeq;
use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub struct WrongSeqWrongMd5 {
    wrong_seq: WrongSeq,
    complete_immediately: bool,
}

impl WrongSeqWrongMd5 {
    pub fn new(cfg: &Config) -> Self {
        Self {
            wrong_seq: WrongSeq::new(cfg),
            complete_immediately: cfg.WRONG_MD5_COMPLETE_IMMEDIATELY,
        }
    }
}

impl BypassMethod for WrongSeqWrongMd5 {
    fn name(&self) -> &'static str {
        "wrong_seq_wrong_md5"
    }

    fn on_handshake_complete_ack(
        &self,
        flow: &FlowState,
        pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        let _ = self.wrong_seq.on_handshake_complete_ack(flow, pkt);
        pkt.append_tcp_options = tcp_md5_signature_option();

        trace!(
            target = "zerodpi::wrong_seq_wrong_md5",
            complete_immediately = self.complete_immediately,
            "staged wrong-sequence fake ClientHello with TCP-MD5 signature option"
        );

        if self.complete_immediately {
            MethodAction::emit_and_complete()
        } else {
            MethodAction::emit_and_wait_for_ack()
        }
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
               BYPASS_METHOD = "wrong_seq_wrong_md5""#,
        )
        .unwrap()
    }

    fn ack_pkt(syn_seq: u32, syn_ack_seq: u32) -> PacketView<'static> {
        PacketView {
            direction: Direction::Outbound,
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            src_port: 12345,
            dst_port: 443,
            seq: syn_seq.wrapping_add(1),
            ack: syn_ack_seq.wrapping_add(1),
            flags: TcpFlags {
                ack: true,
                ..Default::default()
            },
            payload_len: 0,
            payload: &[],
            tcp_options: &[],
            new_seq: None,
            new_ack: None,
            new_flags: None,
            new_payload: None,
            replace_tcp_options: None,
            append_tcp_options: Vec::new(),
            bump_ipv4_ident: false,
            corrupt_tcp_checksum_delta: None,
        }
    }

    #[test]
    fn stages_wrong_seq_payload_and_tcp_md5_option() {
        let mut state = FlowState::new(vec![0xAB; 517]);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);

        let mut pkt = ack_pkt(1000, 2000);
        let action =
            WrongSeqWrongMd5::new(&default_cfg()).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(pkt.new_payload.as_ref().unwrap().len(), 517);
        assert_eq!(pkt.new_seq, Some(1001u32.wrapping_sub(517)));
        assert_eq!(pkt.new_ack, None);
        assert!(pkt.new_flags.unwrap().psh);
        assert!(pkt.bump_ipv4_ident);
        assert_eq!(pkt.append_tcp_options, tcp_md5_signature_option());
        assert_eq!(pkt.corrupt_tcp_checksum_delta, None);
    }

    #[test]
    fn honors_wrong_seq_fields_and_md5_completion_wait() {
        let mut cfg = default_cfg();
        cfg.WRONG_SEQ_EXTRA_OFFSET = 100;
        cfg.WRONG_SEQ_SET_PSH = false;
        cfg.WRONG_SEQ_BUMP_IP_IDENT = false;
        cfg.WRONG_MD5_COMPLETE_IMMEDIATELY = false;

        let mut state = FlowState::new(vec![0xCD; 10]);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);

        let mut pkt = ack_pkt(1000, 2000);
        let action = WrongSeqWrongMd5::new(&cfg).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert_eq!(
            pkt.new_seq,
            Some(1001u32.wrapping_sub(10).wrapping_sub(100))
        );
        assert!(!pkt.new_flags.unwrap().psh);
        assert!(!pkt.bump_ipv4_ident);
        assert_eq!(pkt.append_tcp_options, tcp_md5_signature_option());
    }
}
