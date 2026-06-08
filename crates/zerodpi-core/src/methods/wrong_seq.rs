//! `wrong_seq` bypass: replace the first outbound bare ACK's payload with a
//! fake TLS ClientHello whose TCP sequence number is deliberately set to
//! `syn_seq + 1 - len(payload) - extra_offset` — i.e. behind the server's
//! receive window.
//!
//! The DPI middlebox inspects the spoofed ClientHello (with a permitted SNI)
//! and classifies the flow as benign. The upstream TLS server, on the other
//! hand, sees the segment as old/duplicate and discards its payload but
//! still acknowledges the (correct) `ack_num`, so the handshake completes.

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub struct WrongSeq {
    /// Extra bytes subtracted from the injected seq number on top of
    /// `payload_len`.  0 reproduces the original behaviour.
    extra_offset: u32,
    /// Whether to set the PSH flag on the spoofed packet.
    set_psh: bool,
    /// Whether to bump the IPv4 Identification field on the spoofed packet.
    bump_ip_ident: bool,
}

impl WrongSeq {
    pub fn new(cfg: &Config) -> Self {
        Self {
            extra_offset: cfg.WRONG_SEQ_EXTRA_OFFSET,
            set_psh: cfg.WRONG_SEQ_SET_PSH,
            bump_ip_ident: cfg.WRONG_SEQ_BUMP_IP_IDENT,
        }
    }
}

impl BypassMethod for WrongSeq {
    fn name(&self) -> &'static str {
        "wrong_seq"
    }

    fn on_handshake_complete_ack(
        &self,
        flow: &FlowState,
        pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        let syn_seq = flow
            .syn_seq
            .expect("syn_seq must be set before handshake-complete ACK");
        let payload = flow.fake_data.clone();
        let payload_len = payload.len() as u32;
        // Positions the segment behind the server's rcv_nxt by at least
        // `payload_len` bytes, plus any configured extra offset.
        let new_seq = syn_seq
            .wrapping_add(1)
            .wrapping_sub(payload_len)
            .wrapping_sub(self.extra_offset);

        let mut flags = pkt.flags;
        flags.psh = self.set_psh;

        pkt.new_seq = Some(new_seq);
        pkt.new_flags = Some(flags);
        pkt.new_payload = Some(payload);
        pkt.bump_ipv4_ident = self.bump_ip_ident;

        trace!(
            target = "zerodpi::wrong_seq",
            syn_seq,
            new_seq,
            payload_len,
            extra_offset = self.extra_offset,
            set_psh = self.set_psh,
            bump_ip_ident = self.bump_ip_ident,
            "staged fake ClientHello injection"
        );

        MethodAction::emit_and_wait_for_ack()
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
               LISTEN_PORT = 44444"#,
        )
        .unwrap()
    }

    fn ack_pkt(syn_seq: u32) -> PacketView<'static> {
        PacketView {
            direction: Direction::Outbound,
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            src_port: 12345,
            dst_port: 443,
            seq: syn_seq.wrapping_add(1),
            ack: 99,
            flags: TcpFlags {
                ack: true,
                ..Default::default()
            },
            payload_len: 0,
            payload: &[],
            new_seq: None,
            new_ack: None,
            new_flags: None,
            new_payload: None,
            bump_ipv4_ident: false,
            corrupt_tcp_checksum_delta: None,
        }
    }

    #[test]
    fn stages_payload_and_wrong_seq() {
        let mut state = FlowState::new(vec![0xAB; 517]);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);

        let mut pkt = ack_pkt(1000);
        let action = WrongSeq::new(&default_cfg()).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert_eq!(pkt.new_payload.as_ref().unwrap().len(), 517);
        // 1000 + 1 - 517 - 0 = 484
        assert_eq!(pkt.new_seq, Some(484));
        assert!(pkt.new_flags.unwrap().psh);
        assert!(pkt.bump_ipv4_ident);
    }

    #[test]
    fn handles_seq_wraparound() {
        let mut state = FlowState::new(vec![0; 517]);
        state.syn_seq = Some(10); // small ISN forces wrap
        let mut pkt = ack_pkt(10);
        WrongSeq::new(&default_cfg()).on_handshake_complete_ack(&state, &mut pkt);
        // 10 + 1 - 517 - 0 wraps mod 2^32
        assert_eq!(pkt.new_seq, Some(11u32.wrapping_sub(517)));
    }

    #[test]
    fn extra_offset_shifts_seq_further_back() {
        let mut cfg = default_cfg();
        cfg.WRONG_SEQ_EXTRA_OFFSET = 100;
        let mut state = FlowState::new(vec![0xAB; 517]);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);

        let mut pkt = ack_pkt(1000);
        WrongSeq::new(&cfg).on_handshake_complete_ack(&state, &mut pkt);
        // 1000 + 1 - 517 - 100 = 384
        assert_eq!(pkt.new_seq, Some(384));
    }

    #[test]
    fn set_psh_false_clears_psh_flag() {
        let mut cfg = default_cfg();
        cfg.WRONG_SEQ_SET_PSH = false;
        let mut state = FlowState::new(vec![0; 517]);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);

        let mut pkt = ack_pkt(1000);
        WrongSeq::new(&cfg).on_handshake_complete_ack(&state, &mut pkt);
        assert!(!pkt.new_flags.unwrap().psh);
    }

    #[test]
    fn bump_ip_ident_false() {
        let mut cfg = default_cfg();
        cfg.WRONG_SEQ_BUMP_IP_IDENT = false;
        let mut state = FlowState::new(vec![0; 517]);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);

        let mut pkt = ack_pkt(1000);
        WrongSeq::new(&cfg).on_handshake_complete_ack(&state, &mut pkt);
        assert!(!pkt.bump_ipv4_ident);
    }
}
