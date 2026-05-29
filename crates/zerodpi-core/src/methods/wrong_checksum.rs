//! `wrong_checksum` bypass: replace the first outbound bare ACK's payload with
//! a fake TLS ClientHello that keeps the valid TCP sequence/acknowledgment
//! numbers, then deliberately corrupts the TCP checksum.
//!
//! The DPI middlebox can inspect the spoofed ClientHello and classify the flow
//! as benign. The real upstream server should drop the segment before TCP
//! sequence processing because the checksum is invalid, so it never consumes
//! the fake payload.

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub struct WrongChecksum {
    /// Non-zero value added to the valid TCP checksum after recomputation.
    checksum_delta: u16,
    /// Whether to set the PSH flag on the spoofed packet.
    set_psh: bool,
    /// Whether to bump the IPv4 Identification field on the spoofed packet.
    bump_ip_ident: bool,
    /// Whether to signal bypass completion immediately after emitting the
    /// invalid-checksum packet.
    complete_immediately: bool,
}

impl WrongChecksum {
    pub fn new(cfg: &Config) -> Self {
        Self {
            checksum_delta: cfg.WRONG_CHECKSUM_DELTA,
            set_psh: cfg.WRONG_CHECKSUM_SET_PSH,
            bump_ip_ident: cfg.WRONG_CHECKSUM_BUMP_IP_IDENT,
            complete_immediately: cfg.WRONG_CHECKSUM_COMPLETE_IMMEDIATELY,
        }
    }
}

impl BypassMethod for WrongChecksum {
    fn name(&self) -> &'static str {
        "wrong_checksum"
    }

    fn on_handshake_complete_ack(
        &self,
        flow: &FlowState,
        pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        let payload = flow.fake_data.clone();
        let payload_len = payload.len();

        let mut flags = pkt.flags;
        flags.psh = self.set_psh;

        // Keep the kernel ACK's valid seq/ack numbers. The server drops the
        // payload because of the deliberately corrupted TCP checksum.
        pkt.new_flags = Some(flags);
        pkt.new_payload = Some(payload);
        pkt.bump_ipv4_ident = self.bump_ip_ident;
        pkt.corrupt_tcp_checksum_delta = Some(self.checksum_delta);

        trace!(
            target = "zerodpi::wrong_checksum",
            seq = pkt.seq,
            ack = pkt.ack,
            payload_len,
            checksum_delta = self.checksum_delta,
            set_psh = self.set_psh,
            bump_ip_ident = self.bump_ip_ident,
            complete_immediately = self.complete_immediately,
            "staged fake ClientHello with corrupted TCP checksum"
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
               BYPASS_METHOD = "wrong_checksum""#,
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
            new_seq: None,
            new_flags: None,
            new_payload: None,
            bump_ipv4_ident: false,
            corrupt_tcp_checksum_delta: None,
        }
    }

    #[test]
    fn stages_payload_preserves_seq_and_corrupts_checksum() {
        let mut state = FlowState::new(vec![0xAB; 517]);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);

        let mut pkt = ack_pkt(1000, 2000);
        let action = WrongChecksum::new(&default_cfg()).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(pkt.seq, 1001);
        assert_eq!(pkt.ack, 2001);
        assert_eq!(pkt.new_seq, None);
        assert_eq!(pkt.new_payload.as_ref().unwrap().len(), 517);
        assert!(pkt.new_flags.unwrap().psh);
        assert!(pkt.bump_ipv4_ident);
        assert_eq!(pkt.corrupt_tcp_checksum_delta, Some(1));
    }

    #[test]
    fn honors_disabled_toggles_and_completion_wait() {
        let mut cfg = default_cfg();
        cfg.WRONG_CHECKSUM_DELTA = 7;
        cfg.WRONG_CHECKSUM_SET_PSH = false;
        cfg.WRONG_CHECKSUM_BUMP_IP_IDENT = false;
        cfg.WRONG_CHECKSUM_COMPLETE_IMMEDIATELY = false;

        let state = FlowState::new(vec![0xCD; 10]);
        let mut pkt = ack_pkt(10, 20);
        let action = WrongChecksum::new(&cfg).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert!(!pkt.new_flags.unwrap().psh);
        assert!(!pkt.bump_ipv4_ident);
        assert_eq!(pkt.corrupt_tcp_checksum_delta, Some(7));
    }
}
