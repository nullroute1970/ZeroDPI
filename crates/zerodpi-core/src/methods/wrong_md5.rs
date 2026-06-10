//! `wrong_md5` bypass: replace the first outbound bare ACK's payload with a
//! fake TLS ClientHello and attach a TCP-MD5 Signature option.
//!
//! DPI middleboxes can inspect the spoofed ClientHello and classify the flow
//! as benign. The real upstream server should reject the segment because TCP
//! MD5 was not negotiated for the connection, so it never consumes the fake
//! payload.

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub const TCP_MD5_SIGNATURE_OPTION_KIND: u8 = 19;
pub const TCP_MD5_SIGNATURE_OPTION_LEN: u8 = 18;
pub const TCP_MD5_SIGNATURE_LEN: usize = 16;

pub fn tcp_md5_signature_option() -> Vec<u8> {
    let mut option = Vec::with_capacity(TCP_MD5_SIGNATURE_OPTION_LEN as usize);
    option.push(TCP_MD5_SIGNATURE_OPTION_KIND);
    option.push(TCP_MD5_SIGNATURE_OPTION_LEN);
    option.extend_from_slice(&[0; TCP_MD5_SIGNATURE_LEN]);
    option
}

pub struct WrongMd5 {
    /// Whether to set the PSH flag on the spoofed packet.
    set_psh: bool,
    /// Whether to bump the IPv4 Identification field on the spoofed packet.
    bump_ip_ident: bool,
    /// Whether to signal bypass completion immediately after emitting the
    /// TCP-MD5-tagged fake packet.
    complete_immediately: bool,
}

impl WrongMd5 {
    pub fn new(cfg: &Config) -> Self {
        Self {
            set_psh: cfg.WRONG_MD5_SET_PSH,
            bump_ip_ident: cfg.WRONG_MD5_BUMP_IP_IDENT,
            complete_immediately: cfg.WRONG_MD5_COMPLETE_IMMEDIATELY,
        }
    }
}

impl BypassMethod for WrongMd5 {
    fn name(&self) -> &'static str {
        "wrong_md5"
    }

    fn on_handshake_complete_ack(
        &self,
        flow: &FlowState,
        pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        let payload = flow.fake_data.clone();
        let payload_len = payload.len();
        let md5_option = tcp_md5_signature_option();

        let mut flags = pkt.flags;
        flags.psh = self.set_psh;

        pkt.new_flags = Some(flags);
        pkt.new_payload = Some(payload);
        pkt.append_tcp_options = md5_option;
        pkt.bump_ipv4_ident = self.bump_ip_ident;

        trace!(
            target = "zerodpi::wrong_md5",
            seq = pkt.seq,
            ack = pkt.ack,
            payload_len,
            set_psh = self.set_psh,
            bump_ip_ident = self.bump_ip_ident,
            complete_immediately = self.complete_immediately,
            "staged fake ClientHello with TCP-MD5 signature option"
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
               BYPASS_METHOD = "wrong_md5""#,
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
    fn tcp_md5_option_has_expected_wire_shape() {
        let option = tcp_md5_signature_option();
        assert_eq!(option.len(), TCP_MD5_SIGNATURE_OPTION_LEN as usize);
        assert_eq!(option[0], TCP_MD5_SIGNATURE_OPTION_KIND);
        assert_eq!(option[1], TCP_MD5_SIGNATURE_OPTION_LEN);
        assert_eq!(&option[2..], &[0; TCP_MD5_SIGNATURE_LEN]);
    }

    #[test]
    fn stages_payload_preserves_seq_and_adds_tcp_md5_option() {
        let mut state = FlowState::new(vec![0xAB; 517]);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);

        let mut pkt = ack_pkt(1000, 2000);
        let action = WrongMd5::new(&default_cfg()).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(pkt.seq, 1001);
        assert_eq!(pkt.ack, 2001);
        assert_eq!(pkt.new_seq, None);
        assert_eq!(pkt.new_ack, None);
        assert_eq!(pkt.new_payload.as_ref().unwrap().len(), 517);
        assert!(pkt.new_flags.unwrap().psh);
        assert!(pkt.bump_ipv4_ident);
        assert_eq!(pkt.corrupt_tcp_checksum_delta, None);
        assert_eq!(pkt.append_tcp_options, tcp_md5_signature_option());
    }

    #[test]
    fn honors_disabled_toggles_and_completion_wait() {
        let mut cfg = default_cfg();
        cfg.WRONG_MD5_SET_PSH = false;
        cfg.WRONG_MD5_BUMP_IP_IDENT = false;
        cfg.WRONG_MD5_COMPLETE_IMMEDIATELY = false;

        let state = FlowState::new(vec![0xCD; 10]);
        let mut pkt = ack_pkt(10, 20);
        let action = WrongMd5::new(&cfg).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert!(!pkt.new_flags.unwrap().psh);
        assert!(!pkt.bump_ipv4_ident);
        assert_eq!(pkt.append_tcp_options, tcp_md5_signature_option());
    }
}
