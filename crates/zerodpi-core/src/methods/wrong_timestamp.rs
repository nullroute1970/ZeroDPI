//! `wrong_timestamp` bypass: replace the first outbound bare ACK's payload
//! with a fake TLS ClientHello while carrying a backdated TCP Timestamp option.
//!
//! DPI middleboxes can inspect the spoofed ClientHello and classify the flow
//! as benign. The real upstream server should reject the segment through PAWS
//! because the TCP Timestamp `TSval` is older than the timestamp already seen
//! on the flow, so it never consumes the fake payload.

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub const TCP_TIMESTAMP_OPTION_KIND: u8 = 8;
pub const TCP_TIMESTAMP_OPTION_LEN: u8 = 10;
const TCP_OPTION_EOL: u8 = 0;
const TCP_OPTION_NOP: u8 = 1;
const TCP_TIMESTAMP_TSVAL_OFFSET: usize = 2;
const TCP_TIMESTAMP_TSECR_OFFSET: usize = 6;

pub fn backdate_tcp_timestamp(options: &[u8], offset: u32) -> Option<Vec<u8>> {
    let mut out = options.to_vec();
    let mut cursor = 0usize;

    while cursor < options.len() {
        match options[cursor] {
            TCP_OPTION_EOL => return None,
            TCP_OPTION_NOP => cursor += 1,
            kind => {
                let len_pos = cursor.checked_add(1)?;
                let opt_len = *options.get(len_pos)? as usize;
                if opt_len < 2 {
                    return None;
                }
                let end = cursor.checked_add(opt_len)?;
                if end > options.len() {
                    return None;
                }

                if kind == TCP_TIMESTAMP_OPTION_KIND {
                    if opt_len != TCP_TIMESTAMP_OPTION_LEN as usize {
                        return None;
                    }
                    let tsval_pos = cursor + TCP_TIMESTAMP_TSVAL_OFFSET;
                    let tsecr_pos = cursor + TCP_TIMESTAMP_TSECR_OFFSET;
                    let tsval = u32::from_be_bytes([
                        options[tsval_pos],
                        options[tsval_pos + 1],
                        options[tsval_pos + 2],
                        options[tsval_pos + 3],
                    ]);
                    let tsecr = u32::from_be_bytes([
                        options[tsecr_pos],
                        options[tsecr_pos + 1],
                        options[tsecr_pos + 2],
                        options[tsecr_pos + 3],
                    ]);
                    let new_tsval = tsval.wrapping_sub(offset);
                    out[tsval_pos..tsval_pos + 4].copy_from_slice(&new_tsval.to_be_bytes());
                    trace!(
                        target = "zerodpi::wrong_timestamp",
                        tsval,
                        new_tsval,
                        tsecr,
                        offset,
                        "backdated TCP timestamp option"
                    );
                    return Some(out);
                }

                cursor = end;
            }
        }
    }

    None
}

pub struct WrongTimestamp {
    /// Value subtracted from the captured TCP Timestamp TSval.
    offset: u32,
    /// Whether to set the PSH flag on the spoofed packet.
    set_psh: bool,
    /// Whether to bump the IPv4 Identification field on the spoofed packet.
    bump_ip_ident: bool,
    /// Whether to signal bypass completion immediately after emitting the
    /// backdated-timestamp fake packet.
    complete_immediately: bool,
}

impl WrongTimestamp {
    pub fn new(cfg: &Config) -> Self {
        Self {
            offset: cfg.WRONG_TIMESTAMP_OFFSET,
            set_psh: cfg.WRONG_TIMESTAMP_SET_PSH,
            bump_ip_ident: cfg.WRONG_TIMESTAMP_BUMP_IP_IDENT,
            complete_immediately: cfg.WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY,
        }
    }
}

impl BypassMethod for WrongTimestamp {
    fn name(&self) -> &'static str {
        "wrong_timestamp"
    }

    fn on_handshake_complete_ack(
        &self,
        flow: &FlowState,
        pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        let Some(options) = backdate_tcp_timestamp(pkt.tcp_options, self.offset) else {
            trace!(
                target = "zerodpi::wrong_timestamp",
                options_len = pkt.tcp_options.len(),
                "captured ACK has no usable TCP timestamp option; aborting bypass"
            );
            return MethodAction::abort_and_accept();
        };

        let payload = flow.fake_data.clone();
        let payload_len = payload.len();

        let mut flags = pkt.flags;
        flags.psh = self.set_psh;

        pkt.new_flags = Some(flags);
        pkt.new_payload = Some(payload);
        pkt.replace_tcp_options = Some(options);
        pkt.bump_ipv4_ident = self.bump_ip_ident;

        trace!(
            target = "zerodpi::wrong_timestamp",
            seq = pkt.seq,
            ack = pkt.ack,
            payload_len,
            offset = self.offset,
            set_psh = self.set_psh,
            bump_ip_ident = self.bump_ip_ident,
            complete_immediately = self.complete_immediately,
            "staged fake ClientHello with backdated TCP timestamp"
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
               BYPASS_METHOD = "wrong_timestamp""#,
        )
        .unwrap()
    }

    fn timestamp_option(tsval: u32, tsecr: u32) -> Vec<u8> {
        let mut option = vec![TCP_TIMESTAMP_OPTION_KIND, TCP_TIMESTAMP_OPTION_LEN];
        option.extend_from_slice(&tsval.to_be_bytes());
        option.extend_from_slice(&tsecr.to_be_bytes());
        option
    }

    fn ack_pkt<'a>(syn_seq: u32, syn_ack_seq: u32, tcp_options: &'a [u8]) -> PacketView<'a> {
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
            tcp_options,
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
    fn backdates_timestamp_tsval_and_preserves_tsecr() {
        let options = timestamp_option(100, 77);
        let rewritten = backdate_tcp_timestamp(&options, 3).unwrap();

        assert_eq!(
            rewritten,
            timestamp_option(97, 77),
            "only TSval should be backdated"
        );
    }

    #[test]
    fn preserves_surrounding_options_and_padding() {
        let mut options = vec![TCP_OPTION_NOP, TCP_OPTION_NOP];
        options.extend_from_slice(&timestamp_option(10, 20));
        options.extend_from_slice(&[TCP_OPTION_EOL, 0]);

        let rewritten = backdate_tcp_timestamp(&options, 4).unwrap();
        let mut expected = vec![TCP_OPTION_NOP, TCP_OPTION_NOP];
        expected.extend_from_slice(&timestamp_option(6, 20));
        expected.extend_from_slice(&[TCP_OPTION_EOL, 0]);

        assert_eq!(rewritten, expected);
    }

    #[test]
    fn wraps_timestamp_subtraction() {
        let options = timestamp_option(2, 77);
        let rewritten = backdate_tcp_timestamp(&options, 7).unwrap();

        assert_eq!(rewritten, timestamp_option(2u32.wrapping_sub(7), 77));
    }

    #[test]
    fn returns_none_without_timestamp_option() {
        let options = [TCP_OPTION_NOP, TCP_OPTION_EOL, 0, 0];
        assert_eq!(backdate_tcp_timestamp(&options, 1), None);
    }

    #[test]
    fn returns_none_for_malformed_timestamp_option() {
        let options = [TCP_TIMESTAMP_OPTION_KIND, 9, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(backdate_tcp_timestamp(&options, 1), None);
    }

    #[test]
    fn stages_payload_and_replaces_timestamp_options() {
        let options = timestamp_option(100, 77);
        let mut state = FlowState::new(vec![0xAB; 517]);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);

        let mut pkt = ack_pkt(1000, 2000, &options);
        let action =
            WrongTimestamp::new(&default_cfg()).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(pkt.seq, 1001);
        assert_eq!(pkt.ack, 2001);
        assert_eq!(pkt.new_seq, None);
        assert_eq!(pkt.new_ack, None);
        assert_eq!(pkt.new_payload.as_ref().unwrap().len(), 517);
        assert_eq!(pkt.replace_tcp_options, Some(timestamp_option(99, 77)));
        assert!(pkt.append_tcp_options.is_empty());
        assert!(pkt.new_flags.unwrap().psh);
        assert!(pkt.bump_ipv4_ident);
        assert_eq!(pkt.corrupt_tcp_checksum_delta, None);
    }

    #[test]
    fn honors_disabled_toggles_and_completion_wait() {
        let mut cfg = default_cfg();
        cfg.WRONG_TIMESTAMP_OFFSET = 7;
        cfg.WRONG_TIMESTAMP_SET_PSH = false;
        cfg.WRONG_TIMESTAMP_BUMP_IP_IDENT = false;
        cfg.WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY = false;
        let options = timestamp_option(100, 77);

        let state = FlowState::new(vec![0xCD; 10]);
        let mut pkt = ack_pkt(10, 20, &options);
        let action = WrongTimestamp::new(&cfg).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert_eq!(pkt.replace_tcp_options, Some(timestamp_option(93, 77)));
        assert!(!pkt.new_flags.unwrap().psh);
        assert!(!pkt.bump_ipv4_ident);
    }

    #[test]
    fn aborts_when_no_timestamp_option_exists() {
        let state = FlowState::new(vec![0xCD; 10]);
        let mut pkt = ack_pkt(10, 20, &[]);
        let action =
            WrongTimestamp::new(&default_cfg()).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::abort_and_accept());
        assert!(pkt.new_payload.is_none());
        assert!(pkt.replace_tcp_options.is_none());
    }
}
