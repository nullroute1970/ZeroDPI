//! `ip_frag` bypass: IPv4-layer fragmentation of the outbound data stream.
//!
//! ## How it works
//!
//! The outbound data packet carrying the ClientHello (and, with
//! `IP_FRAG_ONLY_FIRST_PACKET = false`, every subsequent outbound data
//! packet) is split at the IP layer into fragments of at most
//! `IP_FRAG_SIZE` payload bytes. The destination kernel reassembles the
//! fragments before the TLS stack sees the stream, so the handshake is
//! unaffected. Many inline DPIs do not reassemble IP fragments at all (or
//! give up after a short budget), so they never observe a complete
//! ClientHello and cannot extract the SNI.
//!
//! The method itself only stages [`PacketView::ip_frag_payload_size`]; the
//! platform backend splits the rebuilt packet and emits the fragments. The
//! real ClientHello bytes are untouched — the SNI is preserved.
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `IP_FRAG_SIZE` | `usize` | `24` | Max IP payload bytes per fragment (multiple of 8). |
//! | `IP_FRAG_ONLY_FIRST_PACKET` | `bool` | `true` | Fragment only the first data packet. |

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub struct IpFrag {
    /// Maximum IP payload bytes (TCP header + TCP payload) per fragment.
    frag_size: usize,
    /// `false` = fragment-all mode: keep rewriting every outbound data
    /// packet until the connection closes.
    only_first_packet: bool,
}

impl IpFrag {
    pub fn new(cfg: &Config) -> Self {
        Self {
            frag_size: cfg.IP_FRAG_SIZE,
            only_first_packet: cfg.IP_FRAG_ONLY_FIRST_PACKET,
        }
    }
}

impl BypassMethod for IpFrag {
    fn name(&self) -> String {
        "ip_frag".into()
    }

    /// Returns `PassThrough` — this method operates on the data stage, not
    /// the handshake-complete ACK. The handler sets `waiting_for_data` and
    /// calls [`on_first_data_packet`] instead.
    ///
    /// [`on_first_data_packet`]: IpFrag::on_first_data_packet
    fn on_handshake_complete_ack(
        &self,
        _flow: &FlowState,
        _pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        MethodAction::PassThrough
    }

    fn on_first_data_packet(&self, _flow: &FlowState, pkt: &mut PacketView<'_>) -> MethodAction {
        // 20-byte fixed TCP header plus any options present on the packet.
        let tcp_hdr_len = 20 + pkt.tcp_options.len();
        if tcp_hdr_len + pkt.payload_len > self.frag_size {
            pkt.ip_frag_payload_size = Some(self.frag_size);
            trace!(
                target = "zerodpi::ip_frag",
                frag_size = self.frag_size,
                payload_len = pkt.payload_len,
                tcp_hdr_len,
                only_first_packet = self.only_first_packet,
                "staged IP-layer fragmentation"
            );
        } else {
            trace!(
                target = "zerodpi::ip_frag",
                frag_size = self.frag_size,
                payload_len = pkt.payload_len,
                tcp_hdr_len,
                "packet already fits a single fragment; not staging"
            );
        }

        if self.only_first_packet {
            MethodAction::emit_and_complete()
        } else {
            // Fragment-all mode: signal bypass completion at the first data
            // packet but keep the flow monitored so the handler re-invokes
            // this hook for every subsequent outbound data packet.
            MethodAction::EmitFakeAndAccept {
                complete_immediately: false,
                continue_with_data: true,
            }
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
               LISTEN_PORT = 44444"#,
        )
        .unwrap()
    }

    fn data_pkt_with_options(
        payload: &'static [u8],
        tcp_options: &'static [u8],
    ) -> PacketView<'static> {
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
            tcp_options,
            new_seq: None,
            new_ack: None,
            new_flags: None,
            new_payload: None,
            replace_tcp_options: None,
            append_tcp_options: Vec::new(),
            bump_ipv4_ident: false,
            corrupt_tcp_checksum_delta: None,
            emit_original_after: false,
            ip_frag_payload_size: None,
            disorder_spec: None,
            new_ipv4_ttl: None,
            new_urgent_pointer: None,
        }
    }

    fn data_pkt(payload: &'static [u8]) -> PacketView<'static> {
        data_pkt_with_options(payload, &[])
    }

    #[test]
    fn handshake_ack_hook_is_passthrough() {
        let method = IpFrag::new(&default_cfg());
        let state = FlowState::new(vec![], None);
        let mut pkt = data_pkt(&[]);
        let action = method.on_handshake_complete_ack(&state, &mut pkt);
        assert_eq!(action, MethodAction::PassThrough);
        assert_eq!(pkt.ip_frag_payload_size, None);
    }

    #[test]
    fn stages_frag_size_and_completes() {
        let state = FlowState::new(vec![], None);
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        let action = IpFrag::new(&default_cfg()).on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(pkt.ip_frag_payload_size, Some(24));
        assert!(pkt.new_payload.is_none()); // real ClientHello bytes untouched
    }

    #[test]
    fn small_packet_is_not_staged_but_completes() {
        let state = FlowState::new(vec![], None);
        let mut pkt = data_pkt(&[0x16, 0x03, 0x03]); // 20 + 3 = 23 <= 24

        let action = IpFrag::new(&default_cfg()).on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(pkt.ip_frag_payload_size, None);
    }

    #[test]
    fn tcp_options_count_toward_frag_threshold() {
        let state = FlowState::new(vec![], None);
        // 4 bytes of TCP options -> TCP header is 24 bytes. With a 20-byte
        // payload the IP payload is 44 bytes: > 40 (staged), <= 48 (not).
        let payload: &'static [u8] = Box::leak(vec![0u8; 20].into_boxed_slice());
        let options: &'static [u8] = &[0x01, 0x01, 0x08, 0x0A];

        let mut cfg = default_cfg();
        cfg.IP_FRAG_SIZE = 40;
        let mut pkt = data_pkt_with_options(payload, options);
        IpFrag::new(&cfg).on_first_data_packet(&state, &mut pkt);
        assert_eq!(pkt.ip_frag_payload_size, Some(40));

        cfg.IP_FRAG_SIZE = 48;
        let mut pkt = data_pkt_with_options(payload, options);
        IpFrag::new(&cfg).on_first_data_packet(&state, &mut pkt);
        assert_eq!(pkt.ip_frag_payload_size, None);
    }

    #[test]
    fn custom_frag_size_is_staged() {
        let mut cfg = default_cfg();
        cfg.IP_FRAG_SIZE = 40;
        let state = FlowState::new(vec![], None);
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        IpFrag::new(&cfg).on_first_data_packet(&state, &mut pkt);

        assert_eq!(pkt.ip_frag_payload_size, Some(40));
    }

    #[test]
    fn fragment_all_mode_returns_continue_with_data() {
        let mut cfg = default_cfg();
        cfg.IP_FRAG_ONLY_FIRST_PACKET = false;
        let state = FlowState::new(vec![], None);
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        let action = IpFrag::new(&cfg).on_first_data_packet(&state, &mut pkt);

        assert_eq!(
            action,
            MethodAction::EmitFakeAndAccept {
                complete_immediately: false,
                continue_with_data: true,
            }
        );
        assert_eq!(pkt.ip_frag_payload_size, Some(24));
    }

    #[test]
    fn fragment_all_mode_small_packet_still_enters_fragment_all() {
        let mut cfg = default_cfg();
        cfg.IP_FRAG_ONLY_FIRST_PACKET = false;
        let state = FlowState::new(vec![], None);
        let mut pkt = data_pkt(&[0x16, 0x03, 0x03]);

        let action = IpFrag::new(&cfg).on_first_data_packet(&state, &mut pkt);

        // Nothing to split, but the flow still enters fragment-all mode so
        // later, larger packets are fragmented.
        assert_eq!(
            action,
            MethodAction::EmitFakeAndAccept {
                complete_immediately: false,
                continue_with_data: true,
            }
        );
        assert_eq!(pkt.ip_frag_payload_size, None);
    }
}
