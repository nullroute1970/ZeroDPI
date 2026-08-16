//! `disorder` bypass: out-of-order TCP segmentation of the outbound data
//! stream.
//!
//! ## How it works
//!
//! The outbound data packet carrying the ClientHello (and, with
//! `DISORDER_ONLY_FIRST_PACKET = false`, every subsequent outbound data
//! packet) is split into `DISORDER_SEGMENTS` TCP segments of equal size,
//! each carrying the correct TCP sequence number, and emitted in reverse
//! order — optionally with `DISORDER_DELAY_MS` between them. The
//! destination kernel reassembles out-of-order segments before the TLS
//! stack sees the stream, so the handshake is unaffected; DPIs that track
//! per-flow sequence state see non-monotonic sequence numbers and never a
//! complete ClientHello in a single segment.
//!
//! The method itself only stages [`PacketView::disorder_spec`]; the
//! platform backend splits the rebuilt packet and emits the segments. The
//! real ClientHello bytes are untouched — the SNI is preserved.
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `DISORDER_SEGMENTS` | `usize` | `2` | Number of segments (2 or 3). |
//! | `DISORDER_DELAY_MS` | `u64` | `0` | Delay between segment emissions. |
//! | `DISORDER_REVERSE` | `bool` | `true` | Emit segments in reverse order. |
//! | `DISORDER_ONLY_FIRST_PACKET` | `bool` | `true` | Re-chunk only the first data packet. |

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::{DisorderSpec, PacketView};

pub struct Disorder {
    /// Number of segments to split each data packet into (2 or 3).
    segments: usize,
    /// Emit segments in reverse (non-monotonic sequence) order.
    reverse: bool,
    /// Delay in milliseconds between consecutive segment emissions.
    delay_ms: u64,
    /// `false` = fragment-all mode: keep re-chunking every outbound data
    /// packet until the connection closes.
    only_first_packet: bool,
}

impl Disorder {
    pub fn new(cfg: &Config) -> Self {
        Self {
            segments: cfg.DISORDER_SEGMENTS,
            reverse: cfg.DISORDER_REVERSE,
            delay_ms: cfg.DISORDER_DELAY_MS,
            only_first_packet: cfg.DISORDER_ONLY_FIRST_PACKET,
        }
    }
}

impl BypassMethod for Disorder {
    fn name(&self) -> String {
        "disorder".into()
    }

    /// Returns `PassThrough` — this method operates on the data stage, not
    /// the handshake-complete ACK. The handler sets `waiting_for_data` and
    /// calls [`on_first_data_packet`] instead.
    ///
    /// [`on_first_data_packet`]: Disorder::on_first_data_packet
    fn on_handshake_complete_ack(
        &self,
        _flow: &FlowState,
        _pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        MethodAction::PassThrough
    }

    fn on_first_data_packet(&self, _flow: &FlowState, pkt: &mut PacketView<'_>) -> MethodAction {
        if pkt.payload_len >= self.segments {
            pkt.disorder_spec = Some(DisorderSpec {
                segments: self.segments,
                reverse: self.reverse,
                delay_ms: self.delay_ms,
            });
            trace!(
                target = "zerodpi::disorder",
                segments = self.segments,
                reverse = self.reverse,
                delay_ms = self.delay_ms,
                payload_len = pkt.payload_len,
                only_first_packet = self.only_first_packet,
                "staged out-of-order TCP segmentation"
            );
        } else {
            trace!(
                target = "zerodpi::disorder",
                segments = self.segments,
                payload_len = pkt.payload_len,
                "payload too small to split; not staging"
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
            ip_frag_payload_size: None,
            disorder_spec: None,
            new_ipv4_ttl: None,
            new_urgent_pointer: None,
        }
    }

    #[test]
    fn handshake_ack_hook_is_passthrough() {
        let method = Disorder::new(&default_cfg());
        let state = FlowState::new(vec![], None);
        let mut pkt = data_pkt(&[]);
        let action = method.on_handshake_complete_ack(&state, &mut pkt);
        assert_eq!(action, MethodAction::PassThrough);
        assert_eq!(pkt.disorder_spec, None);
    }

    #[test]
    fn stages_disorder_spec_and_completes() {
        let state = FlowState::new(vec![], None);
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        let action = Disorder::new(&default_cfg()).on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(
            pkt.disorder_spec,
            Some(DisorderSpec {
                segments: 2,
                reverse: true,
                delay_ms: 0,
            })
        );
        assert!(pkt.new_payload.is_none()); // real ClientHello bytes untouched
    }

    #[test]
    fn small_packet_is_not_staged_but_completes() {
        let state = FlowState::new(vec![], None);
        let mut pkt = data_pkt(&[0x16]); // 1 byte < 2 segments

        let action = Disorder::new(&default_cfg()).on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(pkt.disorder_spec, None);
    }

    #[test]
    fn custom_segments_are_staged() {
        let mut cfg = default_cfg();
        cfg.DISORDER_SEGMENTS = 3;
        let state = FlowState::new(vec![], None);
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        Disorder::new(&cfg).on_first_data_packet(&state, &mut pkt);

        assert_eq!(
            pkt.disorder_spec,
            Some(DisorderSpec {
                segments: 3,
                reverse: true,
                delay_ms: 0,
            })
        );
    }

    #[test]
    fn reverse_false_is_staged() {
        let mut cfg = default_cfg();
        cfg.DISORDER_REVERSE = false;
        let state = FlowState::new(vec![], None);
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        Disorder::new(&cfg).on_first_data_packet(&state, &mut pkt);

        assert_eq!(
            pkt.disorder_spec,
            Some(DisorderSpec {
                segments: 2,
                reverse: false,
                delay_ms: 0,
            })
        );
    }

    #[test]
    fn delay_is_staged() {
        let mut cfg = default_cfg();
        cfg.DISORDER_DELAY_MS = 15;
        let state = FlowState::new(vec![], None);
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        Disorder::new(&cfg).on_first_data_packet(&state, &mut pkt);

        assert_eq!(
            pkt.disorder_spec,
            Some(DisorderSpec {
                segments: 2,
                reverse: true,
                delay_ms: 15,
            })
        );
    }

    #[test]
    fn fragment_all_mode_returns_continue_with_data() {
        let mut cfg = default_cfg();
        cfg.DISORDER_ONLY_FIRST_PACKET = false;
        let state = FlowState::new(vec![], None);
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        let action = Disorder::new(&cfg).on_first_data_packet(&state, &mut pkt);

        assert_eq!(
            action,
            MethodAction::EmitFakeAndAccept {
                complete_immediately: false,
                continue_with_data: true,
            }
        );
        assert!(pkt.disorder_spec.is_some());
    }

    #[test]
    fn fragment_all_mode_small_packet_still_enters_fragment_all() {
        let mut cfg = default_cfg();
        cfg.DISORDER_ONLY_FIRST_PACKET = false;
        let state = FlowState::new(vec![], None);
        let mut pkt = data_pkt(&[0x16]);

        let action = Disorder::new(&cfg).on_first_data_packet(&state, &mut pkt);

        // Nothing to split, but the flow still enters fragment-all mode so
        // later, larger packets are re-chunked.
        assert_eq!(
            action,
            MethodAction::EmitFakeAndAccept {
                complete_immediately: false,
                continue_with_data: true,
            }
        );
        assert_eq!(pkt.disorder_spec, None);
    }
}
