//! `fake_tls` bypass: decoy TLS record injection at the first outbound data
//! packet.
//!
//! The first outbound data packet (the real ClientHello) is rewritten into a
//! decoy TLS record — `flow.fake_data`, the whitelisted-SNI ClientHello that
//! already carries a valid record header (`16 03 01 02 00`) — with a TCP
//! sequence number placed behind the server's receive window:
//! `syn_seq + 1 - payload_len - FAKE_TLS_EXTRA_OFFSET`.
//!
//! A record-parsing DPI inspects the decoy and classifies the flow benign.
//! The upstream server discards the out-of-window segment, and the real
//! ClientHello reaches it via TCP retransmission (single-packet mode) or is
//! forwarded immediately after the decoy (dual-emission mode, Phase 2).
//!
//! ## Chained mode
//!
//! When `fake_tls` is chained with another data-stage method (`tls_record_frag`,
//! `ip_frag`, `disorder`, and/or `seqovl`), the decoy cannot *replace* the
//! first data packet: the chained method has to shape the real ClientHello. In
//! that mode `fake_tls` stages [`PacketView::decoy`] instead, and the backend
//! emits `FAKE_TLS_REPEATS` decoy copies — with `FAKE_TLS_CHAIN_DELAY_MS`
//! between the last copy and the real data — before the shaped real packet.
//! This is what makes `["fake_tls", "disorder"]` behave like zapret's
//! `fakeddisorder` and `["fake_tls", "seqovl"]` like a fakedsplit with sequence
//! overlap.
//!
//! Chaining requires `FAKE_TLS_FORWARD_REAL = true` (enforced by
//! `Config::validate`), because the real packet only exists in dual-emission
//! mode.

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::config::{Config, Int32Range};
use crate::flow::FlowState;
use crate::interceptor::{DecoyPacket, PacketView};

pub struct FakeTls {
    /// Extra bytes subtracted from the injected seq number on top of
    /// `payload_len`.  0 reproduces the base behaviour.
    extra_offset: u32,
    /// Whether to set the PSH flag on the decoy packet.
    set_psh: bool,
    /// Whether to bump the IPv4 Identification field on the decoy packet.
    bump_ip_ident: bool,
    /// Whether to signal bypass completion immediately after emission.
    complete_immediately: bool,
    /// Whether to forward the original packet after the decoy (dual emission).
    forward_real: bool,
    /// `true` when another data-stage method shapes the real packet, so the
    /// decoy is staged in [`PacketView::decoy`] instead of replacing the
    /// packet.
    chained: bool,
    /// Number of decoy copies emitted in chained mode.
    repeats: usize,
    /// Delay between the last decoy copy and the real data.
    chain_delay_ms: Int32Range,
}

impl FakeTls {
    pub fn new(cfg: &Config) -> Self {
        Self {
            extra_offset: cfg.FAKE_TLS_EXTRA_OFFSET,
            set_psh: cfg.FAKE_TLS_SET_PSH,
            bump_ip_ident: cfg.FAKE_TLS_BUMP_IP_IDENT,
            complete_immediately: cfg.FAKE_TLS_COMPLETE_IMMEDIATELY,
            forward_real: cfg.FAKE_TLS_FORWARD_REAL,
            chained: false,
            repeats: cfg.FAKE_TLS_REPEATS,
            chain_delay_ms: cfg.FAKE_TLS_CHAIN_DELAY_MS,
        }
    }

    /// Mark this instance as chained with another data-stage method.
    pub fn chained(mut self, chained: bool) -> Self {
        self.chained = chained;
        self
    }
}

impl BypassMethod for FakeTls {
    fn name(&self) -> String {
        "fake_tls".into()
    }

    /// Returns `PassThrough` — this method operates on the first data packet.
    /// The handler sets `waiting_for_data` and calls
    /// [`on_first_data_packet`] instead.
    ///
    /// [`on_first_data_packet`]: FakeTls::on_first_data_packet
    fn on_handshake_complete_ack(
        &self,
        _flow: &FlowState,
        _pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        MethodAction::PassThrough
    }

    fn on_first_data_packet(&self, flow: &FlowState, pkt: &mut PacketView<'_>) -> MethodAction {
        // In fragment-all chains the handler re-invokes this hook for every
        // subsequent data packet; the decoy belongs to the first one only.
        if self.chained && flow.first_data_modified {
            return MethodAction::CompleteAndAccept;
        }

        let syn_seq = flow
            .syn_seq
            .expect("syn_seq must be set before the first data packet");
        let payload = flow.fake_data.clone();
        let payload_len = payload.len() as u32;
        // Positions the decoy segment behind the server's rcv_nxt by at least
        // `payload_len` bytes, plus any configured extra offset.
        let new_seq = syn_seq
            .wrapping_add(1)
            .wrapping_sub(payload_len)
            .wrapping_sub(self.extra_offset);

        let mut flags = pkt.flags;
        flags.psh = self.set_psh;

        if self.chained {
            // The chained method owns the primary packet's mutations, so the
            // decoy is staged separately and emitted before it.
            let delay_ms = super::tcp_segmentation::sample_i32(
                self.chain_delay_ms,
                &mut super::tcp_segmentation::FragmentRng::new(),
            )
            .max(0) as u64;
            pkt.decoy = Some(DecoyPacket {
                seq: new_seq,
                payload,
                flags,
                bump_ipv4_ident: self.bump_ip_ident,
                repeats: self.repeats,
                delay_ms,
            });
            trace!(
                target = "zerodpi::fake_tls",
                syn_seq,
                new_seq,
                payload_len,
                repeats = self.repeats,
                delay_ms,
                "staged chained decoy TLS record injection"
            );
            return MethodAction::EmitFakeAndAccept {
                complete_immediately: self.complete_immediately,
                continue_with_data: false,
            };
        }

        pkt.new_seq = Some(new_seq);
        pkt.new_flags = Some(flags);
        pkt.new_payload = Some(payload);
        pkt.bump_ipv4_ident = self.bump_ip_ident;
        pkt.emit_original_after = self.forward_real;

        trace!(
            target = "zerodpi::fake_tls",
            syn_seq,
            new_seq,
            payload_len,
            extra_offset = self.extra_offset,
            set_psh = self.set_psh,
            bump_ip_ident = self.bump_ip_ident,
            complete_immediately = self.complete_immediately,
            forward_real = self.forward_real,
            "staged decoy TLS record injection"
        );

        MethodAction::EmitFakeAndAccept {
            complete_immediately: self.complete_immediately,
            continue_with_data: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::flow::FlowState;
    use crate::interceptor::{Direction, PacketView, TcpFlags};
    use crate::tls_template::build_client_hello;

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
            decoy: None,
            ip_frag_payload_size: None,
            disorder_spec: None,
            new_ipv4_ttl: None,
            new_urgent_pointer: None,
        }
    }

    fn handshake_state() -> FlowState {
        let mut state = FlowState::new(vec![0xAB; 517], None);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);
        state
    }

    #[test]
    fn handshake_ack_hook_is_passthrough() {
        let method = FakeTls::new(&default_cfg());
        let state = FlowState::new(vec![], None);
        let mut pkt = data_pkt(&[]);
        let action = method.on_handshake_complete_ack(&state, &mut pkt);
        assert_eq!(action, MethodAction::PassThrough);
        assert!(pkt.new_payload.is_none());
    }

    #[test]
    fn stages_decoy_record_with_out_of_window_seq() {
        let state = handshake_state();
        let payload: &'static [u8] = Box::leak(vec![0x16u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        let action = FakeTls::new(&default_cfg()).on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        // flow.fake_data is staged verbatim (517 bytes)
        assert_eq!(pkt.new_payload.as_ref().unwrap().len(), 517);
        // 1000 + 1 - 517 - 0 = 484
        assert_eq!(pkt.new_seq, Some(484));
        assert!(pkt.new_flags.unwrap().psh);
        assert!(pkt.bump_ipv4_ident);
    }

    #[test]
    fn decoy_payload_is_a_valid_tls_record() {
        // flow.fake_data is built by tls_template; it must already carry a
        // record header `16 03 01 02 00` (handshake, TLS 1.0 record version,
        // 512-byte body).
        let real_template = build_client_hello(&[0u8; 32], &[0u8; 32], b"mci.ir", &[0u8; 32]);
        let mut state = FlowState::new(real_template.clone(), None);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        FakeTls::new(&default_cfg()).on_first_data_packet(&state, &mut pkt);

        let staged = pkt.new_payload.as_ref().unwrap();
        assert_eq!(staged.len(), 517);
        assert_eq!(&staged[..5], &[0x16, 0x03, 0x01, 0x02, 0x00]);
        assert_eq!(staged, &real_template);
    }

    #[test]
    fn handles_seq_wraparound() {
        let mut state = FlowState::new(vec![0; 517], None);
        state.syn_seq = Some(10); // small ISN forces wrap
        state.syn_ack_seq = Some(2000);
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        FakeTls::new(&default_cfg()).on_first_data_packet(&state, &mut pkt);

        // 10 + 1 - 517 - 0 wraps mod 2^32
        assert_eq!(pkt.new_seq, Some(11u32.wrapping_sub(517)));
    }

    // -----------------------------------------------------------------------
    // Chained mode (fake_tls + another data-stage method)
    // -----------------------------------------------------------------------

    fn chain_cfg() -> Config {
        let mut cfg = default_cfg();
        cfg.FAKE_TLS_REPEATS = 3;
        cfg
    }

    #[test]
    fn chained_mode_stages_a_decoy_instead_of_the_primary() {
        let state = handshake_state();
        let payload: &'static [u8] = Box::leak(vec![0x16u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        let action = FakeTls::new(&chain_cfg())
            .chained(true)
            .on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        let decoy = pkt.decoy.as_ref().expect("decoy must be staged");
        assert_eq!(decoy.seq, 484); // 1000 + 1 - 517
        assert_eq!(decoy.payload.len(), 517);
        assert!(decoy.flags.psh);
        assert!(decoy.bump_ipv4_ident);
        assert_eq!(decoy.repeats, 3);
        assert_eq!(decoy.delay_ms, 0);

        // The primary packet is left to the chained method.
        assert!(pkt.new_payload.is_none());
        assert_eq!(pkt.new_seq, None);
        assert!(pkt.new_flags.is_none());
        assert!(!pkt.bump_ipv4_ident);
        assert!(!pkt.emit_original_after);
    }

    #[test]
    fn chained_mode_does_not_repeat_the_decoy_on_later_packets() {
        let mut state = handshake_state();
        state.first_data_modified = true;
        let payload: &'static [u8] = Box::leak(vec![0x16u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        let action = FakeTls::new(&chain_cfg())
            .chained(true)
            .on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::complete_and_accept());
        assert_eq!(pkt.decoy, None);
    }

    #[test]
    fn standalone_mode_ignores_the_repeat_setting() {
        // Without a chained method the decoy replaces the packet, so `repeats`
        // and the chain delay do not apply.
        let state = handshake_state();
        let payload: &'static [u8] = Box::leak(vec![0x16u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        FakeTls::new(&chain_cfg()).on_first_data_packet(&state, &mut pkt);

        assert_eq!(pkt.decoy, None);
        assert!(pkt.new_payload.is_some());
    }

    #[test]
    fn extra_offset_shifts_seq_further_back() {
        let mut cfg = default_cfg();
        cfg.FAKE_TLS_EXTRA_OFFSET = 100;
        let state = handshake_state();
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        FakeTls::new(&cfg).on_first_data_packet(&state, &mut pkt);

        // 1000 + 1 - 517 - 100 = 384
        assert_eq!(pkt.new_seq, Some(384));
    }

    #[test]
    fn set_psh_false_clears_psh_flag() {
        let mut cfg = default_cfg();
        cfg.FAKE_TLS_SET_PSH = false;
        let state = handshake_state();
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        FakeTls::new(&cfg).on_first_data_packet(&state, &mut pkt);

        assert!(!pkt.new_flags.unwrap().psh);
    }

    #[test]
    fn bump_ip_ident_false() {
        let mut cfg = default_cfg();
        cfg.FAKE_TLS_BUMP_IP_IDENT = false;
        let state = handshake_state();
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        FakeTls::new(&cfg).on_first_data_packet(&state, &mut pkt);

        assert!(!pkt.bump_ipv4_ident);
    }

    #[test]
    fn complete_immediately_false_returns_wait_for_ack_action() {
        let mut cfg = default_cfg();
        cfg.FAKE_TLS_COMPLETE_IMMEDIATELY = false;
        let state = handshake_state();
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        let action = FakeTls::new(&cfg).on_first_data_packet(&state, &mut pkt);

        assert_eq!(
            action,
            MethodAction::EmitFakeAndAccept {
                complete_immediately: false,
                continue_with_data: false,
            }
        );
    }

    #[test]
    fn stages_forward_real_flag_by_default() {
        let state = handshake_state();
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        FakeTls::new(&default_cfg()).on_first_data_packet(&state, &mut pkt);

        assert!(pkt.emit_original_after);
    }

    #[test]
    fn forward_real_false_leaves_flag_unset() {
        let mut cfg = default_cfg();
        cfg.FAKE_TLS_FORWARD_REAL = false;
        let state = handshake_state();
        let payload: &'static [u8] = Box::leak(vec![0u8; 517].into_boxed_slice());
        let mut pkt = data_pkt(payload);

        FakeTls::new(&cfg).on_first_data_packet(&state, &mut pkt);

        assert!(!pkt.emit_original_after);
    }
}
