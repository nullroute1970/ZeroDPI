//! `low_ttl` bypass: replace the first outbound bare ACK's payload with a fake
//! TLS ClientHello that carries a whitelisted SNI, and stamp the IP packet with
//! a low Time-To-Live (TTL) value.
//!
//! The TTL is tuned so the decoy segment survives exactly as far as an inline
//! DPI middlebox (typically 4-8 hops from the client) but expires before it
//! reaches the destination server.  The DPI inspects the decoy ClientHello and
//! classifies the flow as benign, while the real server never receives the
//! fake payload.  The TCP handshake still completes because the kernel
//! retransmits the bare ACK (or the first data segment carries the ACK
//! itself), and that retransmission passes through unmodified.
//!
//! Unlike `wrong_checksum`, the segment keeps valid TCP sequence/acknowledgment
//! numbers and a valid checksum — the TTL alone is what keeps the server from
//! seeing it.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub struct LowTtl {
    /// IPv4 TTL stamped on the spoofed packet: high enough to reach the ISP's
    /// DPI middlebox, low enough to expire before the destination server.
    ///
    /// Stored behind an `Arc<AtomicU8>` so `LOW_TTL_DISCOVER` can update the
    /// live value without rebuilding the method (the root helper and the local
    /// interceptor both share the handle through
    /// [`BypassMethod::low_ttl_handle`]).
    ttl: Arc<AtomicU8>,
    /// Whether to set the PSH flag on the spoofed packet.
    set_psh: bool,
    /// Whether to bump the IPv4 Identification field on the spoofed packet.
    bump_ip_ident: bool,
    /// Whether to signal bypass completion immediately after emitting the
    /// low-TTL packet.
    complete_immediately: bool,
}

impl LowTtl {
    pub fn new(cfg: &Config) -> Self {
        Self {
            ttl: Arc::new(AtomicU8::new(cfg.LOW_TTL_VALUE)),
            set_psh: cfg.LOW_TTL_SET_PSH,
            bump_ip_ident: cfg.LOW_TTL_BUMP_IP_IDENT,
            complete_immediately: cfg.LOW_TTL_COMPLETE_IMMEDIATELY,
        }
    }

    /// Current TTL value, as read at packet-emission time.
    pub fn ttl(&self) -> u8 {
        self.ttl.load(Ordering::Relaxed)
    }
}

impl BypassMethod for LowTtl {
    fn name(&self) -> String {
        "low_ttl".into()
    }

    fn low_ttl_handle(&self) -> Option<Arc<AtomicU8>> {
        Some(self.ttl.clone())
    }

    fn on_handshake_complete_ack(
        &self,
        flow: &FlowState,
        pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        let payload = flow.fake_data.clone();
        let payload_len = payload.len();
        // Per-flow override (LOW_TTL_DISCOVER probes) wins over the shared
        // handle, so probing never mutates the live value for user flows.
        let ttl = flow.low_ttl_override.unwrap_or_else(|| self.ttl());

        let mut flags = pkt.flags;
        flags.psh = self.set_psh;

        // Keep the kernel ACK's valid seq/ack numbers and a valid checksum.
        // The low TTL is what stops the fake payload from reaching the server.
        pkt.new_flags = Some(flags);
        pkt.new_payload = Some(payload);
        pkt.bump_ipv4_ident = self.bump_ip_ident;
        pkt.new_ipv4_ttl = Some(ttl);

        trace!(
            target = "zerodpi::low_ttl",
            seq = pkt.seq,
            ack = pkt.ack,
            payload_len,
            ttl,
            set_psh = self.set_psh,
            bump_ip_ident = self.bump_ip_ident,
            complete_immediately = self.complete_immediately,
            "staged fake ClientHello with low IP TTL"
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
               BYPASS_METHOD = "low_ttl""#,
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
            new_ipv4_ttl: None,
            new_urgent_pointer: None,
        }
    }

    #[test]
    fn stages_payload_keeps_valid_seq_and_sets_ttl() {
        let mut state = FlowState::new(vec![0xAB; 517], None);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(2000);

        let mut pkt = ack_pkt(1000, 2000);
        let action = LowTtl::new(&default_cfg()).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(pkt.seq, 1001);
        assert_eq!(pkt.ack, 2001);
        assert_eq!(pkt.new_seq, None);
        assert_eq!(pkt.new_ack, None);
        assert_eq!(pkt.new_payload.as_ref().unwrap().len(), 517);
        assert!(pkt.new_flags.unwrap().psh);
        assert!(pkt.bump_ipv4_ident);
        assert_eq!(pkt.new_ipv4_ttl, Some(5));
        assert_eq!(pkt.corrupt_tcp_checksum_delta, None);
    }

    #[test]
    fn honors_disabled_toggles_and_completion_wait() {
        let mut cfg = default_cfg();
        cfg.LOW_TTL_VALUE = 8;
        cfg.LOW_TTL_SET_PSH = false;
        cfg.LOW_TTL_BUMP_IP_IDENT = false;
        cfg.LOW_TTL_COMPLETE_IMMEDIATELY = false;

        let state = FlowState::new(vec![0xCD; 10], None);
        let mut pkt = ack_pkt(10, 20);
        let action = LowTtl::new(&cfg).on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert!(!pkt.new_flags.unwrap().psh);
        assert!(!pkt.bump_ipv4_ident);
        assert_eq!(pkt.new_ipv4_ttl, Some(8));
    }

    #[test]
    fn per_flow_override_stamps_ttl_without_touching_handle() {
        let method = LowTtl::new(&default_cfg());
        assert_eq!(method.ttl(), 5);

        let state = FlowState::new(vec![0xEF; 10], Some(7));
        let mut pkt = ack_pkt(10, 20);
        let action = method.on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(pkt.new_ipv4_ttl, Some(7));
        // The shared handle must be untouched by the override.
        assert_eq!(method.ttl(), 5);
    }

    #[test]
    fn shared_handle_updates_stamped_ttl_at_runtime() {
        let method = LowTtl::new(&default_cfg());
        let handle = method.low_ttl_handle().expect("low_ttl exposes a handle");
        assert_eq!(method.ttl(), 5);

        handle.store(12, Ordering::Relaxed);

        let state = FlowState::new(vec![0xEF; 10], None);
        let mut pkt = ack_pkt(10, 20);
        let action = method.on_handshake_complete_ack(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(pkt.new_ipv4_ttl, Some(12));
        assert_eq!(method.ttl(), 12);
    }

    #[test]
    fn other_methods_expose_no_handle() {
        let method = LowTtl::new(&default_cfg());
        assert!(method.low_ttl_handle().is_some());
        let cfg = toml::from_str::<Config>(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "wrong_seq""#,
        )
        .unwrap();
        let other = super::super::wrong_seq::WrongSeq::new(&cfg);
        assert!(other.low_ttl_handle().is_none());
    }
}
