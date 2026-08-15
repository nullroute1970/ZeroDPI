//! Generic composition of multiple bypass methods.
//!
//! [`CompositeMethod`] runs every handshake-stage member from the configured
//! `BYPASS_METHOD` list in order, staging their mutations onto the same fake
//! packet (every injector uses the identical `flow.fake_data` payload and
//! distinct `PacketView` fields), then delegates the data stage to
//! `tls_record_frag` when present. Socket-side `tls_frag` segmentation is
//! signaled through [`CompositeMethod::segments_first_client_hello`] and
//! `tls_padding` through [`CompositeMethod::pads_first_client_hello`] so the
//! proxy enables the corresponding socket-side data-stage transforms.
//! `mixed_case_sni` follows the same pattern via
//! [`CompositeMethod::mixed_case_sni_first_hello`], and `sni_boundary_frag`
//! via [`CompositeMethod::splits_first_client_hello`].
//!
//! Composition rules (provably reproduce the former hard-coded combos):
//! - PSH / IP-ident settings come from the **first** handshake-stage member.
//! - Completion behavior (`wait_for_ack` vs `complete`) comes from the
//!   **last** handshake-stage member.
//! - A member's `AbortAndAccept` is honored only when no member has staged
//!   any mutation yet; otherwise the abort is ignored.

use std::sync::atomic::AtomicU8;
use std::sync::Arc;

use super::{BypassMethod, MethodAction};
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub struct CompositeMethod {
    pub handshake_methods: Vec<Box<dyn BypassMethod>>,
    pub data_method: Option<Box<dyn BypassMethod>>,
    pub segments_first_client_hello: bool,
    pub pads_first_client_hello: bool,
    pub mixed_case_sni_first_hello: bool,
    pub splits_first_client_hello: bool,
}

impl CompositeMethod {
    pub fn new(
        handshake_methods: Vec<Box<dyn BypassMethod>>,
        data_method: Option<Box<dyn BypassMethod>>,
        segments_first_client_hello: bool,
        pads_first_client_hello: bool,
    ) -> Self {
        Self {
            handshake_methods,
            data_method,
            segments_first_client_hello,
            pads_first_client_hello,
            mixed_case_sni_first_hello: false,
            splits_first_client_hello: false,
        }
    }

    /// Mark the composite as including the socket-side `mixed_case_sni`
    /// transform so its name reflects the full method list.
    pub fn with_mixed_case_sni(mut self, enabled: bool) -> Self {
        self.mixed_case_sni_first_hello = enabled;
        self
    }

    /// Mark the composite as including the socket-side `sni_boundary_frag`
    /// transform so its name reflects the full method list and the
    /// handshake stage waits for the data stage.
    pub fn with_sni_boundary_split(mut self, enabled: bool) -> Self {
        self.splits_first_client_hello = enabled;
        self
    }
}

impl BypassMethod for CompositeMethod {
    fn name(&self) -> String {
        let mut parts: Vec<String> = self.handshake_methods.iter().map(|m| m.name()).collect();
        if let Some(data_method) = &self.data_method {
            parts.push(data_method.name());
        }
        if self.segments_first_client_hello {
            parts.push("tls_frag".into());
        }
        if self.pads_first_client_hello {
            parts.push("tls_padding".into());
        }
        if self.mixed_case_sni_first_hello {
            parts.push("mixed_case_sni".into());
        }
        if self.splits_first_client_hello {
            parts.push("sni_boundary_frag".into());
        }
        parts.join(" + ")
    }

    fn low_ttl_handle(&self) -> Option<Arc<AtomicU8>> {
        self.handshake_methods
            .iter()
            .find_map(|m| m.low_ttl_handle())
    }

    fn on_handshake_complete_ack(
        &self,
        flow: &FlowState,
        pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        let mut staged_any = false;
        let mut first_flags: Option<crate::interceptor::TcpFlags> = None;
        let mut first_bump_ident = false;
        let mut last_action: Option<MethodAction> = None;

        for method in &self.handshake_methods {
            let flags_before = pkt.new_flags;
            let bump_before = pkt.bump_ipv4_ident;
            let action = method.on_handshake_complete_ack(flow, pkt);
            if matches!(action, MethodAction::EmitFakeAndAccept { .. }) {
                staged_any = true;
            }
            if flags_before.is_none() && pkt.new_flags.is_some() {
                first_flags = pkt.new_flags;
            }
            if !bump_before && pkt.bump_ipv4_ident {
                first_bump_ident = true;
            }
            last_action = Some(action);
        }

        // PSH / IP-ident come from the first handshake-stage member.
        pkt.new_flags = first_flags;
        pkt.bump_ipv4_ident = first_bump_ident;

        if self.data_method.is_some()
            || self.segments_first_client_hello
            || self.pads_first_client_hello
            || self.splits_first_client_hello
        {
            tracing::trace!(
                target = "zerodpi::composite",
                members = %self.name(),
                "staged handshake-stage mutations; waiting for data stage"
            );
            return MethodAction::emit_and_wait_for_data();
        }

        match last_action {
            Some(MethodAction::EmitFakeAndAccept {
                complete_immediately,
                ..
            }) if complete_immediately => MethodAction::emit_and_complete(),
            Some(MethodAction::EmitFakeAndAccept { .. }) => MethodAction::emit_and_wait_for_ack(),
            Some(MethodAction::AbortAndAccept) if !staged_any => MethodAction::abort_and_accept(),
            Some(MethodAction::CompleteAndAccept) | Some(MethodAction::AbortAndAccept) => {
                MethodAction::complete_and_accept()
            }
            Some(MethodAction::PassThrough) | None => MethodAction::complete_and_accept(),
        }
    }

    fn on_first_data_packet(&self, flow: &FlowState, pkt: &mut PacketView<'_>) -> MethodAction {
        if let Some(data_method) = &self.data_method {
            data_method.on_first_data_packet(flow, pkt)
        } else {
            MethodAction::complete_and_accept()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::config::Config;
    use crate::flow::FlowState;
    use crate::interceptor::{Direction, PacketView, TcpFlags};
    use crate::methods::low_ttl::LowTtl;
    use crate::methods::tls_record_frag::TlsRecordFrag;
    use crate::methods::wrong_checksum::WrongChecksum;
    use crate::methods::wrong_md5::{tcp_md5_signature_option, WrongMd5};
    use crate::methods::wrong_seq::WrongSeq;
    use crate::methods::wrong_timestamp::WrongTimestamp;

    fn cfg_with(toml_extra: &str) -> Config {
        toml::from_str(&format!(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "wrong_seq_tls_frag"
               {toml_extra}"#
        ))
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
            new_ipv4_ttl: None,
            new_urgent_pointer: None,
        }
    }

    fn handshake_state() -> FlowState {
        let mut state = FlowState::new(vec![0xAB; 517], None);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(5000);
        state
    }

    #[test]
    fn name_joins_members_with_plus() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(
            vec![Box::new(WrongSeq::new(&cfg)), Box::new(LowTtl::new(&cfg))],
            None,
            true,
            true,
        );
        assert_eq!(m.name(), "wrong_seq + low_ttl + tls_frag + tls_padding");
    }

    #[test]
    fn wrong_seq_plus_tls_frag_matches_old_combo() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(vec![Box::new(WrongSeq::new(&cfg))], None, true, false);

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_data());
        assert_eq!(packet.new_payload.as_ref().unwrap().len(), 517);
        assert_eq!(packet.new_seq, Some(1001u32.wrapping_sub(517)));
        assert!(packet.new_flags.unwrap().psh);
        assert!(packet.bump_ipv4_ident);

        let payload: &'static [u8] = &[0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03];
        let mut packet = pkt(payload, payload.len());
        let action = m.on_first_data_packet(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::complete_and_accept());
        assert!(packet.new_payload.is_none());
    }

    #[test]
    fn wrong_seq_plus_wrong_md5_uses_first_psh_and_last_action() {
        let cfg = cfg_with("WRONG_MD5_SET_PSH = false\nWRONG_MD5_COMPLETE_IMMEDIATELY = false");
        let m = CompositeMethod::new(
            vec![Box::new(WrongSeq::new(&cfg)), Box::new(WrongMd5::new(&cfg))],
            None,
            false,
            false,
        );

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert_eq!(packet.new_seq, Some(1001u32.wrapping_sub(517)));
        assert!(packet.new_flags.unwrap().psh); // PSH from wrong_seq (first), not wrong_md5
        assert_eq!(packet.append_tcp_options, tcp_md5_signature_option());
    }

    #[test]
    fn wrong_seq_plus_wrong_md5_completes_immediately_when_last_says_so() {
        let cfg = cfg_with("WRONG_MD5_COMPLETE_IMMEDIATELY = true");
        let m = CompositeMethod::new(
            vec![Box::new(WrongSeq::new(&cfg)), Box::new(WrongMd5::new(&cfg))],
            None,
            false,
            false,
        );

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_complete());
    }

    #[test]
    fn wrong_seq_plus_low_ttl_stages_both_twists_on_one_packet() {
        let cfg = cfg_with("LOW_TTL_VALUE = 5\nLOW_TTL_COMPLETE_IMMEDIATELY = false");
        let m = CompositeMethod::new(
            vec![Box::new(WrongSeq::new(&cfg)), Box::new(LowTtl::new(&cfg))],
            None,
            false,
            false,
        );

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert_eq!(packet.new_seq, Some(1001u32.wrapping_sub(517)));
        assert_eq!(packet.new_ipv4_ttl, Some(5));
        assert_eq!(packet.new_payload.as_ref().unwrap().len(), 517);
    }

    #[test]
    fn wrong_seq_plus_sni_boundary_frag_waits_for_data_stage() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(vec![Box::new(WrongSeq::new(&cfg))], None, false, false)
            .with_sni_boundary_split(true);

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_data());
        assert_eq!(m.name(), "wrong_seq + sni_boundary_frag");

        // Data stage: no data-stage method, so the first data packet
        // (the first boundary segment) passes through and completes.
        let payload: &'static [u8] = &[0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03];
        let mut packet = pkt(payload, payload.len());
        let action = m.on_first_data_packet(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::complete_and_accept());
        assert!(packet.new_payload.is_none());
    }

    #[test]
    fn name_omits_sni_boundary_frag_when_not_set() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(vec![Box::new(WrongSeq::new(&cfg))], None, false, false);
        assert_eq!(m.name(), "wrong_seq");
    }

    #[test]
    fn wrong_seq_plus_tls_padding_waits_for_data_stage() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(vec![Box::new(WrongSeq::new(&cfg))], None, false, true);

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_data());
        assert_eq!(m.name(), "wrong_seq + tls_padding");
    }

    #[test]
    fn last_handshake_member_controls_action() {
        let cfg = cfg_with("WRONG_CHECKSUM_COMPLETE_IMMEDIATELY = true");
        let m = CompositeMethod::new(
            vec![
                Box::new(WrongChecksum::new(&cfg)),
                Box::new(WrongSeq::new(&cfg)),
            ],
            None,
            false,
            false,
        );
        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert_eq!(packet.corrupt_tcp_checksum_delta, Some(1));
        assert_eq!(packet.new_seq, Some(1001u32.wrapping_sub(517)));

        let m = CompositeMethod::new(
            vec![
                Box::new(WrongSeq::new(&cfg)),
                Box::new(WrongChecksum::new(&cfg)),
            ],
            None,
            false,
            false,
        );
        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_complete());
    }

    #[test]
    fn abort_ignored_when_another_member_staged() {
        // wrong_timestamp aborts when the ACK has no TCP timestamp option.
        let cfg = cfg_with("");
        let m = CompositeMethod::new(
            vec![
                Box::new(WrongSeq::new(&cfg)),
                Box::new(WrongTimestamp::new(&cfg)),
            ],
            None,
            false,
            false,
        );
        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::complete_and_accept());
        assert!(packet.new_payload.is_some()); // wrong_seq's fake survived
    }

    #[test]
    fn abort_honored_when_nothing_staged() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(
            vec![Box::new(WrongTimestamp::new(&cfg))],
            None,
            false,
            false,
        );
        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::abort_and_accept());
    }

    #[test]
    fn forwards_low_ttl_handle_when_present() {
        let cfg = cfg_with("");
        let with_ttl = CompositeMethod::new(vec![Box::new(LowTtl::new(&cfg))], None, false, false);
        assert!(with_ttl.low_ttl_handle().is_some());
        let without_ttl =
            CompositeMethod::new(vec![Box::new(WrongSeq::new(&cfg))], None, false, false);
        assert!(without_ttl.low_ttl_handle().is_none());
    }

    #[test]
    fn delegates_data_stage_to_tls_record_frag() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(
            vec![],
            Some(Box::new(TlsRecordFrag::new(&cfg))),
            false,
            false,
        );

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_data());

        let mut payload: Vec<u8> = vec![0x16, 0x03, 0x03, 0x02, 0x05];
        payload.extend(std::iter::repeat(0xAA).take(517));
        let payload: &'static [u8] = Box::leak(payload.into_boxed_slice());
        let mut packet = pkt(payload, payload.len());
        let action = m.on_first_data_packet(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_complete());
        assert!(packet.new_payload.is_some());
    }
}
