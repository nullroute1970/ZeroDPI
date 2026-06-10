//! Stateful packet handler implementing the SNI-spoofing state machine.
//!
//! Backends call [`Handler::on_packet`] for every captured TCP/IPv4 packet
//! that matches the per-target filter. The handler:
//! - Looks up the flow's 4-tuple in the shared [`FlowTable`].
//! - Tracks `syn_seq` / `syn_ack_seq` exactly as upstream does.
//! - On the first outbound bare ACK after the handshake, asks the active
//!   [`crate::methods::BypassMethod`] to stage payload mutations and returns
//!   [`crate::interceptor::Verdict::AcceptModified`].
//! - On the inbound ACK that acknowledges the spoofed segment, after first-data
//!   mutation, or immediately for methods that cannot expect a server ACK,
//!   signals the waiting proxy task via the flow's `Notify`.
//! - Any unexpected packet for a tracked flow is forwarded but the flow is
//!   marked closed (mirroring upstream's `on_unexpected_packet`).
//!
//! Packets for unknown flows are always passed through unchanged.

use std::sync::Arc;
use tracing::{debug, trace};

use super::flow::{BypassOutcome, FlowEntry, FlowKey, FlowTable};
use super::interceptor::{Direction, PacketHandler, PacketView, Verdict};
use super::methods::{BypassMethod, MethodAction};

pub struct Handler {
    flows: FlowTable,
    method: Arc<dyn BypassMethod>,
}

impl Handler {
    pub fn new(flows: FlowTable, method: Arc<dyn BypassMethod>) -> Self {
        Self { flows, method }
    }

    fn flow_key_for(&self, pkt: &PacketView<'_>) -> FlowKey {
        // The flow table is keyed on the *outbound* direction.
        match pkt.direction {
            Direction::Outbound => FlowKey {
                src_ip: pkt.src_ip,
                src_port: pkt.src_port,
                dst_ip: pkt.dst_ip,
                dst_port: pkt.dst_port,
            },
            Direction::Inbound => FlowKey {
                src_ip: pkt.dst_ip,
                src_port: pkt.dst_port,
                dst_ip: pkt.src_ip,
                dst_port: pkt.src_port,
            },
        }
    }

    fn unexpected(
        &self,
        entry: &FlowEntry,
        state: &mut super::flow::FlowState,
        pkt: &PacketView<'_>,
        why: &str,
    ) -> Verdict {
        debug!(?pkt.direction, why, "unexpected packet; closing flow");
        if state.outcome.is_none() {
            state.outcome = Some(BypassOutcome::UnexpectedClose);
            state.monitor = false;
            entry.notify.notify_waiters();
        }
        Verdict::Accept
    }
}

impl PacketHandler for Handler {
    fn on_packet(&mut self, pkt: &mut PacketView<'_>) -> Verdict {
        let key = self.flow_key_for(pkt);
        let entry = match self.flows.get(&key).map(|e| e.clone()) {
            Some(e) => e,
            None => return Verdict::Accept,
        };
        let mut state = entry.state.lock();
        if !state.monitor {
            return Verdict::Accept;
        }

        match pkt.direction {
            Direction::Outbound => {
                if pkt.is_bare_syn() {
                    if pkt.ack != 0 {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "outbound SYN with non-zero ack_num",
                        );
                    }
                    if let Some(prev) = state.syn_seq {
                        if prev != pkt.seq {
                            return self.unexpected(
                                &entry,
                                &mut state,
                                pkt,
                                "outbound SYN seq changed (retransmit?)",
                            );
                        }
                    }
                    state.syn_seq = Some(pkt.seq);
                    return Verdict::Accept;
                }
                if pkt.is_bare_ack() {
                    if state.fake_sent || state.waiting_for_data {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "outbound packet after fake already sent",
                        );
                    }
                    let syn_seq = match state.syn_seq {
                        Some(s) => s,
                        None => {
                            return self.unexpected(
                                &entry,
                                &mut state,
                                pkt,
                                "outbound ACK before SYN seen",
                            )
                        }
                    };
                    if pkt.seq != syn_seq.wrapping_add(1) {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "outbound ACK seq does not match syn_seq+1",
                        );
                    }
                    let syn_ack_seq = match state.syn_ack_seq {
                        Some(s) => s,
                        None => {
                            return self.unexpected(
                                &entry,
                                &mut state,
                                pkt,
                                "outbound ACK before SYN-ACK",
                            )
                        }
                    };
                    if pkt.ack != syn_ack_seq.wrapping_add(1) {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "outbound ACK ack_num does not match syn_ack_seq+1",
                        );
                    }
                    // Hand the ACK to the active bypass method to stage mutations.
                    match self.method.on_handshake_complete_ack(&state, pkt) {
                        MethodAction::EmitFakeAndAccept {
                            complete_immediately,
                            continue_with_data,
                        } => {
                            state.fake_sent = true;
                            trace!(method = self.method.name(), "emitting fake (modified ACK)");
                            if continue_with_data {
                                state.waiting_for_data = true;
                                entry.ready_for_data.notify_waiters();
                            } else if complete_immediately {
                                drop(state);
                                entry.finish(BypassOutcome::FakeDataAcked);
                            }
                            return Verdict::AcceptModified;
                        }
                        MethodAction::PassThrough => {
                            // Method deferred to the first data packet (e.g. tls_record_frag).
                            state.waiting_for_data = true;
                            entry.ready_for_data.notify_waiters();
                            trace!(
                                method = self.method.name(),
                                "deferring bypass to first data packet"
                            );
                            return Verdict::Accept;
                        }
                        MethodAction::CompleteAndAccept => {
                            drop(state);
                            entry.finish(BypassOutcome::FakeDataAcked);
                            return Verdict::Accept;
                        }
                        MethodAction::AbortAndAccept => {
                            drop(state);
                            entry.finish(BypassOutcome::UnexpectedClose);
                            return Verdict::Accept;
                        }
                    }
                }
                // First outbound data packet when method deferred to this stage.
                if pkt.payload_len > 0 && state.waiting_for_data && !state.first_data_modified {
                    match self.method.on_first_data_packet(&state, pkt) {
                        MethodAction::EmitFakeAndAccept {
                            complete_immediately,
                            continue_with_data: _,
                        } => {
                            state.first_data_modified = true;
                            state.waiting_for_data = false;
                            trace!(
                                method = self.method.name(),
                                "fragmented first data packet; signalling bypass complete"
                            );
                            if complete_immediately {
                                // Signal completion immediately — no inbound ACK needed.
                                drop(state);
                                entry.finish(BypassOutcome::FakeDataAcked);
                            }
                            return Verdict::AcceptModified;
                        }
                        MethodAction::CompleteAndAccept => {
                            state.first_data_modified = true;
                            state.waiting_for_data = false;
                            drop(state);
                            entry.finish(BypassOutcome::FakeDataAcked);
                            return Verdict::Accept;
                        }
                        MethodAction::PassThrough => return Verdict::Accept,
                        MethodAction::AbortAndAccept => {
                            state.first_data_modified = true;
                            state.waiting_for_data = false;
                            drop(state);
                            entry.finish(BypassOutcome::UnexpectedClose);
                            return Verdict::Accept;
                        }
                    }
                }
                self.unexpected(&entry, &mut state, pkt, "unexpected outbound packet")
            }
            Direction::Inbound => {
                if state.syn_seq.is_none() {
                    return self.unexpected(
                        &entry,
                        &mut state,
                        pkt,
                        "inbound packet before any outbound SYN",
                    );
                }
                if pkt.is_syn_ack() {
                    if pkt.ack != state.syn_seq.unwrap().wrapping_add(1) {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "inbound SYN-ACK ack_num does not match syn_seq+1",
                        );
                    }
                    if let Some(prev) = state.syn_ack_seq {
                        if prev != pkt.seq {
                            return self.unexpected(
                                &entry,
                                &mut state,
                                pkt,
                                "inbound SYN-ACK seq changed (retransmit?)",
                            );
                        }
                    }
                    state.syn_ack_seq = Some(pkt.seq);
                    return Verdict::Accept;
                }
                if pkt.is_bare_ack() && state.fake_sent {
                    let syn_ack_seq = state.syn_ack_seq.expect("checked above via syn_seq");
                    if pkt.seq != syn_ack_seq.wrapping_add(1) {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "inbound post-fake ACK seq mismatch",
                        );
                    }
                    if pkt.ack != state.syn_seq.unwrap().wrapping_add(1) {
                        return self.unexpected(
                            &entry,
                            &mut state,
                            pkt,
                            "inbound post-fake ACK ack mismatch",
                        );
                    }
                    if state.waiting_for_data {
                        trace!(
                            method = self.method.name(),
                            "accepted post-fake ACK while waiting for first data packet"
                        );
                        return Verdict::Accept;
                    }
                    drop(state);
                    entry.finish(BypassOutcome::FakeDataAcked);
                    return Verdict::Accept;
                }
                self.unexpected(&entry, &mut state, pkt, "unexpected inbound packet")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use super::*;
    use crate::config::Config;
    use crate::flow::{new_flow_table, BypassOutcome, FlowEntry, FlowKey};
    use crate::interceptor::{Direction, PacketView, TcpFlags};
    use crate::methods::tls_record_frag::TlsRecordFrag;
    use crate::methods::wrong_ack::WrongAck;
    use crate::methods::wrong_checksum::WrongChecksum;
    use crate::methods::wrong_md5::{tcp_md5_signature_option, WrongMd5};
    use crate::methods::wrong_seq::WrongSeq;
    use crate::methods::wrong_seq_tls_frag::WrongSeqTlsFrag;
    use crate::methods::wrong_seq_tls_record_frag::WrongSeqTlsRecordFrag;
    use crate::methods::wrong_timestamp::WrongTimestamp;

    fn default_cfg() -> Config {
        toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap()
    }

    fn pkt(
        direction: Direction,
        flags: TcpFlags,
        seq: u32,
        ack: u32,
        payload_len: usize,
    ) -> PacketView<'static> {
        let payload: &'static [u8] = if payload_len == 0 {
            &[]
        } else {
            Box::leak(vec![0u8; payload_len].into_boxed_slice())
        };
        pkt_with_payload(direction, flags, seq, ack, payload)
    }

    fn pkt_with_payload(
        direction: Direction,
        flags: TcpFlags,
        seq: u32,
        ack: u32,
        payload: &'static [u8],
    ) -> PacketView<'static> {
        let payload_len = payload.len();
        PacketView {
            direction,
            src_ip: if direction == Direction::Outbound {
                Ipv4Addr::new(10, 0, 0, 1)
            } else {
                Ipv4Addr::new(1, 2, 3, 4)
            },
            dst_ip: if direction == Direction::Outbound {
                Ipv4Addr::new(1, 2, 3, 4)
            } else {
                Ipv4Addr::new(10, 0, 0, 1)
            },
            src_port: if direction == Direction::Outbound {
                12345
            } else {
                443
            },
            dst_port: if direction == Direction::Outbound {
                443
            } else {
                12345
            },
            seq,
            ack,
            flags,
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
        }
    }

    fn tls_record(body: &[u8]) -> &'static [u8] {
        let mut record = vec![0x16, 0x03, 0x03, (body.len() >> 8) as u8, body.len() as u8];
        record.extend_from_slice(body);
        Box::leak(record.into_boxed_slice())
    }

    #[test]
    fn unknown_flows_pass_through() {
        let flows = new_flow_table();
        let mut h = Handler::new(flows, Arc::new(WrongSeq::new(&default_cfg())));
        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            1,
            0,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);
    }

    #[test]
    fn full_happy_path_with_wrong_seq() {
        let flows = new_flow_table();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            dst_port: 443,
        };
        let entry = FlowEntry::new(vec![0xAA; 517]);
        flows.insert(key, entry.clone());
        let mut h = Handler::new(flows.clone(), Arc::new(WrongSeq::new(&default_cfg())));

        // Outbound SYN
        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            1000,
            0,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        // Inbound SYN-ACK
        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            5000,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        // Outbound bare ACK -> rewritten
        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            1001,
            5001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::AcceptModified);
        assert_eq!(p.new_payload.as_ref().unwrap().len(), 517);
        assert_eq!(p.new_seq, Some(1001u32.wrapping_sub(517)));
        assert!(p.new_flags.unwrap().psh);
        assert!(p.bump_ipv4_ident);

        // Inbound ACK acknowledging fake -> finishes flow
        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            5001,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::FakeDataAcked)
        );
    }

    #[test]
    fn wrong_checksum_completes_on_modified_ack() {
        let flows = new_flow_table();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            dst_port: 443,
        };
        let entry = FlowEntry::new(vec![0xAA; 517]);
        flows.insert(key, entry.clone());

        let mut cfg = default_cfg();
        cfg.BYPASS_METHOD = "wrong_checksum".into();
        let mut h = Handler::new(flows, Arc::new(WrongChecksum::new(&cfg)));

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            1000,
            0,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            5000,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            1001,
            5001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::AcceptModified);
        assert_eq!(p.new_seq, None);
        assert_eq!(p.corrupt_tcp_checksum_delta, Some(1));
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::FakeDataAcked)
        );
        assert!(!entry.state.lock().monitor);
    }

    #[test]
    fn wrong_md5_completes_on_modified_ack() {
        let flows = new_flow_table();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            dst_port: 443,
        };
        let entry = FlowEntry::new(vec![0xAA; 517]);
        flows.insert(key, entry.clone());

        let mut cfg = default_cfg();
        cfg.BYPASS_METHOD = "wrong_md5".into();
        let mut h = Handler::new(flows, Arc::new(WrongMd5::new(&cfg)));

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            1000,
            0,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            5000,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            1001,
            5001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::AcceptModified);
        assert_eq!(p.new_seq, None);
        assert_eq!(p.new_ack, None);
        assert_eq!(p.new_payload.as_ref().unwrap().len(), 517);
        assert_eq!(p.append_tcp_options, tcp_md5_signature_option());
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::FakeDataAcked)
        );
        assert!(!entry.state.lock().monitor);
    }

    #[test]
    fn wrong_ack_completes_on_modified_ack() {
        let flows = new_flow_table();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            dst_port: 443,
        };
        let entry = FlowEntry::new(vec![0xAA; 517]);
        flows.insert(key, entry.clone());

        let mut cfg = default_cfg();
        cfg.BYPASS_METHOD = "wrong_ack".into();
        let mut h = Handler::new(flows, Arc::new(WrongAck::new(&cfg)));

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            1000,
            0,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            5000,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            1001,
            5001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::AcceptModified);
        assert_eq!(p.new_seq, None);
        assert_eq!(p.new_ack, Some(5000));
        assert_eq!(p.new_payload.as_ref().unwrap().len(), 517);
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::FakeDataAcked)
        );
        assert!(!entry.state.lock().monitor);
    }

    #[test]
    fn wrong_timestamp_without_tcp_option_aborts_bypass() {
        let flows = new_flow_table();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            dst_port: 443,
        };
        let entry = FlowEntry::new(vec![0xAA; 517]);
        flows.insert(key, entry.clone());

        let mut cfg = default_cfg();
        cfg.BYPASS_METHOD = "wrong_timestamp".into();
        let mut h = Handler::new(flows, Arc::new(WrongTimestamp::new(&cfg)));

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            1000,
            0,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            5000,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            1001,
            5001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);
        assert!(p.new_payload.is_none());
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::UnexpectedClose)
        );
        assert!(!entry.state.lock().monitor);
    }

    #[test]
    fn tls_record_frag_waits_for_first_data_packet() {
        let flows = new_flow_table();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            dst_port: 443,
        };
        let entry = FlowEntry::new(vec![0xAA; 517]);
        flows.insert(key, entry.clone());

        let mut cfg = default_cfg();
        cfg.BYPASS_METHOD = "tls_record_frag".into();
        let mut h = Handler::new(flows, Arc::new(TlsRecordFrag::new(&cfg)));

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            1000,
            0,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            5000,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            1001,
            5001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);
        assert!(entry.state.lock().waiting_for_data);
        assert!(entry.state.lock().outcome.is_none());

        let mut p = pkt_with_payload(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            },
            1001,
            5001,
            tls_record(&[0x01, 0x02, 0x03]),
        );
        assert_eq!(h.on_packet(&mut p), Verdict::AcceptModified);
        assert_eq!(p.new_payload.as_ref().unwrap().len(), 18);
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::FakeDataAcked)
        );
    }

    #[test]
    fn wrong_seq_tls_frag_accepts_post_fake_ack_then_completes_on_tcp_segmented_data() {
        let flows = new_flow_table();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            dst_port: 443,
        };
        let entry = FlowEntry::new(vec![0xAA; 517]);
        flows.insert(key, entry.clone());

        let mut cfg = default_cfg();
        cfg.BYPASS_METHOD = "wrong_seq_tls_frag".into();
        let mut h = Handler::new(flows, Arc::new(WrongSeqTlsFrag::new(&cfg)));

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            1000,
            0,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            5000,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            1001,
            5001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::AcceptModified);
        assert_eq!(p.new_seq, Some(1001u32.wrapping_sub(517)));
        assert!(entry.state.lock().fake_sent);
        assert!(entry.state.lock().waiting_for_data);
        assert!(entry.state.lock().outcome.is_none());

        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            5001,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);
        assert!(entry.state.lock().waiting_for_data);
        assert!(entry.state.lock().outcome.is_none());

        let mut p = pkt_with_payload(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            },
            1001,
            5001,
            tls_record(&[0x01, 0x02, 0x03]),
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);
        assert!(p.new_payload.is_none());
        assert!(p.new_flags.is_none());
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::FakeDataAcked)
        );
        assert!(!entry.state.lock().monitor);
    }

    #[test]
    fn wrong_seq_tls_record_frag_accepts_post_fake_ack_then_fragments_data() {
        let flows = new_flow_table();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            dst_port: 443,
        };
        let entry = FlowEntry::new(vec![0xAA; 517]);
        flows.insert(key, entry.clone());

        let mut cfg = default_cfg();
        cfg.BYPASS_METHOD = "wrong_seq_tls_record_frag".into();
        let mut h = Handler::new(flows, Arc::new(WrongSeqTlsRecordFrag::new(&cfg)));

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                syn: true,
                ..Default::default()
            },
            1000,
            0,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            5000,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);

        let mut p = pkt(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            1001,
            5001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::AcceptModified);
        assert_eq!(p.new_seq, Some(1001u32.wrapping_sub(517)));
        assert!(entry.state.lock().fake_sent);
        assert!(entry.state.lock().waiting_for_data);
        assert!(entry.state.lock().outcome.is_none());

        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            5001,
            1001,
            0,
        );
        assert_eq!(h.on_packet(&mut p), Verdict::Accept);
        assert!(entry.state.lock().waiting_for_data);
        assert!(entry.state.lock().outcome.is_none());

        let mut p = pkt_with_payload(
            Direction::Outbound,
            TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            },
            1001,
            5001,
            tls_record(&[0x01, 0x02, 0x03]),
        );
        assert_eq!(h.on_packet(&mut p), Verdict::AcceptModified);
        assert_eq!(p.new_payload.as_ref().unwrap().len(), 18);
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::FakeDataAcked)
        );
        assert!(!entry.state.lock().monitor);
    }

    #[test]
    fn unexpected_inbound_before_syn_closes_flow() {
        let flows = new_flow_table();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            src_port: 12345,
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            dst_port: 443,
        };
        let entry = FlowEntry::new(vec![0; 517]);
        flows.insert(key, entry.clone());
        let mut h = Handler::new(flows, Arc::new(WrongSeq::new(&default_cfg())));
        let mut p = pkt(
            Direction::Inbound,
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            1,
            1,
            0,
        );
        h.on_packet(&mut p);
        assert_eq!(
            entry.state.lock().outcome,
            Some(BypassOutcome::UnexpectedClose)
        );
    }
}
