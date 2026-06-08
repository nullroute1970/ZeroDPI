//! Pluggable bypass methods.
//!
//! Each method either implements [`BypassMethod`] (interceptor-based) or
//! operates entirely inside the proxy task (socket-based).
//!
//! ## Interceptor-based methods
//!
//! These methods hook into the WinDivert / NFQUEUE packet-capture pipeline.
//! They implement the [`BypassMethod`] trait and are driven by two hooks:
//!
//! - [`BypassMethod::on_handshake_complete_ack`] — fires on the first outbound
//!   bare ACK after the TCP handshake.  `wrong_seq`, `wrong_ack`,
//!   `wrong_checksum`, and the first stage of the `wrong_seq_*` combo methods
//!   act here (fake injection).
//! - [`BypassMethod::on_first_data_packet`] — fires on the first outbound
//!   data packet.  `tls_record_frag` and the second stage of
//!   `wrong_seq_tls_record_frag` act here (TLS record fragmentation). The
//!   second stage of `wrong_seq_tls_frag` completes when it observes the first
//!   TCP-segmented data packet.
//!
//! ## Socket-based methods
//!
//! These methods bypass the interceptor entirely and operate on the proxy's
//! `TcpStream` directly.  They do **not** implement [`BypassMethod`] and the
//! flow is never registered in the [`crate::flow::FlowTable`].
//!
//! - `tcp_segmentation` — TCP-level TLS Fragment. Writes the intact real
//!   ClientHello record in tiny TCP segments with `TCP_NODELAY` so DPI cannot
//!   reassemble the SNI from any single packet.
//!
//! New interceptor-based methods only need to implement this trait and be
//! registered in [`build_method`].  New socket-based methods must be wired
//! directly into `proxy.rs` instead.

pub mod tcp_segmentation;
pub mod tls_record_frag;
pub mod wrong_ack;
pub mod wrong_checksum;
pub mod wrong_seq;
pub mod wrong_seq_tls_frag;
pub mod wrong_seq_tls_record_frag;

use crate::config::Config;
use crate::flow::FlowState;
use crate::interceptor::PacketView;

/// Result of asking a method to act on a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodAction {
    /// Apply the staged mutations on `PacketView` and accept it.
    ///
    /// `complete_immediately = false` keeps monitoring until an inbound ACK
    /// confirms the fake packet path. `true` signals bypass completion as soon
    /// as the modified packet is emitted. `continue_with_data = true` keeps
    /// monitoring for a first outbound data packet after this modified packet.
    EmitFakeAndAccept {
        complete_immediately: bool,
        continue_with_data: bool,
    },
    /// Forward unchanged and mark the bypass phase complete.
    ///
    /// This is used when a data-stage method decides the packet is not safe to
    /// rewrite but should not leave the proxy waiting for a completion signal.
    CompleteAndAccept,
    /// Forward unchanged.
    PassThrough,
}

impl MethodAction {
    pub const fn emit_and_wait_for_ack() -> Self {
        Self::EmitFakeAndAccept {
            complete_immediately: false,
            continue_with_data: false,
        }
    }

    pub const fn emit_and_complete() -> Self {
        Self::EmitFakeAndAccept {
            complete_immediately: true,
            continue_with_data: false,
        }
    }

    pub const fn emit_and_wait_for_data() -> Self {
        Self::EmitFakeAndAccept {
            complete_immediately: false,
            continue_with_data: true,
        }
    }

    pub const fn complete_and_accept() -> Self {
        Self::CompleteAndAccept
    }
}

/// A pluggable DPI-bypass technique.
pub trait BypassMethod: Send + Sync + 'static {
    /// Short identifier (matches the `BYPASS_METHOD` config value).
    fn name(&self) -> &'static str;

    /// Called when the first outbound bare ACK of the handshake is observed.
    ///
    /// Methods that operate at this stage (e.g. `wrong_seq`, `wrong_ack`,
    /// `wrong_checksum`) stage their payload mutations here and return
    /// [`MethodAction::EmitFakeAndAccept`].
    /// Methods that operate later (e.g. `tls_record_frag`) return
    /// [`MethodAction::PassThrough`]; the handler will then set the flow into
    /// `waiting_for_data` mode and call [`on_first_data_packet`] instead.
    ///
    /// [`on_first_data_packet`]: BypassMethod::on_first_data_packet
    fn on_handshake_complete_ack(&self, flow: &FlowState, pkt: &mut PacketView<'_>)
        -> MethodAction;

    /// Called when the first outbound *data* packet is observed.
    ///
    /// This hook is invoked only when [`on_handshake_complete_ack`] returned
    /// [`MethodAction::PassThrough`], putting the flow into `waiting_for_data`
    /// mode.  The default passes the packet through unchanged; methods that
    /// operate at the data layer (e.g. `tls_record_frag`) override this to
    /// stage their payload mutations and return [`MethodAction::EmitFakeAndAccept`],
    /// which causes the handler to signal bypass completion immediately.
    ///
    /// [`on_handshake_complete_ack`]: BypassMethod::on_handshake_complete_ack
    fn on_first_data_packet(&self, _flow: &FlowState, _pkt: &mut PacketView<'_>) -> MethodAction {
        MethodAction::PassThrough
    }
}

/// Build an interceptor-based method from the application config.
///
/// Returns `Some(method)` for interceptor-based methods (`wrong_seq`,
/// `wrong_ack`, `wrong_checksum`, `tls_record_frag`, `wrong_seq_tls_frag`,
/// `wrong_seq_tls_record_frag`) and `None` for socket-based methods
/// (`tcp_segmentation`) or unknown names.  Callers should validate the method
/// name via [`crate::config::Config::validate`] before calling this function.
pub fn build_method(cfg: &Config) -> Option<Box<dyn BypassMethod>> {
    match cfg.BYPASS_METHOD.as_str() {
        "wrong_seq" => Some(Box::new(wrong_seq::WrongSeq::new(cfg))),
        "wrong_ack" => Some(Box::new(wrong_ack::WrongAck::new(cfg))),
        "wrong_checksum" => Some(Box::new(wrong_checksum::WrongChecksum::new(cfg))),
        "tls_record_frag" => Some(Box::new(tls_record_frag::TlsRecordFrag::new(cfg))),
        "wrong_seq_tls_frag" => Some(Box::new(wrong_seq_tls_frag::WrongSeqTlsFrag::new(cfg))),
        "wrong_seq_tls_record_frag" => Some(Box::new(
            wrong_seq_tls_record_frag::WrongSeqTlsRecordFrag::new(cfg),
        )),
        // "tcp_segmentation" is socket-based and handled directly in proxy.rs.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_method(method: &str) -> Config {
        toml::from_str(&format!(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "{method}""#
        ))
        .unwrap()
    }

    #[test]
    fn build_wrong_checksum_method() {
        let cfg = cfg_with_method("wrong_checksum");
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_checksum");
    }

    #[test]
    fn build_wrong_ack_method() {
        let cfg = cfg_with_method("wrong_ack");
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_ack");
    }

    #[test]
    fn build_wrong_seq_tls_frag_method() {
        let cfg = cfg_with_method("wrong_seq_tls_frag");
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq_tls_frag");
    }

    #[test]
    fn build_wrong_seq_tls_record_frag_method() {
        let cfg = cfg_with_method("wrong_seq_tls_record_frag");
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq_tls_record_frag");
    }

    #[test]
    fn socket_method_returns_none() {
        let cfg = cfg_with_method("tcp_segmentation");
        assert!(build_method(&cfg).is_none());
    }
}
