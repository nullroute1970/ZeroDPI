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
//!   `wrong_checksum`, `wrong_md5`, `wrong_seq_wrong_md5`, `low_ttl`,
//!   `wrong_timestamp`, and the first stage of combo methods act here (fake
//!   injection).
//! - [`BypassMethod::on_first_data_packet`] — fires on the first outbound
//!   data packet.  `tls_record_frag` and the second stage of
//!   `wrong_seq_tls_record_frag` act here (TLS record fragmentation). The
//!   second stage of `wrong_seq_tls_frag` and `wrong_md5_tls_frag` completes
//!   when it observes the first TCP-segmented data packet.
//!
//! ## Socket-based methods
//!
//! These methods bypass the interceptor entirely and operate on the proxy's
//! `TcpStream` directly.  They do **not** implement [`BypassMethod`] and the
//! flow is never registered in the [`crate::flow::FlowTable`].
//!
//! - `tls_frag` — TCP-level TLS Fragment. Writes selected client data in
//!   small chunks with `TCP_NODELAY` so DPI cannot reassemble the SNI from any
//!   single packet.
//! - `tls_padding` — RFC 7685 ClientHello Padding Expansion. Reads the first
//!   TLS ClientHello record, inserts a padding extension of
//!   `TLS_PADDING_SIZE` zero bytes (before the SNI extension by default),
//!   and writes the expanded record to the upstream socket. The padding
//!   pushes the SNI past DPI inspection windows (typically 512-1460 bytes).
//! - `mixed_case_sni` — SNI Case Randomization. Randomizes the ASCII letter
//!   case of the hostname inside the real ClientHello's SNI extension;
//!   destination servers lowercase it per RFC 6066, so DPI doing
//!   case-sensitive blocklist matching misses while the handshake succeeds.
//! - `sni_boundary_frag` — SNI Extension Boundary Fragmentation. Parses the
//!   ClientHello down to the SNI extension and writes the first record as two
//!   TCP segments cut at the extension boundary (or mid-domain), separated by
//!   a configurable delay, so inline DPI cannot reassemble the SNI.
//!
//! New interceptor-based methods only need to implement this trait and be
//! registered in [`build_method`].  New socket-based methods must be wired
//! directly into `proxy.rs` instead.

pub mod composite;
pub mod fake_tls;
pub mod low_ttl;
pub mod mixed_case_sni;
pub mod sni;
pub mod sni_boundary_frag;
pub mod tcp_segmentation;
pub mod tls_padding;
pub mod tls_record_frag;
pub mod urg_sni_split;
pub mod wrong_ack;
pub mod wrong_checksum;
pub mod wrong_md5;
pub mod wrong_seq;
pub mod wrong_timestamp;

use std::sync::atomic::AtomicU8;
use std::sync::Arc;

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
    /// Forward unchanged and mark the bypass phase failed.
    AbortAndAccept,
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

    pub const fn abort_and_accept() -> Self {
        Self::AbortAndAccept
    }
}

/// A pluggable DPI-bypass technique.
pub trait BypassMethod: Send + Sync + 'static {
    /// Human-readable identifier (matches the `BYPASS_METHOD` config value, or
    /// a `" + "`-joined list for a composite).
    fn name(&self) -> String;

    /// Handle to the IPv4 TTL stamped by the `low_ttl` method.
    ///
    /// Returns `Some` only for the `low_ttl` method. `LOW_TTL_DISCOVER`
    /// probes never touch this handle — each probe flow carries its candidate
    /// TTL as a per-flow override — and the caller updates the handle exactly
    /// once, after a successful discovery (startup or rescan target switch),
    /// so the interceptor's method follows without rebuilding it. Returns
    /// `None` for all other methods.
    fn low_ttl_handle(&self) -> Option<Arc<AtomicU8>> {
        None
    }

    /// Called when the first outbound bare ACK of the handshake is observed.
    ///
    /// Methods that operate at this stage (e.g. `wrong_seq`, `wrong_ack`,
    /// `wrong_checksum`, `wrong_md5`, `wrong_seq_wrong_md5`,
    /// `wrong_timestamp`) stage their payload mutations here and return
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

/// Build the interceptor-based method chain from the application config.
///
/// Returns `Some(method)` when the configured list contains any
/// interceptor-based method (`wrong_seq`, `wrong_ack`, `wrong_checksum`,
/// `wrong_md5`, `wrong_timestamp`, `low_ttl`, `urg_sni_split`,
/// `tls_record_frag`) and `None` for socket-only lists (`["tls_frag"]`,
/// `["tls_padding"]`, `["mixed_case_sni"]`, `["sni_boundary_frag"]`, or
/// combinations) or empty lists.
/// Callers should validate the method list via
/// [`crate::config::Config::validate`] before calling this function.
pub fn build_method(cfg: &Config) -> Option<Box<dyn BypassMethod>> {
    let list = &cfg.BYPASS_METHOD;
    if list.is_empty() || list.is_socket_only() {
        return None;
    }
    let mut handshake: Vec<Box<dyn BypassMethod>> = Vec::new();
    let mut data: Option<Box<dyn BypassMethod>> = None;
    for name in list.iter() {
        match name {
            "tls_frag" => {}          // socket side; handled directly in proxy.rs
            "tls_padding" => {}       // socket side; handled directly in proxy.rs
            "mixed_case_sni" => {}    // socket side; handled directly in proxy.rs
            "sni_boundary_frag" => {} // socket side; handled directly in proxy.rs
            "tls_record_frag" => data = Some(Box::new(tls_record_frag::TlsRecordFrag::new(cfg))),
            "wrong_seq" => handshake.push(Box::new(wrong_seq::WrongSeq::new(cfg))),
            "wrong_ack" => handshake.push(Box::new(wrong_ack::WrongAck::new(cfg))),
            "wrong_checksum" => handshake.push(Box::new(wrong_checksum::WrongChecksum::new(cfg))),
            "wrong_md5" => handshake.push(Box::new(wrong_md5::WrongMd5::new(cfg))),
            "wrong_timestamp" => {
                handshake.push(Box::new(wrong_timestamp::WrongTimestamp::new(cfg)))
            }
            "low_ttl" => handshake.push(Box::new(low_ttl::LowTtl::new(cfg))),
            "urg_sni_split" => handshake.push(Box::new(urg_sni_split::UrgSniSplit::new(cfg))),
            _ => return None,
        }
    }
    Some(Box::new(
        composite::CompositeMethod::new(
            handshake,
            data,
            list.contains("tls_frag"),
            list.contains("tls_padding"),
        )
        .with_mixed_case_sni(list.contains("mixed_case_sni"))
        .with_sni_boundary_split(list.contains("sni_boundary_frag")),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_method(method_line: &str) -> Config {
        toml::from_str(&format!(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               {method_line}"#
        ))
        .unwrap()
    }

    #[test]
    fn build_wrong_checksum_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "wrong_checksum""#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_checksum");
    }

    #[test]
    fn build_wrong_ack_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "wrong_ack""#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_ack");
    }

    #[test]
    fn build_wrong_md5_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "wrong_md5""#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_md5");
    }

    #[test]
    fn build_low_ttl_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "low_ttl""#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "low_ttl");
    }

    #[test]
    fn build_wrong_seq_wrong_md5_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "wrong_seq_wrong_md5""#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq + wrong_md5");
    }

    #[test]
    fn build_wrong_md5_tls_frag_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "wrong_md5_tls_frag""#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_md5 + tls_frag");
    }

    #[test]
    fn build_wrong_timestamp_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "wrong_timestamp""#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_timestamp");
    }

    #[test]
    fn build_wrong_seq_tls_frag_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "wrong_seq_tls_frag""#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq + tls_frag");
    }

    #[test]
    fn build_wrong_seq_tls_record_frag_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "wrong_seq_tls_record_frag""#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq + tls_record_frag");
    }

    #[test]
    fn build_urg_sni_split_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "urg_sni_split""#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "urg_sni_split");
    }

    #[test]
    fn build_wrong_seq_tls_padding_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["wrong_seq", "tls_padding"]"#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq + tls_padding");
    }

    #[test]
    fn socket_padding_method_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "tls_padding""#);
        assert!(build_method(&cfg).is_none());
    }

    #[test]
    fn socket_method_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "tls_frag""#);
        assert!(build_method(&cfg).is_none());
    }

    #[test]
    fn builds_composite_for_list() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["wrong_seq", "low_ttl"]"#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq + low_ttl");
    }

    #[test]
    fn socket_list_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["tls_frag"]"#);
        assert!(build_method(&cfg).is_none());
    }

    #[test]
    fn socket_mixed_case_method_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "mixed_case_sni""#);
        assert!(build_method(&cfg).is_none());
    }

    #[test]
    fn builds_composite_with_mixed_case_sni() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["wrong_seq", "mixed_case_sni"]"#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq + mixed_case_sni");
    }

    #[test]
    fn build_wrong_seq_sni_boundary_frag_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["wrong_seq", "sni_boundary_frag"]"#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq + sni_boundary_frag");
    }

    #[test]
    fn socket_sni_boundary_frag_method_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "sni_boundary_frag""#);
        assert!(build_method(&cfg).is_none());
    }

    #[test]
    fn socket_list_with_sni_boundary_frag_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["sni_boundary_frag", "tls_padding"]"#);
        assert!(build_method(&cfg).is_none());
    }
}
