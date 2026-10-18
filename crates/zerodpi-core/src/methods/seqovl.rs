//! `seqovl` bypass: TCP sequence overlap.
//!
//! ## How it works
//!
//! The first outbound data packet (the real ClientHello) is split into
//! `SEQOVL_SEGMENTS` TCP segments with correct sequence numbers, and the
//! segment emitted *first* additionally carries `SEQOVL_SIZE` fake bytes in
//! front of its payload with its TCP sequence number rewound by that many
//! bytes. The fake bytes therefore occupy the stream range immediately before
//! that segment's real first byte.
//!
//! What happens at the destination depends on the emission order:
//!
//! - **Ordered split** (`SEQOVL_REVERSE = false`, the default). The prefix
//!   starts below the server's `rcv_nxt`, so every TCP stack trims it and the
//!   real bytes are accepted unchanged.
//! - **Reverse split** (`SEQOVL_REVERSE = true`). The prefix lands inside the
//!   range covered by the segment emitted afterwards, which then overwrites it
//!   (Unix hosts keep the last received copy). The prefix must be smaller than
//!   a segment for this to be safe; otherwise it is omitted. Servers that keep
//!   the *first* received copy of overlapping data (notably Windows) see the
//!   corrupted stream, so this variant is host-O/S-dependent.
//!
//! Either way the destination's TCP stack reconstructs the original stream,
//! while a DPI that reassembles the flow by concatenating segment payloads
//! sees the fake bytes spliced into the ClientHello — the record length field
//! and handshake header are shifted, so the SNI can no longer be extracted.
//! Unlike the fake-packet family (`wrong_seq`, `low_ttl`, `fake_tls`) this
//! needs no out-of-window decoy, so it keeps working on DPIs that validate
//! sequence numbers strictly. The real ClientHello bytes are never replaced —
//! the SNI is preserved, which makes it usable in `ip_bypass_plus` mode.
//!
//! The method only stages [`PacketView::disorder_spec`]; the platform backend
//! splits the rebuilt packet and splices the prefix (see
//! [`crate::tcp_segment::split_tcp_payload`]).
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `SEQOVL_SIZE` | `usize \| None` | `None` | Fake prefix bytes; `None` uses [`DEFAULT_SEQOVL_SIZE`], `0` disables the overlap. |
//! | `SEQOVL_PATTERN` | hex string | `None` | Fixed prefix; `None` = random per connection. Also selects the size when `SEQOVL_SIZE` is omitted. |
//! | `SEQOVL_SEGMENTS` | `usize` | `2` | Number of segments (2 or 3). |
//! | `SEQOVL_REVERSE` | `bool` | `false` | Reverse (non-monotonic) emission order. |
//! | `SEQOVL_DELAY_MS` | `u64` | `0` | Delay between segment emissions. |

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::config::{Config, DEFAULT_SEQOVL_SIZE};
use crate::flow::FlowState;
use crate::interceptor::{DisorderSpec, OverlapFake, PacketView};

pub struct Seqovl {
    /// Number of segments to split the first data packet into (2 or 3).
    segments: usize,
    /// Emit segments in reverse (non-monotonic sequence) order.
    reverse: bool,
    /// Delay in milliseconds between consecutive segment emissions.
    delay_ms: u64,
    /// Fake prefix description; `None` disables the overlap and leaves a
    /// plain ordered split.
    overlap: Option<OverlapFake>,
}

impl Seqovl {
    pub fn new(cfg: &Config) -> Self {
        Self {
            segments: cfg.SEQOVL_SEGMENTS,
            reverse: cfg.SEQOVL_REVERSE,
            delay_ms: cfg.SEQOVL_DELAY_MS,
            overlap: overlap_from_config(cfg, DEFAULT_SEQOVL_SIZE),
        }
    }
}

impl BypassMethod for Seqovl {
    fn name(&self) -> String {
        "seqovl".into()
    }

    /// Returns `PassThrough` — this method operates on the data stage, not the
    /// handshake-complete ACK. The handler sets `waiting_for_data` and calls
    /// [`on_first_data_packet`] instead.
    ///
    /// [`on_first_data_packet`]: Seqovl::on_first_data_packet
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
                overlap: self.overlap.clone(),
            });
            trace!(
                target = "zerodpi::seqovl",
                segments = self.segments,
                reverse = self.reverse,
                delay_ms = self.delay_ms,
                overlap_bytes = self.overlap.as_ref().map(|o| o.bytes).unwrap_or(0),
                fixed_pattern = self.overlap.as_ref().is_some_and(|o| o.pattern.is_some()),
                payload_len = pkt.payload_len,
                "staged TCP sequence overlap"
            );
        } else {
            trace!(
                target = "zerodpi::seqovl",
                segments = self.segments,
                payload_len = pkt.payload_len,
                "payload too small to split; not staging"
            );
        }

        MethodAction::emit_and_complete()
    }
}

/// Build the overlap description from the `SEQOVL_*` config group.
///
/// `default_when_unset` is the prefix size to use when `SEQOVL_SIZE` is
/// omitted *and* no pattern is configured: the standalone `seqovl` method
/// passes [`DEFAULT_SEQOVL_SIZE`], while the `disorder` modifier passes `0` so
/// that existing `disorder` configurations never gain an overlap silently.
///
/// A configured `SEQOVL_PATTERN` always enables the overlap and, when
/// `SEQOVL_SIZE` is omitted, its length selects the prefix size.
/// An explicit `SEQOVL_SIZE = 0` disables the overlap everywhere.
pub(crate) fn overlap_from_config(cfg: &Config, default_when_unset: usize) -> Option<OverlapFake> {
    let pattern = cfg
        .SEQOVL_PATTERN
        .as_deref()
        .and_then(|raw| parse_hex_pattern(raw).ok())
        .map(Arc::<[u8]>::from);

    let bytes = match cfg.SEQOVL_SIZE {
        Some(0) => return None,
        Some(size) => size,
        None => pattern.as_ref().map_or(default_when_unset, |p| p.len()),
    };
    if bytes == 0 {
        return None;
    }

    Some(OverlapFake {
        bytes,
        pattern,
        seed: fresh_seed(),
    })
}

/// Parse a hex prefix pattern such as `"0x1603"`, `"1603"`, or
/// `"16:03:03:01"`.
///
/// An optional `0x`/`0X` prefix is accepted, and `:`, `-`, `_`, and spaces are
/// ignored as grouping separators. The remaining digits must be an even,
/// non-zero count of valid hex digits.
pub fn parse_hex_pattern(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    let body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let digits: Vec<u8> = body
        .bytes()
        .filter(|byte| !matches!(byte, b':' | b'-' | b'_' | b' '))
        .collect();

    if digits.is_empty() {
        return Err("pattern is empty".into());
    }
    if digits.len() % 2 != 0 {
        return Err(format!(
            "pattern has an odd number of hex digits ({})",
            digits.len()
        ));
    }

    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!("invalid hex digit '{}'", other as char)),
    }
}

/// Fresh per-connection seed for the pseudo-random overlap pattern.
///
/// The quality bar is "unpredictable to a DPI", not cryptographic secrecy: the
/// pattern is emitted on the wire in clear, it only must not be a constant.
fn fresh_seed() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::interceptor::{Direction, TcpFlags};

    fn default_cfg() -> Config {
        toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap()
    }

    fn cfg_with(extra: &str) -> Config {
        let cfg: Config = toml::from_str(&format!(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "seqovl"
               {extra}"#
        ))
        .unwrap();
        cfg.validate().unwrap();
        cfg
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

    fn leak_payload(len: usize) -> &'static [u8] {
        Box::leak(vec![0xABu8; len].into_boxed_slice())
    }

    // -----------------------------------------------------------------------
    // parse_hex_pattern
    // -----------------------------------------------------------------------

    #[test]
    fn parses_hex_with_and_without_prefix() {
        assert_eq!(parse_hex_pattern("0x1603").unwrap(), vec![0x16, 0x03]);
        assert_eq!(parse_hex_pattern("1603").unwrap(), vec![0x16, 0x03]);
        assert_eq!(parse_hex_pattern("0X16FF").unwrap(), vec![0x16, 0xFF]);
    }

    #[test]
    fn parses_hex_with_separators() {
        for input in ["16:03:03", "16-03-03", "16_03_03", "16 03 03"] {
            assert_eq!(
                parse_hex_pattern(input).unwrap(),
                vec![0x16, 0x03, 0x03],
                "input {input}"
            );
        }
    }

    #[test]
    fn rejects_invalid_hex_patterns() {
        for input in ["", "0x", "16:0", "zz", "0x1"] {
            assert!(
                parse_hex_pattern(input).is_err(),
                "input {input} should be rejected"
            );
        }
    }

    // -----------------------------------------------------------------------
    // overlap_from_config resolution
    // -----------------------------------------------------------------------

    #[test]
    fn unset_size_uses_the_method_default() {
        let cfg = default_cfg();
        let overlap = overlap_from_config(&cfg, DEFAULT_SEQOVL_SIZE).unwrap();
        assert_eq!(overlap.bytes, DEFAULT_SEQOVL_SIZE);
        assert!(overlap.pattern.is_none(), "default pattern is random");

        // The disorder modifier passes 0 and therefore stays disabled.
        assert_eq!(overlap_from_config(&cfg, 0), None);
    }

    #[test]
    fn explicit_zero_disables_the_overlap() {
        let cfg = cfg_with("SEQOVL_SIZE = 0");
        assert_eq!(overlap_from_config(&cfg, DEFAULT_SEQOVL_SIZE), None);
        assert!(Seqovl::new(&cfg).overlap.is_none());
    }

    #[test]
    fn pattern_selects_the_size_when_unset() {
        let cfg = cfg_with(r#"SEQOVL_PATTERN = "0x1603""#);
        let overlap = overlap_from_config(&cfg, 0).unwrap();
        assert_eq!(overlap.bytes, 2);
        assert_eq!(overlap.pattern.as_deref(), Some(&[0x16, 0x03][..]));
    }

    #[test]
    fn explicit_size_and_pattern_agree() {
        let cfg = cfg_with(
            r#"SEQOVL_SIZE = 4
               SEQOVL_PATTERN = "de:ad:be:ef""#,
        );
        let overlap = overlap_from_config(&cfg, 0).unwrap();
        assert_eq!(overlap.bytes, 4);
        assert_eq!(
            overlap.pattern.as_deref(),
            Some(&[0xDE, 0xAD, 0xBE, 0xEF][..])
        );
    }

    // -----------------------------------------------------------------------
    // BypassMethod integration
    // -----------------------------------------------------------------------

    #[test]
    fn handshake_ack_hook_is_passthrough() {
        let method = Seqovl::new(&default_cfg());
        let state = FlowState::new(vec![], None);
        let mut pkt = data_pkt(&[]);
        let action = method.on_handshake_complete_ack(&state, &mut pkt);
        assert_eq!(action, MethodAction::PassThrough);
        assert_eq!(pkt.disorder_spec, None);
    }

    #[test]
    fn stages_overlap_spec_and_completes() {
        let cfg = cfg_with("SEQOVL_SIZE = 8");
        let method = Seqovl::new(&cfg);
        let state = FlowState::new(vec![], None);
        let payload = leak_payload(517);
        let mut pkt = data_pkt(payload);

        let action = method.on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        let spec = pkt.disorder_spec.as_ref().unwrap();
        assert_eq!(spec.segments, 2);
        assert!(!spec.reverse, "ordered emission is the default");
        assert_eq!(spec.delay_ms, 0);
        let overlap = spec.overlap.as_ref().unwrap();
        assert_eq!(overlap.bytes, 8);
        assert_eq!(overlap.materialize().len(), 8);
        // The real ClientHello bytes are untouched — the SNI is preserved.
        assert!(pkt.new_payload.is_none());
        assert_eq!(pkt.new_seq, None);
    }

    #[test]
    fn reverse_and_delay_are_staged() {
        let cfg = cfg_with(
            r#"SEQOVL_SIZE = 4
               SEQOVL_SEGMENTS = 3
               SEQOVL_REVERSE = true
               SEQOVL_DELAY_MS = 12"#,
        );
        let state = FlowState::new(vec![], None);
        let payload = leak_payload(517);
        let mut pkt = data_pkt(payload);

        Seqovl::new(&cfg).on_first_data_packet(&state, &mut pkt);

        let spec = pkt.disorder_spec.as_ref().unwrap();
        assert_eq!(spec.segments, 3);
        assert!(spec.reverse);
        assert_eq!(spec.delay_ms, 12);
        assert_eq!(spec.overlap.as_ref().unwrap().bytes, 4);
    }

    #[test]
    fn small_packet_is_not_staged_but_completes() {
        let cfg = cfg_with("SEQOVL_SIZE = 8");
        let state = FlowState::new(vec![], None);
        let mut pkt = data_pkt(&[0x16]); // 1 byte < 2 segments

        let action = Seqovl::new(&cfg).on_first_data_packet(&state, &mut pkt);

        assert_eq!(action, MethodAction::emit_and_complete());
        assert_eq!(pkt.disorder_spec, None);
    }

    #[test]
    fn disabled_overlap_still_splits() {
        let cfg = cfg_with("SEQOVL_SIZE = 0");
        let state = FlowState::new(vec![], None);
        let payload = leak_payload(517);
        let mut pkt = data_pkt(payload);

        Seqovl::new(&cfg).on_first_data_packet(&state, &mut pkt);

        let spec = pkt.disorder_spec.as_ref().unwrap();
        assert_eq!(spec.overlap, None);
        assert_eq!(spec.segments, 2);
    }

    #[test]
    fn random_pattern_differs_per_construction() {
        let cfg = cfg_with("SEQOVL_SIZE = 16");
        let first = Seqovl::new(&cfg).overlap.unwrap().materialize();
        let second = Seqovl::new(&cfg).overlap.unwrap().materialize();
        assert_eq!(first.len(), 16);
        assert_eq!(second.len(), 16);
        assert_ne!(first, second, "per-connection seeds must vary");
    }
}
