//! Trait abstractions over the platform packet-interception layer.
//!
//! Concrete implementations live in `zerodpi-platform`:
//! - **Linux**: NFQUEUE; the verdict modifies the captured packet's payload.
//! - **Windows**: WinDivert; the captured `Packet` is mutated and reinjected.
//!
//! The intercept loop is driven entirely by the backend — the backend hands
//! every observed packet to a [`PacketHandler`] which inspects fields, may
//! request mutations, and returns a [`Verdict`].

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::flow::FlowTable;

/// Direction relative to the host running the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub fin: bool,
    pub urg: bool,
}

/// A read/write view of a captured TCP/IPv4 packet.
///
/// Backends construct this from their native packet representation and apply
/// the staged mutations (`new_*`, `replace_tcp_options`,
/// `append_tcp_options`, `bump_ipv4_ident`, `new_ipv4_ttl`,
/// `corrupt_tcp_checksum_delta`, `emit_original_after`) when the handler
/// returns [`Verdict::AcceptModified`].
#[derive(Debug, Clone)]
pub struct PacketView<'a> {
    pub direction: Direction,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    /// Length of the existing TCP payload (informational).
    pub payload_len: usize,
    /// Raw bytes of the existing TCP payload. Empty for zero-payload packets.
    /// Populated by the platform backend so that methods can read and repack
    /// the original data (e.g. `tls_record_frag`).
    pub payload: &'a [u8],
    /// Raw TCP option bytes from the captured packet.
    pub tcp_options: &'a [u8],

    // ---- staged mutations (applied only on `AcceptModified`) ----
    pub new_seq: Option<u32>,
    pub new_ack: Option<u32>,
    pub new_flags: Option<TcpFlags>,
    /// Override the TCP urgent pointer (RFC 793: offset from the segment's
    /// sequence number, one byte past the urgent data). Only meaningful when
    /// `new_flags` sets `urg`.
    pub new_urgent_pointer: Option<u16>,
    /// Replace the entire TCP payload with these bytes.
    pub new_payload: Option<Vec<u8>>,
    /// Replace the entire TCP options area with these raw bytes before any
    /// appended options are applied.
    pub replace_tcp_options: Option<Vec<u8>>,
    /// Raw TCP option bytes appended to the existing TCP options.
    ///
    /// Backends pad the final options to 32-bit alignment and reject packets
    /// whose TCP header would exceed 60 bytes.
    pub append_tcp_options: Vec<u8>,
    /// Increment IPv4 `identification` by 1 (mod 2^16).
    pub bump_ipv4_ident: bool,
    /// Add this value to the valid computed TCP checksum after normal packet
    /// rebuild/checksum calculation. `None` leaves the checksum valid.
    pub corrupt_tcp_checksum_delta: Option<u16>,
    /// When the verdict is `AcceptModified`, also emit the original
    /// unmodified packet after the modified one.
    ///
    /// Used by `fake_tls` (`FAKE_TLS_FORWARD_REAL`) to send the decoy record
    /// ahead of the real ClientHello. Backends without dual-emission support
    /// (e.g. no raw socket on Linux) fall back to single modified emission.
    pub emit_original_after: bool,
    /// Override the IPv4 Time-To-Live (TTL) field.
    ///
    /// Used by decoy-injection methods that want a fake packet to reach an
    /// inline DPI middlebox but expire before the destination server. Only
    /// affects IPv4 packets; IPv6 has a hop-limit field instead.
    pub new_ipv4_ttl: Option<u8>,
}

impl PacketView<'_> {
    /// True if this is a bare ACK (ACK set, no payload, no other control bits).
    pub fn is_bare_ack(&self) -> bool {
        self.flags.ack
            && !self.flags.syn
            && !self.flags.rst
            && !self.flags.fin
            && self.payload_len == 0
    }

    /// True if this is a SYN-ACK (no payload).
    pub fn is_syn_ack(&self) -> bool {
        self.flags.syn
            && self.flags.ack
            && !self.flags.rst
            && !self.flags.fin
            && self.payload_len == 0
    }

    /// True if this is a bare SYN (no payload, no ACK).
    pub fn is_bare_syn(&self) -> bool {
        self.flags.syn
            && !self.flags.ack
            && !self.flags.rst
            && !self.flags.fin
            && self.payload_len == 0
    }
}

/// Verdict returned to the backend after a handler runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Forward the original packet unchanged.
    Accept,
    /// Forward the packet with the staged mutations applied.
    AcceptModified,
    /// Drop the packet.
    Drop,
}

/// User-side packet-processing logic. Implemented by [`crate::methods::Handler`].
pub trait PacketHandler: Send + 'static {
    fn on_packet(&mut self, pkt: &mut PacketView<'_>) -> Verdict;
}

/// Backend-side filter description. Backends translate this to their native
/// filter language (WinDivert filter string, Linux firewall rules, etc.).
#[derive(Debug, Clone)]
pub struct FilterSpec {
    pub interface_ip: Ipv4Addr,
    /// When set, only packets to/from this remote IP are intercepted. When
    /// unset, packets to/from any remote IP on `remote_port` are intercepted.
    pub remote_ip: Option<Ipv4Addr>,
    pub remote_port: u16,
    /// Linux NFQUEUE queue number; ignored on backends that don't use it.
    pub queue_num: u16,
    /// Linux firewall rule backend used to feed packets into NFQUEUE; ignored
    /// on non-Linux backends.
    pub linux_firewall_backend: LinuxFirewallBackend,
    /// Optional internal ownership tag used for targeted crash recovery.
    /// This is never accepted from the Android helper IPC protocol.
    pub firewall_owner: Option<String>,
}

/// Linux firewall-rule manager used by the NFQUEUE backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LinuxFirewallBackend {
    /// Use legacy `iptables` commands. This is the backwards-compatible default.
    #[default]
    Iptables,
    /// Use `nft`/nftables commands.
    Nftables,
}

impl LinuxFirewallBackend {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "iptables" => Some(Self::Iptables),
            "nftables" => Some(Self::Nftables),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Iptables => "iptables",
            Self::Nftables => "nftables",
        }
    }
}

/// A platform packet-interception backend.
#[derive(Clone, Debug, Default)]
pub struct InterceptorShutdown {
    requested: Arc<AtomicBool>,
}

impl InterceptorShutdown {
    pub fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
    }

    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}

pub trait PacketInterceptor: Sized + Send + 'static {
    /// Open the interceptor with the given filter. Backend may install
    /// system rules here; they're removed in `Drop`.
    fn open(filter: FilterSpec) -> anyhow::Result<Self>;

    /// Run the intercept loop, calling `handler` for each captured packet.
    /// Returns when the underlying queue is closed or an unrecoverable
    /// error occurs.
    fn run<H: PacketHandler>(self, handler: H) -> anyhow::Result<()> {
        self.run_until(handler, InterceptorShutdown::default())
    }

    /// Run until the backend ends or `shutdown` is requested.
    fn run_until<H: PacketHandler>(
        self,
        handler: H,
        shutdown: InterceptorShutdown,
    ) -> anyhow::Result<()>;
}

/// Convenience: many handlers want shared access to the flow table.
pub trait FlowHandler: PacketHandler {
    fn flows(&self) -> FlowTable;
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn tcp_flags_has_urg_and_defaults_to_false() {
        let flags = TcpFlags::default();
        assert!(!flags.urg);
    }

    #[test]
    fn packet_view_emit_original_after_defaults_false() {
        let view = PacketView {
            direction: Direction::Outbound,
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            src_port: 12345,
            dst_port: 443,
            seq: 1001,
            ack: 5001,
            flags: TcpFlags::default(),
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
            emit_original_after: false,
            new_ipv4_ttl: None,
            new_urgent_pointer: None,
        };
        assert!(!view.emit_original_after);
    }
}
