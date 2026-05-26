//! Linux backend: NFQUEUE-based packet interception.
//!
//! We install two `iptables` rules that funnel IPv4 TCP packets between the
//! local interface IP and the configured upstream into a netfilter queue.
//! For each captured packet we run the user-provided [`PacketHandler`] and
//! either accept the original bytes or accept a *modified* payload (with
//! IP/TCP checksums recomputed) — this is the "modify outbound packet by
//! replacing payload" path used by the `wrong_seq` bypass.

use std::io::ErrorKind;
use std::process::Command;

use anyhow::{Context, Result};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use nfq::{Queue, Verdict as NfqVerdict};
use tracing::{debug, info, warn};

use zerodpi_core::interceptor::{
    Direction, FilterSpec, PacketHandler, PacketInterceptor, PacketView, TcpFlags, Verdict,
};

const HOOK_LOCAL_IN: u8 = 1;
const HOOK_LOCAL_OUT: u8 = 3;

pub struct NfqInterceptor {
    queue: Queue,
    _rules: IptablesGuard,
}

impl PacketInterceptor for NfqInterceptor {
    fn open(filter: FilterSpec) -> Result<Self> {
        let queue_num = filter.queue_num;
        let rules = IptablesGuard::install(&filter).context("install iptables rules")?;

        let mut queue = Queue::open().context("open NFQUEUE")?;
        queue.bind(queue_num).context("bind NFQUEUE")?;
        // Copy entire packet so we can modify it.
        queue
            .set_copy_range(queue_num, 0xffff)
            .context("set NFQUEUE copy range")?;
        queue
            .set_fail_open(queue_num, false)
            .context("set NFQUEUE fail_open")?;

        info!(queue_num, "NFQUEUE bound");
        Ok(Self {
            queue,
            _rules: rules,
        })
    }

    fn run<H: PacketHandler>(mut self, mut handler: H) -> Result<()> {
        loop {
            let mut msg = match self.queue.recv() {
                Ok(m) => m,
                Err(e) if e.kind() == ErrorKind::Interrupted => {
                    debug!(error = %e, "NFQUEUE recv interrupted; retrying");
                    continue;
                }
                Err(e) => {
                    return Err(e).context("NFQUEUE recv");
                }
            };
            let direction = match msg.get_hook() {
                HOOK_LOCAL_OUT => Direction::Outbound,
                HOOK_LOCAL_IN => Direction::Inbound,
                other => {
                    debug!(hook = other, "unexpected NFQUEUE hook; accepting");
                    msg.set_verdict(NfqVerdict::Accept);
                    let _ = self.queue.verdict(msg);
                    continue;
                }
            };

            let payload = msg.get_payload();
            let (mut view, layout) = match parse_view(direction, payload) {
                Ok(v) => v,
                Err(_) => {
                    // Not a TCP/IPv4 packet we understand — accept untouched.
                    msg.set_verdict(NfqVerdict::Accept);
                    let _ = self.queue.verdict(msg);
                    continue;
                }
            };

            let verdict = handler.on_packet(&mut view);
            match verdict {
                Verdict::Accept => {
                    msg.set_verdict(NfqVerdict::Accept);
                }
                Verdict::Drop => {
                    msg.set_verdict(NfqVerdict::Drop);
                }
                Verdict::AcceptModified => {
                    let new_bytes = match build_modified(payload, &layout, &view) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error = %e, "failed to build modified packet; accepting original");
                            msg.set_verdict(NfqVerdict::Accept);
                            let _ = self.queue.verdict(msg);
                            continue;
                        }
                    };
                    msg.set_payload(new_bytes);
                    msg.set_verdict(NfqVerdict::Accept);
                }
            }
            if let Err(e) = self.queue.verdict(msg) {
                warn!(error = %e, "NFQUEUE verdict failed");
            }
        }
    }
}

/// Parsed offsets inside the captured IPv4+TCP buffer.
struct PacketLayout {
    ip_hdr_len: usize,
    tcp_hdr_len: usize,
    payload_off: usize,
    total_len: usize,
}

fn parse_view<'a>(direction: Direction, buf: &'a [u8]) -> Result<(PacketView<'a>, PacketLayout)> {
    let ip = Ipv4HeaderSlice::from_slice(buf).context("parse ipv4")?;
    if ip.protocol() != etherparse::IpNumber::TCP {
        anyhow::bail!("not tcp");
    }
    let ip_hdr_len = ip.slice().len();
    let tcp = TcpHeaderSlice::from_slice(&buf[ip_hdr_len..]).context("parse tcp")?;
    let tcp_hdr_len = tcp.slice().len();
    let total_len = ip.total_len() as usize;
    let payload_off = ip_hdr_len + tcp_hdr_len;
    let payload_len = total_len.saturating_sub(payload_off);

    let view = PacketView {
        direction,
        src_ip: ip.source_addr(),
        dst_ip: ip.destination_addr(),
        src_port: tcp.source_port(),
        dst_port: tcp.destination_port(),
        seq: tcp.sequence_number(),
        ack: tcp.acknowledgment_number(),
        flags: TcpFlags {
            syn: tcp.syn(),
            ack: tcp.ack(),
            psh: tcp.psh(),
            rst: tcp.rst(),
            fin: tcp.fin(),
        },
        payload_len,
        payload: &buf[payload_off..payload_off + payload_len],
        new_seq: None,
        new_flags: None,
        new_payload: None,
        bump_ipv4_ident: false,
        corrupt_tcp_checksum_delta: None,
    };
    let layout = PacketLayout {
        ip_hdr_len,
        tcp_hdr_len,
        payload_off,
        total_len,
    };
    Ok((view, layout))
}

fn build_modified(orig: &[u8], layout: &PacketLayout, view: &PacketView<'_>) -> Result<Vec<u8>> {
    let mut ip_hdr = etherparse::Ipv4Header::from_slice(&orig[..layout.ip_hdr_len])?.0;
    let mut tcp_hdr = etherparse::TcpHeader::from_slice(
        &orig[layout.ip_hdr_len..layout.ip_hdr_len + layout.tcp_hdr_len],
    )?
    .0;

    let new_payload: &[u8] = match view.new_payload.as_deref() {
        Some(p) => p,
        None => &orig[layout.payload_off..layout.total_len],
    };

    if let Some(seq) = view.new_seq {
        tcp_hdr.sequence_number = seq;
    }
    if let Some(flags) = view.new_flags {
        tcp_hdr.syn = flags.syn;
        tcp_hdr.ack = flags.ack;
        tcp_hdr.psh = flags.psh;
        tcp_hdr.rst = flags.rst;
        tcp_hdr.fin = flags.fin;
    }
    if view.bump_ipv4_ident {
        ip_hdr.identification = ip_hdr.identification.wrapping_add(1);
    }

    // Recompute IPv4 total length and checksums.
    let new_ip_payload_len = layout.tcp_hdr_len + new_payload.len();
    ip_hdr.set_payload_len(new_ip_payload_len)?;
    ip_hdr.header_checksum = ip_hdr.calc_header_checksum();
    tcp_hdr.checksum = tcp_hdr.calc_checksum_ipv4(&ip_hdr, new_payload)?;
    if let Some(delta) = view.corrupt_tcp_checksum_delta {
        tcp_hdr.checksum = tcp_hdr.checksum.wrapping_add(delta);
    }

    let mut out = Vec::with_capacity(layout.ip_hdr_len + layout.tcp_hdr_len + new_payload.len());
    ip_hdr.write(&mut out)?;
    tcp_hdr.write(&mut out)?;
    out.extend_from_slice(new_payload);
    Ok(out)
}

// ---------------------- iptables rule management ----------------------

struct IptablesGuard {
    rules: Vec<Vec<String>>,
}

impl IptablesGuard {
    fn install(filter: &FilterSpec) -> Result<Self> {
        let iface = filter.interface_ip.to_string();
        let port = filter.remote_port.to_string();
        let q = filter.queue_num.to_string();

        let rules: Vec<Vec<String>> = match filter.remote_ip {
            Some(remote_ip) => {
                let remote = remote_ip.to_string();
                vec![
                    vec![
                        "OUTPUT".into(),
                        "-p".into(),
                        "tcp".into(),
                        "-s".into(),
                        iface.clone(),
                        "-d".into(),
                        remote.clone(),
                        "--dport".into(),
                        port.clone(),
                        "-j".into(),
                        "NFQUEUE".into(),
                        "--queue-num".into(),
                        q.clone(),
                        "--queue-bypass".into(),
                    ],
                    vec![
                        "INPUT".into(),
                        "-p".into(),
                        "tcp".into(),
                        "-s".into(),
                        remote,
                        "-d".into(),
                        iface,
                        "--sport".into(),
                        port,
                        "-j".into(),
                        "NFQUEUE".into(),
                        "--queue-num".into(),
                        q,
                        "--queue-bypass".into(),
                    ],
                ]
            }
            None => vec![
                vec![
                    "OUTPUT".into(),
                    "-p".into(),
                    "tcp".into(),
                    "-s".into(),
                    iface.clone(),
                    "--dport".into(),
                    port.clone(),
                    "-j".into(),
                    "NFQUEUE".into(),
                    "--queue-num".into(),
                    q.clone(),
                    "--queue-bypass".into(),
                ],
                vec![
                    "INPUT".into(),
                    "-p".into(),
                    "tcp".into(),
                    "-d".into(),
                    iface,
                    "--sport".into(),
                    port,
                    "-j".into(),
                    "NFQUEUE".into(),
                    "--queue-num".into(),
                    q,
                    "--queue-bypass".into(),
                ],
            ],
        };

        for rule in &rules {
            run_iptables("-A", rule).context("install iptables rule")?;
        }
        info!("iptables rules installed");
        Ok(Self { rules })
    }
}

impl Drop for IptablesGuard {
    fn drop(&mut self) {
        for rule in &self.rules {
            if let Err(e) = run_iptables("-D", rule) {
                warn!(error = %e, "failed to remove iptables rule");
            }
        }
        debug!("iptables rules removed");
    }
}

fn run_iptables(action: &str, rule_args: &[String]) -> Result<()> {
    let mut cmd = Command::new("iptables");
    cmd.arg(action);
    for a in rule_args {
        cmd.arg(a);
    }
    let status = cmd.status().context("spawn iptables")?;
    if !status.success() {
        anyhow::bail!("iptables {action} {:?} failed: {status}", rule_args);
    }
    Ok(())
}

// Re-export FilterSpec extension: backends in this crate need a queue_num.
// To keep `zerodpi-core` platform-agnostic we extend via a helper trait here.
// Currently a no-op since the field lives on FilterSpec directly.

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_view() -> PacketView<'static> {
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
                ..Default::default()
            },
            payload_len: 0,
            payload: &[],
            new_seq: Some(484),
            new_flags: Some(TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            }),
            new_payload: Some(vec![0xAB; 517]),
            bump_ipv4_ident: true,
            corrupt_tcp_checksum_delta: None,
        }
    }

    fn data_packet(payload: &[u8]) -> Vec<u8> {
        use etherparse::{IpNumber, Ipv4Header, TcpHeader};

        let mut ip = Ipv4Header::new(
            (20 + payload.len()).try_into().unwrap(),
            64,
            IpNumber::TCP,
            [10, 0, 0, 1],
            [1, 2, 3, 4],
        )
        .unwrap();
        ip.header_checksum = ip.calc_header_checksum();
        let mut tcp = TcpHeader::new(12345, 443, 1001, 65535);
        tcp.acknowledgment_number = 5001;
        tcp.ack = true;
        tcp.psh = true;
        tcp.checksum = tcp.calc_checksum_ipv4(&ip, payload).unwrap();

        let mut buf = Vec::new();
        ip.write(&mut buf).unwrap();
        tcp.write(&mut buf).unwrap();
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn parse_view_borrows_payload_bytes() {
        let payload = [0x16, 0x03, 0x03, 0x00, 0x01, 0xAA];
        let buf = data_packet(&payload);
        let (view, layout) = parse_view(Direction::Outbound, &buf).unwrap();

        assert_eq!(view.payload_len, payload.len());
        assert_eq!(view.payload, payload.as_slice());
        assert_eq!(layout.payload_off, 40);
    }

    #[test]
    fn round_trip_modified_packet_parses_back() {
        // Build a synthetic bare ACK and modify it.
        use etherparse::{IpNumber, Ipv4Header, TcpHeader};
        let mut ip = Ipv4Header::new(
            20, // payload len: just TCP header
            64,
            IpNumber::TCP,
            [10, 0, 0, 1],
            [1, 2, 3, 4],
        )
        .unwrap();
        ip.identification = 0x1234;
        ip.header_checksum = ip.calc_header_checksum();
        let mut tcp = TcpHeader::new(12345, 443, 1001, 65535);
        tcp.acknowledgment_number = 5001;
        tcp.ack = true;
        tcp.checksum = tcp.calc_checksum_ipv4(&ip, &[]).unwrap();

        let mut buf = Vec::new();
        ip.write(&mut buf).unwrap();
        tcp.write(&mut buf).unwrap();

        let layout = PacketLayout {
            ip_hdr_len: 20,
            tcp_hdr_len: 20,
            payload_off: 40,
            total_len: 40,
        };
        let view = make_view();
        let modified = build_modified(&buf, &layout, &view).unwrap();

        // Re-parse.
        let ip2 = Ipv4HeaderSlice::from_slice(&modified).unwrap();
        let tcp2 = TcpHeaderSlice::from_slice(&modified[ip2.slice().len()..]).unwrap();
        assert_eq!(ip2.identification(), 0x1235);
        assert_eq!(ip2.total_len() as usize, 20 + 20 + 517);
        assert_eq!(tcp2.sequence_number(), 484);
        assert!(tcp2.psh());
        assert!(tcp2.ack());
        // Checksum must verify
        let calculated = tcp2
            .to_header()
            .calc_checksum_ipv4(&ip2.to_header(), &modified[40..])
            .unwrap();
        assert_eq!(tcp2.checksum(), calculated);
    }

    #[test]
    fn tcp_checksum_can_be_corrupted_after_rebuild() {
        use etherparse::{IpNumber, Ipv4Header, TcpHeader};
        let mut ip = Ipv4Header::new(20, 64, IpNumber::TCP, [10, 0, 0, 1], [1, 2, 3, 4]).unwrap();
        ip.header_checksum = ip.calc_header_checksum();
        let mut tcp = TcpHeader::new(12345, 443, 1001, 65535);
        tcp.acknowledgment_number = 5001;
        tcp.ack = true;
        tcp.checksum = tcp.calc_checksum_ipv4(&ip, &[]).unwrap();

        let mut buf = Vec::new();
        ip.write(&mut buf).unwrap();
        tcp.write(&mut buf).unwrap();

        let layout = PacketLayout {
            ip_hdr_len: 20,
            tcp_hdr_len: 20,
            payload_off: 40,
            total_len: 40,
        };
        let mut view = make_view();
        view.corrupt_tcp_checksum_delta = Some(5);
        let modified = build_modified(&buf, &layout, &view).unwrap();

        let ip2 = Ipv4HeaderSlice::from_slice(&modified).unwrap();
        let tcp2 = TcpHeaderSlice::from_slice(&modified[ip2.slice().len()..]).unwrap();
        let calculated = tcp2
            .to_header()
            .calc_checksum_ipv4(&ip2.to_header(), &modified[40..])
            .unwrap();
        assert_eq!(tcp2.checksum(), calculated.wrapping_add(5));
    }
}
