//! Linux backend: NFQUEUE-based packet interception.
//!
//! We install firewall rules that funnel IPv4 TCP packets between the local
//! interface IP and the configured upstream into a netfilter queue. The rule
//! manager is selectable between iptables and nftables.
//! For each captured packet we run the user-provided [`PacketHandler`] and
//! either accept the original bytes or accept a *modified* payload (with
//! IP/TCP checksums recomputed) — this is the "modify outbound packet by
//! replacing payload" path used by the `wrong_seq` bypass.

use std::io::ErrorKind;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use nfq::{Queue, Verdict as NfqVerdict};
use tracing::{debug, info, warn};

use zerodpi_core::interceptor::{
    Direction, FilterSpec, LinuxFirewallBackend, PacketHandler, PacketInterceptor, PacketView,
    TcpFlags, Verdict,
};

const HOOK_LOCAL_IN: u8 = 1;
const HOOK_LOCAL_OUT: u8 = 3;

pub struct NfqInterceptor {
    queue: Queue,
    _rules: FirewallGuard,
}

impl PacketInterceptor for NfqInterceptor {
    fn open(filter: FilterSpec) -> Result<Self> {
        let queue_num = filter.queue_num;
        let rules = FirewallGuard::install(&filter).with_context(|| {
            format!(
                "install Linux firewall rules using {}",
                filter.linux_firewall_backend.as_str()
            )
        })?;

        let mut queue = Queue::open().context("open NFQUEUE")?;
        queue.bind(queue_num).context("bind NFQUEUE")?;
        // Copy entire packet so we can modify it.
        queue
            .set_copy_range(queue_num, 0xffff)
            .context("set NFQUEUE copy range")?;
        queue
            .set_fail_open(queue_num, false)
            .context("set NFQUEUE fail_open")?;

        info!(
            queue_num,
            firewall_backend = filter.linux_firewall_backend.as_str(),
            "NFQUEUE bound"
        );
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
    let tcp_options_off = ip_hdr_len + etherparse::TcpHeader::MIN_LEN;
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
        tcp_options: &buf[tcp_options_off..payload_off],
        new_seq: None,
        new_ack: None,
        new_flags: None,
        new_payload: None,
        replace_tcp_options: None,
        append_tcp_options: Vec::new(),
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
    if let Some(ack) = view.new_ack {
        tcp_hdr.acknowledgment_number = ack;
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
    if let Some(options) = view.replace_tcp_options.as_deref() {
        tcp_hdr
            .set_options_raw(options)
            .context("replace TCP options")?;
    }
    append_tcp_options(&mut tcp_hdr, &view.append_tcp_options)?;

    // Recompute IPv4 total length and checksums.
    let new_tcp_hdr_len = tcp_hdr.header_len();
    let new_ip_payload_len = new_tcp_hdr_len + new_payload.len();
    ip_hdr.set_payload_len(new_ip_payload_len)?;
    ip_hdr.header_checksum = ip_hdr.calc_header_checksum();
    tcp_hdr.checksum = tcp_hdr.calc_checksum_ipv4(&ip_hdr, new_payload)?;
    if let Some(delta) = view.corrupt_tcp_checksum_delta {
        tcp_hdr.checksum = tcp_hdr.checksum.wrapping_add(delta);
    }

    let mut out = Vec::with_capacity(layout.ip_hdr_len + new_tcp_hdr_len + new_payload.len());
    ip_hdr.write(&mut out)?;
    tcp_hdr.write(&mut out)?;
    out.extend_from_slice(new_payload);
    Ok(out)
}

fn append_tcp_options(tcp_hdr: &mut etherparse::TcpHeader, append: &[u8]) -> Result<()> {
    if append.is_empty() {
        return Ok(());
    }

    let original = tcp_hdr.options.as_slice();
    let raw_len = original.len() + append.len();
    let padded_len = (raw_len + 3) & !3;
    let max_options_len = etherparse::TcpHeader::MAX_LEN - etherparse::TcpHeader::MIN_LEN;
    if padded_len > max_options_len {
        anyhow::bail!(
            "TCP options would exceed maximum header size: existing={} append={} padded={}",
            original.len(),
            append.len(),
            padded_len
        );
    }

    let mut options = Vec::with_capacity(raw_len);
    options.extend_from_slice(original);
    options.extend_from_slice(append);
    tcp_hdr
        .set_options_raw(&options)
        .context("append TCP options")?;
    Ok(())
}

// ---------------------- firewall rule management ----------------------

enum FirewallGuard {
    Iptables { _guard: IptablesGuard },
    Nftables { _guard: NftablesGuard },
}

impl FirewallGuard {
    fn install(filter: &FilterSpec) -> Result<Self> {
        match filter.linux_firewall_backend {
            LinuxFirewallBackend::Iptables => {
                IptablesGuard::install(filter).map(|guard| Self::Iptables { _guard: guard })
            }
            LinuxFirewallBackend::Nftables => {
                NftablesGuard::install(filter).map(|guard| Self::Nftables { _guard: guard })
            }
        }
    }
}

// ---------------------- iptables rule management ----------------------

struct IptablesGuard {
    rules: Vec<Vec<String>>,
}

impl IptablesGuard {
    fn install(filter: &FilterSpec) -> Result<Self> {
        let rules = iptables_rules(filter);
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

fn iptables_rules(filter: &FilterSpec) -> Vec<Vec<String>> {
    let iface = filter.interface_ip.to_string();
    let port = filter.remote_port.to_string();
    let q = filter.queue_num.to_string();

    match filter.remote_ip {
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
    }
}

// ---------------------- nftables rule management ----------------------

const NFT_TABLE_FAMILY: &str = "inet";
const NFT_OUTPUT_CHAIN: &str = "output";
const NFT_INPUT_CHAIN: &str = "input";

static NFT_TABLE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct NftablesGuard {
    table_name: String,
}

impl NftablesGuard {
    fn install(filter: &FilterSpec) -> Result<Self> {
        let table_name = next_nft_table_name();
        let commands = nft_install_commands(&table_name, filter);
        for args in &commands {
            if let Err(e) = run_nft(args) {
                let _ = delete_nft_table(&table_name);
                return Err(e).context("install nftables rule");
            }
        }
        info!(table = %table_name, "nftables rules installed");
        Ok(Self { table_name })
    }
}

impl Drop for NftablesGuard {
    fn drop(&mut self) {
        if let Err(e) = delete_nft_table(&self.table_name) {
            warn!(error = %e, table = %self.table_name, "failed to remove nftables table");
        } else {
            debug!(table = %self.table_name, "nftables table removed");
        }
    }
}

fn next_nft_table_name() -> String {
    let id = NFT_TABLE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("zerodpi_{}_{}", std::process::id(), id)
}

fn nft_install_commands(table_name: &str, filter: &FilterSpec) -> Vec<Vec<String>> {
    vec![
        strings(&["add", "table", NFT_TABLE_FAMILY, table_name]),
        nft_add_chain_args(table_name, NFT_OUTPUT_CHAIN, "output"),
        nft_add_chain_args(table_name, NFT_INPUT_CHAIN, "input"),
        nft_add_rule_args(table_name, Direction::Outbound, filter),
        nft_add_rule_args(table_name, Direction::Inbound, filter),
    ]
}

fn nft_add_chain_args(table_name: &str, chain: &str, hook: &str) -> Vec<String> {
    strings(&[
        "add",
        "chain",
        NFT_TABLE_FAMILY,
        table_name,
        chain,
        "{",
        "type",
        "filter",
        "hook",
        hook,
        "priority",
        "0",
        ";",
        "policy",
        "accept",
        ";",
        "}",
    ])
}

fn nft_add_rule_args(table_name: &str, direction: Direction, filter: &FilterSpec) -> Vec<String> {
    let iface = filter.interface_ip.to_string();
    let port = filter.remote_port.to_string();
    let q = filter.queue_num.to_string();
    let mut args = strings(&["add", "rule", NFT_TABLE_FAMILY, table_name]);

    match direction {
        Direction::Outbound => {
            args.push(NFT_OUTPUT_CHAIN.into());
            args.extend(strings(&["ip", "saddr", &iface]));
            if let Some(remote_ip) = filter.remote_ip {
                let remote = remote_ip.to_string();
                args.extend(strings(&["ip", "daddr", &remote]));
            }
            args.extend(strings(&[
                "tcp", "dport", &port, "queue", "num", &q, "bypass",
            ]));
        }
        Direction::Inbound => {
            args.push(NFT_INPUT_CHAIN.into());
            if let Some(remote_ip) = filter.remote_ip {
                let remote = remote_ip.to_string();
                args.extend(strings(&["ip", "saddr", &remote]));
            }
            args.extend(strings(&["ip", "daddr", &iface]));
            args.extend(strings(&[
                "tcp", "sport", &port, "queue", "num", &q, "bypass",
            ]));
        }
    }

    args
}

fn delete_nft_table(table_name: &str) -> Result<()> {
    run_nft(&strings(&["delete", "table", NFT_TABLE_FAMILY, table_name]))
}

fn run_nft(args: &[String]) -> Result<()> {
    let status = Command::new("nft")
        .args(args)
        .status()
        .context("spawn nft")?;
    if !status.success() {
        anyhow::bail!("nft {:?} failed: {status}", args);
    }
    Ok(())
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).into()).collect()
}

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
            tcp_options: &[],
            new_seq: Some(484),
            new_ack: None,
            new_flags: Some(TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            }),
            new_payload: Some(vec![0xAB; 517]),
            replace_tcp_options: None,
            append_tcp_options: Vec::new(),
            bump_ipv4_ident: true,
            corrupt_tcp_checksum_delta: None,
        }
    }

    fn make_filter(remote_ip: Option<Ipv4Addr>) -> FilterSpec {
        FilterSpec {
            interface_ip: Ipv4Addr::new(10, 0, 0, 1),
            remote_ip,
            remote_port: 443,
            queue_num: 7,
            linux_firewall_backend: LinuxFirewallBackend::Iptables,
        }
    }

    #[test]
    fn iptables_rules_without_remote_match_nfqueue_shape() {
        let rules = iptables_rules(&make_filter(None));

        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[0],
            strings(&[
                "OUTPUT",
                "-p",
                "tcp",
                "-s",
                "10.0.0.1",
                "--dport",
                "443",
                "-j",
                "NFQUEUE",
                "--queue-num",
                "7",
                "--queue-bypass",
            ])
        );
        assert_eq!(
            rules[1],
            strings(&[
                "INPUT",
                "-p",
                "tcp",
                "-d",
                "10.0.0.1",
                "--sport",
                "443",
                "-j",
                "NFQUEUE",
                "--queue-num",
                "7",
                "--queue-bypass",
            ])
        );
    }

    #[test]
    fn nftables_commands_without_remote_use_inet_nfqueue_bypass() {
        let commands = nft_install_commands("zerodpi_test", &make_filter(None));

        assert_eq!(commands.len(), 5);
        assert_eq!(
            commands[0],
            strings(&["add", "table", "inet", "zerodpi_test"])
        );
        assert_eq!(
            commands[3],
            strings(&[
                "add",
                "rule",
                "inet",
                "zerodpi_test",
                "output",
                "ip",
                "saddr",
                "10.0.0.1",
                "tcp",
                "dport",
                "443",
                "queue",
                "num",
                "7",
                "bypass",
            ])
        );
        assert_eq!(
            commands[4],
            strings(&[
                "add",
                "rule",
                "inet",
                "zerodpi_test",
                "input",
                "ip",
                "daddr",
                "10.0.0.1",
                "tcp",
                "sport",
                "443",
                "queue",
                "num",
                "7",
                "bypass",
            ])
        );
    }

    #[test]
    fn nftables_commands_with_remote_pin_both_directions() {
        let commands = nft_install_commands(
            "zerodpi_test",
            &make_filter(Some(Ipv4Addr::new(1, 2, 3, 4))),
        );

        assert_eq!(
            commands[3],
            strings(&[
                "add",
                "rule",
                "inet",
                "zerodpi_test",
                "output",
                "ip",
                "saddr",
                "10.0.0.1",
                "ip",
                "daddr",
                "1.2.3.4",
                "tcp",
                "dport",
                "443",
                "queue",
                "num",
                "7",
                "bypass",
            ])
        );
        assert_eq!(
            commands[4],
            strings(&[
                "add",
                "rule",
                "inet",
                "zerodpi_test",
                "input",
                "ip",
                "saddr",
                "1.2.3.4",
                "ip",
                "daddr",
                "10.0.0.1",
                "tcp",
                "sport",
                "443",
                "queue",
                "num",
                "7",
                "bypass",
            ])
        );
    }

    fn data_packet(payload: &[u8]) -> Vec<u8> {
        data_packet_with_options(payload, &[])
    }

    fn data_packet_with_options(payload: &[u8], options: &[u8]) -> Vec<u8> {
        use etherparse::{IpNumber, Ipv4Header, TcpHeader};

        let mut tcp = TcpHeader::new(12345, 443, 1001, 65535);
        tcp.acknowledgment_number = 5001;
        tcp.ack = true;
        tcp.psh = true;
        tcp.set_options_raw(options).unwrap();
        let mut ip = Ipv4Header::new(
            (tcp.header_len() + payload.len()).try_into().unwrap(),
            64,
            IpNumber::TCP,
            [10, 0, 0, 1],
            [1, 2, 3, 4],
        )
        .unwrap();
        ip.header_checksum = ip.calc_header_checksum();
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

    fn timestamp_option(tsval: u32, tsecr: u32) -> Vec<u8> {
        let mut option = vec![8, 10];
        option.extend_from_slice(&tsval.to_be_bytes());
        option.extend_from_slice(&tsecr.to_be_bytes());
        option
    }

    #[test]
    fn parse_view_borrows_tcp_option_bytes() {
        let options = timestamp_option(100, 77);
        let buf = data_packet_with_options(&[], &options);
        let (view, layout) = parse_view(Direction::Outbound, &buf).unwrap();

        assert_eq!(layout.tcp_hdr_len, 32);
        assert_eq!(layout.payload_off, 52);
        assert_eq!(&view.tcp_options[..options.len()], options.as_slice());
        assert_eq!(&view.tcp_options[options.len()..], &[0, 0]);
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

    #[test]
    fn tcp_ack_number_can_be_rewritten_after_rebuild() {
        let buf = data_packet(&[]);
        let layout = PacketLayout {
            ip_hdr_len: 20,
            tcp_hdr_len: 20,
            payload_off: 40,
            total_len: 40,
        };
        let mut view = make_view();
        view.new_seq = None;
        view.new_ack = Some(4999);
        let modified = build_modified(&buf, &layout, &view).unwrap();

        let ip2 = Ipv4HeaderSlice::from_slice(&modified).unwrap();
        let tcp2 = TcpHeaderSlice::from_slice(&modified[ip2.slice().len()..]).unwrap();
        assert_eq!(tcp2.sequence_number(), 1001);
        assert_eq!(tcp2.acknowledgment_number(), 4999);
        let calculated = tcp2
            .to_header()
            .calc_checksum_ipv4(&ip2.to_header(), &modified[40..])
            .unwrap();
        assert_eq!(tcp2.checksum(), calculated);
    }

    #[test]
    fn tcp_options_can_be_appended_after_rebuild() {
        use zerodpi_core::methods::wrong_md5::tcp_md5_signature_option;

        let buf = data_packet(&[]);
        let layout = PacketLayout {
            ip_hdr_len: 20,
            tcp_hdr_len: 20,
            payload_off: 40,
            total_len: 40,
        };
        let mut view = make_view();
        let md5_option = tcp_md5_signature_option();
        view.append_tcp_options = md5_option.clone();
        let modified = build_modified(&buf, &layout, &view).unwrap();

        let ip2 = Ipv4HeaderSlice::from_slice(&modified).unwrap();
        let tcp2 = TcpHeaderSlice::from_slice(&modified[ip2.slice().len()..]).unwrap();
        assert_eq!(tcp2.slice().len(), 40);
        assert_eq!(ip2.total_len() as usize, 20 + 40 + 517);

        let options = tcp2.options();
        assert_eq!(&options[..md5_option.len()], md5_option.as_slice());
        assert_eq!(&options[md5_option.len()..], &[0, 0]);

        let payload_off = ip2.slice().len() + tcp2.slice().len();
        let calculated = tcp2
            .to_header()
            .calc_checksum_ipv4(&ip2.to_header(), &modified[payload_off..])
            .unwrap();
        assert_eq!(tcp2.checksum(), calculated);
    }

    #[test]
    fn tcp_options_can_be_replaced_after_rebuild() {
        let original_options = timestamp_option(100, 77);
        let replacement_options = timestamp_option(99, 77);
        let buf = data_packet_with_options(&[], &original_options);
        let (mut view, layout) = parse_view(Direction::Outbound, &buf).unwrap();
        view.new_payload = Some(vec![0xAB; 10]);
        view.replace_tcp_options = Some(replacement_options.clone());

        let modified = build_modified(&buf, &layout, &view).unwrap();

        let ip2 = Ipv4HeaderSlice::from_slice(&modified).unwrap();
        let tcp2 = TcpHeaderSlice::from_slice(&modified[ip2.slice().len()..]).unwrap();
        assert_eq!(tcp2.slice().len(), 32);
        assert_eq!(ip2.total_len() as usize, 20 + 32 + 10);

        let options = tcp2.options();
        assert_eq!(
            &options[..replacement_options.len()],
            replacement_options.as_slice()
        );
        assert_eq!(&options[replacement_options.len()..], &[0, 0]);

        let payload_off = ip2.slice().len() + tcp2.slice().len();
        let calculated = tcp2
            .to_header()
            .calc_checksum_ipv4(&ip2.to_header(), &modified[payload_off..])
            .unwrap();
        assert_eq!(tcp2.checksum(), calculated);
    }

    #[test]
    fn tcp_option_append_rejects_oversized_header() {
        use etherparse::TcpHeader;
        use zerodpi_core::methods::wrong_md5::tcp_md5_signature_option;

        let mut tcp = TcpHeader::new(12345, 443, 1001, 65535);
        tcp.set_options_raw(&[1; 24]).unwrap();
        let err = append_tcp_options(&mut tcp, &tcp_md5_signature_option()).unwrap_err();
        assert!(err.to_string().contains("TCP options would exceed"));
    }
}
