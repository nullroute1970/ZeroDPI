//! Windows backend: WinDivert-based packet interception.
//!
//! Mirrors the Linux NFQUEUE backend but uses the WinDivert kernel driver.
//! No system rules need to be installed externally — the driver itself
//! receives a filter expression and diverts matching packets to user space.

use std::borrow::Cow;

use anyhow::{Context, Result};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};
use tracing::{debug, info, warn};
use windivert::layer::NetworkLayer;
use windivert::prelude::{WinDivert, WinDivertFlags, WinDivertPacket};
use windivert_sys::ChecksumFlags;

use zerodpi_core::interceptor::{
    Direction, FilterSpec, PacketHandler, PacketInterceptor, PacketView, TcpFlags, Verdict,
};

pub struct WinDivertInterceptor {
    divert: WinDivert<NetworkLayer>,
}

impl PacketInterceptor for WinDivertInterceptor {
    fn open(filter: FilterSpec) -> Result<Self> {
        let filter_str = build_filter(&filter);
        info!(%filter_str, "opening WinDivert");
        let divert = WinDivert::network(filter_str, 0, WinDivertFlags::default())
            .context("WinDivert::network failed (Administrator and WinDivert.dll/sys required)")?;
        Ok(Self { divert })
    }

    fn run<H: PacketHandler>(self, mut handler: H) -> Result<()> {
        let mut buf = vec![0u8; 0xFFFF];
        loop {
            let packet = match self.divert.recv(Some(&mut buf)) {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "WinDivert recv error; exiting loop");
                    return Ok(());
                }
            };
            let direction = if packet.address.outbound() {
                Direction::Outbound
            } else {
                Direction::Inbound
            };

            let (mut view, layout) = match parse_view(direction, &packet.data) {
                Ok(v) => v,
                Err(_) => {
                    // Not a TCP/IPv4 packet — pass through.
                    if let Err(e) = self.divert.send(&packet) {
                        debug!(error = %e, "passthrough send failed");
                    }
                    continue;
                }
            };

            match handler.on_packet(&mut view) {
                Verdict::Accept => {
                    if let Err(e) = self.divert.send(&packet) {
                        debug!(error = %e, "send failed");
                    }
                }
                Verdict::Drop => {
                    // Don't send: WinDivert drops packets that aren't reinjected.
                }
                Verdict::AcceptModified => {
                    let new_bytes = match build_modified(&packet.data, &layout, &view) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error = %e, "build_modified failed; sending original");
                            let _ = self.divert.send(&packet);
                            continue;
                        }
                    };
                    let mut new_pkt = WinDivertPacket::<NetworkLayer> {
                        address: packet.address.clone(),
                        data: Cow::Owned(new_bytes),
                    };
                    if let Err(e) = new_pkt.recalculate_checksums(ChecksumFlags::default()) {
                        warn!(error = %e, "recalculate_checksums failed");
                    }
                    if let Some(delta) = view.corrupt_tcp_checksum_delta {
                        if let Err(e) = corrupt_tcp_checksum(
                            new_pkt.data.to_mut().as_mut_slice(),
                            &layout,
                            delta,
                        ) {
                            warn!(error = %e, "failed to corrupt TCP checksum");
                        }
                    }
                    if let Err(e) = self.divert.send(&new_pkt) {
                        debug!(error = %e, "modified send failed");
                    }
                }
            }
        }
    }
}

/// Build a WinDivert filter equivalent to the upstream Python project's:
/// `tcp and ((ip.SrcAddr == iface and ip.DstAddr == remote) or (ip.SrcAddr == remote and ip.DstAddr == iface))`.
fn build_filter(filter: &FilterSpec) -> String {
    match filter.remote_ip {
        Some(remote) => format!(
            "tcp and ((ip.SrcAddr == {iface} and ip.DstAddr == {remote} and tcp.DstPort == {port}) \
             or (ip.SrcAddr == {remote} and ip.DstAddr == {iface} and tcp.SrcPort == {port}))",
            iface = filter.interface_ip,
            port = filter.remote_port,
        ),
        None => format!(
            "tcp and ((ip.SrcAddr == {iface} and tcp.DstPort == {port}) \
             or (ip.DstAddr == {iface} and tcp.SrcPort == {port}))",
            iface = filter.interface_ip,
            port = filter.remote_port,
        ),
    }
}

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
        new_ack: None,
        new_flags: None,
        new_payload: None,
        append_tcp_options: Vec::new(),
        bump_ipv4_ident: false,
        corrupt_tcp_checksum_delta: None,
    };
    Ok((
        view,
        PacketLayout {
            ip_hdr_len,
            tcp_hdr_len,
            payload_off,
            total_len,
        },
    ))
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
    append_tcp_options(&mut tcp_hdr, &view.append_tcp_options)?;

    let new_tcp_hdr_len = tcp_hdr.header_len();
    let new_ip_payload_len = new_tcp_hdr_len + new_payload.len();
    ip_hdr.set_payload_len(new_ip_payload_len)?;
    ip_hdr.header_checksum = ip_hdr.calc_header_checksum();
    tcp_hdr.checksum = tcp_hdr.calc_checksum_ipv4(&ip_hdr, new_payload)?;
    // WinDivert recalculates these again immediately before send. We compute
    // them here so rebuilt packet buffers are valid before that final pass.
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

fn corrupt_tcp_checksum(buf: &mut [u8], layout: &PacketLayout, delta: u16) -> Result<()> {
    let checksum_off = layout.ip_hdr_len + 16;
    if buf.len() < checksum_off + 2 {
        anyhow::bail!("packet too short for TCP checksum field");
    }
    let checksum = u16::from_be_bytes([buf[checksum_off], buf[checksum_off + 1]]);
    let corrupted = checksum.wrapping_add(delta);
    buf[checksum_off..checksum_off + 2].copy_from_slice(&corrupted.to_be_bytes());
    Ok(())
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
            new_seq: Some(1001),
            new_ack: None,
            new_flags: Some(TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            }),
            new_payload: Some(vec![0xAB; 517]),
            append_tcp_options: Vec::new(),
            bump_ipv4_ident: true,
            corrupt_tcp_checksum_delta: Some(11),
        }
    }

    fn bare_ack_packet() -> Vec<u8> {
        use etherparse::{IpNumber, Ipv4Header, TcpHeader};

        let mut ip = Ipv4Header::new(20, 64, IpNumber::TCP, [10, 0, 0, 1], [1, 2, 3, 4]).unwrap();
        ip.identification = 0x1234;
        ip.header_checksum = ip.calc_header_checksum();
        let mut tcp = TcpHeader::new(12345, 443, 1001, 65535);
        tcp.acknowledgment_number = 5001;
        tcp.ack = true;
        tcp.checksum = tcp.calc_checksum_ipv4(&ip, &[]).unwrap();

        let mut buf = Vec::new();
        ip.write(&mut buf).unwrap();
        tcp.write(&mut buf).unwrap();
        buf
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
        let buf = bare_ack_packet();
        let layout = PacketLayout {
            ip_hdr_len: 20,
            tcp_hdr_len: 20,
            payload_off: 40,
            total_len: 40,
        };
        let mut view = make_view();
        view.corrupt_tcp_checksum_delta = None;
        let modified = build_modified(&buf, &layout, &view).unwrap();

        let ip2 = Ipv4HeaderSlice::from_slice(&modified).unwrap();
        let tcp2 = TcpHeaderSlice::from_slice(&modified[ip2.slice().len()..]).unwrap();
        assert_eq!(ip2.identification(), 0x1235);
        assert_eq!(ip2.total_len() as usize, 20 + 20 + 517);
        assert_eq!(tcp2.sequence_number(), 1001);
        assert!(tcp2.psh());
        assert!(tcp2.ack());
        let calculated = tcp2
            .to_header()
            .calc_checksum_ipv4(&ip2.to_header(), &modified[40..])
            .unwrap();
        assert_eq!(tcp2.checksum(), calculated);
    }

    #[test]
    fn corrupt_tcp_checksum_adds_delta_to_valid_checksum() {
        let buf = bare_ack_packet();
        let layout = PacketLayout {
            ip_hdr_len: 20,
            tcp_hdr_len: 20,
            payload_off: 40,
            total_len: 40,
        };
        let view = make_view();
        let mut modified = build_modified(&buf, &layout, &view).unwrap();

        let ip2 = Ipv4HeaderSlice::from_slice(&modified).unwrap();
        let tcp2 = TcpHeaderSlice::from_slice(&modified[ip2.slice().len()..]).unwrap();
        let valid_checksum = tcp2
            .to_header()
            .calc_checksum_ipv4(&ip2.to_header(), &modified[40..])
            .unwrap();
        assert_eq!(tcp2.checksum(), valid_checksum);

        corrupt_tcp_checksum(
            &mut modified,
            &layout,
            view.corrupt_tcp_checksum_delta.unwrap(),
        )
        .unwrap();
        let ip3 = Ipv4HeaderSlice::from_slice(&modified).unwrap();
        let tcp3 = TcpHeaderSlice::from_slice(&modified[ip3.slice().len()..]).unwrap();
        assert_eq!(tcp3.checksum(), valid_checksum.wrapping_add(11));
    }

    #[test]
    fn tcp_ack_number_can_be_rewritten_after_rebuild() {
        let buf = bare_ack_packet();
        let layout = PacketLayout {
            ip_hdr_len: 20,
            tcp_hdr_len: 20,
            payload_off: 40,
            total_len: 40,
        };
        let mut view = make_view();
        view.new_seq = None;
        view.new_ack = Some(4999);
        view.corrupt_tcp_checksum_delta = None;
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

        let buf = bare_ack_packet();
        let layout = PacketLayout {
            ip_hdr_len: 20,
            tcp_hdr_len: 20,
            payload_off: 40,
            total_len: 40,
        };
        let mut view = make_view();
        view.corrupt_tcp_checksum_delta = None;
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
    fn tcp_option_append_rejects_oversized_header() {
        use etherparse::TcpHeader;
        use zerodpi_core::methods::wrong_md5::tcp_md5_signature_option;

        let mut tcp = TcpHeader::new(12345, 443, 1001, 65535);
        tcp.set_options_raw(&[1; 24]).unwrap();
        let err = append_tcp_options(&mut tcp, &tcp_md5_signature_option()).unwrap_err();
        assert!(err.to_string().contains("TCP options would exceed"));
    }
}
