//! Out-of-order TCP segmentation helpers shared by the platform backends.
//!
//! `disorder` stages `PacketView.disorder_spec`; the WinDivert and NFQUEUE
//! backends rebuild the modified packet and then call
//! [`split_tcp_payload`] to split it into standalone TCP segments before
//! emission.

use crate::ip_fragment::ipv4_header_checksum;

/// Split a rebuilt TCP/IPv4 packet's payload into `segments` non-empty
/// chunks and return one standalone TCP segment per chunk, in emission
/// order: chunk order `[0..n)` when `reverse` is false, `[n-1..0]` when it
/// is true.
///
/// The chunk size is `ceil(payload_len / segments)`, so the last chunk
/// absorbs the remainder and all chunks are non-empty. Splitting is
/// skipped — the input packet is returned unchanged as a single-element
/// `Vec` — when the buffer does not hold a valid minimal IPv4+TCP header,
/// `segments < 2`, or the payload is too small for `segments` non-empty
/// chunks.
///
/// Every emitted segment has:
///
/// - the TCP sequence number advanced by the chunk's byte offset within
///   the original payload (mod 2^32),
/// - the PSH flag kept only on the chunk that ends the in-sequence payload
///   (cleared on the others),
/// - the IPv4 total-length field updated and the IPv4 header checksum
///   recomputed,
/// - the TCP checksum recomputed over the pseudo-header, TCP header, and
///   chunk,
/// - the original IPv4 identification field and TCP options preserved.
pub fn split_tcp_payload(bytes: &[u8], segments: usize, reverse: bool) -> Vec<Vec<u8>> {
    let unchanged = || vec![bytes.to_vec()];
    let Some(&first) = bytes.first() else {
        return unchanged();
    };
    let ihl = usize::from(first & 0x0F) * 4;
    if ihl < 20 || ihl + 20 > bytes.len() {
        return unchanged();
    }
    // TCP data offset (4-bit, in 32-bit words) is the high nibble of the
    // byte at `ihl + 12`.
    let tcp_hdr_len = usize::from(bytes[ihl + 12] >> 4) * 4;
    if tcp_hdr_len < 20 || ihl + tcp_hdr_len > bytes.len() {
        return unchanged();
    }
    let payload_off = ihl + tcp_hdr_len;
    let payload = &bytes[payload_off..];
    if segments < 2 || payload.len() < segments {
        return unchanged();
    }
    let chunk = payload.len().div_ceil(segments);
    let orig_seq = u32::from_be_bytes([
        bytes[ihl + 4],
        bytes[ihl + 5],
        bytes[ihl + 6],
        bytes[ihl + 7],
    ]);

    let mut built = Vec::with_capacity(segments);
    let mut offset = 0usize;
    for part in payload.chunks(chunk) {
        let mut seg = Vec::with_capacity(payload_off + part.len());
        seg.extend_from_slice(&bytes[..payload_off]);
        seg.extend_from_slice(part);

        // IPv4 total length: header + this chunk.
        let total = (payload_off + part.len()) as u16;
        seg[2] = (total >> 8) as u8;
        seg[3] = total as u8;

        // TCP sequence number: original + in-stream byte offset.
        let seq = orig_seq.wrapping_add(offset as u32);
        seg[ihl + 4..ihl + 8].copy_from_slice(&seq.to_be_bytes());

        // PSH only on the chunk that ends the in-sequence payload.
        let ends_payload = offset + part.len() == payload.len();
        let flags_byte = bytes[ihl + 13];
        seg[ihl + 13] = if ends_payload {
            flags_byte
        } else {
            flags_byte & !0x08
        };

        // IPv4 header checksum.
        seg[10] = 0;
        seg[11] = 0;
        let ip_csum = ipv4_header_checksum(&seg[..ihl]);
        seg[10] = (ip_csum >> 8) as u8;
        seg[11] = ip_csum as u8;

        // TCP checksum (pseudo-header + header + chunk).
        seg[ihl + 16] = 0;
        seg[ihl + 17] = 0;
        let tcp_csum = tcp_checksum(&seg, ihl, tcp_hdr_len);
        seg[ihl + 16] = (tcp_csum >> 8) as u8;
        seg[ihl + 17] = tcp_csum as u8;

        built.push(seg);
        offset += part.len();
    }
    if reverse {
        built.reverse();
    }
    built
}

/// RFC 1071 one's-complement checksum over the TCP pseudo-header (source
/// and destination IPv4 addresses, protocol, segment length), the TCP
/// header, and the payload of `seg`. The TCP checksum field must be zeroed
/// by the caller.
fn tcp_checksum(seg: &[u8], ihl: usize, tcp_hdr_len: usize) -> u16 {
    let tcp_len = (tcp_hdr_len + (seg.len() - (ihl + tcp_hdr_len))) as u16;
    let mut sum = 0u32;
    // Pseudo-header: src + dst IPv4 addresses, zero byte + protocol, length.
    sum += u32::from(u16::from_be_bytes([seg[12], seg[13]]));
    sum += u32::from(u16::from_be_bytes([seg[14], seg[15]]));
    sum += u32::from(u16::from_be_bytes([seg[16], seg[17]]));
    sum += u32::from(u16::from_be_bytes([seg[18], seg[19]]));
    sum += 6; // protocol TCP
    sum += u32::from(tcp_len);
    let mut chunks = seg[ihl..].chunks_exact(2);
    for word in &mut chunks {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let [b] = chunks.remainder() {
        sum += u32::from(*b) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic IPv4/TCP packet: 20-byte IPv4 header (no options),
    /// 20-byte TCP header (ACK + optional PSH, no options) + payload, with
    /// valid IP and TCP checksums.
    fn tcp_packet(payload: &[u8], seq: u32, psh: bool) -> Vec<u8> {
        tcp_packet_with_options(payload, seq, psh, &[])
    }

    /// Build the same packet with extra TCP option bytes (`options` must be
    /// a multiple of 4; the caller is responsible for the data offset).
    fn tcp_packet_with_options(payload: &[u8], seq: u32, psh: bool, options: &[u8]) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0);
        let tcp_hdr_len = 20 + options.len();
        let total = (20 + tcp_hdr_len + payload.len()) as u16;
        let mut pkt = vec![
            0x45,
            0x00,
            (total >> 8) as u8,
            total as u8,
            0x56,
            0x78, // ident
            0x40,
            0x00, // flags/frag: DF
            0x40,
            0x06, // TTL 64, protocol TCP
            0x00,
            0x00, // IPv4 checksum placeholder
            0x0A,
            0x00,
            0x00,
            0x01, // src 10.0.0.1
            0x01,
            0x02,
            0x03,
            0x04, // dst 1.2.3.4
        ];
        // TCP header
        pkt.extend_from_slice(&12345u16.to_be_bytes()); // src port
        pkt.extend_from_slice(&443u16.to_be_bytes()); // dst port
        pkt.extend_from_slice(&seq.to_be_bytes()); // sequence number
        pkt.extend_from_slice(&9000u32.to_be_bytes()); // acknowledgment number
        pkt.push(((tcp_hdr_len / 4) << 4) as u8); // data offset in words
        pkt.push(if psh { 0x18 } else { 0x10 }); // flags: ACK (+ PSH)
        pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
        pkt.extend_from_slice(&0u16.to_be_bytes()); // TCP checksum placeholder
        pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
        pkt.extend_from_slice(options);
        pkt.extend_from_slice(payload);

        // IPv4 header checksum.
        let ip_csum = ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (ip_csum >> 8) as u8;
        pkt[11] = ip_csum as u8;

        // TCP checksum over pseudo-header + header + payload.
        let tcp_csum = tcp_checksum(&pkt, 20, tcp_hdr_len);
        let csum_off = 20 + 16;
        pkt[csum_off] = (tcp_csum >> 8) as u8;
        pkt[csum_off + 1] = tcp_csum as u8;
        pkt
    }

    fn payload_of(seg: &[u8]) -> &[u8] {
        let ihl = usize::from(seg[0] & 0x0F) * 4;
        let tcp_hdr_len = usize::from(seg[ihl + 12] >> 4) * 4;
        &seg[ihl + tcp_hdr_len..]
    }

    fn seq_of(seg: &[u8]) -> u32 {
        let ihl = usize::from(seg[0] & 0x0F) * 4;
        u32::from_be_bytes([seg[ihl + 4], seg[ihl + 5], seg[ihl + 6], seg[ihl + 7]])
    }

    #[test]
    fn reverse_emits_tail_first_with_correct_seqs() {
        let pkt = tcp_packet(&[0xAB; 517], 1001, true);
        let segs = split_tcp_payload(&pkt, 2, true);
        assert_eq!(segs.len(), 2);

        // chunk = ceil(517 / 2) = 259: head 259 bytes @ seq 1001, tail 258.
        // Reverse emission: the tail goes out first.
        assert_eq!(payload_of(&segs[0]), &[0xAB; 258]);
        assert_eq!(seq_of(&segs[0]), 1001 + 259);
        assert_eq!(payload_of(&segs[1]), &[0xAB; 259]);
        assert_eq!(seq_of(&segs[1]), 1001);
    }

    #[test]
    fn forward_emits_in_order() {
        let pkt = tcp_packet(&[0xAB; 517], 1001, true);
        let segs = split_tcp_payload(&pkt, 2, false);
        assert_eq!(segs.len(), 2);
        assert_eq!(payload_of(&segs[0]), &[0xAB; 259]);
        assert_eq!(seq_of(&segs[0]), 1001);
        assert_eq!(payload_of(&segs[1]), &[0xAB; 258]);
        assert_eq!(seq_of(&segs[1]), 1001 + 259);
    }

    #[test]
    fn three_segments_advance_seq_by_chunk_offsets() {
        let pkt = tcp_packet(&[0xAB; 517], 1001, true);
        let segs = split_tcp_payload(&pkt, 3, true);
        assert_eq!(segs.len(), 3);
        // chunk = ceil(517 / 3) = 173; offsets 0, 173, 346.
        // Reverse emission: offset 346 first, offset 0 last.
        assert_eq!(seq_of(&segs[0]), 1001 + 346);
        assert_eq!(payload_of(&segs[0]), &[0xAB; 171]);
        assert_eq!(seq_of(&segs[1]), 1001 + 173);
        assert_eq!(payload_of(&segs[1]), &[0xAB; 173]);
        assert_eq!(seq_of(&segs[2]), 1001);
        assert_eq!(payload_of(&segs[2]), &[0xAB; 173]);
    }

    #[test]
    fn psh_only_on_segment_ending_payload() {
        let pkt = tcp_packet(&[0xAB; 517], 1001, true);
        let segs = split_tcp_payload(&pkt, 2, true);
        // Emitted first: the tail chunk ends the in-sequence payload — PSH kept.
        let tail_flags = segs[0][33];
        assert_eq!(tail_flags & 0x08, 0x08);
        // Emitted second: the head chunk does not end the payload — PSH cleared.
        let head_flags = segs[1][33];
        assert_eq!(head_flags & 0x08, 0);
    }

    #[test]
    fn checksums_valid_on_every_segment() {
        let pkt = tcp_packet(&[0xAB; 517], 1001, true);
        for seg in split_tcp_payload(&pkt, 3, true) {
            assert_eq!(ipv4_header_checksum(&seg[..20]), 0, "IPv4 checksum");
            assert_eq!(tcp_checksum(&seg, 20, 20), 0, "TCP checksum");
        }
    }

    #[test]
    fn total_length_matches_segment_size() {
        let pkt = tcp_packet(&[0xAB; 517], 1001, true);
        for seg in split_tcp_payload(&pkt, 2, true) {
            let total = u16::from_be_bytes([seg[2], seg[3]]) as usize;
            assert_eq!(total, seg.len());
        }
    }

    #[test]
    fn payload_too_small_returns_input_unchanged() {
        let pkt = tcp_packet(&[0xAB; 1], 1001, true);
        assert_eq!(split_tcp_payload(&pkt, 2, true), vec![pkt.clone()]);
    }

    #[test]
    fn single_segment_request_returns_input_unchanged() {
        let pkt = tcp_packet(&[0xAB; 517], 1001, true);
        assert_eq!(split_tcp_payload(&pkt, 1, true), vec![pkt.clone()]);
    }

    #[test]
    fn short_buffer_returns_input_unchanged() {
        let bytes = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x01];
        assert_eq!(split_tcp_payload(&bytes, 2, true), vec![bytes.clone()]);
    }

    #[test]
    fn options_and_ip_identification_preserved() {
        // 4 bytes of TCP options -> 24-byte TCP header (data offset 6).
        let options: &[u8] = &[0x01, 0x01, 0x08, 0x0A];
        let pkt = tcp_packet_with_options(&[0xAB; 517], 1001, true, options);
        let segs = split_tcp_payload(&pkt, 2, true);
        assert_eq!(segs.len(), 2);
        for seg in &segs {
            assert_eq!(u16::from_be_bytes([seg[4], seg[5]]), 0x5678, "ident");
            assert_eq!(seg[32] >> 4, 6, "TCP data offset preserved");
            assert_eq!(&seg[40..44], options, "TCP options preserved");
            assert_eq!(ipv4_header_checksum(&seg[..20]), 0);
            assert_eq!(tcp_checksum(seg, 20, 24), 0);
        }
        // Payload split respects the 24-byte TCP header: first emitted
        // segment is the tail at seq 1001 + 259.
        assert_eq!(payload_of(&segs[0]), &[0xAB; 258]);
        assert_eq!(seq_of(&segs[0]), 1001 + 259);
    }
}
