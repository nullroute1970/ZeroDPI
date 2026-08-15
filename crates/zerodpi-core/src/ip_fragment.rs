//! IPv4 packet fragmentation helpers shared by the platform backends.
//!
//! `ip_frag` stages `PacketView.ip_frag_payload_size`; the WinDivert and
//! NFQUEUE backends rebuild the modified packet and then call
//! [`fragment_ipv4_packet`] to split it into wire-ready IPv4 fragments
//! before emission.

/// Split a complete IPv4 packet (header + payload) into fragments whose IP
/// payload — everything after the IP header — is at most `frag_size` bytes.
///
/// `frag_size` is rounded down to a multiple of 8 (the fragment-offset
/// unit). Fragmentation is skipped — the input packet is returned unchanged
/// as a single-element `Vec` — when it is impossible or pointless:
/// `frag_size < 8`, the payload already fits one fragment, or the buffer
/// does not hold a valid minimal IPv4 header.
///
/// Every emitted fragment has:
///
/// - `total_length` set to the fragment size,
/// - the fragment offset (in 8-byte units) and the `MF` flag set on every
///   fragment except the last, with `DF` cleared,
/// - the original identification field preserved (fragments of one datagram
///   must share it),
/// - a recomputed IPv4 header checksum.
///
/// The TCP header and its checksum are carried inside the first fragment's
/// payload and are left untouched; the destination kernel validates the TCP
/// checksum after IP reassembly.
pub fn fragment_ipv4_packet(bytes: &[u8], frag_size: usize) -> Vec<Vec<u8>> {
    let unchanged = || vec![bytes.to_vec()];
    let Some(&first) = bytes.first() else {
        return unchanged();
    };
    let ihl = usize::from(first & 0x0F) * 4;
    if ihl < 20 || ihl > bytes.len() {
        return unchanged();
    }
    let chunk = frag_size & !7;
    if chunk == 0 {
        return unchanged();
    }
    let payload = &bytes[ihl..];
    if payload.len() <= chunk {
        return unchanged();
    }

    let ident = [bytes[4], bytes[5]];
    let mut fragments = Vec::with_capacity(payload.len().div_ceil(chunk));
    let mut offset = 0usize;
    for part in payload.chunks(chunk) {
        let mut frag = Vec::with_capacity(ihl + part.len());
        frag.extend_from_slice(&bytes[..ihl]);

        // Total length: header + this fragment's payload.
        let total = (ihl + part.len()) as u16;
        frag[2] = (total >> 8) as u8;
        frag[3] = total as u8;

        // Byte 6: flags (3 bits) + fragment offset high bits. Byte 7:
        // fragment offset low bits. Writing both bytes clears DF and sets
        // the 13-bit offset in 8-byte units; MF (0x2000) is set on every
        // fragment except the last.
        let last = offset + part.len() >= payload.len();
        let mut flags_offset = (offset / 8) as u16;
        if !last {
            flags_offset |= 0x2000;
        }
        frag[6] = (flags_offset >> 8) as u8;
        frag[7] = flags_offset as u8;

        // Identification preserved across all fragments.
        frag[4] = ident[0];
        frag[5] = ident[1];

        // Zero the checksum field and recompute over the fragment header.
        frag[10] = 0;
        frag[11] = 0;
        let checksum = ipv4_header_checksum(&frag[..ihl]);
        frag[10] = (checksum >> 8) as u8;
        frag[11] = checksum as u8;

        frag.extend_from_slice(part);
        fragments.push(frag);
        offset += part.len();
    }
    fragments
}

/// RFC 1071 one's-complement checksum over an IPv4 header (the checksum
/// field itself must be zeroed by the caller). Summing the header again
/// *with* the checksum field populated yields `0` when the checksum is
/// valid.
fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = header.chunks_exact(2);
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

    /// Build a synthetic IPv4 packet: 20-byte header (no options) + payload,
    /// with the given identification and flags/fragment-offset word.
    fn ipv4_packet(payload: &[u8], ident: u16, flags_frag: u16) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut pkt = vec![
            0x45,
            0x00,
            (total >> 8) as u8,
            total as u8,
            (ident >> 8) as u8,
            ident as u8,
            (flags_frag >> 8) as u8,
            flags_frag as u8,
            0x40,
            0x06, // TTL 64, protocol TCP
            0x00,
            0x00, // checksum (computed below)
            0x0A,
            0x00,
            0x00,
            0x01, // src 10.0.0.1
            0x01,
            0x02,
            0x03,
            0x04, // dst 1.2.3.4
        ];
        pkt.extend_from_slice(payload);
        let checksum = ipv4_header_checksum(&pkt[..20]);
        pkt[10] = (checksum >> 8) as u8;
        pkt[11] = checksum as u8;
        pkt
    }

    fn reassembled_payload(fragments: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for frag in fragments {
            let ihl = usize::from(frag[0] & 0x0F) * 4;
            out.extend_from_slice(&frag[ihl..]);
        }
        out
    }

    fn offset_field(frag: &[u8]) -> u16 {
        u16::from_be_bytes([frag[6], frag[7]]) & 0x1FFF
    }

    #[test]
    fn rfc1071_checksum_vector() {
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8,
            0x00, 0x01, 0xC0, 0xA8, 0x00, 0xC7,
        ];
        assert_eq!(ipv4_header_checksum(&header), 0xB861);
    }

    #[test]
    fn payload_fitting_one_fragment_returns_input_unchanged() {
        let pkt = ipv4_packet(&[0xAB; 10], 0x1234, 0x4000);
        assert_eq!(fragment_ipv4_packet(&pkt, 24), vec![pkt.clone()]);
    }

    #[test]
    fn frag_size_below_eight_returns_input_unchanged() {
        let pkt = ipv4_packet(&[0xAB; 100], 0x1234, 0x4000);
        assert_eq!(fragment_ipv4_packet(&pkt, 4), vec![pkt.clone()]);
    }

    #[test]
    fn frag_size_rounded_down_to_multiple_of_8() {
        let pkt = ipv4_packet(&[0xAB; 100], 0x1234, 0x4000);
        let frags = fragment_ipv4_packet(&pkt, 30); // effective chunk: 24
        assert_eq!(frags.len(), 5);
        for (i, frag) in frags.iter().enumerate() {
            let expected_payload = if i < 4 { 24 } else { 4 };
            assert_eq!(frag.len(), 20 + expected_payload);
        }
        assert_eq!(reassembled_payload(&frags), vec![0xAB; 100]);
    }

    #[test]
    fn offsets_and_mf_flags_are_correct_and_df_is_cleared() {
        let pkt = ipv4_packet(&[0xAB; 40], 0x1234, 0x4000); // input has DF set
        let frags = fragment_ipv4_packet(&pkt, 16);
        assert_eq!(frags.len(), 3);
        for (i, frag) in frags.iter().enumerate() {
            let field = u16::from_be_bytes([frag[6], frag[7]]);
            let mf = field & 0x2000 != 0;
            let df = field & 0x4000 != 0;
            assert_eq!(mf, i < 2, "MF on fragment {i}");
            assert!(!df, "DF cleared on fragment {i}");
            assert_eq!(offset_field(frag), (i * 2) as u16);
        }
    }

    #[test]
    fn identification_preserved_across_fragments() {
        let pkt = ipv4_packet(&[0xAB; 60], 0x5678, 0x4000);
        for frag in fragment_ipv4_packet(&pkt, 24) {
            assert_eq!(u16::from_be_bytes([frag[4], frag[5]]), 0x5678);
        }
    }

    #[test]
    fn header_checksum_valid_on_every_fragment() {
        let pkt = ipv4_packet(&[0xAB; 60], 0x1234, 0x4000);
        for frag in fragment_ipv4_packet(&pkt, 24) {
            assert_eq!(ipv4_header_checksum(&frag[..20]), 0);
        }
    }

    #[test]
    fn total_length_set_on_every_fragment() {
        let pkt = ipv4_packet(&[0xAB; 44], 0x1234, 0);
        for frag in fragment_ipv4_packet(&pkt, 16) {
            let total = u16::from_be_bytes([frag[2], frag[3]]) as usize;
            assert_eq!(total, frag.len());
        }
    }

    #[test]
    fn empty_payload_returns_input_unchanged() {
        let pkt = ipv4_packet(&[], 0x1234, 0);
        assert_eq!(fragment_ipv4_packet(&pkt, 24), vec![pkt.clone()]);
    }

    #[test]
    fn short_buffer_returns_input_unchanged() {
        let bytes = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x01];
        assert_eq!(fragment_ipv4_packet(&bytes, 24), vec![bytes.clone()]);
    }

    #[test]
    fn reassembled_payload_matches_input() {
        let pkt = ipv4_packet(&[0xAB; 517], 0x1234, 0x4000);
        let frags = fragment_ipv4_packet(&pkt, 24);
        assert!(frags.len() > 1);
        assert_eq!(reassembled_payload(&frags), vec![0xAB; 517]);
    }
}
