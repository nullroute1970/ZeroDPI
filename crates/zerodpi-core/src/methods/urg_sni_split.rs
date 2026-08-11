//! `urg_sni_split` bypass: injects a 1-byte dummy payload into the middle of
//! the SNI inside the real ClientHello and marks it with the TCP URG flag.
//!
//! ## How it works
//!
//! BSD-style TCP stacks treat the byte at the urgent pointer as out-of-band
//! data: it is extracted from the normal stream, so the destination server's
//! TLS parser receives the original ClientHello byte-for-byte. Stateless DPI
//! middleboxes that ignore the urgent pointer and read the raw byte stream
//! sequentially instead see the SNI with an extra byte spliced into the middle
//! of the domain string, so their blacklist match fails.
//!
//! The method operates on the real first data packet (the ClientHello written
//! by the proxy), never on a fake packet: the server must actually accept and
//! process the handshake. If the SNI cannot be found in a data packet, the
//! method passes it through; the handler keeps offering subsequent data
//! packets until one is rewritten.

use super::{BypassMethod, MethodAction};
use crate::config::{Config, SniSplitPosition};
use crate::flow::FlowState;
use crate::interceptor::PacketView;

/// Find the host_name (SNI) bytes inside a TLS ClientHello payload.
///
/// Walks the TLS record header, handshake header, fixed ClientHello fields,
/// and the extension list to locate the `server_name` extension (type
/// `0x0000`) and its `host_name` entry (name type `0`). Returns `(start, len)`
/// of the name bytes within `data`, or `None` if the payload is not a complete
/// ClientHello containing a valid non-empty host_name.
fn find_sni_range(data: &[u8]) -> Option<(usize, usize)> {
    // TLS record layer: content_type(1) version(2) length(2)
    let record_header = data.get(..5)?;
    if record_header[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([record_header[3], record_header[4]]) as usize;
    let record_body = data.get(5..5 + record_len)?;

    // Handshake layer: type(1) length(3)
    if record_body.first() != Some(&0x01) {
        return None;
    }
    let hs_len = ((record_body[1] as usize) << 16)
        | ((record_body[2] as usize) << 8)
        | record_body[3] as usize;
    let body = record_body.get(4..4 + hs_len)?;

    // Fixed ClientHello fields: version(2) random(32) session_id_len(1) session_id
    let mut off = 2 + 32 + 1;
    let sid_len = *body.get(off - 1)? as usize;
    off += sid_len;

    // Cipher suites: len(2) suites
    let cs_pair = body.get(off..off + 2)?;
    let cs_len = u16::from_be_bytes([cs_pair[0], cs_pair[1]]) as usize;
    off += 2 + cs_len;

    // Compression methods: len(1) methods
    let cm_len = *body.get(off)? as usize;
    off += 1 + cm_len;

    // Extensions: total len(2) then the list
    let ext_pair = body.get(off..off + 2)?;
    let ext_total = u16::from_be_bytes([ext_pair[0], ext_pair[1]]) as usize;
    let mut p = off + 2;
    let extensions = body.get(p..p + ext_total)?;

    let mut e = 0;
    while e + 4 <= extensions.len() {
        let ext_len = u16::from_be_bytes([extensions[e + 2], extensions[e + 3]]) as usize;
        let ext_data = extensions.get(e + 4..e + 4 + ext_len)?;
        let ext_type = u16::from_be_bytes([extensions[e], extensions[e + 1]]);
        if ext_type == 0x0000 {
            // server_name: list_len(2) then entries: name_type(1) name_len(2) name
            let list_pair = ext_data.get(..2)?;
            let list_len = u16::from_be_bytes([list_pair[0], list_pair[1]]) as usize;
            let list = ext_data.get(2..2 + list_len)?;
            if list.first() != Some(&0x00) {
                return None;
            }
            let name_pair = list.get(1..3)?;
            let name_len = u16::from_be_bytes([name_pair[0], name_pair[1]]) as usize;
            if name_len == 0 {
                return None;
            }
            list.get(3..3 + name_len)?;
            // name start within `body`: the server_name extension entry begins
            // at `p + e` in the extensions list, each entry has a 4-byte
            // header, then list_len(2) + name_type(1) + name_len(2) precede
            // the name bytes.
            let name_start_in_body = p + e + 4 + 2 + 1 + 2;
            // `body` starts 9 bytes into `data` (5 record header + 4
            // handshake header).
            return Some((9 + name_start_in_body, name_len));
        }
        e += 4 + ext_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_template::build_client_hello;

    fn client_hello(sni: &[u8]) -> Vec<u8> {
        build_client_hello(&[0u8; 32], &[0u8; 32], sni, &[0u8; 32])
    }

    #[test]
    fn finds_sni_in_built_client_hello() {
        for sni in ["auth.vercel.com", "mci.ir", "a"] {
            let ch = client_hello(sni.as_bytes());
            assert_eq!(find_sni_range(&ch), Some((127, sni.len())), "sni={sni:?}");
        }
    }

    #[test]
    fn finds_sni_in_an_extension_after_leading_extensions() {
        // Rebuild by splicing: the built CH has the server_name extension
        // first (type 0x0000 at data offset 118). Insert a fake 4-byte
        // extension before it and bump the extensions-total-length field
        // (data offset 116..118) so the structure stays consistent.
        let ch = client_hello(b"example.com");
        let mut extended = Vec::with_capacity(ch.len() + 4);
        extended.extend_from_slice(&ch[..118]);
        extended.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // ext type 0x0017, len 0
        extended.extend_from_slice(&ch[118..]);
        // Bump the TLS record length (data offset 3..5), the handshake length
        // (data offset 6..8), and the extensions-total-length field (data
        // offset 116..118) so the structure stays consistent after the 4-byte
        // splice.
        let record_len = u16::from_be_bytes([extended[3], extended[4]]) + 4;
        extended[3] = (record_len >> 8) as u8;
        extended[4] = record_len as u8;
        let hs_len = u32::from_be_bytes([0, extended[6], extended[7], extended[8]]) + 4;
        extended[6] = (hs_len >> 16) as u8;
        extended[7] = (hs_len >> 8) as u8;
        extended[8] = hs_len as u8;
        let total = u16::from_be_bytes([extended[116], extended[117]]) + 4;
        extended[116] = (total >> 8) as u8;
        extended[117] = total as u8;
        assert_eq!(find_sni_range(&extended), Some((127 + 4, 11)));
    }

    #[test]
    fn rejects_non_handshake_payloads() {
        assert_eq!(find_sni_range(b"GET / HTTP/1.1"), None);
        assert_eq!(find_sni_range(&[]), None);
    }

    #[test]
    fn rejects_truncated_records() {
        let ch = client_hello(b"example.com");
        for cut in [4usize, 10, 100, ch.len() - 1] {
            assert_eq!(find_sni_range(&ch[..cut]), None, "cut={cut}");
        }
    }

    #[test]
    fn rejects_client_hello_without_server_name_extension() {
        let mut ch = client_hello(b"example.com");
        // blank the extension type bytes at data offset 118..120
        ch[118] = 0x00;
        ch[119] = 0x0b;
        assert_eq!(find_sni_range(&ch), None);
    }
}
