//! Shared TLS ClientHello SNI locator.
//!
//! Used by the socket-side and interceptor-side methods that mutate or split
//! the real SNI bytes (`mixed_case_sni`, `urg_sni_split`,
//! `sni_boundary_frag`).

/// Location of the SNI extension inside a TLS ClientHello payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SniBoundary {
    /// Offset one byte past the server_name extension's 2-byte length
    /// field — i.e. where the extension body begins.
    pub ext_len_field_end: usize,
    /// Offset of the first host_name byte within `data`.
    pub name_start: usize,
    /// Length of the host_name in bytes.
    pub name_len: usize,
}

/// Find the host_name (SNI) bytes inside a TLS ClientHello payload.
///
/// Returns `(start, len)` of the name bytes within `data`, or `None` if the
/// payload is not a complete ClientHello containing a valid non-empty
/// host_name. Implemented on top of [`find_sni_boundary`].
pub(crate) fn find_sni_range(data: &[u8]) -> Option<(usize, usize)> {
    find_sni_boundary(data).map(|b| (b.name_start, b.name_len))
}

/// Locate the SNI extension inside a TLS ClientHello payload.
///
/// Walks the TLS record header, handshake header, fixed ClientHello fields,
/// and the extension list to locate the `server_name` extension (type
/// `0x0000`) and its `host_name` entry (name type `0`). Returns the
/// boundary offsets, or `None` if the payload is not a complete ClientHello
/// containing a valid non-empty host_name.
pub(crate) fn find_sni_boundary(data: &[u8]) -> Option<SniBoundary> {
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
    let p = off + 2;
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
            // `body` starts 9 bytes into `data` (5 record header + 4
            // handshake header). The extension entry starts at `p + e` in
            // the extensions list; each entry has a 4-byte header
            // (type(2) + length(2)), then list_len(2) + name_type(1) +
            // name_len(2) precede the name bytes.
            let ext_header_start = 9 + p + e;
            return Some(SniBoundary {
                ext_len_field_end: ext_header_start + 4,
                name_start: ext_header_start + 4 + 2 + 1 + 2,
                name_len,
            });
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
    fn boundary_reports_offsets_for_built_client_hello() {
        let ch = client_hello(b"auth.vercel.com");
        let b = find_sni_boundary(&ch).expect("built CH must contain an SNI");
        // server_name ext header sits at data offset 118 (type 118..120,
        // length 120..122); name bytes start at 127 (matches existing
        // urg_sni_split tests).
        assert_eq!(b.ext_len_field_end, 122);
        assert_eq!(b.name_start, 127);
        assert_eq!(b.name_len, 15);
        assert_eq!(
            &ch[b.name_start..b.name_start + b.name_len],
            b"auth.vercel.com"
        );
    }

    #[test]
    fn boundary_accounts_for_leading_extensions() {
        // Splice a fake 4-byte extension before the server_name extension
        // and keep the record/handshake/extension lengths consistent
        // (same construction as the urg_sni_split leading-extension test).
        let ch = client_hello(b"example.com");
        let mut extended = Vec::with_capacity(ch.len() + 4);
        extended.extend_from_slice(&ch[..118]);
        extended.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // ext type 0x0017, len 0
        extended.extend_from_slice(&ch[118..]);
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

        let b = find_sni_boundary(&extended).expect("must still find SNI");
        assert_eq!(b.ext_len_field_end, 122 + 4);
        assert_eq!(b.name_start, 127 + 4);
        assert_eq!(b.name_len, 11);
    }

    #[test]
    fn boundary_rejects_non_handshake_and_truncated_payloads() {
        assert_eq!(find_sni_boundary(b"GET / HTTP/1.1"), None);
        assert_eq!(find_sni_boundary(&[]), None);
        let ch = client_hello(b"example.com");
        for cut in [4usize, 10, 100, ch.len() - 1] {
            assert_eq!(find_sni_boundary(&ch[..cut]), None, "cut={cut}");
        }
    }

    #[test]
    fn boundary_rejects_client_hello_without_server_name_extension() {
        let mut ch = client_hello(b"example.com");
        ch[118] = 0x00;
        ch[119] = 0x0b; // extension type 0x000b instead of 0x0000
        assert_eq!(find_sni_boundary(&ch), None);
    }

    #[test]
    fn find_sni_range_delegates_to_boundary() {
        let ch = client_hello(b"mci.ir");
        assert_eq!(find_sni_range(&ch), Some((127, 6)));
    }
}
