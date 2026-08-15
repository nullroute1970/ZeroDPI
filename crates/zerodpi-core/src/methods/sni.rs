//! Shared TLS ClientHello SNI locator.
//!
//! Used by the socket-side and interceptor-side methods that mutate the real
//! SNI bytes (`mixed_case_sni`, `urg_sni_split`).

/// Find the host_name (SNI) bytes inside a TLS ClientHello payload.
///
/// Walks the TLS record header, handshake header, fixed ClientHello fields,
/// and the extension list to locate the `server_name` extension (type
/// `0x0000`) and its `host_name` entry (name type `0`). Returns `(start, len)`
/// of the name bytes within `data`, or `None` if the payload is not a complete
/// ClientHello containing a valid non-empty host_name.
pub(crate) fn find_sni_range(data: &[u8]) -> Option<(usize, usize)> {
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
