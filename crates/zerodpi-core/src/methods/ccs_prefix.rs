//! `ccs_prefix` bypass: TLS 1.3 middlebox-compat ChangeCipherSpec prefix.
//!
//! ## How it works
//!
//! RFC 8446 §4.1.3 defines a "middlebox compatibility mode" in which a TLS
//! 1.3 client sends a dummy ChangeCipherSpec record before its real
//! ClientHello, and RFC 8446 §5.5 requires TLS 1.3 servers to treat a
//! ChangeCipherSpec received before their first Finished as a no-op.  Many
//! DPI middleboxes key their classification on the *first* TLS record of a
//! stream; the first record is now a CCS without any SNI, so the flow is
//! classified benign and the genuine ClientHello in record two is never
//! inspected.
//!
//! This method does **not** inject fake packets and does **not** use
//! WinDivert/NFQUEUE interception; the proxy writes the 6-byte CCS record
//! as the very first bytes of the upstream stream, immediately before the
//! (possibly transformed) ClientHello.  Because the platform packet
//! interceptor is not involved, this method does not implement
//! [`super::BypassMethod`] and the flow is never registered in the
//! [`crate::flow::FlowTable`].
//!
//! TLS 1.2 servers are not required to tolerate a pre-ClientHello CCS
//! (RFC 5246 treats an unexpected CCS as an error); the method targets
//! TLS 1.3 endpoints.
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `CCS_PREFIX_RECORD_VERSION` | hex string | `"0x0303"` | The two record-version bytes of the dummy CCS record. |

use crate::config::Config;

/// Number of bytes in the dummy ChangeCipherSpec record:
/// content type (1) + record version (2) + length (2) + CCS payload (1).
pub const CCS_RECORD_LEN: usize = 6;

/// Parameters for the `ccs_prefix` bypass method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CcsPrefix {
    /// The two TLS record-version bytes of the dummy CCS record.
    record_version: [u8; 2],
}

impl CcsPrefix {
    /// Build parameters from the application config. Callers must run
    /// `Config::validate` first (it rejects invalid
    /// `CCS_PREFIX_RECORD_VERSION` values).
    pub fn new(cfg: &Config) -> Self {
        let record_version = parse_record_version(&cfg.CCS_PREFIX_RECORD_VERSION)
            .expect("Config::validate should reject invalid CCS_PREFIX_RECORD_VERSION");
        Self { record_version }
    }

    /// Fixed constructor for tests.
    pub fn exact(record_version: u16) -> Self {
        Self {
            record_version: record_version.to_be_bytes(),
        }
    }

    /// The dummy ChangeCipherSpec record: content type `0x14` (CCS),
    /// `record_version`, body length `0x0001`, body `0x01`.
    pub fn record(&self) -> [u8; CCS_RECORD_LEN] {
        [
            0x14,
            self.record_version[0],
            self.record_version[1],
            0x00,
            0x01,
            0x01,
        ]
    }
}

/// Parse a `CCS_PREFIX_RECORD_VERSION` config value: two hex bytes,
/// with or without a `0x` prefix (`"0x0303"` or `"0303"`).
pub fn parse_record_version(input: &str) -> Result<[u8; 2], String> {
    let cleaned = input.trim();
    let hex = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(cleaned);
    if hex.len() != 4 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "'{input}' is not a valid CCS_PREFIX_RECORD_VERSION; \
             expected two hex bytes such as \"0x0303\""
        ));
    }
    let hi = u8::from_str_radix(&hex[..2], 16).map_err(|e| e.to_string())?;
    let lo = u8::from_str_radix(&hex[2..], 16).map_err(|e| e.to_string())?;
    Ok([hi, lo])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_default_ccs_record() {
        let ccs = CcsPrefix::exact(0x0303);
        assert_eq!(ccs.record(), [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    }

    #[test]
    fn builds_ccs_record_with_custom_version() {
        let ccs = CcsPrefix::exact(0x0301);
        assert_eq!(ccs.record(), [0x14, 0x03, 0x01, 0x00, 0x01, 0x01]);
    }

    #[test]
    fn record_uses_ccs_content_type_byte() {
        assert_eq!(CcsPrefix::exact(0x0303).record()[0], 0x14);
    }

    #[test]
    fn parses_record_version_with_and_without_0x_prefix() {
        assert_eq!(parse_record_version("0x0303").unwrap(), [0x03, 0x03]);
        assert_eq!(parse_record_version("0303").unwrap(), [0x03, 0x03]);
        assert_eq!(parse_record_version("0x0301").unwrap(), [0x03, 0x01]);
    }

    #[test]
    fn rejects_malformed_record_versions() {
        for bad in ["0x03GG", "0x03", "0x03033", "0x030", "", "xyz"] {
            assert!(parse_record_version(bad).is_err(), "should reject '{bad}'");
        }
    }
}
