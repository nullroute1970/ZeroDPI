//! `mixed_case_sni` bypass: SNI Case Randomization.
//!
//! ## How it works
//!
//! Alters the ASCII letter case of the hostname inside the TLS ClientHello's
//! SNI extension (e.g. `wikipedia.org` → `wIkIpeDiA.oRg`).  Per RFC 6066 /
//! RFC 4366 the SNI hostname is ASCII case-insensitive, and destination
//! servers and CDNs lowercase it during lookup, so the TLS handshake is
//! unaffected.  DPI middleboxes that match blocklists with exact,
//! case-sensitive string comparisons fail to match the mixed-case name.
//!
//! The mutation is length-preserving and only touches the `host_name` bytes:
//! ASCII letters are re-cased, everything else (digits, dots, hyphens) is
//! left as-is — important for punycode SNIs whose digits carry meaning.
//!
//! This method does **not** inject fake packets and does **not** use
//! WinDivert/NFQUEUE interception; it operates entirely inside the proxy
//! task on the real ClientHello relayed to the upstream server (same pattern
//! as `tls_padding`).
//!
//! Parsing is generic and **fail-open**: any record that does not parse as a
//! complete TLS ClientHello containing a non-empty `host_name` is left
//! untouched (`apply` returns `None` and the caller forwards the original
//! bytes).  The same applies when the SNI contains no ASCII letters at all
//! (e.g. a purely numeric name), because there is nothing to flip.
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `MIXED_CASE_SNI_FLIP_ALL` | `bool` | `false` | `false`: random case per letter, seeded per connection, ≥1 flip guaranteed. `true`: every ASCII letter case-inverted (`a`→`A`, `A`→`a`). |

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::methods::sni::find_sni_range;

/// Parameters for the `mixed_case_sni` bypass method.
#[derive(Debug, Clone, Copy)]
pub struct MixedCaseSni {
    /// When `true`, every ASCII letter in the SNI is case-inverted instead of
    /// randomly re-cased.
    flip_all: bool,
}

impl MixedCaseSni {
    /// Build parameters from the application config.
    pub fn new(cfg: &Config) -> Self {
        Self {
            flip_all: cfg.MIXED_CASE_SNI_FLIP_ALL,
        }
    }

    /// Fixed constructor (used by tests).
    pub fn exact(flip_all: bool) -> Self {
        Self { flip_all }
    }

    /// Randomize the case of the SNI hostname in `record`, returning the
    /// mutated record, or `None` when the record is not a parseable TLS
    /// ClientHello with a non-empty host_name containing at least one ASCII
    /// letter (fail-open: forward unchanged).
    pub fn apply(&self, record: &[u8]) -> Option<Vec<u8>> {
        let mut rng = MixedCaseRng::new();
        self.apply_with_rng(record, &mut rng)
    }

    /// Same as [`apply`], but with an explicit RNG (test seam).
    fn apply_with_rng(&self, record: &[u8], rng: &mut MixedCaseRng) -> Option<Vec<u8>> {
        let (name_start, name_len) = find_sni_range(record)?;
        let name = &record[name_start..name_start + name_len];
        let mut out = record.to_vec();

        if self.flip_all {
            for (i, &b) in name.iter().enumerate() {
                if b.is_ascii_alphabetic() {
                    out[name_start + i] = swap_ascii_case(b);
                }
            }
            return Some(out);
        }

        // Random case per letter; remember letter indexes so we can enforce
        // the ≥1 flip guarantee afterwards.
        let mut letters: Vec<usize> = Vec::new();
        let mut flipped = false;
        for (i, &b) in name.iter().enumerate() {
            if !b.is_ascii_alphabetic() {
                continue;
            }
            letters.push(i);
            let new = if rng.next_u64() & 1 == 0 {
                b.to_ascii_lowercase()
            } else {
                b.to_ascii_uppercase()
            };
            flipped |= new != b;
            out[name_start + i] = new;
        }
        if letters.is_empty() {
            return None; // nothing to flip — leave the record alone
        }
        if !flipped {
            // Guarantee at least one case change: invert the case of one
            // randomly chosen letter.
            let pick = (rng.next_u64() as usize) % letters.len();
            let i = letters[pick];
            out[name_start + i] = swap_ascii_case(out[name_start + i]);
        }
        Some(out)
    }
}

/// Invert the ASCII case of a letter (`a` ↔ `A`).
fn swap_ascii_case(b: u8) -> u8 {
    if b.is_ascii_lowercase() {
        b.to_ascii_uppercase()
    } else {
        b.to_ascii_lowercase()
    }
}

static RNG_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Tiny splitmix64 RNG (same pattern as `tls_padding.rs` /
/// `tcp_segmentation.rs`) so sampling does not pull in the `rand` crate.
#[derive(Debug, Clone, Copy)]
struct MixedCaseRng {
    state: u64,
}

impl MixedCaseRng {
    /// Seed from wall-clock nanos plus a global counter: a fresh seed per
    /// connection, so each connection gets its own case pattern.
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            state: nanos
                ^ RNG_COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed)
                ^ 0xC0FF_EE00_DEAD_BEEF,
        }
    }

    /// Deterministic constructor (test seam).
    #[cfg(test)]
    fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_template::build_client_hello;

    fn client_hello(sni: &[u8]) -> Vec<u8> {
        build_client_hello(&[0u8; 32], &[0u8; 32], sni, &[0u8; 32])
    }

    /// The template places the SNI name at byte offset 127 (same assumption
    /// as the `urg_sni_split` and `tls_padding` tests).
    const SNI_OFFSET: usize = 127;

    #[test]
    fn random_mode_preserves_non_alpha_bytes_and_flips_some_letters() {
        let sni = b"wiki9-pedia.org";
        let record = client_hello(sni);
        for seed in 0..50u64 {
            let mut rng = MixedCaseRng::from_seed(seed);
            let out = MixedCaseSni::exact(false)
                .apply_with_rng(&record, &mut rng)
                .expect("template ClientHello must parse");
            assert_eq!(out.len(), record.len(), "case randomization is length-preserving");
            let mut flipped = false;
            for (i, &b) in sni.iter().enumerate() {
                let got = out[SNI_OFFSET + i];
                if b.is_ascii_alphabetic() {
                    assert!(
                        got == b.to_ascii_lowercase() || got == b.to_ascii_uppercase(),
                        "letter {i} must stay the same ASCII letter"
                    );
                    flipped |= got != b;
                } else {
                    assert_eq!(got, b, "non-alpha byte {i} must be untouched");
                }
            }
            assert!(flipped, "seed {seed} must flip at least one letter");
        }
    }

    #[test]
    fn flip_all_inverts_every_letter() {
        let sni = b"aBcD.XyZ-01";
        let record = client_hello(sni);
        let out = MixedCaseSni::exact(true).apply(&record).expect("template ClientHello must parse");
        assert_eq!(out.len(), record.len());
        for (i, &b) in sni.iter().enumerate() {
            let got = out[SNI_OFFSET + i];
            if b.is_ascii_alphabetic() {
                assert_eq!(got, swap_ascii_case(b), "letter {i} must be case-inverted");
            } else {
                assert_eq!(got, b, "non-alpha byte {i} must be untouched");
            }
        }
    }

    #[test]
    fn single_letter_name_still_flips() {
        let record = client_hello(b"a");
        for seed in 0..200u64 {
            let mut rng = MixedCaseRng::from_seed(seed);
            let out = MixedCaseSni::exact(false)
                .apply_with_rng(&record, &mut rng)
                .expect("template ClientHello must parse");
            assert_ne!(out[SNI_OFFSET], b'a', "seed {seed} must flip the single letter");
        }
    }

    #[test]
    fn malformed_and_sniless_records_pass_through() {
        let method = MixedCaseSni::exact(false);
        assert_eq!(method.apply(b"GET / HTTP/1.1"), None);
        assert_eq!(method.apply(&[]), None);
        assert_eq!(method.apply(&[0x16, 0x03, 0x01, 0x00]), None);
        let record = client_hello(b"example.com");
        assert_eq!(method.apply(&record[..10]), None);
    }

    #[test]
    fn numeric_only_sni_passes_through() {
        let record = client_hello(b"1234.56");
        let method = MixedCaseSni::exact(false);
        let mut rng = MixedCaseRng::from_seed(7);
        assert_eq!(method.apply_with_rng(&record, &mut rng), None);
    }
}
