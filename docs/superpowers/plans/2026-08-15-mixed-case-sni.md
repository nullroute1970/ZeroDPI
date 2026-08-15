# mixed_case_sni Bypass Method Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new socket-side DPI bypass method `mixed_case_sni` that randomizes the ASCII letter case of the SNI hostname inside the real TLS ClientHello (e.g. `wikipedia.org` → `wIkIpeDiA.oRg`), defeating DPI that does case-sensitive blocklist matching.

**Architecture:** Follows the existing `tls_padding` socket-side pattern exactly: a pure transform module under `crates/zerodpi-core/src/methods/`, registered in the config's `BYPASS_METHOD` list plumbing, and applied inside the proxy task to the first ClientHello record before it is written upstream. No packet interceptor, no root/admin requirement, combinable with every other method the way `tls_padding` is.

**Tech Stack:** Rust 2021 workspace (`zerodpi-core`), serde/TOML config, tokio proxy. No new dependencies — reuse the splitmix64 RNG pattern already in `tls_padding.rs`.

**Spec:** The approved design is summarized in the repo conversation (bounded task, no separate spec file). Decisions locked in: (1) socket-side like `tls_padding`, no root needed; (2) random case per letter, per-connection RNG seed, guaranteed ≥1 flipped letter; (3) unrestricted combinability like `tls_padding` (including `ip_bypass_plus`); (4) one config knob `MIXED_CASE_SNI_FLIP_ALL` (bool, default `false`) — when `true`, every ASCII letter is case-inverted (`a`→`A`, `A`→`a`) instead of randomly re-cased.

## Global Constraints

- Rust 2021 workspace; `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` must all pass.
- 4-space indentation, `snake_case` modules/functions, `PascalCase` types, `SCREAMING_SNAKE_CASE` config keys.
- No new external crates (project avoids `rand`; use the local splitmix64 RNG pattern).
- Fail-open behavior: any record that does not parse as a complete TLS ClientHello with a non-empty SNI `host_name` must be forwarded unchanged (`apply` returns `None`).
- Only ASCII letters are touched; digits, dots, hyphens are preserved (punycode SNIs must keep their digits).
- The mutation is length-preserving (no ClientHello length fields need updating).
- Commit style: conventional prefixes, e.g. `feat: add mixed_case_sni bypass method`.

---

### Task 1: Extract shared SNI locator into `methods/sni.rs`

**Files:**
- Create: `crates/zerodpi-core/src/methods/sni.rs`
- Modify: `crates/zerodpi-core/src/methods/mod.rs` (module registration)
- Modify: `crates/zerodpi-core/src/methods/urg_sni_split.rs` (remove local copy, import shared one)

**Interfaces:**
- Consumes: nothing new.
- Produces: `crate::methods::sni::find_sni_range(data: &[u8]) -> Option<(usize, usize)>` — returns `(start, len)` of the SNI `host_name` bytes inside a complete TLS ClientHello, or `None`. Task 2 and Task 4 tests depend on this.

- [ ] **Step 1: Create `crates/zerodpi-core/src/methods/sni.rs`**

Move `find_sni_range` verbatim from `urg_sni_split.rs` (only change: make it `pub(crate)`). Full file content:

```rust
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
```

- [ ] **Step 2: Register the module in `crates/zerodpi-core/src/methods/mod.rs`**

Change:

```rust
pub mod composite;
pub mod low_ttl;
pub mod tcp_segmentation;
```

to:

```rust
pub mod composite;
pub mod low_ttl;
pub mod mixed_case_sni;
pub mod sni;
pub mod tcp_segmentation;
```

- [ ] **Step 3: Update `crates/zerodpi-core/src/methods/urg_sni_split.rs`**

Replace the whole local function + doc comment (from `/// Find the host_name (SNI) bytes inside a TLS ClientHello payload.` through the final `}` of `find_sni_range`, immediately before `/// Resolve the config position`) with nothing, and add the import. Two edits:

Edit A — imports, change:

```rust
use super::{BypassMethod, MethodAction};
use crate::config::{Config, SniSplitPosition};
```

to:

```rust
use super::sni::find_sni_range;
use super::{BypassMethod, MethodAction};
use crate::config::{Config, SniSplitPosition};
```

Edit B — delete the function: oldText is the exact block from the doc comment down to the closing brace (the same code as Task 1 Step 1 but with `fn find_sni_range` instead of `pub(crate) fn find_sni_range`), newText is empty string. Verify no duplicate/leftover `find_sni_range` remains (the tests at the bottom of the file use it via `use super::*;`, which now resolves to the import).

- [ ] **Step 4: Run the existing tests to verify the refactor is behavior-preserving**

Run: `cargo test --workspace urg_sni_split`
Expected: PASS (all `urg_sni_split` tests: `finds_sni_in_built_client_hello`, `finds_sni_in_an_extension_after_leading_extensions`, `rejects_non_handshake_payloads`, `rejects_truncated_records`, `rejects_client_hello_without_server_name_extension`, and the rest)

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/methods/sni.rs crates/zerodpi-core/src/methods/mod.rs crates/zerodpi-core/src/methods/urg_sni_split.rs
git commit -m "refactor: extract shared SNI locator into methods::sni"
```

---

### Task 2: `mixed_case_sni` transform module (TDD)

**Files:**
- Create: `crates/zerodpi-core/src/methods/mixed_case_sni.rs`

**Interfaces:**
- Consumes: `crate::methods::sni::find_sni_range` (Task 1), `crate::config::Config::MIXED_CASE_SNI_FLIP_ALL` (added in Task 3 — this task compiles only after Task 3; if implementing strictly task-by-task, do Task 3's config-field edit first, or add the field as part of this task and fold Task 3's remaining registry work there).
- Produces: `pub struct MixedCaseSni { flip_all: bool }` with `MixedCaseSni::new(cfg: &Config) -> Self`, `MixedCaseSni::exact(flip_all: bool) -> Self`, `MixedCaseSni::apply(&self, record: &[u8]) -> Option<Vec<u8>>` (used by Task 4).

**Note on ordering:** `MixedCaseSni::new` reads `cfg.MIXED_CASE_SNI_FLIP_ALL`, which does not exist yet. Add the field to `Config` (Task 3, Step 4) before compiling this task, or implement this task with `MixedCaseSni::new` reading the field and expect the compile error to clear in Task 3.

- [ ] **Step 1: Write the failing tests**

Create `crates/zerodpi-core/src/methods/mixed_case_sni.rs` containing only the test module (plus empty struct stubs so the file parses — the tests must fail to compile/run before the implementation exists):

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-core mixed_case_sni`
Expected: FAIL (compile error — `MixedCaseSni`, `MixedCaseRng`, `swap_ascii_case` undefined). If you also added the `Config` field per the ordering note, the only remaining failure is the undefined symbols above.

- [ ] **Step 3: Write the implementation**

Replace the stub file with the full module:

```rust
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core mixed_case_sni`
Expected: PASS (all 5 tests)

- [ ] **Step 5: Full crate test + lint**

Run: `cargo test -p zerodpi-core` then `cargo clippy -p zerodpi-core --all-targets -- -D warnings`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/zerodpi-core/src/methods/mixed_case_sni.rs
git commit -m "feat: add mixed_case_sni case-randomization transform"
```

---

### Task 3: Config plumbing — method registry, socket-only lists, config field

**Files:**
- Modify: `crates/zerodpi-core/src/config.rs`
- Modify: `crates/zerodpi-core/src/methods/mod.rs`

**Interfaces:**
- Consumes: `MixedCaseSni` (Task 2) for the `build_method` no-op arm.
- Produces: `Config::MIXED_CASE_SNI_FLIP_ALL: bool` (default `false`), `"mixed_case_sni"` accepted in `BYPASS_METHOD` everywhere, classified as socket-only (`is_socket_only() == true` for `["mixed_case_sni"]`, `requires_interceptor() == false`).

- [ ] **Step 1: Write the failing tests in `crates/zerodpi-core/src/config.rs` test module**

Append these tests inside the existing `#[cfg(test)] mod tests` (the test module already has `toml::from_str`-based helpers and `ip_bypass_plus_accepts_tls_frag` / `ip_bypass_plus_rejects_fake_sni_methods` as patterns):

```rust
    #[test]
    fn mixed_case_sni_flag_defaults_to_false() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap();
        assert!(!cfg.MIXED_CASE_SNI_FLIP_ALL);
    }

    #[test]
    fn mixed_case_sni_flag_parses_true() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               MIXED_CASE_SNI_FLIP_ALL = true"#,
        )
        .unwrap();
        assert!(cfg.MIXED_CASE_SNI_FLIP_ALL);
    }

    #[test]
    fn validate_accepts_mixed_case_sni() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "mixed_case_sni""#,
        )
        .unwrap();
        cfg.validate().unwrap();
        assert!(cfg.BYPASS_METHOD.is_socket_only());
        assert!(!cfg.BYPASS_METHOD.requires_interceptor());
    }

    #[test]
    fn ip_bypass_plus_accepts_mixed_case_sni() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "ip_bypass_plus"
            BYPASS_METHOD = "mixed_case_sni"
            LOW_TTL_DISCOVER = false
            SELECTED_IP = "1.2.3.4"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.MODE, "ip_bypass_plus");
        assert_eq!(cfg.BYPASS_METHOD, "mixed_case_sni");
    }
```

- [ ] **Step 2: Run the config tests to verify they fail**

Run: `cargo test -p zerodpi-core config::tests::mixed_case_sni`
Expected: FAIL (compile error — `MIXED_CASE_SNI_FLIP_ALL` field missing; `is_socket_only` returns false for the new method name so `validate_accepts_mixed_case_sni` also fails)

- [ ] **Step 3: Implement the config changes in `crates/zerodpi-core/src/config.rs`**

Edit 1 — add the method to `BASE_BYPASS_METHODS` (around line 188). Change:

```rust
    "tls_frag",
    "tls_padding",
    "urg_sni_split",
];
```

to:

```rust
    "tls_frag",
    "tls_padding",
    "mixed_case_sni",
    "urg_sni_split",
];
```

Edit 2 — classify as socket-only. Change both `matches!` arms in `is_socket_only` and `requires_interceptor` from `"tls_frag" | "tls_padding"` to `"tls_frag" | "tls_padding" | "mixed_case_sni"`. Update the `is_socket_only` doc comment: `(`["tls_frag"]`, `["tls_padding"]`, or both), which need no packet interceptor.` → `(`["tls_frag"]`, `["tls_padding"]`, `["mixed_case_sni"]`, or combinations), which need no packet interceptor.`

Edit 3 — add the config field. Insert after the `TLS_PADDING_POSITION` field block (after its `#[serde(default = "default_tls_padding_position")] pub TLS_PADDING_POSITION: String,` line):

```rust
    // -----------------------------------------------------------------------
    // mixed_case_sni method parameters
    // -----------------------------------------------------------------------
    /// When `true`, every ASCII letter in the SNI hostname is case-inverted
    /// (`a` → `A`, `A` → `a`).  When `false` (default), each letter is
    /// randomly uppercased or lowercased per connection, with a guaranteed
    /// minimum of one flipped letter.
    #[serde(default)]
    pub MIXED_CASE_SNI_FLIP_ALL: bool,
```

Edit 4 — allow in `ip_bypass_plus`. In `validate()`, change:

```rust
        if self.MODE == "ip_bypass_plus"
            && !self
                .BYPASS_METHOD
                .iter()
                .all(|m| matches!(m, "tls_record_frag" | "tls_frag" | "tls_padding"))
        {
            anyhow::bail!(
                "MODE = \"ip_bypass_plus\" supports only real-SNI-preserving BYPASS_METHOD values: \"tls_record_frag\", \"tls_frag\", or \"tls_padding\""
            );
        }
```

to the same with `matches!(m, "tls_record_frag" | "tls_frag" | "tls_padding" | "mixed_case_sni")` and error message `...values: \"tls_record_frag\", \"tls_frag\", \"tls_padding\", or \"mixed_case_sni\"`.

Edit 5 — update the `BYPASS_METHOD` doc comment bullet list (around line 443): after the `"tls_padding"` bullet, insert:

```rust
    /// - `"mixed_case_sni"` — SNI Case Randomization. Randomizes the ASCII
    ///   letter case of the hostname in the SNI extension of the client's
    ///   real ClientHello (e.g. `wikipedia.org` → `wIkIpeDiA.oRg`).
    ///   Destination servers lowercase the hostname during lookup (RFC 6066
    ///   hostnames are case-insensitive), while DPI using case-sensitive
    ///   blocklist matching misses. Socket-side only: does not inject fake
    ///   packets or use WinDivert/NFQUEUE interception; operates inside the
    ///   proxy on the relayed ClientHello.
```

and change the sentence `tls_record_frag`, `tls_frag`, and `tls_padding` add the data stage.` → `` `tls_record_frag`, `tls_frag`, `tls_padding`, and `mixed_case_sni` add the data stage.``

- [ ] **Step 4: Implement the registry changes in `crates/zerodpi-core/src/methods/mod.rs`**

Edit 1 — add the socket-side arm in `build_method`. Change:

```rust
            "tls_frag" => {}    // socket side; handled directly in proxy.rs
            "tls_padding" => {} // socket side; handled directly in proxy.rs
```

to:

```rust
            "tls_frag" => {}         // socket side; handled directly in proxy.rs
            "tls_padding" => {}      // socket side; handled directly in proxy.rs
            "mixed_case_sni" => {}   // socket side; handled directly in proxy.rs
```

Edit 2 — update the module docs at the top of the file: add a `mixed_case_sni` bullet after the `tls_padding` bullet in the "Socket-based methods" list:

```rust
//! - `mixed_case_sni` — SNI Case Randomization. Randomizes the ASCII letter
//!   case of the hostname inside the real ClientHello's SNI extension;
//!   destination servers lowercase it per RFC 6066, so DPI doing
//!   case-sensitive blocklist matching misses while the handshake succeeds.
```

Edit 3 — update `build_method`'s doc comment: `None for socket-only lists (`["tls_frag"]`, `["tls_padding"]`, `["tls_frag", "tls_padding"]`)` → `None for socket-only lists (`["tls_frag"]`, `["tls_padding"]`, `["mixed_case_sni"]`, or combinations)`.

- [ ] **Step 5: Write the `build_method` tests in `methods/mod.rs`**

Append to the existing test module:

```rust
    #[test]
    fn socket_mixed_case_method_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "mixed_case_sni""#);
        assert!(build_method(&cfg).is_none());
    }

    #[test]
    fn builds_composite_with_mixed_case_sni() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["wrong_seq", "mixed_case_sni"]"#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq + mixed_case_sni");
    }
```

- [ ] **Step 6: Run all tests to verify they pass**

Run: `cargo test -p zerodpi-core`
Expected: PASS — including the new tests from Steps 1 and 5. Note `builds_composite_with_mixed_case_sni` passes because `mixed_case_sni` is registered in `BASE_BYPASS_METHODS` (validate) and skipped by `build_method` (socket-side arm).

- [ ] **Step 7: Commit**

```bash
git add crates/zerodpi-core/src/config.rs crates/zerodpi-core/src/methods/mod.rs
git commit -m "feat: register mixed_case_sni as socket-only bypass method in config"
```

---

### Task 4: Proxy wiring — apply the transform to the real ClientHello

**Files:**
- Modify: `crates/zerodpi-core/src/proxy.rs`

**Interfaces:**
- Consumes: `MixedCaseSni` (Task 2), `Config::MIXED_CASE_SNI_FLIP_ALL` (Task 3).
- Produces: `ConnectionSettings::apply_socket_transforms(&self, record: &[u8]) -> Vec<u8>` — chains `tls_padding` then `mixed_case_sni`, fail-open.

- [ ] **Step 1: Write the failing tests**

Append to the existing `mod tests` in `proxy.rs` (it already has `use super::*;` and TOML `Config` parsing is available via `toml::from_str`):

```rust
    fn cfg_with(method_line: &str, extra: &str) -> Config {
        toml::from_str(&format!(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               {method_line}
               {extra}"#
        ))
        .unwrap()
    }

    fn swap_case(b: u8) -> u8 {
        if b.is_ascii_lowercase() {
            b.to_ascii_uppercase()
        } else {
            b.to_ascii_lowercase()
        }
    }

    #[test]
    fn settings_include_mixed_case_sni_when_listed() {
        let cfg = cfg_with(
            r#"BYPASS_METHOD = ["wrong_seq", "mixed_case_sni"]"#,
            "",
        );
        let s = ConnectionSettings::from_config(&cfg);
        assert!(s.mixed_case_sni.is_some());
        assert!(s.tls_padding.is_none());

        let cfg = cfg_with(r#"BYPASS_METHOD = "tls_padding""#, "");
        let s = ConnectionSettings::from_config(&cfg);
        assert!(s.mixed_case_sni.is_none());
        assert!(s.tls_padding.is_some());
    }

    #[test]
    fn apply_socket_transforms_chains_padding_then_case_randomization() {
        let cfg = cfg_with(
            r#"BYPASS_METHOD = ["tls_padding", "mixed_case_sni"]"#,
            r#"TLS_PADDING_SIZE = 4
               MIXED_CASE_SNI_FLIP_ALL = true"#,
        );
        let settings = ConnectionSettings::from_config(&cfg);
        let record = crate::tls_template::build_client_hello(
            &[0u8; 32],
            &[0u8; 32],
            b"wikipedia.org",
            &[0u8; 32],
        );
        let out = settings.apply_socket_transforms(&record);
        // padding extension header (4 bytes) + 4 zero bytes
        assert_eq!(out.len(), record.len() + 8);
        // SNI was at offset 127; padding moved it by 8 bytes
        let (start, len) = crate::methods::sni::find_sni_range(&out)
            .expect("transformed record must still parse");
        assert_eq!((start, len), (127 + 8, 13));
        for (i, &orig) in b"wikipedia.org".iter().enumerate() {
            let got = out[start + i];
            if orig.is_ascii_alphabetic() {
                assert_eq!(got, swap_case(orig), "letter {i} must be case-inverted");
            } else {
                assert_eq!(got, orig, "non-alpha byte {i} must be untouched");
            }
        }
    }
```

Note: the test module's existing imports already cover `Config`/`toml` — if the file's test module lacks `use toml;` (it currently relies on `super::*` plus tokio imports), `toml::from_str` resolves through the crate dependency as a path, so no import line is needed.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p zerodpi-core proxy::tests::settings_include_mixed_case_sni_when_listed proxy::tests::apply_socket_transforms_chains_padding_then_case_randomization`
Expected: FAIL (compile error — `ConnectionSettings` has no `mixed_case_sni` field and no `apply_socket_transforms`)

- [ ] **Step 3: Implement the wiring**

Edit 1 — import (next to the existing `use crate::methods::tls_padding::TlsPadding;` at the top of `proxy.rs`):

```rust
use crate::methods::mixed_case_sni::MixedCaseSni;
```

Edit 2 — `ConnectionSettings` struct and constructor. Change:

```rust
struct ConnectionSettings {
    bypass_timeout: Duration,
    max_lifetime: Option<Duration>,
    segment_first_client_hello: bool,
    tls_padding: Option<TlsPadding>,
    tcp_segmentation: TcpSegmentation,
}

impl ConnectionSettings {
    fn from_config(cfg: &Config) -> Self {
        let tcp_segmentation = TcpSegmentation::new(cfg);
        Self {
            bypass_timeout: Duration::from_secs(cfg.BYPASS_TIMEOUT_SECS),
            max_lifetime: configured_relay_max_lifetime(cfg),
            segment_first_client_hello: cfg.BYPASS_METHOD.contains("tls_frag"),
            tls_padding: cfg
                .BYPASS_METHOD
                .contains("tls_padding")
                .then(|| TlsPadding::new(cfg)),
            tcp_segmentation,
        }
    }
}
```

to:

```rust
struct ConnectionSettings {
    bypass_timeout: Duration,
    max_lifetime: Option<Duration>,
    segment_first_client_hello: bool,
    tls_padding: Option<TlsPadding>,
    mixed_case_sni: Option<MixedCaseSni>,
    tcp_segmentation: TcpSegmentation,
}

impl ConnectionSettings {
    fn from_config(cfg: &Config) -> Self {
        let tcp_segmentation = TcpSegmentation::new(cfg);
        Self {
            bypass_timeout: Duration::from_secs(cfg.BYPASS_TIMEOUT_SECS),
            max_lifetime: configured_relay_max_lifetime(cfg),
            segment_first_client_hello: cfg.BYPASS_METHOD.contains("tls_frag"),
            tls_padding: cfg
                .BYPASS_METHOD
                .contains("tls_padding")
                .then(|| TlsPadding::new(cfg)),
            mixed_case_sni: cfg
                .BYPASS_METHOD
                .contains("mixed_case_sni")
                .then(|| MixedCaseSni::new(cfg)),
            tcp_segmentation,
        }
    }

    /// Apply the socket-side ClientHello transforms: `tls_padding` first,
    /// then `mixed_case_sni`. Fail-open: a record that does not parse is
    /// returned unchanged.
    fn apply_socket_transforms(&self, record: &[u8]) -> Vec<u8> {
        let mut out = record.to_vec();
        if let Some(padding) = self.tls_padding {
            out = padding.apply(&out).unwrap_or(out);
        }
        if let Some(mixed) = self.mixed_case_sni {
            out = mixed.apply(&out).unwrap_or(out);
        }
        out
    }
}
```

Edit 3 — combo path (`handle_intercept_connection`): replace all three occurrences of the pattern

```rust
                let client_hello = settings
                    .tls_padding
                    .and_then(|p| p.apply(&client_hello))
                    .unwrap_or(client_hello);
```

with

```rust
                let client_hello = settings.apply_socket_transforms(&client_hello);
```

There are two such `client_hello` blocks (the `TlsFragPackets::TlsHello` branch and the final `else` branch) and one `client_data` block in the `TlsFragPackets::WriteRange { .. }` branch:

```rust
                        let client_data = settings
                            .tls_padding
                            .and_then(|p| p.apply(&client_data))
                            .unwrap_or(client_data);
```

→

```rust
                        let client_data = settings.apply_socket_transforms(&client_data);
```

The `WriteRange` branch has a comment above it: `// Fail-open: pad only when the first write parses as a complete ClientHello record.` — change `pad only` to `transform only`.

Edit 4 — socket-only path (`handle_tcp_seg_connection_with_ip`). Change:

```rust
    // When tls_padding is listed, read the first TLS record and expand it
    // with the RFC 7685 padding extension before any mode-specific handling.
    // Fail-open: unparseable records are forwarded unchanged.
    let padded_prefix = if cfg.BYPASS_METHOD.contains("tls_padding") {
        let record = read_one_tls_record(&mut incoming)
            .await
            .context("tls_padding: reading ClientHello from client")?;
        Some(TlsPadding::new(&cfg).apply(&record).unwrap_or(record))
    } else {
        None
    };
```

to:

```rust
    // When tls_padding and/or mixed_case_sni are listed, read the first TLS
    // record and transform it before any mode-specific handling. Fail-open:
    // unparseable records are forwarded unchanged.
    let transformed_prefix = if cfg.BYPASS_METHOD.contains("tls_padding")
        || cfg.BYPASS_METHOD.contains("mixed_case_sni")
    {
        let record = read_one_tls_record(&mut incoming)
            .await
            .context("socket transforms: reading ClientHello from client")?;
        let record = if cfg.BYPASS_METHOD.contains("tls_padding") {
            TlsPadding::new(&cfg).apply(&record).unwrap_or(record)
        } else {
            record
        };
        let record = if cfg.BYPASS_METHOD.contains("mixed_case_sni") {
            MixedCaseSni::new(&cfg).apply(&record).unwrap_or(record)
        } else {
            record
        };
        Some(record)
    } else {
        None
    };
```

Then rename the two later uses of the variable: `match padded_prefix {` → `match transformed_prefix {` and `if let Some(record) = padded_prefix` → `if let Some(record) = transformed_prefix`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p zerodpi-core proxy::tests`
Expected: PASS (new tests plus existing proxy tests)

- [ ] **Step 5: Workspace test + lint**

Run: `cargo test --workspace`, then `cargo clippy --workspace --all-targets -- -D warnings`, then `cargo fmt --all -- --check`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add crates/zerodpi-core/src/proxy.rs
git commit -m "feat: apply mixed_case_sni to the real ClientHello in proxy paths"
```

---

### Task 5: main.rs messaging, README and config.toml docs, final verification

**Files:**
- Modify: `crates/zerodpi/src/main.rs`
- Modify: `README.md`
- Modify: `config.toml`

**Interfaces:**
- Consumes: everything from Tasks 1–4.
- Produces: nothing new; documentation and user-facing messages only.

- [ ] **Step 1: main.rs — interception-requirement tests first (TDD for the classification)**

In `crates/zerodpi/src/main.rs` test module, `non_interception_modes_do_not_require_packet_interception`: add after the `tls_padding` assertion:

```rust
        assert!(!mode_requires_packet_interception(
            "sni_spoof",
            &method_list("mixed_case_sni")
        ));
```

In `ip_bypass_plus_requires_interception_only_for_tls_record_frag`: add after the `tls_padding` assertion:

```rust
        assert!(!mode_requires_packet_interception(
            "ip_bypass_plus",
            &method_list("mixed_case_sni")
        ));
```

- [ ] **Step 2: Run to verify the new assertions pass (no code change needed — they pass once Task 3 classifies the method as socket-only)**

Run: `cargo test -p zerodpi mode_requires_packet_interception`
Expected: PASS. If any assertion fails, Task 3's `is_socket_only`/`requires_interceptor` edits are incomplete — fix those before continuing.

- [ ] **Step 3: main.rs — update the rootless messaging**

In `root_required_message`, change the string segment:

```rust
        "MODE = \"{}\" with BYPASS_METHOD = \"{}\" requires packet interception; on Android the app must start the packaged root helper while keeping the data plane under the app UID. Rootless alternatives are MODE = \"ip_bypass\", scan-only modes, or BYPASS_METHOD = \"tls_frag\" / \"tls_padding\" where supported.",
```

→

```rust
        "MODE = \"{}\" with BYPASS_METHOD = \"{}\" requires packet interception; on Android the app must start the packaged root helper while keeping the data plane under the app UID. Rootless alternatives are MODE = \"ip_bypass\", scan-only modes, or BYPASS_METHOD = \"tls_frag\" / \"tls_padding\" / \"mixed_case_sni\" where supported.",
```

In `rootless_alternatives`, add one entry after the `tls_padding` entry:

```rust
        "BYPASS_METHOD = \"mixed_case_sni\" for supported relay modes".to_owned(),
```

- [ ] **Step 4: README.md updates**

Edit 1 — features table (line 56): `10 combinable bypass methods` → `11 combinable bypass methods`, and insert `\`mixed_case_sni\`, ` after `\`tls_padding\`, ` in the method list.

Edit 2 — root requirement note (line ~154): `except standalone \`tls_frag\` / \`tls_padding\`` → `except standalone \`tls_frag\` / \`tls_padding\` / \`mixed_case_sni\``, and in the same sentence `when it uses \`tls_frag\` or \`tls_padding\`` → `when it uses \`tls_frag\`, \`tls_padding\`, or \`mixed_case_sni\``.

Edit 3 — Windows row (line ~165): `Standalone \`tls_frag\` / \`tls_padding\` do not open WinDivert` → `Standalone \`tls_frag\` / \`tls_padding\` / \`mixed_case_sni\` do not open WinDivert`.

Edit 4 — Android row (line ~167): `Try \`tls_frag\` or \`tls_padding\` first` → `Try \`tls_frag\`, \`tls_padding\`, or \`mixed_case_sni\` first`.

Edit 5 — ip_bypass_plus mentions (lines ~230, ~243, ~282): in each, `\`tls_record_frag\`, \`tls_frag\`, or \`tls_padding\`` → `\`tls_record_frag\`, \`tls_frag\`, \`tls_padding\`, or \`mixed_case_sni\``; and `or \`BYPASS_METHOD = \`tls_frag\` / \`BYPASS_METHOD = \`tls_padding\` for socket-only transforms` (line ~282) → `or \`BYPASS_METHOD = \`tls_frag\` / \`tls_padding\` / \`mixed_case_sni\` for socket-only transforms`.

Edit 6 — bypass method table: add a row after the `tls_padding` row:

```markdown
| `mixed_case_sni` | SNI Case Randomization: randomizes the ASCII letter case of the SNI hostname in the real ClientHello (e.g. wikipedia.org → wIkIpeDiA.oRg); servers lowercase it per RFC 6066 while case-sensitive DPI blocklists miss | ❌ No | DPI with case-sensitive SNI blocklist matching |
```

Edit 7 — combination limits bullet: `\`MODE = "ip_bypass_plus"\` supports only \`tls_record_frag\`, \`tls_frag\`, or \`tls_padding\` so the VPN client's real SNI is preserved.` → add `\`, or \`mixed_case_sni\`` before ` so the`.

- [ ] **Step 5: config.toml updates**

Edit 1 — after the `"tls_padding"` method description block (ends with `#     extension.  "after" appends the padding at the end of the extension\n#     list instead.`), insert:

```toml
#   "mixed_case_sni"
#     SNI Case Randomization.  Does NOT inject fake packets and does NOT use
#     WinDivert or NFQUEUE packet interception.  Randomizes the ASCII letter
#     case of the hostname inside the SNI extension of the client's real TLS
#     ClientHello (e.g. wikipedia.org -> wIkIpeDiA.oRg).  Per RFC 6066 the
#     SNI hostname is case-insensitive: destination servers lowercase it
#     during lookup, so the handshake completes normally, while DPI that
#     matches blocklists with exact case-sensitive string comparisons misses
#     the name.  Digits, dots, and hyphens are never changed (safe for
#     punycode SNIs).
```

Edit 2 — combinability bullets: change `# - A list containing only "tls_frag" and/or "tls_padding" skips the packet\n#   interceptor entirely.` → `# - A list containing only "tls_frag", "tls_padding", and/or "mixed_case_sni"\n#   skips the packet interceptor entirely.` and add a bullet after the tls_padding bullet: `# - "mixed_case_sni" adds a socket-side data stage that randomizes the\n#   SNI case in the real ClientHello.  It combines with handshake-stage\n#   methods, with "tls_frag", and with "tls_padding" (pad first, then\n#   randomize).`

Edit 3 — limitations bullet: `# - MODE = "ip_bypass_plus" supports only "tls_record_frag", "tls_frag", or\n#   "tls_padding" so the upstream VPN client's real SNI is preserved.` → `# - MODE = "ip_bypass_plus" supports only "tls_record_frag", "tls_frag",\n#   "tls_padding", or "mixed_case_sni" so the upstream VPN client's real SNI\n#   is preserved.`

Edit 4 — add a settings section after the `TLS_PADDING_POSITION = "before"` line (end of the tls_padding parameters block), before `# Legacy fixed fragment length fallback.`:

```toml
# ---------------------------------------------------------------------------
# mixed_case_sni method parameters
# ---------------------------------------------------------------------------
# These settings apply when BYPASS_METHOD = "mixed_case_sni" (alone or
# combined).

# When true, every ASCII letter in the SNI hostname is case-inverted
# (a -> A, A -> a).  When false (default), each letter is randomly
# uppercased or lowercased per connection, with at least one letter
# guaranteed to differ from the original.
MIXED_CASE_SNI_FLIP_ALL = false
```

- [ ] **Step 6: Full verification suite**

Run in order:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: all PASS.

- [ ] **Step 7: Manual smoke test (documented in the PR)**

On a machine with a reachable target and a working `config.toml`:

1. Set `MODE = "sni_spoof"` and `BYPASS_METHOD = "mixed_case_sni"` (no admin/root needed — socket-only).
2. Run `cargo run --bin zerodpi -- --config ./config.toml`.
3. Connect any TLS client through the listener (e.g. a VPN client configured with the ZeroDPI listen address as its remote, or `openssl s_client -connect <listen_host>:<listen_port> -servername wikipedia.org`).
4. Capture the upstream traffic (tcpdump/Wireshark) and locate the ClientHello (`tls.handshake.extensions_server_name` filter in Wireshark).
5. Confirm: SNI hostname letters are mixed-case, the TLS handshake completes, and the connection works.
6. Repeat with `BYPASS_METHOD = ["tls_padding", "mixed_case_sni"]` and with `["wrong_seq", "mixed_case_sni"]` to confirm combos.

- [ ] **Step 8: Commit**

```bash
git add crates/zerodpi/src/main.rs README.md config.toml
git commit -m "docs: document mixed_case_sni bypass method and config knob"
```

---

## Self-Review Notes

- **Spec coverage:** socket-side transform (Task 2+4), no-root classification (Task 3 `is_socket_only` + Task 5 main.rs), random per-letter + ≥1 flip guarantee (Task 2), `MIXED_CASE_SNI_FLIP_ALL` knob (Task 3 field + Task 5 docs), unrestricted combinability incl. `ip_bypass_plus` (Task 3 Edit 4 + Task 5 docs), README/config.toml documentation (Task 5). All covered.
- **Type consistency:** `MixedCaseSni::new(cfg)`, `MixedCaseSni::exact(bool)`, `MixedCaseSni::apply(&[u8]) -> Option<Vec<u8>>`, `apply_with_rng(&self, &[u8], &mut MixedCaseRng) -> Option<Vec<u8>>`, `MixedCaseRng::from_seed(u64)`, `swap_ascii_case(u8) -> u8`, `find_sni_range(&[u8]) -> Option<(usize, usize)>`, `ConnectionSettings::apply_socket_transforms(&self, &[u8]) -> Vec<u8>` — names match across all tasks.
- **Known ordering caveat:** Task 2's `MixedCaseSni::new` references `Config::MIXED_CASE_SNI_FLIP_ALL`, which Task 3 adds. Either implement Task 3's Edit 3 before Task 2 compiles, or treat Tasks 2+3 as one unit.
