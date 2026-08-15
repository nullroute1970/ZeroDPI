# SNI Extension Boundary Fragmentation (`sni_boundary_frag`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new bypass method `sni_boundary_frag` that parses the TLS ClientHello, finds the SNI extension, and writes the ClientHello to the upstream socket as exactly two TCP segments cut at the SNI extension boundary (or mid-domain), separated by a configurable 5–10 ms delay so inline DPI reassembly buffers don't stitch them together.

**Architecture:** Socket-side method (no packet interceptor) modeled on `tls_frag`: the proxy reads exactly one TLS record, computes a split byte offset from an extended SNI parser, then performs two `write_all` + `flush` calls with a sampled delay between them (TCP_NODELAY forced). It works standalone, combined with other socket-side methods (`tls_frag`, `tls_padding`, `mixed_case_sni`), and combined with handshake-stage fake-packet methods (`wrong_seq`, `wrong_ack`, `wrong_checksum`, `wrong_md5`, `wrong_timestamp`, `low_ttl`) via the existing `CompositeMethod` + `ReadyForData` interceptor combo path. Combos with `tls_record_frag` and `urg_sni_split` are rejected in config validation (all three fight over the first data packet).

**Tech Stack:** Rust 2021 workspace, tokio, serde/toml. No new dependencies.

**Spec:** The design agreed in chat on 2026-08-15 (bounded brainstorming). Key decisions:
- Split points: `"extension_length"` (default), `"middle"`, or integer index into the domain name.
- Delay: `Int32Range` sampled per connection, default `"5-10"` ms.
- Method name `sni_boundary_frag`; config prefix `SNI_BOUNDARY_FRAG_*`.
- Combo scope: socket-only lists and interceptor handshake-fake combos (option C).

## Global Constraints

- Rust 2021 workspace; code lives in `crates/zerodpi-core/` (core logic) — no changes to `crates/zerodpi-platform/` or the TUI (TUI renders `BYPASS_METHOD` generically).
- `rustfmt` formatting, 4-space indentation, `snake_case` functions/variables, `PascalCase` types, `SCREAMING_SNAKE_CASE` config fields.
- Follow existing patterns: config fields with `#[serde(default = "default_...")]`, fail-open behavior when the ClientHello does not parse, `anyhow` at proxy boundaries, inline `#[cfg(test)]` modules.
- All new config options must be documented in `config.toml` comments and `README.md` (AGENTS.md requirement).
- Commit messages use conventional prefixes, e.g. `feat: add sni_boundary_frag bypass method`.
- Verification gate per task: `cargo test -p zerodpi-core <targets>`; final gate: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Do not commit private endpoints; no changes to runtime `sni_list.txt` / `ip_list.txt`.

## File Structure

| File | Change | Responsibility |
|------|--------|----------------|
| `crates/zerodpi-core/src/methods/sni.rs` | Modify | Extend SNI parser with `SniBoundary` + `find_sni_boundary()`; refactor `find_sni_range` on top of it |
| `crates/zerodpi-core/src/methods/sni_boundary_frag.rs` | Create | `SniBoundaryFrag` params struct, split-offset resolution, `write_boundary_split()` |
| `crates/zerodpi-core/src/methods/tcp_segmentation.rs` | Modify | Make `FragmentRng` + `sample_i32` `pub(crate)` for reuse |
| `crates/zerodpi-core/src/config.rs` | Modify | `SniBoundarySplitPoint` enum, two config fields + defaults, `BASE_BYPASS_METHODS`, `is_socket_only`, combo validation, `ip_bypass_plus` allowlist |
| `crates/zerodpi-core/src/methods/composite.rs` | Modify | `splits_first_client_hello` flag + name rendering |
| `crates/zerodpi-core/src/methods/mod.rs` | Modify | Register method in `build_method`, module docs |
| `crates/zerodpi-core/src/proxy.rs` | Modify | `ConnectionSettings` field, socket-only path branch, interceptor combo `ReadyForData` branch |
| `config.toml` | Modify | Document new options with examples |
| `README.md` | Modify | Features count, methods table row, combining rules, mode table note |

---

### Task 1: Extend the SNI parser with boundary offsets

**Files:**
- Modify: `crates/zerodpi-core/src/methods/sni.rs`

**Interfaces:**
- Consumes: nothing new (existing `sni.rs` walk).
- Produces:
  - `pub(crate) struct SniBoundary { pub ext_len_field_end: usize, pub name_start: usize, pub name_len: usize }`
  - `pub(crate) fn find_sni_boundary(data: &[u8]) -> Option<SniBoundary>`
  - `find_sni_range` keeps its exact signature `pub(crate) fn find_sni_range(data: &[u8]) -> Option<(usize, usize)>` (Task 3 and existing `urg_sni_split`/`mixed_case_sni` depend on it).

- [ ] **Step 1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` in `sni.rs`. First add this helper next to the existing test helpers (the module currently has no CH builder; use `crate::tls_template::build_client_hello`):

```rust
    use crate::tls_template::build_client_hello;

    fn client_hello(sni: &[u8]) -> Vec<u8> {
        build_client_hello(&[0u8; 32], &[0u8; 32], sni, &[0u8; 32])
    }
```

Then the tests:

```rust
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
        assert_eq!(&ch[b.name_start..b.name_start + b.name_len], b"auth.vercel.com");
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core methods::sni::tests::boundary_reports_offsets_for_built_client_hello`
Expected: FAIL — `find_sni_boundary` not found (E0425).

- [ ] **Step 3: Implement the parser extension**

Replace the body of `sni.rs` (keep the module doc comment at the top) so `find_sni_range` delegates to the new function:

```rust
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
    // ... the existing tests plus the ones from Step 1 ...
}
```

`sni.rs` currently has no test module (its behavior is covered indirectly via `urg_sni_split` tests); the test module created in Step 1 stays appended at the bottom of the file, unchanged. All tests in the module must pass.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core methods::sni`
Expected: PASS (all sni module tests).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/methods/sni.rs
git commit -m "feat: extend SNI parser with extension boundary offsets"
```

---

### Task 2: Config fields, enum, and validation

**Files:**
- Modify: `crates/zerodpi-core/src/config.rs`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:
  - `pub enum SniBoundarySplitPoint { ExtensionLength, Middle, Index(u16) }` with serde `Deserialize`/`Serialize` (string/integer forms) — consumed by Task 3.
  - `pub SNI_BOUNDARY_FRAG_SPLIT_POINT: SniBoundarySplitPoint` on `Config`
  - `pub SNI_BOUNDARY_FRAG_DELAY_MS: Int32Range` on `Config`
  - `"sni_boundary_frag"` accepted in `BYPASS_METHOD`; `is_socket_only()` returns `true` for lists containing only socket-side methods including it.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` in `config.rs` (the module already has `default_config()` / `cfg_with` style helpers — check the helper your neighbors use; the existing tests at the bottom use `toml::from_str` with a minimal prefix):

```rust
    #[test]
    fn sni_boundary_frag_defaults() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "sni_boundary_frag""#,
        )
        .unwrap();
        assert_eq!(
            cfg.SNI_BOUNDARY_FRAG_SPLIT_POINT,
            SniBoundarySplitPoint::ExtensionLength
        );
        assert_eq!(cfg.SNI_BOUNDARY_FRAG_DELAY_MS, Int32Range { min: 5, max: 10 });
        assert!(cfg.BYPASS_METHOD.is_socket_only());
        assert!(!cfg.BYPASS_METHOD.requires_interceptor());
    }

    #[test]
    fn sni_boundary_frag_custom_values() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["wrong_seq", "sni_boundary_frag"]
               SNI_BOUNDARY_FRAG_SPLIT_POINT = 3
               SNI_BOUNDARY_FRAG_DELAY_MS = "7-9""#,
        )
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.SNI_BOUNDARY_FRAG_SPLIT_POINT, SniBoundarySplitPoint::Index(3));
        assert_eq!(cfg.SNI_BOUNDARY_FRAG_DELAY_MS, Int32Range { min: 7, max: 9 });
        assert!(!cfg.BYPASS_METHOD.is_socket_only());
    }

    #[test]
    fn sni_boundary_frag_rejects_invalid_split_point() {
        let result: Result<Config, _> = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "sni_boundary_frag"
               SNI_BOUNDARY_FRAG_SPLIT_POINT = "sideways""#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn sni_boundary_frag_rejects_data_stage_combos() {
        for method in ["tls_record_frag", "urg_sni_split"] {
            let cfg: Config = toml::from_str(&format!(
                r#"LISTEN_HOST = "127.0.0.1"
                   LISTEN_PORT = 44444
                   BYPASS_METHOD = ["sni_boundary_frag", "{method}"]"#
            ))
            .unwrap();
            assert!(
                cfg.validate().is_err(),
                "combo with {method} must be rejected"
            );
        }
    }

    #[test]
    fn sni_boundary_frag_accepts_handshake_fake_combos() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["wrong_seq", "sni_boundary_frag"]"#,
        )
        .unwrap();
        cfg.validate().unwrap();

        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["sni_boundary_frag", "tls_frag", "tls_padding"]"#,
        )
        .unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn sni_boundary_frag_rejects_negative_delay() {
        // Negative values fail Int32Range parsing during TOML deserialization.
        let result: Result<Config, _> = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "sni_boundary_frag"
               SNI_BOUNDARY_FRAG_DELAY_MS = "-1-5""#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn sni_boundary_frag_allowed_in_ip_bypass_plus() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               MODE = "ip_bypass_plus"
               BYPASS_METHOD = "sni_boundary_frag""#,
        )
        .unwrap();
        cfg.validate().unwrap();
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core config::tests::sni_boundary_frag_defaults`
Expected: FAIL — compile errors (`SniBoundarySplitPoint` not found, unknown config field errors at parse time).

- [ ] **Step 3: Implement the enum, fields, defaults, and validation**

**3a.** After the `SniSplitPosition` enum + its serde impls (around line 180), add:

```rust
/// Where `sni_boundary_frag` cuts the first ClientHello TCP write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniBoundarySplitPoint {
    /// Cut right after the server_name extension's 2-byte length field:
    /// segment 1 ends with the length field, segment 2 starts with the
    /// extension body.
    ExtensionLength,
    /// Cut at the exact middle of the SNI domain string (`len / 2`).
    Middle,
    /// Cut after the Nth byte of the domain string (0-based), clamped to
    /// `[0, name_len]`.
    Index(u16),
}

impl<'de> Deserialize<'de> for SniBoundarySplitPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Int(u16),
            Text(String),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Int(value) => Ok(Self::Index(value)),
            Repr::Text(value) => match value.to_ascii_lowercase().as_str() {
                "extension_length" => Ok(Self::ExtensionLength),
                "middle" => Ok(Self::Middle),
                _ => Err(de::Error::custom(format!(
                    "'{value}' is not a valid SNI_BOUNDARY_FRAG_SPLIT_POINT; valid values: \"extension_length\", \"middle\", or an integer"
                ))),
            },
        }
    }
}

impl Serialize for SniBoundarySplitPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::ExtensionLength => serializer.serialize_str("extension_length"),
            Self::Middle => serializer.serialize_str("middle"),
            Self::Index(n) => serializer.serialize_u16(*n),
        }
    }
}
```

**3b.** In `BASE_BYPASS_METHODS` (around line 188), add `"sni_boundary_frag",` after `"urg_sni_split",`:

```rust
pub const BASE_BYPASS_METHODS: &[&str] = &[
    "wrong_seq",
    "wrong_ack",
    "wrong_checksum",
    "wrong_md5",
    "wrong_timestamp",
    "low_ttl",
    "tls_record_frag",
    "tls_frag",
    "tls_padding",
    "mixed_case_sni",
    "urg_sni_split",
    "sni_boundary_frag",
];
```

**3c.** In `is_socket_only()` and `requires_interceptor()` (around lines 261–276), extend the socket-only match arms:

```rust
    /// `true` when the list contains only socket-side methods
    /// (`["tls_frag"]`, `["tls_padding"]`, `["mixed_case_sni"]`,
    /// `["sni_boundary_frag"]`, or combinations), which need no packet
    /// interceptor.
    pub fn is_socket_only(&self) -> bool {
        !self.0.is_empty()
            && self.0.iter().all(|m| {
                matches!(
                    m.as_str(),
                    "tls_frag" | "tls_padding" | "mixed_case_sni" | "sni_boundary_frag"
                )
            })
    }

    /// `true` when any listed method needs the WinDivert/NFQUEUE interceptor.
    pub fn requires_interceptor(&self) -> bool {
        self.0.iter().any(|m| {
            !matches!(
                m.as_str(),
                "tls_frag" | "tls_padding" | "mixed_case_sni" | "sni_boundary_frag"
            )
        })
    }
```

**3d.** In the `Config` struct, after the `SNI_SPLIT_POSITION` field (around line 710), add:

```rust
    // -----------------------------------------------------------------------
    // sni_boundary_frag method parameters
    // -----------------------------------------------------------------------
    /// Where `sni_boundary_frag` cuts the first ClientHello TCP write.
    /// Supported values: `"extension_length"` (default), `"middle"`, or a
    /// 0-based integer index into the domain string (clamped to the domain
    /// length).
    #[serde(default = "default_sni_boundary_split_point")]
    pub SNI_BOUNDARY_FRAG_SPLIT_POINT: SniBoundarySplitPoint,

    /// Delay range, in milliseconds, between the two TCP segments of the
    /// boundary-split ClientHello. Accepts either an integer (`5`) or an
    /// inclusive range string (`"5-10"`). A fresh value is sampled per
    /// connection. Must be `>= 0`. Default: `"5-10"`.
    #[serde(default = "default_sni_boundary_delay_ms")]
    pub SNI_BOUNDARY_FRAG_DELAY_MS: Int32Range,
```

**3e.** Next to the other `default_*` functions (around line 1025, after `default_sni_split_position`), add:

```rust
fn default_sni_boundary_split_point() -> SniBoundarySplitPoint {
    SniBoundarySplitPoint::ExtensionLength
}
fn default_sni_boundary_delay_ms() -> Int32Range {
    Int32Range { min: 5, max: 10 }
}
```

**3f.** In `validate()`, inside the existing `BYPASS_METHOD` block right after the `urg_sni_split` combo check (around line 1205), add:

```rust
            if self.BYPASS_METHOD.contains("sni_boundary_frag")
                && self.BYPASS_METHOD.len() > 1
                && !self.BYPASS_METHOD.iter().all(|m| {
                    m == "sni_boundary_frag"
                        || matches!(
                            m,
                            "tls_frag"
                                | "tls_padding"
                                | "mixed_case_sni"
                                | "wrong_seq"
                                | "wrong_ack"
                                | "wrong_checksum"
                                | "wrong_md5"
                                | "wrong_timestamp"
                                | "low_ttl"
                        )
                })
            {
                anyhow::bail!(
                    "BYPASS_METHOD \"sni_boundary_frag\" cannot be combined with \"tls_record_frag\" or \"urg_sni_split\""
                );
            }
```

**3g.** Next to the `TLS_FRAG_INTERVAL_MS` validation (around line 1251), add:

```rust
        self.SNI_BOUNDARY_FRAG_DELAY_MS
            .validate_at_least("SNI_BOUNDARY_FRAG_DELAY_MS", 0)?;
```

**3h.** Extend the `ip_bypass_plus` allowlist (around line 1268):

```rust
        if self.MODE == "ip_bypass_plus"
            && !self.BYPASS_METHOD.iter().all(|m| {
                matches!(
                    m,
                    "tls_record_frag"
                        | "tls_frag"
                        | "tls_padding"
                        | "mixed_case_sni"
                        | "sni_boundary_frag"
                )
            })
        {
            anyhow::bail!(
                "MODE = \"ip_bypass_plus\" supports only real-SNI-preserving BYPASS_METHOD values: \"tls_record_frag\", \"tls_frag\", \"tls_padding\", \"mixed_case_sni\", or \"sni_boundary_frag\""
            );
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core config::tests::sni_boundary`
Expected: PASS (all six new tests).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/config.rs
git commit -m "feat: add sni_boundary_frag config fields and validation"
```

---

### Task 3: The `sni_boundary_frag` method module

**Files:**
- Create: `crates/zerodpi-core/src/methods/sni_boundary_frag.rs`
- Modify: `crates/zerodpi-core/src/methods/tcp_segmentation.rs` (make RNG reusable)

**Interfaces:**
- Consumes: `find_sni_boundary`/`SniBoundary` (Task 1), `SniBoundarySplitPoint`/`Config`/`Int32Range` (Task 2), `FragmentRng`/`sample_i32` (made `pub(crate)` in this task).
- Produces (used by Task 4 and Task 5):
  - `pub struct SniBoundaryFrag { pub split_point: SniBoundarySplitPoint, pub delay_ms: Int32Range }` (`Copy`)
  - `impl SniBoundaryFrag { pub fn new(cfg: &Config) -> Self; pub fn split_offset(&self, record: &[u8]) -> Option<usize>; }`
  - `pub async fn write_boundary_split<W: AsyncWrite + Unpin>(dst: &mut W, data: &[u8], split: usize, delay_ms: Int32Range) -> anyhow::Result<()>`

- [ ] **Step 1: Make the fragment RNG reusable**

In `crates/zerodpi-core/src/methods/tcp_segmentation.rs`, change the visibility of `FragmentRng` and `sample_i32`:

```rust
pub(crate) struct FragmentRng {
    state: u64,
}

impl FragmentRng {
    pub(crate) fn new() -> Self {
        // ... existing body unchanged ...
    }

    #[cfg(test)]
    fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // ... existing body unchanged ...
    }
}

pub(crate) fn sample_i32(range: Int32Range, rng: &mut FragmentRng) -> i32 {
    // ... existing body unchanged ...
}
```

- [ ] **Step 2: Verify existing tests still pass**

Run: `cargo test -p zerodpi-core methods::tcp_segmentation`
Expected: PASS (visibility change only).

- [ ] **Step 3: Write the failing tests for the new module**

Create `crates/zerodpi-core/src/methods/sni_boundary_frag.rs` containing only the test module for now (the implementation from Step 5 will satisfy it):

```rust
//! `sni_boundary_frag` bypass: SNI Extension Boundary Fragmentation.
//!
//! (full docs added in Step 5)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Int32Range, SniBoundarySplitPoint};
    use crate::tls_template::build_client_hello;

    fn cfg_with(extra: &str) -> Config {
        toml::from_str(&format!(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "sni_boundary_frag"
               {extra}"#
        ))
        .unwrap()
    }

    fn client_hello(sni: &[u8]) -> Vec<u8> {
        build_client_hello(&[0u8; 32], &[0u8; 32], sni, &[0u8; 32])
    }

    /// Handcraft a minimal ClientHello whose server_name extension is the
    /// only extension and the last bytes of the record, so split offsets at
    /// the record end can be exercised.
    fn minimal_hello_ending_in_sni(sni: &[u8]) -> Vec<u8> {
        let name_len = sni.len() as u16;
        let list_len = 3u16 + name_len;
        let ext_len = 5u16 + name_len;
        let ext_total = 4u16 + ext_len;
        let body_len = 2usize + 32 + 1 + 2 + 1 + 2 + ext_total as usize;
        let hs_len = 4usize + body_len;
        let mut rec = vec![
            0x16, 0x03, 0x03, // record header: handshake, version
            ((5 + hs_len) >> 8) as u8,
            (5 + hs_len) as u8, // record length
            0x01, // handshake type: ClientHello
            (hs_len >> 16) as u8,
            (hs_len >> 8) as u8,
            hs_len as u8, // handshake length
            0x03, 0x03, // client version
        ];
        rec.extend_from_slice(&[0u8; 32]); // random
        rec.push(0); // session id length
        rec.extend_from_slice(&[0x00, 0x00]); // cipher suites length
        rec.push(0); // compression methods length
        rec.extend_from_slice(&[(ext_total >> 8) as u8, ext_total as u8]); // extensions total
        rec.extend_from_slice(&[0x00, 0x00, (ext_len >> 8) as u8, ext_len as u8]); // ext header
        rec.extend_from_slice(&[(list_len >> 8) as u8, list_len as u8]); // server_name list len
        rec.push(0x00); // name type: host_name
        rec.extend_from_slice(&[(name_len >> 8) as u8, name_len as u8]); // name len
        rec.extend_from_slice(sni);
        rec
    }

    #[test]
    fn extension_length_split_is_right_after_ext_len_field() {
        let method = SniBoundaryFrag::new(&cfg_with(""));
        let ch = client_hello(b"auth.vercel.com");
        // ext header at 118, length field at 120..122 (see sni.rs tests).
        assert_eq!(method.split_offset(&ch), Some(122));
    }

    #[test]
    fn middle_split_lands_inside_domain() {
        let method = SniBoundaryFrag::new(&cfg_with(r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = "middle""#));
        let ch = client_hello(b"auth.vercel.com"); // name at 127, len 15
        assert_eq!(method.split_offset(&ch), Some(127 + 7));
    }

    #[test]
    fn index_split_is_clamped_to_domain_length() {
        let method = SniBoundaryFrag::new(&cfg_with(r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = 3"#));
        let ch = client_hello(b"auth.vercel.com");
        assert_eq!(method.split_offset(&ch), Some(127 + 3));

        let method = SniBoundaryFrag::new(&cfg_with(r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = 999"#));
        // clamped to name_len (15): offset 127 + 15, which is inside the
        // record (trailing extensions follow), so a split is returned.
        assert_eq!(method.split_offset(&ch), Some(127 + 15));
    }

    #[test]
    fn split_at_record_end_returns_none() {
        // "mci.ir" is 6 bytes and is the last 6 bytes of this record;
        // splitting after all 6 name bytes lands at the record end and must
        // fail open (no split).
        let method = SniBoundaryFrag::new(&cfg_with(r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = 6"#));
        assert_eq!(method.split_offset(&minimal_hello_ending_in_sni(b"mci.ir")), None);
    }

    #[test]
    fn missing_sni_fails_open() {
        let method = SniBoundaryFrag::new(&cfg_with(""));
        assert_eq!(method.split_offset(b"GET / HTTP/1.1"), None);
        assert_eq!(method.split_offset(&[]), None);
        let ch = client_hello(b"example.com");
        assert_eq!(method.split_offset(&ch[..ch.len() - 1]), None);
    }

    #[test]
    fn config_values_reach_the_method() {
        let method = SniBoundaryFrag::new(&cfg_with(
            r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = "middle"
               SNI_BOUNDARY_FRAG_DELAY_MS = "7-9""#,
        ));
        assert_eq!(method.split_point, SniBoundarySplitPoint::Middle);
        assert_eq!(method.delay_ms, Int32Range { min: 7, max: 9 });
    }

    #[tokio::test]
    async fn write_boundary_split_preserves_bytes_in_order() {
        let data: Vec<u8> = (0..64u8).collect();
        let expected = data.clone();
        let (mut writer, mut reader) = tokio::io::duplex(128);

        let write_task = tokio::spawn(async move {
            write_boundary_split(&mut writer, &data, 20, Int32Range::exact(0)).await
        });

        let mut out = vec![0u8; expected.len()];
        reader.read_exact(&mut out).await.unwrap();
        write_task.await.unwrap().unwrap();
        assert_eq!(out, expected);
    }

    #[tokio::test]
    async fn write_boundary_split_delays_the_second_part() {
        let data = b"0123456789abcdef";
        let (mut writer, mut reader) = tokio::io::duplex(64);

        let write_task = tokio::spawn(async move {
            write_boundary_split(&mut writer, data, 8, Int32Range::exact(150)).await
        });

        // First part arrives immediately.
        let mut first = [0u8; 8];
        reader.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"01234567");

        // Second part must NOT arrive before the 150 ms delay elapses.
        let mut early = [0u8; 8];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), reader.read_exact(&mut early))
                .await
                .is_err(),
            "second segment must be delayed"
        );

        // After the delay it arrives.
        reader.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"89abcdef");
        write_task.await.unwrap().unwrap();
    }
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core methods::sni_boundary_frag`
Expected: FAIL — module not declared in `methods/mod.rs` yet (compile error). (This is expected scaffolding order; Step 5 adds both the module and the impl.)

- [ ] **Step 5: Implement the module**

Replace the placeholder module content with the full implementation:

```rust
//! `sni_boundary_frag` bypass: SNI Extension Boundary Fragmentation.
//!
//! ## How it works
//!
//! Rather than splitting TCP packets at random byte positions, this method
//! parses the TLS ClientHello down to the extension array, calculates the
//! exact byte offset of the SNI extension, and cuts the first ClientHello
//! TCP write there. The record is sent as two TCP segments — e.g. segment 1
//! ends right after the server_name extension's length field (or mid-domain,
//! `you` / `tube.com`) — with a configurable millisecond delay
//! (`SNI_BOUNDARY_FRAG_DELAY_MS`, default 5–10 ms) between them, so inline
//! DPI reassembly buffers do not stitch the two segments back together.
//!
//! This method does **not** inject fake packets and does **not** alter the
//! TLS bytes. It operates entirely inside the proxy task:
//!
//! 1. Read exactly one TLS record from the client.
//! 2. Locate the server_name extension (see [`super::sni::find_sni_boundary`]).
//! 3. Resolve the split byte offset from
//!    [`SniBoundarySplitPoint`](crate::config::SniBoundarySplitPoint).
//! 4. Write `record[..split]`, flush, sleep the sampled delay, write
//!    `record[split..]`, flush. `TCP_NODELAY` is enabled on the upstream
//!    socket so each write leaves as its own TCP segment.
//! 5. Fail open: when the record has no parseable ClientHello with an SNI,
//!    or the resolved offset would not split the record into two non-empty
//!    parts, the record is written whole.
//!
//! Because the platform packet interceptor (WinDivert / NFQUEUE) is **not**
//! involved, this method does not implement the [`BypassMethod`] trait and
//! the flow is never registered in the [`FlowTable`].
//!
//! [`BypassMethod`]: super::BypassMethod
//! [`FlowTable`]: crate::flow::FlowTable
//!
//! ## Configuration
//!
//! | Key | Type | Default | Description |
//! |-----|------|---------|-------------|
//! | `SNI_BOUNDARY_FRAG_SPLIT_POINT` | string / int | `"extension_length"` | Where to cut: `"extension_length"`, `"middle"`, or a 0-based index into the domain string. |
//! | `SNI_BOUNDARY_FRAG_DELAY_MS` | `Int32Range` | `"5-10"` | Delay between the two segments. |

use anyhow::Context;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::sni::find_sni_boundary;
use crate::config::{Config, Int32Range, SniBoundarySplitPoint};

/// Parameters for the `sni_boundary_frag` bypass method.
#[derive(Debug, Clone, Copy)]
pub struct SniBoundaryFrag {
    /// Where to cut the first ClientHello TCP write.
    pub split_point: SniBoundarySplitPoint,
    /// Delay between the two TCP segments, in milliseconds.
    pub delay_ms: Int32Range,
}

impl SniBoundaryFrag {
    pub fn new(cfg: &Config) -> Self {
        Self {
            split_point: cfg.SNI_BOUNDARY_FRAG_SPLIT_POINT,
            delay_ms: cfg.SNI_BOUNDARY_FRAG_DELAY_MS,
        }
    }

    /// Resolve the configured split point to a byte offset inside `record`.
    ///
    /// Returns `None` when the record contains no parseable ClientHello with
    /// an SNI, or when the resolved offset would not split the record into
    /// two non-empty parts (offset `0` or `record.len()`). Callers fail open
    /// by writing the record whole.
    pub fn split_offset(&self, record: &[u8]) -> Option<usize> {
        let boundary = find_sni_boundary(record)?;
        let offset = match self.split_point {
            SniBoundarySplitPoint::ExtensionLength => boundary.ext_len_field_end,
            SniBoundarySplitPoint::Middle => boundary.name_start + boundary.name_len / 2,
            SniBoundarySplitPoint::Index(n) => {
                boundary.name_start + (n as usize).min(boundary.name_len)
            }
        };
        (offset > 0 && offset < record.len()).then_some(offset)
    }
}

/// Write `data` to `dst` in two parts: `data[..split]`, then — after a delay
/// sampled from `delay_ms` — `data[split..]`.
///
/// Each part is flushed immediately so the OS emits it as its own TCP
/// segment. `split` must produce two non-empty parts.
pub async fn write_boundary_split<W>(
    dst: &mut W,
    data: &[u8],
    split: usize,
    delay_ms: Int32Range,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    assert!(split > 0 && split < data.len(), "split must produce two non-empty parts");
    assert!(delay_ms.min >= 0, "delay range must be >= 0");

    dst.write_all(&data[..split])
        .await
        .context("writing first boundary segment")?;
    dst.flush().await.context("flushing first boundary segment")?;

    let delay_ms = super::tcp_segmentation::sample_i32(
        delay_ms,
        &mut super::tcp_segmentation::FragmentRng::new(),
    )
    .max(0) as u64;
    if delay_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }

    dst.write_all(&data[split..])
        .await
        .context("writing second boundary segment")?;
    dst.flush().await.context("flushing second boundary segment")?;
    Ok(())
}
```

Note the tests reference `SniBoundaryFrag`, `write_boundary_split`, `cfg_with`, and `minimal_hello_ending_in_sni` — keep the test module from Step 3, and place it after the implementation.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core methods::sni_boundary_frag`
Expected: PASS (all 8 tests).

- [ ] **Step 7: Commit**

```bash
git add crates/zerodpi-core/src/methods/sni_boundary_frag.rs crates/zerodpi-core/src/methods/tcp_segmentation.rs
git commit -m "feat: add sni_boundary_frag split computation and delayed two-part write"
```

---

### Task 4: Register in `build_method` and the composite

**Files:**
- Modify: `crates/zerodpi-core/src/methods/composite.rs`
- Modify: `crates/zerodpi-core/src/methods/mod.rs`

**Interfaces:**
- Consumes: `SniBoundaryFrag` name string only (this task wires the flag; Task 5 does the actual socket work).
- Produces: `CompositeMethod::splits_first_client_hello: bool`; `CompositeMethod::with_sni_boundary_split(enabled: bool) -> Self`; composite `name()` renders `" + sni_boundary_frag"` when set; `build_method` recognizes `"sni_boundary_frag"`.

- [ ] **Step 1: Write the failing tests**

In `composite.rs` tests, add:

```rust
    #[test]
    fn wrong_seq_plus_sni_boundary_frag_waits_for_data_stage() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(vec![Box::new(WrongSeq::new(&cfg))], None, false, false)
            .with_sni_boundary_split(true);

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_data());
        assert_eq!(m.name(), "wrong_seq + sni_boundary_frag");

        // Data stage: no data-stage method, so the first data packet
        // (the first boundary segment) passes through and completes.
        let payload: &'static [u8] = &[0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03];
        let mut packet = pkt(payload, payload.len());
        let action = m.on_first_data_packet(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::complete_and_accept());
        assert!(packet.new_payload.is_none());
    }

    #[test]
    fn name_omits_sni_boundary_frag_when_not_set() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(vec![Box::new(WrongSeq::new(&cfg))], None, false, false);
        assert_eq!(m.name(), "wrong_seq");
    }
```

In `mod.rs` tests, add:

```rust
    #[test]
    fn build_wrong_seq_sni_boundary_frag_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["wrong_seq", "sni_boundary_frag"]"#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq + sni_boundary_frag");
    }

    #[test]
    fn socket_sni_boundary_frag_method_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "sni_boundary_frag""#);
        assert!(build_method(&cfg).is_none());
    }

    #[test]
    fn socket_list_with_sni_boundary_frag_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["sni_boundary_frag", "tls_padding"]"#);
        assert!(build_method(&cfg).is_none());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core methods::composite::tests::wrong_seq_plus_sni_boundary_frag_waits_for_data_stage`
Expected: FAIL — `with_sni_boundary_split` not found (E0599).

- [ ] **Step 3: Implement the composite flag**

In `composite.rs`:

**3a.** Add the field:

```rust
pub struct CompositeMethod {
    pub handshake_methods: Vec<Box<dyn BypassMethod>>,
    pub data_method: Option<Box<dyn BypassMethod>>,
    pub segments_first_client_hello: bool,
    pub pads_first_client_hello: bool,
    pub mixed_case_sni_first_hello: bool,
    pub splits_first_client_hello: bool,
}
```

**3b.** Initialize it in `new()`:

```rust
        Self {
            handshake_methods,
            data_method,
            segments_first_client_hello,
            pads_first_client_hello,
            mixed_case_sni_first_hello: false,
            splits_first_client_hello: false,
        }
```

**3c.** Add the builder after `with_mixed_case_sni`:

```rust
    /// Mark the composite as including the socket-side `sni_boundary_frag`
    /// transform so its name reflects the full method list and the
    /// handshake stage waits for the data stage.
    pub fn with_sni_boundary_split(mut self, enabled: bool) -> Self {
        self.splits_first_client_hello = enabled;
        self
    }
```

**3d.** In `name()`, after the `mixed_case_sni` push:

```rust
        if self.splits_first_client_hello {
            parts.push("sni_boundary_frag".into());
        }
```

**3e.** In `on_handshake_complete_ack`, extend the data-stage condition:

```rust
        if self.data_method.is_some()
            || self.segments_first_client_hello
            || self.pads_first_client_hello
            || self.splits_first_client_hello
        {
```

**3f.** Update the module doc comment of `composite.rs` to mention that socket-side `sni_boundary_frag` splitting is signaled through `CompositeMethod::splits_first_client_hello`.

- [ ] **Step 4: Implement `build_method` registration**

In `mod.rs`:

**4a.** Add `pub mod sni_boundary_frag;` to the module list (alphabetical position after `sni`).

**4b.** In `build_method`, add an arm before the fallback `_ => return None`:

```rust
            "sni_boundary_frag" => {} // socket side; handled directly in proxy.rs
```

**4c.** Pass the flag to the composite:

```rust
    Some(Box::new(
        composite::CompositeMethod::new(
            handshake,
            data,
            list.contains("tls_frag"),
            list.contains("tls_padding"),
        )
        .with_mixed_case_sni(list.contains("mixed_case_sni"))
        .with_sni_boundary_split(list.contains("sni_boundary_frag")),
    ))
```

**4d.** Update the module-level doc comment in `mod.rs`: add `sni_boundary_frag` to the socket-based methods list with one sentence: "`sni_boundary_frag` — SNI Extension Boundary Fragmentation. Parses the ClientHello down to the SNI extension and writes the first record as two TCP segments cut at the extension boundary (or mid-domain), separated by a configurable delay, so inline DPI cannot reassemble the SNI."

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core methods::`
Expected: PASS (all method-module tests).

- [ ] **Step 6: Commit**

```bash
git add crates/zerodpi-core/src/methods/composite.rs crates/zerodpi-core/src/methods/mod.rs
git commit -m "feat: register sni_boundary_frag in the composite method chain"
```

---

### Task 5: Wire the method into the proxy paths

**Files:**
- Modify: `crates/zerodpi-core/src/proxy.rs`

**Interfaces:**
- Consumes: `SniBoundaryFrag` + `write_boundary_split` (Task 3), `is_socket_only`/config (Task 2), composite data-stage behavior (Task 4).
- Produces:
  - `ConnectionSettings::sni_boundary_frag: Option<SniBoundaryFrag>` populated when `BYPASS_METHOD` contains `"sni_boundary_frag"`.
  - Socket-only path: `handle_tcp_seg_connection_with_ip` boundary-splits the first record (after `tls_padding`/`mixed_case_sni` transforms) and hands the rest to the relay; when `tls_frag` is also listed, subsequent client writes are segmented per `tls_frag` settings.
  - Interceptor combo path: `handle_intercept_connection` `ReadyForData` branch boundary-splits the real ClientHello after the fake-packet stage; flow completes when the interceptor observes the first segment.

- [ ] **Step 1: Write the failing tests**

Add to the proxy.rs `#[cfg(test)] mod tests` (it already has `cfg_with(method_line, extra)`):

```rust
    #[test]
    fn sni_boundary_frag_in_list_populates_settings() {
        let cfg = cfg_with(
            r#"BYPASS_METHOD = ["wrong_seq", "sni_boundary_frag"]"#,
            r#"SNI_BOUNDARY_FRAG_SPLIT_POINT = "middle"
               SNI_BOUNDARY_FRAG_DELAY_MS = "7-9""#,
        );
        let settings = ConnectionSettings::from_config(&cfg);
        let boundary = settings
            .sni_boundary_frag
            .expect("sni_boundary_frag is listed");
        assert_eq!(
            boundary.split_point,
            crate::config::SniBoundarySplitPoint::Middle
        );
        assert_eq!(boundary.delay_ms, crate::config::Int32Range::parse("7-9").unwrap());
        assert!(!settings.segment_first_client_hello);
    }

    #[test]
    fn socket_only_list_keeps_sni_boundary_frag_settings() {
        let cfg = cfg_with(r#"BYPASS_METHOD = "sni_boundary_frag""#, "");
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(settings.sni_boundary_frag.is_some());
    }

    #[test]
    fn other_lists_leave_sni_boundary_frag_unset() {
        let cfg = cfg_with(r#"BYPASS_METHOD = "tls_frag""#, "");
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(settings.sni_boundary_frag.is_none());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core proxy::tests::sni_boundary_frag_in_list_populates_settings`
Expected: FAIL — `sni_boundary_frag` field not found on `ConnectionSettings` (E0609).

- [ ] **Step 3: Extend `ConnectionSettings`**

**3a.** Add the import next to the other method imports (top of `proxy.rs`):

```rust
use crate::methods::sni_boundary_frag::{write_boundary_split, SniBoundaryFrag};
```

**3b.** Add the field:

```rust
struct ConnectionSettings {
    bypass_timeout: Duration,
    max_lifetime: Option<Duration>,
    segment_first_client_hello: bool,
    tls_padding: Option<TlsPadding>,
    mixed_case_sni: Option<MixedCaseSni>,
    sni_boundary_frag: Option<SniBoundaryFrag>,
    tcp_segmentation: TcpSegmentation,
}
```

**3c.** Populate it in `from_config`:

```rust
            mixed_case_sni: cfg
                .BYPASS_METHOD
                .contains("mixed_case_sni")
                .then(|| MixedCaseSni::new(cfg)),
            sni_boundary_frag: cfg
                .BYPASS_METHOD
                .contains("sni_boundary_frag")
                .then(|| SniBoundaryFrag::new(cfg)),
            tcp_segmentation,
```

- [ ] **Step 4: Rewire the socket-only path (`handle_tcp_seg_connection_with_ip`)**

Replace the block that currently starts at `let client_fragmentation = match method.packets {` and ends before `emit(` of `ProxyEvent::BypassComplete` with the unified read + branch logic:

```rust
    let boundary = cfg
        .BYPASS_METHOD
        .contains("sni_boundary_frag")
        .then(|| SniBoundaryFrag::new(&cfg));
    let segment_tlshello = cfg.BYPASS_METHOD.contains("tls_frag")
        && method.packets == TlsFragPackets::TlsHello;
    let needs_first_record = boundary.is_some() || segment_tlshello;

    // One TLS record is read at most once, transformed first when
    // tls_padding / mixed_case_sni are listed.
    let first_record = if needs_first_record {
        Some(match transformed_prefix {
            Some(record) => record,
            None => read_one_tls_record(&mut incoming)
                .await
                .context("socket path: reading ClientHello from client")?,
        })
    } else {
        transformed_prefix
    };

    let client_fragmentation = match (boundary, first_record) {
        (Some(boundary), Some(record)) => {
            match boundary.split_offset(&record) {
                Some(split) => {
                    write_boundary_split(&mut outgoing, &record, split, boundary.delay_ms)
                        .await
                        .context("sni_boundary_frag: writing boundary-split ClientHello")?;
                    debug!(
                        split,
                        delay_ms = %boundary.delay_ms,
                        total_bytes = record.len(),
                        "sni_boundary_frag: ClientHello written in two boundary segments; handing off to relay"
                    );
                }
                None => {
                    // Fail-open: no SNI boundary found; forward whole.
                    outgoing
                        .write_all(&record)
                        .await
                        .context("sni_boundary_frag: writing ClientHello whole (fail-open)")?;
                    outgoing
                        .flush()
                        .await
                        .context("sni_boundary_frag: flushing ClientHello")?;
                }
            }
            // The first client write was consumed above; with tls_frag also
            // listed, later writes are segmented per its settings.
            if cfg.BYPASS_METHOD.contains("tls_frag") {
                Some((method, 1))
            } else {
                None
            }
        }
        (None, Some(client_hello)) if segment_tlshello => {
            write_fragmented(
                &mut outgoing,
                &client_hello,
                method.length,
                method.interval_ms,
            )
            .await
            .context("tls_frag: writing fragmented ClientHello")?;
            debug!(
                length = %method.length,
                interval_ms = %method.interval_ms,
                nodelay = method.nodelay,
                total_bytes = client_hello.len(),
                "tls_frag: ClientHello written in fragments; handing off to relay"
            );
            None
        }
        (None, first_record) => {
            if let Some(record) = first_record {
                outgoing
                    .write_all(&record)
                    .await
                    .context("tls_padding: writing padded ClientHello")?;
                outgoing
                    .flush()
                    .await
                    .context("tls_padding: flushing padded ClientHello")?;
            }
            if cfg.BYPASS_METHOD.contains("tls_frag") {
                debug!(
                    packets = ?method.packets,
                    length = %method.length,
                    interval_ms = %method.interval_ms,
                    nodelay = method.nodelay,
                    "tls_frag: fragmenting selected client writes in relay"
                );
                Some((method, 0))
            } else {
                None
            }
        }
        // `boundary.is_some()` implies `needs_first_record`, so the record is
        // always present when a boundary method is configured.
        (Some(_), None) => unreachable!("boundary method implies a first record"),
    };
```

Also, since `sni_boundary_frag` requires a clean two-segment split, force `TCP_NODELAY` regardless of `TCP_SEG_NODELAY`. In the same function, replace the nodelay setup:

```rust
    // Enable TCP_NODELAY on the upstream socket if configured. The boundary
    // split depends on two cleanly separated segments, so sni_boundary_frag
    // always forces it.
    if method.nodelay || cfg.BYPASS_METHOD.contains("sni_boundary_frag") {
        outgoing
            .set_nodelay(true)
            .context("set_nodelay on upstream socket")?;
    }
```

- [ ] **Step 5: Rewire the interceptor combo path (`handle_intercept_connection`)**

In the `Some(BypassProgress::ReadyForData) =>` branch, wrap the existing `if settings.segment_first_client_hello { ... } else { ... }` in a new leading branch. Replace the branch body from `Some(BypassProgress::ReadyForData) => {` through the existing `finish_bypass_or_error(..., "first data bypass timed out")?;` call with the following (the two existing inner blocks `segment_first_client_hello` and the whole-write `else` stay exactly as they are today):

```rust
        Some(BypassProgress::ReadyForData) => {
            if let Some(boundary) = settings.sni_boundary_frag {
                // The boundary split needs two cleanly separated segments.
                outgoing
                    .set_nodelay(true)
                    .context("combo sni_boundary_frag: set_nodelay on upstream socket")?;

                let client_hello = read_client_tls_record_with_timeout(
                    &mut incoming,
                    settings.bypass_timeout,
                    &entry,
                    &event_tx,
                    src_port,
                )
                .await?;
                let client_hello = settings.apply_socket_transforms(&client_hello);

                match boundary.split_offset(&client_hello) {
                    Some(split) => {
                        if let Err(e) =
                            write_boundary_split(&mut outgoing, &client_hello, split, boundary.delay_ms).await
                        {
                            entry.finish(BypassOutcome::UnexpectedClose);
                            emit(
                                &event_tx,
                                ProxyEvent::BypassComplete {
                                    src_port,
                                    outcome: BypassOutcome::UnexpectedClose,
                                },
                            );
                            return Err(e).context(
                                "combo sni_boundary_frag: writing boundary-split ClientHello",
                            );
                        }
                    }
                    None => {
                        // Fail-open: no SNI boundary found; forward whole.
                        if let Err(e) = outgoing.write_all(&client_hello).await {
                            entry.finish(BypassOutcome::UnexpectedClose);
                            emit(
                                &event_tx,
                                ProxyEvent::BypassComplete {
                                    src_port,
                                    outcome: BypassOutcome::UnexpectedClose,
                                },
                            );
                            return Err(e).context(
                                "combo sni_boundary_frag: writing ClientHello to upstream",
                            );
                        }
                        if let Err(e) = outgoing.flush().await {
                            entry.finish(BypassOutcome::UnexpectedClose);
                            emit(
                                &event_tx,
                                ProxyEvent::BypassComplete {
                                    src_port,
                                    outcome: BypassOutcome::UnexpectedClose,
                                },
                            );
                            return Err(e).context(
                                "combo sni_boundary_frag: flushing ClientHello to upstream",
                            );
                        }
                    }
                }

                // With tls_frag also listed, later client writes are
                // segmented per its settings. Write index 1 was the
                // ClientHello above, so the relay resumes at 2.
                if settings.segment_first_client_hello {
                    client_fragmentation_after_prefix =
                        Some((settings.tcp_segmentation, 1));
                }
            } else if settings.segment_first_client_hello {
                // ... existing `segment_first_client_hello` block unchanged ...
            } else {
                // ... existing whole-write block unchanged ...
            }

            let outcome = wait_for_bypass_completion(&entry, settings.bypass_timeout).await;
            finish_bypass_or_error(
                &entry,
                &event_tx,
                src_port,
                outcome,
                "first data bypass timed out",
            )?;
        }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core proxy::tests::sni_boundary_frag && cargo test -p zerodpi-core proxy::tests::`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/zerodpi-core/src/proxy.rs
git commit -m "feat: wire sni_boundary_frag into socket-only and interceptor combo paths"
```

---

### Task 6: Document the new options (`config.toml`, `README.md`)

**Files:**
- Modify: `config.toml`
- Modify: `README.md`

**Interfaces:**
- Consumes: the config keys from Task 2 (`SNI_BOUNDARY_FRAG_SPLIT_POINT`, `SNI_BOUNDARY_FRAG_DELAY_MS`, method name `sni_boundary_frag`).

- [ ] **Step 1: Add a `config.toml` section**

Insert after the `SNI_SPLIT_POSITION = "middle"` block (before the `tls_frag method parameters` separator comment):

```toml
# ---------------------------------------------------------------------------
# sni_boundary_frag method parameters
# ---------------------------------------------------------------------------
# These settings apply when BYPASS_METHOD = "sni_boundary_frag" (alone or
# combined with tls_frag / tls_padding / mixed_case_sni or the handshake
# fake-packet methods wrong_seq, wrong_ack, wrong_checksum, wrong_md5,
# wrong_timestamp, low_ttl).
#
# Unlike wrong_seq and tls_record_frag, this method does NOT use the
# WinDivert / NFQUEUE packet interceptor when combined only with other
# socket-side methods.  In combos with fake-packet methods, the fake packet
# stage still requires packet interception, while these settings control how
# the real ClientHello is written after the fake packet stage.
#
# The proxy parses the ClientHello down to the extension array, computes the
# exact byte offset of the SNI extension, and writes the ClientHello as two
# TCP segments cut at that boundary, with a small delay between them so
# inline DPI reassembly buffers do not stitch them back together.

# Where to cut the first ClientHello TCP write.
#   "extension_length" — right after the server_name extension's 2-byte
#                        length field; segment 2 starts with the extension
#                        body (default)
#   "middle"           — exact middle of the SNI domain string
#                        (e.g. https://you | tube.com)
#   N                  — after the Nth byte of the domain string (0-based),
#                        clamped to the domain length
SNI_BOUNDARY_FRAG_SPLIT_POINT = "extension_length"

# Delay between the two TCP segments, in milliseconds.
#
# Accepts either a fixed integer or an inclusive range string:
#   5        — always wait 5 ms
#   "5-10"   — randomly choose 5 through 10 ms per connection
#   0        — send both segments back-to-back
#
# A fresh value is chosen per connection.
#
# Must be >= 0.  Default: "5-10".
SNI_BOUNDARY_FRAG_DELAY_MS = "5-10"
```

- [ ] **Step 2: Update `README.md`**

**2a.** Features table (line ~56): change `**11 combinable bypass methods**` to `**12 combinable bypass methods**` and append `sni_boundary_frag` to the method list.

**2b.** Bypass Methods table (after the `urg_sni_split` row): add:

```markdown
| `sni_boundary_frag` | SNI Extension Boundary Fragmentation: parses the ClientHello down to the SNI extension and writes the first record as two TCP segments cut at the extension length field (or mid-domain), separated by a 5–10 ms delay so inline DPI cannot stitch them together | ❌ No | DPI with reassembly buffers that stitch adjacent TCP segments |
```

**2c.** In the method descriptions paragraph (around line 410, after the `urg_sni_split` bullet): add:

```markdown
- `sni_boundary_frag` keeps the TLS bytes unchanged and writes the first ClientHello as exactly two TCP segments cut at the SNI extension boundary (`SNI_BOUNDARY_FRAG_SPLIT_POINT`), with a configurable delay between them (`SNI_BOUNDARY_FRAG_DELAY_MS`). It needs no packet interception when combined only with other socket-side methods (`tls_frag`, `tls_padding`, `mixed_case_sni`).
```

**2d.** Combining rules list (around line 357, next to the `urg_sni_split` rule): add:

```markdown
- `sni_boundary_frag` cannot be combined with `tls_record_frag` or
  `urg_sni_split`; it combines with the handshake fake-packet methods, and
  with `tls_frag`, `tls_padding`, and `mixed_case_sni`.
```

**2e.** In the "Choosing a Bypass Method" table row "You cannot run packet interception but can point the VPN client at ZeroDPI" (line ~393): change `tls_frag` to `` `tls_frag` / `sni_boundary_frag` ``.

**2f.** In the `ip_bypass_plus` mentions (lines ~230, ~243, ~282): add `sni_boundary_frag` to the lists of supported methods, e.g. "supports only `tls_record_frag`, `tls_frag`, `tls_padding`, `mixed_case_sni`, or `sni_boundary_frag`."

**2g.** Check the "Packet-Interception-Free" recipe section (line ~465) and the first-run checklist (line ~154) mention socket-only method lists — add `sni_boundary_frag` where `tls_frag` / `tls_padding` / `mixed_case_sni` are enumerated as rootless options.

**2h.** Update the Android helper-message strings in `crates/zerodpi/src/main.rs` so rootless guidance mentions the new method: in `root_required_message` (line ~1298) change `BYPASS_METHOD = "tls_frag" / "tls_padding" / "mixed_case_sni"` to `BYPASS_METHOD = "tls_frag" / "tls_padding" / "mixed_case_sni" / "sni_boundary_frag"`, and in `rootless_alternatives` (line ~1303) add:

```rust
        "BYPASS_METHOD = \"sni_boundary_frag\" for supported relay modes".to_owned(),
```

- [ ] **Step 3: Verify docs build references only real config keys**

Run: `grep -n "SNI_BOUNDARY_FRAG" config.toml README.md`
Expected: the new section in `config.toml` and the README mentions.

- [ ] **Step 4: Commit**

```bash
git add config.toml README.md
git commit -m "docs: document sni_boundary_frag bypass method and options"
```

---

### Task 7: Full verification

**Files:** none (verification only).

- [ ] **Step 1: Formatting**

Run: `cargo fmt --all -- --check`
Expected: PASS. If not, run `cargo fmt --all` and re-run.

- [ ] **Step 2: Lints**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS with zero warnings.

- [ ] **Step 3: Full test suite**

Run: `cargo test --workspace`
Expected: PASS (all crates).

- [ ] **Step 4: Manual smoke test (optional but recommended)**

1. Add to `config.toml`: `MODE = "sni_spoof"`, `BYPASS_METHOD = "sni_boundary_frag"`, keep `SNI_LIST = "sni_list.txt"`.
2. Run `cargo run --bin zerodpi -- --config ./config.toml`.
3. Point a TLS client (e.g. `curl --resolve example.com:443:127.0.0.1 -x http://127.0.0.1:LISTEN_PORT https://example.com`) at the proxy, or run the app against a test network.
4. Verify with a packet capture that the ClientHello leaves the host as two TCP segments with a ~5–10 ms gap and that the split lands at the configured boundary; verify the TLS handshake completes.
5. Repeat with `BYPASS_METHOD = ["wrong_seq", "sni_boundary_frag"]` (requires packet interception: run as Administrator/root).

- [ ] **Step 5: Final commit (if anything changed during verification)**

```bash
git status
git add -u
git commit -m "chore: polish after sni_boundary_frag verification" || true
```
