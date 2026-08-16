# TLS 1.3 Middlebox-Compat ChangeCipherSpec Prefix (`ccs_prefix`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new socket-side bypass method `ccs_prefix` that writes a dummy ChangeCipherSpec record (`14 03 03 00 01 01`) as the very first bytes of the upstream TLS stream, before the (possibly transformed) ClientHello, so DPIs that classify flows on the first TLS record see a benign CCS instead of the SNI-bearing ClientHello.

**Architecture:** `ccs_prefix` is a pure socket-side method modeled on `tls_padding` — no `BypassMethod` impl, no FlowTable registration, no WinDivert/NFQUEUE. A new `methods/ccs_prefix.rs` module builds the 6-byte CCS record (`CcsPrefix`, with `CCS_PREFIX_RECORD_VERSION` selecting the two record-version bytes). `ConnectionSettings` gains `ccs_prefix: Option<CcsPrefix>`; both proxy paths (interceptor combo path and socket-only path) write the CCS as their first upstream write with `TCP_NODELAY` forced so it leaves as its own segment. `CompositeMethod` gains a `ccs_prefix_first_hello` flag (builder, display name, wait-for-data condition) so `["wrong_seq", "ccs_prefix"]` keeps the interceptor flow alive until the proxy writes the prefixed ClientHello. Config validation accepts the name, treats it as socket-only, allows it as a `sni_boundary_frag` partner, and includes it in the `ip_bypass_plus` real-SNI whitelist. The Android root helper's `MethodConfig::validate` `SUPPORTED` list gets `"ccs_prefix"` so mixed lists pass helper-side validation.

**Tech Stack:** Rust 2021 workspace (`zerodpi-core`, `zerodpi`, `zerodpi-helper-protocol`). No new dependencies. No changes to `zerodpi-platform` (error-message doc strings only, Task 5).

**Spec:** `docs/bypass-methods-candidates.md` §4.3 — the plan argues from that section; read it first.

**Approved design decisions (chat, 2026-08-16):**
- 1a: include `CCS_PREFIX_RECORD_VERSION` config knob now (hex string, default `"0x0303"`).
- 2a: allow `ccs_prefix` in `MODE = "ip_bypass_plus"` (it preserves the real SNI).
- 3a: combination rules mirror `tls_padding` exactly — combinable with everything the existing rules permit (handshake fakes, `tls_frag`, `tls_padding`, `mixed_case_sni`, `sni_boundary_frag`, `tls_record_frag`, `fake_tls`, `ip_frag`); the existing `urg_sni_split` restriction stays untouched, so `ccs_prefix` + `urg_sni_split` remains rejected.

## Global Constraints

- Rust 2021 workspace; business logic in `crates/zerodpi-core/`, CLI in `crates/zerodpi/`, wire protocol in `crates/zerodpi-helper-protocol/`. `rustfmt` formatting, 4-space indentation, `snake_case` functions/variables, `PascalCase` types, `SCREAMING_SNAKE_CASE` config fields.
- Socket-side methods never touch the interceptor pipeline: no `PacketView` changes, no `FlowTable` registration changes, no `zerodpi-platform` code changes (Task 5 edits a doc string there only).
- Config keys are parsed into `Config` with `#[serde(default = ...)]` defaults, validated in `Config::validate`, documented in `config.toml` and `README.md` (AGENTS.md requirement). Unknown `BYPASS_METHOD` names must fail validation.
- Inline `#[cfg(test)]` modules, tests named by behavior (`builds_default_ccs_record`, `rejects_invalid_ccs_prefix_record_version`).
- Per-task verification: `cargo test -p zerodpi-core <test names>` / `cargo test -p zerodpi-helper-protocol` / `cargo test -p zerodpi`; final gate: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Commit messages use conventional prefixes (`feat:`, `docs:`). No changes to runtime `sni_list.txt` / `ip_list.txt`; no private endpoints committed.
- Platform impact: none — pure socket transform, works everywhere including Termux/Android without NFQUEUE and without root. Document the TLS 1.2 caveat (RFC 5246 treats an unexpected CCS as an error; some stacks tolerate it, but TLS 1.3 is required for reliable use).

## File Structure

| File | Change | Responsibility |
|------|--------|----------------|
| `crates/zerodpi-core/src/methods/ccs_prefix.rs` | Create | `CcsPrefix` params, 6-byte CCS record builder, `parse_record_version`, tests |
| `crates/zerodpi-core/src/methods/mod.rs` | Modify | `pub mod ccs_prefix;`, `build_method` match arm + `.with_ccs_prefix(...)`, module docs, tests |
| `crates/zerodpi-core/src/methods/composite.rs` | Modify | `ccs_prefix_first_hello` flag, builder, name, wait-for-data condition, docs, tests |
| `crates/zerodpi-core/src/config.rs` | Modify | `CCS_PREFIX_RECORD_VERSION` field + default + validation, `BASE_BYPASS_METHODS`, `is_socket_only` / `requires_interceptor`, combo rules, `BYPASS_METHOD` doc comment, tests |
| `crates/zerodpi-core/src/proxy.rs` | Modify | `ConnectionSettings.ccs_prefix`, `write_ccs_prefix` helper, CCS writes in both proxy paths, module doc, tests |
| `crates/zerodpi-helper-protocol/src/lib.rs` | Modify | `SUPPORTED` list accepts `ccs_prefix` in mixed lists (Android root helper), test |
| `crates/zerodpi/src/main.rs` | Modify | `root_required_message` / `rootless_alternatives` strings, mode-interception tests |
| `crates/zerodpi-platform/src/lib.rs` | Modify | Rootless-alternative error message strings (doc only) |
| `config.toml` | Modify | `ccs_prefix` base-method entry, parameter section, `BYPASS_METHOD` examples, mode comment |
| `README.md` | Modify | Feature count, methods table, combining rules, mode matrix, quick-choice table, config table, method-workings bullets, platform notes |
| `docs/bypass-methods-candidates.md` | Modify | Mark §4.3 implemented, update §3 coverage/gap, §7 table, §8 recommendation |

---

### Task 1: `ccs_prefix` module — CCS record builder and version parsing

**Files:**
- Create: `crates/zerodpi-core/src/methods/ccs_prefix.rs`
- Modify: `crates/zerodpi-core/src/methods/mod.rs` (add `pub mod ccs_prefix;`)

**Interfaces:**
- Consumes: `crate::config::Config` (only for `new`; the field is added in Task 2, so this file references it but compilation succeeds across tasks — build the whole workspace per task).
- Produces:
  - `pub const CCS_RECORD_LEN: usize` (= 6)
  - `pub struct CcsPrefix` — `Copy, Clone, Debug, PartialEq, Eq`; methods `new(cfg: &Config) -> Self`, `exact(record_version: u16) -> Self`, `record(&self) -> [u8; CCS_RECORD_LEN]`
  - `pub fn parse_record_version(input: &str) -> Result<[u8; 2], String>` (consumed by Task 2's `Config::validate`)

- [ ] **Step 1: Write the failing tests**

Create `crates/zerodpi-core/src/methods/ccs_prefix.rs` containing only the tests module (the referenced items do not exist yet):

```rust
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
            assert!(
                parse_record_version(bad).is_err(),
                "should reject '{bad}'"
            );
        }
    }
}
```

Add the module declaration to `crates/zerodpi-core/src/methods/mod.rs`, before `pub mod composite;`:

```rust
pub mod ccs_prefix;
pub mod composite;
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core ccs_prefix`
Expected: FAIL — compile error (cannot find `CcsPrefix` / `parse_record_version`).

- [ ] **Step 3: Write the module implementation**

Replace the file content with:

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core ccs_prefix`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/methods/ccs_prefix.rs crates/zerodpi-core/src/methods/mod.rs
git commit -m "feat: add ccs_prefix CCS record builder"
```

---

### Task 2: Config — method name, socket-only classification, version knob, combo rules

**Files:**
- Modify: `crates/zerodpi-core/src/config.rs`

**Interfaces:**
- Consumes: `crate::methods::ccs_prefix::parse_record_version` (Task 1).
- Produces: `Config.CCS_PREFIX_RECORD_VERSION: String` (default `"0x0303"`); `"ccs_prefix"` accepted in `BYPASS_METHOD`, classified socket-only by `is_socket_only()` / `requires_interceptor()` (consumed by `main.rs` routing, Task 3, Task 4).

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` in `config.rs` (near the other method-parse tests):

```rust
    #[test]
    fn ccs_prefix_record_version_defaults_and_parses() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap();
        assert_eq!(cfg.CCS_PREFIX_RECORD_VERSION, "0x0303");

        let overridden: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               CCS_PREFIX_RECORD_VERSION = "0x0301""#,
        )
        .unwrap();
        assert_eq!(overridden.CCS_PREFIX_RECORD_VERSION, "0x0301");
        overridden.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_ccs_prefix_record_version() {
        for bad in ["0x03GG", "0x03", "0x03033", "xyz"] {
            let cfg: Config = toml::from_str(&format!(
                r#"LISTEN_HOST = "127.0.0.1"
                   LISTEN_PORT = 44444
                   CCS_PREFIX_RECORD_VERSION = "{bad}""#
            ))
            .unwrap();
            assert!(cfg.validate().is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn ccs_prefix_is_socket_only() {
        let single = BypassMethodList::from("ccs_prefix");
        assert!(single.is_socket_only());
        assert!(!single.requires_interceptor());

        let combo = BypassMethodList::from_delimited("ccs_prefix, wrong_seq");
        assert!(!combo.is_socket_only());
        assert!(combo.requires_interceptor());
    }

    #[test]
    fn validates_ccs_prefix_combos() {
        let ok: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["wrong_seq", "ccs_prefix"]"#,
        )
        .unwrap();
        ok.validate().unwrap();

        let with_boundary: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["sni_boundary_frag", "ccs_prefix"]"#,
        )
        .unwrap();
        with_boundary.validate().unwrap();

        let plus_mode: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               MODE = "ip_bypass_plus"
               BYPASS_METHOD = "ccs_prefix""#,
        )
        .unwrap();
        plus_mode.validate().unwrap();

        // The existing urg_sni_split restriction is unchanged.
        let urg_combo: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["urg_sni_split", "ccs_prefix"]"#,
        )
        .unwrap();
        assert!(urg_combo.validate().is_err());

        // Unknown names still fail.
        let unknown: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "ccs_prefixx""#,
        )
        .unwrap();
        assert!(unknown.validate().is_err());
    }
```

Also extend the existing helper test so `ccs_prefix` is covered by the same loop (edit the array in `socket_only_and_interceptor_helpers_include_tls_padding`):

```rust
        for name in ["tls_frag", "tls_padding", "ccs_prefix"] {
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core ccs_prefix`
Expected: FAIL — compile error (`Config` has no field `CCS_PREFIX_RECORD_VERSION`; the config tests that compile fail on `validate()`).

- [ ] **Step 3: Implement the config changes**

1. Add the import next to the existing `use crate::methods::tls_padding::PaddingPosition;` (line 10):

```rust
use crate::methods::ccs_prefix::parse_record_version;
use crate::methods::tls_padding::PaddingPosition;
```

2. Add `"ccs_prefix"` to `BASE_BYPASS_METHODS`, after `"tls_frag"`:

```rust
pub const BASE_BYPASS_METHODS: &[&str] = &[
    "wrong_seq",
    "wrong_ack",
    "wrong_checksum",
    "wrong_md5",
    "wrong_timestamp",
    "low_ttl",
    "tls_record_frag",
    "fake_tls",
    "ip_frag",
    "tls_frag",
    "ccs_prefix",
    "tls_padding",
    "mixed_case_sni",
    "urg_sni_split",
    "sni_boundary_frag",
];
```

3. Update `BypassMethodList::is_socket_only` and `requires_interceptor` — add `"ccs_prefix"` to both `matches!` lists:

```rust
                matches!(
                    m.as_str(),
                    "tls_frag" | "ccs_prefix" | "tls_padding" | "mixed_case_sni" | "sni_boundary_frag"
                )
```

4. Add the new field after `MIXED_CASE_SNI_FLIP_ALL` (before the `// Proxy timing` banner):

```rust
    // -----------------------------------------------------------------------
    // ccs_prefix method parameters
    // -----------------------------------------------------------------------
    /// The two TLS record-version bytes of the dummy ChangeCipherSpec record
    /// written by `ccs_prefix`, as a hex string. TLS 1.3's middlebox
    /// compatibility mode (RFC 8446 §4.1.3) uses `0x0303`; vary this only
    /// when a DPI fingerprints on the record version.
    /// Must be exactly two bytes (e.g. `"0x0303"` or `"0303"`).
    /// Default: `"0x0303"`.
    #[serde(default = "default_ccs_prefix_record_version")]
    pub CCS_PREFIX_RECORD_VERSION: String,
```

5. Add the default function next to `default_tls_padding_position`:

```rust
fn default_ccs_prefix_record_version() -> String {
    "0x0303".into()
}
```

6. Add validation right after the `PaddingPosition::parse(...)` check in `validate`:

```rust
        parse_record_version(&self.CCS_PREFIX_RECORD_VERSION)
            .map_err(|e| anyhow::anyhow!("CCS_PREFIX_RECORD_VERSION is invalid: {e}"))?;
```

7. Add `"ccs_prefix"` to the `sni_boundary_frag` allowed-partner list (inside the `matches!` in the `sni_boundary_frag` combo rule, after `"ip_frag"`):

```rust
                                | "fake_tls"
                                | "ip_frag"
                                | "ccs_prefix"
```

8. Add `"ccs_prefix"` to the `ip_bypass_plus` whitelist `matches!` (after `"sni_boundary_frag"`) and update the error message:

```rust
                matches!(
                    m,
                    "tls_record_frag"
                        | "tls_frag"
                        | "tls_padding"
                        | "mixed_case_sni"
                        | "sni_boundary_frag"
                        | "ccs_prefix"
                        | "ip_frag"
                )
```

```rust
            anyhow::bail!(
                "MODE = \"ip_bypass_plus\" supports only real-SNI-preserving BYPASS_METHOD values: \"tls_record_frag\", \"tls_frag\", \"tls_padding\", \"mixed_case_sni\", \"sni_boundary_frag\", \"ccs_prefix\", or \"ip_frag\""
            );
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core ccs_prefix`
Expected: PASS — including `validates_ccs_prefix_combos`, `ccs_prefix_is_socket_only`, and the extended helper loop test.

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/config.rs
git commit -m "feat: add ccs_prefix config name, socket-only classification, and CCS_PREFIX_RECORD_VERSION"
```

---

### Task 3: Composite flag, `build_method` registration, Android helper support

**Files:**
- Modify: `crates/zerodpi-core/src/methods/composite.rs`
- Modify: `crates/zerodpi-core/src/methods/mod.rs`
- Modify: `crates/zerodpi-helper-protocol/src/lib.rs`

**Interfaces:**
- Consumes: `"ccs_prefix"` config name (Task 2).
- Produces: `CompositeMethod::with_ccs_prefix(enabled: bool) -> Self`; composite display name includes `"ccs_prefix"`; composite waits for the data stage when the flag is set (consumed by the proxy path in Task 4). Helper-protocol `SUPPORTED` accepts `"ccs_prefix"`.

- [ ] **Step 1: Write the failing tests**

In `composite.rs` `#[cfg(test)] mod tests`, append:

```rust
    #[test]
    fn wrong_seq_plus_ccs_prefix_waits_for_data_stage() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(vec![Box::new(WrongSeq::new(&cfg))], None, false, false)
            .with_ccs_prefix(true);

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_data());
        assert_eq!(m.name(), "wrong_seq + ccs_prefix");
    }

    #[test]
    fn name_omits_ccs_prefix_when_not_set() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(vec![Box::new(WrongSeq::new(&cfg))], None, false, false);
        assert_eq!(m.name(), "wrong_seq");
    }
```

In `methods/mod.rs` `#[cfg(test)] mod tests`, append:

```rust
    #[test]
    fn build_wrong_seq_ccs_prefix_method() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["wrong_seq", "ccs_prefix"]"#);
        let method = build_method(&cfg).unwrap();
        assert_eq!(method.name(), "wrong_seq + ccs_prefix");
    }

    #[test]
    fn socket_ccs_prefix_method_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = "ccs_prefix""#);
        assert!(build_method(&cfg).is_none());
    }

    #[test]
    fn socket_list_with_ccs_prefix_returns_none() {
        let cfg = cfg_with_method(r#"BYPASS_METHOD = ["ccs_prefix", "tls_padding"]"#);
        assert!(build_method(&cfg).is_none());
    }
```

In `zerodpi-helper-protocol/src/lib.rs` `#[cfg(test)] mod tests` (near the other `validate` tests), append:

```rust
    #[test]
    fn validate_accepts_ccs_prefix_in_mixed_list() {
        let mut config = method();
        config.methods = vec!["wrong_seq".into(), "ccs_prefix".into()];
        config.validate().unwrap();
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core ccs_prefix` and `cargo test -p zerodpi-helper-protocol validate_accepts_ccs_prefix`
Expected: FAIL — compile errors (`with_ccs_prefix` not found; helper rejects the method name at runtime, so the helper test fails on `unwrap()`).

- [ ] **Step 3: Implement**

In `composite.rs`:

1. Add the field to `CompositeMethod` and initialize it in `new`:

```rust
    pub splits_first_client_hello: bool,
    pub ccs_prefix_first_hello: bool,
```

```rust
            mixed_case_sni_first_hello: false,
            splits_first_client_hello: false,
            ccs_prefix_first_hello: false,
```

2. Add the builder after `with_sni_boundary_split`:

```rust
    /// Mark the composite as including the socket-side `ccs_prefix` transform
    /// so its name reflects the full method list and the handshake stage
    /// waits for the data stage.
    pub fn with_ccs_prefix(mut self, enabled: bool) -> Self {
        self.ccs_prefix_first_hello = enabled;
        self
    }
```

3. In `name()`, after the `splits_first_client_hello` push:

```rust
        if self.ccs_prefix_first_hello {
            parts.push("ccs_prefix".into());
        }
```

4. Extend the wait-for-data condition in `on_handshake_complete_ack`:

```rust
        if self.data_method.is_some()
            || self.segments_first_client_hello
            || self.pads_first_client_hello
            || self.splits_first_client_hello
            || self.ccs_prefix_first_hello
        {
```

5. Update the module doc: append to the socket-side flags sentence in the header comment (`...and `sni_boundary_frag` via [`CompositeMethod::splits_first_client_hello`].`) an equivalent sentence for `ccs_prefix` via `CompositeMethod::ccs_prefix_first_hello`.

In `methods/mod.rs`:

6. Add the `build_method` match arm after the `"tls_frag"` arm:

```rust
            "tls_frag" => {}          // socket side; handled directly in proxy.rs
            "ccs_prefix" => {}        // socket side; handled directly in proxy.rs
            "tls_padding" => {}       // socket side; handled directly in proxy.rs
```

7. Chain the new builder at the end of `build_method`:

```rust
        .with_mixed_case_sni(list.contains("mixed_case_sni"))
        .with_sni_boundary_split(list.contains("sni_boundary_frag"))
        .with_ccs_prefix(list.contains("ccs_prefix")),
```

8. Update the module docs: add a socket-based bullet for `ccs_prefix` after the `sni_boundary_frag` bullet:

```rust
//! - `ccs_prefix` — TLS 1.3 Middlebox-Compat ChangeCipherSpec Prefix. Writes
//!   a dummy ChangeCipherSpec record (`14 03 03 00 01 01`) as the very first
//!   upstream bytes before the ClientHello, so DPIs that classify on the
//!   first TLS record see a benign CCS (RFC 8446 §4.1.3, §5.5).
```

9. Update the `build_method` doc comment: mention `ccs_prefix` in the socket-only list example.

In `zerodpi-helper-protocol/src/lib.rs`:

10. Add `"ccs_prefix"` to `SUPPORTED` in `MethodConfig::validate` (after `"tls_padding"`):

```rust
            "tls_frag",
            "tls_padding",
            "ccs_prefix",
            "urg_sni_split",
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core ccs_prefix && cargo test -p zerodpi-helper-protocol`
Expected: PASS (composite, build_method, and helper tests all green).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/methods/composite.rs crates/zerodpi-core/src/methods/mod.rs crates/zerodpi-helper-protocol/src/lib.rs
git commit -m "feat: wire ccs_prefix through composite, build_method, and Android helper"
```

---

### Task 4: Proxy wiring — write the CCS as the first upstream bytes

**Files:**
- Modify: `crates/zerodpi-core/src/proxy.rs`

**Interfaces:**
- Consumes: `CcsPrefix` (Task 1), `Config.BYPASS_METHOD` / `CCS_PREFIX_RECORD_VERSION` (Task 2).
- Produces: `ConnectionSettings.ccs_prefix: Option<CcsPrefix>`; `async fn write_ccs_prefix<W: AsyncWrite + Unpin>(dst: &mut W, ccs: CcsPrefix) -> anyhow::Result<()>`.

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` in `proxy.rs` (which already has `RecordingWriter` and `use super::*`):

```rust
    #[test]
    fn connection_settings_enable_ccs_prefix_from_config() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "ccs_prefix""#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert_eq!(settings.ccs_prefix, Some(CcsPrefix::exact(0x0303)));

        let plain: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap();
        assert!(ConnectionSettings::from_config(&plain).ccs_prefix.is_none());
    }

    #[tokio::test]
    async fn ccs_prefix_write_emits_the_six_byte_record() {
        let mut writer = RecordingWriter::default();
        write_ccs_prefix(&mut writer, CcsPrefix::exact(0x0303))
            .await
            .unwrap();
        assert_eq!(writer.writes, vec![vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01]]);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core ccs_prefix`
Expected: FAIL — compile error (`CcsPrefix` not imported, no `ccs_prefix` field, no `write_ccs_prefix`).

- [ ] **Step 3: Implement**

1. Add the import after `use crate::flow::...`:

```rust
use crate::methods::ccs_prefix::CcsPrefix;
```

2. Add the field to `ConnectionSettings` (after `tls_padding`) and populate it in `from_config`:

```rust
    tls_padding: Option<TlsPadding>,
    ccs_prefix: Option<CcsPrefix>,
    mixed_case_sni: Option<MixedCaseSni>,
```

```rust
            tls_padding: cfg
                .BYPASS_METHOD
                .contains("tls_padding")
                .then(|| TlsPadding::new(cfg)),
            ccs_prefix: cfg
                .BYPASS_METHOD
                .contains("ccs_prefix")
                .then(|| CcsPrefix::new(cfg)),
            mixed_case_sni: cfg
                .BYPASS_METHOD
                .contains("mixed_case_sni")
                .then(|| MixedCaseSni::new(cfg)),
```

3. Add the helper after `write_client_data`:

```rust
/// Write the dummy ChangeCipherSpec record of `ccs_prefix` as the very first
/// bytes of the upstream stream, flushed so it leaves as its own segment.
async fn write_ccs_prefix<W>(dst: &mut W, ccs: CcsPrefix) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    dst.write_all(&ccs.record())
        .await
        .context("ccs_prefix: writing dummy ChangeCipherSpec record")?;
    dst.flush()
        .await
        .context("ccs_prefix: flushing dummy ChangeCipherSpec record")
}
```

4. Interceptor combo path: in `handle_intercept_connection`, at the top of the `Some(BypassProgress::ReadyForData) => {` arm, before `if let Some(boundary) = settings.sni_boundary_frag {`, insert:

```rust
        Some(BypassProgress::ReadyForData) => {
            // `ccs_prefix`: the dummy ChangeCipherSpec must be the very first
            // bytes written upstream, before any ClientHello write below.
            if let Some(ccs) = settings.ccs_prefix {
                outgoing
                    .set_nodelay(true)
                    .context("ccs_prefix: set_nodelay on upstream socket")?;
                if let Err(e) = write_ccs_prefix(&mut outgoing, ccs).await {
                    entry.finish(BypassOutcome::UnexpectedClose);
                    emit(
                        &event_tx,
                        ProxyEvent::BypassComplete {
                            src_port,
                            outcome: BypassOutcome::UnexpectedClose,
                        },
                    );
                    return Err(e).context("ccs_prefix: writing ChangeCipherSpec prefix");
                }
            }
            if let Some(boundary) = settings.sni_boundary_frag {
```

5. Socket-only path: in `handle_tcp_seg_connection_with_ip`, extend the `TCP_NODELAY` condition and write the CCS right after that block, before the `transformed_prefix` read:

```rust
    if method.nodelay
        || cfg.BYPASS_METHOD.contains("sni_boundary_frag")
        || cfg.BYPASS_METHOD.contains("ccs_prefix")
    {
        outgoing
            .set_nodelay(true)
            .context("set_nodelay on upstream socket")?;
    }

    // `ccs_prefix`: write the dummy ChangeCipherSpec as the very first
    // upstream bytes; every ClientHello write below follows it.  When
    // `ccs_prefix` is listed alone, the relay then forwards the client's
    // stream untouched — the CCS is still the first record on the wire.
    if cfg.BYPASS_METHOD.contains("ccs_prefix") {
        write_ccs_prefix(&mut outgoing, CcsPrefix::new(&cfg))
            .await
            .context("ccs_prefix: writing ChangeCipherSpec prefix")?;
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core ccs_prefix`
Expected: PASS (2 new tests + Task 1 tests). Also run `cargo test -p zerodpi-core proxy::` to confirm the existing proxy tests stay green.

- [ ] **Step 5: Manual smoke check (optional but recommended)**

Run: `cargo run --bin zerodpi -- --config ./config.toml` with `BYPASS_METHOD = "ccs_prefix"` and `MODE = "sni_spoof"`, connect a VPN client, and capture the upstream connection (e.g. Wireshark/tcpdump): the first upstream bytes must be `14 03 03 00 01 01`, followed by the ClientHello, and the TLS handshake must complete against a TLS 1.3 endpoint.

- [ ] **Step 6: Commit**

```bash
git add crates/zerodpi-core/src/proxy.rs
git commit -m "feat: write ccs_prefix ChangeCipherSpec before the first upstream ClientHello"
```

---

### Task 5: Documentation, repo `config.toml`, and CLI messages

**Files:**
- Modify: `crates/zerodpi-core/src/config.rs` (`BYPASS_METHOD` doc comment)
- Modify: `crates/zerodpi-core/src/proxy.rs` (top module doc)
- Modify: `crates/zerodpi/src/main.rs` (messages + tests)
- Modify: `crates/zerodpi-platform/src/lib.rs` (error strings)
- Modify: `config.toml`
- Modify: `README.md`
- Modify: `docs/bypass-methods-candidates.md`

No behavior changes — docs and config surface only.

- [ ] **Step 1: `config.rs` — `BYPASS_METHOD` doc comment**

After the `sni_boundary_frag` bullet in the `BYPASS_METHOD` doc comment, add:

```rust
    /// - `"ccs_prefix"` — TLS 1.3 Middlebox-Compat ChangeCipherSpec Prefix.
    ///   Writes a dummy ChangeCipherSpec record (`14 03 03 00 01 01`,
    ///   version configurable via `CCS_PREFIX_RECORD_VERSION`) as the very
    ///   first upstream bytes, before the (possibly transformed)
    ///   ClientHello. TLS 1.3 servers ignore the early CCS (RFC 8446
    ///   §5.5); DPI that classifies on the first TLS record sees a benign
    ///   CCS instead of the ClientHello. Socket-side only: does not inject
    ///   fake packets or use WinDivert/NFQUEUE interception; operates
    ///   inside the proxy before the first ClientHello write.
```

And update the summary sentence that lists data-stage methods: `` `tls_record_frag`, `tls_frag`, `tls_padding`, `mixed_case_sni`, and `sni_boundary_frag` add the data stage. `` becomes `` `tls_record_frag`, `tls_frag`, `tls_padding`, `mixed_case_sni`, and `sni_boundary_frag` add the data stage; `ccs_prefix` adds a socket-side prefix stage. ``

- [ ] **Step 2: `proxy.rs` — top module doc**

In the socket-based methods paragraph near the top of `proxy.rs`, add:

```rust
//! For `ccs_prefix` (TLS 1.3 middlebox-compat ChangeCipherSpec prefix), a
//! 6-byte dummy ChangeCipherSpec record is written as the very first
//! upstream bytes before the ClientHello; the TLS bytes are not modified.
```

- [ ] **Step 3: `main.rs` — rootless hints and tests**

1. In `root_required_message`, extend the alternatives list: `` `"tls_frag"` / `"tls_padding"` / `"mixed_case_sni"` / `"sni_boundary_frag"` `` becomes `` `"tls_frag"` / `"tls_padding"` / `"mixed_case_sni"` / `"sni_boundary_frag"` / `"ccs_prefix"` ``.
2. In `rootless_alternatives`, add after the `sni_boundary_frag` entry:

```rust
        "BYPASS_METHOD = \"ccs_prefix\" for supported relay modes".to_owned(),
```

3. Add test assertions. In `non_interception_modes_do_not_require_packet_interception`:

```rust
        assert!(!mode_requires_packet_interception(
            "sni_spoof",
            &method_list("ccs_prefix")
        ));
```

In `ip_bypass_plus_requires_interception_only_for_tls_record_frag`:

```rust
        assert!(!mode_requires_packet_interception(
            "ip_bypass_plus",
            &method_list("ccs_prefix")
        ));
```

- [ ] **Step 4: `zerodpi-platform/src/lib.rs` — rootless hints**

In the three `packet_interception_access_error` strings, change `use BYPASS_METHOD = \"tls_frag\"` to `use BYPASS_METHOD = \"tls_frag\" / \"ccs_prefix\"` (Windows message and both Linux/Android messages).

- [ ] **Step 5: `config.toml`**

1. In the `ip_bypass_plus` comment at the top (MODE section), the line `#                      "tls_padding", "mixed_case_sni", "sni_boundary_frag",` becomes `#                      "tls_padding", "mixed_case_sni", "sni_boundary_frag",\n#                      "ccs_prefix",` and the following `#                      or "ip_frag").` stays.
2. In the `BYPASS_METHOD` examples block, add a third example line after `#   BYPASS_METHOD = ["wrong_seq", "tls_frag"]`:

```
#   BYPASS_METHOD = "ccs_prefix"
```

3. In the `Base methods:` comment block, after the `"sni_boundary_frag"` entry, add:

```
#   "ccs_prefix"
#     TLS 1.3 Middlebox-Compat ChangeCipherSpec Prefix.  Does NOT inject fake
#     packets and does NOT use WinDivert or NFQUEUE packet interception.
#     Writes a dummy ChangeCipherSpec record (14 03 03 00 01 01, version
#     bytes configurable via CCS_PREFIX_RECORD_VERSION) as the very first
#     bytes of the upstream stream, before the real ClientHello.  TLS 1.3
#     servers treat a ChangeCipherSpec received before their first Finished
#     as a no-op (RFC 8446 §4.1.3, §5.5), so the handshake proceeds; DPIs
#     that classify on the first TLS record see a benign CCS instead of the
#     ClientHello.  TLS 1.2 servers are not required to tolerate the prefix.
```

4. After the `mixed_case_sni` parameter section (after `MIXED_CASE_SNI_FLIP_ALL = false`), add:

```toml
# ---------------------------------------------------------------------------
# ccs_prefix method parameters
# ---------------------------------------------------------------------------
# These settings apply when BYPASS_METHOD = "ccs_prefix" (alone or combined).

# The two TLS record-version bytes of the dummy ChangeCipherSpec record, as a
# hex string.  TLS 1.3's middlebox compatibility mode uses 0x0303; change
# this only when a DPI fingerprints on the record version.
CCS_PREFIX_RECORD_VERSION = "0x0303"
```

- [ ] **Step 6: `README.md`**

1. Feature bullet (line 56): `🧩 **14 combinable bypass methods**` → `🧩 **15 combinable bypass methods**`, and add `` `ccs_prefix` `` to the method list after `` `tls_padding` ``.
2. Methods table: add a row after the `sni_boundary_frag` row:

```markdown
| `ccs_prefix` | TLS 1.3 Middlebox-Compat ChangeCipherSpec Prefix: writes a dummy ChangeCipherSpec record (`14 03 03 00 01 01`) as the very first upstream bytes, so DPIs that classify on the first TLS record see a benign CCS instead of the ClientHello; TLS 1.3 servers ignore the early CCS per RFC 8446 §5.5 (TLS 1.2 servers may reject it) | ❌ No | DPI that classifies flows on the first TLS record only |
```

3. Combining rules bullets:
   - In the `sni_boundary_frag` bullet, `with `tls_frag`, `tls_padding`, and `mixed_case_sni`.` becomes `with `tls_frag`, `tls_padding`, `mixed_case_sni`, and `ccs_prefix`.`
   - Add a new bullet after the `ip_frag` bullet:

```markdown
- `ccs_prefix` combines with every method except `urg_sni_split` (which keeps
  its existing restriction); it is included in the `ip_bypass_plus` real-SNI
  whitelist.
```

   - In the `ip_bypass_plus` bullet, add `` `ccs_prefix` `` to the supported list.
4. "How combinations behave" paragraph: after "`sni_boundary_frag` adds a socket-side data stage that writes the real ClientHello as two TCP segments cut at the SNI extension boundary." append "`ccs_prefix` adds a socket-side prefix stage that writes a dummy ChangeCipherSpec record as the very first upstream bytes." And in the same paragraph, the sentence "a list containing only `tls_frag`, `tls_padding`, `mixed_case_sni`, and/or `sni_boundary_frag` skips the interceptor entirely." becomes "a list containing only `tls_frag`, `tls_padding`, `mixed_case_sni`, `sni_boundary_frag`, and/or `ccs_prefix` skips the interceptor entirely."
5. In the `fake_tls` and `ip_frag` "How combinations behave" bullets, add `` `ccs_prefix` `` to their "combines with `tls_frag`, `tls_padding`, `mixed_case_sni`, and `sni_boundary_frag`" lists.
6. Platform notes: in line 154 add `/ `ccs_prefix`` to both socket-method lists; line 165 add `` `ccs_prefix` `` after `` `mixed_case_sni` ``; line 167 add `` `ccs_prefix` `` to the "Try ... first" list.
7. Mode table (line 230) and mode matrix (line 243): add `` `ccs_prefix` `` to the `ip_bypass_plus` supported-method lists.
8. Line 235: add `` `BYPASS_METHOD = "ccs_prefix"` `` to the no-interception suggestions.
9. Line 282 (`ip_bypass_plus` description): add `` / `BYPASS_METHOD = "ccs_prefix"` `` to the socket-only transform list.
10. Quick-choice table: add a row after the `tls_padding` row:

```markdown
| DPI classifies flows on the first TLS record only | `ccs_prefix` |
```

11. "How the methods work" section: after the `sni_boundary_frag` bullet, add:

```markdown
- `ccs_prefix` writes a dummy ChangeCipherSpec record (`14 03 03 00 01 01`,
  version bytes configurable via `CCS_PREFIX_RECORD_VERSION`) as the very
  first bytes of the upstream stream, before any ClientHello write. TLS 1.3
  servers treat an early CCS as a no-op (RFC 8446 §5.5); DPIs that classify
  on the first TLS record see the CCS instead of the ClientHello. It needs
  no packet interception and combines with every other method except
  `urg_sni_split`. TLS 1.2 servers are not required to tolerate a
  pre-ClientHello CCS.
```

12. Config table: add a row after `TLS_PADDING_POSITION`:

```markdown
| `CCS_PREFIX_RECORD_VERSION` | string | `"0x0303"` | The two record-version bytes of the dummy ChangeCipherSpec record written by `ccs_prefix`, as a hex string (`"0x0303"` or `"0303"`) |
```

13. Method tips (near "If the DPI reassembles adjacent TCP segments..."): add a new sentence:

```markdown
If the DPI instead classifies flows on the first TLS record only, use
`BYPASS_METHOD = "ccs_prefix"` — a dummy ChangeCipherSpec record is written
before the real ClientHello (`CCS_PREFIX_RECORD_VERSION`), without any
packet interception.
```

- [ ] **Step 7: `docs/bypass-methods-candidates.md` status updates**

1. §4.3 heading: add a status line directly under the heading:

```markdown
**Status (2026-08-16):** Implemented (`ccs_prefix`, socket-side, writes the
dummy CCS record `14 03 03 00 01 01` as the first upstream bytes, version
configurable via `CCS_PREFIX_RECORD_VERSION`).
```

2. §3 coverage table: add a row after the `sni_boundary_frag` row:

```markdown
| `ccs_prefix` | socket | dummy ChangeCipherSpec record before the ClientHello; first-record DPIs see no SNI (RFC 8446 §4.1.3) |
```

3. §3 gap summary: the sentence "What is missing versus the comparable tools is decoy-TLS-record injection (`fake_tls`), out-of-order delivery (`disorder`), IP-layer fragmentation, and a handful of header/record-level tricks." becomes "What is missing versus the comparable tools is `fake_tls` variant B (socket-side forged record length), out-of-order delivery (`disorder`), and record-level tricks such as `tls_record_split` and `tcp_opt_pad`."
4. §7 comparison table: mark the `ccs_prefix` row with `✅ implemented` in the Effort column text (append " — ✅ implemented").
5. §8 recommendation: item 2 `**`ccs_prefix`** — a few hours of work, platform-neutral, and gives Termux/Android users a new non-root option.` becomes `**`ccs_prefix`** — ✅ implemented.`

- [ ] **Step 8: Verify docs-only changes compile and tests pass**

Run: `cargo test -p zerodpi` and `cargo test -p zerodpi-core config::`
Expected: PASS (main.rs message tests unchanged; new mode-interception assertions pass).

- [ ] **Step 9: Commit**

```bash
git add crates/zerodpi-core/src/config.rs crates/zerodpi-core/src/proxy.rs crates/zerodpi/src/main.rs crates/zerodpi-platform/src/lib.rs config.toml README.md docs/bypass-methods-candidates.md
git commit -m "docs: document ccs_prefix in config.toml, README, and candidates doc"
```

---

### Task 6: Full verification gate

- [ ] **Step 1: Formatting**

Run: `cargo fmt --all -- --check`
Expected: clean (or run `cargo fmt --all` and re-check).

- [ ] **Step 2: Lints**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 3: Full test suite**

Run: `cargo test --workspace`
Expected: all tests pass, including the existing `rejects_unknown_bypass_method`, `socket_only_*`, composite, config, proxy, and helper-protocol tests.

- [ ] **Step 4: Grep sweep for missed enumerations**

Run: `rg -n "tls_padding" crates/zerodpi-core/src/proxy.rs crates/zerodpi/src/main.rs crates/zerodpi-platform/src/lib.rs README.md config.toml docs/bypass-methods-candidates.md | rg -i "socket|standalone|rootless|admin|intercept" `
Expected: every socket-method enumeration that lists `tls_padding` should also mention `ccs_prefix` where the context covers standalone/socket-only methods. Fix any missed spot and re-run Steps 1–3.

- [ ] **Step 5: Final commit (only if Step 4 changed anything)**

```bash
git add -u
git commit -m "docs: complete ccs_prefix mention sweep"
```

---

## Self-Review Notes (plan author, checked before handoff)

- **Spec coverage:** §4.3's overview (CCS before ClientHello), integration (socket-side, composes with handshake methods via composite flag), config (`CCS_PREFIX_RECORD_VERSION`, default `0x0303`), platform (everywhere, no admin/root), risks (TLS 1.2 caveat documented in module doc, README, config.toml), and §9 checklist items (config group, registration, validation incl. `rejects_unknown_bypass_method`, inline behavior-named tests, README config table + combining rules, platform notes, TUI/`--json-events` display — automatic via `BypassMethodList` Display / composite `name()`) all map to Tasks 1–5. Candidates-doc status updated (Task 5, Step 7).
- **Type consistency:** `CcsPrefix::new/exact/record`, `parse_record_version -> Result<[u8; 2], String>`, `CCS_RECORD_LEN = 6`, `ConnectionSettings.ccs_prefix: Option<CcsPrefix>`, `write_ccs_prefix(dst, ccs)`, `CompositeMethod::with_ccs_prefix(bool)` — identical names across all tasks.
- **Combo semantics check:** with `ccs_prefix` in the composite wait-for-data condition, `handle_intercept_connection` always reaches the `ReadyForData` branch when the method is listed, so the proxy itself writes the CCS + ClientHello; the `Complete` branch cannot pre-empt it (same invariant `tls_padding` already relies on). Socket-only lists route to `handle_tcp_seg_connection_with_ip` via `is_socket_only()`.
