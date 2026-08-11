# `BYPASS_METHOD` Method List Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `BYPASS_METHOD` accept a single method name or a TOML array of method names, compose methods generically at runtime, and document the combination limits in `config.toml` and `README.md`.

**Architecture:** A new `BypassMethodList` config type (string-or-array deserializer, combo aliases expanded at parse time) replaces `Config::BYPASS_METHOD: String`. A new generic `CompositeMethod` implements the `BypassMethod` trait by running every handshake-stage member in order onto one fake packet, then delegating the data stage to `tls_record_frag` when present. The four hard-coded combo structs are deleted; their names survive as expanding aliases.

**Tech Stack:** Rust 2021 workspace (`zerodpi-core`, `zerodpi`, `zerodpi-platform`, `zerodpi-helper-protocol`, `zerodpi-root-helper`), serde/toml, tokio, tracing.

## Global Constraints

- Command to check a single crate: `cargo test -p zerodpi-core` (etc.); full check: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`.
- Base method names (exact strings): `wrong_seq`, `wrong_ack`, `wrong_checksum`, `wrong_md5`, `wrong_timestamp`, `low_ttl`, `tls_record_frag`, `tls_frag`, `urg_sni_split`.
- Combo aliases (exact strings) expand at parse time: `wrong_seq_wrong_md5` → `["wrong_seq", "wrong_md5"]`; `wrong_seq_tls_frag` → `["wrong_seq", "tls_frag"]`; `wrong_md5_tls_frag` → `["wrong_md5", "tls_frag"]`; `wrong_seq_tls_record_frag` → `["wrong_seq", "tls_record_frag"]`.
- Combination limits (also documented in `config.toml` + `README.md`): no empty list; no unknown names; no duplicates (after alias expansion); `urg_sni_split` only alone or with `tls_frag`/`tls_record_frag`; `MODE = "ip_bypass_plus"` requires every element to be `tls_record_frag` or `tls_frag`; `LOW_TTL_DISCOVER = true` requires `low_ttl` in the list.
- Composite precedence rules: PSH / IP-ident from the **first** handshake-stage member; completion action from the **last**; a member's `AbortAndAccept` is honored only if no member staged anything.
- `BypassMethod::name()` signature changes to return `String` (the composite name is dynamic).
- `BypassMethodList` always stores **only base names** (aliases are expanded in every constructor).
- Windows dev machine; repo-local `windivert/` untouched. Never commit private endpoints/credentials.

---

### Task 1: `BypassMethodList` config type

**Files:**
- Modify: `crates/zerodpi-core/src/config.rs` (top of file, after the `use` block, before `pub struct Config`; and in `mod tests`)

**Interfaces:**
- Produces:
  - `pub struct BypassMethodList(Vec<String>)` — `Clone, Debug, PartialEq, Eq, Default`.
  - `pub const BASE_BYPASS_METHODS: &[&str]` — the 9 base names.
  - Methods: `from_delimited(&str) -> Self` (comma-separated), `contains(&self, &str) -> bool`, `iter(&self) -> impl Iterator<Item = &str>`, `as_slice(&self) -> &[String]`, `is_empty(&self) -> bool`, `len(&self) -> usize`, `is_socket_only(&self) -> bool` (exactly `["tls_frag"]`), `requires_interceptor(&self) -> bool` (any element other than `tls_frag`).
  - `impl fmt::Display` — joins with `" + "`.
  - `impl PartialEq<&str>` — equal when the list is exactly that one name (keeps existing single-name `assert_eq!(cfg.BYPASS_METHOD, "x")` tests working).
  - `impl From<&str>`, `From<String>`, `From<Vec<String>>` — each expands aliases element-wise.
  - `impl<'de> serde::Deserialize<'de>` — accepts a string or an array of strings; expands aliases.
- Consumes: nothing (standalone addition; `Config` field untouched in this task).

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `crates/zerodpi-core/src/config.rs`:

```rust
#[test]
fn parses_single_method_string() {
    let cfg: Config = toml::from_str(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = "wrong_seq""#,
    )
    .unwrap();
    assert_eq!(cfg.BYPASS_METHOD, "wrong_seq");
    assert_eq!(
        cfg.BYPASS_METHOD.iter().collect::<Vec<_>>(),
        vec!["wrong_seq"]
    );
}

#[test]
fn parses_method_array() {
    let cfg: Config = toml::from_str(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = ["wrong_seq", "low_ttl"]"#,
    )
    .unwrap();
    assert_eq!(
        cfg.BYPASS_METHOD.iter().collect::<Vec<_>>(),
        vec!["wrong_seq", "low_ttl"]
    );
}

#[test]
fn expands_combo_alias_in_string() {
    let cfg: Config = toml::from_str(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = "wrong_seq_tls_frag""#,
    )
    .unwrap();
    assert_eq!(
        cfg.BYPASS_METHOD.iter().collect::<Vec<_>>(),
        vec!["wrong_seq", "tls_frag"]
    );
}

#[test]
fn expands_combo_alias_in_array() {
    let cfg: Config = toml::from_str(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = ["wrong_seq_tls_frag", "low_ttl"]"#,
    )
    .unwrap();
    assert_eq!(
        cfg.BYPASS_METHOD.iter().collect::<Vec<_>>(),
        vec!["wrong_seq", "tls_frag", "low_ttl"]
    );
}

#[test]
fn display_joins_methods_with_plus() {
    let list = BypassMethodList::from_delimited("wrong_seq, tls_frag");
    assert_eq!(list.to_string(), "wrong_seq + tls_frag");
}

#[test]
fn socket_only_and_interceptor_helpers() {
    let socket_only = BypassMethodList::from("tls_frag");
    assert!(socket_only.is_socket_only());
    assert!(!socket_only.requires_interceptor());

    let combo = BypassMethodList::from_delimited("tls_frag, wrong_seq");
    assert!(!combo.is_socket_only());
    assert!(combo.requires_interceptor());

    let single = BypassMethodList::from("wrong_seq");
    assert!(!single.is_socket_only());
    assert!(single.requires_interceptor());
}

#[test]
fn from_delimited_splits_commas() {
    let list = BypassMethodList::from_delimited("wrong_seq, wrong_ack, tls_frag");
    assert_eq!(
        list.iter().collect::<Vec<_>>(),
        vec!["wrong_seq", "wrong_ack", "tls_frag"]
    );
}

#[test]
fn rejects_non_string_method_type() {
    let err = toml::from_str::<Config>(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = 5"#,
    );
    assert!(err.is_err());
}
```

Note: these tests do not compile yet because `BypassMethodList` does not exist and `Config::BYPASS_METHOD` is still `String`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core config::tests::parses_single_method_string`
Expected: FAIL (compile error — `BypassMethodList` not found).

- [ ] **Step 3: Implement `BypassMethodList`**

Add `use std::fmt;` to the imports in `config.rs` if not already present, then insert before `pub struct Config`:

```rust
/// Base bypass method names that can be combined in `BYPASS_METHOD`.
pub const BASE_BYPASS_METHODS: &[&str] = &[
    "wrong_seq",
    "wrong_ack",
    "wrong_checksum",
    "wrong_md5",
    "wrong_timestamp",
    "low_ttl",
    "tls_record_frag",
    "tls_frag",
    "urg_sni_split",
];

/// Expand a combo alias into its base method names; other names pass through.
fn expand_method_alias(name: &str) -> Vec<String> {
    match name {
        "wrong_seq_wrong_md5" => vec!["wrong_seq", "wrong_md5"],
        "wrong_seq_tls_frag" => vec!["wrong_seq", "tls_frag"],
        "wrong_md5_tls_frag" => vec!["wrong_md5", "tls_frag"],
        "wrong_seq_tls_record_frag" => vec!["wrong_seq", "tls_record_frag"],
        other => vec![other.to_owned()],
    }
}

/// The configured bypass method list.
///
/// Accepts either a single method name (`"wrong_seq"`) or a TOML array of
/// method names (`["wrong_seq", "tls_frag"]`). Combo aliases such as
/// `"wrong_seq_tls_frag"` are expanded to their base names at parse time, so
/// this type always stores only [`BASE_BYPASS_METHODS`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BypassMethodList(Vec<String>);

impl BypassMethodList {
    /// Parse a comma-separated list (used by the CLI `--method` flag),
    /// e.g. `"wrong_seq,tls_frag"`.
    pub fn from_delimited(input: &str) -> Self {
        Self(
            input
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .flat_map(expand_method_alias)
                .collect(),
        )
    }

    pub fn contains(&self, name: &str) -> bool {
        self.0.iter().any(|m| m == name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` when the list is exactly `["tls_frag"]` (socket-only relay).
    pub fn is_socket_only(&self) -> bool {
        self.0.len() == 1 && self.0[0] == "tls_frag"
    }

    /// `true` when any listed method needs the WinDivert/NFQUEUE interceptor.
    pub fn requires_interceptor(&self) -> bool {
        self.0.iter().any(|m| m != "tls_frag")
    }
}

impl fmt::Display for BypassMethodList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.join(" + "))
    }
}

impl PartialEq<&str> for BypassMethodList {
    fn eq(&self, other: &&str) -> bool {
        self.0.len() == 1 && self.0[0] == *other
    }
}

impl From<&str> for BypassMethodList {
    fn from(name: &str) -> Self {
        Self(expand_method_alias(name))
    }
}

impl From<String> for BypassMethodList {
    fn from(name: String) -> Self {
        Self(expand_method_alias(&name))
    }
}

impl From<Vec<String>> for BypassMethodList {
    fn from(names: Vec<String>) -> Self {
        Self(names.iter().flat_map(|n| expand_method_alias(n)).collect())
    }
}

impl<'de> serde::Deserialize<'de> for BypassMethodList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct MethodListVisitor;

        impl<'de> serde::de::Visitor<'de> for MethodListVisitor {
            type Value = BypassMethodList;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a method name string or an array of method name strings")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Self::Value::from(v))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(name) = seq.next_element::<String>()? {
                    out.extend(expand_method_alias(&name));
                }
                Ok(BypassMethodList(out))
            }
        }

        deserializer.deserialize_any(MethodListVisitor)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core config::tests`
Expected: all `parses_*`, `expands_*`, `display_*`, `socket_only_*`, `from_delimited_*`, `rejects_non_string_*` tests PASS. Other config tests still compile (field type unchanged in this task).

- [ ] **Step 5: Commit**

```bash
git add crates/zerodpi-core/src/config.rs
git commit -m "feat: add BypassMethodList config type"
```

---

### Task 2: `CompositeMethod` and `BypassMethod::name()` returning `String`

**Files:**
- Create: `crates/zerodpi-core/src/methods/composite.rs`
- Modify: `crates/zerodpi-core/src/methods/mod.rs` (trait `name()` signature, doc comment, `pub mod composite;`)
- Modify: `crates/zerodpi-core/src/methods/wrong_seq.rs`, `wrong_ack.rs`, `wrong_checksum.rs`, `wrong_md5.rs`, `wrong_timestamp.rs`, `low_ttl.rs`, `tls_record_frag.rs`, `urg_sni_split.rs`, `wrong_seq_tls_frag.rs`, `wrong_md5_tls_frag.rs`, `wrong_seq_tls_record_frag.rs`, `wrong_seq_wrong_md5.rs` (all: `name()` returns `String`)

**Interfaces:**
- Consumes: existing `BypassMethod` trait, `MethodAction` helpers, `FlowState`, `PacketView`, the base method structs (`WrongSeq::new(&Config)` etc.).
- Produces:
  - `pub struct CompositeMethod { pub handshake_methods: Vec<Box<dyn BypassMethod>>, pub data_method: Option<Box<dyn BypassMethod>>, pub segments_first_client_hello: bool }`
  - `CompositeMethod::new(handshake_methods, data_method, segments_first_client_hello) -> Self`
  - `BypassMethod::name(&self) -> String` (trait change; composite joins member names with `" + "`).

- [ ] **Step 1: Change the trait `name()` signature and all impls**

In `crates/zerodpi-core/src/methods/mod.rs`, change the trait:

```rust
/// Human-readable identifier (matches the `BYPASS_METHOD` config value, or a
/// `" + "`-joined list for a composite).
fn name(&self) -> String;
```

In each of the 12 method files listed above, change `fn name(&self) -> &'static str { "wrong_seq" }` to `fn name(&self) -> String { "wrong_seq".into() }` (same for each method's own name string). Also update the trait doc in `mod.rs` lines 12-20 (the `on_handshake_complete_ack` hook list) to mention that the composite runs members in order.

Run: `cargo test -p zerodpi-core` — the existing `methods::tests` compile (String vs `&str` compares fine in `assert_eq!`) and pass.

- [ ] **Step 2: Write the failing composite tests**

Create `crates/zerodpi-core/src/methods/composite.rs` with the implementation stub (struct + `new`) and these tests in `mod tests` (fixture pattern copied from `wrong_seq_tls_frag.rs` tests):

```rust
#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::flow::FlowState;
    use crate::interceptor::{Direction, PacketView, TcpFlags};
    use crate::methods::low_ttl::LowTtl;
    use crate::methods::tls_record_frag::TlsRecordFrag;
    use crate::methods::wrong_checksum::WrongChecksum;
    use crate::methods::wrong_md5::{tcp_md5_signature_option, WrongMd5};
    use crate::methods::wrong_seq::WrongSeq;
    use crate::methods::wrong_timestamp::WrongTimestamp;

    fn cfg_with(toml_extra: &str) -> Config {
        toml::from_str(&format!(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "wrong_seq_tls_frag"
               {toml_extra}"#
        ))
        .unwrap()
    }

    fn pkt(payload: &'static [u8], payload_len: usize) -> PacketView<'static> {
        PacketView {
            direction: Direction::Outbound,
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(1, 2, 3, 4),
            src_port: 12345,
            dst_port: 443,
            seq: 1001,
            ack: 5001,
            flags: TcpFlags {
                ack: true,
                psh: payload_len > 0,
                ..Default::default()
            },
            payload_len,
            payload,
            tcp_options: &[],
            new_seq: None,
            new_ack: None,
            new_flags: None,
            new_payload: None,
            replace_tcp_options: None,
            append_tcp_options: Vec::new(),
            bump_ipv4_ident: false,
            corrupt_tcp_checksum_delta: None,
            new_ipv4_ttl: None,
            new_urgent_pointer: None,
        }
    }

    fn handshake_state() -> FlowState {
        let mut state = FlowState::new(vec![0xAB; 517]);
        state.syn_seq = Some(1000);
        state.syn_ack_seq = Some(5000);
        state
    }

    #[test]
    fn name_joins_members_with_plus() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(
            vec![
                Box::new(WrongSeq::new(&cfg)),
                Box::new(LowTtl::new(&cfg)),
            ],
            None,
            true,
        );
        assert_eq!(m.name(), "wrong_seq + low_ttl + tls_frag");
    }

    #[test]
    fn wrong_seq_plus_tls_frag_matches_old_combo() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(vec![Box::new(WrongSeq::new(&cfg))], None, true);

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_data());
        assert_eq!(packet.new_payload.as_ref().unwrap().len(), 517);
        assert_eq!(packet.new_seq, Some(1001u32.wrapping_sub(517)));
        assert!(packet.new_flags.unwrap().psh);
        assert!(packet.bump_ipv4_ident);

        let payload: &'static [u8] = &[0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03];
        let mut packet = pkt(payload, payload.len());
        let action = m.on_first_data_packet(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::complete_and_accept());
        assert!(packet.new_payload.is_none());
    }

    #[test]
    fn wrong_seq_plus_wrong_md5_uses_first_psh_and_last_action() {
        let cfg = cfg_with("WRONG_MD5_SET_PSH = false");
        let m = CompositeMethod::new(
            vec![Box::new(WrongSeq::new(&cfg)), Box::new(WrongMd5::new(&cfg))],
            None,
            false,
        );

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert_eq!(packet.new_seq, Some(1001u32.wrapping_sub(517)));
        assert!(packet.new_flags.unwrap().psh); // PSH from wrong_seq (first), not wrong_md5
        assert_eq!(packet.append_tcp_options, tcp_md5_signature_option());
    }

    #[test]
    fn wrong_seq_plus_wrong_md5_completes_immediately_when_last_says_so() {
        let cfg = cfg_with("WRONG_MD5_COMPLETE_IMMEDIATELY = true");
        let m = CompositeMethod::new(
            vec![Box::new(WrongSeq::new(&cfg)), Box::new(WrongMd5::new(&cfg))],
            None,
            false,
        );

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_complete());
    }

    #[test]
    fn wrong_seq_plus_low_ttl_stages_both_twists_on_one_packet() {
        let cfg = cfg_with("LOW_TTL_VALUE = 5");
        let m = CompositeMethod::new(
            vec![Box::new(WrongSeq::new(&cfg)), Box::new(LowTtl::new(&cfg))],
            None,
            false,
        );

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert_eq!(packet.new_seq, Some(1001u32.wrapping_sub(517)));
        assert_eq!(packet.new_ipv4_ttl, Some(5));
        assert_eq!(packet.new_payload.as_ref().unwrap().len(), 517);
    }

    #[test]
    fn last_handshake_member_controls_action() {
        let cfg = cfg_with("WRONG_CHECKSUM_COMPLETE_IMMEDIATELY = true");
        let m = CompositeMethod::new(
            vec![Box::new(WrongChecksum::new(&cfg)), Box::new(WrongSeq::new(&cfg))],
            None,
            false,
        );
        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_ack());
        assert_eq!(packet.corrupt_tcp_checksum_delta, Some(1));
        assert_eq!(packet.new_seq, Some(1001u32.wrapping_sub(517)));

        let m = CompositeMethod::new(
            vec![Box::new(WrongSeq::new(&cfg)), Box::new(WrongChecksum::new(&cfg))],
            None,
            false,
        );
        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_complete());
    }

    #[test]
    fn abort_ignored_when_another_member_staged() {
        // wrong_timestamp aborts when the ACK has no TCP timestamp option.
        let cfg = cfg_with("");
        let m = CompositeMethod::new(
            vec![Box::new(WrongSeq::new(&cfg)), Box::new(WrongTimestamp::new(&cfg))],
            None,
            false,
        );
        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::complete_and_accept());
        assert!(packet.new_payload.is_some()); // wrong_seq's fake survived
    }

    #[test]
    fn abort_honored_when_nothing_staged() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(vec![Box::new(WrongTimestamp::new(&cfg))], None, false);
        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::abort_and_accept());
    }

    #[test]
    fn forwards_low_ttl_handle_when_present() {
        let cfg = cfg_with("");
        let with_ttl = CompositeMethod::new(vec![Box::new(LowTtl::new(&cfg))], None, false);
        assert!(with_ttl.low_ttl_handle().is_some());
        let without_ttl = CompositeMethod::new(vec![Box::new(WrongSeq::new(&cfg))], None, false);
        assert!(without_ttl.low_ttl_handle().is_none());
    }

    #[test]
    fn delegates_data_stage_to_tls_record_frag() {
        let cfg = cfg_with("");
        let m = CompositeMethod::new(vec![], Some(Box::new(TlsRecordFrag::new(&cfg))), false);

        let mut packet = pkt(&[], 0);
        let action = m.on_handshake_complete_ack(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_wait_for_data());

        let mut payload: Vec<u8> = vec![0x16, 0x03, 0x03, 0x02, 0x05];
        payload.extend(std::iter::repeat(0xAA).take(517));
        let payload: &'static [u8] = Box::leak(payload.into_boxed_slice());
        let mut packet = pkt(payload, payload.len());
        let action = m.on_first_data_packet(&handshake_state(), &mut packet);
        assert_eq!(action, MethodAction::emit_and_complete());
        assert!(packet.new_payload.is_some());
    }
}
```

Note: `Box::leak` in the test only (static lifetime needed by the fixture; tests are short-lived).

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p zerodpi-core methods::composite`
Expected: FAIL (module `composite` not found).

- [ ] **Step 4: Implement `CompositeMethod`**

Add `pub mod composite;` to `methods/mod.rs` (alphabetical: after `wrong_checksum`? — keep grouping with the existing `pub mod` list). Fill `composite.rs`:

```rust
//! Generic composition of multiple bypass methods.
//!
//! [`CompositeMethod`] runs every handshake-stage member from the configured
//! `BYPASS_METHOD` list in order, staging their mutations onto the same fake
//! packet (every injector uses the identical `flow.fake_data` payload and
//! distinct `PacketView` fields), then delegates the data stage to
//! `tls_record_frag` when present. Socket-side `tls_frag` segmentation is
//! signaled through [`CompositeMethod::segments_first_client_hello`] so the
//! proxy enables TCP-level write segmentation.
//!
//! Composition rules (provably reproduce the former hard-coded combos):
//! - PSH / IP-ident settings come from the **first** handshake-stage member.
//! - Completion behavior (`wait_for_ack` vs `complete`) comes from the
//!   **last** handshake-stage member.
//! - A member's `AbortAndAccept` is honored only when no member has staged
//!   any mutation yet; otherwise the abort is ignored.

use std::sync::atomic::AtomicU8;
use std::sync::Arc;

use tracing::trace;

use super::{BypassMethod, MethodAction};
use crate::flow::FlowState;
use crate::interceptor::PacketView;

pub struct CompositeMethod {
    pub handshake_methods: Vec<Box<dyn BypassMethod>>,
    pub data_method: Option<Box<dyn BypassMethod>>,
    pub segments_first_client_hello: bool,
}

impl CompositeMethod {
    pub fn new(
        handshake_methods: Vec<Box<dyn BypassMethod>>,
        data_method: Option<Box<dyn BypassMethod>>,
        segments_first_client_hello: bool,
    ) -> Self {
        Self {
            handshake_methods,
            data_method,
            segments_first_client_hello,
        }
    }
}

impl BypassMethod for CompositeMethod {
    fn name(&self) -> String {
        let mut parts: Vec<String> = self.handshake_methods.iter().map(|m| m.name()).collect();
        if let Some(data_method) = &self.data_method {
            parts.push(data_method.name());
        }
        if self.segments_first_client_hello {
            parts.push("tls_frag".into());
        }
        parts.join(" + ")
    }

    fn low_ttl_handle(&self) -> Option<Arc<AtomicU8>> {
        self.handshake_methods
            .iter()
            .find_map(|m| m.low_ttl_handle())
    }

    fn on_handshake_complete_ack(
        &self,
        flow: &FlowState,
        pkt: &mut PacketView<'_>,
    ) -> MethodAction {
        let mut staged_any = false;
        let mut first_flags: Option<crate::interceptor::TcpFlags> = None;
        let mut first_bump_ident = false;
        let mut last_action: Option<MethodAction> = None;

        for method in &self.handshake_methods {
            let flags_before = pkt.new_flags;
            let bump_before = pkt.bump_ipv4_ident;
            let action = method.on_handshake_complete_ack(flow, pkt);
            if matches!(action, MethodAction::EmitFakeAndAccept { .. }) {
                staged_any = true;
            }
            if flags_before.is_none() && pkt.new_flags.is_some() {
                first_flags = pkt.new_flags;
            }
            if !bump_before && pkt.bump_ipv4_ident {
                first_bump_ident = true;
            }
            last_action = Some(action);
        }

        // PSH / IP-ident come from the first handshake-stage member.
        pkt.new_flags = first_flags;
        pkt.bump_ipv4_ident = first_bump_ident;

        if self.data_method.is_some() || self.segments_first_client_hello {
            trace!(
                target = "zerodpi::composite",
                members = %self.name(),
                "staged handshake-stage mutations; waiting for data stage"
            );
            return MethodAction::emit_and_wait_for_data();
        }

        match last_action {
            Some(MethodAction::EmitFakeAndAccept {
                complete_immediately,
                ..
            }) if complete_immediately => MethodAction::emit_and_complete(),
            Some(MethodAction::EmitFakeAndAccept { .. }) => {
                MethodAction::emit_and_wait_for_ack()
            }
            Some(MethodAction::AbortAndAccept) if !staged_any => MethodAction::abort_and_accept(),
            Some(MethodAction::CompleteAndAccept) | Some(MethodAction::AbortAndAccept) => {
                MethodAction::complete_and_accept()
            }
            Some(MethodAction::PassThrough) | None => MethodAction::complete_and_accept(),
        }
    }

    fn on_first_data_packet(&self, flow: &FlowState, pkt: &mut PacketView<'_>) -> MethodAction {
        if let Some(data_method) = &self.data_method {
            data_method.on_first_data_packet(flow, pkt)
        } else {
            MethodAction::complete_and_accept()
        }
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p zerodpi-core methods::composite`
Expected: all composite tests PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/zerodpi-core/src/methods/
git commit -m "feat: add composite bypass method"
```

---

### Task 3: Switch `Config::BYPASS_METHOD` to the list across the workspace

**Files:**
- Modify: `crates/zerodpi-core/src/config.rs` (field type, `default_method`, `validate()`, doc comment, test updates)
- Modify: `crates/zerodpi-core/src/methods/mod.rs` (`build_method` → composite; delete 4 combo module declarations; test updates)
- Delete: `crates/zerodpi-core/src/methods/wrong_seq_tls_frag.rs`, `wrong_md5_tls_frag.rs`, `wrong_seq_tls_record_frag.rs`, `wrong_seq_wrong_md5.rs`
- Modify: `crates/zerodpi-core/src/handler.rs` (tests: use `build_method` instead of deleted structs)
- Modify: `crates/zerodpi-core/src/proxy.rs` (`segment_first_client_hello`, `is_socket_only` at 2 sites, delete `method_segments_first_client_hello` + its test)
- Modify: `crates/zerodpi-core/src/proxy_tester.rs` (`is_socket_only` at line 195)
- Modify: `crates/zerodpi-helper-protocol/src/lib.rs` (`MethodConfig.name` → `methods: Vec<String>`, `validate()`, `PROTOCOL_MINOR` 1→2, tests)
- Modify: `crates/zerodpi-root-helper/src/unix.rs` (line 453: build from wire `methods`)
- Modify: `crates/zerodpi/src/main.rs` (CLI flag parsing, `is_socket_only` at 2 sites, `mode_requires_packet_interception`, `LOW_TTL_DISCOVER` gate, event `.to_string()`)
- Modify: `crates/zerodpi/src/tui.rs` (2 sites: `.to_string()`), `crates/zerodpi/src/runtime_events.rs` (2 sites: `.to_string()`), `crates/zerodpi/src/helper_client.rs` (line 533: `methods`)

**Interfaces:**
- Consumes: `BypassMethodList` (Task 1), `CompositeMethod` (Task 2).
- Produces: `Config::BYPASS_METHOD: BypassMethodList`; `Config::validate()` enforcing the Global Constraints; `build_method(cfg)` returning `Option<Box<dyn BypassMethod>>` (composite or `None` for socket-only/empty); wire `MethodConfig.methods: Vec<String>`.

**Sub-step 3a — zerodpi-core (config, methods, proxy, proxy_tester, handler):**

- [ ] **Step 1: Change the `Config` field and defaults**

In `config.rs`:

```rust
    /// Bypass method(s) to use. Accepts a single method name or a TOML array
    /// of method names, e.g. `["wrong_seq", "tls_frag"]`. Combo aliases
    /// (`wrong_seq_tls_frag`, `wrong_md5_tls_frag`,
    /// `wrong_seq_tls_record_frag`, `wrong_seq_wrong_md5`) are accepted and
    /// expand to their base names. Handshake-stage methods (`wrong_seq`,
    /// `wrong_ack`, `wrong_checksum`, `wrong_md5`, `wrong_timestamp`,
    /// `low_ttl`) combine onto one fake packet; `tls_record_frag` and
    /// `tls_frag` add the data stage. Base names:
    /// ...
    #[serde(default = "default_method")]
    pub BYPASS_METHOD: BypassMethodList,
```

(replace the existing 40-line doc comment for the field with a short version pointing at the aliases, then keep the bullets). Change:

```rust
fn default_method() -> BypassMethodList {
    BypassMethodList::from("wrong_seq_tls_frag")
}
```

- [ ] **Step 2: Replace the `BYPASS_METHOD` validation block**

Replace the `if !matches!(self.BYPASS_METHOD.as_str(), ...)` block (currently config.rs lines 956-976) with:

```rust
        if self.BYPASS_METHOD.is_empty() {
            anyhow::bail!(
                "BYPASS_METHOD must not be empty; valid base methods: {:?}, aliases: \"wrong_seq_wrong_md5\", \"wrong_seq_tls_frag\", \"wrong_md5_tls_frag\", \"wrong_seq_tls_record_frag\"",
                BASE_BYPASS_METHODS
            );
        }
        {
            let mut seen = std::collections::HashSet::new();
            for method in self.BYPASS_METHOD.iter() {
                if !BASE_BYPASS_METHODS.contains(&method) {
                    anyhow::bail!(
                        "Unknown BYPASS_METHOD '{}'. Valid base methods: {:?}, aliases: \"wrong_seq_wrong_md5\", \"wrong_seq_tls_frag\", \"wrong_md5_tls_frag\", \"wrong_seq_tls_record_frag\"",
                        method, BASE_BYPASS_METHODS
                    );
                }
                if !seen.insert(method) {
                    anyhow::bail!("Duplicate BYPASS_METHOD entry '{method}'");
                }
            }
            if self.BYPASS_METHOD.contains("urg_sni_split")
                && self.BYPASS_METHOD.len() > 1
                && !self
                    .BYPASS_METHOD
                    .iter()
                    .all(|m| m == "urg_sni_split" || matches!(m, "tls_frag" | "tls_record_frag"))
            {
                anyhow::bail!(
                    "BYPASS_METHOD \"urg_sni_split\" can only be combined with \"tls_frag\" or \"tls_record_frag\""
                );
            }
        }
```

Add the `LOW_TTL_DISCOVER` rule next to the existing `LOW_TTL_*` checks:

```rust
        if self.LOW_TTL_DISCOVER && !self.BYPASS_METHOD.contains("low_ttl") {
            anyhow::bail!("LOW_TTL_DISCOVER = true requires \"low_ttl\" in BYPASS_METHOD");
        }
```

Replace the `ip_bypass_plus` exact-match check (config.rs lines 1030-1036) with:

```rust
        if self.MODE == "ip_bypass_plus"
            && !self
                .BYPASS_METHOD
                .iter()
                .all(|m| matches!(m, "tls_record_frag" | "tls_frag"))
        {
            anyhow::bail!(
                "MODE = \"ip_bypass_plus\" supports only real-SNI-preserving BYPASS_METHOD values: \"tls_record_frag\" or \"tls_frag\""
            );
        }
```

- [ ] **Step 3: Update config tests**

In `mod tests` of `config.rs`:
1. Every `assert_eq!(cfg.BYPASS_METHOD, "some_combo_alias")` must become an expanded-list assertion:
   `assert_eq!(cfg.BYPASS_METHOD.iter().collect::<Vec<_>>(), vec!["wrong_seq", "tls_frag"]);` — affected: the default-method test (currently ~line 1086) and the combo parsing tests (~lines 1644-1690).
2. Single-name assertions (`assert_eq!(cfg.BYPASS_METHOD, "wrong_checksum")` etc.) compile unchanged via `PartialEq<&str>` — leave them.
3. Add new validation tests:

```rust
#[test]
fn rejects_empty_method_list() {
    let cfg: Config = toml::from_str(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = []"#,
    )
    .unwrap();
    assert!(cfg.validate().is_err());
}

#[test]
fn rejects_duplicate_method_entries() {
    let cfg: Config = toml::from_str(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = ["wrong_seq", "wrong_seq"]"#,
    )
    .unwrap();
    assert!(cfg.validate().is_err());
}

#[test]
fn rejects_duplicate_method_via_alias_expansion() {
    let cfg: Config = toml::from_str(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = ["wrong_seq_tls_frag", "wrong_seq"]"#,
    )
    .unwrap();
    assert!(cfg.validate().is_err());
}

#[test]
fn rejects_urg_sni_split_with_handshake_method() {
    let cfg: Config = toml::from_str(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = ["urg_sni_split", "wrong_seq"]"#,
    )
    .unwrap();
    assert!(cfg.validate().is_err());
}

#[test]
fn accepts_urg_sni_split_with_data_stage() {
    let cfg: Config = toml::from_str(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = ["urg_sni_split", "tls_frag"]"#,
    )
    .unwrap();
    cfg.validate().unwrap();
}

#[test]
fn accepts_handshake_and_data_stage_combination() {
    let cfg: Config = toml::from_str(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = ["wrong_seq", "low_ttl", "tls_frag"]"#,
    )
    .unwrap();
    cfg.validate().unwrap();
}

#[test]
fn rejects_low_ttl_discover_without_low_ttl_method() {
    let cfg: Config = toml::from_str(
        r#"LISTEN_HOST = "127.0.0.1"
           LISTEN_PORT = 44444
           BYPASS_METHOD = "wrong_seq"
           LOW_TTL_DISCOVER = true"#,
    )
    .unwrap();
    assert!(cfg.validate().is_err());
}
```

4. Fix any existing test that sets `LOW_TTL_DISCOVER = true` with a non-`low_ttl` method by changing it to `LOW_TTL_DISCOVER = false` (or the method to `"low_ttl"`).

- [ ] **Step 4: Rewrite `build_method` in `methods/mod.rs`**

Replace the whole `build_method` function and its doc comment:

```rust
/// Build the interceptor-based method chain from the application config.
///
/// Returns `Some(method)` when the configured list contains any
/// interceptor-based method (`wrong_seq`, `wrong_ack`, `wrong_checksum`,
/// `wrong_md5`, `wrong_timestamp`, `low_ttl`, `urg_sni_split`,
/// `tls_record_frag`) and `None` for socket-only lists (`["tls_frag"]`) or
/// empty lists. Callers should validate the method list via
/// [`crate::config::Config::validate`] before calling this function.
pub fn build_method(cfg: &Config) -> Option<Box<dyn BypassMethod>> {
    let list = &cfg.BYPASS_METHOD;
    if list.is_empty() || list.is_socket_only() {
        return None;
    }
    let mut handshake: Vec<Box<dyn BypassMethod>> = Vec::new();
    let mut data: Option<Box<dyn BypassMethod>> = None;
    for name in list.iter() {
        match name {
            "tls_frag" => {} // socket side; handled directly in proxy.rs
            "tls_record_frag" => data = Some(Box::new(tls_record_frag::TlsRecordFrag::new(cfg))),
            "wrong_seq" => handshake.push(Box::new(wrong_seq::WrongSeq::new(cfg))),
            "wrong_ack" => handshake.push(Box::new(wrong_ack::WrongAck::new(cfg))),
            "wrong_checksum" => handshake.push(Box::new(wrong_checksum::WrongChecksum::new(cfg))),
            "wrong_md5" => handshake.push(Box::new(wrong_md5::WrongMd5::new(cfg))),
            "wrong_timestamp" => handshake.push(Box::new(wrong_timestamp::WrongTimestamp::new(cfg))),
            "low_ttl" => handshake.push(Box::new(low_ttl::LowTtl::new(cfg))),
            "urg_sni_split" => handshake.push(Box::new(urg_sni_split::UrgSniSplit::new(cfg))),
            _ => return None,
        }
    }
    Some(Box::new(composite::CompositeMethod::new(
        handshake,
        data,
        list.contains("tls_frag"),
    )))
}
```

- [ ] **Step 5: Delete the four combo files and update `mod.rs`**

Delete `methods/wrong_seq_tls_frag.rs`, `wrong_md5_tls_frag.rs`, `wrong_seq_tls_record_frag.rs`, `wrong_seq_wrong_md5.rs` and remove their `pub mod` declarations from `mod.rs`. `tcp_md5_signature_option()` already lives in `wrong_md5.rs` — no move needed.

Update `methods/mod.rs` tests:
- The combo build tests now assert composite names: `assert_eq!(method.name(), "wrong_seq + tls_frag")` (was `"wrong_seq_tls_frag"`), and similarly `"wrong_md5 + tls_frag"`, `"wrong_seq + tls_record_frag"`, `"wrong_seq + wrong_md5"`.
- `socket_method_returns_none` stays as-is.
- Add:

```rust
#[test]
fn builds_composite_for_list() {
    let cfg = cfg_with_method(r#"BYPASS_METHOD = ["wrong_seq", "low_ttl"]"#);
    let method = build_method(&cfg).unwrap();
    assert_eq!(method.name(), "wrong_seq + low_ttl");
}

#[test]
fn socket_list_returns_none() {
    let cfg = cfg_with_method(r#"BYPASS_METHOD = ["tls_frag"]"#);
    assert!(build_method(&cfg).is_none());
}
```

Change the existing `cfg_with_method` helper in `mod tests` so it takes the **full method line** instead of the method name:

```rust
    fn cfg_with_method(method_line: &str) -> Config {
        toml::from_str(&format!(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               {method_line}"#
        ))
        .unwrap()
    }
```

(All existing `cfg_with_method("wrong_checksum")` call sites must become `cfg_with_method(r#"BYPASS_METHOD = "wrong_checksum""#)`.)

- [ ] **Step 6: Update `handler.rs` tests**

Replace direct combo struct constructions with `build_method`:
- Line ~698: `let mut h = Handler::new(flows, Arc::new(WrongSeqWrongMd5::new(&cfg)));` → `let mut h = Handler::new(flows, Arc::from(build_method(&cfg).unwrap()));`
- Line ~1124 (`WrongSeqTlsFrag`), and the analogous `WrongMd5TlsFrag` / `WrongSeqTlsRecordFrag` constructions (~lines 1217, 1311): same replacement.
- Remove the now-unused `use crate::methods::wrong_seq_wrong_md5::WrongSeqWrongMd5;`-style imports from the test module and add `use crate::methods::build_method;` if not already imported.
- Run `cargo test -p zerodpi-core handler` — tests that set `cfg.BYPASS_METHOD = "wrong_seq_wrong_md5".into()` still work: the `.into()` picks `From<&str>`, the alias expands, and `build_method` builds the equivalent composite.

- [ ] **Step 7: Update `proxy.rs` and `proxy_tester.rs`**

In `proxy.rs`:
- Line 157: `segment_first_client_hello: method_segments_first_client_hello(&cfg.BYPASS_METHOD),` → `segment_first_client_hello: cfg.BYPASS_METHOD.contains("tls_frag"),`
- Delete `method_segments_first_client_hello` (lines 321-323) and its test `combo_tls_frag_methods_segment_first_client_hello` (lines 1438-1447); replace with:

```rust
    #[test]
    fn tls_frag_in_list_segments_first_client_hello() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["wrong_seq", "tls_frag"]"#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(settings.segment_first_client_hello);

        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = "wrong_seq_tls_record_frag""#,
        )
        .unwrap();
        let settings = ConnectionSettings::from_config(&cfg);
        assert!(!settings.segment_first_client_hello);
    }
```

- Lines 474 and 792: `if cfg.BYPASS_METHOD == "tls_frag" {` → `if cfg.BYPASS_METHOD.is_socket_only() {` (keep the surrounding comments accurate: "Route to the socket-based path for a socket-only method list.").
- Line 765 `method = %cfg.BYPASS_METHOD` needs no change (Display works).

In `proxy_tester.rs` line 195: `if config.BYPASS_METHOD == "tls_frag" {` → `if config.BYPASS_METHOD.is_socket_only() {`.

- [ ] **Step 8: Verify zerodpi-core compiles and tests pass**

Run: `cargo test -p zerodpi-core`
Expected: PASS (config, composite, handler, proxy, methods tests all green).

**Sub-step 3b — helper protocol + root helper:**

- [ ] **Step 9: Update `zerodpi-helper-protocol`**

In `crates/zerodpi-helper-protocol/src/lib.rs`:
- Line 15: `pub const PROTOCOL_MINOR: u16 = 1;` → `pub const PROTOCOL_MINOR: u16 = 2;` (wire layout of `MethodConfig` changes).
- `MethodConfig` (lines 111-139): replace `pub name: String,` with `pub methods: Vec<String>,`.
- `MethodConfig::validate` (lines 141-158): replace the `SUPPORTED` const and name check with:

```rust
        const SUPPORTED: &[&str] = &[
            "wrong_seq",
            "wrong_ack",
            "wrong_checksum",
            "wrong_md5",
            "wrong_timestamp",
            "low_ttl",
            "tls_record_frag",
            "tls_frag",
            "urg_sni_split",
        ];
        if self.methods.is_empty() || self.methods.iter().any(|m| !SUPPORTED.contains(&m.as_str()))
        {
            return Err(ProtocolError::InvalidField("method names"));
        }
```

- Test helper `method()` (line 524-553): `name: "wrong_seq".into(),` → `methods: vec!["wrong_seq".into()],`.
- Any other tests referencing `MethodConfig { name: ... }` or combo names in `SUPPORTED` — update to the 9 base names. (Search the crate for `name:` and `wrong_seq_tls_frag`.)
- Run: `cargo test -p zerodpi-helper-protocol` — PASS.

- [ ] **Step 10: Update `zerodpi-root-helper`**

In `crates/zerodpi-root-helper/src/unix.rs` line 453:
`cfg.BYPASS_METHOD = wire.name.clone();` → `cfg.BYPASS_METHOD = wire.methods.clone().into();`

Run: `cargo test -p zerodpi-root-helper` (or at least `cargo check -p zerodpi-root-helper`) — PASS/OK.

**Sub-step 3c — zerodpi app crate:**

- [ ] **Step 11: Update `main.rs`**

- Import: add `use zerodpi_core::config::BypassMethodList;` next to the existing `Config` import.
- CLI help (line 119): `/// Override `BYPASS_METHOD` — a single method or a comma-separated list (e.g. `wrong_seq,tls_frag`).`
- Lines 244-246:

```rust
    if let Some(v) = args.method {
        cfg.BYPASS_METHOD = BypassMethodList::from_delimited(&v);
    }
```

- Lines 469 and 1798: `if cfg.BYPASS_METHOD == "tls_frag" {` → `if cfg.BYPASS_METHOD.is_socket_only() {`
- Line 532: `if cfg.LOW_TTL_DISCOVER && cfg.BYPASS_METHOD == "low_ttl" {` → `if cfg.LOW_TTL_DISCOVER {` (validate() already enforces `low_ttl` presence; keep the existing `LOW_TTL_COMPLETE_IMMEDIATELY` warning below it).
- Lines 1105-1111:

```rust
fn requires_packet_interception(cfg: &Config) -> bool {
    mode_requires_packet_interception(&cfg.MODE, &cfg.BYPASS_METHOD)
}

fn mode_requires_packet_interception(mode: &str, bypass_method: &BypassMethodList) -> bool {
    matches!(mode, "sni_spoof" | "proxy_scan" | "ip_bypass_plus")
        && !bypass_method.is_socket_only()
}
```

- Lines 298 and 309: `bypass_method: cfg.BYPASS_METHOD.clone(),` → `bypass_method: cfg.BYPASS_METHOD.to_string(),`
- `root_required_message` (line 1167-1172): the `{}` on `cfg.BYPASS_METHOD` renders the `" + "`-joined display — no change needed.
- `build_method` error contexts (lines 492, 1816) keep working (`{}` displays the list).

- [ ] **Step 12: Update `tui.rs`, `runtime_events.rs`, `helper_client.rs`**

- `tui.rs` lines 1128 and 1167: `cfg.BYPASS_METHOD.clone()` → `cfg.BYPASS_METHOD.to_string()`.
- `runtime_events.rs` — no field type change (they are `String`); the `.to_string()` in main.rs feeds them.
- `helper_client.rs` line 533: `name: cfg.BYPASS_METHOD.clone(),` → `methods: cfg.BYPASS_METHOD.as_slice().to_vec(),`

- [ ] **Step 13: Full workspace check**

Run: `cargo test --workspace`
Expected: PASS across all crates.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings.

Run: `cargo fmt --all` then `cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 14: Commit**

```bash
git add -A
git commit -m "feat: support BYPASS_METHOD as a composable method list"
```

---

### Task 4: Document the list syntax and combination limits

**Files:**
- Modify: `config.toml` (lines 152-268, the `BYPASS_METHOD` comment block)
- Modify: `README.md` (line 55 badge text, bypass methods table lines 323-337, detail bullets 359-367, config table row ~602, one recipe example)

**Interfaces:** Consumes: final behavior from Task 3. Produces: user-facing documentation of the limits (Global Constraints).

- [ ] **Step 1: Rewrite the `BYPASS_METHOD` comment block in `config.toml`**

Replace lines 152-268 with:

```toml
# Bypass method(s) to use for SNI-spoof mode.
#
# Accepts a single method name or a list of method names, e.g.:
#
#   BYPASS_METHOD = "wrong_seq"
#   BYPASS_METHOD = ["wrong_seq", "tls_frag"]
#
# Base methods:
#
#   "wrong_seq"
#     Waits for the first outbound TCP ACK after the SYN/SYN-ACK exchange,
#     then injects a fake TLS ClientHello on that packet with a deliberately
#     old TCP sequence number.  DPI devices inspect the payload using the
#     allowed SNI; the real upstream server treats the segment as old/duplicate
#     and discards its payload, so the real TLS handshake proceeds unaffected.
#
#   "wrong_checksum"
#     Waits for the first outbound TCP ACK after the SYN/SYN-ACK exchange,
#     then injects a fake TLS ClientHello on that packet with the normal valid
#     TCP sequence number and ACK number.  ZeroDPI computes normal IPv4/TCP
#     checksums first, then deliberately corrupts the TCP checksum.  DPI
#     devices can inspect the payload using the allowed SNI, while the real
#     upstream server drops the invalid-checksum segment before consuming data.
#
#   "wrong_md5"
#     Waits for the first outbound TCP ACK after the SYN/SYN-ACK exchange,
#     then injects a fake TLS ClientHello on that packet with the normal valid
#     TCP sequence number and ACK number plus a TCP-MD5 Signature option.  DPI
#     devices can inspect the payload using the allowed SNI, while the real
#     upstream server rejects the segment because no TCP-MD5 key was negotiated.
#
#   "wrong_ack"
#     Waits for the first outbound TCP ACK after the SYN/SYN-ACK exchange,
#     then injects a fake TLS ClientHello on that packet with the normal valid
#     TCP sequence number and a deliberately old TCP ACK number.  DPI devices
#     can inspect the payload using the allowed SNI, while the real upstream
#     server rejects the segment because its ACK is before the server send
#     window.
#
#   "wrong_timestamp"
#     Waits for the first outbound TCP ACK after the SYN/SYN-ACK exchange,
#     then injects a fake TLS ClientHello on that packet with the normal valid
#     TCP sequence and ACK numbers but a backdated TCP Timestamp TSval.  DPI
#     devices can inspect the payload using the allowed SNI, while the real
#     upstream server rejects the segment as a PAWS replay.
#
#   "low_ttl"
#     TTL-Based Decoy Injection.  Waits for the first outbound TCP ACK after
#     the SYN/SYN-ACK exchange, then injects a fake TLS ClientHello carrying
#     the selected whitelisted SNI on that packet with the normal valid TCP
#     sequence/ACK numbers and a valid checksum, but stamps the IP packet with
#     the LOW_TTL_VALUE.  The TTL is tuned so the decoy reaches an inline DPI
#     middlebox (typically 4-8 hops from the client) but expires before the
#     destination server, so the server never sees the fake payload.  The real
#     handshake still completes because the kernel retransmits the bare ACK.
#     Works best when the DPI is physically closer to the client than the
#     destination server; use "traceroute" or similar to find the middlebox
#     distance and adjust LOW_TTL_VALUE accordingly.
#
#   "tls_record_frag"
#     TLS Record Fragment / TLS-layer fragmentation.  Does NOT inject any fake
#     packet.  Instead, it intercepts the first outbound data packet carrying
#     the real TLS ClientHello, splits the TLS record body, and re-wraps those
#     chunks as multiple small TLS records.  DPI engines that cannot reassemble
#     TLS records across fragment boundaries will fail to extract the SNI.  The
#     upstream TLS server reassembles the fragments normally.
#
#   "urg_sni_split"
#     TCP Urgent + SNI byte splice.  Does NOT inject any fake packet.  Instead,
#     it intercepts the first outbound data packet carrying the real TLS
#     ClientHello, splices a single dummy byte (SNI_SPLIT_DUMMY_BYTE) into the
#     middle of the SNI domain string (at SNI_SPLIT_POSITION), and sets the TCP
#     URG flag with the urgent pointer marking the dummy byte.  BSD-style
#     destination stacks extract the urgent byte from the stream, so the server
#     still receives the original ClientHello; DPI middleboxes that read the
#     raw byte stream sequentially see a mangled SNI instead.
#
#   "tls_frag"
#     TLS Fragment / TCP-level fragmentation.  Does NOT inject fake packets
#     and does NOT use WinDivert or NFQUEUE packet interception.  Instead, it
#     fragments the first TLS ClientHello record or a configured range of
#     client-to-upstream data writes using TLS_FRAG_PACKETS, TLS_FRAG_LENGTH,
#     and TLS_FRAG_INTERVAL_MS.  With TCP_NODELAY enabled, the OS is less
#     likely to coalesce small writes, so no single packet carries the full
#     SNI.  The upstream server reassembles the stream normally.
#
# Combo aliases (equivalent to their expanded lists, kept for compatibility):
#
#   "wrong_seq_wrong_md5"        -> ["wrong_seq", "wrong_md5"]
#   "wrong_seq_tls_frag"         -> ["wrong_seq", "tls_frag"]          (default)
#   "wrong_md5_tls_frag"         -> ["wrong_md5", "tls_frag"]
#   "wrong_seq_tls_record_frag"  -> ["wrong_seq", "tls_record_frag"]
#
# Combining methods:
#
# - Handshake-stage methods (wrong_seq, wrong_ack, wrong_checksum, wrong_md5,
#   wrong_timestamp, low_ttl) all inject the same fake ClientHello; when
#   several are listed they merge their tricks onto that one fake packet.
#   PSH / IPv4-Identification behavior comes from the first listed method;
#   completion behavior comes from the last listed method.
# - "tls_record_frag" and/or "tls_frag" add the data stage after the fake
#   packet: TLS-record fragmentation inside the interceptor and TCP-level
#   write segmentation inside the proxy respectively.  A list containing
#   "tls_frag" alongside other methods still uses packet interception.
# - A list of exactly ["tls_frag"] skips the packet interceptor entirely.
#
# Limitations:
#
# - The list must not be empty and must not contain duplicate method names
#   (after alias expansion).
# - "urg_sni_split" can only be used alone or together with "tls_frag" /
#   "tls_record_frag"; it cannot be combined with other handshake-stage
#   methods.
# - MODE = "ip_bypass_plus" supports only "tls_record_frag" or "tls_frag" so
#   the upstream VPN client's real SNI is preserved.
# - LOW_TTL_DISCOVER = true requires "low_ttl" in the list.
#
# This setting is used by SNI-based modes ("sni_spoof", "sni_scan", and
# "proxy_scan").  The "ip_bypass" and "ip_scan" modes do not use a bypass
# method.
BYPASS_METHOD = "wrong_seq_tls_frag"
```

- [ ] **Step 2: Update `README.md`**

1. Line 55 (badge): `| 🧩 **13 bypass methods** | \`wrong_seq\`, ... |` → `| 🧩 **9 combinable bypass methods** | \`wrong_seq\`, \`wrong_ack\`, \`wrong_checksum\`, \`wrong_md5\`, \`wrong_timestamp\`, \`low_ttl\`, \`tls_record_frag\`, \`tls_frag\`, \`urg_sni_split\` — combinable via \`BYPASS_METHOD = [...]\` |`
2. Bypass-methods table (lines 323-337): change the three combo rows to alias rows:
   - `| \`wrong_seq_wrong_md5\` | Alias for \`["wrong_seq", "wrong_md5"]\` — one fake ClientHello with an old TCP sequence number and a TCP-MD5 option | ✅ Yes | ... |` (keep existing mechanism/best-for text, prepend "Alias for ... —").
   - Same pattern for `wrong_seq_tls_frag` and `wrong_md5_tls_frag` and `wrong_seq_tls_record_frag`.
3. Add a "Combining Bypass Methods" subsection right after the table (before "Choosing a Bypass Method"), containing the limits verbatim from Global Constraints, plus: `BYPASS_METHOD = ["wrong_seq", "low_ttl"]` example; note that list order matters for PSH/IP-ident (first) and completion (last); `["tls_frag"]` alone skips interception.
4. Line 367 bullet: "The combo methods such as ..." → "The combo names such as \`wrong_seq_tls_frag\` are compatibility aliases for method lists, e.g. \`BYPASS_METHOD = ["wrong_seq", "tls_frag"]\`."
5. Config table row (~line 602): `\`BYPASS_METHOD\` | \`string\` | \`"wrong_seq_tls_frag"\` | ...` → `\`BYPASS_METHOD\` | \`string or array of strings\` | \`"wrong_seq_tls_frag"\` | one or more of \`wrong_seq\`, \`wrong_checksum\`, \`wrong_md5\`, \`wrong_seq_wrong_md5\`, \`wrong_ack\`, \`wrong_timestamp\`, \`low_ttl\`, \`tls_record_frag\`, \`wrong_seq_tls_frag\`, \`wrong_md5_tls_frag\`, \`wrong_seq_tls_record_frag\`, \`tls_frag\`, \`urg_sni_split\` — aliases expand; see "Combining Bypass Methods" for limits; \`ip_bypass_plus\` allows only \`tls_record_frag\` or \`tls_frag\` |`
6. In one recipe (e.g. "Default SNI Spoofing" ~line 384), keep the alias value and add a comment line above it showing the equivalent list: `# BYPASS_METHOD = ["wrong_seq", "tls_frag"]  # same as the alias below`.

- [ ] **Step 3: Touch up `zerodpi-platform` doc comments**

In `crates/zerodpi-platform/src/lib.rs` lines 84-105, the mentions of `BYPASS_METHOD = "tls_frag"` are still valid single-string syntax; leave them, but add one sentence where the module doc explains bypass methods:

```text
     `BYPASS_METHOD` also accepts a list of methods, e.g.
     `BYPASS_METHOD = ["wrong_seq", "tls_frag"]`; see zerodpi-core config docs.
```

- [ ] **Step 4: Verify**

Run: `cargo test --workspace` (docs-only change; ensure nothing else broke) — PASS.
Read the new `config.toml` block once for accuracy against `BASE_BYPASS_METHODS` and the alias table.

- [ ] **Step 5: Commit**

```bash
git add config.toml README.md crates/zerodpi-platform/src/lib.rs
git commit -m "docs: document BYPASS_METHOD list syntax and combination limits"
```

---

### Task 5: Final verification gate

**Files:** none (verification only; fix anything that fails).

- [ ] **Step 1: Format**

Run: `cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 2: Lint**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 3: Tests**

Run: `cargo test --workspace`
Expected: all pass.

- [ ] **Step 4: Release build**

Run: `cargo build --workspace --release`
Expected: builds.

- [ ] **Step 5: Behavior spot-check**

Run: `cargo run --bin zerodpi -- --help` — confirm `--method` help shows the comma-separated list form.
Run: `cargo run --bin zerodpi -- --config ./config.toml --no-tui` for a few seconds if the environment allows (may need Administrator; skip if it errors on privileges) — confirm startup logs print the method list (e.g. `wrong_seq + tls_frag`).
