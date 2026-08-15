//! Configuration loaded from `config.toml`.

use std::fmt;
use std::path::Path;

use serde::de;
use serde::{Deserialize, Serialize};

use crate::interceptor::LinuxFirewallBackend;
use crate::methods::tls_padding::PaddingPosition;
use crate::tls_template::MAX_SNI_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Int32Range {
    pub min: i32,
    pub max: i32,
}

impl Int32Range {
    pub const fn exact(value: i32) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("range cannot be empty".into());
        }

        if let Some((start, end)) = input.split_once('-') {
            let min = parse_i32(start.trim())?;
            let max = parse_i32(end.trim())?;
            if max < min {
                return Err(format!("range '{input}' has max lower than min"));
            }
            Ok(Self { min, max })
        } else {
            Ok(Self::exact(parse_i32(input)?))
        }
    }

    pub fn validate_at_least(&self, field: &str, min_value: i32) -> anyhow::Result<()> {
        if self.min < min_value {
            anyhow::bail!("{field} must be >= {min_value}");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for Int32Range {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Int(i32),
            Text(String),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Int(value) => Ok(Self::exact(value)),
            Repr::Text(value) => Self::parse(&value).map_err(de::Error::custom),
        }
    }
}

fn parse_i32(value: &str) -> Result<i32, String> {
    value
        .parse::<i32>()
        .map_err(|_| format!("'{value}' is not a valid Int32 value"))
}

impl fmt::Display for Int32Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.min == self.max {
            write!(f, "{}", self.min)
        } else {
            write!(f, "{}-{}", self.min, self.max)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFragPackets {
    TlsHello,
    WriteRange { start: u32, end: u32 },
}

impl TlsFragPackets {
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.eq_ignore_ascii_case("tlshello") {
            return Ok(Self::TlsHello);
        }

        let parse_packet_index = |value: &str| -> Result<u32, String> {
            let parsed = value
                .trim()
                .parse::<u32>()
                .map_err(|_| format!("'{value}' is not a valid packet index"))?;
            if parsed == 0 {
                return Err("packet indexes are 1-based and must be >= 1".into());
            }
            Ok(parsed)
        };

        let (start, end) = if let Some((start, end)) = input.split_once('-') {
            (parse_packet_index(start)?, parse_packet_index(end)?)
        } else {
            let index = parse_packet_index(input)?;
            (index, index)
        };

        if end < start {
            return Err(format!("packet range '{input}' has end lower than start"));
        }

        Ok(Self::WriteRange { start, end })
    }

    pub fn includes_write(self, write_index: u32) -> bool {
        match self {
            Self::TlsHello => false,
            Self::WriteRange { start, end } => (start..=end).contains(&write_index),
        }
    }
}

/// Where inside the SNI domain string `urg_sni_split` inserts its dummy byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniSplitPosition {
    /// Exact middle of the name (`len / 2`).
    Middle,
    /// Before the first name byte.
    Start,
    /// Before the last name byte.
    End,
    /// 0-based index, clamped to `[0, len - 1]`.
    Index(u16),
}

impl<'de> Deserialize<'de> for SniSplitPosition {
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
                "middle" => Ok(Self::Middle),
                "start" => Ok(Self::Start),
                "end" => Ok(Self::End),
                _ => Err(de::Error::custom(format!(
                    "'{value}' is not a valid SNI_SPLIT_POSITION; valid values: \"middle\", \"start\", \"end\", or an integer"
                ))),
            },
        }
    }
}

impl Serialize for SniSplitPosition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Middle => serializer.serialize_str("middle"),
            Self::Start => serializer.serialize_str("start"),
            Self::End => serializer.serialize_str("end"),
            Self::Index(n) => serializer.serialize_u16(*n),
        }
    }
}

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

/// Base bypass method names that can be combined in `BYPASS_METHOD`.
pub const BASE_BYPASS_METHODS: &[&str] = &[
    "wrong_seq",
    "wrong_ack",
    "wrong_checksum",
    "wrong_md5",
    "wrong_timestamp",
    "low_ttl",
    "tls_record_frag",
    "fake_tls",
    "tls_frag",
    "tls_padding",
    "mixed_case_sni",
    "urg_sni_split",
    "sni_boundary_frag",
];

/// Expand a combo alias into its base method names; other names pass through.
fn expand_method_alias(name: &str) -> Vec<String> {
    match name {
        "wrong_seq_wrong_md5" => vec!["wrong_seq".to_owned(), "wrong_md5".to_owned()],
        "wrong_seq_tls_frag" => vec!["wrong_seq".to_owned(), "tls_frag".to_owned()],
        "wrong_md5_tls_frag" => vec!["wrong_md5".to_owned(), "tls_frag".to_owned()],
        "wrong_seq_tls_record_frag" => {
            vec!["wrong_seq".to_owned(), "tls_record_frag".to_owned()]
        }
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

impl serde::Serialize for BypassMethodList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0.len() == 1 {
            serializer.serialize_str(&self.0[0])
        } else {
            serializer.collect_seq(self.0.iter())
        }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Config {
    /// Local address the proxy listens on (e.g. `0.0.0.0` or `127.0.0.1`).
    pub LISTEN_HOST: String,

    /// Local port the proxy listens on.
    pub LISTEN_PORT: u16,

    /// Path to the SNI list file (one hostname per line).
    /// Relative paths are resolved from the directory that contains `config.toml`.
    #[serde(default = "default_sni_list")]
    pub SNI_LIST: String,

    /// Whether SNI hostnames should be resolved through `CUSTOM_DNS_SERVER`
    /// instead of the operating system resolver. Default: `false`.
    #[serde(default)]
    pub CUSTOM_DNS_ENABLED: bool,

    /// Plain DNS server used when `CUSTOM_DNS_ENABLED` is true.
    /// Accepts a literal IPv4 or IPv6 address with an optional port; when the
    /// port is omitted, port 53 is used.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub CUSTOM_DNS_SERVER: Option<String>,

    /// Per-probe timeout in seconds.
    /// Each (SNI, IP) combination is given this many seconds to complete all
    /// checks (DNS, TCP connect, TLS handshake, HTTP request).
    #[serde(default = "default_scan_timeout")]
    pub SCAN_TIMEOUT_SECS: u64,

    /// When `true` the application automatically picks the top-ranked entry
    /// after scanning instead of showing the manual selection table.
    /// TUI progress, result, and dashboard views are still shown.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub AUTO_SELECT: bool,

    /// Rescan interval in seconds.  After the proxy starts the scanner runs
    /// again in the background every this many seconds and logs the new
    /// rankings.  Set to `0` to disable periodic rescanning.  Default: `600`.
    #[serde(default = "default_rescan_interval_secs")]
    pub RESCAN_INTERVAL_SECS: u64,

    /// Minimum score required before a background SNI rescan is allowed to
    /// switch the active target. Default: `1`.
    #[serde(default = "default_sni_switch_min_score")]
    pub SNI_SWITCH_MIN_SCORE: u8,

    /// If set, skip scanning entirely and use this hostname as the SNI.
    /// The IP is resolved from DNS at startup.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub SELECTED_SNI: Option<String>,

    /// Bypass method(s) to use. Accepts a single method name or a TOML array
    /// of method names, e.g. `["wrong_seq", "tls_frag"]`. Combo aliases
    /// (`wrong_seq_wrong_md5`, `wrong_seq_tls_frag`, `wrong_md5_tls_frag`,
    /// `wrong_seq_tls_record_frag`) are accepted and expand to their base
    /// names. Base methods:
    /// - `"wrong_seq"` — injects a fake TLS ClientHello with a
    ///   deliberately wrong TCP sequence number so DPI inspects the fake SNI
    ///   while the real server discards the out-of-window payload.
    /// - `"wrong_checksum"` — injects a fake TLS ClientHello with the normal
    ///   TCP sequence number, then corrupts the TCP checksum so DPI can inspect
    ///   the fake SNI while the real server drops the invalid segment.
    /// - `"wrong_md5"` — injects a fake TLS ClientHello with the normal TCP
    ///   sequence/acknowledgment numbers and a TCP-MD5 Signature option. DPI
    ///   can inspect the fake SNI while the real server rejects the segment
    ///   because no TCP-MD5 key was negotiated.
    /// - `"wrong_ack"` — injects a fake TLS ClientHello with the normal TCP
    ///   sequence number and a deliberately old TCP acknowledgment number so
    ///   DPI inspects the fake SNI while the real server rejects the segment.
    /// - `"wrong_timestamp"` — injects a fake TLS ClientHello with a
    ///   backdated TCP Timestamp TSval so DPI inspects the fake SNI while the
    ///   real server rejects the segment as a PAWS replay.
    /// - `"low_ttl"` — injects a fake TLS ClientHello carrying the selected
    ///   whitelisted SNI with the normal TCP sequence/acknowledgment numbers
    ///   and a valid checksum, but stamps the IP packet with a low Time-To-Live
    ///   (`LOW_TTL_VALUE`) so the decoy reaches an inline DPI middlebox yet
    ///   expires before reaching the destination server. The real handshake
    ///   completes via TCP retransmission.
    /// - `"tls_record_frag"` — TLS Record Fragment / TLS-layer fragmentation.
    ///   Splits the real ClientHello into multiple small TLS records so no
    ///   single record contains the full SNI. No fake packet is injected; the
    ///   server reassembles normally.
    /// - `"tls_frag"` — TLS Fragment / TCP-level fragmentation.
    ///   Splits a normal, intact TLS ClientHello record into multiple tiny TCP
    ///   segments so DPI cannot reassemble the SNI from any single packet.
    ///   Does **not** inject fake packets or use WinDivert/NFQUEUE interception;
    ///   operates entirely inside the proxy via controlled socket writes.
    /// - `"tls_padding"` — TLS ClientHello Padding Expansion (RFC 7685).
    ///   Inserts a padding extension (type `0x0015`) of `TLS_PADDING_SIZE`
    ///   zero bytes into the client's real ClientHello. With
    ///   `TLS_PADDING_POSITION = "before"` (default) the padding is inserted
    ///   immediately before the SNI extension, pushing the SNI past the DPI's
    ///   inspection window (typically 512–1460 bytes); `"after"` appends it
    ///   at the end of the extension list. Socket-side only: does not inject
    ///   fake packets or use WinDivert/NFQUEUE interception; operates inside
    ///   the proxy on the relayed ClientHello.
    /// - `"mixed_case_sni"` — SNI Case Randomization. Randomizes the ASCII
    ///   letter case of the hostname in the SNI extension of the client's
    ///   real ClientHello (e.g. `wikipedia.org` → `wIkIpeDiA.oRg`).
    ///   Destination servers lowercase the hostname during lookup (RFC 6066
    ///   hostnames are case-insensitive), while DPI using case-sensitive
    ///   blocklist matching misses. Socket-side only: does not inject fake
    ///   packets or use WinDivert/NFQUEUE interception; operates inside the
    ///   proxy on the relayed ClientHello.
    /// - `"urg_sni_split"` — injects a 1-byte dummy payload into the middle of
    ///   the SNI inside the real ClientHello and sets the TCP URG flag so the
    ///   destination server strips the byte while byte-scanning DPI sees a
    ///   mangled SNI. No fake packet is injected; the server reassembles the
    ///   original handshake via BSD urgent-data semantics.
    /// - `"sni_boundary_frag"` — SNI Extension Boundary Fragmentation.
    ///   Parses the ClientHello down to the SNI extension and writes the
    ///   first record as exactly two TCP segments cut at the extension
    ///   boundary (or mid-domain), separated by a configurable delay, so
    ///   inline DPI cannot reassemble the SNI. Socket-side only: does not
    ///   inject fake packets or use WinDivert/NFQUEUE interception; operates
    ///   inside the proxy on the relayed ClientHello.
    ///
    /// Handshake-stage methods (`wrong_seq`, `wrong_ack`, `wrong_checksum`,
    /// `wrong_md5`, `wrong_timestamp`, `low_ttl`) all inject the same fake
    /// ClientHello; several may be listed to merge their tricks onto one fake
    /// packet. `tls_record_frag`, `tls_frag`, `tls_padding`,
    /// `mixed_case_sni`, and `sni_boundary_frag` add the data stage. See the
    /// `BYPASS_METHOD` section of `config.toml` for the combination limits.
    #[serde(default = "default_method")]
    pub BYPASS_METHOD: BypassMethodList,
    /// (Linux only) NFQUEUE queue number used to intercept packets. Must
    /// match the queue number in the firewall rules installed by ZeroDPI.
    /// Default: `1`.
    #[serde(default = "default_queue_num")]
    pub NFQUEUE_NUM: u16,

    /// (Linux only) Firewall rule backend used to route matching packets into
    /// NFQUEUE. Supported values:
    /// - `"iptables"` (default) — preserve legacy iptables behavior.
    /// - `"nftables"` — use the `nft` command and an `inet` table.
    #[serde(default = "default_linux_firewall_backend")]
    pub LINUX_FIREWALL_BACKEND: String,

    // -----------------------------------------------------------------------
    // wrong_seq method parameters
    // -----------------------------------------------------------------------
    /// Extra bytes subtracted from the injected TCP sequence number on top of
    /// the payload length. Used by `wrong_seq`, `wrong_seq_wrong_md5`, and
    /// wrong-sequence combo methods. The default formula positions the spoofed
    /// segment exactly at `syn_seq + 1 - payload_len`; adding an extra offset
    /// pushes it further behind `rcv_nxt` and can help on networks that
    /// perform tighter window checks.
    /// Must be `<= u32::MAX`.  Default: `0`.
    #[serde(default)]
    pub WRONG_SEQ_EXTRA_OFFSET: u32,

    /// Whether to set the `PSH` flag on the wrong-sequence spoofed ClientHello
    /// packet.
    /// Most DPI implementations expect application data to carry `PSH`; keep
    /// this `true` unless you are debugging a specific DPI device.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub WRONG_SEQ_SET_PSH: bool,

    /// Whether to increment the IPv4 `Identification` field on the
    /// wrong-sequence spoofed packet. Bumping the ID makes the spoofed packet
    /// look like a fresh
    /// datagram rather than a retransmit, which helps some stateful
    /// middleboxes accept it.  Default: `true`.
    #[serde(default = "default_true")]
    pub WRONG_SEQ_BUMP_IP_IDENT: bool,

    // -----------------------------------------------------------------------
    // wrong_checksum method parameters
    // -----------------------------------------------------------------------
    /// Non-zero value added to the valid computed TCP checksum on the spoofed
    /// ClientHello packet. The packet is rebuilt normally first, then the TCP
    /// checksum field is corrupted with wrapping addition.
    /// Must be `>= 1`. Default: `1`.
    #[serde(default = "default_wrong_checksum_delta")]
    pub WRONG_CHECKSUM_DELTA: u16,

    /// Whether to set the `PSH` flag on the spoofed ClientHello packet.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub WRONG_CHECKSUM_SET_PSH: bool,

    /// Whether to increment the IPv4 `Identification` field on the spoofed
    /// packet. Default: `true`.
    #[serde(default = "default_true")]
    pub WRONG_CHECKSUM_BUMP_IP_IDENT: bool,

    /// Whether to signal bypass completion immediately after emitting the
    /// corrupted packet. The default is `true` because a correct
    /// invalid-checksum packet should be silently dropped by the server.
    #[serde(default = "default_true")]
    pub WRONG_CHECKSUM_COMPLETE_IMMEDIATELY: bool,

    // -----------------------------------------------------------------------
    // low_ttl method parameters
    // -----------------------------------------------------------------------
    /// IPv4 Time-To-Live stamped on the spoofed decoy ClientHello packet.
    /// The value must be high enough to reach the ISP's inline DPI middlebox
    /// (typically 4-8 hops from the client) but low enough that the segment
    /// expires before reaching the destination server.
    /// Must be `>= 1` and `<= 64`. Default: `5`.
    #[serde(default = "default_low_ttl_value")]
    pub LOW_TTL_VALUE: u8,

    /// Whether to set the `PSH` flag on the spoofed decoy ClientHello packet.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub LOW_TTL_SET_PSH: bool,

    /// Whether to increment the IPv4 `Identification` field on the spoofed
    /// decoy packet. Default: `true`.
    #[serde(default = "default_true")]
    pub LOW_TTL_BUMP_IP_IDENT: bool,

    /// Whether to signal bypass completion immediately after emitting the
    /// low-TTL decoy packet. The default is `true` because the segment is
    /// expected to expire before reaching the server and therefore will not
    /// produce an ACK.
    #[serde(default = "default_true")]
    pub LOW_TTL_COMPLETE_IMMEDIATELY: bool,

    /// Whether to automatically discover the correct `LOW_TTL_VALUE` at
    /// startup (and again after every background rescan that switches the
    /// SNI/IP target). Discovery probes TTL candidates from `1` up to
    /// `LOW_TTL_DISCOVER_MAX`, injecting a real decoy ClientHello and
    /// verifying the handshake completes for each candidate, then applies the
    /// largest working value (the server's hop distance minus one, which
    /// reaches any inline DPI middlebox with maximum margin). It adds a
    /// one-time startup delay and requires
    /// `LOW_TTL_COMPLETE_IMMEDIATELY = true`. Default: `true`.
    #[serde(default = "default_true")]
    pub LOW_TTL_DISCOVER: bool,

    /// Upper bound of the `LOW_TTL_DISCOVER` search range, bounding the
    /// worst-case startup delay. Must be `>= 1` and `<= 64`. Default: `32`.
    #[serde(default = "default_low_ttl_discover_max")]
    pub LOW_TTL_DISCOVER_MAX: u8,

    /// Per-candidate timeout in milliseconds used while discovering
    /// `LOW_TTL_VALUE`. Lower values speed up discovery but may cause false
    /// negatives on slow links. Must be `>= 100`. Default: `5000`.
    #[serde(default = "default_low_ttl_discover_timeout_ms")]
    pub LOW_TTL_DISCOVER_TIMEOUT_MS: u64,

    // -----------------------------------------------------------------------
    // wrong_md5 method parameters
    // -----------------------------------------------------------------------
    /// Whether to set the `PSH` flag on the spoofed TCP-MD5 ClientHello
    /// packet. Default: `true`.
    #[serde(default = "default_true")]
    pub WRONG_MD5_SET_PSH: bool,

    /// Whether to increment the IPv4 `Identification` field on the spoofed
    /// TCP-MD5 packet. Default: `true`.
    #[serde(default = "default_true")]
    pub WRONG_MD5_BUMP_IP_IDENT: bool,

    /// Whether to signal bypass completion immediately after emitting the
    /// TCP-MD5-tagged fake packet. Used by `wrong_md5` and
    /// `wrong_seq_wrong_md5`. The default is `true` because a server without a
    /// negotiated MD5 key should reject or drop the segment.
    #[serde(default = "default_true")]
    pub WRONG_MD5_COMPLETE_IMMEDIATELY: bool,

    // -----------------------------------------------------------------------
    // wrong_ack method parameters
    // -----------------------------------------------------------------------
    /// Bytes subtracted from `syn_ack_seq + 1` for the spoofed TCP ACK number.
    /// A value of `1` places the forged segment's ACK one byte before the
    /// server's current send-window left edge.
    /// Must be `>= 1`. Default: `1`.
    #[serde(default = "default_wrong_ack_offset")]
    pub WRONG_ACK_OFFSET: u32,

    /// Whether to set the `PSH` flag on the spoofed ClientHello packet.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub WRONG_ACK_SET_PSH: bool,

    /// Whether to increment the IPv4 `Identification` field on the spoofed
    /// packet. Default: `true`.
    #[serde(default = "default_true")]
    pub WRONG_ACK_BUMP_IP_IDENT: bool,

    /// Whether to signal bypass completion immediately after emitting the
    /// old-ACK packet. The default is `true` because out-of-window ACK handling
    /// is not consistent enough to wait for a server response.
    #[serde(default = "default_true")]
    pub WRONG_ACK_COMPLETE_IMMEDIATELY: bool,

    // -----------------------------------------------------------------------
    // wrong_timestamp method parameters
    // -----------------------------------------------------------------------
    /// Value subtracted from the captured TCP Timestamp TSval on the spoofed
    /// ClientHello packet. A value of `1` makes the forged segment older than
    /// the timestamp already seen by the server, which should trigger PAWS.
    /// Must be `>= 1`. Default: `1`.
    #[serde(default = "default_wrong_timestamp_offset")]
    pub WRONG_TIMESTAMP_OFFSET: u32,

    /// Whether to set the `PSH` flag on the spoofed ClientHello packet.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub WRONG_TIMESTAMP_SET_PSH: bool,

    /// Whether to increment the IPv4 `Identification` field on the spoofed
    /// packet. Default: `true`.
    #[serde(default = "default_true")]
    pub WRONG_TIMESTAMP_BUMP_IP_IDENT: bool,

    /// Whether to signal bypass completion immediately after emitting the
    /// backdated-timestamp packet. The default is `true` because a PAWS-rejected
    /// packet should not be acknowledged as new data by the server.
    #[serde(default = "default_true")]
    pub WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY: bool,

    // -----------------------------------------------------------------------
    // tls_record_frag method parameters
    // -----------------------------------------------------------------------
    /// Maximum bytes placed in each TLS record fragment when using
    /// `tls_record_frag` or `wrong_seq_tls_record_frag`.
    ///
    /// The real ClientHello TLS record body is split into chunks of at most
    /// this many bytes, each wrapped in its own TLS record header.  The
    /// resulting reassembled handshake is identical from the server's
    /// perspective.
    ///
    /// Smaller values produce more fragments, making it harder for DPI to
    /// reconstruct the SNI.  A value of `1` puts exactly one byte of record
    /// body per record (most aggressive). A value of `5` puts five body bytes
    /// in each fragment. Must be `>= 1`.
    /// Default: `1`.
    #[serde(default = "default_tls_frag_size")]
    pub TLS_RECORD_FRAG_SIZE: usize,

    /// Whether to set the TCP `PSH` flag on the packet carrying the fragmented
    /// ClientHello.  Default: `true`.
    #[serde(default = "default_true")]
    pub TLS_RECORD_FRAG_SET_PSH: bool,

    /// Whether to increment the IPv4 `Identification` field on the packet
    /// carrying the fragmented ClientHello.  Default: `true`.
    #[serde(default = "default_true")]
    pub TLS_RECORD_FRAG_BUMP_IP_IDENT: bool,

    // -----------------------------------------------------------------------
    // fake_tls method parameters
    // -----------------------------------------------------------------------
    /// Extra bytes subtracted from the decoy record's injected TCP sequence
    /// number on top of the decoy payload length. The decoy is placed at
    /// `syn_seq + 1 - payload_len - FAKE_TLS_EXTRA_OFFSET`, i.e. behind the
    /// server's receive window.  Default: `0`.
    #[serde(default)]
    pub FAKE_TLS_EXTRA_OFFSET: u32,

    /// Whether to set the TCP `PSH` flag on the decoy record packet.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub FAKE_TLS_SET_PSH: bool,

    /// Whether to increment the IPv4 `Identification` field on the decoy
    /// record packet.  Default: `true`.
    #[serde(default = "default_true")]
    pub FAKE_TLS_BUMP_IP_IDENT: bool,

    /// Whether to signal the bypass phase complete immediately after the
    /// decoy record is emitted. When `false`, the flow waits for the server
    /// to acknowledge the first data packet.  Default: `true`.
    #[serde(default = "default_true")]
    pub FAKE_TLS_COMPLETE_IMMEDIATELY: bool,

    /// Whether to forward the original first data packet (the real
    /// ClientHello) immediately after the decoy record, instead of relying
    /// on TCP retransmission. Requires backend dual-emission support
    /// (WinDivert send; raw socket on Linux/Android); backends without it
    /// fall back to single-packet emission.  Default: `true`.
    #[serde(default = "default_true")]
    pub FAKE_TLS_FORWARD_REAL: bool,

    // -----------------------------------------------------------------------
    // urg_sni_split method parameters
    // -----------------------------------------------------------------------
    /// The 1-byte dummy payload `urg_sni_split` inserts into the middle of the
    /// SNI domain string. The destination server's TCP stack extracts this
    /// byte as urgent data, so its TLS stream is unaffected; DPI middleboxes
    /// that read the raw byte stream see the mangled name.
    /// Default: `0`.
    #[serde(default = "default_sni_split_dummy_byte")]
    pub SNI_SPLIT_DUMMY_BYTE: u8,

    /// Where `urg_sni_split` inserts the dummy byte inside the SNI domain
    /// string. Supported values: `"middle"` (default), `"start"`, `"end"`,
    /// or a 0-based integer index (clamped to the last byte).
    #[serde(default = "default_sni_split_position")]
    pub SNI_SPLIT_POSITION: SniSplitPosition,

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

    // -----------------------------------------------------------------------
    // tls_frag method parameters
    // -----------------------------------------------------------------------
    /// Which client data should be fragmented by `tls_frag`,
    /// `wrong_seq_tls_frag`, or `wrong_md5_tls_frag`.
    ///
    /// Supported values:
    /// - `"tlshello"` fragments the first complete TLS record, preserving the
    ///   historical ZeroDPI behavior.
    /// - `"N-M"` fragments the Nth through Mth client-to-upstream data writes
    ///   seen by ZeroDPI. Packet indexes are 1-based.
    ///
    /// Default: `"1-3"`.
    #[serde(default = "default_tls_frag_packets")]
    pub TLS_FRAG_PACKETS: String,

    /// Xray-style fragment length range, in bytes, for TCP-level
    /// fragmentation. Accepts either an integer (`1`) or an inclusive range
    /// string (`"1-5"`). A fresh value is sampled for every fragment chunk.
    ///
    /// If this field is `None` in an in-memory config, ZeroDPI falls back to
    /// the legacy `TCP_SEG_SIZE` value. Must be `>= 1` when set.
    /// Default: `"100-200"`.
    #[serde(default = "default_tls_frag_length")]
    pub TLS_FRAG_LENGTH: Option<Int32Range>,

    /// Xray-style interval range, in milliseconds, between TCP-level
    /// fragments. Accepts either an integer (`0`) or an inclusive range string
    /// (`"0-10"`). A fresh value is sampled between fragment chunks.
    /// Must be `>= 0`. Default: `"10-20"`.
    #[serde(default = "default_tls_frag_interval_ms")]
    pub TLS_FRAG_INTERVAL_MS: Int32Range,

    /// Maximum ClientHello bytes sent in each TCP segment when using
    /// `tls_frag`, `wrong_seq_tls_frag`, or `wrong_md5_tls_frag`.
    ///
    /// Legacy alias for fixed `TLS_FRAG_LENGTH`; used only when
    /// `TLS_FRAG_LENGTH` is not set.
    ///
    /// The normal, intact TLS ClientHello record is sliced into chunks of at
    /// most this many bytes and each chunk is written to the upstream socket
    /// individually.
    /// With `TCP_SEG_NODELAY = true` the OS sends each chunk as a separate
    /// TCP segment, preventing any DPI engine from seeing the full SNI in a
    /// single segment.
    ///
    /// Smaller values produce more segments and are harder for DPI to
    /// reassemble, at the cost of slightly higher connection-setup overhead.
    /// A value of `1` sends one byte per segment (most aggressive).
    /// Must be `>= 1`.  Default: `1`.
    #[serde(default = "default_tcp_seg_size")]
    pub TCP_SEG_SIZE: usize,

    /// Whether to set `TCP_NODELAY` on the upstream socket before writing the
    /// segmented ClientHello.
    ///
    /// `TCP_NODELAY` disables Nagle's algorithm, which would otherwise
    /// coalesce small writes into a single TCP segment and defeat the bypass.
    /// Keep this `true` for normal use; set to `false` only when debugging a
    /// specific network that reacts poorly to `TCP_NODELAY`.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub TCP_SEG_NODELAY: bool,

    // -----------------------------------------------------------------------
    // tls_padding method parameters
    // -----------------------------------------------------------------------
    /// Zero-byte count of the RFC 7685 padding extension inserted into the
    /// client's real TLS ClientHello. Accepts an integer or an inclusive
    /// range string; a fresh value is sampled per connection and clamped at
    /// runtime so the final TLS record never exceeds 16383 bytes.
    /// Must be `>= 1` and `<= 16000`.  Default: `"1500-2500"`.
    #[serde(default = "default_tls_padding_size")]
    pub TLS_PADDING_SIZE: Int32Range,

    /// Where the padding extension is inserted inside the ClientHello
    /// extensions:
    /// - `"before"` (default) — immediately before the SNI extension,
    ///   pushing the SNI bytes past the DPI's inspection window.
    /// - `"after"` — at the end of the extension list (canonical RFC 7685
    ///   placement).
    #[serde(default = "default_tls_padding_position")]
    pub TLS_PADDING_POSITION: String,

    // -----------------------------------------------------------------------
    // mixed_case_sni method parameters
    // -----------------------------------------------------------------------
    /// When `true`, every ASCII letter in the SNI hostname is case-inverted
    /// (`a` → `A`, `A` → `a`).  When `false` (default), each letter is
    /// randomly uppercased or lowercased per connection, with a guaranteed
    /// minimum of one flipped letter.
    #[serde(default)]
    pub MIXED_CASE_SNI_FLIP_ALL: bool,

    // -----------------------------------------------------------------------
    // Proxy timing
    // -----------------------------------------------------------------------
    /// How many seconds the proxy waits for the intercept thread to confirm
    /// that the spoofed packet was acknowledged before giving up on a
    /// connection.  Increase on very high-latency links.
    /// Must be `>= 1`.  Default: `20`.
    #[serde(default = "default_bypass_timeout")]
    pub BYPASS_TIMEOUT_SECS: u64,

    /// Maximum lifetime for an established relay before ZeroDPI closes it and
    /// lets the upstream client reconnect through the current target.
    /// `0` disables relay rotation.  Default: `0`.
    #[serde(default)]
    pub RELAY_MAX_LIFETIME_SECS: u64,

    // -----------------------------------------------------------------------
    // IP bypass mode
    // -----------------------------------------------------------------------
    /// Operating mode.  `"sni_spoof"` (default) uses SNI-based DPI bypass.
    /// `"ip_bypass"` skips packet interception entirely and routes connections
    /// through a pre-scanned IP from `ip_list.txt`. `"ip_bypass_plus"` also
    /// uses IP selection, but applies only real-SNI-preserving bypass methods.
    #[serde(default = "default_mode")]
    pub MODE: String,

    /// Path to the IP list file used in `ip_bypass` mode.
    /// One entry per line: plain IPs or CIDR ranges (IPv4 and IPv6).
    /// Lines starting with `#` and blank lines are ignored.
    /// Relative paths are resolved from the directory containing `config.toml`.
    /// Default: `"ip_list.txt"`.
    #[serde(default = "default_ip_list")]
    pub IP_LIST: String,

    /// If set, skip the IP scan in `ip_bypass` mode and use this IP directly.
    /// Must be a valid IP address (v4 or v6).
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub SELECTED_IP: Option<String>,

    /// SNI hostname used *only* during the TLS phase of IP scanning.
    /// It is never inserted into proxied connections — the upstream app's
    /// own SNI passes through unchanged.
    /// Default: `"cloudflare.com"`.
    #[serde(default = "default_ip_scan_sni")]
    pub IP_SCAN_SNI: String,

    /// Maximum number of host addresses expanded from a single IPv6 CIDR.
    /// Prevents accidentally enumerating huge address spaces.
    /// Default: `65536`.
    #[serde(default = "default_ipv6_max_hosts")]
    pub IPV6_MAX_HOSTS: u64,

    // -----------------------------------------------------------------------
    // Scan-only output
    // -----------------------------------------------------------------------
    /// Optional path to write scan results as a JSON file after a scan-only
    /// run (`MODE = "sni_scan"` or `MODE = "ip_scan"`).
    /// Relative paths are resolved from the directory containing `config.toml`.
    /// When unset the results are shown in the TUI but not saved to disk.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub SCAN_OUTPUT: Option<String>,

    // -----------------------------------------------------------------------
    // Scanner tuning
    // -----------------------------------------------------------------------
    /// Max concurrent SNI probes.
    #[serde(default = "default_sni_max_concurrent")]
    pub SNI_MAX_CONCURRENT: usize,

    /// Max concurrent TCP connections in IP phase 1.
    #[serde(default = "default_ip_max_p1_concurrent")]
    pub IP_MAX_P1_CONCURRENT: usize,

    /// Max concurrent TLS probes in IP phase 2.
    #[serde(default = "default_ip_max_p2_concurrent")]
    pub IP_MAX_P2_CONCURRENT: usize,

    /// Max bytes downloaded for speed tests.
    #[serde(default = "default_scan_download_cap")]
    pub SCAN_DOWNLOAD_CAP: usize,

    /// Max bytes uploaded for upload speed tests.
    #[serde(default = "default_scan_upload_cap")]
    pub SCAN_UPLOAD_CAP: usize,

    /// Candidate-relative HTTP path used for upload speed tests.
    #[serde(default = "default_scan_upload_path")]
    pub SCAN_UPLOAD_PATH: String,

    /// Max valid TCP latency for scoring (ms).
    #[serde(default = "default_tcp_latency_cap_ms")]
    pub TCP_LATENCY_CAP_MS: f64,

    /// Max valid TLS latency for scoring (ms).
    #[serde(default = "default_tls_latency_cap_ms")]
    pub TLS_LATENCY_CAP_MS: f64,

    /// Max valid TTFB for scoring (ms).
    #[serde(default = "default_ttfb_cap_ms")]
    pub TTFB_CAP_MS: f64,

    /// Download speed cap for scoring (bytes/sec).
    #[serde(default = "default_speed_cap_bps")]
    pub SPEED_CAP_BPS: f64,

    /// Upload speed cap for scoring (bytes/sec).
    #[serde(default = "default_upload_speed_cap_bps")]
    pub UPLOAD_SPEED_CAP_BPS: f64,

    // -----------------------------------------------------------------------
    // proxy_scan mode
    // -----------------------------------------------------------------------
    /// Minimum SNI-scan score (Phase 1) a candidate must reach to be
    /// eligible for the proxy test (Phase 2).  Default: `1`.
    #[serde(default = "default_proxy_test_min_sni_score")]
    pub PROXY_TEST_MIN_SNI_SCORE: u8,

    /// Maximum number of Phase 1 candidates to carry forward into the proxy
    /// test.  `0` means "no cap — test all passing candidates".
    /// Default: `0`.
    #[serde(default)]
    pub PROXY_TEST_TOP_N: usize,

    /// Host of the SOCKS5 proxy (V2RayN / any SOCKS5 mixed port).
    /// Default: `"127.0.0.1"`.
    #[serde(default = "default_proxy_socks5_host")]
    pub PROXY_TEST_SOCKS5_HOST: String,

    /// Port of the SOCKS5 proxy.  Default: `10808`.
    #[serde(default = "default_proxy_socks5_port")]
    pub PROXY_TEST_SOCKS5_PORT: u16,

    /// HTTPS URL to fetch through the proxy for speed / latency measurement.
    /// Default: Cloudflare's speed-test endpoint (~512 KB).
    #[serde(default = "default_proxy_test_url")]
    pub PROXY_TEST_URL: String,

    /// Per-probe timeout for the proxy test phase (seconds).  Default: `30`.
    #[serde(default = "default_proxy_test_timeout")]
    pub PROXY_TEST_TIMEOUT_SECS: u64,

    /// Weight given to the Phase 1 SNI-scan score when blending into the
    /// final score.  The proxy-test weight is `1.0 - PROXY_TEST_SNI_WEIGHT`.
    /// Must be in `[0.0, 1.0]`.  Default: `0.5` (equal blend).
    #[serde(default = "default_proxy_sni_weight")]
    pub PROXY_TEST_SNI_WEIGHT: f64,

    /// Proxy TCP-latency cap used in proxy-test scoring (ms).  Default: `500`.
    #[serde(default = "default_proxy_latency_cap_ms")]
    pub PROXY_TEST_LATENCY_CAP_MS: f64,

    /// Proxy TTFB cap used in proxy-test scoring (ms).  Default: `3000`.
    #[serde(default = "default_proxy_ttfb_cap_ms")]
    pub PROXY_TEST_TTFB_CAP_MS: f64,

    /// Proxy download speed cap used in proxy-test scoring (bytes/sec).
    /// Default: `2 048 000` (≈ 2 MB/s).
    #[serde(default = "default_proxy_speed_cap_bps")]
    pub PROXY_TEST_SPEED_CAP_BPS: f64,
}

fn empty_string_as_none<'de, D>(de: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => Ok(Some(s.to_owned())),
    }
}

fn default_sni_list() -> String {
    "sni_list.txt".into()
}
fn default_scan_timeout() -> u64 {
    5
}
fn default_rescan_interval_secs() -> u64 {
    600
}
fn default_method() -> BypassMethodList {
    BypassMethodList::from_delimited("wrong_seq, tls_frag")
}
fn default_queue_num() -> u16 {
    1
}
fn default_linux_firewall_backend() -> String {
    LinuxFirewallBackend::default().as_str().into()
}
fn default_true() -> bool {
    true
}
fn default_wrong_checksum_delta() -> u16 {
    1
}
fn default_low_ttl_value() -> u8 {
    5
}
fn default_low_ttl_discover_max() -> u8 {
    32
}
fn default_low_ttl_discover_timeout_ms() -> u64 {
    5000
}
fn default_wrong_ack_offset() -> u32 {
    1
}
fn default_wrong_timestamp_offset() -> u32 {
    1
}
fn default_tls_frag_size() -> usize {
    1
}
fn default_sni_split_dummy_byte() -> u8 {
    0
}
fn default_sni_split_position() -> SniSplitPosition {
    SniSplitPosition::Middle
}
fn default_sni_boundary_split_point() -> SniBoundarySplitPoint {
    SniBoundarySplitPoint::ExtensionLength
}
fn default_sni_boundary_delay_ms() -> Int32Range {
    Int32Range { min: 5, max: 10 }
}
fn default_tls_frag_packets() -> String {
    "1-3".into()
}
fn default_tls_frag_length() -> Option<Int32Range> {
    Some(Int32Range { min: 100, max: 200 })
}
fn default_tls_frag_interval_ms() -> Int32Range {
    Int32Range { min: 10, max: 20 }
}
fn default_tls_padding_size() -> Int32Range {
    Int32Range::parse("1500-2500").expect("static default TLS_PADDING_SIZE")
}
fn default_tls_padding_position() -> String {
    "before".into()
}
fn default_tcp_seg_size() -> usize {
    1
}
fn default_bypass_timeout() -> u64 {
    20
}
fn default_mode() -> String {
    "sni_spoof".into()
}
fn default_ip_list() -> String {
    "ip_list.txt".into()
}
fn default_ip_scan_sni() -> String {
    "cloudflare.com".into()
}
fn default_ipv6_max_hosts() -> u64 {
    65536
}
fn default_sni_max_concurrent() -> usize {
    64
}
fn default_ip_max_p1_concurrent() -> usize {
    128
}
fn default_ip_max_p2_concurrent() -> usize {
    32
}
fn default_scan_download_cap() -> usize {
    10_240
}
fn default_scan_upload_cap() -> usize {
    10_240
}
fn default_scan_upload_path() -> String {
    "/".into()
}
fn default_tcp_latency_cap_ms() -> f64 {
    500.0
}
fn default_tls_latency_cap_ms() -> f64 {
    1_000.0
}
fn default_ttfb_cap_ms() -> f64 {
    2_000.0
}
fn default_speed_cap_bps() -> f64 {
    2_048_000.0
}
fn default_upload_speed_cap_bps() -> f64 {
    2_048_000.0
}
fn default_sni_switch_min_score() -> u8 {
    1
}
fn default_proxy_test_min_sni_score() -> u8 {
    1
}
fn default_proxy_socks5_host() -> String {
    "127.0.0.1".into()
}
fn default_proxy_socks5_port() -> u16 {
    10808
}
fn default_proxy_test_url() -> String {
    "https://speed.cloudflare.com/__down?bytes=524288".into()
}
fn default_proxy_test_timeout() -> u64 {
    30
}
fn default_proxy_sni_weight() -> f64 {
    0.5
}
fn default_proxy_latency_cap_ms() -> f64 {
    500.0
}
fn default_proxy_ttfb_cap_ms() -> f64 {
    3_000.0
}
fn default_proxy_speed_cap_bps() -> f64 {
    2_048_000.0
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())?;
        let cfg: Self = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.CUSTOM_DNS_ENABLED {
            let server = self.CUSTOM_DNS_SERVER.as_deref().ok_or_else(|| {
                anyhow::anyhow!("CUSTOM_DNS_SERVER is required when CUSTOM_DNS_ENABLED is true")
            })?;
            crate::dns::parse_custom_dns_server(server)?;
        }
        if self.SCAN_TIMEOUT_SECS == 0 {
            anyhow::bail!("SCAN_TIMEOUT_SECS must be > 0");
        }
        if self.BYPASS_TIMEOUT_SECS == 0 {
            anyhow::bail!("BYPASS_TIMEOUT_SECS must be > 0");
        }
        if self.SNI_SWITCH_MIN_SCORE > 100 {
            anyhow::bail!("SNI_SWITCH_MIN_SCORE must be <= 100");
        }
        if self.SCAN_DOWNLOAD_CAP == 0 {
            anyhow::bail!("SCAN_DOWNLOAD_CAP must be > 0");
        }
        if self.SCAN_UPLOAD_CAP == 0 {
            anyhow::bail!("SCAN_UPLOAD_CAP must be > 0");
        }
        if self.SCAN_UPLOAD_PATH.is_empty()
            || !self.SCAN_UPLOAD_PATH.starts_with('/')
            || self.SCAN_UPLOAD_PATH.contains('\r')
            || self.SCAN_UPLOAD_PATH.contains('\n')
        {
            anyhow::bail!(
                "SCAN_UPLOAD_PATH must be a non-empty HTTP path starting with '/' and containing no CR/LF"
            );
        }
        if !self.SPEED_CAP_BPS.is_finite() || self.SPEED_CAP_BPS <= 0.0 {
            anyhow::bail!("SPEED_CAP_BPS must be a finite value > 0");
        }
        if !self.UPLOAD_SPEED_CAP_BPS.is_finite() || self.UPLOAD_SPEED_CAP_BPS <= 0.0 {
            anyhow::bail!("UPLOAD_SPEED_CAP_BPS must be a finite value > 0");
        }
        if let Some(ref sni) = self.SELECTED_SNI {
            if sni.len() > MAX_SNI_LEN {
                anyhow::bail!(
                    "SELECTED_SNI is too long ({} bytes, max {MAX_SNI_LEN}): '{sni}'",
                    sni.len()
                );
            }
        }
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
                                | "fake_tls"
                        )
                })
            {
                anyhow::bail!(
                    "BYPASS_METHOD \"sni_boundary_frag\" cannot be combined with \"tls_record_frag\" or \"urg_sni_split\""
                );
            }
            if self.BYPASS_METHOD.contains("fake_tls")
                && (self.BYPASS_METHOD.contains("tls_record_frag")
                    || self.BYPASS_METHOD.contains("urg_sni_split"))
            {
                anyhow::bail!(
                    "BYPASS_METHOD \"fake_tls\" cannot be combined with \"tls_record_frag\" or \"urg_sni_split\""
                );
            }
        }
        if self.WRONG_CHECKSUM_DELTA == 0 {
            anyhow::bail!("WRONG_CHECKSUM_DELTA must be >= 1");
        }
        if self.WRONG_ACK_OFFSET == 0 {
            anyhow::bail!("WRONG_ACK_OFFSET must be >= 1");
        }
        if self.WRONG_TIMESTAMP_OFFSET == 0 {
            anyhow::bail!("WRONG_TIMESTAMP_OFFSET must be >= 1");
        }
        if self.LOW_TTL_VALUE == 0 {
            anyhow::bail!("LOW_TTL_VALUE must be >= 1");
        }
        if self.LOW_TTL_VALUE > 64 {
            anyhow::bail!("LOW_TTL_VALUE must be <= 64");
        }
        if self.LOW_TTL_DISCOVER_MAX == 0 {
            anyhow::bail!("LOW_TTL_DISCOVER_MAX must be >= 1");
        }
        if self.LOW_TTL_DISCOVER_MAX > 64 {
            anyhow::bail!("LOW_TTL_DISCOVER_MAX must be <= 64");
        }
        if self.LOW_TTL_DISCOVER_TIMEOUT_MS < 100 {
            anyhow::bail!("LOW_TTL_DISCOVER_TIMEOUT_MS must be >= 100");
        }
        if self.TLS_RECORD_FRAG_SIZE == 0 {
            anyhow::bail!("TLS_RECORD_FRAG_SIZE must be >= 1");
        }
        if self.TCP_SEG_SIZE == 0 {
            anyhow::bail!("TCP_SEG_SIZE must be >= 1");
        }
        if self.TCP_SEG_SIZE > i32::MAX as usize {
            anyhow::bail!("TCP_SEG_SIZE must be <= i32::MAX");
        }
        self.TLS_PADDING_SIZE
            .validate_at_least("TLS_PADDING_SIZE", 1)?;
        if self.TLS_PADDING_SIZE.max > 16000 {
            anyhow::bail!("TLS_PADDING_SIZE must be <= 16000");
        }
        PaddingPosition::parse(&self.TLS_PADDING_POSITION)
            .map_err(|e| anyhow::anyhow!("TLS_PADDING_POSITION is invalid: {e}"))?;
        let _ = self.tls_frag_packets()?;
        self.tls_frag_length_range()?
            .validate_at_least("TLS_FRAG_LENGTH", 1)?;
        self.TLS_FRAG_INTERVAL_MS
            .validate_at_least("TLS_FRAG_INTERVAL_MS", 0)?;
        self.SNI_BOUNDARY_FRAG_DELAY_MS
            .validate_at_least("SNI_BOUNDARY_FRAG_DELAY_MS", 0)?;
        if LinuxFirewallBackend::parse(&self.LINUX_FIREWALL_BACKEND).is_none() {
            anyhow::bail!(
                "Unknown LINUX_FIREWALL_BACKEND '{}'. Valid values: \"iptables\", \"nftables\"",
                self.LINUX_FIREWALL_BACKEND
            );
        }
        if !matches!(
            self.MODE.as_str(),
            "sni_spoof" | "ip_bypass" | "ip_bypass_plus" | "sni_scan" | "ip_scan" | "proxy_scan"
        ) {
            anyhow::bail!(
                "Unknown MODE '{}'. Valid values: \"sni_spoof\", \"ip_bypass\", \"ip_bypass_plus\", \"sni_scan\", \"ip_scan\", \"proxy_scan\"",
                self.MODE
            );
        }
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
        if !(0.0..=1.0).contains(&self.PROXY_TEST_SNI_WEIGHT) {
            anyhow::bail!("PROXY_TEST_SNI_WEIGHT must be in [0.0, 1.0]");
        }
        if self.PROXY_TEST_TIMEOUT_SECS == 0 {
            anyhow::bail!("PROXY_TEST_TIMEOUT_SECS must be > 0");
        }
        if let Some(ref ip) = self.SELECTED_IP {
            let parsed = ip
                .parse::<std::net::IpAddr>()
                .map_err(|_| anyhow::anyhow!("SELECTED_IP '{}' is not a valid IP address", ip))?;
            if self.MODE == "ip_bypass_plus" && parsed.is_ipv6() {
                anyhow::bail!("MODE = \"ip_bypass_plus\" is IPv4-only; SELECTED_IP '{ip}' is IPv6");
            }
        }
        Ok(())
    }

    pub fn tls_frag_packets(&self) -> anyhow::Result<TlsFragPackets> {
        TlsFragPackets::parse(&self.TLS_FRAG_PACKETS)
            .map_err(|e| anyhow::anyhow!("TLS_FRAG_PACKETS is invalid: {e}"))
    }

    pub fn tls_frag_length_range(&self) -> anyhow::Result<Int32Range> {
        if let Some(range) = self.TLS_FRAG_LENGTH {
            return Ok(range);
        }
        let value = i32::try_from(self.TCP_SEG_SIZE)
            .map_err(|_| anyhow::anyhow!("TCP_SEG_SIZE must be <= i32::MAX"))?;
        Ok(Int32Range::exact(value))
    }

    pub fn linux_firewall_backend(&self) -> LinuxFirewallBackend {
        LinuxFirewallBackend::parse(&self.LINUX_FIREWALL_BACKEND).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct MethodWrapper {
        value: BypassMethodList,
    }

    fn parse_method(toml_value: &str) -> Result<BypassMethodList, toml::de::Error> {
        toml::from_str::<MethodWrapper>(&format!("value = {toml_value}")).map(|w| w.value)
    }

    #[test]
    fn deserializes_single_string() {
        let list = parse_method("\"wrong_seq\"").unwrap();
        assert_eq!(list, "wrong_seq");
        assert_eq!(list.iter().collect::<Vec<_>>(), vec!["wrong_seq"]);
    }

    #[test]
    fn deserializes_array() {
        let list = parse_method("[\"wrong_seq\", \"low_ttl\"]").unwrap();
        assert_eq!(
            list.iter().collect::<Vec<_>>(),
            vec!["wrong_seq", "low_ttl"]
        );
    }

    #[test]
    fn expands_combo_alias_in_string() {
        let list = parse_method("\"wrong_seq_tls_frag\"").unwrap();
        assert_eq!(
            list.iter().collect::<Vec<_>>(),
            vec!["wrong_seq", "tls_frag"]
        );
    }

    #[test]
    fn expands_combo_alias_in_array() {
        let list = parse_method("[\"wrong_seq_tls_frag\", \"low_ttl\"]").unwrap();
        assert_eq!(
            list.iter().collect::<Vec<_>>(),
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
    fn socket_only_and_interceptor_helpers_include_tls_padding() {
        for name in ["tls_frag", "tls_padding"] {
            let list = BypassMethodList::from(name);
            assert!(list.is_socket_only(), "{name} should be socket-only");
            assert!(
                !list.requires_interceptor(),
                "{name} should not require interceptor"
            );
        }
        let both = BypassMethodList::from_delimited("tls_frag, tls_padding");
        assert!(both.is_socket_only());
        assert!(!both.requires_interceptor());

        let combo = BypassMethodList::from_delimited("tls_padding, wrong_seq");
        assert!(!combo.is_socket_only());
        assert!(combo.requires_interceptor());
    }

    #[test]
    fn tls_padding_fields_parse_and_default() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap();
        assert_eq!(
            cfg.TLS_PADDING_SIZE,
            Int32Range::parse("1500-2500").unwrap()
        );
        assert_eq!(cfg.TLS_PADDING_POSITION, "before");
        cfg.validate().unwrap();
    }

    #[test]
    fn parses_custom_tls_padding_values() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               TLS_PADDING_SIZE = "2000-3000"
               TLS_PADDING_POSITION = "after""#,
        )
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.TLS_PADDING_SIZE,
            Int32Range::parse("2000-3000").unwrap()
        );
        assert_eq!(cfg.TLS_PADDING_POSITION, "after");
    }

    #[test]
    fn rejects_invalid_tls_padding_size() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               TLS_PADDING_SIZE = 0"#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_oversized_tls_padding_size() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               TLS_PADDING_SIZE = 20000"#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_invalid_tls_padding_position() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               TLS_PADDING_POSITION = "middle""#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn ip_bypass_plus_accepts_tls_padding() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               MODE = "ip_bypass_plus"
               BYPASS_METHOD = "tls_padding""#,
        )
        .unwrap();
        cfg.validate().unwrap();
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
        assert!(parse_method("5").is_err());
        assert!(parse_method("true").is_err());
    }

    #[test]
    fn parses_minimal_toml() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.LISTEN_PORT, 40443);
        assert_eq!(
            cfg.BYPASS_METHOD.iter().collect::<Vec<_>>(),
            vec!["wrong_seq", "tls_frag"]
        );
        assert_eq!(cfg.NFQUEUE_NUM, 1);
        assert_eq!(cfg.LINUX_FIREWALL_BACKEND, "iptables");
        assert!(cfg.AUTO_SELECT);
        assert_eq!(cfg.RESCAN_INTERVAL_SECS, 600);
        assert_eq!(cfg.SNI_SWITCH_MIN_SCORE, 1);
        assert_eq!(cfg.SNI_LIST, "sni_list.txt");
        assert_eq!(cfg.SCAN_TIMEOUT_SECS, 5);
        // wrong_seq defaults
        assert_eq!(cfg.WRONG_SEQ_EXTRA_OFFSET, 0);
        assert!(cfg.WRONG_SEQ_SET_PSH);
        assert!(cfg.WRONG_SEQ_BUMP_IP_IDENT);
        // wrong_checksum defaults
        assert_eq!(cfg.WRONG_CHECKSUM_DELTA, 1);
        assert!(cfg.WRONG_CHECKSUM_SET_PSH);
        assert!(cfg.WRONG_CHECKSUM_BUMP_IP_IDENT);
        assert!(cfg.WRONG_CHECKSUM_COMPLETE_IMMEDIATELY);
        // low_ttl defaults
        assert_eq!(cfg.LOW_TTL_VALUE, 5);
        assert!(cfg.LOW_TTL_SET_PSH);
        assert!(cfg.LOW_TTL_BUMP_IP_IDENT);
        assert!(cfg.LOW_TTL_COMPLETE_IMMEDIATELY);
        // wrong_md5 defaults
        assert!(cfg.WRONG_MD5_SET_PSH);
        assert!(cfg.WRONG_MD5_BUMP_IP_IDENT);
        assert!(cfg.WRONG_MD5_COMPLETE_IMMEDIATELY);
        // wrong_ack defaults
        assert_eq!(cfg.WRONG_ACK_OFFSET, 1);
        assert!(cfg.WRONG_ACK_SET_PSH);
        assert!(cfg.WRONG_ACK_BUMP_IP_IDENT);
        assert!(cfg.WRONG_ACK_COMPLETE_IMMEDIATELY);
        // wrong_timestamp defaults
        assert_eq!(cfg.WRONG_TIMESTAMP_OFFSET, 1);
        assert!(cfg.WRONG_TIMESTAMP_SET_PSH);
        assert!(cfg.WRONG_TIMESTAMP_BUMP_IP_IDENT);
        assert!(cfg.WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY);
        // tls_record_frag defaults
        assert_eq!(cfg.TLS_RECORD_FRAG_SIZE, 1);
        assert!(cfg.TLS_RECORD_FRAG_SET_PSH);
        assert!(cfg.TLS_RECORD_FRAG_BUMP_IP_IDENT);
        // tls_frag defaults
        assert_eq!(cfg.TLS_FRAG_PACKETS, "1-3");
        assert_eq!(cfg.TLS_FRAG_LENGTH, Some(Int32Range { min: 100, max: 200 }));
        assert_eq!(
            cfg.tls_frag_length_range().unwrap(),
            Int32Range { min: 100, max: 200 }
        );
        assert_eq!(cfg.TLS_FRAG_INTERVAL_MS, Int32Range { min: 10, max: 20 });
        assert_eq!(cfg.TCP_SEG_SIZE, 1);
        assert!(cfg.TCP_SEG_NODELAY);
        // proxy timing defaults
        assert_eq!(cfg.BYPASS_TIMEOUT_SECS, 20);
        assert_eq!(cfg.RELAY_MAX_LIFETIME_SECS, 0);
    }

    #[test]
    fn sni_split_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.SNI_SPLIT_DUMMY_BYTE, 0);
        assert_eq!(cfg.SNI_SPLIT_POSITION, SniSplitPosition::Middle);
    }

    #[test]
    fn sni_split_position_parsing() {
        for (toml_value, expected) in [
            ("\"middle\"", SniSplitPosition::Middle),
            ("\"MIDDLE\"", SniSplitPosition::Middle),
            ("\"start\"", SniSplitPosition::Start),
            ("\"end\"", SniSplitPosition::End),
            ("3", SniSplitPosition::Index(3)),
            ("0", SniSplitPosition::Index(0)),
        ] {
            let toml_str = format!(
                r#"
                LISTEN_HOST = "0.0.0.0"
                LISTEN_PORT = 40443
                SNI_SPLIT_POSITION = {toml_value}
            "#
            );
            let cfg: Config = toml::from_str(&toml_str).unwrap();
            assert_eq!(cfg.SNI_SPLIT_POSITION, expected);
        }
    }

    #[test]
    fn invalid_sni_split_position_rejected() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            SNI_SPLIT_POSITION = "sideways"
        "#;
        assert!(toml::from_str::<Config>(toml_str).is_err());
    }

    #[test]
    fn urg_sni_split_is_a_valid_method() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "urg_sni_split"
            LOW_TTL_DISCOVER = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn wrong_checksum_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_checksum"
            LOW_TTL_DISCOVER = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.BYPASS_METHOD, "wrong_checksum");
        assert_eq!(cfg.WRONG_CHECKSUM_DELTA, 1);
        assert!(cfg.WRONG_CHECKSUM_SET_PSH);
        assert!(cfg.WRONG_CHECKSUM_BUMP_IP_IDENT);
        assert!(cfg.WRONG_CHECKSUM_COMPLETE_IMMEDIATELY);
    }

    #[test]
    fn parses_wrong_checksum_fields() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_checksum"
            LOW_TTL_DISCOVER = false
            WRONG_CHECKSUM_DELTA = 17
            WRONG_CHECKSUM_SET_PSH = false
            WRONG_CHECKSUM_BUMP_IP_IDENT = false
            WRONG_CHECKSUM_COMPLETE_IMMEDIATELY = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.WRONG_CHECKSUM_DELTA, 17);
        assert!(!cfg.WRONG_CHECKSUM_SET_PSH);
        assert!(!cfg.WRONG_CHECKSUM_BUMP_IP_IDENT);
        assert!(!cfg.WRONG_CHECKSUM_COMPLETE_IMMEDIATELY);
    }

    #[test]
    fn rejects_wrong_checksum_delta_zero() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_checksum"
            WRONG_CHECKSUM_DELTA = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn low_ttl_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "low_ttl"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.BYPASS_METHOD, "low_ttl");
        assert_eq!(cfg.LOW_TTL_VALUE, 5);
        assert!(cfg.LOW_TTL_SET_PSH);
        assert!(cfg.LOW_TTL_BUMP_IP_IDENT);
        assert!(cfg.LOW_TTL_COMPLETE_IMMEDIATELY);
        assert!(cfg.LOW_TTL_DISCOVER);
        assert_eq!(cfg.LOW_TTL_DISCOVER_MAX, 32);
        assert_eq!(cfg.LOW_TTL_DISCOVER_TIMEOUT_MS, 5000);
    }

    #[test]
    fn parses_low_ttl_fields() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "low_ttl"
            LOW_TTL_VALUE = 8
            LOW_TTL_SET_PSH = false
            LOW_TTL_BUMP_IP_IDENT = false
            LOW_TTL_COMPLETE_IMMEDIATELY = false
            LOW_TTL_DISCOVER = true
            LOW_TTL_DISCOVER_MAX = 16
            LOW_TTL_DISCOVER_TIMEOUT_MS = 700
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.LOW_TTL_VALUE, 8);
        assert!(!cfg.LOW_TTL_SET_PSH);
        assert!(!cfg.LOW_TTL_BUMP_IP_IDENT);
        assert!(!cfg.LOW_TTL_COMPLETE_IMMEDIATELY);
        assert!(cfg.LOW_TTL_DISCOVER);
        assert_eq!(cfg.LOW_TTL_DISCOVER_MAX, 16);
        assert_eq!(cfg.LOW_TTL_DISCOVER_TIMEOUT_MS, 700);
    }

    #[test]
    fn rejects_low_ttl_value_zero() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "low_ttl"
            LOW_TTL_VALUE = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_low_ttl_value_out_of_range() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "low_ttl"
            LOW_TTL_VALUE = 65
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_low_ttl_discover_max_zero() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "low_ttl"
            LOW_TTL_DISCOVER = true
            LOW_TTL_DISCOVER_MAX = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_low_ttl_discover_max_out_of_range() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "low_ttl"
            LOW_TTL_DISCOVER = true
            LOW_TTL_DISCOVER_MAX = 65
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_low_ttl_discover_timeout_too_small() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "low_ttl"
            LOW_TTL_DISCOVER = true
            LOW_TTL_DISCOVER_TIMEOUT_MS = 50
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn wrong_md5_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_md5"
            LOW_TTL_DISCOVER = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.BYPASS_METHOD, "wrong_md5");
        assert!(cfg.WRONG_MD5_SET_PSH);
        assert!(cfg.WRONG_MD5_BUMP_IP_IDENT);
        assert!(cfg.WRONG_MD5_COMPLETE_IMMEDIATELY);
    }

    #[test]
    fn parses_wrong_md5_fields() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_md5"
            LOW_TTL_DISCOVER = false
            WRONG_MD5_SET_PSH = false
            WRONG_MD5_BUMP_IP_IDENT = false
            WRONG_MD5_COMPLETE_IMMEDIATELY = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert!(!cfg.WRONG_MD5_SET_PSH);
        assert!(!cfg.WRONG_MD5_BUMP_IP_IDENT);
        assert!(!cfg.WRONG_MD5_COMPLETE_IMMEDIATELY);
    }

    #[test]
    fn wrong_seq_wrong_md5_accepted_by_validate() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_seq_wrong_md5"
            LOW_TTL_DISCOVER = false
            WRONG_SEQ_EXTRA_OFFSET = 33
            WRONG_SEQ_SET_PSH = false
            WRONG_SEQ_BUMP_IP_IDENT = false
            WRONG_MD5_COMPLETE_IMMEDIATELY = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.BYPASS_METHOD.iter().collect::<Vec<_>>(),
            vec!["wrong_seq", "wrong_md5"]
        );
        assert_eq!(cfg.WRONG_SEQ_EXTRA_OFFSET, 33);
        assert!(!cfg.WRONG_SEQ_SET_PSH);
        assert!(!cfg.WRONG_SEQ_BUMP_IP_IDENT);
        assert!(!cfg.WRONG_MD5_COMPLETE_IMMEDIATELY);
    }

    #[test]
    fn wrong_ack_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_ack"
            LOW_TTL_DISCOVER = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.BYPASS_METHOD, "wrong_ack");
        assert_eq!(cfg.WRONG_ACK_OFFSET, 1);
        assert!(cfg.WRONG_ACK_SET_PSH);
        assert!(cfg.WRONG_ACK_BUMP_IP_IDENT);
        assert!(cfg.WRONG_ACK_COMPLETE_IMMEDIATELY);
    }

    #[test]
    fn parses_wrong_ack_fields() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_ack"
            LOW_TTL_DISCOVER = false
            WRONG_ACK_OFFSET = 17
            WRONG_ACK_SET_PSH = false
            WRONG_ACK_BUMP_IP_IDENT = false
            WRONG_ACK_COMPLETE_IMMEDIATELY = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.WRONG_ACK_OFFSET, 17);
        assert!(!cfg.WRONG_ACK_SET_PSH);
        assert!(!cfg.WRONG_ACK_BUMP_IP_IDENT);
        assert!(!cfg.WRONG_ACK_COMPLETE_IMMEDIATELY);
    }

    #[test]
    fn rejects_wrong_ack_offset_zero() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_ack"
            WRONG_ACK_OFFSET = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn wrong_timestamp_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_timestamp"
            LOW_TTL_DISCOVER = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.BYPASS_METHOD, "wrong_timestamp");
        assert_eq!(cfg.WRONG_TIMESTAMP_OFFSET, 1);
        assert!(cfg.WRONG_TIMESTAMP_SET_PSH);
        assert!(cfg.WRONG_TIMESTAMP_BUMP_IP_IDENT);
        assert!(cfg.WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY);
    }

    #[test]
    fn parses_wrong_timestamp_fields() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_timestamp"
            LOW_TTL_DISCOVER = false
            WRONG_TIMESTAMP_OFFSET = 17
            WRONG_TIMESTAMP_SET_PSH = false
            WRONG_TIMESTAMP_BUMP_IP_IDENT = false
            WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.WRONG_TIMESTAMP_OFFSET, 17);
        assert!(!cfg.WRONG_TIMESTAMP_SET_PSH);
        assert!(!cfg.WRONG_TIMESTAMP_BUMP_IP_IDENT);
        assert!(!cfg.WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY);
    }

    #[test]
    fn rejects_wrong_timestamp_offset_zero() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_timestamp"
            WRONG_TIMESTAMP_OFFSET = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn tls_record_frag_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_record_frag"
            LOW_TTL_DISCOVER = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.BYPASS_METHOD, "tls_record_frag");
        assert_eq!(cfg.TLS_RECORD_FRAG_SIZE, 1);
        assert!(cfg.TLS_RECORD_FRAG_SET_PSH);
        assert!(cfg.TLS_RECORD_FRAG_BUMP_IP_IDENT);
    }

    #[test]
    fn parses_tls_record_frag_fields() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_record_frag"
            LOW_TTL_DISCOVER = false
            TLS_RECORD_FRAG_SIZE = 5
            TLS_RECORD_FRAG_SET_PSH = false
            TLS_RECORD_FRAG_BUMP_IP_IDENT = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.TLS_RECORD_FRAG_SIZE, 5);
        assert!(!cfg.TLS_RECORD_FRAG_SET_PSH);
        assert!(!cfg.TLS_RECORD_FRAG_BUMP_IP_IDENT);
    }

    #[test]
    fn parses_fake_tls_defaults() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap();
        assert_eq!(cfg.FAKE_TLS_EXTRA_OFFSET, 0);
        assert!(cfg.FAKE_TLS_SET_PSH);
        assert!(cfg.FAKE_TLS_BUMP_IP_IDENT);
        assert!(cfg.FAKE_TLS_COMPLETE_IMMEDIATELY);
    }

    #[test]
    fn parses_fake_tls_overrides() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               FAKE_TLS_EXTRA_OFFSET = 33
               FAKE_TLS_SET_PSH = false
               FAKE_TLS_BUMP_IP_IDENT = false
               FAKE_TLS_COMPLETE_IMMEDIATELY = false"#,
        )
        .unwrap();
        assert_eq!(cfg.FAKE_TLS_EXTRA_OFFSET, 33);
        assert!(!cfg.FAKE_TLS_SET_PSH);
        assert!(!cfg.FAKE_TLS_BUMP_IP_IDENT);
        assert!(!cfg.FAKE_TLS_COMPLETE_IMMEDIATELY);
    }

    #[test]
    fn parses_fake_tls_forward_real() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444"#,
        )
        .unwrap();
        assert!(cfg.FAKE_TLS_FORWARD_REAL);
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               FAKE_TLS_FORWARD_REAL = false"#,
        )
        .unwrap();
        assert!(!cfg.FAKE_TLS_FORWARD_REAL);
    }

    #[test]
    fn rejects_tls_frag_size_zero() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_record_frag"
            TLS_RECORD_FRAG_SIZE = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_fake_tls_with_tls_record_frag() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["fake_tls", "tls_record_frag"]"#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_fake_tls_with_urg_sni_split() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               BYPASS_METHOD = ["fake_tls", "urg_sni_split"]"#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_fake_tls_combos() {
        for method in [
            r#""fake_tls""#,
            r#"["fake_tls", "wrong_seq"]"#,
            r#"["fake_tls", "low_ttl"]"#,
            r#"["fake_tls", "tls_frag"]"#,
            r#"["fake_tls", "tls_padding"]"#,
            r#"["fake_tls", "mixed_case_sni"]"#,
            r#"["fake_tls", "sni_boundary_frag"]"#,
            r#"["fake_tls", "wrong_seq", "tls_padding"]"#,
        ] {
            let cfg: Config = toml::from_str(&format!(
                r#"LISTEN_HOST = "127.0.0.1"
                   LISTEN_PORT = 44444
                   BYPASS_METHOD = {method}"#
            ))
            .unwrap();
            cfg.validate().unwrap();
        }
    }

    #[test]
    fn ip_bypass_plus_rejects_fake_tls() {
        let cfg: Config = toml::from_str(
            r#"LISTEN_HOST = "127.0.0.1"
               LISTEN_PORT = 44444
               MODE = "ip_bypass_plus"
               BYPASS_METHOD = "fake_tls""#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_bypass_method() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "quantum_tunneling"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_empty_method_list() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = []
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_method_entries() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = ["wrong_seq", "wrong_seq"]
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_method_via_alias_expansion() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = ["wrong_seq_tls_frag", "wrong_seq"]
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_urg_sni_split_with_handshake_method() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = ["urg_sni_split", "wrong_seq"]
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_urg_sni_split_with_data_stage() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = ["urg_sni_split", "tls_frag"]
            LOW_TTL_DISCOVER = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn accepts_handshake_and_data_stage_combination() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = ["wrong_seq", "low_ttl", "tls_frag"]
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn accepts_low_ttl_discover_without_low_ttl_method() {
        // Discovery is skipped at runtime when `low_ttl` is not in the list;
        // the config must still load.
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_seq"
            LOW_TTL_DISCOVER = true
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn linux_firewall_backend_accepts_nftables() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            LINUX_FIREWALL_BACKEND = "nftables"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.linux_firewall_backend(), LinuxFirewallBackend::Nftables);
    }

    #[test]
    fn rejects_unknown_linux_firewall_backend() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            LINUX_FIREWALL_BACKEND = "pf"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn parses_all_fields() {
        let toml_str = r#"
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            SNI_LIST = "/etc/zerodpi/sni_list.txt"
            SCAN_TIMEOUT_SECS = 10
            AUTO_SELECT = true
            RESCAN_INTERVAL_SECS = 300
            SNI_SWITCH_MIN_SCORE = 40
            SELECTED_SNI = "auth.vercel.com"
            BYPASS_METHOD = "wrong_seq"
            LOW_TTL_DISCOVER = false
            NFQUEUE_NUM = 2
            LINUX_FIREWALL_BACKEND = "nftables"
            WRONG_SEQ_EXTRA_OFFSET = 100
            WRONG_SEQ_SET_PSH = false
            WRONG_SEQ_BUMP_IP_IDENT = false
            WRONG_CHECKSUM_DELTA = 9
            WRONG_CHECKSUM_SET_PSH = false
            WRONG_CHECKSUM_BUMP_IP_IDENT = false
            WRONG_CHECKSUM_COMPLETE_IMMEDIATELY = false
            WRONG_MD5_SET_PSH = false
            WRONG_MD5_BUMP_IP_IDENT = false
            WRONG_MD5_COMPLETE_IMMEDIATELY = false
            WRONG_ACK_OFFSET = 11
            WRONG_ACK_SET_PSH = false
            WRONG_ACK_BUMP_IP_IDENT = false
            WRONG_ACK_COMPLETE_IMMEDIATELY = false
            WRONG_TIMESTAMP_OFFSET = 13
            WRONG_TIMESTAMP_SET_PSH = false
            WRONG_TIMESTAMP_BUMP_IP_IDENT = false
            WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY = false
            BYPASS_TIMEOUT_SECS = 5
            RELAY_MAX_LIFETIME_SECS = 7200
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.SNI_LIST, "/etc/zerodpi/sni_list.txt");
        assert_eq!(cfg.SCAN_TIMEOUT_SECS, 10);
        assert!(cfg.AUTO_SELECT);
        assert_eq!(cfg.RESCAN_INTERVAL_SECS, 300);
        assert_eq!(cfg.SNI_SWITCH_MIN_SCORE, 40);
        assert_eq!(cfg.SELECTED_SNI.as_deref(), Some("auth.vercel.com"));
        assert_eq!(cfg.linux_firewall_backend(), LinuxFirewallBackend::Nftables);
        assert_eq!(cfg.WRONG_SEQ_EXTRA_OFFSET, 100);
        assert!(!cfg.WRONG_SEQ_SET_PSH);
        assert!(!cfg.WRONG_SEQ_BUMP_IP_IDENT);
        assert_eq!(cfg.WRONG_CHECKSUM_DELTA, 9);
        assert!(!cfg.WRONG_CHECKSUM_SET_PSH);
        assert!(!cfg.WRONG_CHECKSUM_BUMP_IP_IDENT);
        assert!(!cfg.WRONG_CHECKSUM_COMPLETE_IMMEDIATELY);
        assert!(!cfg.WRONG_MD5_SET_PSH);
        assert!(!cfg.WRONG_MD5_BUMP_IP_IDENT);
        assert!(!cfg.WRONG_MD5_COMPLETE_IMMEDIATELY);
        assert_eq!(cfg.WRONG_ACK_OFFSET, 11);
        assert!(!cfg.WRONG_ACK_SET_PSH);
        assert!(!cfg.WRONG_ACK_BUMP_IP_IDENT);
        assert!(!cfg.WRONG_ACK_COMPLETE_IMMEDIATELY);
        assert_eq!(cfg.WRONG_TIMESTAMP_OFFSET, 13);
        assert!(!cfg.WRONG_TIMESTAMP_SET_PSH);
        assert!(!cfg.WRONG_TIMESTAMP_BUMP_IP_IDENT);
        assert!(!cfg.WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY);
        assert_eq!(cfg.BYPASS_TIMEOUT_SECS, 5);
        assert_eq!(cfg.RELAY_MAX_LIFETIME_SECS, 7200);
    }

    #[test]
    fn wrong_seq_tls_frag_accepted_by_validate() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_seq_tls_frag"
            LOW_TTL_DISCOVER = false
            TCP_SEG_SIZE = 9
            TCP_SEG_NODELAY = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.BYPASS_METHOD.iter().collect::<Vec<_>>(),
            vec!["wrong_seq", "tls_frag"]
        );
        assert_eq!(cfg.WRONG_SEQ_EXTRA_OFFSET, 0);
        assert_eq!(cfg.TCP_SEG_SIZE, 9);
        assert!(!cfg.TCP_SEG_NODELAY);
    }

    #[test]
    fn wrong_md5_tls_frag_accepted_by_validate() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_md5_tls_frag"
            LOW_TTL_DISCOVER = false
            WRONG_MD5_SET_PSH = false
            WRONG_MD5_BUMP_IP_IDENT = false
            WRONG_MD5_COMPLETE_IMMEDIATELY = false
            TCP_SEG_SIZE = 9
            TCP_SEG_NODELAY = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.BYPASS_METHOD.iter().collect::<Vec<_>>(),
            vec!["wrong_md5", "tls_frag"]
        );
        assert!(!cfg.WRONG_MD5_SET_PSH);
        assert!(!cfg.WRONG_MD5_BUMP_IP_IDENT);
        assert!(!cfg.WRONG_MD5_COMPLETE_IMMEDIATELY);
        assert_eq!(cfg.TCP_SEG_SIZE, 9);
        assert!(!cfg.TCP_SEG_NODELAY);
    }

    #[test]
    fn wrong_seq_tls_record_frag_accepted_by_validate() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_seq_tls_record_frag"
            LOW_TTL_DISCOVER = false
            TLS_RECORD_FRAG_SIZE = 7
            TLS_RECORD_FRAG_SET_PSH = false
            TLS_RECORD_FRAG_BUMP_IP_IDENT = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.BYPASS_METHOD.iter().collect::<Vec<_>>(),
            vec!["wrong_seq", "tls_record_frag"]
        );
        assert_eq!(cfg.WRONG_SEQ_EXTRA_OFFSET, 0);
        assert_eq!(cfg.TLS_RECORD_FRAG_SIZE, 7);
        assert!(!cfg.TLS_RECORD_FRAG_SET_PSH);
        assert!(!cfg.TLS_RECORD_FRAG_BUMP_IP_IDENT);
    }

    #[test]
    fn rejects_negative_relay_max_lifetime() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            RELAY_MAX_LIFETIME_SECS = -1
        "#;
        assert!(toml::from_str::<Config>(toml_str).is_err());
    }

    #[test]
    fn rejects_zero_timeout() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            SCAN_TIMEOUT_SECS = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_bypass_timeout() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_TIMEOUT_SECS = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_sni_switch_score_above_100() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            SNI_SWITCH_MIN_SCORE = 101
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_sni_too_long() {
        // MAX_SNI_LEN is 219; build a hostname that exceeds it.
        let long_sni = "a".repeat(MAX_SNI_LEN + 1);
        let toml_str = format!(
            r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            SELECTED_SNI = "{long_sni}"
        "#
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_sni_at_max_len() {
        let max_sni = "a".repeat(MAX_SNI_LEN);
        let toml_str = format!(
            r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            SELECTED_SNI = "{max_sni}"
        "#
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn ip_bypass_mode_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "ip_bypass"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.MODE, "ip_bypass");
        assert_eq!(cfg.IP_LIST, "ip_list.txt");
        assert_eq!(cfg.IP_SCAN_SNI, "cloudflare.com");
        assert_eq!(cfg.IPV6_MAX_HOSTS, 65536);
        assert!(cfg.SELECTED_IP.is_none());
    }

    #[test]
    fn ip_bypass_mode_selected_ip() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "ip_bypass"
            SELECTED_IP = "1.2.3.4"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.SELECTED_IP.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn ip_bypass_plus_accepts_tls_record_frag() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "ip_bypass_plus"
            BYPASS_METHOD = "tls_record_frag"
            LOW_TTL_DISCOVER = false
            SELECTED_IP = "1.2.3.4"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.MODE, "ip_bypass_plus");
        assert_eq!(cfg.BYPASS_METHOD, "tls_record_frag");
    }

    #[test]
    fn ip_bypass_plus_accepts_tls_frag() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "ip_bypass_plus"
            BYPASS_METHOD = "tls_frag"
            LOW_TTL_DISCOVER = false
            SELECTED_IP = "1.2.3.4"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.MODE, "ip_bypass_plus");
        assert_eq!(cfg.BYPASS_METHOD, "tls_frag");
    }

    #[test]
    fn ip_bypass_plus_rejects_fake_sni_methods() {
        for method in [
            "wrong_seq",
            "wrong_checksum",
            "wrong_md5",
            "wrong_seq_wrong_md5",
            "wrong_ack",
            "wrong_timestamp",
            "low_ttl",
            "wrong_seq_tls_frag",
            "wrong_md5_tls_frag",
            "wrong_seq_tls_record_frag",
        ] {
            let toml_str = format!(
                r#"
                LISTEN_HOST = "0.0.0.0"
                LISTEN_PORT = 40443
                MODE = "ip_bypass_plus"
                BYPASS_METHOD = "{method}"
                SELECTED_IP = "1.2.3.4"
            "#
            );
            let cfg: Config = toml::from_str(&toml_str).unwrap();
            assert!(
                cfg.validate().is_err(),
                "ip_bypass_plus accepted method {method}"
            );
        }
    }

    #[test]
    fn ip_bypass_plus_rejects_ipv6_selected_ip() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "ip_bypass_plus"
            BYPASS_METHOD = "tls_frag"
            SELECTED_IP = "2606:4700:4700::1111"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_invalid_selected_ip() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "ip_bypass"
            SELECTED_IP = "not-an-ip"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_mode() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "turbo_bypass"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn sni_scan_mode_valid() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "sni_scan"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.MODE, "sni_scan");
        assert!(cfg.SCAN_OUTPUT.is_none());
    }

    #[test]
    fn ip_scan_mode_valid() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "ip_scan"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.MODE, "ip_scan");
    }

    #[test]
    fn scan_output_field_parsed() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "sni_scan"
            SCAN_OUTPUT = "results.json"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.SCAN_OUTPUT.as_deref(), Some("results.json"));
    }

    #[test]
    fn scanner_upload_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.SCAN_UPLOAD_CAP, 10_240);
        assert_eq!(cfg.SCAN_UPLOAD_PATH, "/");
        assert!((cfg.UPLOAD_SPEED_CAP_BPS - 2_048_000.0).abs() < 1e-9);
    }

    #[test]
    fn parses_scanner_upload_fields() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            SCAN_UPLOAD_CAP = 32768
            SCAN_UPLOAD_PATH = "/upload"
            UPLOAD_SPEED_CAP_BPS = 4096000.0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.SCAN_UPLOAD_CAP, 32_768);
        assert_eq!(cfg.SCAN_UPLOAD_PATH, "/upload");
        assert!((cfg.UPLOAD_SPEED_CAP_BPS - 4_096_000.0).abs() < 1e-9);
    }

    #[test]
    fn rejects_zero_scan_upload_cap() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            SCAN_UPLOAD_CAP = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_invalid_scan_upload_path() {
        for path in ["", "upload"] {
            let toml_str = format!(
                r#"
                LISTEN_HOST = "0.0.0.0"
                LISTEN_PORT = 40443
                SCAN_UPLOAD_PATH = "{path}"
            "#
            );
            let cfg: Config = toml::from_str(&toml_str).unwrap();
            assert!(cfg.validate().is_err());
        }

        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            SCAN_UPLOAD_PATH = "/bad\r\nInjected: yes"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_upload_speed_cap() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            UPLOAD_SPEED_CAP_BPS = 0.0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn proxy_scan_mode_valid() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "proxy_scan"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.MODE, "proxy_scan");
        // Check all proxy_scan defaults.
        assert_eq!(cfg.PROXY_TEST_MIN_SNI_SCORE, 1);
        assert_eq!(cfg.PROXY_TEST_TOP_N, 0);
        assert_eq!(cfg.PROXY_TEST_SOCKS5_HOST, "127.0.0.1");
        assert_eq!(cfg.PROXY_TEST_SOCKS5_PORT, 10808);
        assert_eq!(
            cfg.PROXY_TEST_URL,
            "https://speed.cloudflare.com/__down?bytes=524288"
        );
        assert_eq!(cfg.PROXY_TEST_TIMEOUT_SECS, 30);
        assert!((cfg.PROXY_TEST_SNI_WEIGHT - 0.5).abs() < 1e-9);
        assert!((cfg.PROXY_TEST_LATENCY_CAP_MS - 500.0).abs() < 1e-9);
        assert!((cfg.PROXY_TEST_TTFB_CAP_MS - 3_000.0).abs() < 1e-9);
        assert!((cfg.PROXY_TEST_SPEED_CAP_BPS - 2_048_000.0).abs() < 1e-9);
    }

    #[test]
    fn proxy_scan_rejects_invalid_sni_weight() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "proxy_scan"
            PROXY_TEST_SNI_WEIGHT = 1.5
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn proxy_scan_rejects_zero_timeout() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "proxy_scan"
            PROXY_TEST_TIMEOUT_SECS = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    // -----------------------------------------------------------------------
    // tls_frag tests
    // -----------------------------------------------------------------------

    #[test]
    fn tls_frag_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_frag"
            LOW_TTL_DISCOVER = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.BYPASS_METHOD, "tls_frag");
        assert_eq!(
            cfg.tls_frag_packets().unwrap(),
            TlsFragPackets::WriteRange { start: 1, end: 3 }
        );
        assert_eq!(
            cfg.tls_frag_length_range().unwrap(),
            Int32Range { min: 100, max: 200 }
        );
        assert_eq!(cfg.TLS_FRAG_INTERVAL_MS, Int32Range { min: 10, max: 20 });
        assert_eq!(cfg.TCP_SEG_SIZE, 1);
        assert!(cfg.TCP_SEG_NODELAY);
    }

    #[test]
    fn parses_tls_frag_fields() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_frag"
            LOW_TTL_DISCOVER = false
            TCP_SEG_SIZE = 16
            TCP_SEG_NODELAY = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.TLS_FRAG_LENGTH, Some(Int32Range { min: 100, max: 200 }));
        assert_eq!(
            cfg.tls_frag_length_range().unwrap(),
            Int32Range { min: 100, max: 200 }
        );
        assert_eq!(cfg.TCP_SEG_SIZE, 16);
        assert!(!cfg.TCP_SEG_NODELAY);
    }

    #[test]
    fn parses_tls_frag_xray_style_fields() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_frag"
            LOW_TTL_DISCOVER = false
            TLS_FRAG_PACKETS = "1-3"
            TLS_FRAG_LENGTH = "2-7"
            TLS_FRAG_INTERVAL_MS = "0-10"
            TCP_SEG_SIZE = 16
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.tls_frag_packets().unwrap(),
            TlsFragPackets::WriteRange { start: 1, end: 3 }
        );
        assert_eq!(
            cfg.tls_frag_length_range().unwrap(),
            Int32Range { min: 2, max: 7 }
        );
        assert_eq!(cfg.TLS_FRAG_INTERVAL_MS, Int32Range { min: 0, max: 10 });
    }

    #[test]
    fn parses_tls_frag_integer_ranges() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_frag"
            LOW_TTL_DISCOVER = false
            TLS_FRAG_PACKETS = "2"
            TLS_FRAG_LENGTH = 5
            TLS_FRAG_INTERVAL_MS = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            cfg.tls_frag_packets().unwrap(),
            TlsFragPackets::WriteRange { start: 2, end: 2 }
        );
        assert_eq!(cfg.tls_frag_length_range().unwrap(), Int32Range::exact(5));
        assert_eq!(cfg.TLS_FRAG_INTERVAL_MS, Int32Range::exact(0));
    }

    #[test]
    fn rejects_invalid_tls_frag_packets() {
        for packets in ["", "0-3", "3-1", "abc"] {
            let toml_str = format!(
                r#"
                LISTEN_HOST = "0.0.0.0"
                LISTEN_PORT = 40443
                BYPASS_METHOD = "tls_frag"
                TLS_FRAG_PACKETS = "{packets}"
            "#
            );
            let cfg: Config = toml::from_str(&toml_str).unwrap();
            assert!(
                cfg.validate().is_err(),
                "accepted invalid TLS_FRAG_PACKETS={packets:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_tls_frag_ranges() {
        let bad_length = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_frag"
            TLS_FRAG_LENGTH = "0-5"
        "#;
        let cfg: Config = toml::from_str(bad_length).unwrap();
        assert!(cfg.validate().is_err());

        let bad_interval = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_frag"
            TLS_FRAG_INTERVAL_MS = -1
        "#;
        let cfg: Config = toml::from_str(bad_interval).unwrap();
        assert!(cfg.validate().is_err());

        let reversed = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_frag"
            TLS_FRAG_LENGTH = "9-2"
        "#;
        assert!(toml::from_str::<Config>(reversed).is_err());
    }

    #[test]
    fn rejects_tcp_seg_size_zero() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_frag"
            TCP_SEG_SIZE = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn tls_frag_accepted_by_validate() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_frag"
            LOW_TTL_DISCOVER = false
            TCP_SEG_SIZE = 100
            TCP_SEG_NODELAY = true
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_old_tcp_segmentation_method_name() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tcp_segmentation"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn custom_dns_defaults_to_system_resolver() {
        let cfg: Config = toml::from_str(
            r#"
            LISTEN_HOST = "127.0.0.1"
            LISTEN_PORT = 44444
            "#,
        )
        .unwrap();

        assert!(!cfg.CUSTOM_DNS_ENABLED);
        assert_eq!(cfg.CUSTOM_DNS_SERVER, None);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validates_enabled_custom_dns_server() {
        for server in [
            "1.1.1.1",
            "1.1.1.1:5353",
            "2606:4700:4700::1111",
            "[2606:4700:4700::1111]:5353",
        ] {
            let toml_str = format!(
                r#"
                LISTEN_HOST = "127.0.0.1"
                LISTEN_PORT = 44444
                CUSTOM_DNS_ENABLED = true
                CUSTOM_DNS_SERVER = "{server}"
                "#
            );
            let cfg: Config = toml::from_str(&toml_str).unwrap();
            assert!(cfg.validate().is_ok(), "rejected {server}");
        }
    }

    #[test]
    fn rejects_missing_or_invalid_enabled_custom_dns_server() {
        for server_line in [
            "",
            "CUSTOM_DNS_SERVER = \"\"",
            "CUSTOM_DNS_SERVER = \"dns.example.com\"",
            "CUSTOM_DNS_SERVER = \"1.1.1.1:0\"",
        ] {
            let toml_str = format!(
                r#"
                LISTEN_HOST = "127.0.0.1"
                LISTEN_PORT = 44444
                CUSTOM_DNS_ENABLED = true
                {server_line}
                "#
            );
            let cfg: Config = toml::from_str(&toml_str).unwrap();
            assert!(cfg.validate().is_err(), "accepted {server_line:?}");
        }
    }

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
        assert_eq!(
            cfg.SNI_BOUNDARY_FRAG_DELAY_MS,
            Int32Range { min: 5, max: 10 }
        );
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
        assert_eq!(
            cfg.SNI_BOUNDARY_FRAG_SPLIT_POINT,
            SniBoundarySplitPoint::Index(3)
        );
        assert_eq!(
            cfg.SNI_BOUNDARY_FRAG_DELAY_MS,
            Int32Range { min: 7, max: 9 }
        );
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
}
