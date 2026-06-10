//! Configuration loaded from `config.toml`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::interceptor::LinuxFirewallBackend;
use crate::tls_template::MAX_SNI_LEN;

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

    /// Per-probe timeout in seconds.
    /// Each (SNI, IP) combination is given this many seconds to complete all
    /// checks (DNS, TCP connect, TLS handshake, HTTP request).
    #[serde(default = "default_scan_timeout")]
    pub SCAN_TIMEOUT_SECS: u64,

    /// When `true` the application automatically picks the top-ranked entry
    /// after scanning instead of showing the manual selection table.
    /// TUI progress, result, and dashboard views are still shown.
    /// Default: `false`.
    #[serde(default)]
    pub AUTO_SELECT: bool,

    /// Rescan interval in seconds.  After the proxy starts the scanner runs
    /// again in the background every this many seconds and logs the new
    /// rankings.  Set to `0` to disable periodic rescanning.  Default: `0`.
    #[serde(default)]
    pub RESCAN_INTERVAL_SECS: u64,

    /// Minimum score required before a background SNI rescan is allowed to
    /// switch the active target. Default: `1`.
    #[serde(default = "default_sni_switch_min_score")]
    pub SNI_SWITCH_MIN_SCORE: u8,

    /// If set, skip scanning entirely and use this hostname as the SNI.
    /// The IP is resolved from DNS at startup.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub SELECTED_SNI: Option<String>,

    /// Bypass method to use.  Supported values:
    /// - `"wrong_seq"` (default) — injects a fake TLS ClientHello with a
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
    /// - `"tls_record_frag"` — TLS Record Fragment / TLS-layer fragmentation.
    ///   Splits the real ClientHello into multiple small TLS records so no
    ///   single record contains the full SNI. No fake packet is injected; the
    ///   server reassembles normally.
    /// - `"wrong_seq_tls_frag"` — injects a `wrong_seq` fake ClientHello,
    ///   then sends the intact real ClientHello in small TCP segments for
    ///   downstream DPI layers.
    /// - `"wrong_seq_tls_record_frag"` — injects a `wrong_seq` fake
    ///   ClientHello, then fragments the real ClientHello into multiple small
    ///   TLS records for downstream DPI layers.
    /// - `"tcp_segmentation"` — TLS Fragment / TCP-level fragmentation.
    ///   Splits a normal, intact TLS ClientHello record into multiple tiny TCP
    ///   segments so DPI cannot reassemble the SNI from any single packet.
    ///   Does **not** inject fake packets or use WinDivert/NFQUEUE interception;
    ///   operates entirely inside the proxy via controlled socket writes.
    #[serde(default = "default_method")]
    pub BYPASS_METHOD: String,
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
    /// the payload length.  The default formula positions the spoofed segment
    /// exactly at `syn_seq + 1 - payload_len`; adding an extra offset pushes
    /// it further behind `rcv_nxt` and can help on networks that perform
    /// tighter window checks.
    /// Must be `<= u32::MAX`.  Default: `0`.
    #[serde(default)]
    pub WRONG_SEQ_EXTRA_OFFSET: u32,

    /// Whether to set the `PSH` flag on the spoofed ClientHello packet.
    /// Most DPI implementations expect application data to carry `PSH`; keep
    /// this `true` unless you are debugging a specific DPI device.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub WRONG_SEQ_SET_PSH: bool,

    /// Whether to increment the IPv4 `Identification` field on the spoofed
    /// packet.  Bumping the ID makes the spoofed packet look like a fresh
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
    /// TCP-MD5-tagged fake packet. The default is `true` because a server
    /// without a negotiated MD5 key should reject or drop the segment.
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
    // tcp_segmentation method parameters
    // -----------------------------------------------------------------------
    /// Maximum ClientHello bytes sent in each TCP segment when using
    /// `tcp_segmentation` or `wrong_seq_tls_frag`.
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
    // Proxy timing
    // -----------------------------------------------------------------------
    /// How many seconds the proxy waits for the intercept thread to confirm
    /// that the spoofed packet was acknowledged before giving up on a
    /// connection.  Increase on very high-latency links.
    /// Must be `>= 1`.  Default: `2`.
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
fn default_method() -> String {
    "wrong_seq".into()
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
fn default_wrong_ack_offset() -> u32 {
    1
}
fn default_tls_frag_size() -> usize {
    1
}
fn default_tcp_seg_size() -> usize {
    1
}
fn default_bypass_timeout() -> u64 {
    2
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
        if self.SCAN_TIMEOUT_SECS == 0 {
            anyhow::bail!("SCAN_TIMEOUT_SECS must be > 0");
        }
        if self.BYPASS_TIMEOUT_SECS == 0 {
            anyhow::bail!("BYPASS_TIMEOUT_SECS must be > 0");
        }
        if self.SNI_SWITCH_MIN_SCORE > 100 {
            anyhow::bail!("SNI_SWITCH_MIN_SCORE must be <= 100");
        }
        if let Some(ref sni) = self.SELECTED_SNI {
            if sni.len() > MAX_SNI_LEN {
                anyhow::bail!(
                    "SELECTED_SNI is too long ({} bytes, max {MAX_SNI_LEN}): '{sni}'",
                    sni.len()
                );
            }
        }
        if !matches!(
            self.BYPASS_METHOD.as_str(),
            "wrong_seq"
                | "wrong_checksum"
                | "wrong_md5"
                | "wrong_ack"
                | "tls_record_frag"
                | "wrong_seq_tls_frag"
                | "wrong_seq_tls_record_frag"
                | "tcp_segmentation"
        ) {
            anyhow::bail!(
                "Unknown BYPASS_METHOD '{}'. Valid values: \"wrong_seq\", \"wrong_checksum\", \"wrong_md5\", \"wrong_ack\", \"tls_record_frag\", \"wrong_seq_tls_frag\", \"wrong_seq_tls_record_frag\", \"tcp_segmentation\"",
                self.BYPASS_METHOD
            );
        }
        if self.WRONG_CHECKSUM_DELTA == 0 {
            anyhow::bail!("WRONG_CHECKSUM_DELTA must be >= 1");
        }
        if self.WRONG_ACK_OFFSET == 0 {
            anyhow::bail!("WRONG_ACK_OFFSET must be >= 1");
        }
        if self.TLS_RECORD_FRAG_SIZE == 0 {
            anyhow::bail!("TLS_RECORD_FRAG_SIZE must be >= 1");
        }
        if self.TCP_SEG_SIZE == 0 {
            anyhow::bail!("TCP_SEG_SIZE must be >= 1");
        }
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
            && !matches!(
                self.BYPASS_METHOD.as_str(),
                "tls_record_frag" | "tcp_segmentation"
            )
        {
            anyhow::bail!(
                "MODE = \"ip_bypass_plus\" supports only real-SNI-preserving BYPASS_METHOD values: \"tls_record_frag\" or \"tcp_segmentation\""
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

    pub fn linux_firewall_backend(&self) -> LinuxFirewallBackend {
        LinuxFirewallBackend::parse(&self.LINUX_FIREWALL_BACKEND).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_toml() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.LISTEN_PORT, 40443);
        assert_eq!(cfg.BYPASS_METHOD, "wrong_seq");
        assert_eq!(cfg.NFQUEUE_NUM, 1);
        assert_eq!(cfg.LINUX_FIREWALL_BACKEND, "iptables");
        assert!(!cfg.AUTO_SELECT);
        assert_eq!(cfg.RESCAN_INTERVAL_SECS, 0);
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
        // wrong_md5 defaults
        assert!(cfg.WRONG_MD5_SET_PSH);
        assert!(cfg.WRONG_MD5_BUMP_IP_IDENT);
        assert!(cfg.WRONG_MD5_COMPLETE_IMMEDIATELY);
        // wrong_ack defaults
        assert_eq!(cfg.WRONG_ACK_OFFSET, 1);
        assert!(cfg.WRONG_ACK_SET_PSH);
        assert!(cfg.WRONG_ACK_BUMP_IP_IDENT);
        assert!(cfg.WRONG_ACK_COMPLETE_IMMEDIATELY);
        // tls_record_frag defaults
        assert_eq!(cfg.TLS_RECORD_FRAG_SIZE, 1);
        assert!(cfg.TLS_RECORD_FRAG_SET_PSH);
        assert!(cfg.TLS_RECORD_FRAG_BUMP_IP_IDENT);
        // tcp_segmentation defaults
        assert_eq!(cfg.TCP_SEG_SIZE, 1);
        assert!(cfg.TCP_SEG_NODELAY);
        // proxy timing defaults
        assert_eq!(cfg.BYPASS_TIMEOUT_SECS, 2);
        assert_eq!(cfg.RELAY_MAX_LIFETIME_SECS, 0);
    }

    #[test]
    fn wrong_checksum_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_checksum"
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
    fn wrong_md5_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_md5"
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
    fn wrong_ack_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_ack"
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
    fn tls_record_frag_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tls_record_frag"
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
        assert_eq!(cfg.BYPASS_TIMEOUT_SECS, 5);
        assert_eq!(cfg.RELAY_MAX_LIFETIME_SECS, 7200);
    }

    #[test]
    fn wrong_seq_tls_frag_accepted_by_validate() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_seq_tls_frag"
            TCP_SEG_SIZE = 9
            TCP_SEG_NODELAY = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.BYPASS_METHOD, "wrong_seq_tls_frag");
        assert_eq!(cfg.WRONG_SEQ_EXTRA_OFFSET, 0);
        assert_eq!(cfg.TCP_SEG_SIZE, 9);
        assert!(!cfg.TCP_SEG_NODELAY);
    }

    #[test]
    fn wrong_seq_tls_record_frag_accepted_by_validate() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "wrong_seq_tls_record_frag"
            TLS_RECORD_FRAG_SIZE = 7
            TLS_RECORD_FRAG_SET_PSH = false
            TLS_RECORD_FRAG_BUMP_IP_IDENT = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.BYPASS_METHOD, "wrong_seq_tls_record_frag");
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
            SELECTED_IP = "1.2.3.4"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.MODE, "ip_bypass_plus");
        assert_eq!(cfg.BYPASS_METHOD, "tls_record_frag");
    }

    #[test]
    fn ip_bypass_plus_accepts_tcp_segmentation() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            MODE = "ip_bypass_plus"
            BYPASS_METHOD = "tcp_segmentation"
            SELECTED_IP = "1.2.3.4"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.MODE, "ip_bypass_plus");
        assert_eq!(cfg.BYPASS_METHOD, "tcp_segmentation");
    }

    #[test]
    fn ip_bypass_plus_rejects_fake_sni_methods() {
        for method in [
            "wrong_seq",
            "wrong_checksum",
            "wrong_md5",
            "wrong_ack",
            "wrong_seq_tls_frag",
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
            BYPASS_METHOD = "tcp_segmentation"
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
    // tcp_segmentation tests
    // -----------------------------------------------------------------------

    #[test]
    fn tcp_segmentation_defaults() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tcp_segmentation"
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.BYPASS_METHOD, "tcp_segmentation");
        assert_eq!(cfg.TCP_SEG_SIZE, 1);
        assert!(cfg.TCP_SEG_NODELAY);
    }

    #[test]
    fn parses_tcp_segmentation_fields() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tcp_segmentation"
            TCP_SEG_SIZE = 16
            TCP_SEG_NODELAY = false
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.TCP_SEG_SIZE, 16);
        assert!(!cfg.TCP_SEG_NODELAY);
    }

    #[test]
    fn rejects_tcp_seg_size_zero() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tcp_segmentation"
            TCP_SEG_SIZE = 0
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn tcp_segmentation_accepted_by_validate() {
        let toml_str = r#"
            LISTEN_HOST = "0.0.0.0"
            LISTEN_PORT = 40443
            BYPASS_METHOD = "tcp_segmentation"
            TCP_SEG_SIZE = 100
            TCP_SEG_NODELAY = true
        "#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert!(cfg.validate().is_ok());
    }
}
