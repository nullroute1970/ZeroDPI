# 🛡️ ZeroDPI

> **Cross-platform DPI bypass proxy** — written in Rust, works on **Windows**, **Linux**, and **rooted Android/Termux**.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20android-blue)

ZeroDPI sits between your **upstream VPN app** (xray-core, sing-box, v2ray, Hysteria, etc.) and the internet, transparently evading **Deep Packet Inspection (DPI)** that would otherwise block or throttle your VPN traffic.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🧩 **4 bypass methods** | `wrong_seq`, `wrong_checksum`, `tls_record_frag`, `tcp_segmentation` |
| 🎯 **5 operating modes** | `sni_spoof`, `ip_bypass`, `sni_scan`, `ip_scan`, `proxy_scan` |
| 🖥️ **TUI dashboard** | Ratatui-powered live progress, selection tables, and connection monitoring |
| 🔄 **Auto-rescan** | Background re-scanning hot-swaps the best target without restart |
| 🧪 **Smart scoring** | Unified 0–100 composite score across TCP, TLS, TTFB, speed, and cert validity |
| ⚡ **Concurrent scanning** | Configurable concurrency per phase for fast results |
| 🔌 **Protocol agnostic** | Raw TCP relay — works with any TLS-based VPN protocol |
| 🪟 **Windows** | WinDivert packet interception |
| 🐧 **Linux / Android** | NFQUEUE packet interception |

---

## 🏗️ Project Layout

```
📦 zerodpi/
├── 📁 crates/
│   ├── 📁 zerodpi-core/        # Platform-independent: config, TLS templates,
│   │                           #   flow tracking, bypass methods, scanners
│   ├── 📁 zerodpi-platform/    # Packet interception: WinDivert (win), NFQUEUE (nix)
│   └── 📁 zerodpi/             # CLI binary + ratatui TUI
├── 📄 config.toml              # Configuration file
├── 📄 sni_list.txt             # Decoy CDN hostnames (sni_spoof mode)
├── 📄 ip_list.txt              # Relay IPs / CIDR ranges (ip_bypass mode)
├── 📁 windivert/               # Windows: WinDivert.dll, .lib, .sys
└── 🐍 build.py                 # Cross-platform packaging script
```

---

## 🚀 Operating Modes

### 1️⃣ `sni_spoof` (default) — TLS SNI Spoofing

Injects a **decoy ClientHello** with a harmless CDN-hosted SNI (e.g. `auth.vercel.com`) that the DPI classifies as benign. The decoy uses a deliberately broken TCP sequence or checksum so the real upstream server discards it — but the DPI has already passed the flow. Your real ClientHello then passes through unchallenged.

```
🖥️ Local apps → 🌐 VPN App → 🔄 ZeroDPI (sni_spoof) → 🌍 CDN Edge → 🖥️ VPN Server
                 SOCKS :44444                         TCP :443
```

**Use when:** Your VPN server sits behind a CDN and you have CDN-hosted hostnames.

---

### 2️⃣ `ip_bypass` — Pure TCP Relay

No packet interception, no SNI manipulation. Scans a list of IPs (or CIDR ranges), picks the best one via a 4-phase quality test, and relays all connections through it.

```
🖥️ Local apps → 🌐 VPN App → 🔄 ZeroDPI (ip_bypass) → 🌍 Selected IP :443
                 SOCKS :44444                         Raw TCP (SNI untouched)
```

**Use when:** No CDN hostname is available, or you just need a reliable relay point.

---

### 3️⃣ `sni_scan` — SNI Scan-Only

Runs the full SNI scan pipeline (same as `sni_spoof`), displays ranked results, optionally saves to JSON, then exits. **No proxy is started.**

**Use for:** Auditing `sni_list.txt` before deployment.

---

### 4️⃣ `ip_scan` — IP Scan-Only

Runs the full IP scan pipeline (same as `ip_bypass`), displays ranked results, optionally saves to JSON, then exits. **No proxy is started.**

**Use for:** Auditing `ip_list.txt` before deployment.

---

### 5️⃣ `proxy_scan` — End-to-End Proxy Scan 🔬

A two-phase hybrid scan:

1. **Phase 1** — Standard SNI scan (`sni_list.txt`)
2. **Phase 2** — For each passing candidate, opens a SOCKS5 connection through your running V2RayN/sing-box instance and measures real-world TCP latency, TTFB, and download speed

Results are blended using a configurable weight and displayed in the TUI.

**Use for:** Evaluating how each SNI candidate performs end-to-end through your actual proxy setup.

---

## 🧠 Bypass Methods

| Method | Mechanism | Requires Packet Interception? | Best For |
|--------|-----------|:---:|---|
| `wrong_seq` | Injects fake ClientHello with deliberately old TCP sequence number | ✅ Yes (WinDivert/NFQUEUE) | Most DPI systems |
| `wrong_checksum` | Injects fake ClientHello with corrupted TCP checksum | ✅ Yes | DPI that doesn't verify checksums |
| `tls_record_frag` | Splits real ClientHello into multiple tiny TLS records | ✅ Yes | DPI that can't reassemble TLS fragments |
| `tcp_segmentation` | Writes real ClientHello in tiny TCP segments (no packet interception) | ❌ No | DPI that inspects individual TCP segments |

---

## ⚙️ Configuration Reference

All fields go in `config.toml` (loaded from the binary's directory, or via `--config <path>`). Every field has a sensible default — start minimal and override as needed.

### 🔌 Proxy Listener

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `LISTEN_HOST` | `string` | `"127.0.0.1"` | IP address to bind the local TCP proxy |
| `LISTEN_PORT` | `u16` | `44444` | TCP port for the local proxy |

### 🎮 Operating Mode

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `MODE` | `string` | `"sni_spoof"` | One of: `sni_spoof`, `ip_bypass`, `sni_scan`, `ip_scan`, `proxy_scan` |
| `AUTO_SELECT` | `bool` | `false` | Auto-pick rank-1 after scan (skip manual selection table) |
| `SELECTED_SNI` | `string` | — | Skip SNI scan; use this hostname directly |
| `SELECTED_IP` | `string` | — | Skip IP scan; use this IP directly |

### 📂 Input Files

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `SNI_LIST` | `string` | `"sni_list.txt"` | Path to decoy SNI hostname file (one per line) |
| `IP_LIST` | `string` | `"ip_list.txt"` | Path to IP list file (plain IPs or CIDR ranges) |

### 🔍 Scan Behavior

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `SCAN_TIMEOUT_SECS` | `u64` | `5` | Per-probe timeout (seconds) |
| `RESCAN_INTERVAL_SECS` | `u64` | `0` | Background rescan interval (`0` = disabled) |
| `SNI_SWITCH_MIN_SCORE` | `u8` | `1` | Minimum score to auto-switch target on rescan (0–100) |
| `SCAN_OUTPUT` | `string` | — | Path to save scan results as JSON (scan-only modes) |

### ⚡ Scanner Tuning

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `SNI_MAX_CONCURRENT` | `usize` | `64` | Max concurrent SNI probes |
| `IP_MAX_P1_CONCURRENT` | `usize` | `128` | Max concurrent TCP connections in IP phase 1 |
| `IP_MAX_P2_CONCURRENT` | `usize` | `32` | Max concurrent TLS probes in IP phase 2 |
| `SCAN_DOWNLOAD_CAP` | `usize` | `10240` | Max bytes downloaded for speed tests |
| `IP_SCAN_SNI` | `string` | `"cloudflare.com"` | SNI used during IP scan TLS phase only |
| `IPV6_MAX_HOSTS` | `u64` | `65536` | Max hosts expanded from a single IPv6 CIDR |

### 📊 Scoring Parameters

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `TCP_LATENCY_CAP_MS` | `f64` | `500.0` | TCP latency cap for scoring (ms) |
| `TLS_LATENCY_CAP_MS` | `f64` | `1000.0` | TLS handshake latency cap (ms) |
| `TTFB_CAP_MS` | `f64` | `2000.0` | Time-to-first-byte cap (ms) |
| `SPEED_CAP_BPS` | `f64` | `2048000` | Download speed cap for scoring (bytes/sec) |

### 🛠️ Bypass Engine

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `BYPASS_METHOD` | `string` | `"wrong_seq"` | `wrong_seq`, `wrong_checksum`, `tls_record_frag`, or `tcp_segmentation` |
| `BYPASS_TIMEOUT_SECS` | `u64` | `2` | Time to wait for bypass ACK before giving up |
| `NFQUEUE_NUM` | `u16` | `1` | (Linux) NFQUEUE queue number |

#### `wrong_seq` Parameters

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `WRONG_SEQ_EXTRA_OFFSET` | `u32` | `0` | Extra bytes subtracted from injected TCP seq number |
| `WRONG_SEQ_SET_PSH` | `bool` | `true` | Set PSH flag on the spoofed packet |
| `WRONG_SEQ_BUMP_IP_IDENT` | `bool` | `true` | Bump IPv4 Identification field |

#### `wrong_checksum` Parameters

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `WRONG_CHECKSUM_DELTA` | `u16` | `1` | Value added to corrupt TCP checksum (≥ 1) |
| `WRONG_CHECKSUM_SET_PSH` | `bool` | `true` | Set PSH flag on the spoofed packet |
| `WRONG_CHECKSUM_BUMP_IP_IDENT` | `bool` | `true` | Bump IPv4 Identification field |
| `WRONG_CHECKSUM_COMPLETE_IMMEDIATELY` | `bool` | `true` | Signal bypass complete immediately after emission |

#### `tls_record_frag` Parameters

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `TLS_RECORD_FRAG_SIZE` | `usize` | `1` | Max payload bytes per TLS record fragment (≥ 1) |
| `TLS_RECORD_FRAG_SET_PSH` | `bool` | `true` | Set PSH flag on the fragmented packet |
| `TLS_RECORD_FRAG_BUMP_IP_IDENT` | `bool` | `true` | Bump IPv4 Identification field |

#### `tcp_segmentation` Parameters

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `TCP_SEG_SIZE` | `usize` | `1` | Max payload bytes per TCP segment (≥ 1) |
| `TCP_SEG_NODELAY` | `bool` | `true` | Enable TCP_NODELAY to prevent Nagle coalescing |

### 🔬 Proxy Scan Mode (`proxy_scan`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `PROXY_TEST_MIN_SNI_SCORE` | `u8` | `1` | Min Phase-1 score to enter Phase 2 |
| `PROXY_TEST_TOP_N` | `usize` | `0` | Max candidates to carry into Phase 2 (`0` = all) |
| `PROXY_TEST_SOCKS5_HOST` | `string` | `"127.0.0.1"` | SOCKS5 proxy host |
| `PROXY_TEST_SOCKS5_PORT` | `u16` | `10808` | SOCKS5 proxy port |
| `PROXY_TEST_URL` | `string` | `"https://speed.cloudflare.com/__down?bytes=524288"` | HTTPS URL for speed test |
| `PROXY_TEST_TIMEOUT_SECS` | `u64` | `30` | Per-proxy-test probe timeout |
| `PROXY_TEST_SNI_WEIGHT` | `f64` | `0.5` | SNI-score blend weight (0.0–1.0) |
| `PROXY_TEST_LATENCY_CAP_MS` | `f64` | `500.0` | Proxy TCP latency cap (ms) |
| `PROXY_TEST_TTFB_CAP_MS` | `f64` | `3000.0` | Proxy TTFB cap (ms) |
| `PROXY_TEST_SPEED_CAP_BPS` | `f64` | `2048000` | Proxy speed cap (bytes/sec) |

---

## 📊 Unified Probe Scoring (0–100)

Both the SNI and IP scanners use the same scoring formula. Each `(SNI, IP)` pair or plain IP is evaluated across phases:

| Component | Max Pts | Formula |
|-----------|:-------:|---------|
| ✅ TCP latency | **25** | Linear: 0 ms → 25 pts, ≥ `TCP_LATENCY_CAP_MS` → 0 pts |
| 🔒 TLS success | **10** | Flat bonus for a successful TLS handshake |
| ⏱️ TLS latency | **15** | Linear: 0 ms → 15 pts, ≥ `TLS_LATENCY_CAP_MS` → 0 pts |
| 🏷️ Cert valid | **5** | Flat bonus for valid certificate (Mozilla roots via `webpki-roots`) |
| 🚀 TTFB | **20** | Linear: 0 ms → 20 pts, ≥ `TTFB_CAP_MS` → 0 pts |
| ⚡ Download speed | **15** | Linear: 0 B/s → 0 pts, ≥ `SPEED_CAP_BPS` → 15 pts |
| 🏆 All phases bonus | **10** | All five signals present |

**Tiebreaker:** Score (desc) → TCP latency (asc).

- **SNI probe endpoint:** `GET /` on each resolved IPv4 address.
- **IP probe endpoint:** `GET /cdn-cgi/trace` with `IP_SCAN_SNI` in the `Host` header.

---

## 🖥️ Interactive TUI

ZeroDPI uses [ratatui](https://github.com/ratatui-org/ratatui) for a live terminal UI in every mode:

| Mode | View 1 | View 2 | View 3 |
|------|--------|--------|--------|
| `sni_spoof` | 📊 Scan progress (Score · SNI · IP · TCP · TLS · TTFB · Speed · HTTP) | 🎯 Selection table | 📈 Dashboard |
| `ip_bypass` | 📊 IP scan progress | 🎯 Selection table | 📈 Dashboard |
| `sni_scan` | 📊 Scan progress | 📋 Results table (view-only) | — |
| `ip_scan` | 📊 IP scan progress | 📋 Results table (view-only) | — |
| `proxy_scan` | 📊 Phase 1 + Phase 2 progress | 📋 Blended results table | — |

**Navigation:** `↑`/`↓` or `j`/`k` to move, `Enter` to confirm, `q`/`Esc` to skip to rank-1.

---

## 💻 CLI Reference

```
zerodpi [OPTIONS]

Options:
  -c, --config <PATH>                  Path to config.toml
      --listen-host <HOST>             Override LISTEN_HOST
      --listen-port <PORT>             Override LISTEN_PORT
      --auto-select                    Auto-select top-ranked candidate
      --no-tui                         Disable ratatui screens for headless/service runs
      --sni <SNI>                      Override SELECTED_SNI (skip scan)
      --method <METHOD>                Override BYPASS_METHOD
      --queue-num <N>                  Override NFQUEUE_NUM (Linux)
      --scan-timeout <SECS>            Override SCAN_TIMEOUT_SECS
      --rescan-interval <SECS>         Override RESCAN_INTERVAL_SECS
      --sni-switch-min-score <SCORE>   Override SNI_SWITCH_MIN_SCORE
      --wrong-seq-extra-offset <N>     Override WRONG_SEQ_EXTRA_OFFSET
      --wrong-seq-no-psh               Clear PSH flag (wrong_seq)
      --wrong-seq-no-bump-ident        Skip IPv4 ID bump (wrong_seq)
      --bypass-timeout <SECS>          Override BYPASS_TIMEOUT_SECS
  -h, --help                           Print help
  -V, --version                        Print version
```

---

## 🧩 Integrating with Upstream VPN Apps

Configure your VPN app to point to `LISTEN_HOST:LISTEN_PORT` (default: `127.0.0.1:44444`) instead of your actual VPN server. ZeroDPI handles the DPI bypass and relays the raw TCP stream.

<details>
<summary><b>xray-core</b> (click to expand)</summary>

```json
{
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": 44444,
            "users": [{ "id": "<uuid>", "encryption": "none" }]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "your.vpn.domain.com"
        }
      }
    }
  ]
}
```
</details>

<details>
<summary><b>sing-box</b> (click to expand)</summary>

```json
{
  "outbounds": [
    {
      "type": "vless",
      "tag": "proxy",
      "server": "127.0.0.1",
      "server_port": 44444,
      "uuid": "<uuid>",
      "tls": {
        "enabled": true,
        "server_name": "your.vpn.domain.com"
      }
    }
  ]
}
```
</details>

**Protocol agnostic** — ZeroDPI relays raw TCP bytes. Any TLS-based VPN protocol works.

---

## 📝 Choosing Decoy SNIs (`sni_list.txt`)

1. **Same CDN** — Decoy hostnames must resolve to CDN edge IPs that also terminate your VPN server domain.
2. **Low latency** — ZeroDPI ranks candidates automatically; pick from the top.

```
# Example sni_list.txt
cloudflare.com
auth.vercel.com
www.fastly.com
```

---

## 📝 IP List (`ip_list.txt`)

```
# Plain IPv4
104.16.132.229
# Plain IPv6
2606:4700::6810:84e5
# IPv4 CIDR
104.16.0.0/24
# IPv6 CIDR (capped at IPV6_MAX_HOSTS)
2606:4700::/32
```

Hostnames are silently skipped — IPs and CIDRs only.

---

## 🏃 Running

### 🐧 Linux

```sh
sudo ./zerodpi --config ./config.toml
```

Requires `CAP_NET_ADMIN` (or root). iptables rules are installed on startup and **automatically removed on shutdown**.

### 🪟 Windows

```powershell
.\zerodpi.exe --config .\config.toml
```

Run from an **Administrator** prompt. Requires `WinDivert.dll` and `WinDivert64.sys` next to the EXE.

### 📱 Android / Termux

```sh
./zerodpi --config ./config.toml
```

Requires root, `iptables`, and a kernel with NFQUEUE support.

---

## 🔨 Building from Source

```sh
cargo build --release
```

<details>
<summary><b>Linux</b> (click to expand)</summary>

```sh
sudo apt-get install libnetfilter-queue-dev
cargo build --release
```
</details>

<details>
<summary><b>Windows</b> (click to expand)</summary>

Requires MSYS2 and the GNU toolchain. When using `build.py`, WinDivert is downloaded into the repo-local `windivert/` folder automatically.

```powershell
cargo +stable-x86_64-pc-windows-gnu build --release
```

Or use the build script:

```sh
python build.py --platform windows
```
</details>

<details>
<summary><b>Android / Termux</b> (click to expand)</summary>

```sh
python build.py --platform termux --termux-arch aarch64 --android-ndk /path/to/android-ndk
```

Output staged under `dist/termux/<arch>/`.
</details>

---

## ✅ Testing

```sh
cargo test --workspace
```

Unit tests cover:
- 🔄 TLS ClientHello byte-exact round-trip
- 🏗️ Handshake state machine
- 📦 IPv4/TCP packet rewrite and checksum recomputation
- ⚙️ Config parsing (all fields, defaults, validation modes)
- 📊 SNI & IP scanner unified scoring
- 🌐 CIDR expansion, IPv6 cap, hostname skipping

---

## 🧩 Extending

| Task | Interface / Location |
|------|---------------------|
| **New bypass method** | Implement [`zerodpi_core::methods::BypassMethod`] → register in `methods::build_method` |
| **New OS backend** | Implement [`zerodpi_core::interceptor::PacketInterceptor`] in `zerodpi-platform` |
| **New operating mode** | Add branch in `zerodpi/src/main.rs` guarded by `cfg.MODE` + implement proxy logic in `zerodpi-core::proxy` |

---

## 🙏 Credits

- Original Python project: [`patterniha/SNI-Spoofing`](https://github.com/patterniha/SNI-Spoofing)
- WinDivert: <https://reqrypt.org/windivert.html>

---

## 📄 License

MIT — see [LICENSE](LICENSE).
