//! ZeroDPI: cross-platform DPI bypass via SNI spoofing.
//!
//! Start-up flow:
//!   1. Load `config.toml`.
//!   2. Read `sni_list.txt` (or the path set in `SNI_LIST`).
//!   3. If `SELECTED_SNI` is set, skip scanning; resolve the IP from DNS.
//!   4. Otherwise scan all SNIs concurrently (DNS → TCP → TLS → HTTP) and
//!      show the ratatui progress view, then either auto-select the top result
//!      (`AUTO_SELECT = true`) or show the selection table.
//!   5. Start the tokio TCP proxy and, for interceptor-based methods, the
//!      packet interceptor thread.
//!   6. If `RESCAN_INTERVAL_SECS > 0`, run the scanner again in the background
//!      every that many seconds and switch new connections to better targets.

mod tui;

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

use zerodpi_core::config::Config;
use zerodpi_core::flow::new_flow_table;
use zerodpi_core::handler::Handler;
use zerodpi_core::interceptor::{FilterSpec, PacketInterceptor};
use zerodpi_core::ip_scanner::{load_ip_list, scan_ip_list, IpProbeEntry, IpScanEvent};
use zerodpi_core::methods::build_method;
use zerodpi_core::net::default_interface_ipv4;
use zerodpi_core::proxy::{
    run_ip_bypass_proxy, run_proxy, ActiveSniTarget, ProxyEvent, ProxyEventSender, CONNECT_PORT,
};
use zerodpi_core::proxy_tester::{test_candidate_full, ProxyTestEntry};
use zerodpi_core::sni_scanner::{scan_sni_list, SniProbeEntry};
use zerodpi_platform::{ensure_packet_interception_access, DefaultInterceptor};

#[derive(Clone, Copy)]
struct TuiAwareStderr;

enum TuiAwareStderrGuard {
    Stderr(io::Stderr),
    Sink(io::Sink),
}

impl Write for TuiAwareStderrGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TuiAwareStderrGuard::Stderr(stderr) => stderr.write(buf),
            TuiAwareStderrGuard::Sink(sink) => sink.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TuiAwareStderrGuard::Stderr(stderr) => stderr.flush(),
            TuiAwareStderrGuard::Sink(sink) => sink.flush(),
        }
    }
}

impl<'a> MakeWriter<'a> for TuiAwareStderr {
    type Writer = TuiAwareStderrGuard;

    fn make_writer(&'a self) -> Self::Writer {
        if tui::is_tui_active() {
            TuiAwareStderrGuard::Sink(io::sink())
        } else {
            TuiAwareStderrGuard::Stderr(io::stderr())
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about = "Cross-platform DPI bypass via SNI spoofing")]
struct Args {
    /// Path to config.toml (defaults to one next to the binary).
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Override `LISTEN_HOST`.
    #[arg(long)]
    listen_host: Option<String>,
    /// Override `LISTEN_PORT`.
    #[arg(long)]
    listen_port: Option<u16>,
    /// Override `AUTO_SELECT` (automatically choose the top-ranked candidate).
    #[arg(long)]
    auto_select: bool,
    /// Disable ratatui screens; suitable for systemd and other headless runs.
    #[arg(long)]
    no_tui: bool,
    /// Override `SELECTED_SNI` — skip scanning and use this hostname.
    #[arg(long)]
    sni: Option<String>,
    /// Override `BYPASS_METHOD` (default: `wrong_seq`).
    #[arg(long)]
    method: Option<String>,
    /// Linux-only: NFQUEUE queue number to use.
    #[arg(long)]
    queue_num: Option<u16>,
    /// Override `SCAN_TIMEOUT_SECS`.
    #[arg(long)]
    scan_timeout: Option<u64>,
    /// Override `RESCAN_INTERVAL_SECS`.
    #[arg(long)]
    rescan_interval: Option<u64>,
    /// Override `SNI_SWITCH_MIN_SCORE`.
    #[arg(long)]
    sni_switch_min_score: Option<u8>,
    /// Override `WRONG_SEQ_EXTRA_OFFSET`: extra bytes subtracted from the
    /// injected TCP seq number beyond `payload_len`.
    #[arg(long)]
    wrong_seq_extra_offset: Option<u32>,
    /// Override `WRONG_SEQ_SET_PSH`: clear the PSH flag on the spoofed packet.
    #[arg(long)]
    wrong_seq_no_psh: bool,
    /// Override `WRONG_SEQ_BUMP_IP_IDENT`: skip bumping the IPv4 ID field.
    #[arg(long)]
    wrong_seq_no_bump_ident: bool,
    /// Override `BYPASS_TIMEOUT_SECS`.
    #[arg(long)]
    bypass_timeout: Option<u64>,
}

fn main() -> Result<()> {
    // Install the ring CryptoProvider as the process-level default.  This must
    // happen before any rustls ClientConfig (or ServerConfig) is constructed.
    // rustls 0.23 no longer auto-selects a provider from crate features alone.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install ring CryptoProvider"))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(TuiAwareStderr)
        .with_ansi(true)
        .with_level(true)
        .with_target(false)
        .init();

    let args = Args::parse();

    let no_tui = args.no_tui;

    // ---- config ----
    let cfg_path = args.config.clone().unwrap_or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("config.toml")))
            .unwrap_or_else(|| PathBuf::from("config.toml"))
    });
    let mut cfg = Config::from_file(&cfg_path)
        .with_context(|| format!("loading config from {}", cfg_path.display()))?;

    if let Some(v) = args.listen_host {
        cfg.LISTEN_HOST = v;
    }
    if let Some(v) = args.listen_port {
        cfg.LISTEN_PORT = v;
    }
    if args.auto_select {
        cfg.AUTO_SELECT = true;
    }
    if let Some(v) = args.sni {
        cfg.SELECTED_SNI = Some(v);
    }
    if let Some(v) = args.method {
        cfg.BYPASS_METHOD = v;
    }
    if let Some(v) = args.queue_num {
        cfg.NFQUEUE_NUM = v;
    }
    if let Some(v) = args.scan_timeout {
        cfg.SCAN_TIMEOUT_SECS = v;
    }
    if let Some(v) = args.rescan_interval {
        cfg.RESCAN_INTERVAL_SECS = v;
    }
    if let Some(v) = args.sni_switch_min_score {
        cfg.SNI_SWITCH_MIN_SCORE = v;
    }
    if let Some(v) = args.wrong_seq_extra_offset {
        cfg.WRONG_SEQ_EXTRA_OFFSET = v;
    }
    if args.wrong_seq_no_psh {
        cfg.WRONG_SEQ_SET_PSH = false;
    }
    if args.wrong_seq_no_bump_ident {
        cfg.WRONG_SEQ_BUMP_IP_IDENT = false;
    }
    if let Some(v) = args.bypass_timeout {
        cfg.BYPASS_TIMEOUT_SECS = v;
    }
    cfg.validate()?;
    if requires_packet_interception(&cfg) {
        ensure_packet_interception_access()?;
    }
    let cfg = Arc::new(cfg);

    // ---- branch: ip_bypass mode ----
    if cfg.MODE == "ip_bypass" {
        let cfg_clone = cfg.clone();
        let cfg_path_clone = cfg_path.clone();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return ip_bypass_main(cfg_clone, cfg_path_clone, rt, no_tui);
    }

    // ---- branch: scan-only modes ----
    if cfg.MODE == "sni_scan" {
        let cfg_clone = cfg.clone();
        let cfg_path_clone = cfg_path.clone();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return sni_scan_main(cfg_clone, cfg_path_clone, rt, no_tui);
    }
    if cfg.MODE == "ip_scan" {
        let cfg_clone = cfg.clone();
        let cfg_path_clone = cfg_path.clone();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return ip_scan_main(cfg_clone, cfg_path_clone, rt, no_tui);
    }

    if cfg.MODE == "proxy_scan" {
        let cfg_clone = cfg.clone();
        let cfg_path_clone = cfg_path.clone();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return proxy_scan_main(cfg_clone, cfg_path_clone, rt, no_tui);
    }

    // ---- resolve SNI list path relative to the config file ----
    let sni_list_path = {
        let raw = PathBuf::from(&cfg.SNI_LIST);
        if raw.is_absolute() {
            raw
        } else {
            cfg_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(raw)
        }
    };

    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);

    // ---- build tokio runtime ----
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // ---- step 1: obtain a sorted list of probe results ----
    let sorted_entries: Vec<SniProbeEntry> = if let Some(ref forced_sni) = cfg.SELECTED_SNI {
        // Skip scanning; just resolve the forced SNI.
        info!(sni = %forced_sni, "SELECTED_SNI set — skipping scan");
        let sni = forced_sni.clone();
        rt.block_on(async move { resolve_single_sni(&sni).await })
            .with_context(|| format!("resolving SELECTED_SNI '{}'", forced_sni))?
    } else {
        info!(path = %sni_list_path.display(), "scanning SNI list");
        let path = sni_list_path.clone();
        let cfg_clone = cfg.clone();
        let entries = if no_tui {
            let entries = rt.block_on(scan_sni_list(&path, scan_timeout, cfg_clone, None))?;
            log_sni_scan_results("headless scan", &entries);
            entries
        } else {
            rt.block_on(async move {
                scan_sni_list_with_progress(cfg_clone, &path, scan_timeout).await
            })?
        };
        if entries.is_empty() {
            anyhow::bail!(
                "no reachable SNI candidates found in {}",
                sni_list_path.display()
            );
        }
        entries
    };

    // ---- step 2: select a candidate ----
    if no_tui && !cfg.AUTO_SELECT && cfg.SELECTED_SNI.is_none() {
        warn!("--no-tui cannot show the selection table; auto-selecting rank-1");
    }
    let selected: SniProbeEntry = if cfg.AUTO_SELECT || cfg.SELECTED_SNI.is_some() || no_tui {
        let best = sorted_entries
            .into_iter()
            .next()
            .context("no probe results")?;
        info!(sni = %best.sni, ip = %best.ip, score = best.score, "auto-selected SNI");
        best
    } else {
        // Interactive ratatui selection.
        let mut terminal = tui::enter_tui()?;
        let result = tui::run_selection(&mut terminal, &sorted_entries);
        tui::leave_tui(terminal)?;
        match result {
            Ok(entry) => {
                info!(sni = %entry.sni, ip = %entry.ip, score = entry.score, "selected SNI");
                entry
            }
            Err(e) => {
                return Err(e).context("SNI selection");
            }
        }
    };

    let active_target = Arc::new(std::sync::RwLock::new(ActiveSniTarget::new(
        selected.sni.clone(),
        selected.ip,
        selected.score,
    )));
    let connect_ip = selected.ip;

    // ---- step 3: start the proxy ----
    let interface_ip = default_interface_ipv4(connect_ip)
        .context("could not determine local interface IP for upstream")?;
    info!(%interface_ip, %connect_ip, sni = %selected.sni, "starting proxy");

    let flows = new_flow_table();

    let _intercept_thread = if cfg.BYPASS_METHOD == "tcp_segmentation" {
        info!("tcp_segmentation selected; skipping packet interceptor");
        None
    } else {
        let method_box = build_method(&cfg)
            .with_context(|| format!("unknown BYPASS_METHOD '{}'", cfg.BYPASS_METHOD))?;
        let method: Arc<dyn zerodpi_core::methods::BypassMethod> = Arc::from(method_box);

        let filter = FilterSpec {
            interface_ip,
            remote_ip: None,
            remote_port: CONNECT_PORT,
            queue_num: cfg.NFQUEUE_NUM,
        };
        let interceptor = DefaultInterceptor::open(filter).context("open packet interceptor")?;

        let handler = Handler::new(flows.clone(), method);
        Some(
            std::thread::Builder::new()
                .name("zerodpi-intercept".into())
                .spawn(move || {
                    if let Err(e) = interceptor.run(handler) {
                        error!(error = %e, "intercept loop ended with error");
                    }
                })
                .context("spawn intercept thread")?,
        )
    };

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<ProxyEvent>();

    // ---- step 4: optional background rescan ----
    let rescan_cfg = cfg.clone();
    let rescan_path = sni_list_path.clone();
    if cfg.RESCAN_INTERVAL_SECS > 0 {
        let interval = cfg.RESCAN_INTERVAL_SECS;
        let active_target = active_target.clone();
        let rescan_event_tx = if no_tui { None } else { Some(event_tx.clone()) };
        rt.spawn(async move {
            background_rescan(
                rescan_cfg,
                rescan_path,
                interval,
                active_target,
                rescan_event_tx,
                no_tui,
            )
            .await;
        });
    }

    let cfg_dash = cfg.clone();
    let selected_dash = selected.clone();

    // Spawn the proxy on the tokio runtime's worker threads so the main
    // thread is free to drive the ratatui dashboard.
    let dashboard_event_tx = if no_tui { None } else { Some(event_tx) };
    let proxy_handle = rt.spawn(async move {
        run_proxy(cfg, active_target, interface_ip, flows, dashboard_event_tx).await
    });

    if no_tui {
        let result = rt.block_on(run_headless_proxy(proxy_handle));
        info!("shutting down");
        return result;
    }

    let mut terminal = tui::enter_tui()?;
    let dash_info = tui::DashboardInfo::SniSpoof {
        sni: selected_dash.sni.clone(),
        ip: selected_dash.ip,
        score: selected_dash.score,
    };
    let dash_result = tui::run_dashboard(&mut terminal, &mut event_rx, &dash_info, &cfg_dash);
    tui::leave_tui(terminal)?;

    proxy_handle.abort();
    info!("shutting down");
    dash_result?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve `sni` to all IPv4 addresses and return a synthetic probe entry for
/// each one (no TCP/TLS/HTTP checks are performed).
async fn resolve_single_sni(sni: &str) -> anyhow::Result<Vec<SniProbeEntry>> {
    let target = format!("{sni}:443");
    let addrs: Vec<Ipv4Addr> = tokio::net::lookup_host(&target)
        .await
        .with_context(|| format!("DNS lookup for {sni}"))?
        .filter_map(|sa| match sa.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect();

    if addrs.is_empty() {
        anyhow::bail!("no IPv4 addresses found for {sni}");
    }

    // Return a minimal entry (score 0 — we skipped probing intentionally).
    Ok(addrs
        .into_iter()
        .map(|ip| SniProbeEntry {
            sni: sni.to_owned(),
            ip,
            tcp_latency_ms: None,
            tls_ok: false,
            tls_latency_ms: None,
            cert_valid: false,
            ttfb_ms: None,
            speed_bps: None,
            http_status: None,
            score: 0,
        })
        .collect())
}

/// Run the scanner with TUI progress display.
///
/// The ratatui scan-progress view streams results in real time. If the user
/// presses `q`/`Esc` the ongoing scan is aborted and the results collected so
/// far are used.
async fn scan_sni_list_with_progress(
    cfg: Arc<Config>,
    path: &std::path::Path,
    timeout: Duration,
) -> anyhow::Result<Vec<SniProbeEntry>> {
    let total_hostnames = count_hostnames(path);
    let path_owned = path.to_owned();

    let (tx, mut rx) = mpsc::unbounded_channel::<SniProbeEntry>();

    // Spawn scanner; it sends each result over `tx` as it arrives.
    let cfg_clone = cfg.clone();
    let scan_handle =
        tokio::spawn(async move { scan_sni_list(&path_owned, timeout, cfg_clone, Some(tx)).await });

    let mut terminal = tui::enter_tui()?;
    let (arrived, aborted) = tui::run_scan_progress(&mut terminal, &mut rx, total_hostnames)?;
    tui::leave_tui(terminal)?;

    // Obtain the authoritative sorted list.
    let sorted = if scan_handle.is_finished() {
        // Scanner already completed — use its sorted result.
        scan_handle.await.context("scanner task panicked")??
    } else {
        // User aborted early — stop the scan and sort what arrived.
        scan_handle.abort();
        if aborted {
            info!(
                "scan aborted by user — using {} results collected so far",
                arrived.len()
            );
        }
        let mut entries = arrived;
        entries.sort_by(|a, b| {
            b.score.cmp(&a.score).then(
                a.tcp_latency_ms
                    .unwrap_or(u64::MAX)
                    .cmp(&b.tcp_latency_ms.unwrap_or(u64::MAX)),
            )
        });
        entries
    };

    info!("scan complete — {} (SNI, IP) pairs probed", sorted.len());
    for e in &sorted {
        info!("{}", e.summary_line());
    }
    Ok(sorted)
}

/// Count valid hostname lines in the SNI list file.
fn count_hostnames(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count()
}

fn log_sni_scan_results(context: &str, entries: &[SniProbeEntry]) {
    info!(
        "{context} complete — {} (SNI, IP) pairs probed",
        entries.len()
    );
    for e in entries {
        info!("{}", e.summary_line());
    }
}

fn log_sni_scan_top(context: &str, entries: &[SniProbeEntry]) {
    for (rank, e) in entries.iter().take(5).enumerate() {
        info!(rank = rank + 1, "{}", e.summary_line());
    }
    if entries.len() > 5 {
        info!(
            remaining = entries.len() - 5,
            "{context}: additional candidates omitted"
        );
    }
}

fn log_ip_scan_results(context: &str, entries: &[IpProbeEntry]) {
    info!("{context} complete — {} IPs probed", entries.len());
    for e in entries {
        info!("{}", e.summary_line());
    }
}

fn log_ip_scan_top(context: &str, entries: &[IpProbeEntry]) {
    for (rank, e) in entries.iter().take(5).enumerate() {
        info!(rank = rank + 1, "{}", e.summary_line());
    }
    if entries.len() > 5 {
        info!(
            remaining = entries.len() - 5,
            "{context}: additional candidates omitted"
        );
    }
}

/// Background rescan task: runs every `interval_secs` seconds and switches
/// new connections to better SNI targets.
///
/// This runs while the ratatui dashboard owns the terminal. Keep routine scan
/// output below `info` so it does not write over the live UI.
async fn background_rescan(
    cfg: Arc<Config>,
    path: PathBuf,
    interval_secs: u64,
    active_target: Arc<std::sync::RwLock<ActiveSniTarget>>,
    event_tx: Option<ProxyEventSender>,
    headless: bool,
) {
    let interval = Duration::from_secs(interval_secs);
    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);
    loop {
        tokio::time::sleep(interval).await;
        if headless {
            info!(path = %path.display(), "background SNI rescan starting");
        } else {
            debug!("background rescan starting");
        }
        let cfg_clone = cfg.clone();
        match scan_sni_list(&path, scan_timeout, cfg_clone, None).await {
            Ok(entries) => {
                if headless {
                    info!(
                        "background SNI rescan complete — {} (SNI, IP) pairs",
                        entries.len()
                    );
                    log_sni_scan_top("background SNI rescan top candidates", &entries);
                } else {
                    debug!(
                        "background rescan complete — {} (SNI, IP) pairs",
                        entries.len()
                    );
                }
                if let Some(best) = entries.first() {
                    let current = active_target.read().unwrap().clone();
                    if headless {
                        info!(
                            sni = %best.sni,
                            ip = %best.ip,
                            score = best.score,
                            current_sni = %current.sni,
                            current_ip = %current.ip,
                            current_score = current.score,
                            "background SNI rescan evaluated top result"
                        );
                    } else {
                        debug!(
                            sni = %best.sni,
                            ip = %best.ip,
                            score = best.score,
                            current_sni = %current.sni,
                            current_ip = %current.ip,
                            current_score = current.score,
                            "rescan top result"
                        );
                    }

                    if should_switch_sni_target(&current, best, cfg.SNI_SWITCH_MIN_SCORE) {
                        let next = ActiveSniTarget::new(best.sni.clone(), best.ip, best.score);
                        *active_target.write().unwrap() = next.clone();
                        info!(
                            old_sni = %current.sni,
                            old_ip = %current.ip,
                            old_score = current.score,
                            new_sni = %next.sni,
                            new_ip = %next.ip,
                            new_score = next.score,
                            "hot-swapped active SNI target"
                        );
                        if let Some(ref tx) = event_tx {
                            let _ = tx.send(ProxyEvent::SniTargetChanged {
                                sni: next.sni.to_string(),
                                ip: next.ip,
                                score: next.score,
                            });
                        }
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "background rescan failed");
            }
        }
    }
}

fn should_switch_sni_target(
    current: &ActiveSniTarget,
    candidate: &SniProbeEntry,
    min_score: u8,
) -> bool {
    if current.ip == candidate.ip && current.sni.as_ref() == candidate.sni {
        return false;
    }
    candidate.score >= min_score
}

fn requires_packet_interception(cfg: &Config) -> bool {
    mode_requires_packet_interception(&cfg.MODE, &cfg.BYPASS_METHOD)
}

fn mode_requires_packet_interception(mode: &str, bypass_method: &str) -> bool {
    matches!(mode, "sni_spoof" | "proxy_scan") && bypass_method != "tcp_segmentation"
}

async fn run_headless_proxy(
    proxy_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    log_headless_proxy_start();
    let mut proxy_handle = proxy_handle;
    tokio::select! {
        signal = shutdown_signal() => {
            signal?;
            proxy_handle.abort();
            Ok(())
        }
        result = &mut proxy_handle => {
            result.context("proxy task panicked")?
        }
    }
}

#[cfg(unix)]
fn log_headless_proxy_start() {
    info!("running without TUI; send SIGTERM to stop");
}

#[cfg(not(unix))]
fn log_headless_proxy_start() {
    info!("running without TUI; press Ctrl-C to stop");
}

#[cfg(unix)]
async fn shutdown_signal() -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    let mut terminate = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut hangup = signal(SignalKind::hangup()).context("install SIGHUP handler")?;

    loop {
        tokio::select! {
            _ = interrupt.recv() => {
                warn!("received SIGINT; continuing because --no-tui is running headless; send SIGTERM to stop");
            }
            _ = terminate.recv() => {
                info!("received SIGTERM");
                return Ok(());
            }
            _ = hangup.recv() => {
                warn!("received SIGHUP; continuing because --no-tui is running headless");
            }
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> anyhow::Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    info!("received Ctrl-C");
    Ok(())
}

// ---------------------------------------------------------------------------
// IP bypass mode
// ---------------------------------------------------------------------------

fn ip_bypass_main(
    cfg: Arc<Config>,
    cfg_path: PathBuf,
    rt: tokio::runtime::Runtime,
    no_tui: bool,
) -> Result<()> {
    let ip_list_path = {
        let raw = PathBuf::from(&cfg.IP_LIST);
        if raw.is_absolute() {
            raw
        } else {
            cfg_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(raw)
        }
    };

    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);

    // ---- step 1: obtain active IP ----
    let active_ip: std::net::IpAddr = if let Some(ref forced_ip) = cfg.SELECTED_IP {
        let ip: std::net::IpAddr = forced_ip
            .parse()
            .with_context(|| format!("parsing SELECTED_IP '{forced_ip}'"))?;
        info!(%ip, "SELECTED_IP set — skipping scan");
        ip
    } else {
        let ips = load_ip_list(&ip_list_path, cfg.IPV6_MAX_HOSTS)
            .with_context(|| format!("loading ip_list from '{}'", ip_list_path.display()))?;
        if ips.is_empty() {
            anyhow::bail!(
                "ip_list '{}' is empty — add at least one IP or CIDR",
                ip_list_path.display()
            );
        }
        let total_ips = ips.len();
        info!(total_ips, "scanning IP list");

        let scan_sni: Arc<str> = Arc::from(cfg.IP_SCAN_SNI.as_str());
        let cfg_clone = cfg.clone();
        let entries = if no_tui {
            let entries = rt.block_on(scan_ip_list(ips, scan_sni, scan_timeout, cfg_clone, None));
            log_ip_scan_results("headless IP scan", &entries);
            Ok(entries)
        } else {
            scan_ip_list_with_ip_progress(cfg_clone, &rt, ips, scan_sni, scan_timeout, total_ips)
        }?;

        if entries.is_empty() {
            anyhow::bail!("no IPs passed the scan — check connectivity or ip_list");
        }

        if no_tui && !cfg.AUTO_SELECT {
            warn!("--no-tui cannot show the IP selection table; auto-selecting rank-1");
        }
        let selected_entry: IpProbeEntry = if cfg.AUTO_SELECT || no_tui {
            let best = entries.into_iter().next().context("no probe results")?;
            info!(ip = %best.ip, score = best.score, "auto-selected IP");
            best
        } else {
            let mut terminal = tui::enter_tui()?;
            let result = tui::run_ip_selection(&mut terminal, &entries);
            tui::leave_tui(terminal)?;
            let entry = result.context("IP selection")?;
            info!(ip = %entry.ip, score = entry.score, "selected IP");
            entry
        };
        selected_entry.ip
    };

    let active_ip_arc = Arc::new(std::sync::RwLock::new(active_ip));
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<ProxyEvent>();

    // ---- step 2: optional background IP rescan ----
    if cfg.RESCAN_INTERVAL_SECS > 0 {
        let rescan_cfg = cfg.clone();
        let rescan_path = ip_list_path.clone();
        let interval = cfg.RESCAN_INTERVAL_SECS;
        let active_clone = active_ip_arc.clone();
        let rescan_event_tx = if no_tui { None } else { Some(event_tx.clone()) };
        rt.spawn(async move {
            background_ip_rescan(
                rescan_cfg,
                rescan_path,
                interval,
                active_clone,
                rescan_event_tx,
                no_tui,
            )
            .await;
        });
    }

    info!(%active_ip, "ip_bypass: starting proxy (no packet interception)");

    // ---- step 3: run the proxy ----
    let cfg_dash = cfg.clone();
    let proxy_active = active_ip_arc.clone();

    let dashboard_event_tx = if no_tui { None } else { Some(event_tx) };
    let proxy_handle =
        rt.spawn(async move { run_ip_bypass_proxy(cfg, proxy_active, dashboard_event_tx).await });

    if no_tui {
        let result = rt.block_on(run_headless_proxy(proxy_handle));
        info!("shutting down");
        return result;
    }

    let dash_info = tui::DashboardInfo::IpBypass { ip: active_ip };
    let mut terminal = tui::enter_tui()?;
    let dash_result = tui::run_dashboard(&mut terminal, &mut event_rx, &dash_info, &cfg_dash);
    tui::leave_tui(terminal)?;

    proxy_handle.abort();
    info!("shutting down");
    dash_result?;

    Ok(())
}

/// Run the IP scanner with TUI progress display.
fn scan_ip_list_with_ip_progress(
    cfg: Arc<Config>,
    rt: &tokio::runtime::Runtime,
    ips: Vec<std::net::IpAddr>,
    scan_sni: Arc<str>,
    timeout: Duration,
    total_ips: usize,
) -> anyhow::Result<Vec<IpProbeEntry>> {
    let (tx, mut rx) = mpsc::unbounded_channel::<IpScanEvent>();
    let cfg_clone = cfg.clone();
    let scan_handle =
        rt.spawn(async move { scan_ip_list(ips, scan_sni, timeout, cfg_clone, Some(tx)).await });

    let mut terminal = tui::enter_tui()?;
    let (arrived, aborted) = tui::run_ip_scan_progress(&mut terminal, &mut rx, total_ips)?;
    tui::leave_tui(terminal)?;

    let sorted = if scan_handle.is_finished() {
        rt.block_on(scan_handle).context("scanner task panicked")?
    } else {
        scan_handle.abort();
        if aborted {
            info!(
                "IP scan aborted — using {} results collected so far",
                arrived.len()
            );
        }
        let mut entries = arrived;
        entries.sort_by(|a, b| {
            b.score.cmp(&a.score).then(
                a.tcp_latency_ms
                    .unwrap_or(u64::MAX)
                    .cmp(&b.tcp_latency_ms.unwrap_or(u64::MAX)),
            )
        });
        entries
    };

    info!("IP scan complete — {} IPs probed", sorted.len());
    for e in &sorted {
        info!("{}", e.summary_line());
    }
    Ok(sorted)
}

/// Background IP rescan: rescans `ip_list` every `interval_secs` seconds.
/// If the best IP changes, hot-swaps `active_ip`.
///
/// This runs while the ratatui dashboard owns the terminal. Keep routine scan
/// output below `info` so it does not write over the live UI.
async fn background_ip_rescan(
    cfg: Arc<Config>,
    ip_list_path: PathBuf,
    interval_secs: u64,
    active_ip: Arc<std::sync::RwLock<std::net::IpAddr>>,
    event_tx: Option<ProxyEventSender>,
    headless: bool,
) {
    let interval = Duration::from_secs(interval_secs);
    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);
    let scan_sni: Arc<str> = Arc::from(cfg.IP_SCAN_SNI.as_str());
    loop {
        tokio::time::sleep(interval).await;
        if headless {
            info!(path = %ip_list_path.display(), "ip_bypass: background IP rescan starting");
        } else {
            debug!("ip_bypass: background rescan starting");
        }

        let ips = match load_ip_list(&ip_list_path, cfg.IPV6_MAX_HOSTS) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "ip_bypass: background rescan failed to load ip_list");
                continue;
            }
        };
        let cfg_clone = cfg.clone();
        let entries = scan_ip_list(ips, scan_sni.clone(), scan_timeout, cfg_clone, None).await;
        if entries.is_empty() {
            warn!("ip_bypass: background rescan found no working IPs");
            continue;
        }
        let best = &entries[0];
        if headless {
            info!(
                "ip_bypass: background IP rescan complete — {} IPs probed",
                entries.len()
            );
            log_ip_scan_top("ip_bypass: background IP rescan top candidates", &entries);
            info!(ip = %best.ip, score = best.score, "ip_bypass: background IP rescan evaluated top result");
        } else {
            debug!(ip = %best.ip, score = best.score, "ip_bypass: rescan top result");
        }

        let current = *active_ip.read().unwrap();
        if best.ip != current {
            *active_ip.write().unwrap() = best.ip;
            if let Some(ref tx) = event_tx {
                let _ = tx.send(ProxyEvent::IpTargetChanged { ip: best.ip });
            }
            info!(old = %current, new = %best.ip, "ip_bypass: hot-swapped active IP");
        }
    }
}

// ---------------------------------------------------------------------------
// sni_scan mode
// ---------------------------------------------------------------------------

fn sni_scan_main(
    cfg: Arc<Config>,
    cfg_path: PathBuf,
    rt: tokio::runtime::Runtime,
    no_tui: bool,
) -> Result<()> {
    let sni_list_path = {
        let raw = PathBuf::from(&cfg.SNI_LIST);
        if raw.is_absolute() {
            raw
        } else {
            cfg_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(raw)
        }
    };

    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);

    info!(path = %sni_list_path.display(), "sni_scan: scanning SNI list");

    let total_hostnames = count_hostnames(&sni_list_path);
    let path = sni_list_path.clone();
    let cfg_clone = cfg.clone();
    let sorted = if no_tui {
        rt.block_on(scan_sni_list(&path, scan_timeout, cfg_clone, None))?
    } else {
        let (tx, mut rx) = mpsc::unbounded_channel::<SniProbeEntry>();
        let scan_handle =
            rt.spawn(async move { scan_sni_list(&path, scan_timeout, cfg_clone, Some(tx)).await });

        let mut terminal = tui::enter_tui()?;
        let (arrived, aborted) = tui::run_scan_progress(&mut terminal, &mut rx, total_hostnames)?;
        tui::leave_tui(terminal)?;

        if scan_handle.is_finished() {
            rt.block_on(scan_handle)
                .context("scanner task panicked")??
        } else {
            scan_handle.abort();
            if aborted {
                info!(
                    "sni_scan aborted — using {} results collected so far",
                    arrived.len()
                );
            }
            let mut e = arrived;
            e.sort_by(|a, b| {
                b.score.cmp(&a.score).then(
                    a.tcp_latency_ms
                        .unwrap_or(u64::MAX)
                        .cmp(&b.tcp_latency_ms.unwrap_or(u64::MAX)),
                )
            });
            e
        }
    };

    info!("sni_scan complete — {} (SNI, IP) pairs", sorted.len());
    for e in &sorted {
        info!("{}", e.summary_line());
    }

    // Resolve output path before entering TUI (so we can show it in the footer).
    let output_path = resolve_output_path(&cfg, &cfg_path);
    let saved_path_str: Option<String> = if let Some(ref p) = output_path {
        save_sni_results(p, &sorted)?;
        Some(p.display().to_string())
    } else {
        None
    };

    if !no_tui {
        let mut terminal = tui::enter_tui()?;
        tui::run_sni_results_view(&mut terminal, &sorted, saved_path_str.as_deref())?;
        tui::leave_tui(terminal)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// ip_scan mode
// ---------------------------------------------------------------------------

fn ip_scan_main(
    cfg: Arc<Config>,
    cfg_path: PathBuf,
    rt: tokio::runtime::Runtime,
    no_tui: bool,
) -> Result<()> {
    let ip_list_path = {
        let raw = PathBuf::from(&cfg.IP_LIST);
        if raw.is_absolute() {
            raw
        } else {
            cfg_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(raw)
        }
    };

    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);
    let ips = load_ip_list(&ip_list_path, cfg.IPV6_MAX_HOSTS)
        .with_context(|| format!("loading ip_list from '{}'", ip_list_path.display()))?;
    if ips.is_empty() {
        anyhow::bail!(
            "ip_list '{}' is empty — add at least one IP or CIDR",
            ip_list_path.display()
        );
    }
    let total_ips = ips.len();
    info!(total_ips, "ip_scan: scanning IP list");

    let scan_sni: Arc<str> = Arc::from(cfg.IP_SCAN_SNI.as_str());

    let cfg_clone = cfg.clone();
    let sorted = if no_tui {
        rt.block_on(scan_ip_list(ips, scan_sni, scan_timeout, cfg_clone, None))
    } else {
        let (tx, mut rx) = mpsc::unbounded_channel::<IpScanEvent>();
        let scan_handle = rt.spawn(async move {
            scan_ip_list(ips, scan_sni, scan_timeout, cfg_clone, Some(tx)).await
        });

        let mut terminal = tui::enter_tui()?;
        let (arrived, aborted) = tui::run_ip_scan_progress(&mut terminal, &mut rx, total_ips)?;
        tui::leave_tui(terminal)?;

        if scan_handle.is_finished() {
            rt.block_on(scan_handle).context("scanner task panicked")?
        } else {
            scan_handle.abort();
            if aborted {
                info!(
                    "ip_scan aborted — using {} results collected so far",
                    arrived.len()
                );
            }
            let mut e = arrived;
            e.sort_by(|a, b| {
                b.score.cmp(&a.score).then(
                    a.tcp_latency_ms
                        .unwrap_or(u64::MAX)
                        .cmp(&b.tcp_latency_ms.unwrap_or(u64::MAX)),
                )
            });
            e
        }
    };

    info!("ip_scan complete — {} IPs probed", sorted.len());
    for e in &sorted {
        info!("{}", e.summary_line());
    }

    let output_path = resolve_output_path(&cfg, &cfg_path);
    let saved_path_str: Option<String> = if let Some(ref p) = output_path {
        save_ip_results(p, &sorted)?;
        Some(p.display().to_string())
    } else {
        None
    };

    if !no_tui {
        let mut terminal = tui::enter_tui()?;
        tui::run_ip_results_view(&mut terminal, &sorted, saved_path_str.as_deref())?;
        tui::leave_tui(terminal)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Scan result persistence helpers
// ---------------------------------------------------------------------------

/// Resolve `SCAN_OUTPUT` relative to the config file directory.
fn resolve_output_path(cfg: &Config, cfg_path: &Path) -> Option<PathBuf> {
    let raw = cfg.SCAN_OUTPUT.as_deref()?;
    let raw_path = PathBuf::from(raw);
    if raw_path.is_absolute() {
        Some(raw_path)
    } else {
        Some(
            cfg_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(raw_path),
        )
    }
}

fn save_sni_results(path: &PathBuf, entries: &[SniProbeEntry]) -> Result<()> {
    let json = serde_json::to_string_pretty(entries).context("serialising SNI scan results")?;
    std::fs::write(path, json)
        .with_context(|| format!("writing SNI scan results to '{}'", path.display()))?;
    info!(path = %path.display(), "sni_scan: results saved");
    Ok(())
}

fn save_ip_results(path: &PathBuf, entries: &[IpProbeEntry]) -> Result<()> {
    let json = serde_json::to_string_pretty(entries).context("serialising IP scan results")?;
    std::fs::write(path, json)
        .with_context(|| format!("writing IP scan results to '{}'", path.display()))?;
    info!(path = %path.display(), "ip_scan: results saved");
    Ok(())
}

// ---------------------------------------------------------------------------
// proxy_scan mode
// ---------------------------------------------------------------------------

fn proxy_scan_main(
    cfg: Arc<Config>,
    cfg_path: PathBuf,
    rt: tokio::runtime::Runtime,
    no_tui: bool,
) -> Result<()> {
    // ---- resolve SNI list path ----
    let sni_list_path = {
        let raw = PathBuf::from(&cfg.SNI_LIST);
        if raw.is_absolute() {
            raw
        } else {
            cfg_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(raw)
        }
    };

    let scan_timeout = Duration::from_secs(cfg.SCAN_TIMEOUT_SECS);

    // ---- Phase 1: SNI scan ----
    info!(path = %sni_list_path.display(), "proxy_scan: Phase 1 — scanning SNI list");
    let path = sni_list_path.clone();
    let cfg_clone = cfg.clone();
    let phase1_sorted = if no_tui {
        rt.block_on(scan_sni_list(&path, scan_timeout, cfg_clone, None))?
    } else {
        let total_hostnames = count_hostnames(&sni_list_path);
        let (tx1, mut rx1) = mpsc::unbounded_channel::<SniProbeEntry>();
        let scan_handle =
            rt.spawn(async move { scan_sni_list(&path, scan_timeout, cfg_clone, Some(tx1)).await });

        let mut terminal = tui::enter_tui()?;
        let (arrived, aborted) = tui::run_scan_progress(&mut terminal, &mut rx1, total_hostnames)?;
        tui::leave_tui(terminal)?;

        if scan_handle.is_finished() {
            rt.block_on(scan_handle)
                .context("scanner task panicked")??
        } else {
            scan_handle.abort();
            if aborted {
                info!(
                    "proxy_scan: Phase 1 aborted — using {} results collected so far",
                    arrived.len()
                );
            }
            let mut entries = arrived;
            entries.sort_by(|a, b| {
                b.score.cmp(&a.score).then(
                    a.tcp_latency_ms
                        .unwrap_or(u64::MAX)
                        .cmp(&b.tcp_latency_ms.unwrap_or(u64::MAX)),
                )
            });
            entries
        }
    };

    info!(
        "proxy_scan: Phase 1 complete — {} (SNI, IP) pairs",
        phase1_sorted.len()
    );
    if no_tui {
        log_sni_scan_results("proxy_scan: headless Phase 1 SNI scan", &phase1_sorted);
    }

    // ---- Filter Phase 1 results ----
    let min_score = cfg.PROXY_TEST_MIN_SNI_SCORE;
    let mut candidates: Vec<SniProbeEntry> = phase1_sorted
        .into_iter()
        .filter(|e| e.score >= min_score)
        .collect();
    if cfg.PROXY_TEST_TOP_N > 0 {
        candidates.truncate(cfg.PROXY_TEST_TOP_N);
    }

    if candidates.is_empty() {
        anyhow::bail!(
            "proxy_scan: no SNI candidates reached the minimum score of {} in Phase 1",
            min_score
        );
    }
    info!(
        "proxy_scan: {} candidates will be proxy-tested (min_score={}, top_n={})",
        candidates.len(),
        min_score,
        cfg.PROXY_TEST_TOP_N,
    );

    // ---- Verify SOCKS5 proxy is reachable before starting Phase 2 ----
    let socks5_addr = format!(
        "{}:{}",
        cfg.PROXY_TEST_SOCKS5_HOST, cfg.PROXY_TEST_SOCKS5_PORT
    );
    rt.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&socks5_addr),
        )
        .await
    })
    .with_context(|| {
        format!("proxy_scan: SOCKS5 proxy at {socks5_addr} is not reachable — is V2RayN running?")
    })?
    .with_context(|| {
        format!(
            "proxy_scan: could not connect to SOCKS5 proxy at {socks5_addr} — is V2RayN running?"
        )
    })?;
    info!(%socks5_addr, "proxy_scan: SOCKS5 proxy is reachable");

    // ---- Determine interface IP using first candidate's Cloudflare IP ----
    let first_ip = candidates[0].ip;
    let interface_ip =
        default_interface_ipv4(first_ip).context("could not determine local interface IP")?;

    // ---- Phase 2: proxy test per candidate ----
    info!(
        "proxy_scan: Phase 2 — proxy testing {} candidates",
        candidates.len()
    );

    let (tx2, mut rx2) = mpsc::unbounded_channel::<ProxyTestEntry>();
    let cfg_for_phase2 = cfg.clone();
    let candidates_for_phase2 = candidates.clone();

    // Each candidate spins up an OS thread (WinDivert/NFQUEUE), so we run
    // the loop inside spawn_blocking to avoid blocking the async executor.
    let phase2_handle = rt.spawn_blocking(move || {
        let rt2 = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("proxy_scan: failed to build phase2 runtime");

        rt2.block_on(async move {
            let mut results = Vec::with_capacity(candidates_for_phase2.len());
            for candidate in &candidates_for_phase2 {
                let cfg_c = cfg_for_phase2.clone();
                let tx_c = tx2.clone();

                let entry = test_candidate_full(candidate, cfg_c, interface_ip, |filter| {
                    DefaultInterceptor::open(filter)
                })
                .await;

                info!("{}", entry.summary_line());
                let _ = tx_c.send(entry.clone());
                results.push(entry);

                // Small gap between candidates so the previous interceptor
                // thread has time to exit before the next one opens.
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            results
        })
    });

    let mut phase2_results: Vec<ProxyTestEntry> = if no_tui {
        rt.block_on(phase2_handle)
            .context("proxy_scan phase2 task panicked")?
    } else {
        let mut terminal = tui::enter_tui()?;
        let (proxy_arrived, _) =
            tui::run_proxy_scan_progress(&mut terminal, &mut rx2, candidates.len())?;
        tui::leave_tui(terminal)?;

        if phase2_handle.is_finished() {
            rt.block_on(phase2_handle)
                .context("proxy_scan phase2 task panicked")?
        } else {
            phase2_handle.abort();
            proxy_arrived
        }
    };

    // Sort by final_score descending.
    phase2_results.sort_by(|a, b| {
        b.final_score.cmp(&a.final_score).then(
            a.proxy_ttfb_ms
                .unwrap_or(u64::MAX)
                .cmp(&b.proxy_ttfb_ms.unwrap_or(u64::MAX)),
        )
    });

    info!(
        "proxy_scan complete — {} candidates tested",
        phase2_results.len()
    );

    // ---- Optionally save JSON ----
    let output_path = resolve_output_path(&cfg, &cfg_path);
    let saved_path_str: Option<String> = if let Some(ref p) = output_path {
        let json = serde_json::to_string_pretty(&phase2_results)
            .context("serialising proxy scan results")?;
        std::fs::write(p, json)
            .with_context(|| format!("writing proxy scan results to '{}'", p.display()))?;
        info!(path = %p.display(), "proxy_scan: results saved");
        Some(p.display().to_string())
    } else {
        None
    };

    // ---- TUI results view ----
    if !no_tui {
        let mut terminal = tui::enter_tui()?;
        tui::run_proxy_scan_results_view(
            &mut terminal,
            &phase2_results,
            saved_path_str.as_deref(),
        )?;
        tui::leave_tui(terminal)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    fn current(score: u8) -> ActiveSniTarget {
        ActiveSniTarget::new("old.example.com", Ipv4Addr::new(1, 1, 1, 1), score)
    }

    fn candidate(sni: &str, ip: Ipv4Addr, score: u8) -> SniProbeEntry {
        SniProbeEntry {
            sni: sni.to_owned(),
            ip,
            tcp_latency_ms: Some(10),
            tls_ok: true,
            tls_latency_ms: Some(20),
            cert_valid: true,
            ttfb_ms: Some(30),
            speed_bps: Some(1000.0),
            http_status: Some(200),
            score,
        }
    }

    #[test]
    fn sni_switches_to_different_top_target() {
        let c = candidate("new.example.com", Ipv4Addr::new(2, 2, 2, 2), 61);
        assert!(should_switch_sni_target(&current(50), &c, 1));
    }

    #[test]
    fn sni_does_not_switch_below_min_score() {
        let c = candidate("new.example.com", Ipv4Addr::new(2, 2, 2, 2), 40);
        assert!(!should_switch_sni_target(&current(10), &c, 50));
    }

    #[test]
    fn sni_switches_without_requiring_score_improvement() {
        let c = candidate("new.example.com", Ipv4Addr::new(2, 2, 2, 2), 59);
        assert!(should_switch_sni_target(&current(50), &c, 1));
    }

    #[test]
    fn sni_does_not_switch_for_same_target() {
        let c = candidate("old.example.com", Ipv4Addr::new(1, 1, 1, 1), 100);
        assert!(!should_switch_sni_target(&current(50), &c, 1));
    }

    #[test]
    fn selected_sni_can_switch_after_qualifying_scan() {
        let c = candidate("new.example.com", Ipv4Addr::new(2, 2, 2, 2), 10);
        assert!(should_switch_sni_target(&current(0), &c, 1));
    }

    #[test]
    fn normal_spoofing_requires_packet_interception() {
        assert!(mode_requires_packet_interception("sni_spoof", "wrong_seq"));
        assert!(mode_requires_packet_interception(
            "sni_spoof",
            "tls_record_frag"
        ));
    }

    #[test]
    fn non_interception_modes_do_not_require_packet_interception() {
        assert!(!mode_requires_packet_interception(
            "sni_spoof",
            "tcp_segmentation"
        ));
        assert!(!mode_requires_packet_interception("ip_bypass", "wrong_seq"));
        assert!(!mode_requires_packet_interception("sni_scan", "wrong_seq"));
        assert!(!mode_requires_packet_interception("ip_scan", "wrong_seq"));
    }

    #[test]
    fn proxy_scan_only_requires_interception_for_interceptor_methods() {
        assert!(mode_requires_packet_interception("proxy_scan", "wrong_seq"));
        assert!(!mode_requires_packet_interception(
            "proxy_scan",
            "tcp_segmentation"
        ));
    }
}
