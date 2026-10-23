//! ratatui-based UI: scan-progress view, interactive SNI selection table, and
//! live proxy dashboard.
//!
//! # Scan-progress view
//! Displayed while probing is running.  Results stream in via a
//! `tokio::sync::mpsc` channel and are shown as they arrive.
//!
//! # Selection table
//! Shown after all probes finish when manual selection is enabled.
//! The user navigates with ↑/↓ / j/k and confirms with Enter; pressing Esc or
//! q defaults to rank-1.
//!
//! # Live proxy dashboard
//! Shown after an SNI or IP is selected.  Streams [`ProxyEvent`]s
//! from the running proxy and displays per-connection status, byte counters,
//! and aggregate stats.  Press ↑/↓ (or j/k) to scroll the log; q/Esc to quit.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Stdout};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState};
use ratatui::Terminal;
use tokio::sync::mpsc;

use zerodpi_core::config::Config;
use zerodpi_core::flow::BypassOutcome;
use zerodpi_core::ip_scanner::{IpProbeEntry, IpScanEvent};
use zerodpi_core::method_scanner::{MethodScanEntry, MethodScanEvent, MethodScanReport};
#[cfg(test)]
use zerodpi_core::proxy::RescanKind;
use zerodpi_core::proxy::{ProxyEvent, ProxyEventReceiver, RelayEndReason, RelayProgress};
use zerodpi_core::sni_scanner::SniProbeEntry;

use crate::manual_rescan::{Controller as RescanController, Selection};
use zerodpi_core::target_pool::TargetPool;

mod targets;
use targets::{draw_targets, fit, DashboardView, TargetsState};

pub(crate) type Term = Terminal<CrosstermBackend<Stdout>>;
static TUI_ACTIVE: AtomicBool = AtomicBool::new(false);

pub fn is_tui_active() -> bool {
    TUI_ACTIVE.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Per-cell color helpers
// ---------------------------------------------------------------------------

const TCP_LOW_MS: u64 = 100;
const TCP_HIGH_MS: u64 = 300;

fn score_style(score: u8) -> Style {
    let color = if score >= 60 {
        Color::Green
    } else if score >= 30 {
        Color::Yellow
    } else {
        Color::Red
    };
    Style::default().fg(color)
}

fn tls_style(tls_ok: bool) -> Style {
    if tls_ok {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Red)
    }
}

fn tcp_style(latency_ms: Option<u64>) -> Style {
    let color = match latency_ms {
        Some(ms) if ms < TCP_LOW_MS => Color::Green,
        Some(ms) if ms <= TCP_HIGH_MS => Color::Yellow,
        _ => Color::Red,
    };
    Style::default().fg(color)
}

fn http_style(status: Option<u16>) -> Style {
    let color = match status {
        Some(s) if (200..300).contains(&s) => Color::Green,
        Some(s) if (300..400).contains(&s) => Color::Yellow,
        Some(_) => Color::Red,
        None => Color::Gray,
    };
    Style::default().fg(color)
}

fn cert_style(valid: bool) -> Style {
    if valid {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Red)
    }
}

fn label_style() -> Style {
    Style::default().fg(Color::Gray)
}

fn fmt_rate_bps(speed: Option<f64>) -> String {
    speed
        .map(|bps| {
            if bps >= 1_048_576.0 {
                format!("{:.1}MB/s", bps / 1_048_576.0)
            } else {
                format!("{:.0}KB/s", bps / 1024.0)
            }
        })
        .unwrap_or_else(|| "—".into())
}

// ---------------------------------------------------------------------------
// Dashboard mode descriptor
// ---------------------------------------------------------------------------

/// What the dashboard should display in its header area.
#[derive(Clone)]
pub enum DashboardInfo {
    /// SNI-spoof mode: show the selected SNI and the resolved IP.
    SniSpoof {
        sni: String,
        ip: Ipv4Addr,
        score: u8,
    },
    /// IP-bypass mode: show the current active IP.
    IpBypass { ip: IpAddr },
    /// IP-bypass-plus mode: show the current active IP and bypass method.
    IpBypassPlus { ip: IpAddr },
}

// ---------------------------------------------------------------------------
// Terminal lifecycle helpers
// ---------------------------------------------------------------------------

pub fn enter_tui() -> anyhow::Result<Term> {
    enable_raw_mode()?;
    TUI_ACTIVE.store(true, Ordering::SeqCst);
    let mut stdout = io::stdout();
    if let Err(e) = execute!(stdout, EnterAlternateScreen) {
        TUI_ACTIVE.store(false, Ordering::SeqCst);
        let _ = disable_raw_mode();
        return Err(e.into());
    }
    let backend = CrosstermBackend::new(stdout);
    match Terminal::new(backend) {
        Ok(terminal) => Ok(terminal),
        Err(e) => {
            TUI_ACTIVE.store(false, Ordering::SeqCst);
            let _ = disable_raw_mode();
            Err(e.into())
        }
    }
}

pub fn leave_tui(mut terminal: Term) -> anyhow::Result<()> {
    let raw_result = disable_raw_mode();
    let leave_result = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let cursor_result = terminal.show_cursor();
    TUI_ACTIVE.store(false, Ordering::SeqCst);
    raw_result?;
    leave_result?;
    cursor_result?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Scan-progress view
// ---------------------------------------------------------------------------

/// Show a live scan-progress screen while probing runs in the background.
///
/// `rx` receives `SniProbeEntry` values as each (SNI, IP) probe finishes.
/// `total_hostnames` is the number of hostnames in the SNI list; since each
/// hostname can resolve to multiple IPs, completed probes will often exceed
/// this count — the gauge therefore shows `"N probes done (~M hostnames)"` to
/// make the approximation clear.
///
/// Returns `(entries, aborted)` where `aborted = true` when the user pressed
/// `q`/`Esc` before the scan finished naturally.
pub fn run_scan_progress(
    terminal: &mut Term,
    rx: &mut mpsc::UnboundedReceiver<SniProbeEntry>,
    total_hostnames: usize,
) -> anyhow::Result<(Vec<SniProbeEntry>, bool)> {
    let mut arrived: Vec<SniProbeEntry> = Vec::new();

    loop {
        // Drain all currently available results.
        loop {
            match rx.try_recv() {
                Ok(entry) => {
                    arrived.push(entry);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Scanner finished – draw one final frame and return.
                    draw_scan_progress(terminal, &arrived, total_hostnames)?;
                    return Ok((arrived, false));
                }
            }
        }

        draw_scan_progress(terminal, &arrived, total_hostnames)?;

        // Poll for user input (Ctrl-C / q to abort).
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press
                    && (matches!(k.code, KeyCode::Char('q') | KeyCode::Char('Q'))
                        || k.code == KeyCode::Esc)
                {
                    // Return whatever we have so far, flagging as aborted.
                    return Ok((arrived, true));
                }
            }
        }
    }
}

fn draw_scan_progress(
    terminal: &mut Term,
    arrived: &[SniProbeEntry],
    total_hostnames: usize,
) -> anyhow::Result<()> {
    let done = arrived.len();
    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // header
                Constraint::Length(3), // progress bar
                Constraint::Min(5),    // results so far
            ])
            .split(area);

        // Header
        let header = Paragraph::new("ZeroDPI — Scanning SNIs…")
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(header, chunks[0]);

        // Progress gauge — uses probe-pair count over hostname count as
        // an approximation (ratio capped at 1.0 since IPs per SNI > 1).
        let ratio = if total_hostnames == 0 {
            0.0
        } else {
            (done as f64 / total_hostnames as f64).min(1.0)
        };
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" Progress "))
            .gauge_style(Style::default().fg(Color::Green))
            .ratio(ratio)
            .label(format!("{done} probes done (~{total_hostnames} hostnames)"));
        frame.render_widget(gauge, chunks[1]);

        // Results so far
        let rows: Vec<Row> = arrived
            .iter()
            .map(|e| {
                let tcp_str = e
                    .tcp_latency_ms
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "—".into());
                let tls_str = if e.tls_ok {
                    e.tls_latency_ms
                        .map(|ms| format!("✓ {ms}ms"))
                        .unwrap_or_else(|| "✓".into())
                } else {
                    "✗".into()
                };
                let ttfb_str = e
                    .ttfb_ms
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "—".into());
                let down_str = fmt_rate_bps(e.download_bps);
                let up_str = fmt_rate_bps(e.upload_bps);
                let http_str = e
                    .http_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "—".into());
                Row::new(vec![
                    Cell::from(e.score.to_string()).style(score_style(e.score)),
                    Cell::from(e.sni.clone()),
                    Cell::from(e.ip.to_string()),
                    Cell::from(tcp_str).style(tcp_style(e.tcp_latency_ms)),
                    Cell::from(tls_str).style(tls_style(e.tls_ok)),
                    Cell::from(ttfb_str),
                    Cell::from(down_str),
                    Cell::from(up_str),
                    Cell::from(http_str).style(http_style(e.http_status)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(5),
            Constraint::Min(28),
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(6),
        ];
        let table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    "Score", "SNI", "IP", "TCP", "TLS", "TTFB", "Down", "Up", "HTTP",
                ])
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Live results "),
            );
        frame.render_widget(table, chunks[2]);
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Interactive selection table
// ---------------------------------------------------------------------------

/// Show the ranked results table and let the user select one entry.
///
/// Returns the selected [`SniProbeEntry`].  If `entries` is empty this returns
/// an error.
pub fn run_selection(
    terminal: &mut Term,
    entries: &[SniProbeEntry],
) -> anyhow::Result<SniProbeEntry> {
    if entries.is_empty() {
        anyhow::bail!("no SNI candidates to select from");
    }

    let mut state = TableState::default();
    state.select(Some(0));

    loop {
        terminal.draw(|frame| draw_selection(frame, entries, &mut state))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some(i.saturating_sub(1)));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some((i + 1).min(entries.len() - 1)));
                    }
                    KeyCode::Enter => {
                        let idx = state.selected().unwrap_or(0);
                        return Ok(entries[idx].clone());
                    }
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                        // Default to rank-1.
                        return Ok(entries[0].clone());
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw_selection(frame: &mut ratatui::Frame, entries: &[SniProbeEntry], state: &mut TableState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(5),    // table
            Constraint::Length(3), // help bar
        ])
        .split(area);

    // Header
    let header = Paragraph::new("ZeroDPI — Select SNI")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    // Table
    let rows: Vec<Row> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let rank = (i + 1).to_string();
            let rank_style = if i == 0 {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let tcp_str = e
                .tcp_latency_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "—".into());
            let tls_str = if e.tls_ok {
                e.tls_latency_ms
                    .map(|ms| format!("✓ {ms}ms"))
                    .unwrap_or_else(|| "✓".into())
            } else {
                "✗".into()
            };
            let cert = if e.cert_valid { "✓" } else { "✗" };
            let ttfb_str = e
                .ttfb_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "—".into());
            let down_str = fmt_rate_bps(e.download_bps);
            let up_str = fmt_rate_bps(e.upload_bps);
            let http_str = e
                .http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "—".into());
            Row::new(vec![
                Cell::from(rank).style(rank_style),
                Cell::from(e.score.to_string()).style(score_style(e.score)),
                Cell::from(e.sni.clone()),
                Cell::from(e.ip.to_string()),
                Cell::from(tcp_str).style(tcp_style(e.tcp_latency_ms)),
                Cell::from(tls_str).style(tls_style(e.tls_ok)),
                Cell::from(cert).style(cert_style(e.cert_valid)),
                Cell::from(ttfb_str),
                Cell::from(down_str),
                Cell::from(up_str),
                Cell::from(http_str).style(http_style(e.http_status)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Min(26),
        Constraint::Length(16),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(6),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Score", "SNI", "IP", "TCP", "TLS", "Cert", "TTFB", "Down", "Up", "HTTP",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Ranked SNI candidates "),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, chunks[1], state);

    // Help bar
    let help_spans: Line = Line::from(vec![
        Span::styled(" ↑/↓ or j/k ", Style::default().fg(Color::Yellow)),
        Span::raw("navigate  "),
        Span::styled(" Enter ", Style::default().fg(Color::Green)),
        Span::raw("select  "),
        Span::styled(" q / Esc ", Style::default().fg(Color::Red)),
        Span::raw("pick rank-1 "),
    ]);
    let help = Paragraph::new(help_spans).block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

// ---------------------------------------------------------------------------
// Live proxy dashboard
// ---------------------------------------------------------------------------

/// Maximum number of connection records retained in the dashboard log.
const MAX_RECORDS: usize = 200;
const ACTIVE_RATE_BPS: f64 = 50.0;
const NON_RELAYING_TOP_GRACE: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrafficDirection {
    Idle,
    Upload,
    Download,
    Bidirectional,
}

/// Lifecycle status of a proxied connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnStatus {
    Connecting,
    Relaying,
    Done,
    Rotated,
    Failed,
}

impl ConnStatus {
    fn label(&self) -> &'static str {
        match self {
            ConnStatus::Connecting => "Connecting",
            ConnStatus::Relaying => "Relaying",
            ConnStatus::Done => "Done",
            ConnStatus::Rotated => "Rotated",
            ConnStatus::Failed => "Failed",
        }
    }

    fn style(&self) -> Style {
        match self {
            ConnStatus::Connecting => Style::default().fg(Color::Yellow),
            ConnStatus::Relaying => Style::default().fg(Color::Cyan),
            ConnStatus::Done => Style::default().fg(Color::Green),
            ConnStatus::Rotated => Style::default().fg(Color::Magenta),
            ConnStatus::Failed => Style::default().fg(Color::Red),
        }
    }
}

fn traffic_direction(
    status: &ConnStatus,
    upload_bps: f64,
    download_bps: f64,
) -> Option<TrafficDirection> {
    if !matches!(status, ConnStatus::Relaying) {
        return None;
    }

    match (
        upload_bps >= ACTIVE_RATE_BPS,
        download_bps >= ACTIVE_RATE_BPS,
    ) {
        (true, true) => Some(TrafficDirection::Bidirectional),
        (true, false) => Some(TrafficDirection::Upload),
        (false, true) => Some(TrafficDirection::Download),
        (false, false) => Some(TrafficDirection::Idle),
    }
}

fn connection_row_style(record: &ConnectionRecord) -> Style {
    match record.status {
        ConnStatus::Connecting => Style::default().bg(Color::Indexed(58)),
        ConnStatus::Relaying => {
            match traffic_direction(&record.status, record.rate_c2s_bps, record.rate_s2c_bps) {
                Some(TrafficDirection::Upload) => Style::default().bg(Color::Indexed(22)),
                Some(TrafficDirection::Download) => Style::default().bg(Color::Indexed(24)),
                Some(TrafficDirection::Bidirectional) => Style::default().bg(Color::Indexed(29)),
                Some(TrafficDirection::Idle) | None => Style::default(),
            }
        }
        ConnStatus::Failed => Style::default().bg(Color::Indexed(52)),
        ConnStatus::Done | ConnStatus::Rotated => Style::default(),
    }
}

// ---------------------------------------------------------------------------
// Connection log filter
// ---------------------------------------------------------------------------

/// Which connections to show in the dashboard log.
#[derive(Debug, Clone, PartialEq, Default)]
enum FilterStatus {
    #[default]
    All,
    Active,
    Done,
    Failed,
}

impl FilterStatus {
    fn label(&self) -> &'static str {
        match self {
            FilterStatus::All => "All",
            FilterStatus::Active => "Active",
            FilterStatus::Done => "Done",
            FilterStatus::Failed => "Failed",
        }
    }

    fn next(&self) -> Self {
        match self {
            FilterStatus::All => FilterStatus::Active,
            FilterStatus::Active => FilterStatus::Done,
            FilterStatus::Done => FilterStatus::Failed,
            FilterStatus::Failed => FilterStatus::All,
        }
    }

    fn matches(&self, status: &ConnStatus) -> bool {
        match self {
            FilterStatus::All => true,
            FilterStatus::Active => matches!(status, ConnStatus::Connecting | ConnStatus::Relaying),
            FilterStatus::Done => matches!(status, ConnStatus::Done | ConnStatus::Rotated),
            FilterStatus::Failed => matches!(status, ConnStatus::Failed),
        }
    }
}

/// Summary of the most recently completed background rescan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RescanSummary {
    found: usize,
    best_score: Option<u8>,
    duration_ms: u64,
    switched: bool,
}

/// The most recent fatal connection error, shown in the header.
#[derive(Debug, Clone)]
struct LastError {
    src_port: u16,
    message: String,
    at: SystemTime,
}

/// Per-connection record kept in the dashboard log.
struct ConnectionRecord {
    /// Wall-clock time at which the connection was accepted (for display).
    started_at: SystemTime,
    /// Monotonic start time (for duration calculation).
    start_instant: Instant,
    /// Monotonic end time, set when the connection is fully closed.
    end_instant: Option<Instant>,
    /// Source port of the outbound socket (unique connection identifier).
    src_port: u16,
    /// Address of the client that opened the inbound connection.
    peer: SocketAddr,
    /// Outbound target IP this connection relays to (from ConnectionAccepted).
    target_ip: IpAddr,
    target_sni: Option<std::sync::Arc<str>>,
    status: ConnStatus,
    status_changed_at: Instant,
    c2s_bytes: u64,
    s2c_bytes: u64,
    /// Instantaneous throughput (bytes/sec) computed from the last two RelayProgress events.
    rate_c2s_bps: f64,
    rate_s2c_bps: f64,
    /// Previous (time, c2s, s2c) snapshot used to compute the rate above.
    last_snapshot: Option<(Instant, u64, u64)>,
}

impl ConnectionRecord {
    fn is_active(&self) -> bool {
        matches!(self.status, ConnStatus::Connecting | ConnStatus::Relaying)
    }

    fn set_status(&mut self, status: ConnStatus, now: Instant) {
        if self.status != status {
            self.status = status;
            self.status_changed_at = now;
        }
    }

    fn duration_str(&self) -> String {
        let elapsed = self
            .end_instant
            .unwrap_or_else(Instant::now)
            .saturating_duration_since(self.start_instant);
        let ms = elapsed.as_millis();
        if ms < 1000 {
            format!("{}ms", ms)
        } else {
            format!("{:.1}s", elapsed.as_secs_f64())
        }
    }
}

fn connection_display_rank(record: &ConnectionRecord, now: Instant) -> u8 {
    if matches!(record.status, ConnStatus::Relaying) {
        0
    } else if now.saturating_duration_since(record.status_changed_at) < NON_RELAYING_TOP_GRACE {
        1
    } else {
        2
    }
}

fn ordered_connection_records(state: &DashboardState, now: Instant) -> Vec<&ConnectionRecord> {
    let mut filtered: Vec<(usize, &ConnectionRecord)> = state
        .records
        .iter()
        .enumerate()
        .filter(|(_, r)| state.filter.matches(&r.status))
        .collect();

    filtered.sort_by_key(|(idx, record)| (connection_display_rank(record, now), *idx));
    filtered.into_iter().map(|(_, record)| record).collect()
}

fn prune_connection_records(records: &mut VecDeque<ConnectionRecord>) {
    while records.len() > MAX_RECORDS {
        let Some(idx) = records.iter().rposition(|record| !record.is_active()) else {
            break;
        };
        records.remove(idx);
    }
}

// ---------------------------------------------------------------------------
// Dashboard state
// ---------------------------------------------------------------------------

/// All mutable state owned by the live proxy dashboard event loop.
struct DashboardState {
    reload_status: Option<String>,
    view: DashboardView,
    targets: TargetsState,
    target_pool: Option<(usize, zerodpi_core::target_pool::SelectionStrategy)>,
    records: VecDeque<ConnectionRecord>,
    total: u64,
    bypasses_ok: u64,
    bypasses_failed: u64,
    active: u64,
    total_c2s: u64,
    total_s2c: u64,
    scroll_offset: usize,
    /// When `true`, scroll is reset to 0 whenever new events arrive so the
    /// most recent connection is always visible.
    auto_scroll: bool,
    filter: FilterStatus,
    active_sni: Option<(String, Ipv4Addr, u8)>,
    active_ip: Option<IpAddr>,
    /// Last value discovered by `LOW_TTL_DISCOVER` (startup or rescan).
    low_ttl: Option<u8>,
    /// `true` while a periodic background rescan is running.
    rescan_running: bool,
    /// Deadline for the next rescan cycle, set from `NextRescanScheduled`.
    next_rescan_at: Option<Instant>,
    /// Highest number of simultaneously active connections seen so far.
    peak_active: u64,
    /// How many times the active target has been hot-swapped by a rescan.
    target_switches: u64,
    /// When the most recent target switch happened (for "Xs ago" display).
    last_switch_at: Option<Instant>,
    /// Number of completed background rescans.
    rescan_count: u64,
    /// Summary of the most recently completed rescan.
    last_rescan: Option<RescanSummary>,
    /// When the current rescan started (shown while running).
    rescan_started_at: Option<Instant>,
    /// Most recent ConnectionError, shown as a header line.
    last_error: Option<LastError>,
    /// Most recent network recovery status, shown as a header line.
    network_status: Option<String>,
    /// Score of the active IP target (from `IpTargetChanged`).
    active_ip_score: Option<u8>,
    /// (mode, bound address) reported by `ListenerStarted`.
    listener: Option<(String, SocketAddr)>,
    start: Instant,
    channel_closed: bool,
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn fmt_time(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n}B")
    } else if n < 1024 * 1024 {
        format!("{:.1}K", n as f64 / 1024.0)
    } else {
        format!("{:.1}M", n as f64 / (1024.0 * 1024.0))
    }
}

fn fmt_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Compact "how long ago" label for target switches.
fn fmt_ago(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h ago", secs / 3600)
    }
}

/// Status line for the dashboard header: shows a running indicator while a
/// background rescan is in progress, otherwise the countdown to the next
/// scheduled rescan. Returns `None` when no rescan is configured or has
/// ever been scheduled, so the line can be hidden entirely.
fn rescan_status_line(state: &DashboardState, now: Instant) -> Option<Line<'static>> {
    if state.rescan_running {
        let elapsed = state
            .rescan_started_at
            .map(|t| format!(" {}", fmt_uptime(now.saturating_duration_since(t))))
            .unwrap_or_default();
        return Some(Line::from(vec![
            Span::styled("Rescan: ", label_style()),
            Span::styled(
                format!("running…{elapsed}"),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    }
    let next_at = state.next_rescan_at?;
    let remaining = next_at.saturating_duration_since(now);
    let mut spans = vec![
        Span::styled("Next rescan in: ", label_style()),
        Span::styled(fmt_uptime(remaining), Style::default().fg(Color::White)),
    ];
    if let Some(last) = &state.last_rescan {
        let score = last
            .best_score
            .map(|s| s.to_string())
            .unwrap_or_else(|| "—".into());
        let verdict = if last.switched { "switched" } else { "kept" };
        spans.push(Span::styled(
            format!(
                "   · rescan #{}: {} found, best {}, {:.1}s, {}",
                state.rescan_count,
                last.found,
                score,
                last.duration_ms as f64 / 1000.0,
                verdict,
            ),
            Style::default().fg(Color::Gray),
        ));
    }
    Some(Line::from(spans))
}

/// Number of text lines the dashboard header renders, excluding borders.
fn header_content_rows(state: &DashboardState, now: Instant) -> usize {
    2 + usize::from(rescan_status_line(state, now).is_some())
        + usize::from(state.target_pool.is_some())
        + usize::from(state.network_status.is_some())
        + usize::from(state.last_error.is_some())
        + usize::from(state.reload_status.is_some())
}

/// Fixed rows consumed by the dashboard outside the connection table
/// (header, stats, help, table header, borders). The header is two rows
/// taller when the rescan status line is visible.
fn fixed_dashboard_rows(state: &DashboardState) -> usize {
    // header (content lines + borders + slack) + stats(4) + help(3)
    // + table header(1) + table borders(2)
    header_content_rows(state, Instant::now()) + 3 + 4 + 3 + 1 + 2
}

fn fmt_rate(bps: f64) -> String {
    if bps < ACTIVE_RATE_BPS {
        return "—".to_string();
    }
    if bps < 1024.0 {
        format!("{:.0}B/s", bps)
    } else if bps < 1_048_576.0 {
        format!("{:.1}K/s", bps / 1024.0)
    } else {
        format!("{:.1}M/s", bps / 1_048_576.0)
    }
}

fn fmt_stats_field(value: impl AsRef<str>) -> String {
    format!("{:>8}", value.as_ref())
}

fn live_transfer_totals(state: &DashboardState) -> (u64, u64) {
    let active_c2s: u64 = state
        .records
        .iter()
        .filter(|r| r.end_instant.is_none())
        .map(|r| r.c2s_bytes)
        .sum();
    let active_s2c: u64 = state
        .records
        .iter()
        .filter(|r| r.end_instant.is_none())
        .map(|r| r.s2c_bytes)
        .sum();

    (
        state.total_c2s.saturating_add(active_c2s),
        state.total_s2c.saturating_add(active_s2c),
    )
}

/// Sum the instantaneous rates of all relaying connections:
/// returns `(c2s_bps, s2c_bps)`.
fn aggregate_throughput(records: &VecDeque<ConnectionRecord>) -> (f64, f64) {
    let mut c2s = 0.0f64;
    let mut s2c = 0.0f64;
    for record in records
        .iter()
        .filter(|r| matches!(r.status, ConnStatus::Relaying))
    {
        c2s += record.rate_c2s_bps;
        s2c += record.rate_s2c_bps;
    }
    (c2s, s2c)
}

// ---------------------------------------------------------------------------
// Dashboard public entry point
// ---------------------------------------------------------------------------

/// Show the live proxy dashboard.
///
/// Receives [`ProxyEvent`]s from `rx` and redraws every 200 ms.  Blocks until
/// the user presses `q`/`Esc`/`Ctrl-C` **or** the proxy channel closes.
/// After the channel closes the dashboard stays visible so the user can inspect
/// the final state; pressing any quit key (or waiting for the next key press)
/// exits.
pub enum DashboardExit {
    Quit,
    Reload(std::sync::Arc<Config>),
}

fn handle_reload_key(
    state: &mut DashboardState,
    key: KeyCode,
    cfg: &Config,
    reload: &crate::reload::Session,
    scan_busy: bool,
) -> Option<std::sync::Arc<Config>> {
    if !matches!(key, KeyCode::Char('l') | KeyCode::Char('L')) {
        return None;
    }
    if state.rescan_running || scan_busy {
        state.reload_status = Some("Config reload busy: wait for the current scan".into());
        return None;
    }
    match reload.candidate((!state.channel_closed).then_some(cfg)) {
        Ok(Some(next)) => {
            state.reload_status = Some("Reloading config; closing current connections...".into());
            Some(next)
        }
        Ok(None) => {
            state.reload_status = Some("Config unchanged".into());
            None
        }
        Err(error) => {
            state.reload_status = Some(format!("Config reload failed: {error:#}"));
            None
        }
    }
}

pub fn run_dashboard(
    terminal: &mut Term,
    rx: &mut ProxyEventReceiver,
    info: &DashboardInfo,
    cfg: &Config,
    rescan: &mut RescanController,
    pool: &TargetPool,
    reload: &mut crate::reload::Session,
) -> anyhow::Result<DashboardExit> {
    let active_sni = match info {
        DashboardInfo::SniSpoof { sni, ip, score } => Some((sni.clone(), *ip, *score)),
        DashboardInfo::IpBypass { .. } | DashboardInfo::IpBypassPlus { .. } => None,
    };
    let active_ip = match info {
        DashboardInfo::SniSpoof { .. } => None,
        DashboardInfo::IpBypass { ip } | DashboardInfo::IpBypassPlus { ip } => Some(*ip),
    };
    let mut state = DashboardState {
        reload_status: reload.notice.clone(),
        view: DashboardView::Connections,
        targets: TargetsState::default(),
        target_pool: None,
        records: VecDeque::with_capacity(MAX_RECORDS),
        total: 0,
        bypasses_ok: 0,
        bypasses_failed: 0,
        active: 0,
        total_c2s: 0,
        total_s2c: 0,
        scroll_offset: 0,
        auto_scroll: true,
        filter: FilterStatus::All,
        active_sni,
        active_ip,
        low_ttl: None,
        rescan_running: false,
        next_rescan_at: None,
        peak_active: 0,
        target_switches: 0,
        last_switch_at: None,
        rescan_count: 0,
        last_rescan: None,
        rescan_started_at: None,
        last_error: None,
        network_status: None,
        active_ip_score: None,
        listener: None,
        start: Instant::now(),
        channel_closed: false,
    };

    for event in reload.take_initial_events() {
        apply_event(event, &mut state);
    }

    // Keys typed during startup/reload must not queue a second reload. Preserve
    // navigation and quit keys so users can still leave immediately afterwards.
    let mut pending_input = VecDeque::new();
    while event::poll(Duration::ZERO)? {
        let input = event::read()?;
        if !matches!(input, Event::Key(k) if matches!(k.code, KeyCode::Char('l') | KeyCode::Char('L')))
        {
            pending_input.push_back(input);
        }
    }

    loop {
        // Drain all currently available events.
        let mut got_event = false;
        if !state.channel_closed {
            loop {
                match rx.try_recv() {
                    Ok(event) => {
                        apply_event(event, &mut state);
                        got_event = true;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        state.channel_closed = true;
                        break;
                    }
                }
            }
        }

        if let Ok(selection) = rescan.selections.try_recv() {
            let result = match selection {
                Selection::Sni(entries, reply) => {
                    let result = run_selection(terminal, &entries);
                    let _ = reply.send(result.as_ref().ok().cloned());
                    result.map(|_| ())
                }
                Selection::Ip(entries, reply) => {
                    let result = run_ip_selection(terminal, &entries);
                    let _ = reply.send(result.as_ref().ok().cloned());
                    result.map(|_| ())
                }
            };
            if let Err(error) = result {
                state.last_error = Some(LastError {
                    src_port: 0,
                    message: format!("rescan selection: {error}"),
                    at: SystemTime::now(),
                });
            }
            terminal.clear()?;
        }

        if state.view == DashboardView::Connections && state.auto_scroll && got_event {
            state.scroll_offset = 0;
        }

        if state.targets.refresh(pool, Instant::now()) && cfg.LOAD_BALANCE_ENABLED {
            state.target_pool = Some((
                state
                    .targets
                    .rows
                    .iter()
                    .filter(|row| row.snapshot.rank.is_some())
                    .count(),
                state.targets.strategy,
            ));
        }
        if state.channel_closed {
            state.targets.stop();
        }
        draw_dashboard(terminal, &state, info, cfg)?;

        // Filtered count — needed for scroll bounds in key handler.
        let filtered_connections = state
            .records
            .iter()
            .filter(|r| state.filter.matches(&r.status))
            .count();

        let filtered_len = match state.view {
            DashboardView::Connections => filtered_connections,
            DashboardView::Targets => state.targets.rows.len(),
        };
        // Page size: terminal height minus the fixed widget rows (computed by
        // fixed_dashboard_rows: header, stats, help, table header, and table
        // borders).
        let visible_rows = terminal
            .size()
            .map(|s| {
                (s.height as usize).saturating_sub(fixed_dashboard_rows(&state))
                    / if s.width >= 140 { 1 } else { 2 }
            })
            .unwrap_or(10)
            .max(1);

        if !pending_input.is_empty()
            || event::poll(
                Duration::from_millis(200).min(state.targets.next_sample_in(Instant::now())),
            )?
        {
            if let Event::Key(k) = match pending_input.pop_front() {
                Some(input) => input,
                None => event::read()?,
            } {
                if k.kind == KeyEventKind::Press {
                    match k.code {
                        KeyCode::Char('l') | KeyCode::Char('L') => {
                            let scan_busy = crate::manual_rescan::SCAN_LOCK.try_lock().is_err();
                            if let Some(next) =
                                handle_reload_key(&mut state, k.code, cfg, reload, scan_busy)
                            {
                                reload.remember_ttl(state.low_ttl);
                                draw_dashboard(terminal, &state, info, cfg)?;
                                return Ok(DashboardExit::Reload(next));
                            }
                        }
                        KeyCode::Char('r') | KeyCode::Char('R')
                            if !state.rescan_running && !state.channel_closed =>
                        {
                            if rescan.requests.try_send(()).is_ok() {
                                state.rescan_running = true;
                                state.rescan_started_at = Some(Instant::now());
                            }
                        }
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                            return Ok(DashboardExit::Quit);
                        }
                        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                            return Ok(DashboardExit::Quit);
                        }
                        _ => handle_dashboard_navigation(
                            &mut state,
                            k.code,
                            filtered_len,
                            visible_rows,
                        ),
                    }
                }
            }
        }
    }
}

/// Keep a recoverable failure on the same alternate screen, even when there is
/// no running listener or when interceptor cleanup has not been confirmed.
pub fn run_reload_error(terminal: &mut Term, message: &str) -> anyhow::Result<bool> {
    terminal.clear()?;
    loop {
        terminal.draw(|frame| {
            let text = format!("{message}\n\nL reload config / retry    q/Esc quit");
            frame.render_widget(
                Paragraph::new(text)
                    .wrap(ratatui::widgets::Wrap { trim: false })
                    .block(
                        Block::default()
                            .title(" ZeroDPI — Stopped ")
                            .borders(Borders::ALL),
                    ),
                frame.area(),
            );
        })?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('l') | KeyCode::Char('L') => return Ok(true),
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => return Ok(false),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(false)
                    }
                    _ => {}
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Event processing
// ---------------------------------------------------------------------------

fn apply_event(event: ProxyEvent, state: &mut DashboardState) {
    match event {
        ProxyEvent::TargetPoolUpdated {
            target_count,
            strategy,
        } => {
            state.target_pool = Some((target_count, strategy));
        }
        ProxyEvent::ListenerStarted { mode, listen_addr } => {
            state.listener = Some((mode, listen_addr));
        }
        ProxyEvent::ConnectionAccepted {
            peer,
            src_port,
            target_ip,
            target_sni,
        } => {
            state.total += 1;
            state.active += 1;
            state.peak_active = state.peak_active.max(state.active);
            let now = Instant::now();
            let rec = ConnectionRecord {
                started_at: SystemTime::now(),
                start_instant: now,
                end_instant: None,
                src_port,
                peer,
                target_ip,
                target_sni,
                status: ConnStatus::Connecting,
                status_changed_at: now,
                c2s_bytes: 0,
                s2c_bytes: 0,
                rate_c2s_bps: 0.0,
                rate_s2c_bps: 0.0,
                last_snapshot: None,
            };
            state.records.push_front(rec);
        }
        ProxyEvent::BypassComplete { src_port, outcome } => match outcome {
            BypassOutcome::FakeDataAcked => {
                state.bypasses_ok += 1;
                if let Some(r) = find_record(&mut state.records, src_port) {
                    r.set_status(ConnStatus::Relaying, Instant::now());
                }
            }
            BypassOutcome::UnexpectedClose => {
                state.bypasses_failed += 1;
                state.active = state.active.saturating_sub(1);
                if let Some(r) = find_record(&mut state.records, src_port) {
                    let now = Instant::now();
                    r.set_status(ConnStatus::Failed, now);
                    r.end_instant = Some(now);
                }
            }
        },
        ProxyEvent::RelayFinished {
            src_port,
            c2s_bytes,
            s2c_bytes,
            reason,
        } => {
            state.active = state.active.saturating_sub(1);
            state.total_c2s += c2s_bytes;
            state.total_s2c += s2c_bytes;
            if let Some(r) = find_record(&mut state.records, src_port) {
                let now = Instant::now();
                let status = match reason {
                    RelayEndReason::Completed => ConnStatus::Done,
                    RelayEndReason::MaxLifetime => ConnStatus::Rotated,
                    RelayEndReason::NetworkError => ConnStatus::Failed,
                };
                r.set_status(status, now);
                r.c2s_bytes = c2s_bytes;
                r.s2c_bytes = s2c_bytes;
                r.rate_c2s_bps = 0.0;
                r.rate_s2c_bps = 0.0;
                r.end_instant = Some(now);
            }
        }
        ProxyEvent::RelayProgress {
            src_port,
            c2s_bytes,
            s2c_bytes,
        } => {
            if let Some(r) = find_record(&mut state.records, src_port) {
                apply_relay_progress(
                    r,
                    RelayProgress {
                        src_port,
                        c2s_bytes,
                        s2c_bytes,
                    },
                    Instant::now(),
                );
            }
        }
        ProxyEvent::RelayProgressBatch {
            sampled_at,
            entries,
        } => {
            let mut progress: HashMap<_, _> = entries
                .into_iter()
                .map(|entry| (entry.src_port, entry))
                .collect();
            // Records are newest first. Apply each port once, ignoring finished rows.
            for record in state
                .records
                .iter_mut()
                .filter(|record| matches!(record.status, ConnStatus::Relaying))
            {
                if let Some(entry) = progress.remove(&record.src_port) {
                    apply_relay_progress(record, entry, sampled_at);
                }
            }
        }
        ProxyEvent::ConnectionError { src_port, error } => {
            state.last_error = Some(LastError {
                src_port,
                message: error,
                at: SystemTime::now(),
            });
            state.bypasses_failed += 1;
            state.active = state.active.saturating_sub(1);
            if let Some(r) = find_record(&mut state.records, src_port) {
                let now = Instant::now();
                r.set_status(ConnStatus::Failed, now);
                r.end_instant = Some(now);
            }
        }
        ProxyEvent::NetworkStatus { status } => {
            state.network_status = Some(match status {
                zerodpi_core::proxy::NetworkStatus::Online { interface_ip } => {
                    interface_ip.to_string()
                }
                zerodpi_core::proxy::NetworkStatus::Changing { interface_ip } => {
                    format!("changing to {interface_ip}")
                }
                zerodpi_core::proxy::NetworkStatus::Recovering { attempt } => {
                    format!("recovering (attempt {attempt})")
                }
                zerodpi_core::proxy::NetworkStatus::Unavailable { message } => {
                    format!("unavailable ({message})")
                }
            });
        }
        ProxyEvent::SniTargetChanged { sni, ip, score } => {
            let changed = state
                .active_sni
                .as_ref()
                .map(|(old_sni, old_ip, _)| (old_sni.as_str(), *old_ip))
                != Some((sni.as_str(), ip));
            state.active_sni = Some((sni, ip, score));
            if changed {
                state.target_switches += 1;
                state.last_switch_at = Some(Instant::now());
            }
        }
        ProxyEvent::IpTargetChanged { ip, score } => {
            let changed = state.active_ip != Some(ip);
            state.active_ip = Some(ip);
            state.active_ip_score = Some(score);
            if changed {
                state.target_switches += 1;
                state.last_switch_at = Some(Instant::now());
            }
        }
        ProxyEvent::LowTtlDiscovered { value } => {
            state.low_ttl = Some(value);
        }
        ProxyEvent::NextRescanScheduled { interval_secs, .. } => {
            state.next_rescan_at = Some(Instant::now() + Duration::from_secs(interval_secs));
        }
        ProxyEvent::RescanStarted { .. } => {
            state.rescan_running = true;
            state.rescan_started_at = Some(Instant::now());
        }
        ProxyEvent::RescanFinished {
            found,
            best_score,
            duration_ms,
            switched,
            ..
        } => {
            state.rescan_running = false;
            state.rescan_started_at = None;
            state.rescan_count += 1;
            state.last_rescan = Some(RescanSummary {
                found,
                best_score,
                duration_ms,
                switched,
            });
        }
    }

    prune_connection_records(&mut state.records);
}

fn apply_relay_progress(
    record: &mut ConnectionRecord,
    progress: RelayProgress,
    sampled_at: Instant,
) {
    if !matches!(record.status, ConnStatus::Relaying) {
        return;
    }
    if let Some((previous, c2s, s2c)) = record.last_snapshot {
        if sampled_at <= previous {
            return;
        }
        let seconds = sampled_at.duration_since(previous).as_secs_f64().max(0.001);
        record.rate_c2s_bps = progress.c2s_bytes.saturating_sub(c2s) as f64 / seconds;
        record.rate_s2c_bps = progress.s2c_bytes.saturating_sub(s2c) as f64 / seconds;
    }
    record.c2s_bytes = progress.c2s_bytes;
    record.s2c_bytes = progress.s2c_bytes;
    record.last_snapshot = Some((sampled_at, progress.c2s_bytes, progress.s2c_bytes));
}

fn find_record(
    records: &mut VecDeque<ConnectionRecord>,
    src_port: u16,
) -> Option<&mut ConnectionRecord> {
    records.iter_mut().find(|r| r.src_port == src_port)
}

// ---------------------------------------------------------------------------
// Dashboard rendering
// ---------------------------------------------------------------------------

fn handle_dashboard_navigation(state: &mut DashboardState, key: KeyCode, len: usize, page: usize) {
    if matches!(key, KeyCode::Char('v') | KeyCode::Char('V')) {
        state.view = match state.view {
            DashboardView::Connections => DashboardView::Targets,
            DashboardView::Targets => DashboardView::Connections,
        };
        return;
    }
    if key == KeyCode::Tab {
        if state.view == DashboardView::Connections {
            state.filter = state.filter.next();
            state.scroll_offset = 0;
        }
        return;
    }
    if matches!(key, KeyCode::Char(' ') | KeyCode::Char('a')) {
        if state.view == DashboardView::Connections {
            state.auto_scroll = !state.auto_scroll;
            if state.auto_scroll {
                state.scroll_offset = 0;
            }
        }
        return;
    }
    if !matches!(
        key,
        KeyCode::Up
            | KeyCode::Down
            | KeyCode::Char('j')
            | KeyCode::Char('k')
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Home
            | KeyCode::End
    ) {
        return;
    }
    if state.view == DashboardView::Connections && key != KeyCode::Home {
        state.auto_scroll = false;
    }
    let offset = match state.view {
        DashboardView::Connections => &mut state.scroll_offset,
        DashboardView::Targets => &mut state.targets.scroll_offset,
    };
    *offset = match key {
        KeyCode::Up | KeyCode::Char('k') => offset.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => offset.saturating_add(1).min(len.saturating_sub(1)),
        KeyCode::PageUp => offset.saturating_sub(page),
        KeyCode::PageDown => offset.saturating_add(page).min(len.saturating_sub(1)),
        KeyCode::Home => 0,
        KeyCode::End => len.saturating_sub(1),
        _ => *offset,
    };
}

fn draw_connections(
    frame: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    state: &DashboardState,
    show_sni: bool,
    now: Instant,
) {
    let filtered = ordered_connection_records(state, now);
    let title = format!(
        " Connections [{}] ({} shown / {} total) ",
        state.filter.label(),
        filtered.len(),
        state.records.len()
    );
    let wide = area.width >= 140;
    let widths: Vec<u16> = if wide {
        let mut widths = vec![8, 18, 24];
        if show_sni {
            widths.push(
                area.width
                    .saturating_sub(2 + 9 + 8 + 18 + 24 + 10 + 7 + 7 + 9 + 9 + 8),
            );
        }
        widths.extend([10, 7, 7, 9, 9, 8]);
        widths
    } else if show_sni {
        vec![
            24.min(area.width / 3),
            area.width.saturating_sub(4 + 24.min(area.width / 3) + 18),
            18,
        ]
    } else {
        vec![
            area.width.saturating_sub(3) / 2,
            area.width.saturating_sub(3).div_ceil(2),
        ]
    };
    let rows = filtered.iter().skip(state.scroll_offset).map(|record| {
        let texts = if wide {
            let mut cells = vec![
                fmt_time(record.started_at),
                record.peer.to_string(),
                record.target_ip.to_string(),
            ];
            if show_sni {
                cells.push(record.target_sni.as_deref().unwrap_or("—").into());
            }
            cells.extend([
                record.status.label().into(),
                fmt_bytes(record.c2s_bytes),
                fmt_bytes(record.s2c_bytes),
                fmt_rate(record.rate_c2s_bps),
                fmt_rate(record.rate_s2c_bps),
                record.duration_str(),
            ]);
            cells
        } else {
            let up = format!(
                "↑ {} / {}",
                fmt_rate(record.rate_c2s_bps),
                fmt_bytes(record.c2s_bytes)
            );
            let down = format!(
                "↓ {} / {}",
                fmt_rate(record.rate_s2c_bps),
                fmt_bytes(record.s2c_bytes)
            );
            if show_sni {
                vec![
                    format!(
                        "{}\n{}",
                        fit(&record.target_ip.to_string(), widths[0]),
                        fit(&up, widths[0])
                    ),
                    format!(
                        "{}\n{}",
                        fit(record.target_sni.as_deref().unwrap_or("—"), widths[1]),
                        fit(&down, widths[1])
                    ),
                    format!(
                        "{}\n{}",
                        record.status.label(),
                        fit(&record.duration_str(), widths[2])
                    ),
                ]
            } else {
                vec![
                    format!(
                        "{}\n{}",
                        fit(&record.target_ip.to_string(), widths[0]),
                        fit(&up, widths[0])
                    ),
                    format!("{}\n{}", record.status.label(), fit(&down, widths[1])),
                ]
            }
        };
        let status_column = if wide {
            if show_sni {
                4
            } else {
                3
            }
        } else if show_sni {
            2
        } else {
            1
        };
        let cells: Vec<_> = texts
            .into_iter()
            .zip(&widths)
            .enumerate()
            .map(|(index, (text, width))| {
                let cell = Cell::from(if wide { fit(&text, *width) } else { text });
                if index == status_column {
                    cell.style(record.status.style())
                } else {
                    cell
                }
            })
            .collect();
        Row::new(cells)
            .height(if wide { 1 } else { 2 })
            .style(connection_row_style(record))
    });
    let headers = if wide {
        let mut headers = vec!["Time", "Peer", "Target"];
        if show_sni {
            headers.push("SNI");
        }
        headers.extend(["Status", "↑ Bytes", "↓ Bytes", "Rate↑", "Rate↓", "Duration"]);
        headers
    } else if show_sni {
        vec!["Target / upload", "SNI / download", "Status / duration"]
    } else {
        vec!["Target / upload", "Status / download"]
    };
    let header = Row::new(
        headers
            .into_iter()
            .zip(&widths)
            .map(|(text, width)| Cell::from(fit(text, *width))),
    )
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    );
    frame.render_widget(
        Table::new(rows, widths.iter().copied().map(Constraint::Length))
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn draw_dashboard<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    state: &DashboardState,
    info: &DashboardInfo,
    cfg: &Config,
) -> anyhow::Result<()> {
    terminal.draw(|frame| {
        let area = frame.area();
        let now = Instant::now();
        let rescan_line = rescan_status_line(state, now);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length((header_content_rows(state, now) + 3) as u16), // header lines + borders + slack
                Constraint::Length(4), // stats bar (2 content lines + borders)
                Constraint::Min(5),    // connection log
                Constraint::Length(3), // help bar
            ])
            .split(area);

        // ── Header ──────────────────────────────────────────────────────────
        let title = if state.channel_closed {
            " ZeroDPI — Stopped "
        } else {
            " ZeroDPI — Running "
        };
        let uptime = fmt_uptime(state.start.elapsed());
        let mut header_lines = match info {
            DashboardInfo::SniSpoof { .. } => {
                let (sni, ip, score) = state
                    .active_sni
                    .as_ref()
                    .expect("SNI dashboard state is initialised");
                vec![
                    {
                        let mut spans = vec![
                            Span::styled(if state.target_pool.is_some() { "Rank 1 SNI: " } else { "SNI: " }, label_style()),
                            Span::styled(
                                fit(sni, area.width.saturating_sub(67)),
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::raw("   "),
                            Span::styled("IP: ", label_style()),
                            Span::styled(ip.to_string(), Style::default().fg(Color::White)),
                            Span::raw("   "),
                            Span::styled("Score: ", label_style()),
                            Span::styled(score.to_string(), score_style(*score)),
                            Span::raw("   "),
                            Span::styled("Switches: ", label_style()),
                            Span::styled(
                                state.target_switches.to_string(),
                                Style::default().fg(Color::White),
                            ),
                        ];
                        if let Some(at) = state.last_switch_at {
                            spans.push(Span::styled(
                                format!(" ({})", fmt_ago(now.saturating_duration_since(at))),
                                label_style(),
                            ));
                        }
                        Line::from(spans)
                    },
                    Line::from({
                        let mut spans = vec![
                            Span::styled("Method: ", label_style()),
                            Span::styled(
                                cfg.BYPASS_METHOD.to_string(),
                                Style::default().fg(Color::White),
                            ),
                            Span::raw("   "),
                            Span::styled("Listen: ", label_style()),
                            Span::styled(
                                state
                                    .listener
                                    .as_ref()
                                    .map(|(_, addr)| addr.to_string())
                                    .unwrap_or_else(|| {
                                        format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
                                    }),
                                Style::default().fg(Color::White),
                            ),
                            Span::raw("   "),
                            Span::styled("Uptime: ", label_style()),
                            Span::styled(uptime, Style::default().fg(Color::White)),
                        ];
                        if let Some(value) = state.low_ttl {
                            spans.push(Span::raw("   "));
                            spans.push(Span::styled("Low TTL: ", label_style()));
                            spans.push(Span::styled(
                                value.to_string(),
                                Style::default().fg(Color::Green),
                            ));
                        }
                        spans
                    }),
                ]
            }
            DashboardInfo::IpBypass { .. } | DashboardInfo::IpBypassPlus { .. } => {
                let ip = state.active_ip.expect("IP dashboard state is initialised");
                let mode_label = match info {
                    DashboardInfo::IpBypass { .. } => "ip_bypass",
                    DashboardInfo::IpBypassPlus { .. } => "ip_bypass_plus",
                    DashboardInfo::SniSpoof { .. } => unreachable!(),
                };
                let status_line = match info {
                    DashboardInfo::IpBypass { .. } => Line::from(vec![
                        Span::styled("Uptime: ", label_style()),
                        Span::styled(uptime, Style::default().fg(Color::White)),
                    ]),
                    DashboardInfo::IpBypassPlus { .. } => Line::from(vec![
                        Span::styled("Method: ", label_style()),
                        Span::styled(
                            cfg.BYPASS_METHOD.to_string(),
                            Style::default().fg(Color::White),
                        ),
                        Span::raw("   "),
                        Span::styled("Uptime: ", label_style()),
                        Span::styled(uptime, Style::default().fg(Color::White)),
                    ]),
                    DashboardInfo::SniSpoof { .. } => unreachable!(),
                };
                vec![
                    {
                        let mut spans = vec![
                            Span::styled("Mode: ", label_style()),
                            Span::styled(
                                mode_label,
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::raw("   "),
                            Span::styled(if state.target_pool.is_some() { "Rank 1 IP: " } else { "Active IP: " }, label_style()),
                            Span::styled(ip.to_string(), Style::default().fg(Color::White)),
                        ];
                        if let Some(score) = state.active_ip_score {
                            spans.push(Span::raw("  "));
                            spans.push(Span::styled("Score: ", label_style()));
                            spans.push(Span::styled(score.to_string(), score_style(score)));
                        }
                        spans.push(Span::raw("  "));
                        spans.push(Span::styled("Switches: ", label_style()));
                        spans.push(Span::styled(
                            state.target_switches.to_string(),
                            Style::default().fg(Color::White),
                        ));
                        if let Some(at) = state.last_switch_at {
                            spans.push(Span::styled(
                                format!(" ({})", fmt_ago(now.saturating_duration_since(at))),
                                label_style(),
                            ));
                        }
                        spans.push(Span::raw("   "));
                        spans.push(Span::styled("Listen: ", label_style()));
                        spans.push(Span::styled(
                            state
                                .listener
                                .as_ref()
                                .map(|(_, addr)| addr.to_string())
                                .unwrap_or_else(|| {
                                    format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
                                }),
                            Style::default().fg(Color::White),
                        ));
                        Line::from(spans)
                    },
                    status_line,
                ]
            }
        };
        if let Some((count, strategy)) = state.target_pool {
            header_lines.push(Line::from(format!(
                "Load balancing: ON   Targets: {count}   Strategy: {strategy}   Rank 1"
            )));
        }
        if let Some(line) = rescan_line {
            header_lines.push(line);
        }
        if let Some(status) = &state.network_status {
            header_lines.push(Line::from(vec![
                Span::styled(
                    "Network: ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(status.clone(), label_style()),
            ]));
        }
        if let Some(err) = &state.last_error {
            header_lines.push(Line::from(vec![
                Span::styled(
                    "Last error: ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("[{}] {}", err.src_port, err.message),
                    Style::default().fg(Color::Red),
                ),
                Span::styled(format!("  {}", fmt_time(err.at)), label_style()),
            ]));
        }
        if let Some(status) = &state.reload_status {
            header_lines.push(Line::from(Span::styled(status.clone(), Style::default().fg(Color::Yellow))));
        }
        let header =
            Paragraph::new(header_lines).block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(header, chunks[0]);

        // ── Stats bar ────────────────────────────────────────────────────────
        let ok_pct = state
            .bypasses_ok
            .saturating_mul(100)
            .checked_div(state.total)
            .map_or_else(String::new, |pct| format!("({pct}%)"));
        // Aggregate instantaneous throughput from all relaying connections.
        let (agg_c2s_bps, agg_s2c_bps) = aggregate_throughput(&state.records);
        let (total_upload, total_download) = live_transfer_totals(state);
        let stats_line = Line::from(vec![
            Span::styled("Total: ", label_style()),
            Span::styled(
                state.total.to_string(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("OK: ", label_style()),
            Span::styled(
                state.bypasses_ok.to_string(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {ok_pct}"), Style::default().fg(Color::Green)),
            Span::raw("  "),
            Span::styled("Failed: ", label_style()),
            Span::styled(
                state.bypasses_failed.to_string(),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("Active: ", label_style()),
            Span::styled(
                state.active.to_string(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("Peak: ", label_style()),
            Span::styled(
                state.peak_active.to_string(),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);
        let stats_line2 = Line::from(vec![
            Span::styled("Download: ", label_style()),
            Span::styled(
                fmt_stats_field(fmt_rate(agg_s2c_bps)),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(" / ", label_style()),
            Span::styled(
                fmt_stats_field(fmt_bytes(total_download)),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("  "),
            Span::styled("Upload: ", label_style()),
            Span::styled(
                fmt_stats_field(fmt_rate(agg_c2s_bps)),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(" / ", label_style()),
            Span::styled(
                fmt_stats_field(fmt_bytes(total_upload)),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" "),
        ]);
        let stats = Paragraph::new(vec![stats_line, stats_line2])
            .block(Block::default().borders(Borders::ALL).title(" Stats "));
        frame.render_widget(stats, chunks[1]);

        // ── Connection log ───────────────────────────────────────────────────
        match state.view {
            DashboardView::Connections => draw_connections(frame, chunks[2], state,
                matches!(info, DashboardInfo::SniSpoof { .. }), now),
            DashboardView::Targets => draw_targets(frame, chunks[2], &state.targets),
        }

        let auto_span = if state.view == DashboardView::Targets {
            Span::styled("[TARGETS] ", Style::default().fg(Color::Cyan))
        } else if state.auto_scroll {
            Span::styled(
                "[AUTO] ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(
                "[PAUSED] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        };
        let help_line = if area.width < 140 {
            Line::from(vec![
                auto_span,
                Span::styled(" v ", Style::default().fg(Color::Cyan)), Span::raw("views "),
                Span::styled(" R ", Style::default().fg(Color::Cyan)), Span::raw("rescan "),
                Span::styled(" L ", Style::default().fg(Color::Cyan)), Span::raw("reload config "),
                Span::raw(if state.view == DashboardView::Connections {
                    "↑/↓ scroll  Tab filter  q/Esc quit"
                } else {
                    "↑/↓ scroll  q/Esc quit"
                }),
            ])
        } else {
            Line::from(vec![
                auto_span,
                Span::styled(" v ", Style::default().fg(Color::Cyan)), Span::raw("views  "),
                Span::styled(" R ", Style::default().fg(Color::Cyan)), Span::raw("rescan  "),
                Span::styled(" L ", Style::default().fg(Color::Cyan)), Span::raw("reload config  "),
                Span::raw(if state.view == DashboardView::Connections {
                    "↑/↓ j/k scroll  PgUp/Dn page  Home/End jump  Space/a auto  Tab filter  q/Esc quit"
                } else {
                    "↑/↓ j/k scroll  PgUp/Dn page  Home/End jump  q/Esc quit"
                }),
            ])
        };
        let help = Paragraph::new(help_line).block(Block::default().borders(Borders::ALL));
        frame.render_widget(help, chunks[3]);
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// IP scan progress view
// ---------------------------------------------------------------------------

/// Show a live scan-progress screen while the IP scan runs in the background.
///
/// `rx` receives one [`IpProbeEntry`] per IP that has completed Phase 2+3.
/// `total_ips` is the total number of IPs being scanned (for the progress gauge).
///
/// Returns `(entries, aborted)` where `aborted = true` when the user pressed
/// `q`/`Esc` before the scan finished.
pub fn run_ip_scan_progress(
    terminal: &mut Term,
    rx: &mut mpsc::UnboundedReceiver<IpScanEvent>,
    total_ips: usize,
) -> anyhow::Result<(Vec<IpProbeEntry>, bool)> {
    let mut arrived: Vec<IpProbeEntry> = Vec::new();
    let mut tcp_done: usize = 0;

    loop {
        loop {
            match rx.try_recv() {
                Ok(IpScanEvent::TcpDone { tcp_tested }) => {
                    tcp_done = tcp_tested;
                }
                Ok(IpScanEvent::ProbeComplete(entry)) => {
                    arrived.push(entry);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    draw_ip_scan_progress(terminal, &arrived, tcp_done, total_ips)?;
                    return Ok((arrived, false));
                }
            }
        }

        draw_ip_scan_progress(terminal, &arrived, tcp_done, total_ips)?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press
                    && matches!(
                        k.code,
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc
                    )
                {
                    return Ok((arrived, true));
                }
            }
        }
    }
}

fn draw_ip_scan_progress(
    terminal: &mut Term,
    arrived: &[IpProbeEntry],
    tcp_done: usize,
    total_ips: usize,
) -> anyhow::Result<()> {
    let probe_count = arrived.len();
    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(5),
            ])
            .split(area);

        let header = Paragraph::new("ZeroDPI — Scanning IPs…")
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(header, chunks[0]);

        // Phase 1 (TCP) drives the gauge; Phase 2 count shown in the label.
        let ratio = if total_ips == 0 {
            0.0
        } else {
            (tcp_done as f64 / total_ips as f64).min(1.0)
        };
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" Progress "))
            .gauge_style(Style::default().fg(Color::Green))
            .ratio(ratio)
            .label(format!(
                "{tcp_done}/{total_ips} TCP tested — {probe_count} TLS probed"
            ));
        frame.render_widget(gauge, chunks[1]);

        let rows: Vec<Row> = arrived
            .iter()
            .map(|e| {
                let tcp_str = e
                    .tcp_latency_ms
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "fail".into());
                let tls_str = if e.tls_ok {
                    e.tls_latency_ms
                        .map(|ms| format!("✓ {ms}ms"))
                        .unwrap_or_else(|| "✓".into())
                } else {
                    "✗".into()
                };
                let ttfb_str = e
                    .ttfb_ms
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "—".into());
                let cert = if e.cert_valid { "✓" } else { "✗" };
                let down_str = fmt_rate_bps(e.download_bps);
                let up_str = fmt_rate_bps(e.upload_bps);
                let http_str = e
                    .http_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "—".into());
                Row::new(vec![
                    Cell::from(e.score.to_string()).style(score_style(e.score)),
                    Cell::from(e.ip.to_string()),
                    Cell::from(tcp_str).style(tcp_style(e.tcp_latency_ms)),
                    Cell::from(tls_str).style(tls_style(e.tls_ok)),
                    Cell::from(cert).style(cert_style(e.cert_valid)),
                    Cell::from(ttfb_str),
                    Cell::from(down_str),
                    Cell::from(up_str),
                    Cell::from(http_str).style(http_style(e.http_status)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(5),
            Constraint::Min(36),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(6),
        ];
        let table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    "Score", "IP", "TCP", "TLS", "Cert", "TTFB", "Down", "Up", "HTTP",
                ])
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Live results "),
            );
        frame.render_widget(table, chunks[2]);
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// IP selection table
// ---------------------------------------------------------------------------

/// Show the ranked IP list and let the user select one entry.
///
/// Returns the selected [`IpProbeEntry`].
pub fn run_ip_selection(
    terminal: &mut Term,
    entries: &[IpProbeEntry],
) -> anyhow::Result<IpProbeEntry> {
    if entries.is_empty() {
        anyhow::bail!("no IP candidates to select from");
    }

    let mut state = TableState::default();
    state.select(Some(0));

    loop {
        terminal.draw(|frame| draw_ip_selection(frame, entries, &mut state))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some(i.saturating_sub(1)));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some((i + 1).min(entries.len() - 1)));
                    }
                    KeyCode::Enter => {
                        let idx = state.selected().unwrap_or(0);
                        return Ok(entries[idx].clone());
                    }
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                        return Ok(entries[0].clone());
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw_ip_selection(frame: &mut ratatui::Frame, entries: &[IpProbeEntry], state: &mut TableState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    let header = Paragraph::new("ZeroDPI — Select IP")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let rows: Vec<Row> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let rank = (i + 1).to_string();
            let rank_style = if i == 0 {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let tcp_str = e
                .tcp_latency_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "fail".into());
            let tls_str = if e.tls_ok {
                e.tls_latency_ms
                    .map(|ms| format!("✓ {ms}ms"))
                    .unwrap_or_else(|| "✓".into())
            } else {
                "✗".into()
            };
            let ttfb_str = e
                .ttfb_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "—".into());
            let cert = if e.cert_valid { "✓" } else { "✗" };
            let down_str = fmt_rate_bps(e.download_bps);
            let up_str = fmt_rate_bps(e.upload_bps);
            let http_str = e
                .http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "—".into());
            Row::new(vec![
                Cell::from(rank).style(rank_style),
                Cell::from(e.score.to_string()).style(score_style(e.score)),
                Cell::from(e.ip.to_string()),
                Cell::from(tcp_str).style(tcp_style(e.tcp_latency_ms)),
                Cell::from(tls_str).style(tls_style(e.tls_ok)),
                Cell::from(cert).style(cert_style(e.cert_valid)),
                Cell::from(ttfb_str),
                Cell::from(down_str),
                Cell::from(up_str),
                Cell::from(http_str).style(http_style(e.http_status)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Min(36),
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(6),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Score", "IP", "TCP", "TLS", "Cert", "TTFB", "Down", "Up", "HTTP",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Ranked IP candidates "),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, chunks[1], state);

    let help_spans: Line = Line::from(vec![
        Span::styled(" ↑/↓ or j/k ", Style::default().fg(Color::Yellow)),
        Span::raw("navigate  "),
        Span::styled(" Enter ", Style::default().fg(Color::Green)),
        Span::raw("select  "),
        Span::styled(" q / Esc ", Style::default().fg(Color::Red)),
        Span::raw("pick rank-1 "),
    ]);
    let help = Paragraph::new(help_spans).block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

// ---------------------------------------------------------------------------
// Scan-only result views (sni_scan / ip_scan modes)
// ---------------------------------------------------------------------------

/// Show the ranked SNI results in view-only mode (scan-only).
///
/// The user can scroll the table; any non-navigation key exits.
/// Unlike [`run_selection`] this never starts a proxy — it is used purely for
/// display before the process exits.
pub fn run_sni_results_view(
    terminal: &mut Term,
    entries: &[SniProbeEntry],
    output_path: Option<&str>,
) -> anyhow::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    let mut state = TableState::default();
    state.select(Some(0));

    loop {
        terminal.draw(|frame| draw_sni_results_view(frame, entries, &mut state, output_path))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some(i.saturating_sub(1)));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some((i + 1).min(entries.len() - 1)));
                    }
                    _ => return Ok(()),
                }
            }
        }
    }
}

fn draw_sni_results_view(
    frame: &mut ratatui::Frame,
    entries: &[SniProbeEntry],
    state: &mut TableState,
    output_path: Option<&str>,
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    let title = format!("ZeroDPI — SNI Scan Results ({} entries)", entries.len());
    let header = Paragraph::new(title)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let rows: Vec<Row> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let rank = (i + 1).to_string();
            let rank_style = if i == 0 {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let tcp_str = e
                .tcp_latency_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "—".into());
            let tls_str = if e.tls_ok {
                e.tls_latency_ms
                    .map(|ms| format!("✓ {ms}ms"))
                    .unwrap_or_else(|| "✓".into())
            } else {
                "✗".into()
            };
            let cert = if e.cert_valid { "✓" } else { "✗" };
            let ttfb_str = e
                .ttfb_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "—".into());
            let down_str = fmt_rate_bps(e.download_bps);
            let up_str = fmt_rate_bps(e.upload_bps);
            let http_str = e
                .http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "—".into());
            Row::new(vec![
                Cell::from(rank).style(rank_style),
                Cell::from(e.score.to_string()).style(score_style(e.score)),
                Cell::from(e.sni.clone()),
                Cell::from(e.ip.to_string()),
                Cell::from(tcp_str).style(tcp_style(e.tcp_latency_ms)),
                Cell::from(tls_str).style(tls_style(e.tls_ok)),
                Cell::from(cert).style(cert_style(e.cert_valid)),
                Cell::from(ttfb_str),
                Cell::from(down_str),
                Cell::from(up_str),
                Cell::from(http_str).style(http_style(e.http_status)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Min(26),
        Constraint::Length(16),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(6),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Score", "SNI", "IP", "TCP", "TLS", "Cert", "TTFB", "Down", "Up", "HTTP",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Ranked SNI candidates "),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, chunks[1], state);

    let saved_span = match output_path {
        Some(p) => Span::styled(format!(" Saved → {p}  "), Style::default().fg(Color::Green)),
        None => Span::raw(""),
    };
    let help_line: Line = Line::from(vec![
        Span::styled(" ↑/↓ or j/k ", Style::default().fg(Color::Yellow)),
        Span::raw("scroll  "),
        Span::styled(" any other key ", Style::default().fg(Color::Red)),
        Span::raw("exit  "),
        saved_span,
    ]);
    let help = Paragraph::new(help_line).block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn connection_sni_survives_representative_changes() {
        let mut state = dashboard_state(vec![]);
        apply_event(
            ProxyEvent::ConnectionAccepted {
                peer: "127.0.0.1:1234".parse().unwrap(),
                src_port: 1234,
                target_ip: "192.0.2.1".parse().unwrap(),
                target_sni: Some("original.example".into()),
            },
            &mut state,
        );
        apply_event(
            ProxyEvent::SniTargetChanged {
                sni: "other.example".into(),
                ip: "192.0.2.2".parse().unwrap(),
                score: 90,
            },
            &mut state,
        );
        assert_eq!(
            state.records[0].target_sni.as_deref(),
            Some("original.example")
        );
        assert_eq!(state.records[0].target_ip.to_string(), "192.0.2.1");
    }

    #[test]
    fn dashboard_navigation_keeps_scroll_and_filters_independent() {
        let mut state = dashboard_state(vec![]);
        state.scroll_offset = 3;
        handle_dashboard_navigation(&mut state, KeyCode::Char('v'), 10, 2);
        handle_dashboard_navigation(&mut state, KeyCode::PageDown, 10, 2);
        assert_eq!(state.targets.scroll_offset, 2);
        assert_eq!(state.scroll_offset, 3);
        handle_dashboard_navigation(&mut state, KeyCode::Tab, 10, 2);
        assert!(matches!(state.filter, FilterStatus::All));
        handle_dashboard_navigation(&mut state, KeyCode::Char('v'), 10, 2);
        handle_dashboard_navigation(&mut state, KeyCode::Down, 10, 2);
        assert_eq!(state.scroll_offset, 4);
        assert_eq!(state.targets.scroll_offset, 2);
        handle_dashboard_navigation(&mut state, KeyCode::Tab, 10, 2);
        assert!(!matches!(state.filter, FilterStatus::All));
        assert_eq!(state.scroll_offset, 0);
        assert_eq!(state.targets.scroll_offset, 2);
    }

    #[test]
    fn pool_sampling_is_bounded_and_draining_load_counts_toward_share() {
        use zerodpi_core::target_pool::{SelectionStrategy, Target, TargetPool};
        let first = Target::ip("192.0.2.1".parse().unwrap(), 90);
        let second = Target::ip("192.0.2.2".parse().unwrap(), 80);
        let pool =
            TargetPool::new(SelectionStrategy::RoundRobin, vec![first, second.clone()]).unwrap();
        let mut targets = TargetsState::default();
        let now = Instant::now();
        assert!(targets.refresh(&pool, now));
        let _old = pool.acquire();
        let _current = pool.acquire();
        pool.replace(vec![second]);
        assert!(!targets.refresh(&pool, now + Duration::from_millis(499)));
        assert_eq!(targets.rows[0].snapshot.active_connections, 0);
        assert!(targets.refresh(&pool, now + Duration::from_millis(500)));
        assert_eq!(targets.rows[0].share, 50.0);
        assert_eq!(targets.rows[1].share, 50.0);
        assert_eq!(targets::membership(&targets.rows[1].snapshot), "Draining");
        targets.scroll_offset = 1;
        assert!(targets.refresh(&pool, now + Duration::from_secs(1)));
        assert_eq!(targets.scroll_offset, 1);
    }

    #[test]
    fn pruning_connection_history_does_not_reset_target_totals() {
        use zerodpi_core::target_pool::{Target, TargetPool};
        let pool = TargetPool::single(Target::ip("192.0.2.1".parse().unwrap(), 90));
        let mut snapshot = pool.snapshot();
        snapshot.targets[0].c2s_bytes = 1_000;
        snapshot.targets[0].s2c_bytes = 2_000;
        let mut state = dashboard_state(vec![]);
        state.targets.update(snapshot, Instant::now());
        for port in 1..=250 {
            apply_event(
                ProxyEvent::ConnectionAccepted {
                    peer: "127.0.0.1:1234".parse().unwrap(),
                    src_port: port,
                    target_ip: "192.0.2.1".parse().unwrap(),
                    target_sni: None,
                },
                &mut state,
            );
            apply_event(
                ProxyEvent::RelayFinished {
                    src_port: port,
                    c2s_bytes: 4,
                    s2c_bytes: 8,
                    reason: RelayEndReason::Completed,
                },
                &mut state,
            );
        }
        assert_eq!(state.records.len(), 200);
        assert_eq!(state.targets.rows[0].snapshot.c2s_bytes, 1_000);
        assert_eq!(state.targets.rows[0].snapshot.s2c_bytes, 2_000);
    }

    #[test]
    fn ip_connection_table_hides_sni_and_sni_table_marks_missing_values() {
        for width in [80, 140, 160] {
            for show_sni in [false, true] {
                let state = dashboard_state(vec![record(ConnStatus::Connecting, 0.0, 0.0)]);
                let mut terminal =
                    Terminal::new(ratatui::backend::TestBackend::new(width, 10)).unwrap();
                terminal
                    .draw(|frame| {
                        draw_connections(frame, frame.area(), &state, show_sni, Instant::now())
                    })
                    .unwrap();
                let text = terminal
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .map(|c| c.symbol())
                    .collect::<String>();
                assert_eq!(text.contains("SNI"), show_sni, "{width}: {text}");
                assert!(text.contains("203.0.113.1"));
                assert!(text.contains("Connecting"), "{width}: {text}");
            }
        }
    }

    #[test]
    fn target_rates_use_actual_elapsed_time_and_survive_refresh() {
        use zerodpi_core::target_pool::{Target, TargetPool};
        let pool = TargetPool::single(Target::ip("192.0.2.1".parse().unwrap(), 90));
        let mut targets = TargetsState::default();
        let now = Instant::now();
        targets.update(pool.snapshot(), now);
        assert_eq!(targets.rows[0].upload_bps, 0.0);
        assert_eq!(targets.rows[0].share, 0.0);
        let mut snapshot = pool.snapshot();
        snapshot.targets[0].c2s_bytes = 400;
        snapshot.targets[0].s2c_bytes = 800;
        snapshot.targets[0].active_connections = 2;
        targets.update(snapshot.clone(), now + Duration::from_secs(4));
        assert_eq!(targets.rows[0].upload_bps, 100.0);
        assert_eq!(targets.rows[0].download_bps, 200.0);
        assert_eq!(targets.rows[0].share, 100.0);
        snapshot.targets[0].rank = None;
        snapshot.targets[0].target.score = 95;
        snapshot.targets[0].c2s_bytes = 600;
        targets.update(snapshot, now + Duration::from_secs(6));
        assert_eq!(targets.rows[0].upload_bps, 100.0);
        targets.stop();
        assert_eq!(targets.rows[0].upload_bps, 0.0);
    }

    #[test]
    fn both_dashboard_views_render_at_supported_sizes() {
        use zerodpi_core::target_pool::{SelectionStrategy, Target, TargetPool};
        let sni = format!("{}.example", "long-hostname-".repeat(8));
        let first = Target::sni(sni.clone(), "192.0.2.1".parse().unwrap(), 90);
        let second = Target::ip(
            "2001:db8:abcd:1234:5678:90ab:cdef:1234".parse().unwrap(),
            80,
        );
        let pool = TargetPool::new(
            SelectionStrategy::LeastLoad,
            vec![first.clone(), second.clone()],
        )
        .unwrap();
        pool.replace(vec![first]);
        let mut state = dashboard_state(vec![record(ConnStatus::Relaying, 100.0, 200.0)]);
        state.records[0].target_sni = Some(sni.clone().into());
        state.active_sni = Some((sni.clone(), "192.0.2.1".parse().unwrap(), 90));
        state.target_pool = Some((1, SelectionStrategy::LeastLoad));
        let mut snapshot = pool.snapshot();
        snapshot.targets[1].ping_source = zerodpi_core::target_pool::PingSource::Live;
        state.targets.update(snapshot, Instant::now());
        let info = DashboardInfo::SniSpoof {
            sni,
            ip: "192.0.2.1".parse().unwrap(),
            score: 90,
        };
        let mut cfg = crate::config_for_tests();
        cfg.LOAD_BALANCE_ENABLED = true;
        for (width, height) in [(160, 40), (120, 30), (80, 24)] {
            for view in [DashboardView::Connections, DashboardView::Targets] {
                state.view = view;
                let mut terminal =
                    Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
                draw_dashboard(&mut terminal, &state, &info, &cfg).unwrap();
                let text = terminal
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .map(|c| c.symbol())
                    .collect::<String>();
                assert!(text.contains("SNI"), "{width} {view:?}: {text}");
                assert!(text.contains("Rank 1"), "{width} {view:?}: {text}");
                assert!(text.contains("rescan"));
                assert!(text.contains("views"));
                if view == DashboardView::Targets {
                    assert!(text.contains("Retired"), "{width}: {text}");
                    assert!(text.contains("In pool"));
                    assert!(text.contains("2001:db8"));
                    assert!(text.contains("failed Live"));
                    assert!(text.contains("unknown Scan"));
                }
                let lines = terminal
                    .backend()
                    .buffer()
                    .content()
                    .chunks(width as usize)
                    .map(|line| line.iter().map(|cell| cell.symbol()).collect::<String>())
                    .collect::<Vec<_>>();
                println!("\n{width}x{height} {view:?}\n{}", lines.join("\n"));
            }
        }
        assert_eq!(
            state.records[0].target_sni.as_deref(),
            Some(info_sni(&info))
        );
    }

    fn info_sni(info: &DashboardInfo) -> &str {
        match info {
            DashboardInfo::SniSpoof { sni, .. } => sni,
            _ => unreachable!(),
        }
    }

    fn record(status: ConnStatus, upload_bps: f64, download_bps: f64) -> ConnectionRecord {
        let now = Instant::now();
        ConnectionRecord {
            started_at: UNIX_EPOCH,
            start_instant: now,
            end_instant: None,
            src_port: 443,
            peer: "127.0.0.1:12345".parse().unwrap(),
            target_ip: "203.0.113.1".parse().unwrap(),
            target_sni: None,
            status,
            status_changed_at: now,
            c2s_bytes: 0,
            s2c_bytes: 0,
            rate_c2s_bps: upload_bps,
            rate_s2c_bps: download_bps,
            last_snapshot: None,
        }
    }

    #[test]
    fn traffic_direction_classifies_upload_only() {
        assert_eq!(
            traffic_direction(
                &ConnStatus::Relaying,
                ACTIVE_RATE_BPS,
                ACTIVE_RATE_BPS - 1.0
            ),
            Some(TrafficDirection::Upload)
        );
    }

    #[test]
    fn traffic_direction_classifies_download_only() {
        assert_eq!(
            traffic_direction(
                &ConnStatus::Relaying,
                ACTIVE_RATE_BPS - 1.0,
                ACTIVE_RATE_BPS
            ),
            Some(TrafficDirection::Download)
        );
    }

    #[test]
    fn traffic_direction_classifies_bidirectional() {
        assert_eq!(
            traffic_direction(&ConnStatus::Relaying, ACTIVE_RATE_BPS, ACTIVE_RATE_BPS),
            Some(TrafficDirection::Bidirectional)
        );
    }

    #[test]
    fn traffic_direction_classifies_idle_relaying() {
        assert_eq!(
            traffic_direction(
                &ConnStatus::Relaying,
                ACTIVE_RATE_BPS - 1.0,
                ACTIVE_RATE_BPS - 1.0
            ),
            Some(TrafficDirection::Idle)
        );
    }

    #[test]
    fn traffic_direction_ignores_non_relaying_statuses() {
        for status in [ConnStatus::Connecting, ConnStatus::Done, ConnStatus::Failed] {
            assert_eq!(
                traffic_direction(&status, ACTIVE_RATE_BPS, ACTIVE_RATE_BPS),
                None
            );
        }
    }

    #[test]
    fn stats_fields_are_right_aligned_to_stabilize_labels() {
        assert_eq!(fmt_stats_field("8.2M/s"), "  8.2M/s");
        assert_eq!(fmt_stats_field("49.1K/s"), " 49.1K/s");
        assert_eq!(fmt_stats_field("2367.3M"), " 2367.3M");
    }

    #[test]
    fn connection_row_style_uses_direction_specific_backgrounds() {
        assert_eq!(
            connection_row_style(&record(
                ConnStatus::Relaying,
                ACTIVE_RATE_BPS,
                ACTIVE_RATE_BPS - 1.0
            )),
            Style::default().bg(Color::Indexed(22))
        );
        assert_eq!(
            connection_row_style(&record(
                ConnStatus::Relaying,
                ACTIVE_RATE_BPS - 1.0,
                ACTIVE_RATE_BPS
            )),
            Style::default().bg(Color::Indexed(24))
        );
        assert_eq!(
            connection_row_style(&record(
                ConnStatus::Relaying,
                ACTIVE_RATE_BPS,
                ACTIVE_RATE_BPS
            )),
            Style::default().bg(Color::Indexed(29))
        );
        assert_eq!(
            connection_row_style(&record(
                ConnStatus::Relaying,
                ACTIVE_RATE_BPS - 1.0,
                ACTIVE_RATE_BPS - 1.0
            )),
            Style::default()
        );
    }

    #[test]
    fn dashboard_shows_rescan_shortcut_at_standard_terminal_width() {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        let ip = "192.0.2.1".parse().unwrap();
        let mut state = dashboard_state(vec![]);
        state.active_ip = Some(ip);
        draw_dashboard(
            &mut terminal,
            &state,
            &DashboardInfo::IpBypass { ip },
            &crate::config_for_tests(),
        )
        .unwrap();
        let lines: Vec<String> = terminal
            .backend()
            .buffer()
            .content
            .chunks(80)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect())
            .collect();
        assert!(lines.last().unwrap().contains('─'));
        assert!(
            lines[22].contains("R rescan"),
            "shortcut must remain visible: {}",
            lines[22]
        );
        assert!(lines[22].contains("L reload config"), "{}", lines[22]);
        println!("{}", lines.join("\n"));
    }

    #[test]
    fn reload_keys_preserve_the_dashboard_on_invalid_or_unchanged_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let text = "LISTEN_HOST='127.0.0.1'\nLISTEN_PORT=1234\nMODE='ip_bypass'\nSELECTED_IP='192.0.2.1'\n";
        std::fs::write(&path, text).unwrap();
        let source = crate::reload::ConfigSource::new(<crate::Args as clap::Parser>::parse_from([
            "zerodpi",
            "--config",
            path.to_str().unwrap(),
        ]))
        .unwrap();
        let cfg = source.load().unwrap();
        let session = crate::reload::Session::new(source, None);
        let mut state = dashboard_state(vec![record(ConnStatus::Relaying, 100.0, 200.0)]);
        state.total = 42;
        state.scroll_offset = 3;
        for key in ['l', 'L'] {
            assert!(
                handle_reload_key(&mut state, KeyCode::Char(key), &cfg, &session, false).is_none()
            );
            assert_eq!(state.reload_status.as_deref(), Some("Config unchanged"));
        }
        std::fs::write(&path, "LISTEN_HOST=[").unwrap();
        assert!(handle_reload_key(&mut state, KeyCode::Char('L'), &cfg, &session, false).is_none());
        assert!(state
            .reload_status
            .as_ref()
            .unwrap()
            .starts_with("Config reload failed"));
        assert_eq!(state.total, 42);
        assert_eq!(state.records.len(), 1);
        assert_eq!(state.scroll_offset, 3);
        assert_eq!(cfg.LISTEN_PORT, 1234);
        std::fs::write(&path, text.replace("1234", "5678")).unwrap();
        for key in ['l', 'L'] {
            let next =
                handle_reload_key(&mut state, KeyCode::Char(key), &cfg, &session, false).unwrap();
            assert_eq!(next.LISTEN_PORT, 5678);
        }
        state.rescan_running = true;
        assert!(handle_reload_key(&mut state, KeyCode::Char('L'), &cfg, &session, false).is_none());
        assert!(state.reload_status.as_ref().unwrap().contains("busy"));
        state.rescan_running = false;
        assert!(handle_reload_key(&mut state, KeyCode::Char('l'), &cfg, &session, true).is_none());
        assert!(state.reload_status.as_ref().unwrap().contains("busy"));
        state.reload_status = None;
        assert!(handle_reload_key(&mut state, KeyCode::Char('r'), &cfg, &session, false).is_none());
        assert!(state.reload_status.is_none());
    }

    #[test]
    fn both_views_show_reload_and_its_result_at_eighty_columns() {
        let mut state = dashboard_state(vec![]);
        state.active_ip = Some("192.0.2.1".parse().unwrap());
        state.reload_status = Some("Config reloaded successfully".into());
        for view in [DashboardView::Connections, DashboardView::Targets] {
            state.view = view;
            let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
            draw_dashboard(
                &mut terminal,
                &state,
                &DashboardInfo::IpBypass {
                    ip: state.active_ip.unwrap(),
                },
                &crate::config_for_tests(),
            )
            .unwrap();
            let lines: Vec<String> = terminal
                .backend()
                .buffer()
                .content
                .chunks(80)
                .map(|row| row.iter().map(|cell| cell.symbol()).collect())
                .collect();
            assert!(lines[22].contains("R rescan"));
            assert!(lines[22].contains("L reload config"));
            assert!(lines
                .iter()
                .any(|line| line.contains("Config reloaded successfully")));
        }
    }

    #[test]
    fn dashboard_shows_actual_pool_size_and_strategy_at_standard_width() {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        let ip = "192.0.2.1".parse().unwrap();
        let mut state = dashboard_state(vec![]);
        state.active_ip = Some(ip);
        apply_event(
            ProxyEvent::TargetPoolUpdated {
                target_count: 2,
                strategy: zerodpi_core::target_pool::SelectionStrategy::LeastLoad,
            },
            &mut state,
        );
        let mut cfg = crate::config_for_tests();
        cfg.LOAD_BALANCE_ENABLED = true;
        cfg.LOAD_BALANCE_TARGET_COUNT = 10;
        draw_dashboard(&mut terminal, &state, &DashboardInfo::IpBypass { ip }, &cfg).unwrap();
        let lines: Vec<String> = terminal
            .backend()
            .buffer()
            .content
            .chunks(80)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect())
            .collect();
        assert!(lines.iter().any(|line| line.contains("Load balancing: ON")
            && line.contains("Targets: 2")
            && line.contains("least_load")
            && line.contains("Rank 1")));
        println!("{}", lines.join("\n"));
    }

    fn dashboard_state(records: Vec<ConnectionRecord>) -> DashboardState {
        DashboardState {
            reload_status: None,
            view: DashboardView::Connections,
            targets: TargetsState::default(),
            target_pool: None,
            records: VecDeque::from(records),
            total: 0,
            bypasses_ok: 0,
            bypasses_failed: 0,
            active: 0,
            total_c2s: 0,
            total_s2c: 0,
            scroll_offset: 0,
            auto_scroll: true,
            filter: FilterStatus::All,
            active_sni: None,
            active_ip: None,
            low_ttl: None,
            rescan_running: false,
            next_rescan_at: None,
            peak_active: 0,
            target_switches: 0,
            last_switch_at: None,
            rescan_count: 0,
            last_rescan: None,
            rescan_started_at: None,
            last_error: None,
            network_status: None,
            active_ip_score: None,
            listener: None,
            start: Instant::now(),
            channel_closed: false,
        }
    }

    #[test]
    fn refreshing_the_same_representative_updates_score_without_counting_a_switch() {
        let mut state = dashboard_state(vec![]);
        for score in [90, 95] {
            apply_event(
                ProxyEvent::SniTargetChanged {
                    sni: "same.example".into(),
                    ip: Ipv4Addr::new(192, 0, 2, 1),
                    score,
                },
                &mut state,
            );
        }
        assert_eq!(state.target_switches, 1);
        assert_eq!(state.active_sni.as_ref().unwrap().2, 95);
        for score in [80, 85] {
            apply_event(
                ProxyEvent::IpTargetChanged {
                    ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                    score,
                },
                &mut state,
            );
        }
        assert_eq!(state.target_switches, 2);
        assert_eq!(state.active_ip_score, Some(85));
    }

    #[test]
    fn progress_batch_updates_active_rows_and_resets_idle_rates() {
        let sampled_at = Instant::now();
        let mut active = record(ConnStatus::Relaying, 1.0, 1.0);
        active.last_snapshot = Some((sampled_at - Duration::from_millis(500), 50, 100));
        let mut done = record(ConnStatus::Done, 0.0, 0.0);
        done.src_port = 444;
        done.c2s_bytes = 999;
        let mut state = dashboard_state(vec![active, done]);
        apply_event(
            ProxyEvent::RelayProgressBatch {
                sampled_at,
                entries: vec![
                    RelayProgress {
                        src_port: 443,
                        c2s_bytes: 100,
                        s2c_bytes: 200,
                    },
                    RelayProgress {
                        src_port: 444,
                        c2s_bytes: 1,
                        s2c_bytes: 1,
                    },
                ],
            },
            &mut state,
        );
        let active = &state.records[0];
        assert_eq!((active.c2s_bytes, active.s2c_bytes), (100, 200));
        assert_eq!((active.rate_c2s_bps, active.rate_s2c_bps), (100.0, 200.0));
        assert_eq!(state.records[1].c2s_bytes, 999);
        apply_event(
            ProxyEvent::RelayProgressBatch {
                sampled_at: sampled_at + Duration::from_millis(500),
                entries: vec![RelayProgress {
                    src_port: 443,
                    c2s_bytes: 100,
                    s2c_bytes: 200,
                }],
            },
            &mut state,
        );
        assert_eq!(state.records[0].rate_c2s_bps, 0.0);
        assert_eq!(state.records[0].rate_s2c_bps, 0.0);
    }

    #[test]
    fn progress_batch_cannot_overwrite_final_bytes() {
        let mut state = dashboard_state(vec![record(ConnStatus::Relaying, 1.0, 1.0)]);
        apply_event(
            ProxyEvent::RelayFinished {
                src_port: 443,
                c2s_bytes: 100,
                s2c_bytes: 200,
                reason: RelayEndReason::Completed,
            },
            &mut state,
        );
        apply_event(
            ProxyEvent::RelayProgressBatch {
                sampled_at: Instant::now(),
                entries: vec![RelayProgress {
                    src_port: 443,
                    c2s_bytes: 1,
                    s2c_bytes: 2,
                }],
            },
            &mut state,
        );
        assert_eq!(
            (state.records[0].c2s_bytes, state.records[0].s2c_bytes),
            (100, 200)
        );
        assert!(matches!(state.records[0].status, ConnStatus::Done));
        assert_eq!(state.total_c2s, 100);
        assert_eq!(state.total_s2c, 200);
    }

    #[test]
    fn apply_event_keeps_active_connections_when_log_is_full() {
        let old_active_port = 1111;
        let new_active_port = 2222;
        let mut records = Vec::with_capacity(MAX_RECORDS);

        for i in 0..(MAX_RECORDS - 1) {
            let mut done = record(ConnStatus::Done, 0.0, 0.0);
            done.src_port = 3000 + i as u16;
            done.end_instant = Some(Instant::now());
            records.push(done);
        }

        let mut old_active = record(ConnStatus::Relaying, 0.0, 0.0);
        old_active.src_port = old_active_port;
        records.push(old_active);

        let mut state = dashboard_state(records);
        state.active = 1;

        apply_event(
            ProxyEvent::ConnectionAccepted {
                peer: "127.0.0.1:22222".parse().unwrap(),
                src_port: new_active_port,
                target_ip: "203.0.113.2".parse().unwrap(),
                target_sni: None,
            },
            &mut state,
        );

        assert_eq!(state.records.len(), MAX_RECORDS);
        assert!(state
            .records
            .iter()
            .any(|r| r.src_port == old_active_port && r.is_active()));
        assert!(state
            .records
            .iter()
            .any(|r| r.src_port == new_active_port && r.is_active()));
    }

    #[test]
    fn ordered_connection_records_keeps_relaying_connections_on_top() {
        let now = Instant::now();
        let mut stale_failed = record(ConnStatus::Failed, 0.0, 0.0);
        stale_failed.src_port = 1;
        stale_failed.status_changed_at = now - NON_RELAYING_TOP_GRACE - Duration::from_millis(1);

        let mut recent_done = record(ConnStatus::Done, 0.0, 0.0);
        recent_done.src_port = 2;
        recent_done.status_changed_at = now - Duration::from_secs(1);

        let mut relaying = record(ConnStatus::Relaying, 0.0, 0.0);
        relaying.src_port = 3;
        relaying.status_changed_at = now - NON_RELAYING_TOP_GRACE - Duration::from_secs(1);

        let state = dashboard_state(vec![stale_failed, recent_done, relaying]);
        let ports: Vec<u16> = ordered_connection_records(&state, now)
            .into_iter()
            .map(|r| r.src_port)
            .collect();

        assert_eq!(ports, vec![3, 2, 1]);
    }

    #[test]
    fn ordered_connection_records_moves_non_relaying_connections_down_after_grace() {
        let now = Instant::now();
        let mut stale_done = record(ConnStatus::Done, 0.0, 0.0);
        stale_done.src_port = 1;
        stale_done.status_changed_at = now - NON_RELAYING_TOP_GRACE - Duration::from_millis(1);

        let mut recent_failed = record(ConnStatus::Failed, 0.0, 0.0);
        recent_failed.src_port = 2;
        recent_failed.status_changed_at = now - Duration::from_secs(1);

        let state = dashboard_state(vec![stale_done, recent_failed]);
        let ports: Vec<u16> = ordered_connection_records(&state, now)
            .into_iter()
            .map(|r| r.src_port)
            .collect();

        assert_eq!(ports, vec![2, 1]);
    }

    #[test]
    fn apply_event_schedules_next_rescan_deadline() {
        let mut state = dashboard_state(vec![]);
        let before = Instant::now();
        apply_event(
            ProxyEvent::NextRescanScheduled {
                kind: RescanKind::Sni,
                interval_secs: 300,
            },
            &mut state,
        );
        let after = Instant::now();
        let at = state.next_rescan_at.expect("deadline should be set");
        assert!(at >= before + Duration::from_secs(300));
        assert!(at <= after + Duration::from_secs(300));
    }

    #[test]
    fn apply_event_tracks_rescan_running_state() {
        let mut state = dashboard_state(vec![]);
        apply_event(
            ProxyEvent::RescanStarted {
                kind: RescanKind::Ip,
            },
            &mut state,
        );
        assert!(state.rescan_running);
        apply_event(
            ProxyEvent::RescanFinished {
                kind: RescanKind::Ip,
                found: 0,
                best_score: None,
                duration_ms: 0,
                switched: false,
            },
            &mut state,
        );
        assert!(!state.rescan_running);
    }

    #[test]
    fn rescan_status_line_hidden_without_schedule() {
        let state = dashboard_state(vec![]);
        assert!(rescan_status_line(&state, Instant::now()).is_none());
    }

    #[test]
    fn rescan_status_line_shows_running_indicator() {
        let mut state = dashboard_state(vec![]);
        state.rescan_running = true;
        let line = rescan_status_line(&state, Instant::now()).expect("line should be present");
        assert_eq!(line.spans.len(), 2);
        assert_eq!(line.spans[0].content, "Rescan: ");
        assert_eq!(line.spans[1].content, "running…");
    }

    #[test]
    fn rescan_status_line_shows_countdown_to_next_rescan() {
        let mut state = dashboard_state(vec![]);
        let now = Instant::now();
        state.next_rescan_at = Some(now + Duration::from_secs(272)); // 4m 32s
        let line = rescan_status_line(&state, now).expect("line should be present");
        assert_eq!(line.spans[0].content, "Next rescan in: ");
        assert_eq!(line.spans[1].content, "4m 32s");
    }

    #[test]
    fn rescan_status_line_prefers_running_over_countdown() {
        let mut state = dashboard_state(vec![]);
        let now = Instant::now();
        state.next_rescan_at = Some(now + Duration::from_secs(60));
        state.rescan_running = true;
        let line = rescan_status_line(&state, now).expect("line should be present");
        assert_eq!(line.spans[1].content, "running…");
    }

    #[test]
    fn fixed_dashboard_rows_grows_when_status_line_visible() {
        let mut state = dashboard_state(vec![]);
        assert_eq!(fixed_dashboard_rows(&state), 15);
        state.next_rescan_at = Some(Instant::now() + Duration::from_secs(60));
        assert_eq!(fixed_dashboard_rows(&state), 16);
        state.next_rescan_at = None;
        state.rescan_running = true;
        assert_eq!(fixed_dashboard_rows(&state), 16);
    }

    #[test]
    fn apply_event_tracks_peak_active_connections() {
        let mut state = dashboard_state(vec![]);
        for port in [1000u16, 2000, 3000] {
            apply_event(
                ProxyEvent::ConnectionAccepted {
                    peer: "127.0.0.1:11111".parse().unwrap(),
                    src_port: port,
                    target_ip: "203.0.113.1".parse().unwrap(),
                    target_sni: None,
                },
                &mut state,
            );
        }
        assert_eq!(state.active, 3);
        assert_eq!(state.peak_active, 3);

        apply_event(
            ProxyEvent::RelayFinished {
                src_port: 2000,
                c2s_bytes: 0,
                s2c_bytes: 0,
                reason: RelayEndReason::Completed,
            },
            &mut state,
        );
        assert_eq!(state.active, 2);
        assert_eq!(state.peak_active, 3);
    }

    #[test]
    fn apply_event_counts_target_switches() {
        let mut state = dashboard_state(vec![]);
        apply_event(
            ProxyEvent::SniTargetChanged {
                sni: "example.com".into(),
                ip: "203.0.113.1".parse().unwrap(),
                score: 80,
            },
            &mut state,
        );
        apply_event(
            ProxyEvent::IpTargetChanged {
                ip: "203.0.113.2".parse().unwrap(),
                score: 70,
            },
            &mut state,
        );
        assert_eq!(state.target_switches, 2);
        assert!(state.last_switch_at.is_some());
        assert_eq!(state.active_ip_score, Some(70));
    }

    #[test]
    fn apply_event_records_last_connection_error() {
        let mut state = dashboard_state(vec![]);
        apply_event(
            ProxyEvent::ConnectionError {
                src_port: 99,
                error: "connection refused".into(),
            },
            &mut state,
        );
        let err = state.last_error.as_ref().expect("last_error should be set");
        assert_eq!(err.src_port, 99);
        assert_eq!(err.message, "connection refused");
    }

    #[test]
    fn apply_event_stores_network_status_without_rendering_label() {
        let mut state = dashboard_state(vec![]);
        apply_event(
            ProxyEvent::NetworkStatus {
                status: zerodpi_core::proxy::NetworkStatus::Online {
                    interface_ip: "192.168.0.222".parse().unwrap(),
                },
            },
            &mut state,
        );

        assert_eq!(state.network_status.as_deref(), Some("192.168.0.222"));
    }

    #[test]
    fn apply_event_stores_rescan_summary() {
        let mut state = dashboard_state(vec![]);
        apply_event(
            ProxyEvent::RescanStarted {
                kind: RescanKind::Sni,
            },
            &mut state,
        );
        assert!(state.rescan_running);
        apply_event(
            ProxyEvent::RescanFinished {
                kind: RescanKind::Sni,
                found: 3,
                best_score: Some(88),
                duration_ms: 2100,
                switched: true,
            },
            &mut state,
        );
        assert!(!state.rescan_running);
        assert_eq!(state.rescan_count, 1);
        assert_eq!(
            state.last_rescan,
            Some(RescanSummary {
                found: 3,
                best_score: Some(88),
                duration_ms: 2100,
                switched: true,
            })
        );
    }

    #[test]
    fn apply_event_stores_target_ip_on_accept() {
        let mut state = dashboard_state(vec![]);
        apply_event(
            ProxyEvent::ConnectionAccepted {
                peer: "127.0.0.1:12345".parse().unwrap(),
                src_port: 777,
                target_ip: "203.0.113.7".parse().unwrap(),
                target_sni: None,
            },
            &mut state,
        );
        let rec = state.records.front().expect("record should exist");
        assert_eq!(rec.target_ip, "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn fmt_ago_formats_seconds_minutes_hours() {
        assert_eq!(fmt_ago(Duration::from_secs(9)), "9s ago");
        assert_eq!(fmt_ago(Duration::from_secs(90)), "1m ago");
        assert_eq!(fmt_ago(Duration::from_secs(7200)), "2h ago");
    }

    #[test]
    fn rescan_status_line_shows_elapsed_while_running() {
        let mut state = dashboard_state(vec![]);
        state.rescan_running = true;
        state.rescan_started_at = Some(Instant::now() - Duration::from_secs(3));
        let line = rescan_status_line(&state, Instant::now()).expect("line should be present");
        assert_eq!(line.spans[1].content, "running… 3s");
    }

    #[test]
    fn rescan_status_line_includes_last_rescan_summary() {
        let mut state = dashboard_state(vec![]);
        let now = Instant::now();
        state.next_rescan_at = Some(now + Duration::from_secs(300));
        state.rescan_count = 2;
        state.last_rescan = Some(RescanSummary {
            found: 3,
            best_score: Some(88),
            duration_ms: 2100,
            switched: true,
        });
        let line = rescan_status_line(&state, now).expect("line should be present");
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("rescan #2: 3 found, best 88, 2.1s, switched"));
    }

    #[test]
    fn header_content_rows_counts_error_and_rescan_lines() {
        let mut state = dashboard_state(vec![]);
        let now = Instant::now();
        assert_eq!(header_content_rows(&state, now), 2);
        state.last_error = Some(LastError {
            src_port: 1,
            message: "boom".into(),
            at: SystemTime::now(),
        });
        assert_eq!(header_content_rows(&state, now), 3);
        state.next_rescan_at = Some(now + Duration::from_secs(60));
        assert_eq!(header_content_rows(&state, now), 4);
    }

    #[test]
    fn aggregate_throughput_sums_only_relaying_connections() {
        let mut up = record(ConnStatus::Relaying, ACTIVE_RATE_BPS, 0.0);
        up.src_port = 1;
        let mut down = record(ConnStatus::Relaying, 0.0, ACTIVE_RATE_BPS * 2.0);
        down.src_port = 2;
        let mut done = record(ConnStatus::Done, 999.0, 999.0);
        done.src_port = 3;
        let state = dashboard_state(vec![up, down, done]);
        let (c2s, s2c) = aggregate_throughput(&state.records);
        assert_eq!(c2s, ACTIVE_RATE_BPS);
        assert_eq!(s2c, ACTIVE_RATE_BPS * 2.0);
    }
}

/// Show the ranked IP results in view-only mode (scan-only).
///
/// The user can scroll; any non-navigation key exits.
pub fn run_ip_results_view(
    terminal: &mut Term,
    entries: &[IpProbeEntry],
    output_path: Option<&str>,
) -> anyhow::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    let mut state = TableState::default();
    state.select(Some(0));

    loop {
        terminal.draw(|frame| draw_ip_results_view(frame, entries, &mut state, output_path))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some(i.saturating_sub(1)));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some((i + 1).min(entries.len() - 1)));
                    }
                    _ => return Ok(()),
                }
            }
        }
    }
}

fn draw_ip_results_view(
    frame: &mut ratatui::Frame,
    entries: &[IpProbeEntry],
    state: &mut TableState,
    output_path: Option<&str>,
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    let title = format!("ZeroDPI — IP Scan Results ({} entries)", entries.len());
    let header = Paragraph::new(title)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let rows: Vec<Row> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let rank = (i + 1).to_string();
            let rank_style = if i == 0 {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let tcp_str = e
                .tcp_latency_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "fail".into());
            let tls_str = if e.tls_ok {
                e.tls_latency_ms
                    .map(|ms| format!("✓ {ms}ms"))
                    .unwrap_or_else(|| "✓".into())
            } else {
                "✗".into()
            };
            let cert = if e.cert_valid { "✓" } else { "✗" };
            let ttfb_str = e
                .ttfb_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "—".into());
            let down_str = fmt_rate_bps(e.download_bps);
            let up_str = fmt_rate_bps(e.upload_bps);
            let http_str = e
                .http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "—".into());
            Row::new(vec![
                Cell::from(rank).style(rank_style),
                Cell::from(e.score.to_string()).style(score_style(e.score)),
                Cell::from(e.ip.to_string()),
                Cell::from(tcp_str).style(tcp_style(e.tcp_latency_ms)),
                Cell::from(tls_str).style(tls_style(e.tls_ok)),
                Cell::from(cert).style(cert_style(e.cert_valid)),
                Cell::from(ttfb_str),
                Cell::from(down_str),
                Cell::from(up_str),
                Cell::from(http_str).style(http_style(e.http_status)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Min(36),
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(6),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Score", "IP", "TCP", "TLS", "Cert", "TTFB", "Down", "Up", "HTTP",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Ranked IP candidates "),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, chunks[1], state);

    let saved_span = match output_path {
        Some(p) => Span::styled(format!(" Saved → {p}  "), Style::default().fg(Color::Green)),
        None => Span::raw(""),
    };
    let help_line: Line = Line::from(vec![
        Span::styled(" ↑/↓ or j/k ", Style::default().fg(Color::Yellow)),
        Span::raw("scroll  "),
        Span::styled(" any other key ", Style::default().fg(Color::Red)),
        Span::raw("exit  "),
        saved_span,
    ]);
    let help = Paragraph::new(help_line).block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

// ---------------------------------------------------------------------------
// proxy_scan — Phase 2 progress view
// ---------------------------------------------------------------------------

/// Show a live progress screen while proxy tests run in the background.
///
/// Each `ProxyTestEntry` arriving on `rx` represents one completed candidate.
/// Returns `(entries, aborted)`.
pub fn run_proxy_scan_progress(
    terminal: &mut Term,
    rx: &mut mpsc::UnboundedReceiver<zerodpi_core::proxy_tester::ProxyTestEntry>,
    total_candidates: usize,
) -> anyhow::Result<(Vec<zerodpi_core::proxy_tester::ProxyTestEntry>, bool)> {
    let mut arrived: Vec<zerodpi_core::proxy_tester::ProxyTestEntry> = Vec::new();

    loop {
        loop {
            match rx.try_recv() {
                Ok(entry) => arrived.push(entry),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    draw_proxy_scan_progress(terminal, &arrived, total_candidates)?;
                    return Ok((arrived, false));
                }
            }
        }

        draw_proxy_scan_progress(terminal, &arrived, total_candidates)?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press
                    && (matches!(k.code, KeyCode::Char('q') | KeyCode::Char('Q'))
                        || k.code == KeyCode::Esc)
                {
                    return Ok((arrived, true));
                }
            }
        }
    }
}

fn draw_proxy_scan_progress(
    terminal: &mut Term,
    arrived: &[zerodpi_core::proxy_tester::ProxyTestEntry],
    total_candidates: usize,
) -> anyhow::Result<()> {
    let done = arrived.len();
    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // header
                Constraint::Length(3), // progress gauge
                Constraint::Min(5),    // live results table
            ])
            .split(area);

        // Header
        let header = Paragraph::new("ZeroDPI — Proxy Scan: Phase 2 — Testing via VPN proxy…")
            .style(
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(header, chunks[0]);

        // Progress gauge
        let ratio = if total_candidates == 0 {
            0.0
        } else {
            (done as f64 / total_candidates as f64).min(1.0)
        };
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" Progress "))
            .gauge_style(Style::default().fg(Color::Magenta))
            .ratio(ratio)
            .label(format!("{done} / {total_candidates} candidates tested"));
        frame.render_widget(gauge, chunks[1]);

        // Live results table
        let rows: Vec<Row> = arrived
            .iter()
            .map(|e| {
                let proxy_status = if e.proxy_ok {
                    Cell::from("✓").style(Style::default().fg(Color::Green))
                } else {
                    Cell::from("✗").style(Style::default().fg(Color::Red))
                };
                let ttfb_str = e
                    .proxy_ttfb_ms
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "—".into());
                let speed_str = e
                    .proxy_speed_bps
                    .map(|bps| {
                        if bps >= 1_048_576.0 {
                            format!("{:.1}MB/s", bps / 1_048_576.0)
                        } else {
                            format!("{:.0}KB/s", bps / 1024.0)
                        }
                    })
                    .unwrap_or_else(|| "—".into());
                let http_str = e
                    .proxy_http_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "—".into());
                Row::new(vec![
                    Cell::from(e.final_score.to_string()).style(score_style(e.final_score)),
                    Cell::from(e.sni_score.to_string()).style(score_style(e.sni_score)),
                    Cell::from(e.proxy_score.to_string()).style(score_style(e.proxy_score)),
                    Cell::from(e.sni.clone()),
                    Cell::from(e.ip.to_string()),
                    proxy_status,
                    Cell::from(ttfb_str),
                    Cell::from(speed_str),
                    Cell::from(http_str).style(http_style(e.proxy_http_status)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(6),  // Final
            Constraint::Length(5),  // SNI
            Constraint::Length(6),  // Proxy
            Constraint::Min(28),    // SNI hostname
            Constraint::Length(16), // IP
            Constraint::Length(6),  // VPN ok
            Constraint::Length(8),  // TTFB
            Constraint::Length(10), // Speed
            Constraint::Length(6),  // HTTP
        ];
        let table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    "Final", "SNI", "Proxy", "Hostname", "IP", "VPN", "TTFB", "Speed", "HTTP",
                ])
                .style(
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Live proxy-test results "),
            );
        frame.render_widget(table, chunks[2]);
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// proxy_scan — Final results view
// ---------------------------------------------------------------------------

/// Show the final ranked proxy-scan results in a scrollable view.
///
/// The user can scroll with ↑/↓ / j/k; any other key exits.
pub fn run_proxy_scan_results_view(
    terminal: &mut Term,
    entries: &[zerodpi_core::proxy_tester::ProxyTestEntry],
    output_path: Option<&str>,
) -> anyhow::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    let mut state = TableState::default();
    state.select(Some(0));

    loop {
        terminal.draw(|frame| draw_proxy_scan_results(frame, entries, &mut state, output_path))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some(i.saturating_sub(1)));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some((i + 1).min(entries.len() - 1)));
                    }
                    _ => return Ok(()),
                }
            }
        }
    }
}

fn draw_proxy_scan_results(
    frame: &mut ratatui::Frame,
    entries: &[zerodpi_core::proxy_tester::ProxyTestEntry],
    state: &mut TableState,
    output_path: Option<&str>,
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    let passed = entries.iter().filter(|e| e.proxy_ok).count();
    let title = format!(
        "ZeroDPI — Proxy Scan Results ({} tested, {} passed VPN)",
        entries.len(),
        passed,
    );
    let header_widget = Paragraph::new(title)
        .style(
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header_widget, chunks[0]);

    let rows: Vec<Row> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let rank = (i + 1).to_string();
            let rank_style = if i == 0 {
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let vpn_cell = if e.proxy_ok {
                Cell::from("✓").style(Style::default().fg(Color::Green))
            } else {
                Cell::from("✗").style(Style::default().fg(Color::Red))
            };
            let tcp_str = e
                .proxy_tcp_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "—".into());
            let ttfb_str = e
                .proxy_ttfb_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "—".into());
            let speed_str = e
                .proxy_speed_bps
                .map(|bps| {
                    if bps >= 1_048_576.0 {
                        format!("{:.1}MB/s", bps / 1_048_576.0)
                    } else {
                        format!("{:.0}KB/s", bps / 1024.0)
                    }
                })
                .unwrap_or_else(|| "—".into());
            let http_str = e
                .proxy_http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "—".into());
            Row::new(vec![
                Cell::from(rank).style(rank_style),
                Cell::from(e.final_score.to_string()).style(score_style(e.final_score)),
                Cell::from(e.sni_score.to_string()).style(score_style(e.sni_score)),
                Cell::from(e.proxy_score.to_string()).style(score_style(e.proxy_score)),
                Cell::from(e.sni.clone()),
                Cell::from(e.ip.to_string()),
                vpn_cell,
                Cell::from(tcp_str),
                Cell::from(ttfb_str),
                Cell::from(speed_str),
                Cell::from(http_str).style(http_style(e.proxy_http_status)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(4),  // #
        Constraint::Length(6),  // Final
        Constraint::Length(5),  // SNI
        Constraint::Length(6),  // Proxy
        Constraint::Min(26),    // Hostname
        Constraint::Length(16), // IP
        Constraint::Length(5),  // VPN
        Constraint::Length(8),  // Proxy TCP
        Constraint::Length(8),  // TTFB
        Constraint::Length(10), // Speed
        Constraint::Length(6),  // HTTP
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Final", "SNI", "Proxy", "Hostname", "IP", "VPN", "ProxyTCP", "TTFB", "Speed",
                "HTTP",
            ])
            .style(
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Ranked proxy-scan candidates (Final = blend of SNI + Proxy scores) "),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Magenta)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    frame.render_stateful_widget(table, chunks[1], state);

    let saved_span = match output_path {
        Some(p) => Span::styled(format!(" Saved → {p}  "), Style::default().fg(Color::Green)),
        None => Span::raw(""),
    };
    let help_line: Line = Line::from(vec![
        Span::styled(" ↑/↓ or j/k ", Style::default().fg(Color::Yellow)),
        Span::raw("scroll  "),
        Span::styled(" any other key ", Style::default().fg(Color::Red)),
        Span::raw("exit  "),
        saved_span,
    ]);
    let help = Paragraph::new(help_line).block(Block::default().borders(Borders::ALL));
    frame.render_widget(help, chunks[2]);
}

// ---------------------------------------------------------------------------
// Method-scan Phase 1 progress view
// ---------------------------------------------------------------------------

/// Live progress view for method-scan Phase 1. Returns entries collected so
/// far and whether the user aborted.
pub fn run_method_scan_progress(
    terminal: &mut Term,
    rx: &mut mpsc::UnboundedReceiver<MethodScanEvent>,
    total_methods: usize,
    samples_per_method: usize,
) -> anyhow::Result<(Vec<MethodScanEntry>, bool)> {
    let mut state = MethodScanProgressState {
        done: Vec::new(),
        current_method: None,
        current_sample: 0,
        ok_in_current: 0,
    };

    loop {
        // Drain all currently available events.
        loop {
            match rx.try_recv() {
                Ok(MethodScanEvent::SampleDone { method, sample, ok }) => {
                    state.current_method = Some(method);
                    state.current_sample = sample;
                    if ok {
                        state.ok_in_current += 1;
                    }
                }
                Ok(MethodScanEvent::MethodDone { entry, .. }) => {
                    state.done.push(entry);
                    state.current_method = None;
                    state.current_sample = 0;
                    state.ok_in_current = 0;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    // Engine finished - draw one final frame and return.
                    draw_method_scan_progress(terminal, &state, total_methods, samples_per_method)?;
                    return Ok((state.done, false));
                }
            }
        }

        draw_method_scan_progress(terminal, &state, total_methods, samples_per_method)?;

        // Poll for user input (Ctrl-C / q to abort).
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press
                    && (matches!(k.code, KeyCode::Char('q') | KeyCode::Char('Q'))
                        || k.code == KeyCode::Esc)
                {
                    return Ok((state.done, true));
                }
            }
        }
    }
}

struct MethodScanProgressState {
    done: Vec<MethodScanEntry>,
    current_method: Option<String>,
    current_sample: usize,
    ok_in_current: usize,
}

fn draw_method_scan_progress(
    terminal: &mut Term,
    state: &MethodScanProgressState,
    total_methods: usize,
    samples_per_method: usize,
) -> anyhow::Result<()> {
    let completed = state.done.len();
    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // header
                Constraint::Length(3), // methods gauge
                Constraint::Length(3), // current sample line
                Constraint::Min(5),    // results so far
            ])
            .split(area);

        let header = Paragraph::new("ZeroDPI — Testing Bypass Methods…")
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(header, chunks[0]);

        let ratio = if total_methods == 0 {
            0.0
        } else {
            (completed as f64 / total_methods as f64).min(1.0)
        };
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" Methods "))
            .gauge_style(Style::default().fg(Color::Green))
            .ratio(ratio)
            .label(format!("{completed}/{total_methods} methods tested"));
        frame.render_widget(gauge, chunks[1]);

        let current_line = match &state.current_method {
            Some(m) => format!(
                "Testing {m}: sample {}/{samples_per_method} ({} ok so far)",
                state.current_sample, state.ok_in_current
            ),
            None => "—".to_owned(),
        };
        let current = Paragraph::new(current_line)
            .block(Block::default().borders(Borders::ALL).title(" Current "));
        frame.render_widget(current, chunks[2]);

        let rows: Vec<Row> = state
            .done
            .iter()
            .rev()
            .take(8)
            .map(|e| {
                Row::new(vec![
                    Cell::from(format!("{:.1}%", e.success_rate)),
                    Cell::from(e.method.clone()),
                    Cell::from(format!("{}/{}", e.samples_ok, e.samples_total)),
                    Cell::from(
                        e.avg_ttfb_ms
                            .map(|v| format!("{v:.0}ms"))
                            .unwrap_or_else(|| "—".into()),
                    ),
                    Cell::from(e.last_error.clone().unwrap_or_default()),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(8),
            Constraint::Length(24),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Min(20),
        ];
        let table = Table::new(rows, widths)
            .header(
                Row::new(vec!["Rate", "Method", "OK", "Avg TTFB", "Error"]).style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Results so far "),
            );
        frame.render_widget(table, chunks[3]);
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Method-scan results view
// ---------------------------------------------------------------------------

/// Interactive results table: ranked methods with the best on top.
pub fn run_method_results_view(
    terminal: &mut Term,
    report: &MethodScanReport,
    output_path: Option<&str>,
) -> anyhow::Result<()> {
    if report.methods.is_empty() {
        return Ok(());
    }

    let mut state = TableState::default();
    state.select(Some(0));

    loop {
        terminal.draw(|frame| draw_method_results_view(frame, report, &mut state, output_path))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some(i.saturating_sub(1)));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = state.selected().unwrap_or(0);
                        state.select(Some((i + 1).min(report.methods.len() - 1)));
                    }
                    _ => return Ok(()),
                }
            }
        }
    }
}

fn draw_method_results_view(
    frame: &mut ratatui::Frame,
    report: &MethodScanReport,
    state: &mut TableState,
    output_path: Option<&str>,
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(2), // sub-header
            Constraint::Min(5),    // table
            Constraint::Length(1), // footer
        ])
        .split(area);

    let header = Paragraph::new(format!(
        "ZeroDPI — Best bypass method for {} ({})",
        report.target_sni, report.target_ip
    ))
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let sub = Paragraph::new(format!(
        "{} methods × {} samples, interval {} ms — ranked by success rate, then avg TTFB",
        report.methods.len(),
        report.samples_per_method,
        report.interval_ms
    ));
    frame.render_widget(sub, chunks[1]);

    let rows: Vec<Row> = report
        .methods
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let rate_style = if e.success_rate >= 100.0 {
                Style::default().fg(Color::Green)
            } else if e.success_rate >= 50.0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Red)
            };
            Row::new(vec![
                Cell::from((i + 1).to_string()),
                Cell::from(e.method.clone()).style(if i == 0 {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                }),
                Cell::from(format!("{}/{}", e.samples_ok, e.samples_total)),
                Cell::from(format!("{:.1}%", e.success_rate)).style(rate_style),
                Cell::from(
                    e.avg_ttfb_ms
                        .map(|v| format!("{v:.0}ms"))
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(
                    e.min_ttfb_ms
                        .map(|v| format!("{v}ms"))
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(
                    e.max_ttfb_ms
                        .map(|v| format!("{v}ms"))
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(
                    e.avg_tls_ms
                        .map(|v| format!("{v:.0}ms"))
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(
                    e.http_status
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "—".into()),
                ),
                Cell::from(e.last_error.clone().unwrap_or_default()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(24),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Min(20),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Method", "OK", "Rate", "Avg TTFB", "Min", "Max", "Avg TLS", "HTTP", "Error",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(Block::default().borders(Borders::ALL))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    frame.render_stateful_widget(table, chunks[2], state);

    let footer = Paragraph::new(match output_path {
        Some(p) => format!("Report saved to {p} — press any key to exit"),
        None => "METHOD_SCAN_OUTPUT not set — press any key to exit".to_owned(),
    });
    frame.render_widget(footer, chunks[3]);
}
