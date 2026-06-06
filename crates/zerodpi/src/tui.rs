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

use std::collections::VecDeque;
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
use zerodpi_core::proxy::{ProxyEvent, RelayEndReason};
use zerodpi_core::sni_scanner::SniProbeEntry;

type Term = Terminal<CrosstermBackend<Stdout>>;
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
                let speed_str = e
                    .speed_bps
                    .map(|bps| {
                        if bps >= 1_048_576.0 {
                            format!("{:.1}MB/s", bps / 1_048_576.0)
                        } else {
                            format!("{:.0}KB/s", bps / 1024.0)
                        }
                    })
                    .unwrap_or_else(|| "—".into());
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
                    Cell::from(speed_str),
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
            Constraint::Length(6),
        ];
        let table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    "Score", "SNI", "IP", "TCP", "TLS", "TTFB", "Speed", "HTTP",
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
            let speed_str = e
                .speed_bps
                .map(|bps| {
                    if bps >= 1_048_576.0 {
                        format!("{:.1}MB/s", bps / 1_048_576.0)
                    } else {
                        format!("{:.0}KB/s", bps / 1024.0)
                    }
                })
                .unwrap_or_else(|| "—".into());
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
                Cell::from(speed_str),
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
        Constraint::Length(6),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Score", "SNI", "IP", "TCP", "TLS", "Cert", "TTFB", "Speed", "HTTP",
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

// ---------------------------------------------------------------------------
// Dashboard state
// ---------------------------------------------------------------------------

/// All mutable state owned by the live proxy dashboard event loop.
struct DashboardState {
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
pub fn run_dashboard(
    terminal: &mut Term,
    rx: &mut mpsc::UnboundedReceiver<ProxyEvent>,
    info: &DashboardInfo,
    cfg: &Config,
) -> anyhow::Result<()> {
    let active_sni = match info {
        DashboardInfo::SniSpoof { sni, ip, score } => Some((sni.clone(), *ip, *score)),
        DashboardInfo::IpBypass { .. } => None,
    };
    let active_ip = match info {
        DashboardInfo::SniSpoof { .. } => None,
        DashboardInfo::IpBypass { ip } => Some(*ip),
    };
    let mut state = DashboardState {
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
        start: Instant::now(),
        channel_closed: false,
    };

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

        if state.auto_scroll && got_event {
            state.scroll_offset = 0;
        }

        draw_dashboard(terminal, &state, info, cfg)?;

        // Filtered count — needed for scroll bounds in key handler.
        let filtered_len = state
            .records
            .iter()
            .filter(|r| state.filter.matches(&r.status))
            .count();

        // Page size: terminal height minus the fixed widget rows (header=5, stats=3,
        // help=3, table header=1, table borders=2 → 14 total fixed rows).
        let visible_rows = terminal
            .size()
            .map(|s| (s.height as usize).saturating_sub(14))
            .unwrap_or(10)
            .max(1);

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind == KeyEventKind::Press {
                    match k.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                            return Ok(());
                        }
                        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                            return Ok(());
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            state.auto_scroll = false;
                            state.scroll_offset = state.scroll_offset.saturating_sub(1);
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            state.auto_scroll = false;
                            if filtered_len > 0 && state.scroll_offset + 1 < filtered_len {
                                state.scroll_offset += 1;
                            }
                        }
                        KeyCode::PageUp => {
                            state.auto_scroll = false;
                            state.scroll_offset = state.scroll_offset.saturating_sub(visible_rows);
                        }
                        KeyCode::PageDown => {
                            state.auto_scroll = false;
                            state.scroll_offset = (state.scroll_offset + visible_rows)
                                .min(filtered_len.saturating_sub(1));
                        }
                        KeyCode::Home => {
                            state.scroll_offset = 0;
                        }
                        KeyCode::End => {
                            state.auto_scroll = false;
                            state.scroll_offset = filtered_len.saturating_sub(1);
                        }
                        KeyCode::Char(' ') | KeyCode::Char('a') => {
                            state.auto_scroll = !state.auto_scroll;
                            if state.auto_scroll {
                                state.scroll_offset = 0;
                            }
                        }
                        KeyCode::Tab => {
                            state.filter = state.filter.next();
                            state.scroll_offset = 0;
                        }
                        _ => {}
                    }
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
        ProxyEvent::ConnectionAccepted { peer, src_port } => {
            state.total += 1;
            state.active += 1;
            let now = Instant::now();
            let rec = ConnectionRecord {
                started_at: SystemTime::now(),
                start_instant: now,
                end_instant: None,
                src_port,
                peer,
                status: ConnStatus::Connecting,
                status_changed_at: now,
                c2s_bytes: 0,
                s2c_bytes: 0,
                rate_c2s_bps: 0.0,
                rate_s2c_bps: 0.0,
                last_snapshot: None,
            };
            state.records.push_front(rec);
            if state.records.len() > MAX_RECORDS {
                state.records.pop_back();
            }
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
                let now = Instant::now();
                if let Some((prev_time, prev_c2s, prev_s2c)) = r.last_snapshot {
                    let secs = now.duration_since(prev_time).as_secs_f64().max(0.001);
                    r.rate_c2s_bps = c2s_bytes.saturating_sub(prev_c2s) as f64 / secs;
                    r.rate_s2c_bps = s2c_bytes.saturating_sub(prev_s2c) as f64 / secs;
                }
                r.c2s_bytes = c2s_bytes;
                r.s2c_bytes = s2c_bytes;
                r.last_snapshot = Some((now, c2s_bytes, s2c_bytes));
            }
        }
        ProxyEvent::ConnectionError { src_port, .. } => {
            state.bypasses_failed += 1;
            state.active = state.active.saturating_sub(1);
            if let Some(r) = find_record(&mut state.records, src_port) {
                let now = Instant::now();
                r.set_status(ConnStatus::Failed, now);
                r.end_instant = Some(now);
            }
        }
        ProxyEvent::SniTargetChanged { sni, ip, score } => {
            state.active_sni = Some((sni, ip, score));
        }
        ProxyEvent::IpTargetChanged { ip } => {
            state.active_ip = Some(ip);
        }
    }
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

fn draw_dashboard(
    terminal: &mut Term,
    state: &DashboardState,
    info: &DashboardInfo,
    cfg: &Config,
) -> anyhow::Result<()> {
    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5), // header (2 info lines + borders)
                Constraint::Length(3), // stats bar
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
        let header_lines = match info {
            DashboardInfo::SniSpoof { .. } => {
                let (sni, ip, score) = state
                    .active_sni
                    .as_ref()
                    .expect("SNI dashboard state is initialised");
                vec![
                    Line::from(vec![
                        Span::styled("SNI: ", label_style()),
                        Span::styled(
                            sni.clone(),
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
                    ]),
                    Line::from(vec![
                        Span::styled("Method: ", label_style()),
                        Span::styled(cfg.BYPASS_METHOD.clone(), Style::default().fg(Color::White)),
                        Span::raw("   "),
                        Span::styled("Listen: ", label_style()),
                        Span::styled(
                            format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT),
                            Style::default().fg(Color::White),
                        ),
                        Span::raw("   "),
                        Span::styled("Uptime: ", label_style()),
                        Span::styled(uptime, Style::default().fg(Color::White)),
                    ]),
                ]
            }
            DashboardInfo::IpBypass { .. } => {
                let ip = state.active_ip.expect("IP dashboard state is initialised");
                vec![
                    Line::from(vec![
                        Span::styled("Mode: ", label_style()),
                        Span::styled(
                            "ip_bypass",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw("   "),
                        Span::styled("Active IP: ", label_style()),
                        Span::styled(ip.to_string(), Style::default().fg(Color::White)),
                        Span::raw("   "),
                        Span::styled("Listen: ", label_style()),
                        Span::styled(
                            format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT),
                            Style::default().fg(Color::White),
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("Uptime: ", label_style()),
                        Span::styled(uptime, Style::default().fg(Color::White)),
                    ]),
                ]
            }
        };
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
        let agg_c2s_bps: f64 = state
            .records
            .iter()
            .filter(|r| matches!(r.status, ConnStatus::Relaying))
            .map(|r| r.rate_c2s_bps)
            .sum();
        let agg_s2c_bps: f64 = state
            .records
            .iter()
            .filter(|r| matches!(r.status, ConnStatus::Relaying))
            .map(|r| r.rate_s2c_bps)
            .sum();
        let (total_upload, total_download) = live_transfer_totals(state);
        let stats_line = Line::from(vec![
            Span::styled(" Total: ", label_style()),
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
        let stats = Paragraph::new(stats_line)
            .block(Block::default().borders(Borders::ALL).title(" Stats "));
        frame.render_widget(stats, chunks[1]);

        // ── Connection log ───────────────────────────────────────────────────
        let now = Instant::now();
        let filtered = ordered_connection_records(state, now);
        let filter_label = state.filter.label();
        let table_title = if filtered.is_empty() {
            format!(" Connections [{}] — no traffic yet ", filter_label)
        } else {
            format!(
                " Connections [{}] ({} shown / {} total) ",
                filter_label,
                filtered.len(),
                state.records.len()
            )
        };

        let rows: Vec<Row> = filtered
            .iter()
            .skip(state.scroll_offset)
            .map(|r| {
                let row_style = connection_row_style(r);
                Row::new(vec![
                    Cell::from(fmt_time(r.started_at)),
                    Cell::from(r.peer.to_string()),
                    Cell::from(r.status.label()).style(r.status.style()),
                    Cell::from(fmt_bytes(r.c2s_bytes)),
                    Cell::from(fmt_bytes(r.s2c_bytes)),
                    Cell::from(fmt_rate(r.rate_c2s_bps)),
                    Cell::from(fmt_rate(r.rate_s2c_bps)),
                    Cell::from(r.duration_str()),
                ])
                .style(row_style)
            })
            .collect();

        let widths = [
            Constraint::Length(8),  // Time
            Constraint::Length(21), // Peer
            Constraint::Length(11), // Status
            Constraint::Length(8),  // ↑ Bytes
            Constraint::Length(8),  // ↓ Bytes
            Constraint::Length(9),  // Rate↑
            Constraint::Length(9),  // Rate↓
            Constraint::Min(5),     // Duration
        ];
        let log_table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    "Time",
                    "Peer",
                    "Status",
                    "↑ Bytes",
                    "↓ Bytes",
                    "Rate↑",
                    "Rate↓",
                    "Duration",
                ])
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ),
            )
            .block(Block::default().borders(Borders::ALL).title(table_title));
        frame.render_widget(log_table, chunks[2]);

        // ── Help bar ─────────────────────────────────────────────────────────
        let auto_span = if state.auto_scroll {
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
        let help_line = Line::from(vec![
            auto_span,
            Span::styled(" ↑/↓ j/k ", Style::default().fg(Color::Yellow)),
            Span::raw("scroll  "),
            Span::styled(" PgUp/Dn ", Style::default().fg(Color::Yellow)),
            Span::raw("page  "),
            Span::styled(" Home/End ", Style::default().fg(Color::Yellow)),
            Span::raw("jump  "),
            Span::styled(" Space/a ", Style::default().fg(Color::Yellow)),
            Span::raw("auto  "),
            Span::styled(" Tab ", Style::default().fg(Color::Yellow)),
            Span::raw("filter  "),
            Span::styled(" q/Esc ", Style::default().fg(Color::Red)),
            Span::raw("quit "),
        ]);
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
                let speed_str = e
                    .speed_bps
                    .map(|bps| {
                        if bps >= 1_048_576.0 {
                            format!("{:.1}MB/s", bps / 1_048_576.0)
                        } else {
                            format!("{:.0}KB/s", bps / 1024.0)
                        }
                    })
                    .unwrap_or_else(|| "—".into());
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
                    Cell::from(speed_str),
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
            Constraint::Length(6),
        ];
        let table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    "Score", "IP", "TCP", "TLS", "Cert", "TTFB", "Speed", "HTTP",
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
            let speed_str = e
                .speed_bps
                .map(|bps| {
                    if bps >= 1_048_576.0 {
                        format!("{:.1}MB/s", bps / 1_048_576.0)
                    } else {
                        format!("{:.0}KB/s", bps / 1024.0)
                    }
                })
                .unwrap_or_else(|| "—".into());
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
                Cell::from(speed_str),
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
        Constraint::Length(6),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Score", "IP", "TCP", "TLS", "Cert", "TTFB", "Speed", "HTTP",
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
            let speed_str = e
                .speed_bps
                .map(|bps| {
                    if bps >= 1_048_576.0 {
                        format!("{:.1}MB/s", bps / 1_048_576.0)
                    } else {
                        format!("{:.0}KB/s", bps / 1024.0)
                    }
                })
                .unwrap_or_else(|| "—".into());
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
                Cell::from(speed_str),
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
        Constraint::Length(6),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Score", "SNI", "IP", "TCP", "TLS", "Cert", "TTFB", "Speed", "HTTP",
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

    fn record(status: ConnStatus, upload_bps: f64, download_bps: f64) -> ConnectionRecord {
        let now = Instant::now();
        ConnectionRecord {
            started_at: UNIX_EPOCH,
            start_instant: now,
            end_instant: None,
            src_port: 443,
            peer: "127.0.0.1:12345".parse().unwrap(),
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

    fn dashboard_state(records: Vec<ConnectionRecord>) -> DashboardState {
        DashboardState {
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
            start: Instant::now(),
            channel_closed: false,
        }
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
            let speed_str = e
                .speed_bps
                .map(|bps| {
                    if bps >= 1_048_576.0 {
                        format!("{:.1}MB/s", bps / 1_048_576.0)
                    } else {
                        format!("{:.0}KB/s", bps / 1024.0)
                    }
                })
                .unwrap_or_else(|| "—".into());
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
                Cell::from(speed_str),
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
        Constraint::Length(6),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                "#", "Score", "IP", "TCP", "TLS", "Cert", "TTFB", "Speed", "HTTP",
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
