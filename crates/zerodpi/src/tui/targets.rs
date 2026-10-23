//! Read-only pool samples and the Targets dashboard view.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use zerodpi_core::target_pool::{
    PingSource, SelectionStrategy, TargetPool, TargetPoolSnapshot, TargetSnapshot,
};

use super::{fmt_bytes, fmt_rate};

const SAMPLE_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum DashboardView {
    #[default]
    Connections,
    Targets,
}

pub(super) struct TargetRow {
    pub snapshot: TargetSnapshot,
    pub upload_bps: f64,
    pub download_bps: f64,
    pub share: f64,
}

#[derive(Default)]
pub(super) struct TargetsState {
    pub strategy: SelectionStrategy,
    pub rows: Vec<TargetRow>,
    pub scroll_offset: usize,
    sampled_at: Option<Instant>,
}

impl TargetsState {
    pub fn next_sample_in(&self, now: Instant) -> Duration {
        self.sampled_at
            .map(|last| SAMPLE_INTERVAL.saturating_sub(now.saturating_duration_since(last)))
            .unwrap_or_default()
    }

    /// Sample on the existing UI loop, never enqueue another stream of events.
    pub fn refresh(&mut self, pool: &TargetPool, now: Instant) -> bool {
        if self
            .sampled_at
            .is_some_and(|last| now.saturating_duration_since(last) < SAMPLE_INTERVAL)
        {
            return false;
        }
        self.update(pool.snapshot(), now);
        true
    }

    pub fn update(&mut self, snapshot: TargetPoolSnapshot, now: Instant) {
        self.strategy = snapshot.strategy;
        let previous: HashMap<_, _> = self
            .rows
            .iter()
            .map(|row| {
                (
                    (row.snapshot.target.sni.clone(), row.snapshot.target.ip),
                    (row.snapshot.c2s_bytes, row.snapshot.s2c_bytes),
                )
            })
            .collect();
        let elapsed = self
            .sampled_at
            .map(|last| now.saturating_duration_since(last).as_secs_f64())
            .unwrap_or(0.0);
        let active: usize = snapshot
            .targets
            .iter()
            .map(|target| target.active_connections)
            .sum();
        self.rows = snapshot
            .targets
            .into_iter()
            .map(|target| {
                let key = (target.target.sni.clone(), target.target.ip);
                let (upload_bps, download_bps) = previous
                    .get(&key)
                    .filter(|_| elapsed > 0.0)
                    .map(|(up, down)| {
                        (
                            target.c2s_bytes.saturating_sub(*up) as f64 / elapsed,
                            target.s2c_bytes.saturating_sub(*down) as f64 / elapsed,
                        )
                    })
                    .unwrap_or((0.0, 0.0));
                let share = if active == 0 {
                    0.0
                } else {
                    target.active_connections as f64 * 100.0 / active as f64
                };
                TargetRow {
                    snapshot: target,
                    upload_bps,
                    download_bps,
                    share,
                }
            })
            .collect();
        self.scroll_offset = self.scroll_offset.min(self.rows.len().saturating_sub(1));
        self.sampled_at = Some(now);
    }

    pub fn stop(&mut self) {
        for row in &mut self.rows {
            row.upload_bps = 0.0;
            row.download_bps = 0.0;
        }
    }
}

/// Truncate by terminal cell width rather than bytes; keep model strings intact.
pub(super) fn fit(text: &str, width: u16) -> String {
    if Line::from(text).width() <= width as usize {
        return text.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    let mut result = String::new();
    let mut used = 0;
    for ch in text.chars() {
        let size = Line::from(ch.to_string()).width();
        if used + size >= width as usize {
            break;
        }
        result.push(ch);
        used += size;
    }
    result.push('…');
    result
}

pub(super) fn membership(target: &TargetSnapshot) -> &'static str {
    if target.rank.is_some() {
        "In pool"
    } else if target.active_connections > 0 {
        "Draining"
    } else {
        "Retired"
    }
}

fn ping_label(target: &TargetSnapshot) -> String {
    let source = match target.ping_source {
        PingSource::Scan => "Scan",
        PingSource::Live => "Live",
    };
    match target.ping {
        Some(ping) => format!("{}ms {source}", ping.as_millis()),
        None if target.ping_source == PingSource::Live => "failed Live".into(),
        None => "unknown Scan".into(),
    }
}

pub(super) fn draw_targets(frame: &mut ratatui::Frame, area: Rect, state: &TargetsState) {
    let wide = area.width >= 140;
    let widths = if wide {
        let ip_width = if area.width >= 160 { 39 } else { 24 };
        // The SNI column takes the remainder after fixed fields and separators.
        let sni_width = area.width.saturating_sub(2 + 11 + 81 + ip_width);
        vec![4, 9, ip_width, sni_width, 5, 15, 6, 6, 9, 9, 9, 9]
    } else {
        let edge = 24.min(area.width.saturating_sub(4) / 3);
        vec![edge, area.width.saturating_sub(4 + 2 * edge), edge]
    };
    let rows = state.rows.iter().skip(state.scroll_offset).map(|row| {
        let target = &row.snapshot;
        let rank = target
            .rank
            .map(|rank| rank.to_string())
            .unwrap_or_else(|| "—".into());
        let state_label = membership(target);
        let ping = ping_label(target);
        let texts = if wide {
            vec![
                rank,
                state_label.into(),
                target.target.ip.to_string(),
                target.target.sni.as_deref().unwrap_or("—").into(),
                target.target.score.to_string(),
                ping,
                target.active_connections.to_string(),
                format!("{:.0}%", row.share),
                fmt_rate(row.upload_bps),
                fmt_rate(row.download_bps),
                fmt_bytes(target.c2s_bytes),
                fmt_bytes(target.s2c_bytes),
            ]
        } else {
            vec![
                format!(
                    "{}\n{}",
                    fit(&target.target.ip.to_string(), widths[0]),
                    fit(
                        &format!(
                            "↑ {} / {}",
                            fmt_rate(row.upload_bps),
                            fmt_bytes(target.c2s_bytes)
                        ),
                        widths[0]
                    )
                ),
                format!(
                    "{}\n{}",
                    fit(target.target.sni.as_deref().unwrap_or("—"), widths[1]),
                    fit(
                        &format!(
                            "↓ {} / {}",
                            fmt_rate(row.download_bps),
                            fmt_bytes(target.s2c_bytes)
                        ),
                        widths[1]
                    )
                ),
                format!(
                    "{}\n{}",
                    fit(
                        &format!(
                            "{} {state_label} / {}",
                            target
                                .rank
                                .map(|rank| format!("#{rank}"))
                                .unwrap_or_else(|| "—".into()),
                            target.active_connections
                        ),
                        widths[2]
                    ),
                    fit(
                        &format!("{}pt {ping} {:.0}%", target.target.score, row.share),
                        widths[2]
                    )
                ),
            ]
        };
        let cells: Vec<_> = texts
            .into_iter()
            .zip(&widths)
            .map(|(text, width)| Cell::from(if wide { fit(&text, *width) } else { text }))
            .collect();
        let style = if target.rank.is_some() {
            Style::default()
        } else if target.active_connections > 0 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        Row::new(cells)
            .height(if wide { 1 } else { 2 })
            .style(style)
    });
    let headers = if wide {
        vec![
            "Rank",
            "State",
            "Target",
            "SNI",
            "Score",
            "TCP",
            "Active",
            "Share",
            "Rate↑",
            "Rate↓",
            "↑ Bytes",
            "↓ Bytes",
        ]
    } else {
        vec!["Target / upload", "SNI / download", "State / active"]
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
    let table = Table::new(rows, widths.iter().map(|width| Constraint::Length(*width)))
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(
            format!(" Targets ({} current / {} historical) ",
                state.rows.iter().filter(|row| row.snapshot.rank.is_some()).count(),
                state.rows.iter().filter(|row| row.snapshot.rank.is_none()).count()),
        ));
    frame.render_widget(table, area);
}
