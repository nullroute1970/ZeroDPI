//! DNS discovery progress for the first stage of sni_list+ip_list scans.

use std::collections::{HashSet, VecDeque};

use zerodpi_core::sni_scanner::SniResolveEvent;

use super::*;

#[derive(Default)]
struct DiscoveryState {
    total: usize,
    completed: usize,
    unique_ips: HashSet<Ipv4Addr>,
    recent: VecDeque<(String, String, &'static str)>,
}

impl DiscoveryState {
    fn apply(&mut self, event: SniResolveEvent) {
        match event {
            SniResolveEvent::Started { total } => self.total = total,
            SniResolveEvent::Resolved {
                hostname,
                ips,
                error,
            } => {
                self.completed += 1;
                self.unique_ips.extend(&ips);
                let status = if error.is_some() {
                    "Failed"
                } else if ips.is_empty() {
                    "No IPv4"
                } else {
                    "Resolved"
                };
                let addresses = error.unwrap_or_else(|| {
                    ips.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                });
                self.recent.push_back((hostname, addresses, status));
                if self.recent.len() > 100 {
                    self.recent.pop_front();
                }
            }
        }
    }
}

/// Returns true when the user cancels discovery with q/Esc.
pub fn run_sni_discovery_progress(
    terminal: &mut Term,
    rx: &mut mpsc::UnboundedReceiver<SniResolveEvent>,
) -> anyhow::Result<bool> {
    let mut state = DiscoveryState::default();
    terminal.draw(|frame| draw(frame, &state))?;
    loop {
        let finished = loop {
            match rx.try_recv() {
                Ok(event) => state.apply(event),
                Err(mpsc::error::TryRecvError::Empty) => break false,
                Err(mpsc::error::TryRecvError::Disconnected) => break true,
            }
        };
        terminal.draw(|frame| draw(frame, &state))?;
        if finished {
            return Ok(false);
        }
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press
                    && matches!(key.code, KeyCode::Char('q' | 'Q') | KeyCode::Esc)
                {
                    return Ok(true);
                }
            }
        }
    }
}

fn draw(frame: &mut ratatui::Frame, state: &DiscoveryState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
        ])
        .split(frame.area());
    frame.render_widget(
        Paragraph::new("ZeroDPI — Stage 1/2 — Resolving SNIs to IPv4")
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL)),
        chunks[0],
    );
    let ratio = if state.total == 0 {
        0.0
    } else {
        (state.completed as f64 / state.total as f64).min(1.0)
    };
    frame.render_widget(
        Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" DNS discovery "),
            )
            .gauge_style(Style::default().fg(Color::Green))
            .ratio(ratio)
            .label(format!(
                "{} / {} SNIs checked — {} unique IPs",
                state.completed,
                state.total,
                state.unique_ips.len()
            )),
        chunks[1],
    );
    let visible = chunks[2].height.saturating_sub(3) as usize;
    let rows = state
        .recent
        .iter()
        .skip(state.recent.len().saturating_sub(visible))
        .map(|(hostname, addresses, status)| {
            Row::new(vec![
                Cell::from(hostname.as_str()),
                Cell::from(addresses.as_str()),
                Cell::from(*status).style(Style::default().fg(if *status == "Resolved" {
                    Color::Green
                } else {
                    Color::Red
                })),
            ])
        });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Percentage(35),
                Constraint::Percentage(65),
                Constraint::Length(9),
            ],
        )
        .header(
            Row::new(vec!["SNI", "IPv4 addresses / error", "DNS"]).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Discovery — q/Esc to cancel "),
        ),
        chunks[2],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_view_shows_live_counts_addresses_and_dns_failures() {
        let mut state = DiscoveryState::default();
        state.apply(SniResolveEvent::Started { total: 3 });
        for hostname in ["first.test", "second.test"] {
            state.apply(SniResolveEvent::Resolved {
                hostname: hostname.into(),
                ips: vec!["192.0.2.8".parse().unwrap()],
                error: None,
            });
        }
        state.apply(SniResolveEvent::Resolved {
            hostname: "missing.test".into(),
            ips: vec![],
            error: Some("DNS lookup failed".into()),
        });
        for (width, height) in [(80, 24), (120, 30)] {
            let mut terminal =
                Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| draw(frame, &state)).unwrap();
            let text = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|cell| cell.symbol())
                .collect::<String>();
            assert!(text.contains("Stage 1/2"));
            assert!(text.contains("3 / 3 SNIs checked"));
            assert!(text.contains("1 unique IPs"));
            assert!(text.contains("first.test"));
            assert!(text.contains("192.0.2.8"));
            assert!(text.contains("missing.test"));
            assert!(text.contains("DNS lookup failed"));
            assert!(text.contains("Failed"));
        }
    }
}
