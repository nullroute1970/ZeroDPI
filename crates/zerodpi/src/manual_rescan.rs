//! Commands and selection requests exchanged between the dashboard and scanner.

use tokio::sync::{mpsc, oneshot};
use zerodpi_core::{ip_scanner::IpProbeEntry, sni_scanner::SniProbeEntry};

// The process runs one proxy mode. Serialize periodic, recovery, and manual
// scans through selection and TTL discovery so they cannot race a target swap.
pub static SCAN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub struct Controller {
    pub requests: mpsc::Sender<()>,
    pub selections: mpsc::UnboundedReceiver<Selection>,
}

pub struct Worker {
    requests: mpsc::Receiver<()>,
    selections: mpsc::UnboundedSender<Selection>,
}

pub enum Selection {
    Sni(Vec<SniProbeEntry>, oneshot::Sender<Option<SniProbeEntry>>),
    Ip(Vec<IpProbeEntry>, oneshot::Sender<Option<IpProbeEntry>>),
}

pub fn channel() -> (Controller, Worker) {
    let (request_tx, request_rx) = mpsc::channel(1);
    let (selection_tx, selection_rx) = mpsc::unbounded_channel();
    (
        Controller {
            requests: request_tx,
            selections: selection_rx,
        },
        Worker {
            requests: request_rx,
            selections: selection_tx,
        },
    )
}

impl Worker {
    pub async fn select_sni(&self, auto: bool, entries: &[SniProbeEntry]) -> Option<SniProbeEntry> {
        self.select(auto, entries, Selection::Sni).await
    }

    pub async fn select_ip(&self, auto: bool, entries: &[IpProbeEntry]) -> Option<IpProbeEntry> {
        self.select(auto, entries, Selection::Ip).await
    }

    async fn select<T: Clone>(
        &self,
        auto: bool,
        entries: &[T],
        selection: impl FnOnce(Vec<T>, oneshot::Sender<Option<T>>) -> Selection,
    ) -> Option<T> {
        if auto || entries.is_empty() {
            return entries.first().cloned();
        }
        let (tx, rx) = oneshot::channel();
        self.selections.send(selection(entries.to_vec(), tx)).ok()?;
        rx.await.ok().flatten()
    }
}

/// `true` is a user request; `false` is a periodic scan. A zero interval only
/// disables the timer. Dropping the dashboard stops a manual-only worker.
pub async fn wait_for_rescan(worker: &mut Option<Worker>, interval_secs: u64) -> Option<bool> {
    loop {
        if worker.is_none() && interval_secs == 0 {
            return None;
        }
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)), if interval_secs > 0 => {
                return Some(false);
            }
            request = async {
                match worker.as_mut() {
                    Some(worker) => worker.requests.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if request.is_some() {
                    return Some(true);
                }
                *worker = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ip: &str, score: u8) -> IpProbeEntry {
        IpProbeEntry {
            ip: ip.parse().unwrap(),
            tcp_latency_ms: Some(10),
            tls_ok: true,
            tls_latency_ms: Some(20),
            cert_valid: true,
            ttfb_ms: Some(30),
            download_bps: None,
            upload_bps: None,
            http_status: Some(200),
            score,
        }
    }

    #[tokio::test]
    async fn automatic_rescan_selects_rank_one_without_prompting() {
        let (mut controller, worker) = channel();
        let entries = vec![entry("192.0.2.1", 90), entry("192.0.2.2", 80)];
        let selected = worker.select_ip(true, &entries).await.unwrap();
        assert_eq!(selected.ip.to_string(), "192.0.2.1");
        assert!(controller.selections.try_recv().is_err());
    }

    #[tokio::test]
    async fn manual_rescan_waits_for_the_users_choice_from_fresh_results() {
        let (mut controller, worker) = channel();
        let entries = vec![entry("192.0.2.1", 90), entry("192.0.2.2", 80)];
        let selection = tokio::spawn(async move { worker.select_ip(false, &entries).await });
        let Selection::Ip(entries, reply) = controller
            .selections
            .recv()
            .await
            .expect("manual scan must prompt for selection")
        else {
            panic!("expected IP choices");
        };
        assert!(!selection.is_finished());
        assert_eq!(entries.len(), 2);
        reply.send(Some(entries[1].clone())).unwrap();
        assert_eq!(
            selection.await.unwrap().unwrap().ip.to_string(),
            "192.0.2.2"
        );
    }

    #[tokio::test]
    async fn rescan_can_be_requested_when_periodic_scanning_is_disabled() {
        let (controller, worker) = channel();
        let mut worker = Some(worker);
        controller.requests.try_send(()).unwrap();
        assert_eq!(wait_for_rescan(&mut worker, 0).await, Some(true));
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_scan_still_runs_without_a_manual_request() {
        let (_controller, worker) = channel();
        let mut worker = Some(worker);
        assert_eq!(wait_for_rescan(&mut worker, 300).await, Some(false));
    }

    #[tokio::test]
    async fn closing_the_dashboard_cancels_a_pending_selection() {
        let (mut controller, worker) = channel();
        let entries = vec![entry("192.0.2.1", 90)];
        let selection = tokio::spawn(async move { worker.select_ip(false, &entries).await });
        let prompt = controller.selections.recv().await.unwrap();
        drop(prompt);
        assert!(selection.await.unwrap().is_none());
    }
}
