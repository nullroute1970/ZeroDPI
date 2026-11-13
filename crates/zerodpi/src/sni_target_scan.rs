//! Run the full hostname scan before preparing IP-list targets.
use std::collections::HashSet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use zerodpi_core::cloudflare::ScanFilter;
use zerodpi_core::config::{Config, SniTargetSource};
use zerodpi_core::net::OutboundNetwork;
use zerodpi_core::sni_scanner::{scan_sni_ips, scan_sni_list, SniProbeEntry};

pub struct PreparedSniScan {
    path: PathBuf,
    pub total: usize,
    filter: Arc<ScanFilter>,
    fixed: Option<(String, Vec<Ipv4Addr>)>,
}

impl PreparedSniScan {
    pub async fn prepare(cfg: &Config, path: &Path, network: OutboundNetwork) -> Result<Self> {
        Self::prepare_with_progress(cfg, path, network, None).await
    }

    pub async fn prepare_with_progress(
        cfg: &Config,
        path: &Path,
        network: OutboundNetwork,
        progress: Option<mpsc::UnboundedSender<SniProbeEntry>>,
    ) -> Result<Self> {
        if cfg.SNI_TARGET_SOURCE == SniTargetSource::SniListIpList {
            let sni_path = cfg.sni_list_path();
            tracing::info!(path = %sni_path.display(), "stage 1/2: scanning SNI list before IP list");
            let entries = scan_sni_list(
                &sni_path,
                Duration::from_secs(cfg.SCAN_TIMEOUT_SECS),
                Arc::new(cfg.clone()),
                network,
                cfg.scan_filter()?,
                progress,
            )
            .await?;
            let mut ips: Vec<_> = entries.iter().map(|entry| entry.ip).collect();
            ips.sort_unstable();
            ips.dedup();
            let discovered = ips.len();
            let added = append_discovered_ips(cfg, path, ips)?;
            tracing::info!(path = %path.display(), pairs = entries.len(), discovered, added, "SNI scan complete; preparing stage 2/2 IP scan");
        }
        Self::new(cfg, path)
    }

    pub fn new(cfg: &Config, path: &Path) -> Result<Self> {
        let (total, filter, fixed) = match cfg.SNI_TARGET_SOURCE {
            SniTargetSource::SniList => {
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading SNI list '{}'", path.display()))?;
                (
                    crate::count_hostnames(path, cfg.DEDUPLICATE_SCAN_LISTS),
                    cfg.scan_filter()?,
                    None,
                )
            }
            SniTargetSource::IpList | SniTargetSource::SniListIpList => {
                let (mut ips, filter) = crate::load_ip_scan_input(cfg, path)?;
                if cfg.DEDUPLICATE_SCAN_LISTS {
                    let mut seen = std::collections::HashSet::new();
                    ips.retain(|ip| seen.insert(*ip));
                }
                crate::reject_ipv6_ip_candidates(&ips, "SNI_TARGET_SOURCE = ip_list", path)?;
                anyhow::ensure!(
                    !ips.is_empty(),
                    "IP list '{}' has no candidates",
                    path.display()
                );
                let sni = cfg
                    .SELECTED_SNI
                    .clone()
                    .context("SELECTED_SNI is required for ip_list")?;
                let ips = ips
                    .into_iter()
                    .map(|ip| match ip {
                        std::net::IpAddr::V4(ip) => ip,
                        std::net::IpAddr::V6(_) => unreachable!("IPv6 rejected above"),
                    })
                    .collect::<Vec<_>>();
                (ips.len(), filter, Some((sni, ips)))
            }
        };
        tracing::info!(path = %path.display(), source = ?cfg.SNI_TARGET_SOURCE, sni = ?cfg.SELECTED_SNI,
            total, "prepared SNI target scan");
        Ok(Self {
            path: path.to_owned(),
            total,
            filter,
            fixed,
        })
    }

    pub async fn run(
        self,
        timeout: Duration,
        cfg: Arc<Config>,
        network: OutboundNetwork,
        progress: Option<mpsc::UnboundedSender<SniProbeEntry>>,
    ) -> Result<Vec<SniProbeEntry>> {
        match self.fixed {
            Some((sni, ips)) => {
                Ok(scan_sni_ips(ips, sni, timeout, cfg, network, self.filter, progress).await)
            }
            None => scan_sni_list(&self.path, timeout, cfg, network, self.filter, progress).await,
        }
    }
}

/// Append only new addresses, preserving existing text and its newline style.
fn append_discovered_ips(cfg: &Config, path: &Path, ips: Vec<Ipv4Addr>) -> Result<usize> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(error).with_context(|| format!("reading IP list '{}'", path.display()))
        }
    };
    let mut seen: HashSet<IpAddr> = if content.is_empty() {
        HashSet::new()
    } else {
        zerodpi_core::ip_scanner::load_ip_list_with_options(path, cfg.IPV6_MAX_HOSTS, false)?
            .into_iter()
            .collect()
    };
    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut appended = String::new();
    let mut added = 0;
    for ip in ips {
        if seen.insert(IpAddr::V4(ip)) {
            if appended.is_empty() && !content.is_empty() && !content.ends_with('\n') {
                appended.push_str(newline);
            }
            appended.push_str(&ip.to_string());
            appended.push_str(newline);
            added += 1;
        }
    }
    if added > 0 || !path.exists() {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| {
                format!(
                    "opening IP list '{}' for discovered addresses",
                    path.display()
                )
            })?;
        file.write_all(appended.as_bytes())
            .with_context(|| format!("appending discovered addresses to '{}'", path.display()))?;
    }
    Ok(added)
}

/// Reports keep failed probes; connection selection excludes dead IPs only in the new source.
pub fn retain_selectable(cfg: &Config, entries: &mut Vec<SniProbeEntry>) {
    if cfg.SNI_TARGET_SOURCE != SniTargetSource::SniList {
        entries.retain(|entry| entry.tcp_latency_ms.is_some() && entry.score > 0);
    }
}

pub fn select_automatically(cfg: &Config, headless: bool) -> bool {
    cfg.AUTO_SELECT || cfg.LOAD_BALANCE_ENABLED || headless || cfg.selected_sni_uses_dns()
}

pub fn balanced_targets(
    cfg: &Config,
    entries: &[SniProbeEntry],
) -> Vec<zerodpi_core::target_pool::Target> {
    use zerodpi_core::target_pool::{sni_candidates, Target};
    if !cfg.LOAD_BALANCE_ENABLED {
        Vec::new()
    } else if cfg.selected_sni_uses_dns() {
        entries.first().map(Target::from_sni).into_iter().collect()
    } else {
        sni_candidates(entries, cfg.LOAD_BALANCE_TARGET_COUNT, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerodpi_core::config::Config;

    fn test_network() -> OutboundNetwork {
        struct RejectSocket;
        impl zerodpi_core::net::OutboundSocketBinder for RejectSocket {
            fn configure(
                &self,
                _: &tokio::net::TcpSocket,
                _: &zerodpi_core::net::InterfaceBinding,
            ) -> Result<()> {
                anyhow::bail!("reject test socket")
            }
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        OutboundNetwork::new(
            zerodpi_core::net::InterfaceBinding::fixed(Ipv4Addr::LOCALHOST),
            Arc::new(RejectSocket),
        )
    }

    #[tokio::test]
    async fn combined_source_probes_each_hostname_before_starting_the_next_dns_lookup() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct ObserveProbes {
            dns: Arc<crate::dns_test_support::TestDnsServer>,
            calls: AtomicUsize,
            dns_at_probe: std::sync::Mutex<Vec<usize>>,
        }
        impl zerodpi_core::net::OutboundSocketBinder for ObserveProbes {
            fn configure(
                &self,
                _: &tokio::net::TcpSocket,
                _: &zerodpi_core::net::InterfaceBinding,
            ) -> Result<()> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.dns_at_probe.lock().unwrap().push(self.dns.requests());
                anyhow::bail!("reject test socket")
            }
        }
        let dns = Arc::new(
            crate::dns_test_support::TestDnsServer::start(
                0,
                Some("192.0.2.8".parse().unwrap()),
                Some(Duration::ZERO),
            )
            .await,
        );
        let (dir, mut cfg, path) = fixture("", None);
        cfg.SNI_TARGET_SOURCE = SniTargetSource::SniListIpList;
        cfg.CUSTOM_DNS_ENABLED = true;
        cfg.CUSTOM_DNS_SERVERS = vec![dns.addr.to_string()];
        cfg.SNI_MAX_CONCURRENT = 1;
        std::fs::write(dir.path().join("sni_list.txt"), "first.test\nsecond.test\n").unwrap();
        let binder = Arc::new(ObserveProbes {
            dns: dns.clone(),
            calls: AtomicUsize::new(0),
            dns_at_probe: Default::default(),
        });
        let _ = rustls::crypto::ring::default_provider().install_default();
        let network = OutboundNetwork::new(
            zerodpi_core::net::InterfaceBinding::fixed(Ipv4Addr::LOCALHOST),
            binder.clone(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let input = PreparedSniScan::prepare_with_progress(&cfg, &path, network.clone(), Some(tx))
            .await
            .unwrap();
        assert_eq!(
            binder.calls.load(Ordering::SeqCst),
            2,
            "first stage must probe both SNI/IP pairs"
        );
        assert_eq!(*binder.dns_at_probe.lock().unwrap(), vec![1, 2]);
        let first = rx.try_recv().unwrap();
        let second = rx.try_recv().unwrap();
        assert_eq!(first.sni, "first.test");
        assert_eq!(second.sni, "second.test");
        assert_eq!(
            first.score, 0,
            "failed probes must still be reported and saved"
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "192.0.2.8\n");
        let entries = input
            .run(Duration::from_secs(1), Arc::new(cfg), network, None)
            .await
            .unwrap();
        assert_eq!(
            binder.calls.load(Ordering::SeqCst),
            3,
            "second stage must probe the unique IP again"
        );
        assert_eq!(dns.requests(), 2, "IP scan must not repeat DNS lookups");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sni, "fixed.example");
    }

    fn candidate(
        sni: &str,
        ip: std::net::Ipv4Addr,
        score: u8,
    ) -> zerodpi_core::sni_scanner::SniProbeEntry {
        zerodpi_core::sni_scanner::SniProbeEntry {
            sni: sni.into(),
            ip,
            score,
            tcp_latency_ms: Some(10),
            tls_ok: false,
            tls_latency_ms: None,
            cert_valid: false,
            ttfb_ms: None,
            download_bps: None,
            upload_bps: None,
            http_status: None,
        }
    }

    fn fixture(ips: &str, ranges: Option<&str>) -> (tempfile::TempDir, Config, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, format!("LISTEN_HOST='127.0.0.1'\nLISTEN_PORT=44444\nSNI_TARGET_SOURCE='ip_list'\nSELECTED_SNI='fixed.example'\nCLOUDFLARE_ONLY={}\n", ranges.is_some())).unwrap();
        let input = dir.path().join("ip_list.txt");
        std::fs::write(&input, ips).unwrap();
        if let Some(ranges) = ranges {
            std::fs::write(dir.path().join("cf.txt"), ranges).unwrap();
        }
        let cfg = Config::from_file(config).unwrap();
        (dir, cfg, input)
    }

    #[test]
    fn preparation_expands_deduplicates_and_filters_before_counting() {
        let (_dir, cfg, path) = fixture(
            "192.0.2.0/30\n192.0.2.1\n198.51.100.1\n",
            Some("192.0.2.0/24\n"),
        );
        let input = PreparedSniScan::new(&cfg, &path).unwrap();
        assert_eq!(input.total, 2);
        assert_eq!(cfg.sni_scan_list(), "ip_list.txt");
    }

    #[tokio::test]
    async fn combined_source_appends_scanned_ips_then_prepares_fixed_sni_scan() {
        let server = crate::dns_test_support::TestDnsServer::start_many(
            0,
            vec![
                "192.0.2.1".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                "198.51.100.7".parse().unwrap(),
            ],
            Some(Duration::ZERO),
        )
        .await;
        let (dir, mut cfg, path) = fixture("# existing\r\n192.0.2.1", Some("192.0.2.0/24\n"));
        cfg.SNI_TARGET_SOURCE = SniTargetSource::SniListIpList;
        cfg.SNI_LIST = "names/hosts.txt".into();
        cfg.CUSTOM_DNS_ENABLED = true;
        cfg.CUSTOM_DNS_SERVERS = vec![server.addr.to_string()];
        cfg.DEDUPLICATE_SCAN_LISTS = false;
        std::fs::create_dir(dir.path().join("names")).unwrap();
        std::fs::write(
            dir.path().join("names/hosts.txt"),
            "# hosts\nfirst.test\n\nsecond.test\n",
        )
        .unwrap();
        let input = PreparedSniScan::prepare(&cfg, &path, test_network())
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "# existing\r\n192.0.2.1\r\n192.0.2.2\r\n"
        );
        assert_eq!(input.total, 2);
        let (sni, ips) = input.fixed.unwrap();
        assert_eq!(sni, "fixed.example");
        assert_eq!(
            ips,
            vec![
                "192.0.2.1".parse::<Ipv4Addr>().unwrap(),
                "192.0.2.2".parse().unwrap()
            ]
        );
        assert_eq!(server.requests(), 2);
        let before = std::fs::read(&path).unwrap();
        PreparedSniScan::prepare(&cfg, &path, test_network())
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn combined_source_creates_missing_ip_list() {
        let server = crate::dns_test_support::TestDnsServer::start(
            0,
            Some("192.0.2.8".parse().unwrap()),
            Some(Duration::ZERO),
        )
        .await;
        let (dir, mut cfg, path) = fixture("", None);
        cfg.SNI_TARGET_SOURCE = SniTargetSource::SniListIpList;
        cfg.CUSTOM_DNS_ENABLED = true;
        cfg.CUSTOM_DNS_SERVERS = vec![server.addr.to_string()];
        std::fs::write(dir.path().join("sni_list.txt"), "first.test\n").unwrap();
        std::fs::remove_file(&path).unwrap();
        let input = PreparedSniScan::prepare(&cfg, &path, test_network())
            .await
            .unwrap();
        assert_eq!(input.total, 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "192.0.2.8\n");
    }

    #[tokio::test]
    async fn combined_source_keeps_existing_ips_when_dns_fails() {
        let server =
            crate::dns_test_support::TestDnsServer::start(3, None, Some(Duration::ZERO)).await;
        let (dir, mut cfg, path) = fixture("192.0.2.1\n", None);
        cfg.SNI_TARGET_SOURCE = SniTargetSource::SniListIpList;
        cfg.CUSTOM_DNS_ENABLED = true;
        cfg.CUSTOM_DNS_SERVERS = vec![server.addr.to_string()];
        std::fs::write(dir.path().join("sni_list.txt"), "missing.test\n").unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let input = PreparedSniScan::prepare_with_progress(&cfg, &path, test_network(), Some(tx))
            .await
            .unwrap();
        assert_eq!(input.total, 1);
        assert!(server.requests() > 0);
        assert!(
            rx.try_recv().is_err(),
            "failed DNS produces no probe entry, as in sni_list"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "192.0.2.1\n");
    }

    #[test]
    fn discovery_does_not_append_existing_cidr_hosts_or_duplicate_answers() {
        let (_dir, cfg, path) = fixture("# candidates\n192.0.2.0/30\n", None);
        let ips = vec![
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            "198.51.100.7".parse().unwrap(),
            "198.51.100.7".parse().unwrap(),
        ];
        assert_eq!(append_discovered_ips(&cfg, &path, ips).unwrap(), 1);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "# candidates\n192.0.2.0/30\n198.51.100.7\n"
        );
    }

    #[tokio::test]
    async fn ip_list_preparation_does_not_require_a_hostname_file() {
        let (_dir, cfg, path) = fixture("192.0.2.1\n", None);
        let input = PreparedSniScan::prepare(&cfg, &path, test_network())
            .await
            .unwrap();
        assert_eq!(input.total, 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "192.0.2.1\n");
    }

    #[test]
    fn preparation_rejects_ipv6_empty_missing_and_filtered_inputs() {
        for ips in ["::1\n", "192.0.2.1\n::1\n", ""] {
            let (_dir, cfg, path) = fixture(ips, None);
            assert!(PreparedSniScan::new(&cfg, &path).is_err());
        }
        let (_dir, cfg, path) = fixture("198.51.100.1\n", Some("192.0.2.0/24\n"));
        assert!(PreparedSniScan::new(&cfg, &path).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(PreparedSniScan::new(&cfg, &path).is_err());
    }

    #[test]
    fn selectable_ip_targets_require_tcp_and_score_but_not_tls() {
        let (_dir, cfg, _path) = fixture("192.0.2.1", None);
        let mut entries = vec![
            candidate("fixed.example", "192.0.2.1".parse().unwrap(), 20),
            candidate("fixed.example", "192.0.2.2".parse().unwrap(), 99),
            candidate("fixed.example", "192.0.2.3".parse().unwrap(), 0),
        ];
        entries[0].tls_ok = false;
        entries[1].tcp_latency_ms = None;
        retain_selectable(&cfg, &mut entries);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip.to_string(), "192.0.2.1");
    }

    #[test]
    fn fixed_sni_keeps_manual_selection_and_multiple_balanced_ips() {
        let (_dir, mut cfg, _) = fixture("192.0.2.1", None);
        assert!(!select_automatically(&cfg, false));
        assert!(select_automatically(&cfg, true));
        cfg.LOAD_BALANCE_ENABLED = true;
        assert!(select_automatically(&cfg, false));
        let entries = vec![
            candidate("fixed.example", "192.0.2.1".parse().unwrap(), 20),
            candidate("fixed.example", "192.0.2.2".parse().unwrap(), 15),
        ];
        let targets = balanced_targets(&cfg, &entries);
        assert_eq!(targets.len(), 2);
        assert!(targets
            .iter()
            .all(|t| t.sni.as_deref() == Some("fixed.example")));
        assert_eq!(targets[1].ip.to_string(), "192.0.2.2");
        cfg.SNI_TARGET_SOURCE = SniTargetSource::SniList;
        assert_eq!(balanced_targets(&cfg, &entries).len(), 1);
        cfg.LOAD_BALANCE_ENABLED = false;
        assert!(select_automatically(&cfg, false));
    }
}
