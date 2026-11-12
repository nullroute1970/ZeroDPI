//! Prepare the active source once, before progress UI or probe workers start.
use std::net::Ipv4Addr;
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
            SniTargetSource::IpList => {
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

/// Reports keep failed probes; connection selection excludes dead IPs only in the new source.
pub fn retain_selectable(cfg: &Config, entries: &mut Vec<SniProbeEntry>) {
    if cfg.SNI_TARGET_SOURCE == SniTargetSource::IpList {
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
