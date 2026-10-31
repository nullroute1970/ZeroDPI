//! Cloudflare CIDR filtering for scan candidates.

use std::net::IpAddr;
use std::path::Path;

use anyhow::Context;
use ipnet::IpNet;

/// Immutable per-scan allowlist. `None` bypasses filtering without file access.
#[derive(Debug, Clone, Default)]
pub struct ScanFilter {
    ranges: Option<Vec<IpNet>>,
}

impl ScanFilter {
    pub fn load(enabled: bool, config_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        if !enabled {
            return Ok(Self::default());
        }
        let path = config_path
            .as_ref()
            .parent()
            .unwrap_or(Path::new("."))
            .join("cf.txt");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading Cloudflare ranges from '{}'", path.display()))?;
        let mut ranges = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let range = line.parse::<IpNet>().with_context(|| {
                format!(
                    "invalid Cloudflare CIDR in '{}' at line {}: {line}",
                    path.display(),
                    index + 1
                )
            })?;
            ranges.push(range);
        }
        anyhow::ensure!(
            !ranges.is_empty(),
            "Cloudflare file '{}' contains no CIDR ranges",
            path.display()
        );
        Ok(Self {
            ranges: Some(ranges),
        })
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        match &self.ranges {
            Some(ranges) => ranges.iter().any(|range| range.contains(&ip)),
            None => true,
        }
    }

    /// Filter before computing progress totals as well as before spawning probes.
    pub fn retain(&self, ips: &mut Vec<IpAddr>) {
        let before = ips.len();
        ips.retain(|ip| self.allows(*ip));
        if self.ranges.is_some() {
            tracing::debug!(
                allowed = ips.len(),
                skipped = before - ips.len(),
                "Cloudflare candidate filter"
            );
            if ips.is_empty() {
                tracing::warn!("no IP candidates match the Cloudflare ranges in cf.txt");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn cloudflare_filter_checks_both_address_families_and_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            dir.path().join("cf.txt"),
            "# ranges\r\n\r\n104.16.0.0/13\r\n2606:4700::/32\r\n",
        )
        .unwrap();
        let filter = ScanFilter::load(true, &config).unwrap();
        for ip in [
            "104.16.0.0",
            "104.23.255.255",
            "2606:4700::",
            "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(filter.allows(ip.parse::<IpAddr>().unwrap()), "{ip}");
        }
        for ip in [
            "104.15.255.255",
            "104.24.0.0",
            "2606:46ff:ffff::1",
            "2606:4701::",
            "127.0.0.1",
        ] {
            assert!(!filter.allows(ip.parse::<IpAddr>().unwrap()), "{ip}");
        }
    }

    #[test]
    fn cloudflare_filter_reports_missing_empty_unreadable_and_invalid_files() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let path = dir.path().join("cf.txt");
        assert!(
            format!("{:#}", ScanFilter::load(true, &config).unwrap_err())
                .contains(&path.display().to_string())
        );
        std::fs::create_dir(&path).unwrap();
        assert!(ScanFilter::load(true, &config).is_err());
        std::fs::remove_dir(&path).unwrap();
        for text in ["", "# no ranges\n\n"] {
            std::fs::write(&path, text).unwrap();
            assert!(
                format!("{:#}", ScanFilter::load(true, &config).unwrap_err())
                    .contains("no CIDR ranges")
            );
        }
        std::fs::write(&path, "104.16.0.0/13\nnot-a-cidr\n").unwrap();
        let error = format!("{:#}", ScanFilter::load(true, &config).unwrap_err());
        assert!(error.contains(&path.display().to_string()));
        assert!(error.contains("line 2"));
    }

    #[test]
    fn cloudflare_filter_disabled_never_reads_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        for text in [None, Some("invalid")] {
            if let Some(text) = text {
                std::fs::write(dir.path().join("cf.txt"), text).unwrap();
            }
            let filter = ScanFilter::load(false, &config).unwrap();
            assert!(filter.allows("192.0.2.1".parse().unwrap()));
            assert!(filter.allows("::1".parse().unwrap()));
        }
    }
}
