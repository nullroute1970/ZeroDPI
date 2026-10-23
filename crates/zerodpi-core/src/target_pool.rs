//! Ranked relay targets and connection-lifetime reservations shared by all listeners.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::ip_scanner::IpProbeEntry;
use crate::sni_scanner::SniProbeEntry;

pub mod ping;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionStrategy {
    Random,
    #[default]
    RoundRobin,
    LeastPing,
    LeastLoad,
}

impl fmt::Display for SelectionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Random => "random",
            Self::RoundRobin => "round_robin",
            Self::LeastPing => "least_ping",
            Self::LeastLoad => "least_load",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub ip: IpAddr,
    pub sni: Option<Arc<str>>,
    pub score: u8,
    pub tcp_latency: Option<Duration>,
    pub low_ttl: Option<u8>,
}

type TargetKey = (Option<Arc<str>>, IpAddr);

impl Target {
    pub fn ip(ip: IpAddr, score: u8) -> Self {
        Self {
            ip,
            sni: None,
            score,
            tcp_latency: None,
            low_ttl: None,
        }
    }

    pub fn sni(sni: impl Into<Arc<str>>, ip: std::net::Ipv4Addr, score: u8) -> Self {
        Self {
            sni: Some(sni.into()),
            ..Self::ip(ip.into(), score)
        }
    }

    fn key(&self) -> TargetKey {
        (self.sni.clone(), self.ip)
    }

    pub fn from_sni(entry: &SniProbeEntry) -> Self {
        Self {
            tcp_latency: entry.tcp_latency_ms.map(Duration::from_millis),
            ..Self::sni(entry.sni.clone(), entry.ip, entry.score)
        }
    }

    pub fn from_ip(entry: &IpProbeEntry) -> Self {
        Self {
            tcp_latency: entry.tcp_latency_ms.map(Duration::from_millis),
            ..Self::ip(entry.ip, entry.score)
        }
    }
}

/// Input is already ranked by the scanner; filtering never changes that order.
pub fn sni_candidates(entries: &[SniProbeEntry], limit: usize, min_score: u8) -> Vec<Target> {
    unique_targets(
        entries
            .iter()
            .filter(|e| e.tcp_latency_ms.is_some() && e.score >= min_score.max(1))
            .map(Target::from_sni),
        limit,
    )
}

pub fn ip_candidates(entries: &[IpProbeEntry], limit: usize) -> Vec<Target> {
    unique_targets(
        entries
            .iter()
            .filter(|e| e.tcp_latency_ms.is_some() && e.score > 0)
            .map(Target::from_ip),
        limit,
    )
}

fn unique_targets(targets: impl Iterator<Item = Target>, limit: usize) -> Vec<Target> {
    let mut seen = HashSet::new();
    targets
        .filter(|target| seen.insert(target.key()))
        .take(limit)
        .collect()
}

/// A missing scan measurement is unknown; a missing live measurement failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingSource {
    Scan,
    Live,
}

#[derive(Debug, Clone)]
pub struct TargetSnapshot {
    pub target: Target,
    /// One-based scan rank, or None when no longer in the selection pool.
    pub rank: Option<usize>,
    pub ping: Option<Duration>,
    pub ping_source: PingSource,
    pub active_connections: usize,
    pub c2s_bytes: u64,
    pub s2c_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct TargetPoolSnapshot {
    pub strategy: SelectionStrategy,
    /// Current members in rank order, followed by history in first-seen order.
    pub targets: Vec<TargetSnapshot>,
}

#[derive(Debug, Default)]
pub(crate) struct TargetTraffic {
    pub c2s: AtomicU64,
    pub s2c: AtomicU64,
}

#[derive(Debug, Clone)]
struct Member {
    target: Target,
    ping: Option<Duration>,
    load: Arc<AtomicUsize>,
    traffic: Arc<TargetTraffic>,
    ping_source: PingSource,
}

#[derive(Debug)]
struct PoolState {
    members: Vec<Member>,
    history: Vec<Member>,
    history_indices: HashMap<TargetKey, usize>,
    cursor: usize,
    generation: u64,
    random: u64,
}

/// Clones share selection state. The pool is always nonempty.
#[derive(Debug, Clone)]
pub struct TargetPool {
    state: Arc<Mutex<PoolState>>,
    strategy: SelectionStrategy,
}

/// Own this for the whole worker future, including connect and bypass setup.
pub struct TargetLease {
    pub target: Target,
    load: Arc<AtomicUsize>,
    pub(crate) traffic: Arc<TargetTraffic>,
}

impl Drop for TargetLease {
    fn drop(&mut self) {
        self.load.fetch_sub(1, Ordering::Relaxed);
    }
}

impl TargetPool {
    pub fn new(strategy: SelectionStrategy, targets: Vec<Target>) -> anyhow::Result<Self> {
        anyhow::ensure!(!targets.is_empty(), "no valid relay targets found");
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let pool = Self {
            strategy,
            state: Arc::new(Mutex::new(PoolState {
                members: Vec::new(),
                history: Vec::new(),
                history_indices: HashMap::new(),
                cursor: 0,
                generation: 0,
                random: seed,
            })),
        };
        pool.replace(targets);
        Ok(pool)
    }

    pub fn single(target: Target) -> Self {
        Self::new(SelectionStrategy::RoundRobin, vec![target]).expect("one target")
    }

    pub fn len(&self) -> usize {
        self.state.lock().members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.state.lock().members.is_empty()
    }
    pub fn representative(&self) -> Target {
        self.state.lock().members[0].target.clone()
    }

    pub fn active_connections(&self) -> usize {
        self.state
            .lock()
            .history
            .iter()
            .map(|member| member.load.load(Ordering::Relaxed))
            .sum()
    }

    /// Session counters survive rescans and worker cancellation. Atomics are
    /// sampled without stopping relays; no network IO or selection takes place.
    pub fn snapshot(&self) -> TargetPoolSnapshot {
        let state = self.state.lock();
        let current: HashSet<_> = state.members.iter().map(|m| m.target.key()).collect();
        let sample = |member: &Member, rank| TargetSnapshot {
            target: member.target.clone(),
            rank,
            ping: member.ping,
            ping_source: member.ping_source,
            active_connections: member.load.load(Ordering::Relaxed),
            c2s_bytes: member.traffic.c2s.load(Ordering::Relaxed),
            s2c_bytes: member.traffic.s2c.load(Ordering::Relaxed),
        };
        let targets = state
            .members
            .iter()
            .enumerate()
            .map(|(i, member)| sample(member, Some(i + 1)))
            .chain(
                state
                    .history
                    .iter()
                    .filter(|m| !current.contains(&m.target.key()))
                    .map(|member| sample(member, None)),
            )
            .collect();
        TargetPoolSnapshot {
            strategy: self.strategy,
            targets,
        }
    }

    /// Preserve counters even when an address is removed and re-added while a
    /// worker still owns it. A failed scan cannot clear the live pool.
    pub fn replace(&self, targets: Vec<Target>) -> bool {
        if targets.is_empty() {
            return false;
        }
        let mut state = self.state.lock();
        let targets = unique_targets(targets.into_iter(), usize::MAX);
        let changed = state
            .members
            .iter()
            .map(|m| m.target.key())
            .collect::<Vec<_>>()
            != targets.iter().map(Target::key).collect::<Vec<_>>();
        state.members = targets
            .into_iter()
            .map(|target| {
                let key = target.key();
                let previous = state.history_indices.get(&key).copied();
                let member = Member {
                    ping: target.tcp_latency,
                    ping_source: PingSource::Scan,
                    target,
                    load: previous
                        .map(|i| state.history[i].load.clone())
                        .unwrap_or_default(),
                    traffic: previous
                        .map(|i| state.history[i].traffic.clone())
                        .unwrap_or_default(),
                };
                if let Some(i) = previous {
                    state.history[i] = member.clone();
                } else {
                    let i = state.history.len();
                    state.history_indices.insert(key, i);
                    state.history.push(member.clone());
                }
                member
            })
            .collect();
        state.cursor = 0;
        state.generation = state.generation.wrapping_add(1);
        changed
    }

    pub fn acquire(&self) -> TargetLease {
        let mut state = self.state.lock();
        let count = state.members.len();
        let round_robin = state.cursor % count;
        let index = match self.strategy {
            SelectionStrategy::RoundRobin => round_robin,
            SelectionStrategy::Random => random_index(&mut state.random, count),
            SelectionStrategy::LeastPing => state
                .members
                .iter()
                .enumerate()
                .filter_map(|(i, member)| member.ping.map(|ping| (i, ping)))
                .min_by_key(|(_, ping)| *ping)
                .map(|(i, _)| i)
                .unwrap_or(round_robin),
            SelectionStrategy::LeastLoad => (0..count)
                .map(|offset| (round_robin + offset) % count)
                .min_by_key(|i| state.members[*i].load.load(Ordering::Relaxed))
                .unwrap(),
        };
        state.cursor = (index + 1) % count;
        let member = &state.members[index];
        member.load.fetch_add(1, Ordering::Relaxed);
        TargetLease {
            target: member.target.clone(),
            load: member.load.clone(),
            traffic: member.traffic.clone(),
        }
    }

    pub fn probe_snapshot(&self) -> (u64, Vec<Target>) {
        let state = self.state.lock();
        (
            state.generation,
            state
                .members
                .iter()
                .map(|member| member.target.clone())
                .collect(),
        )
    }

    pub fn update_ping(&self, generation: u64, target: &Target, ping: Option<Duration>) {
        let mut state = self.state.lock();
        if state.generation == generation {
            if let Some(member) = state
                .members
                .iter_mut()
                .find(|m| m.target.key() == target.key())
            {
                member.ping = ping;
                member.ping_source = PingSource::Live;
                let i = state.history_indices[&target.key()];
                state.history[i].ping = ping;
                state.history[i].ping_source = PingSource::Live;
            }
        }
    }
}

// SplitMix64 with rejection sampling avoids modulo bias without a new dependency.
fn random_index(state: &mut u64, count: usize) -> usize {
    let bound = count as u64;
    let threshold = bound.wrapping_neg() % bound;
    loop {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        if z >= threshold {
            return (z % bound) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_preserve_identity_traffic_and_history_across_replacement() {
        let ip = std::net::Ipv4Addr::new(192, 0, 2, 1);
        let first = Target::sni("first.example", ip, 90);
        let second = Target::sni("second.example", ip, 80);
        let pool = TargetPool::new(
            SelectionStrategy::RoundRobin,
            vec![first.clone(), second.clone()],
        )
        .unwrap();
        let a = pool.acquire();
        let b = pool.acquire();
        a.traffic.c2s.fetch_add(100, Ordering::Relaxed);
        b.traffic.s2c.fetch_add(200, Ordering::Relaxed);
        pool.replace(vec![second]);
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.strategy, SelectionStrategy::RoundRobin);
        assert_eq!(
            snapshot.targets[0].target.sni.as_deref(),
            Some("second.example")
        );
        assert_eq!(snapshot.targets[0].rank, Some(1));
        assert_eq!(snapshot.targets[0].s2c_bytes, 200);
        assert_eq!(snapshot.targets[1].rank, None);
        assert_eq!(snapshot.targets[1].active_connections, 1);
        assert_eq!(snapshot.targets[1].c2s_bytes, 100);
        drop((a, b));
        assert_eq!(pool.snapshot().targets[1].active_connections, 0);
        pool.replace(vec![first]);
        let a = pool.acquire();
        a.traffic.c2s.fetch_add(50, Ordering::Relaxed);
        assert_eq!(pool.snapshot().targets[0].c2s_bytes, 150);
        assert_eq!(pool.active_connections(), 1);
    }

    #[test]
    fn snapshots_distinguish_scan_unknown_and_failed_live_ping() {
        let pool = TargetPool::single(target(1, 12));
        let initial = pool.snapshot();
        assert_eq!(initial.targets[0].ping_source, PingSource::Scan);
        assert_eq!(initial.targets[0].ping, Some(Duration::from_millis(12)));
        let (generation, targets) = pool.probe_snapshot();
        pool.update_ping(generation, &targets[0], None);
        let failed = pool.snapshot();
        assert_eq!(failed.targets[0].ping_source, PingSource::Live);
        assert_eq!(failed.targets[0].ping, None);
        assert_eq!(failed.targets[0].rank, Some(1));
        pool.replace(vec![Target::ip(targets[0].ip, 80)]);
        pool.update_ping(generation, &targets[0], Some(Duration::ZERO));
        assert_eq!(pool.snapshot().targets[0].ping_source, PingSource::Scan);
        assert_eq!(pool.snapshot().targets[0].ping, None);
    }

    #[test]
    fn random_choice_is_reproducible_and_spreads_across_members() {
        let pool = TargetPool::new(
            SelectionStrategy::Random,
            (1..=4).map(|n| target(n, 10)).collect(),
        )
        .unwrap();
        pool.state.lock().random = 42;
        let mut counts = [0; 4];
        let mut repeated = false;
        let mut last = None;
        for _ in 0..10_000 {
            let ip = pool.acquire().target.ip;
            repeated |= last == Some(ip);
            last = Some(ip);
            let IpAddr::V4(ip) = ip else {
                panic!("IPv4 fixture");
            };
            counts[usize::from(ip.octets()[3] - 1)] += 1;
        }
        assert!(repeated, "random must not silently become round robin");
        assert!(
            counts.iter().all(|count| (2000..3000).contains(count)),
            "{counts:?}"
        );
        assert_eq!(pool.active_connections(), 0);
    }

    #[test]
    fn least_load_is_balanced_for_concurrent_reservations() {
        let pool = TargetPool::new(
            SelectionStrategy::LeastLoad,
            vec![target(1, 10), target(2, 20)],
        )
        .unwrap();
        let workers: Vec<_> = (0..24)
            .map(|_| {
                let pool = pool.clone();
                std::thread::spawn(move || pool.acquire())
            })
            .collect();
        let leases: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(
            leases
                .iter()
                .filter(|lease| lease.target.ip == target(1, 0).ip)
                .count(),
            12
        );
        assert_eq!(pool.active_connections(), 24);
        drop(leases);
        assert_eq!(pool.active_connections(), 0);
    }

    #[test]
    fn acquired_sni_and_ttl_survive_metadata_refresh() {
        let mut before = Target::sni("old.example", std::net::Ipv4Addr::new(192, 0, 2, 1), 90);
        before.low_ttl = Some(5);
        let pool = TargetPool::single(before);
        let lease = pool.acquire();
        let mut after = Target::sni("new.example", std::net::Ipv4Addr::new(192, 0, 2, 2), 95);
        after.low_ttl = Some(9);
        pool.replace(vec![after]);
        assert_eq!(lease.target.sni.as_deref(), Some("old.example"));
        assert_eq!(lease.target.low_ttl, Some(5));
        let fresh = pool.acquire();
        assert_eq!(fresh.target.sni.as_deref(), Some("new.example"));
        assert_eq!(fresh.target.low_ttl, Some(9));
    }

    #[test]
    fn candidate_filter_keeps_unique_valid_ranked_pairs_and_score_floor() {
        let fixture = |name: &str, n: u8, score: u8, ping: Option<u64>| SniProbeEntry {
            sni: name.into(),
            ip: std::net::Ipv4Addr::new(192, 0, 2, n),
            score,
            tcp_latency_ms: ping,
            tls_ok: false,
            tls_latency_ms: None,
            cert_valid: false,
            ttfb_ms: None,
            download_bps: None,
            upload_bps: None,
            http_status: None,
        };
        let entries = vec![
            fixture("dead.example", 1, 100, None),
            fixture("a.example", 2, 90, Some(10)),
            fixture("a.example", 2, 90, Some(10)),
            fixture("a.example", 3, 80, Some(20)),
            fixture("b.example", 2, 70, Some(30)),
            fixture("zero.example", 4, 0, Some(10)),
        ];
        let selected = sni_candidates(&entries, 2, 1);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].ip, target(2, 0).ip);
        assert_eq!(selected[1].ip, target(3, 0).ip);
        assert_eq!(sni_candidates(&entries, 10, 85).len(), 1);
        assert_eq!(sni_candidates(&entries, 10, 1).len(), 3);
        let ips: Vec<_> = entries
            .iter()
            .map(|entry| IpProbeEntry {
                ip: entry.ip.into(),
                tcp_latency_ms: entry.tcp_latency_ms,
                score: entry.score,
                tls_ok: false,
                tls_latency_ms: None,
                cert_valid: false,
                ttfb_ms: None,
                download_bps: None,
                upload_bps: None,
                http_status: None,
            })
            .collect();
        assert_eq!(ip_candidates(&ips, 10).len(), 2);
        assert!(sni_candidates(&[], 10, 1).is_empty());
        assert!(TargetPool::new(SelectionStrategy::RoundRobin, vec![]).is_err());
    }

    fn target(n: u8, ping: u64) -> Target {
        Target {
            ip: std::net::Ipv4Addr::new(192, 0, 2, n).into(),
            sni: None,
            score: 100 - n,
            tcp_latency: Some(std::time::Duration::from_millis(ping)),
            low_ttl: None,
        }
    }

    #[test]
    fn round_robin_wraps_in_rank_order() {
        let pool = TargetPool::new(
            SelectionStrategy::RoundRobin,
            vec![target(1, 30), target(2, 10)],
        )
        .unwrap();
        let selected: Vec<_> = (0..5).map(|_| pool.acquire().target.ip).collect();
        assert_eq!(
            selected,
            vec![
                target(1, 0).ip,
                target(2, 0).ip,
                target(1, 0).ip,
                target(2, 0).ip,
                target(1, 0).ip
            ]
        );
    }

    #[test]
    fn least_load_reserves_before_connect_and_releases_on_drop() {
        let pool = TargetPool::new(
            SelectionStrategy::LeastLoad,
            vec![target(1, 30), target(2, 10)],
        )
        .unwrap();
        let first = pool.acquire();
        let second = pool.acquire();
        assert_ne!(first.target.ip, second.target.ip);
        let third = pool.acquire();
        assert_eq!(third.target.ip, first.target.ip);
        drop(second);
        assert_eq!(pool.acquire().target.ip, target(2, 0).ip);
        drop(first);
        drop(third);
        assert_eq!(pool.active_connections(), 0);
    }

    #[test]
    fn replacement_preserves_live_and_retired_load() {
        let pool = TargetPool::new(
            SelectionStrategy::LeastLoad,
            vec![target(1, 30), target(2, 10)],
        )
        .unwrap();
        let held = pool.acquire();
        pool.replace(vec![target(1, 20), target(3, 10)]);
        assert_eq!(pool.acquire().target.ip, target(3, 0).ip);
        pool.replace(vec![target(2, 10)]);
        pool.replace(vec![target(1, 20), target(2, 10)]);
        assert_eq!(pool.acquire().target.ip, target(2, 0).ip);
        drop(held);
        assert_eq!(pool.active_connections(), 0);
        assert!(!pool.replace(vec![]));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn least_ping_uses_fresh_results_and_ignores_old_generations() {
        let pool = TargetPool::new(
            SelectionStrategy::LeastPing,
            vec![target(1, 30), target(2, 10)],
        )
        .unwrap();
        assert_eq!(pool.acquire().target.ip, target(2, 0).ip);
        let (generation, _) = pool.probe_snapshot();
        pool.update_ping(generation, &target(2, 0), None);
        assert_eq!(pool.acquire().target.ip, target(1, 0).ip);
        pool.replace(vec![target(1, 30), target(2, 10)]);
        pool.update_ping(generation, &target(1, 0), Some(std::time::Duration::ZERO));
        assert_eq!(pool.acquire().target.ip, target(2, 0).ip);
        let (generation, _) = pool.probe_snapshot();
        for n in [1, 2] {
            pool.update_ping(generation, &target(n, 0), None);
        }
        assert_ne!(pool.acquire().target.ip, pool.acquire().target.ip);
    }
}
