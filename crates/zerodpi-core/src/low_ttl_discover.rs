//! Automatic `LOW_TTL_VALUE` discovery for the `low_ttl` bypass method.
//!
//! The decoy ClientHello trick only works while the stamped TTL falls inside
//! the window `[DPI hop distance, server hop distance − 1]`:
//!
//! - A TTL below the DPI's distance means the decoy expires before the DPI
//!   ever sees it, so the DPI inspects the real ClientHello and blocks the
//!   flow.
//! - A TTL at or above the server's distance means the decoy reaches the
//!   server, whose unexpected ServerHello desynchronizes the real handshake.
//! - Any TTL in between delivers the decoy to the DPI while it still expires
//!   before the server, so the real handshake completes.
//!
//! Discovery therefore probes TTL candidates upward from `1`, running the
//! full bypass machinery end-to-end per candidate, and picks the **largest
//! working value** (the server's hop distance minus one) because it reaches
//! any inline DPI middlebox with maximum margin. The search stops at the
//! first failure observed after at least one success.
//!
//! Probing never mutates the live `low_ttl` handle: each probe registers its
//! flow with the candidate TTL as a **per-flow override** carried in
//! `FlowState`, so user flows keep using the shared handle throughout.
//! `discover_low_ttl` therefore has no global side effect; the caller applies
//! the discovered value exactly once, immediately before any target switch.
//!
//! Every probe registers a real intercepted flow (decoy ClientHello carrying
//! the selected whitelisted SNI), connects to the target on the configured
//! interface IP, waits for the bypass to complete, then performs a full rustls
//! handshake to the target. The probe's real ClientHello also carries the
//! whitelisted SNI; the upper boundary is still detected reliably because a
//! server that already answered the decoy produces an out-of-order
//! ServerHello/Finished that rustls rejects.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use tracing::info;

use crate::config::Config;
use crate::flow::{FlowController, FlowEntry, FlowKey};
use crate::proxy::{fresh_fake_client_hello, CONNECT_PORT};

/// Per-candidate probe timeout.
#[derive(Debug, Clone, Copy)]
pub struct LowTtlDiscovery {
    /// Upper bound of the TTL search (inclusive).
    pub max_ttl: u8,
    /// Per-candidate connect/handshake timeout.
    pub probe_timeout: Duration,
}

impl LowTtlDiscovery {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            max_ttl: cfg.LOW_TTL_DISCOVER_MAX,
            probe_timeout: Duration::from_millis(cfg.LOW_TTL_DISCOVER_TIMEOUT_MS),
        }
    }
}

/// Scan TTL candidates from `1` up to `max`, returning the **largest** value
/// for which `probe` succeeds, or `None` if no candidate succeeds.
///
/// The scan stops at the first failure after at least one success: outside
/// pathological networks the working TTLs form one contiguous window
/// `[DPI distance, server distance − 1]`, so the first post-success failure
/// marks its upper boundary.
pub async fn scan_ttl<F, Fut>(max: u8, mut probe: F) -> Option<u8>
where
    F: FnMut(u8) -> Fut,
    Fut: Future<Output = bool>,
{
    let mut last_success = None;
    let mut any_success = false;
    for ttl in 1..=max {
        if probe(ttl).await {
            last_success = Some(ttl);
            any_success = true;
        } else if any_success {
            break;
        }
    }
    last_success
}

/// Run `LOW_TTL_DISCOVER` against one target.
///
/// Each probe registers its flow with the candidate TTL as a per-flow
/// override, so the running interceptor stamps that value on the decoy while
/// the live handle stays untouched. A probe whose 4-tuple already belongs to
/// another flow (live user flow or an earlier probe) is treated as failed.
/// Returns the discovered TTL, or `None` if no candidate worked (the caller
/// should keep `LOW_TTL_VALUE` and the current target).
pub async fn discover_low_ttl(
    discovery: LowTtlDiscovery,
    sni: &str,
    connect_ip: Ipv4Addr,
    interface_ip: Ipv4Addr,
    flow_controller: Arc<dyn FlowController>,
    connector: TlsConnector,
) -> Option<u8> {
    let server_name = match ServerName::try_from(sni.to_owned()) {
        Ok(name) => name,
        Err(_) => {
            info!(sni, "LOW_TTL_DISCOVER skipped: invalid SNI");
            return None;
        }
    };
    let fake_data = fresh_fake_client_hello(sni.as_bytes());
    let timeout = discovery.probe_timeout;

    let found = scan_ttl(discovery.max_ttl, |ttl| {
        let fake_data = fake_data.clone();
        let server_name = server_name.clone();
        let flow_controller = flow_controller.clone();
        let connector = connector.clone();
        async move {
            probe_ttl(
                fake_data,
                &server_name,
                connect_ip,
                interface_ip,
                &flow_controller,
                &connector,
                timeout,
                ttl,
            )
            .await
        }
    })
    .await;

    if let Some(ttl) = found {
        info!(
            ttl,
            sni, "LOW_TTL_DISCOVER: discovered working low_ttl value"
        );
    } else {
        info!(
            sni,
            "LOW_TTL_DISCOVER: no working TTL found; keeping LOW_TTL_VALUE"
        );
    }
    found
}

/// Register a probe flow, refusing to clobber a flow that already owns the
/// 4-tuple: a live user flow locally, or any flow remotely (the root helper
/// rejects duplicate flow keys with `HelperFatal`). `low_ttl_override` is
/// the candidate TTL, so the interceptor stamps it without touching the
/// shared live handle.
async fn register_probe_flow(
    flow_controller: &dyn FlowController,
    key: FlowKey,
    fake_data: Vec<u8>,
    low_ttl_override: Option<u8>,
) -> anyhow::Result<Arc<FlowEntry>> {
    if flow_controller.flow_exists(key) {
        return Err(anyhow::anyhow!("flow key already registered"));
    }
    flow_controller
        .register_flow(key, fake_data, low_ttl_override)
        .await
}

/// One full bypass + handshake probe at a fixed TTL.
///
/// Mirrors the proxy's `handle_intercept_connection` socket pattern: bind on
/// the interface IP with a kernel-chosen port, register the flow, connect,
/// wait for the decoy bypass to complete, then run a rustls handshake.
#[allow(clippy::too_many_arguments)]
async fn probe_ttl(
    fake_data: Vec<u8>,
    server_name: &ServerName<'static>,
    connect_ip: Ipv4Addr,
    interface_ip: Ipv4Addr,
    flow_controller: &Arc<dyn FlowController>,
    connector: &TlsConnector,
    timeout: Duration,
    candidate_ttl: u8,
) -> bool {
    let socket = match TcpSocket::new_v4() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let bind_addr = SocketAddr::from((interface_ip, 0));
    if socket.bind(bind_addr).is_err() {
        return false;
    }
    let local = match socket.local_addr() {
        Ok(addr) => addr,
        Err(_) => return false,
    };
    let src_port = local.port();
    let key = FlowKey {
        src_ip: interface_ip,
        src_port,
        dst_ip: connect_ip,
        dst_port: CONNECT_PORT,
    };
    let entry = match register_probe_flow(
        flow_controller.as_ref(),
        key,
        fake_data,
        Some(candidate_ttl),
    )
    .await
    {
        Ok(entry) => entry,
        Err(_) => return false,
    };

    let connect_addr = SocketAddr::from((connect_ip, CONNECT_PORT));
    let outgoing = match tokio::time::timeout(timeout, socket.connect(connect_addr)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            flow_controller.remove_flow(key);
            return false;
        }
    };

    if !wait_for_bypass_progress(&entry, timeout).await {
        flow_controller.remove_flow(key);
        return false;
    }

    let ok = tls_handshake_ok(connector, server_name, outgoing, timeout).await;
    flow_controller.remove_flow(key);
    ok
}

/// Whether the interceptor has either completed the decoy bypass or deferred
/// to a first data packet. The flow-state lock is confined to this helper so
/// the awaiting future stays `Send`.
fn bypass_progress(entry: &FlowEntry) -> bool {
    let state = entry.state.lock();
    state.outcome.is_some() || state.waiting_for_data
}

/// Wait until [`bypass_progress`] holds, for at most `timeout`.
async fn wait_for_bypass_progress(entry: &FlowEntry, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, async {
        loop {
            if bypass_progress(entry) {
                return;
            }
            tokio::select! {
                _ = entry.notify.notified() => {}
                _ = entry.ready_for_data.notified() => {}
            }
        }
    })
    .await
    .is_ok()
}

/// Complete a rustls handshake (with server certificate validation) within
/// `timeout`. Returns `true` only on a cleanly completed handshake.
async fn tls_handshake_ok(
    connector: &TlsConnector,
    server_name: &ServerName<'static>,
    stream: TcpStream,
    timeout: Duration,
) -> bool {
    matches!(
        tokio::time::timeout(timeout, connector.connect(server_name.clone(), stream)).await,
        Ok(Ok(_))
    )
}

/// Build the TLS connector used by discovery probes (webpki roots, no client
/// auth), mirroring the scanner's connector.
pub fn make_discovery_tls_connector() -> TlsConnector {
    let root_store = {
        let mut store = tokio_rustls::rustls::RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    };
    let tls_config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(tls_config))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::flow::FlowRegistrationFuture;

    /// Records every `register_flow` call and can force `flow_exists` to
    /// report a collision.
    struct RecordingController {
        registrations: Mutex<Vec<(FlowKey, Option<u8>)>>,
        existing: Mutex<bool>,
    }

    impl RecordingController {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                registrations: Mutex::new(Vec::new()),
                existing: Mutex::new(false),
            })
        }
    }

    impl FlowController for RecordingController {
        fn register_flow(
            &self,
            key: FlowKey,
            fake_data: Vec<u8>,
            low_ttl_override: Option<u8>,
        ) -> FlowRegistrationFuture<'_> {
            Box::pin(async move {
                self.registrations
                    .lock()
                    .unwrap()
                    .push((key, low_ttl_override));
                Ok(FlowEntry::new(fake_data, low_ttl_override))
            })
        }

        fn flow_exists(&self, _key: FlowKey) -> bool {
            *self.existing.lock().unwrap()
        }

        fn remove_flow(&self, _key: FlowKey) {}
    }

    fn probe_key() -> FlowKey {
        FlowKey {
            src_ip: Ipv4Addr::LOCALHOST,
            src_port: 1234,
            dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            dst_port: 443,
        }
    }

    #[tokio::test]
    async fn discover_registers_each_candidate_with_its_own_override() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let recording = RecordingController::new();
        let flow_controller: Arc<dyn FlowController> = recording.clone();
        let discovery = LowTtlDiscovery {
            max_ttl: 5,
            probe_timeout: Duration::from_millis(50),
        };
        // No real target behind the probe I/O, so every probe fails and the
        // scan walks all five candidates.
        let found = discover_low_ttl(
            discovery,
            "example.com",
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::LOCALHOST,
            flow_controller,
            make_discovery_tls_connector(),
        )
        .await;
        assert_eq!(found, None);

        let registrations = recording.registrations.lock().unwrap();
        assert_eq!(registrations.len(), 5);
        for (index, (key, override_ttl)) in registrations.iter().enumerate() {
            let expected = index as u8 + 1;
            assert_eq!(*override_ttl, Some(expected));
            assert_eq!(key.dst_ip, Ipv4Addr::new(1, 1, 1, 1));
            assert_eq!(key.dst_port, CONNECT_PORT);
        }
    }

    #[tokio::test]
    async fn probe_ttl_fails_on_key_collision_without_registering() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let recording = RecordingController::new();
        let flow_controller: Arc<dyn FlowController> = recording.clone();
        *recording.existing.lock().unwrap() = true;
        let server_name = ServerName::try_from("example.com").unwrap();
        let ok = probe_ttl(
            vec![1],
            &server_name,
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::LOCALHOST,
            &flow_controller,
            &make_discovery_tls_connector(),
            Duration::from_secs(1),
            5,
        )
        .await;
        assert!(!ok);
        assert!(recording.registrations.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn register_probe_flow_registers_when_key_is_free() {
        let recording = RecordingController::new();
        let entry = register_probe_flow(recording.as_ref(), probe_key(), vec![1], Some(3))
            .await
            .unwrap();
        assert_eq!(entry.state.lock().low_ttl_override, Some(3));
        let registrations = recording.registrations.lock().unwrap();
        assert_eq!(registrations.len(), 1);
        assert_eq!(registrations[0].0, probe_key());
        assert_eq!(registrations[0].1, Some(3));
    }

    #[tokio::test]
    async fn picks_last_success_in_contiguous_window() {
        // Fail below 4, succeed 4..=9, fail at 10 and beyond.
        let success_window = 4..=9;
        let found = scan_ttl(32, move |ttl| {
            let success_window = success_window.clone();
            async move { success_window.contains(&ttl) }
        })
        .await;
        assert_eq!(found, Some(9));
    }

    #[tokio::test]
    async fn returns_none_when_nothing_works() {
        let found = scan_ttl(32, |_| async move { false }).await;
        assert_eq!(found, None);
    }

    #[tokio::test]
    async fn returns_last_success_when_everything_works() {
        let found = scan_ttl(12, |_| async move { true }).await;
        assert_eq!(found, Some(12));
    }

    #[tokio::test]
    async fn stops_early_at_first_failure_after_success() {
        // Verify the loop does not probe beyond the boundary by counting calls.
        let mut calls = 0u8;
        let found = scan_ttl(32, |ttl| {
            calls += 1;
            async move { ttl <= 7 }
        })
        .await;
        assert_eq!(found, Some(7));
        assert_eq!(calls, 8);
    }

    #[tokio::test]
    async fn honors_max_bound() {
        let found = scan_ttl(5, |_| async move { true }).await;
        assert_eq!(found, Some(5));
    }
}
