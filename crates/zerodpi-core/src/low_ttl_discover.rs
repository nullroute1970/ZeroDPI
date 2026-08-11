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
/// For each candidate TTL, `set_ttl` is invoked *before* the probe so the
/// running interceptor stamps that value on the decoy; it returns `false`
/// when the value could not be applied (the probe is then treated as failed).
/// Returns the discovered TTL, or `None` if no candidate worked (the caller
/// should keep `LOW_TTL_VALUE`).
pub async fn discover_low_ttl<F, Fut>(
    discovery: LowTtlDiscovery,
    sni: &str,
    connect_ip: Ipv4Addr,
    interface_ip: Ipv4Addr,
    flow_controller: Arc<dyn FlowController>,
    connector: TlsConnector,
    set_ttl: F,
) -> Option<u8>
where
    F: Fn(u8) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
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
        let apply = set_ttl.clone();
        let fake_data = fake_data.clone();
        let server_name = server_name.clone();
        let flow_controller = flow_controller.clone();
        let connector = connector.clone();
        async move {
            if !apply(ttl).await {
                return false;
            }
            probe_ttl(
                fake_data,
                &server_name,
                connect_ip,
                interface_ip,
                &flow_controller,
                &connector,
                timeout,
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

/// One full bypass + handshake probe at a fixed TTL.
///
/// Mirrors the proxy's `handle_intercept_connection` socket pattern: bind on
/// the interface IP with a kernel-chosen port, register the flow, connect,
/// wait for the decoy bypass to complete, then run a rustls handshake.
async fn probe_ttl(
    fake_data: Vec<u8>,
    server_name: &ServerName<'static>,
    connect_ip: Ipv4Addr,
    interface_ip: Ipv4Addr,
    flow_controller: &Arc<dyn FlowController>,
    connector: &TlsConnector,
    timeout: Duration,
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
    let entry = match flow_controller.register_flow(key, fake_data).await {
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
    use super::*;

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
