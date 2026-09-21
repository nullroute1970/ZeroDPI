//! Ownership and in-place rebuild of the live packet-interception plane.

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{oneshot, Mutex};
use tracing::{error, info};

use zerodpi_core::config::Config;
use zerodpi_core::flow::{FlowController, FlowTable, LocalFlowController};
use zerodpi_core::handler::Handler;
use zerodpi_core::interceptor::{FilterSpec, InterceptorShutdown, PacketInterceptor};
use zerodpi_core::methods::BypassMethod;
use zerodpi_core::proxy::CONNECT_PORT;
use zerodpi_platform::DefaultInterceptor;

use crate::helper_client::{interceptor_config, RemoteHelperClient};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A live data plane that can be rebuilt for a new interface address.
pub trait DataPlane: Send + Sync {
    fn rebuild<'a>(&'a self, interface_ip: Ipv4Addr) -> BoxFuture<'a, Result<()>>;
    fn stop<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
    /// True when the remote root helper is gone and no rebuild can succeed.
    fn remote_disconnected(&self) -> bool {
        false
    }
    /// Resolves with a fatal reason when the plane can never recover.
    /// Default planes wait forever.
    fn wait_fatal(&self) -> BoxFuture<'static, String> {
        Box::pin(std::future::pending::<String>())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
const INTERCEPTOR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the local filter used by every intercept mode.
pub fn interceptor_filter(cfg: &Config, interface_ip: Ipv4Addr) -> FilterSpec {
    FilterSpec {
        interface_ip,
        remote_ip: None,
        remote_port: CONNECT_PORT,
        queue_num: cfg.NFQUEUE_NUM,
        linux_firewall_backend: cfg.linux_firewall_backend(),
        firewall_owner: None,
    }
}

enum Inner {
    Local(LocalPlane),
    Remote(RemotePlane),
    None,
}

struct LocalPlane {
    cfg: Arc<Config>,
    flows: FlowTable,
    flow_controller: Arc<dyn FlowController>,
    method: Arc<dyn BypassMethod>,
    shutdown: Option<InterceptorShutdown>,
    done_rx: Option<oneshot::Receiver<Result<()>>>,
    /// True while an interceptor may still be live. Cleared only after a
    /// confirmed shutdown, so a failed stop can never reopen over live rules.
    armed: bool,
}

struct RemotePlane {
    cfg: Arc<Config>,
    helper: RemoteHelperClient,
    flow_controller: Arc<dyn FlowController>,
}

/// Owns the live interceptor and rebuilds it for a new address.
pub struct DataPlaneController {
    inner: Mutex<Inner>,
    remote_helper: Option<RemoteHelperClient>,
}

impl DataPlaneController {
    /// Open a local interceptor immediately.
    pub fn local(
        cfg: Arc<Config>,
        flows: FlowTable,
        method: Arc<dyn BypassMethod>,
        interface_ip: Ipv4Addr,
    ) -> Result<Self> {
        let flow_controller: Arc<dyn FlowController> =
            Arc::new(LocalFlowController::new(flows.clone()));
        let mut plane = LocalPlane {
            cfg,
            flows,
            flow_controller,
            method,
            shutdown: None,
            done_rx: None,
            armed: false,
        };
        plane.open(interface_ip)?;
        Ok(Self {
            inner: Mutex::new(Inner::Local(plane)),
            remote_helper: None,
        })
    }

    /// Configure and open the root-helper interceptor immediately.
    pub async fn remote(
        cfg: Arc<Config>,
        helper: RemoteHelperClient,
        flow_controller: Arc<dyn FlowController>,
        interface_ip: Ipv4Addr,
    ) -> Result<Self> {
        helper
            .configure(interceptor_config(&cfg, interface_ip, None, CONNECT_PORT))
            .await
            .context("configure root helper interceptor")?;
        helper
            .open()
            .await
            .context("open root helper interceptor")?;
        Ok(Self {
            inner: Mutex::new(Inner::Remote(RemotePlane {
                cfg,
                helper: helper.clone(),
                flow_controller,
            })),
            remote_helper: Some(helper),
        })
    }

    /// A plane for modes without interception (`ip_bypass`, socket-only).
    pub fn none() -> Self {
        Self {
            inner: Mutex::new(Inner::None),
            remote_helper: None,
        }
    }
}

impl DataPlane for DataPlaneController {
    fn rebuild<'a>(&'a self, interface_ip: Ipv4Addr) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut inner = self.inner.lock().await;
            match &mut *inner {
                Inner::Local(plane) => {
                    stop_local(plane).await?;
                    plane.flow_controller.reset();
                    plane.open(interface_ip)?;
                    Ok(())
                }
                Inner::Remote(plane) => {
                    plane
                        .helper
                        .close()
                        .await
                        .context("close root helper interceptor")?;
                    plane.flow_controller.reset();
                    plane
                        .helper
                        .configure(interceptor_config(
                            &plane.cfg,
                            interface_ip,
                            None,
                            CONNECT_PORT,
                        ))
                        .await
                        .context("reconfigure root helper interceptor")?;
                    plane
                        .helper
                        .open()
                        .await
                        .context("reopen root helper interceptor")
                }
                Inner::None => Ok(()),
            }
        })
    }

    fn stop<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut inner = self.inner.lock().await;
            match &mut *inner {
                Inner::Local(plane) => stop_local(plane).await,
                Inner::Remote(plane) => {
                    plane.helper.close().await?;
                    plane.helper.shutdown().await
                }
                Inner::None => Ok(()),
            }
        })
    }

    fn remote_disconnected(&self) -> bool {
        self.remote_helper
            .as_ref()
            .map(RemoteHelperClient::is_disconnected)
            .unwrap_or(false)
    }

    fn wait_fatal(&self) -> BoxFuture<'static, String> {
        match self.remote_helper.clone() {
            Some(helper) => Box::pin(async move {
                helper.wait_disconnected().await;
                "root helper disconnected while interception was active".to_owned()
            }),
            None => Box::pin(std::future::pending::<String>()),
        }
    }
}

impl LocalPlane {
    fn open(&mut self, interface_ip: Ipv4Addr) -> Result<()> {
        let filter = interceptor_filter(&self.cfg, interface_ip);
        let interceptor = DefaultInterceptor::open(filter).context("open packet interceptor")?;
        let handler = Handler::new(self.flows.clone(), self.method.clone());
        let (done_tx, done_rx) = oneshot::channel();
        let shutdown = InterceptorShutdown::default();
        let thread_shutdown = shutdown.clone();
        std::thread::Builder::new()
            .name("zerodpi-intercept".into())
            .spawn(move || {
                let result = interceptor.run_until(handler, thread_shutdown);
                if let Err(ref error) = result {
                    error!(%error, "intercept loop ended with error");
                }
                let _ = done_tx.send(result);
            })
            .context("spawn intercept thread")?;
        self.shutdown = Some(shutdown);
        self.done_rx = Some(done_rx);
        self.armed = true;
        info!(%interface_ip, "packet interceptor open");
        Ok(())
    }
}

async fn stop_local(plane: &mut LocalPlane) -> Result<()> {
    if !plane.armed {
        return Ok(());
    }
    let Some(shutdown) = plane.shutdown.take() else {
        anyhow::bail!(
            "packet interceptor stop did not complete; refusing to reopen over live firewall rules"
        );
    };
    shutdown.request();
    let Some(done_rx) = plane.done_rx.take() else {
        anyhow::bail!(
            "packet interceptor stop did not complete; refusing to reopen over live firewall rules"
        );
    };
    let mut report_rx = spawn_interceptor_report(done_rx);
    wait_for_interceptor_shutdown(&mut report_rx).await?;
    plane.armed = false;
    Ok(())
}

fn spawn_interceptor_report(
    done_rx: oneshot::Receiver<Result<()>>,
) -> tokio::sync::mpsc::UnboundedReceiver<Result<()>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let result = match done_rx.await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "packet interceptor thread stopped before reporting a result"
            )),
        };
        let _ = tx.send(result);
    });
    rx
}

#[cfg(any(target_os = "linux", target_os = "android"))]
async fn wait_for_interceptor_shutdown(
    report_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Result<()>>,
) -> Result<()> {
    match tokio::time::timeout(INTERCEPTOR_SHUTDOWN_TIMEOUT, report_rx.recv()).await {
        Ok(Some(Ok(()))) => Ok(()),
        Ok(Some(Err(error))) => Err(error.context("packet interceptor stopped during shutdown")),
        Ok(None) => Err(anyhow::anyhow!(
            "packet interceptor thread stopped before reporting a result"
        )),
        Err(_) => Err(anyhow::anyhow!(
            "packet interceptor did not stop within {} seconds",
            INTERCEPTOR_SHUTDOWN_TIMEOUT.as_secs()
        )),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
async fn wait_for_interceptor_shutdown(
    report_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Result<()>>,
) -> Result<()> {
    let _ = tokio::time::timeout(Duration::from_millis(100), report_rx.recv()).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn interceptor_filter_matches_the_legacy_shape() {
        let cfg = Arc::new(crate::config_for_tests());
        let filter = interceptor_filter(&cfg, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(filter.interface_ip, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(filter.remote_ip, None);
        assert_eq!(filter.remote_port, zerodpi_core::proxy::CONNECT_PORT);
        assert_eq!(filter.queue_num, cfg.NFQUEUE_NUM);
        assert_eq!(filter.firewall_owner, None);
    }

    #[tokio::test]
    async fn none_plane_rebuild_and_stop_are_noops() {
        let plane = DataPlaneController::none();
        plane.rebuild(Ipv4Addr::LOCALHOST).await.unwrap();
        plane.stop().await.unwrap();
        assert!(!plane.remote_disconnected());
    }
    fn local_plane_with_missing_handles() -> LocalPlane {
        let cfg = Arc::new(crate::config_for_tests());
        let flows = zerodpi_core::flow::new_flow_table();
        let flow_controller: Arc<dyn FlowController> =
            Arc::new(LocalFlowController::new(flows.clone()));
        let method: Arc<dyn BypassMethod> =
            Arc::from(zerodpi_core::methods::build_method(&cfg).expect("method"));
        LocalPlane {
            cfg,
            flows,
            flow_controller,
            method,
            shutdown: None,
            done_rx: None,
            armed: true,
        }
    }

    #[tokio::test]
    async fn stop_local_after_a_failed_shutdown_does_not_silently_succeed() {
        let mut plane = local_plane_with_missing_handles();
        let error = stop_local(&mut plane).await.unwrap_err();
        assert!(error.to_string().contains("did not complete"), "{error}");
        assert!(
            plane.armed,
            "a plane whose interceptor may still be live stays armed"
        );
    }
}
