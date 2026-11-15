//! Ownership and in-place rebuild of the live packet-interception plane.

use std::future::Future;
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
use zerodpi_core::net::InterfaceBinding;
use zerodpi_core::proxy::CONNECT_PORT;
use zerodpi_platform::DefaultInterceptor;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A live data plane that can be rebuilt for a new interface address.
pub trait DataPlane: Send + Sync {
    fn rebuild<'a>(&'a self, binding: InterfaceBinding) -> BoxFuture<'a, Result<()>>;
    fn stop<'a>(&'a self) -> BoxFuture<'a, Result<()>>;
    /// Close interception before loading a new configuration.
    fn close_for_reload<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
        self.stop()
    }
}

const INTERCEPTOR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the local filter used by every intercept mode.
pub fn interceptor_filter(cfg: &Config, binding: &InterfaceBinding) -> FilterSpec {
    FilterSpec {
        interface_ip: binding.ip,
        remote_ip: None,
        remote_port: CONNECT_PORT,
        queue_num: cfg.NFQUEUE_NUM,
        linux_firewall_backend: cfg.linux_firewall_backend(),
    }
}

enum Inner {
    Local(LocalPlane),
    None,
}

struct LocalPlane {
    cfg: Arc<Config>,
    flows: FlowTable,
    flow_controller: Arc<dyn FlowController>,
    method: Arc<dyn BypassMethod>,
    shutdown: Option<InterceptorShutdown>,
    done_rx: Option<oneshot::Receiver<Result<()>>>,
    stop_report: Option<tokio::sync::mpsc::UnboundedReceiver<Result<()>>>,
    /// True while an interceptor may still be live. Cleared only after a
    /// confirmed shutdown, so a failed stop can never reopen over live rules.
    armed: bool,
}

/// Owns the live interceptor and rebuilds it for a new address.
pub struct DataPlaneController {
    inner: Mutex<Inner>,
}

impl DataPlaneController {
    /// Open a local interceptor immediately.
    pub fn local(
        cfg: Arc<Config>,
        flows: FlowTable,
        method: Arc<dyn BypassMethod>,
        binding: InterfaceBinding,
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
            stop_report: None,
            armed: false,
        };
        plane.open(binding)?;
        Ok(Self {
            inner: Mutex::new(Inner::Local(plane)),
        })
    }

    /// A plane for modes without interception (`ip_bypass`, socket-only).
    pub fn none() -> Self {
        Self {
            inner: Mutex::new(Inner::None),
        }
    }
}

impl DataPlane for DataPlaneController {
    fn close_for_reload<'a>(&'a self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut inner = self.inner.lock().await;
            match &mut *inner {
                Inner::Local(plane) => stop_local(plane).await,
                Inner::None => Ok(()),
            }
        })
    }
    fn rebuild<'a>(&'a self, binding: InterfaceBinding) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut inner = self.inner.lock().await;
            match &mut *inner {
                Inner::Local(plane) => {
                    stop_local(plane).await?;
                    plane.flow_controller.reset();
                    plane.open(binding)?;
                    Ok(())
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
                Inner::None => Ok(()),
            }
        })
    }
}

impl LocalPlane {
    fn open(&mut self, binding: InterfaceBinding) -> Result<()> {
        let filter = interceptor_filter(&self.cfg, &binding);
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
        info!(interface_ip = %binding.ip, interface_name = %binding.if_name, "packet interceptor open");
        Ok(())
    }
}

async fn stop_local(plane: &mut LocalPlane) -> Result<()> {
    if !plane.armed {
        return Ok(());
    }
    if plane.stop_report.is_none() {
        let shutdown = plane.shutdown.take().context(
            "packet interceptor stop did not complete; refusing to reopen over live firewall rules",
        )?;
        shutdown.request();
        let done_rx = plane.done_rx.take().context(
            "packet interceptor stop did not complete; refusing to reopen over live firewall rules",
        )?;
        plane.stop_report = Some(spawn_interceptor_report(done_rx));
    }
    wait_for_interceptor_shutdown(plane.stop_report.as_mut().unwrap()).await?;
    plane.stop_report = None;
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn interceptor_filter_matches_the_legacy_shape() {
        let cfg = Arc::new(crate::config_for_tests());
        let binding = InterfaceBinding::fixed(Ipv4Addr::new(10, 0, 0, 5));
        let filter = interceptor_filter(&cfg, &binding);
        assert_eq!(filter.interface_ip, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(filter.remote_ip, None);
        assert_eq!(filter.remote_port, zerodpi_core::proxy::CONNECT_PORT);
        assert_eq!(filter.queue_num, cfg.NFQUEUE_NUM);
    }

    #[tokio::test]
    async fn none_plane_rebuild_and_stop_are_noops() {
        let plane = DataPlaneController::none();
        plane
            .rebuild(InterfaceBinding::fixed(Ipv4Addr::LOCALHOST))
            .await
            .unwrap();
        plane.stop().await.unwrap();
        plane.close_for_reload().await.unwrap();
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
            stop_report: None,
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

    #[tokio::test(start_paused = true)]
    async fn delayed_stop_can_be_confirmed_on_retry_without_reopening() {
        let mut plane = local_plane_with_missing_handles();
        let (done_tx, done_rx) = oneshot::channel();
        let shutdown = InterceptorShutdown::default();
        plane.shutdown = Some(shutdown.clone());
        plane.done_rx = Some(done_rx);
        assert!(stop_local(&mut plane).await.is_err());
        assert!(shutdown.is_requested());
        assert!(plane.armed);
        done_tx.send(Ok(())).unwrap();
        stop_local(&mut plane).await.unwrap();
        assert!(!plane.armed);
        stop_local(&mut plane).await.unwrap();
    }
}
