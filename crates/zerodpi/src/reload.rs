//! Configuration reload and ownership of interactive service generations.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use zerodpi_core::config::Config;

use crate::data_plane::DataPlane;
use crate::helper_client::RemoteHelperClient;
use crate::runtime_events::RuntimeEventEmitter;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use zerodpi_core::proxy::{ProxyEvent, ProxyEventReceiver};
use zerodpi_core::target_pool::{Target, TargetPool};
use zerodpi_platform::netmon::NetworkMonitor;

pub struct ConfigSource {
    pub path: PathBuf,
    overrides: crate::Args,
}

impl ConfigSource {
    pub fn new(overrides: crate::Args) -> Result<Self> {
        let path = overrides.config.clone().unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("config.toml")))
                .unwrap_or_else(|| PathBuf::from("config.toml"))
        });
        let path = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()?.join(path)
        };
        Ok(Self { path, overrides })
    }

    pub fn load(&self) -> Result<Config> {
        let mut cfg = Config::from_file(&self.path)
            .with_context(|| format!("loading config from {}", self.path.display()))?;
        self.overrides.apply(&mut cfg);
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn relative_path(&self, value: &str) -> PathBuf {
        relative_path(&self.path, value)
    }
}

pub fn relative_path(config: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        config.parent().unwrap_or(Path::new(".")).join(path)
    }
}

pub fn same_config(first: &Config, second: &Config) -> Result<bool> {
    Ok(serde_json::to_value(first)? == serde_json::to_value(second)?)
}

pub fn is_proxy_mode(mode: &str) -> bool {
    matches!(mode, "sni_spoof" | "ip_bypass" | "ip_bypass_plus")
}

/// Rollback uses cached addresses, never a changed list file or fresh DNS.
pub fn restore_pool(cfg: &Config, targets: Vec<Target>) -> Result<TargetPool> {
    TargetPool::new(
        if cfg.LOAD_BALANCE_ENABLED {
            cfg.LOAD_BALANCE_STRATEGY
        } else {
            zerodpi_core::target_pool::SelectionStrategy::RoundRobin
        },
        targets,
    )
}

fn validate_reload(cfg: &Config, helper: Option<&RemoteHelperClient>) -> Result<()> {
    cfg.validate()?;
    anyhow::ensure!(
        is_proxy_mode(&cfg.MODE),
        "config reload supports only proxy MODE values: sni_spoof, ip_bypass, ip_bypass_plus"
    );
    let _: SocketAddr = format!("{}:{}", cfg.LISTEN_HOST, cfg.LISTEN_PORT)
        .parse()
        .context("invalid LISTEN_HOST/LISTEN_PORT")?;
    if let Some(ip) = &cfg.SELECTED_IP {
        let _: IpAddr = ip.parse().context("invalid SELECTED_IP")?;
    }
    if crate::requires_packet_interception(cfg) {
        if let Some(helper) = helper {
            anyhow::ensure!(!helper.is_disconnected(), "root helper is disconnected");
        } else {
            zerodpi_platform::ensure_packet_interception_access()?;
        }
        zerodpi_core::methods::build_method(cfg).context("unsupported BYPASS_METHOD")?;
    }
    Ok(())
}

/// The terminal and helper outlive individual service runtimes. Each mode owns
/// its own Runtime; returning from it drops and joins all its async workers
/// (including detached scanners, connection JoinSets, and ping monitors) before
/// `close_generation` closes the interceptor on the separate control runtime.
pub struct Session {
    source: ConfigSource,
    helper: Option<RemoteHelperClient>,
    terminal: Option<crate::tui::Term>,
    plane: Option<Arc<dyn DataPlane>>,
    monitor: Option<Arc<NetworkMonitor>>,
    pool: Option<TargetPool>,
    pending: Option<Arc<Config>>,
    pub restore_targets: Option<Vec<Target>>,
    pub notice: Option<String>,
    initial_events: Vec<ProxyEvent>,
    ready: bool,
    discovered_ttl: Option<u8>,
}

impl Session {
    pub(crate) fn new(source: ConfigSource, helper: Option<RemoteHelperClient>) -> Self {
        Self {
            source,
            helper,
            terminal: None,
            plane: None,
            monitor: None,
            pool: None,
            pending: None,
            restore_targets: None,
            notice: None,
            initial_events: Vec::new(),
            ready: false,
            discovered_ttl: None,
        }
    }

    pub fn terminal(&mut self) -> Result<&mut crate::tui::Term> {
        if self.terminal.is_none() {
            self.terminal = Some(crate::tui::enter_tui()?);
        }
        Ok(self.terminal.as_mut().unwrap())
    }

    pub fn own_plane(&mut self, plane: Arc<dyn DataPlane>) {
        self.plane = Some(plane);
    }

    pub fn own_monitor(&mut self, monitor: Arc<NetworkMonitor>) {
        self.monitor = Some(monitor);
    }

    pub fn own_pool(&mut self, pool: TargetPool) {
        self.pool = Some(pool);
    }

    fn close_generation(&mut self, control: &Runtime) -> Result<()> {
        if let Some(monitor) = self.monitor.take() {
            monitor.shutdown();
        }
        if let Some(plane) = &self.plane {
            // Retain ownership on failure: a retry may confirm a delayed stop,
            // but must never start another interceptor over unconfirmed rules.
            control.block_on(plane.close_for_reload())?;
        }
        self.plane = None;
        Ok(())
    }

    pub fn candidate(&self, active: Option<&Config>) -> Result<Option<Arc<Config>>> {
        let next = self.source.load()?;
        validate_reload(&next, self.helper.as_ref())?;
        if active
            .map(|cfg| same_config(cfg, &next))
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let list = match next.MODE.as_str() {
            "sni_spoof" if next.SELECTED_SNI.is_none() => Some(&next.SNI_LIST),
            "ip_bypass" | "ip_bypass_plus" if next.SELECTED_IP.is_none() => Some(&next.IP_LIST),
            _ => None,
        };
        if let Some(list) = list {
            let path = self.source.relative_path(list);
            std::fs::File::open(&path).with_context(|| format!("reading {}", path.display()))?;
        }
        Ok(Some(Arc::new(next)))
    }

    pub fn take_initial_events(&mut self) -> Vec<ProxyEvent> {
        std::mem::take(&mut self.initial_events)
    }

    pub fn remember_ttl(&mut self, value: Option<u8>) {
        self.discovered_ttl = value;
    }

    /// Binding happens inside the proxy task, so spawning it is not readiness.
    pub fn wait_listener(
        &mut self,
        rt: &Runtime,
        proxy: &mut JoinHandle<Result<()>>,
        rx: &mut ProxyEventReceiver,
    ) -> Result<()> {
        rt.block_on(async {
            loop {
                tokio::select! {
                    result = &mut *proxy => {
                        result.context("proxy task panicked")??;
                        anyhow::bail!("proxy stopped before its listener was ready");
                    }
                    event = rx.recv() => {
                        let Some(event) = event else {
                            // Sender drop and task completion can become ready
                            // together. Preserve the actual bind/startup error.
                            (&mut *proxy).await.context("proxy task panicked")??;
                            anyhow::bail!("proxy stopped before its listener was ready");
                        };
                        let listening = matches!(event, ProxyEvent::ListenerStarted { .. });
                        self.initial_events.push(event);
                        if listening { return Ok(()); }
                    }
                }
            }
        })?;
        self.ready = true;
        Ok(())
    }

    pub fn dashboard(
        &mut self,
        rx: &mut ProxyEventReceiver,
        info: &crate::tui::DashboardInfo,
        cfg: &Config,
        rescan: &mut crate::manual_rescan::Controller,
        pool: &TargetPool,
    ) -> Result<()> {
        self.own_pool(pool.clone());
        // Move the terminal out only for this call, avoiding two mutable borrows
        // of Session while keeping the same alternate screen across reloads.
        self.terminal()?;
        let mut terminal = self.terminal.take().unwrap();
        let result = (|| {
            terminal.clear()?;
            crate::tui::run_dashboard(&mut terminal, rx, info, cfg, rescan, pool, self)
        })();
        self.terminal = Some(terminal);
        match result? {
            crate::tui::DashboardExit::Quit => {}
            crate::tui::DashboardExit::Reload(next) => self.pending = Some(next),
        }
        Ok(())
    }

    fn retry_screen(&mut self, mut message: String) -> Result<Option<Arc<Config>>> {
        loop {
            if !crate::tui::run_reload_error(self.terminal()?, &message)? {
                return Ok(None);
            }
            match self.candidate(None) {
                Ok(next) => return Ok(next),
                Err(error) => message = format!("Service stopped. Config reload failed: {error:#}"),
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(terminal) = self.terminal.take() {
            let _ = crate::tui::leave_tui(terminal);
        }
    }
}

#[derive(Clone)]
struct Backup {
    config: Arc<Config>,
    targets: Vec<Target>,
}

pub fn run(
    source: ConfigSource,
    cfg: Arc<Config>,
    events: RuntimeEventEmitter,
    helper: Option<RemoteHelperClient>,
) -> Result<()> {
    let path = source.path.clone();
    let helper_for_generation = helper.clone();
    run_with(Session::new(source, helper), cfg, |cfg, session| {
        crate::run_config(
            cfg,
            path.clone(),
            false,
            events.clone(),
            helper_for_generation.clone(),
            Some(session),
        )
    })
}

fn run_with(
    mut session: Session,
    cfg: Arc<Config>,
    mut execute: impl FnMut(Arc<Config>, &mut Session) -> Result<()>,
) -> Result<()> {
    let control = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = run_loop(&mut session, &control, cfg, &mut execute);
    let close_result = session.close_generation(&control);
    let helper_result = match &session.helper {
        Some(helper) if !helper.is_disconnected() => control.block_on(helper.shutdown()),
        _ => Ok(()),
    };
    result.and(close_result).and(helper_result)
}

fn run_loop(
    session: &mut Session,
    control: &Runtime,
    mut cfg: Arc<Config>,
    execute: &mut impl FnMut(Arc<Config>, &mut Session) -> Result<()>,
) -> Result<()> {
    let mut last_good: Option<Backup> = None;
    let mut restoring = false;
    loop {
        session.pending = None;
        session.ready = false;
        session.pool = None;
        session.initial_events.clear();
        session.discovered_ttl = None;
        let result = execute(cfg.clone(), session);
        // execute has returned: its service Runtime has already been dropped
        // and joined. No previous worker can touch the helper after this point.
        if session.ready {
            let mut targets = session
                .pool
                .as_ref()
                .map(|p| p.probe_snapshot().1)
                .unwrap_or_default();
            if !cfg.LOAD_BALANCE_ENABLED {
                if let Some(target) = targets.first_mut() {
                    target.low_ttl = session.discovered_ttl.or(target.low_ttl);
                }
            }
            last_good = Some(Backup {
                config: cfg.clone(),
                targets,
            });
        }
        while let Err(error) = session.close_generation(control) {
            let message = format!("Service stopped; cleanup not confirmed: {error:#}. L retries cleanup before starting any service.");
            if !crate::tui::run_reload_error(session.terminal()?, &message)? {
                return Err(error);
            }
        }
        match result {
            Ok(()) => match session.pending.take() {
                Some(next) => {
                    cfg = next;
                    session.restore_targets = None;
                    session.notice = Some("Config reloaded successfully".into());
                    restoring = false;
                }
                None => return Ok(()),
            },
            Err(error) if session.ready || last_good.is_none() => return Err(error),
            Err(error) if !restoring => {
                let previous = last_good.as_ref().unwrap();
                cfg = previous.config.clone();
                session.restore_targets = Some(previous.targets.clone());
                session.notice = Some(format!(
                    "Previous configuration restored. Config reload failed: {error:#}"
                ));
                restoring = true;
            }
            Err(error) => {
                let message = format!(
                    "Service stopped. Restoring the previous configuration also failed: {error:#}"
                );
                match session.retry_screen(message)? {
                    Some(next) => {
                        cfg = next;
                        session.restore_targets = None;
                        session.notice = Some("Config reloaded successfully".into());
                        restoring = false;
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;

    fn session_fixture() -> (tempfile::TempDir, Session, Arc<Config>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "LISTEN_HOST='127.0.0.1'\nLISTEN_PORT=0\nMODE='ip_bypass'\nSELECTED_IP='192.0.2.1'\nBYPASS_METHOD='tls_frag'\n").unwrap();
        let source = ConfigSource::new(crate::Args::parse_from([
            "zerodpi",
            "--config",
            path.to_str().unwrap(),
        ]))
        .unwrap();
        let cfg = Arc::new(source.load().unwrap());
        (dir, Session::new(source, None), cfg)
    }

    fn spawn_proxy(
        rt: &Runtime,
        cfg: Arc<Config>,
        pool: TargetPool,
    ) -> (JoinHandle<Result<()>>, ProxyEventReceiver) {
        use zerodpi_core::flow::{new_flow_table, LocalFlowController};
        use zerodpi_core::net::{interface_binding_channel, InterfaceBinding, NoopSocketBinder};
        let (_, binding) =
            interface_binding_channel(InterfaceBinding::fixed(std::net::Ipv4Addr::LOCALHOST));
        let (tx, rx) = zerodpi_core::proxy::proxy_event_channel(true);
        let task = rt.spawn(async move {
            let binder = Arc::new(NoopSocketBinder);
            let flows = Arc::new(LocalFlowController::new(new_flow_table()));
            match cfg.MODE.as_str() {
                "ip_bypass" => {
                    zerodpi_core::proxy::run_ip_bypass_proxy(cfg, pool, binding, binder, Some(tx))
                        .await
                }
                "ip_bypass_plus" => {
                    zerodpi_core::proxy::run_ip_bypass_plus_proxy(
                        cfg,
                        pool,
                        binding,
                        binder,
                        flows,
                        Some(tx),
                    )
                    .await
                }
                _ => {
                    zerodpi_core::proxy::run_proxy(cfg, pool, binding, binder, flows, Some(tx))
                        .await
                }
            }
        });
        (task, rx)
    }

    fn listener_addr(session: &Session) -> std::net::SocketAddr {
        session
            .initial_events
            .iter()
            .find_map(|event| match event {
                ProxyEvent::ListenerStarted { listen_addr, .. } => Some(*listen_addr),
                _ => None,
            })
            .unwrap()
    }

    #[test]
    fn bind_failure_is_not_reported_as_ready() {
        let (_dir, mut session, cfg) = session_fixture();
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut cfg = (*cfg).clone();
        cfg.LISTEN_PORT = occupied.local_addr().unwrap().port();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pool = TargetPool::single(Target::ip("192.0.2.1".parse().unwrap(), 90));
        let (mut proxy, mut rx) = spawn_proxy(&rt, Arc::new(cfg), pool);
        let error = session.wait_listener(&rt, &mut proxy, &mut rx).unwrap_err();
        assert!(format!("{error:#}").contains("bind"));
        assert!(!session.ready);
    }

    #[test]
    fn supervisor_releases_workers_and_listener_before_switching_all_proxy_modes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let (_dir, session, cfg) = session_fixture();
        let mut previous_addr = None;
        let mut previous_worker: Option<Arc<AtomicBool>> = None;
        let mut attempts = Vec::new();
        run_with(session, cfg, |cfg, session| {
            if let Some(address) = previous_addr {
                let _listener = std::net::TcpListener::bind(address).unwrap();
                assert!(previous_worker.as_ref().unwrap().load(Ordering::SeqCst));
            }
            attempts.push(cfg.MODE.clone());
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?;
            let target = if cfg.MODE == "sni_spoof" {
                Target::sni("cached.example", "192.0.2.1".parse().unwrap(), 90)
            } else {
                Target::ip("192.0.2.1".parse().unwrap(), 90)
            };
            let pool = TargetPool::single(target);
            session.own_pool(pool.clone());
            let (mut proxy, mut rx) = spawn_proxy(&rt, cfg.clone(), pool);
            session.wait_listener(&rt, &mut proxy, &mut rx)?;
            previous_addr = Some(listener_addr(session));
            assert!(std::net::TcpStream::connect(previous_addr.unwrap()).is_ok());
            let dropped = Arc::new(AtomicBool::new(false));
            let guard = Dropped(dropped.clone());
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            rt.spawn(async move {
                // Deliberately detached: only dropping the generation runtime
                // can guarantee this worker is finished before the next one.
                let _guard = guard;
                let _ = entered_tx.send(());
                std::future::pending::<()>().await;
            });
            rt.block_on(entered_rx).unwrap();
            previous_worker = Some(dropped);
            let mut next = (*cfg).clone();
            match attempts.len() {
                1 => {
                    next.MODE = "ip_bypass_plus".into();
                    next.LISTEN_HOST = "127.0.0.2".into();
                }
                2 => {
                    next.MODE = "sni_spoof".into();
                    next.BYPASS_METHOD =
                        zerodpi_core::config::BypassMethodList::from_delimited("tls_padding");
                }
                _ => return Ok(()),
            }
            session.pending = Some(Arc::new(next));
            Ok(())
        })
        .unwrap();
        assert_eq!(attempts, ["ip_bypass", "ip_bypass_plus", "sni_spoof"]);
        assert!(previous_worker.unwrap().load(Ordering::SeqCst));
        assert!(std::net::TcpListener::bind(previous_addr.unwrap()).is_ok());
    }

    #[test]
    fn failed_reload_restores_cached_targets_after_list_files_disappear() {
        let (dir, session, cfg) = session_fixture();
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = occupied.local_addr().unwrap().port();
        let mut attempt = 0;
        run_with(session, cfg, |cfg, session| {
            attempt += 1;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let pool = if attempt == 3 {
                assert_eq!(cfg.MODE, "ip_bypass");
                assert_eq!(cfg.LISTEN_PORT, 0);
                assert!(session
                    .notice
                    .as_ref()
                    .unwrap()
                    .starts_with("Previous configuration restored"));
                restore_pool(&cfg, session.restore_targets.take().unwrap())?
            } else {
                TargetPool::single(Target::ip("192.0.2.99".parse().unwrap(), 87))
            };
            assert_eq!(pool.representative().ip.to_string(), "192.0.2.99");
            session.own_pool(pool.clone());
            let (mut proxy, mut rx) = spawn_proxy(&rt, cfg.clone(), pool);
            session.wait_listener(&rt, &mut proxy, &mut rx)?;
            if attempt == 1 {
                fs::remove_file(dir.path().join("config.toml"))?;
                let mut next = (*cfg).clone();
                next.LISTEN_PORT = port;
                session.pending = Some(Arc::new(next));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(attempt, 3);
    }

    #[test]
    fn interceptor_startup_failure_also_rolls_back() {
        let (_dir, session, cfg) = session_fixture();
        let mut attempt = 0;
        run_with(session, cfg, |cfg, session| {
            attempt += 1;
            if attempt == 2 {
                anyhow::bail!("interceptor unavailable");
            }
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let pool = match session.restore_targets.take() {
                Some(targets) => restore_pool(&cfg, targets)?,
                None => TargetPool::single(Target::ip("192.0.2.1".parse().unwrap(), 90)),
            };
            session.own_pool(pool.clone());
            let (mut proxy, mut rx) = spawn_proxy(&rt, cfg.clone(), pool);
            session.wait_listener(&rt, &mut proxy, &mut rx)?;
            if attempt == 1 {
                let mut next = (*cfg).clone();
                next.MODE = "sni_spoof".into();
                session.pending = Some(Arc::new(next));
            } else {
                assert_eq!(cfg.MODE, "ip_bypass");
                assert!(session
                    .notice
                    .as_ref()
                    .unwrap()
                    .contains("interceptor unavailable"));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(attempt, 3);
    }

    #[test]
    fn unconfirmed_interceptor_cleanup_retains_ownership_for_retry() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct DelayedStop(AtomicBool);
        impl DataPlane for DelayedStop {
            fn rebuild<'a>(
                &'a self,
                _: zerodpi_core::net::InterfaceBinding,
            ) -> crate::data_plane::BoxFuture<'a, Result<()>> {
                Box::pin(async { Ok(()) })
            }
            fn stop<'a>(&'a self) -> crate::data_plane::BoxFuture<'a, Result<()>> {
                Box::pin(async move {
                    anyhow::ensure!(
                        self.0.swap(true, Ordering::SeqCst),
                        "stop not yet confirmed"
                    );
                    Ok(())
                })
            }
        }
        let (_dir, mut session, _cfg) = session_fixture();
        session.own_plane(Arc::new(DelayedStop(AtomicBool::new(false))));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(session.close_generation(&rt).is_err());
        assert!(
            session.plane.is_some(),
            "failed cleanup must retain the old interceptor"
        );
        session.close_generation(&rt).unwrap();
        assert!(session.plane.is_none());
    }

    #[test]
    fn reload_reads_the_original_path_and_preserves_cli_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("custom.toml");
        fs::write(&path, "LISTEN_HOST='127.0.0.1'\nLISTEN_PORT=1234\n").unwrap();
        let args = crate::Args::parse_from([
            "zerodpi",
            "--config",
            path.to_str().unwrap(),
            "--listen-port",
            "5678",
            "--method",
            "tls_frag",
        ]);
        let source = ConfigSource::new(args).unwrap();
        let first = source.load().unwrap();
        fs::write(
            &path,
            "LISTEN_HOST='127.0.0.2'\nLISTEN_PORT=9999\nSNI_LIST='lists/sni.txt'\n",
        )
        .unwrap();
        let next = source.load().unwrap();
        assert_eq!(first.LISTEN_PORT, 5678);
        assert_eq!(next.LISTEN_PORT, 5678);
        assert_eq!(next.LISTEN_HOST, "127.0.0.2");
        assert_eq!(next.BYPASS_METHOD.to_string(), "tls_frag");
        assert_eq!(
            source.relative_path(&next.SNI_LIST),
            dir.path().join("lists/sni.txt")
        );
    }

    #[test]
    fn malformed_or_missing_file_does_not_replace_the_active_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "LISTEN_HOST='127.0.0.1'\nLISTEN_PORT=1234\n").unwrap();
        let source = ConfigSource::new(crate::Args::parse_from([
            "zerodpi",
            "--config",
            path.to_str().unwrap(),
        ]))
        .unwrap();
        let active = source.load().unwrap();
        assert!(same_config(&active, &source.load().unwrap()).unwrap());
        fs::write(&path, "LISTEN_HOST = [").unwrap();
        assert!(source.load().is_err());
        fs::remove_file(&path).unwrap();
        assert!(source.load().is_err());
        assert_eq!(active.LISTEN_PORT, 1234);
    }

    #[test]
    fn rejects_scan_modes_and_invalid_listener_before_stopping() {
        let mut cfg = crate::config_for_tests();
        for mode in ["sni_spoof", "ip_bypass", "ip_bypass_plus"] {
            cfg.MODE = mode.into();
            cfg.BYPASS_METHOD = zerodpi_core::config::BypassMethodList::from_delimited("tls_frag");
            assert!(validate_reload(&cfg, None).is_ok(), "{mode}");
        }
        cfg.MODE = "sni_scan".into();
        assert!(validate_reload(&cfg, None)
            .unwrap_err()
            .to_string()
            .contains("MODE"));
        cfg.MODE = "ip_bypass".into();
        cfg.LISTEN_HOST = "invalid listener".into();
        assert!(validate_reload(&cfg, None).is_err());
    }
}
