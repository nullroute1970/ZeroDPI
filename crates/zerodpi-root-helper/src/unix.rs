use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
use zerodpi_core::config::Config;
use zerodpi_core::flow::{new_flow_table, BypassOutcome, FlowEntry, FlowKey, FlowTable};
use zerodpi_core::handler::Handler;
use zerodpi_core::interceptor::{
    FilterSpec, InterceptorShutdown, LinuxFirewallBackend, PacketInterceptor,
};
use zerodpi_core::methods::{build_method, BypassMethod};
use zerodpi_helper_protocol::{
    read_frame, write_frame, ErrorCode, FirewallBackend, Frame, HelloAccepted, HelperState,
    InterceptorConfig, Message, Progress, MAX_LIVE_FLOWS, PROTOCOL_MAJOR, PROTOCOL_MINOR,
    SESSION_PROOF_SIZE,
};
use zerodpi_platform::{linux::recover_stale_firewall_state, DefaultInterceptor};

const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Parser)]
#[command(about = "ZeroDPI Android privileged packet-interception helper")]
struct Args {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    expected_uid: u32,
    #[arg(long)]
    session_file: PathBuf,
    #[arg(long)]
    parent_pid: Option<u32>,
}

struct InterceptorSession {
    flows: FlowTable,
    shutdown: InterceptorShutdown,
    thread: Option<JoinHandle<Result<()>>>,
}

impl InterceptorSession {
    fn close(mut self) -> Result<()> {
        self.shutdown.request();
        self.thread
            .take()
            .expect("interceptor thread must be present")
            .join()
            .map_err(|_| anyhow::anyhow!("interceptor thread panicked"))?
    }

    fn is_finished(&self) -> bool {
        match self.thread.as_ref() {
            Some(thread) => thread.is_finished(),
            None => true,
        }
    }
}

impl Drop for InterceptorSession {
    fn drop(&mut self) {
        self.shutdown.request();
        if let Some(thread) = self.thread.take() {
            match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => error!(%error, "interceptor failed during helper cleanup"),
                Err(_) => error!("interceptor thread panicked during helper cleanup"),
            }
        }
    }
}

struct RegisteredFlow {
    key: FlowKey,
    entry: Arc<FlowEntry>,
    last_progress: Option<Progress>,
}

pub fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .init();
    let args = Args::parse();
    require_root()?;
    validate_bootstrap_paths(&args)?;
    let proof = read_session_proof(&args.session_file, args.expected_uid)?;

    let _socket_cleanup = SocketCleanup(args.socket.clone());
    if args.socket.exists() {
        fs::remove_file(&args.socket).context("remove stale helper socket path")?;
    }
    let listener = UnixListener::bind(&args.socket).context("bind helper Unix socket")?;
    set_socket_owner(&args.socket, args.expected_uid)?;
    listener.set_nonblocking(true)?;
    eprintln!(
        "ZERODPI_HELPER_READY pid={} uid={}",
        std::process::id(),
        effective_uid()
    );

    let (stream, _) = accept_before(&listener, ACCEPT_TIMEOUT)?;
    let peer = peer_credentials(&stream)?;
    if peer.uid != args.expected_uid {
        bail!("helper peer UID did not match expected app UID");
    }
    if let Some(parent_pid) = args.parent_pid {
        info!(parent_pid, "helper parent identity recorded");
    }
    serve(stream, peer, proof)
}

fn serve(mut writer: UnixStream, peer: PeerCredentials, proof: Vec<u8>) -> Result<()> {
    let mut reader = writer.try_clone().context("clone helper control socket")?;
    let (frame_tx, frame_rx) = mpsc::sync_channel(64);
    std::thread::Builder::new()
        .name("zerodpi-helper-ipc".into())
        .spawn(move || {
            while let Ok(frame) = read_frame(&mut reader) {
                if frame_tx.send(frame).is_err() {
                    break;
                }
            }
        })
        .context("spawn helper IPC reader")?;

    let mut state = HelperState::Created;
    let mut config: Option<InterceptorConfig> = None;
    let mut interceptor: Option<InterceptorSession> = None;
    let mut registered: HashMap<u64, RegisteredFlow> = HashMap::new();
    let mut last_activity = Instant::now();

    loop {
        if let Some(active) = interceptor.as_ref() {
            if active.is_finished() {
                let active = interceptor.take().expect("interceptor checked as present");
                let result = active.close();
                send(
                    &mut writer,
                    0,
                    Message::HelperFatal {
                        code: ErrorCode::InterceptorFailed,
                        message: result
                            .err()
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "interceptor stopped unexpectedly".into()),
                    },
                )?;
                bail!("interceptor stopped unexpectedly");
            }
            publish_progress(&mut writer, &mut registered)?;
        }

        let frame = match frame_rx.recv_timeout(POLL_INTERVAL) {
            Ok(frame) => frame,
            Err(mpsc::RecvTimeoutError::Timeout) if last_activity.elapsed() < HEARTBEAT_TIMEOUT => {
                continue
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                send(
                    &mut writer,
                    0,
                    Message::HelperFatal {
                        code: ErrorCode::Internal,
                        message: "data-plane heartbeat timed out".into(),
                    },
                )?;
                bail!("data-plane heartbeat timed out");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                info!("data-plane control socket disconnected; cleaning up");
                break;
            }
        };
        last_activity = Instant::now();
        if !state.accepts(&frame.message) {
            send(
                &mut writer,
                frame.request_id,
                Message::HelperFatal {
                    code: ErrorCode::InvalidState,
                    message: "request is invalid in the current helper state".into(),
                },
            )?;
            bail!("invalid helper lifecycle transition");
        }

        match frame.message {
            Message::Hello(hello) => {
                if hello.session_proof != proof {
                    send(
                        &mut writer,
                        frame.request_id,
                        Message::HelperFatal {
                            code: ErrorCode::AuthenticationFailed,
                            message: "session authentication failed".into(),
                        },
                    )?;
                    bail!("session proof mismatch");
                }
                if hello.data_plane_pid != peer.pid {
                    send(
                        &mut writer,
                        frame.request_id,
                        Message::HelperFatal {
                            code: ErrorCode::AuthenticationFailed,
                            message: "data-plane PID did not match peer credentials".into(),
                        },
                    )?;
                    bail!("data-plane PID did not match peer credentials");
                }
                state = HelperState::Authenticated;
                send(
                    &mut writer,
                    frame.request_id,
                    Message::HelloAccepted(HelloAccepted {
                        peer_uid: peer.uid,
                        helper_pid: std::process::id(),
                        helper_uid: effective_uid(),
                        protocol_major: PROTOCOL_MAJOR,
                        protocol_minor: PROTOCOL_MINOR,
                        capabilities: vec!["nfqueue".into(), "flow_progress".into()],
                    }),
                )?;
            }
            Message::ConfigureInterceptor(value) => {
                value
                    .validate()
                    .context("validate interceptor configuration")?;
                let backend = match value.firewall_backend {
                    FirewallBackend::Iptables => LinuxFirewallBackend::Iptables,
                    FirewallBackend::Nftables => LinuxFirewallBackend::Nftables,
                };
                let recovered = recover_stale_firewall_state(backend)
                    .context("recover stale ZeroDPI firewall state")?;
                if recovered > 0 {
                    send(
                        &mut writer,
                        0,
                        Message::HelperWarning {
                            code: ErrorCode::Internal,
                            message: format!("recovered {recovered} stale firewall object(s)"),
                        },
                    )?;
                }
                config = Some(value);
                state = HelperState::Configured;
                send(&mut writer, frame.request_id, Message::Configured)?;
            }
            Message::OpenInterceptor => {
                let value = config
                    .as_ref()
                    .context("missing interceptor configuration")?;
                let flows = new_flow_table();
                let method = build_wire_method(&value.method)?;
                let filter = FilterSpec {
                    interface_ip: value.interface_ip,
                    remote_ip: value.remote_ip,
                    remote_port: value.remote_port,
                    queue_num: value.queue_num,
                    linux_firewall_backend: match value.firewall_backend {
                        FirewallBackend::Iptables => LinuxFirewallBackend::Iptables,
                        FirewallBackend::Nftables => LinuxFirewallBackend::Nftables,
                    },
                    firewall_owner: Some(format!("zerodpi-{}", std::process::id())),
                };
                let packet_interceptor =
                    DefaultInterceptor::open(filter).context("open privileged interceptor")?;
                let shutdown = InterceptorShutdown::default();
                let thread_shutdown = shutdown.clone();
                let handler = Handler::new(flows.clone(), method);
                let thread = std::thread::Builder::new()
                    .name("zerodpi-helper-nfq".into())
                    .spawn(move || packet_interceptor.run_until(handler, thread_shutdown))
                    .context("spawn helper interceptor thread")?;
                interceptor = Some(InterceptorSession {
                    flows,
                    shutdown,
                    thread: Some(thread),
                });
                state = HelperState::InterceptorOpen;
                send(&mut writer, frame.request_id, Message::InterceptorReady)?;
            }
            Message::RegisterFlow {
                flow_id,
                key,
                fake_data,
            } => {
                if registered.contains_key(&flow_id) {
                    send(
                        &mut writer,
                        frame.request_id,
                        Message::HelperFatal {
                            code: ErrorCode::InvalidState,
                            message: "duplicate flow identifier".into(),
                        },
                    )?;
                    bail!("duplicate flow identifier");
                }
                if registered.len() >= MAX_LIVE_FLOWS {
                    send(
                        &mut writer,
                        frame.request_id,
                        Message::HelperFatal {
                            code: ErrorCode::FlowLimitReached,
                            message: "live flow limit reached".into(),
                        },
                    )?;
                    bail!("live flow limit reached");
                }
                let flow_key = FlowKey {
                    src_ip: key.src_ip,
                    src_port: key.src_port,
                    dst_ip: key.dst_ip,
                    dst_port: key.dst_port,
                };
                if registered.values().any(|flow| flow.key == flow_key) {
                    send(
                        &mut writer,
                        frame.request_id,
                        Message::HelperFatal {
                            code: ErrorCode::InvalidState,
                            message: "duplicate flow key".into(),
                        },
                    )?;
                    bail!("duplicate flow key");
                }
                let entry = FlowEntry::new(fake_data);
                let active = interceptor.as_ref().context("interceptor is not open")?;
                active.flows.insert(flow_key, entry.clone());
                registered.insert(
                    flow_id,
                    RegisteredFlow {
                        key: flow_key,
                        entry,
                        last_progress: None,
                    },
                );
                send(
                    &mut writer,
                    frame.request_id,
                    Message::FlowRegistered { flow_id },
                )?;
            }
            Message::RemoveFlow { flow_id } => {
                if let Some(flow) = registered.remove(&flow_id) {
                    if let Some(active) = interceptor.as_ref() {
                        active.flows.remove(&flow.key);
                    }
                }
                send(
                    &mut writer,
                    frame.request_id,
                    Message::FlowRemoved { flow_id },
                )?;
            }
            Message::CloseInterceptor => {
                close_interceptor(&mut interceptor, &mut registered)?;
                state = HelperState::Configured;
                send(&mut writer, frame.request_id, Message::InterceptorClosed)?;
            }
            Message::Ping => send(&mut writer, frame.request_id, Message::Pong)?,
            Message::Shutdown => {
                state = HelperState::ShuttingDown;
                info!(?state, "root helper shutdown requested");
                close_interceptor(&mut interceptor, &mut registered)?;
                send(&mut writer, frame.request_id, Message::ShutdownComplete)?;
                state = HelperState::Exited;
                break;
            }
            _ => unreachable!("request direction checked by state machine"),
        }
    }

    if let Err(error) = close_interceptor(&mut interceptor, &mut registered) {
        error!(%error, "helper cleanup failed after disconnect");
        return Err(error);
    }
    info!(?state, "helper exited after cleanup");
    Ok(())
}

fn close_interceptor(
    interceptor: &mut Option<InterceptorSession>,
    registered: &mut HashMap<u64, RegisteredFlow>,
) -> Result<()> {
    registered.clear();
    if let Some(active) = interceptor.take() {
        active.close().context("close privileged interceptor")?;
    }
    Ok(())
}

fn publish_progress(
    writer: &mut UnixStream,
    registered: &mut HashMap<u64, RegisteredFlow>,
) -> Result<()> {
    for (&flow_id, flow) in registered.iter_mut() {
        let state = flow.entry.state.lock();
        let progress = if let Some(outcome) = state.outcome {
            Some(match outcome {
                BypassOutcome::FakeDataAcked => Progress::FakeDataAcked,
                BypassOutcome::UnexpectedClose => Progress::UnexpectedClose,
            })
        } else if state.waiting_for_data {
            Some(Progress::ReadyForData)
        } else {
            None
        };
        drop(state);
        if let Some(progress) = progress.filter(|progress| Some(*progress) != flow.last_progress) {
            flow.last_progress = Some(progress);
            send(writer, 0, Message::FlowProgress { flow_id, progress })?;
        }
    }
    Ok(())
}

fn send(writer: &mut UnixStream, request_id: u32, message: Message) -> Result<()> {
    write_frame(writer, &Frame::new(request_id, message)).context("write helper response")
}

fn build_wire_method(
    wire: &zerodpi_helper_protocol::MethodConfig,
) -> Result<Arc<dyn BypassMethod>> {
    // Deserialize a fixed, local-only baseline and copy only the explicitly
    // typed method fields supplied by the protocol. No app file is read here.
    let mut cfg: Config = toml::from_str("LISTEN_HOST = '127.0.0.1'\nLISTEN_PORT = 1\n")
        .context("construct helper method baseline")?;
    cfg.BYPASS_METHOD = wire.name.clone();
    cfg.WRONG_SEQ_EXTRA_OFFSET = wire.wrong_seq_extra_offset;
    cfg.WRONG_SEQ_SET_PSH = wire.wrong_seq_set_psh;
    cfg.WRONG_SEQ_BUMP_IP_IDENT = wire.wrong_seq_bump_ip_ident;
    cfg.WRONG_CHECKSUM_DELTA = wire.wrong_checksum_delta;
    cfg.WRONG_CHECKSUM_SET_PSH = wire.wrong_checksum_set_psh;
    cfg.WRONG_CHECKSUM_BUMP_IP_IDENT = wire.wrong_checksum_bump_ip_ident;
    cfg.WRONG_CHECKSUM_COMPLETE_IMMEDIATELY = wire.wrong_checksum_complete_immediately;
    cfg.WRONG_MD5_SET_PSH = wire.wrong_md5_set_psh;
    cfg.WRONG_MD5_BUMP_IP_IDENT = wire.wrong_md5_bump_ip_ident;
    cfg.WRONG_MD5_COMPLETE_IMMEDIATELY = wire.wrong_md5_complete_immediately;
    cfg.WRONG_ACK_OFFSET = wire.wrong_ack_offset;
    cfg.WRONG_ACK_SET_PSH = wire.wrong_ack_set_psh;
    cfg.WRONG_ACK_BUMP_IP_IDENT = wire.wrong_ack_bump_ip_ident;
    cfg.WRONG_ACK_COMPLETE_IMMEDIATELY = wire.wrong_ack_complete_immediately;
    cfg.WRONG_TIMESTAMP_OFFSET = wire.wrong_timestamp_offset;
    cfg.WRONG_TIMESTAMP_SET_PSH = wire.wrong_timestamp_set_psh;
    cfg.WRONG_TIMESTAMP_BUMP_IP_IDENT = wire.wrong_timestamp_bump_ip_ident;
    cfg.WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY = wire.wrong_timestamp_complete_immediately;
    cfg.TLS_RECORD_FRAG_SIZE = wire.tls_record_frag_size;
    cfg.TLS_RECORD_FRAG_SET_PSH = wire.tls_record_frag_set_psh;
    cfg.TLS_RECORD_FRAG_BUMP_IP_IDENT = wire.tls_record_frag_bump_ip_ident;
    cfg.LOW_TTL_VALUE = wire.low_ttl_value;
    cfg.LOW_TTL_SET_PSH = wire.low_ttl_set_psh;
    cfg.LOW_TTL_BUMP_IP_IDENT = wire.low_ttl_bump_ip_ident;
    cfg.LOW_TTL_COMPLETE_IMMEDIATELY = wire.low_ttl_complete_immediately;
    let method = build_method(&cfg).context("unsupported helper bypass method")?;
    Ok(Arc::from(method))
}

fn accept_before(
    listener: &UnixListener,
    timeout: Duration,
) -> Result<(UnixStream, std::os::unix::net::SocketAddr)> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(connection) => return Ok(connection),
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                bail!("timed out waiting for authenticated data-plane peer")
            }
            Err(error) => return Err(error).context("accept helper peer"),
        }
    }
}

fn validate_bootstrap_paths(args: &Args) -> Result<()> {
    if args.expected_uid == 0 {
        bail!("expected app UID must not be root");
    }
    let socket_parent = args
        .socket
        .parent()
        .context("helper socket has no parent")?;
    let session_parent = args
        .session_file
        .parent()
        .context("session file has no parent")?;
    if socket_parent != session_parent {
        bail!("helper socket and session metadata must share one private directory");
    }
    let metadata =
        fs::symlink_metadata(socket_parent).context("inspect helper runtime directory")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != args.expected_uid
        || metadata.mode() & 0o077 != 0
    {
        bail!("helper runtime directory is not private and owned by the expected app UID");
    }
    Ok(())
}

fn read_session_proof(path: &Path, expected_uid: u32) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).context("inspect session proof")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o077 != 0
    {
        bail!("session proof must be a private regular file");
    }
    let proof = fs::read(path).context("read session proof")?;
    if proof.len() != SESSION_PROOF_SIZE {
        bail!("session proof has invalid length");
    }
    Ok(proof)
}

fn set_socket_owner(path: &Path, uid: u32) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let encoded_path =
        CString::new(path.as_os_str().as_bytes()).context("socket path contains NUL")?;
    if unsafe { libc::chown(encoded_path.as_ptr(), uid, uid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("chown helper socket");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).context("chmod helper socket")
}

#[derive(Clone, Copy)]
struct PeerCredentials {
    pid: u32,
    uid: u32,
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut libc::c_void,
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("read Unix peer credentials");
    }
    if credentials.pid <= 0 {
        bail!("Unix peer credentials contained an invalid PID");
    }
    Ok(PeerCredentials {
        pid: credentials.pid as u32,
        uid: credentials.uid,
    })
}

fn require_root() -> Result<()> {
    let mut real = 0;
    let mut effective = 0;
    let mut saved = 0;
    if unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read helper process UIDs");
    }
    if real != 0 || effective != 0 || saved != 0 {
        bail!("root helper must run with real, effective, and saved UID 0");
    }
    Ok(())
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

struct SocketCleanup(PathBuf);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.0) {
            if error.kind() != ErrorKind::NotFound {
                warn!(%error, "failed to remove helper socket path");
            }
        }
    }
}
