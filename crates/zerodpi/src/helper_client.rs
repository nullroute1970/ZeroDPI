#[cfg(not(any(target_os = "linux", target_os = "android")))]
use std::path::Path;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
use anyhow::{bail, Result};
use zerodpi_core::config::Config;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use zerodpi_core::flow::{FlowController, FlowKey, FlowRegistrationFuture};
use zerodpi_helper_protocol::{FirewallBackend, InterceptorConfig, MethodConfig};

#[cfg(any(target_os = "linux", target_os = "android"))]
mod unix {
    use std::collections::HashMap;
    use std::fs;
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use anyhow::{bail, Context, Result};
    use tokio::sync::oneshot;
    use zerodpi_core::flow::{
        BypassOutcome, FlowController, FlowEntry, FlowKey, FlowRegistrationFuture,
    };
    use zerodpi_helper_protocol::{
        read_frame, write_frame, Frame, Hello, InterceptorConfig, Message, Progress,
        SESSION_PROOF_SIZE,
    };

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
    const MAX_PENDING_REQUESTS: usize = 1024;

    type PendingResult = std::result::Result<Message, String>;

    #[derive(Clone)]
    pub struct RemoteHelperClient {
        inner: Arc<Inner>,
    }

    struct Inner {
        writer: Mutex<UnixStream>,
        pending: Mutex<HashMap<u32, oneshot::Sender<PendingResult>>>,
        flows: Mutex<HashMap<u64, Arc<FlowEntry>>>,
        flow_ids: Mutex<HashMap<FlowKey, u64>>,
        next_request_id: AtomicU32,
        next_flow_id: AtomicU64,
        disconnected: AtomicBool,
        helper_pid: u32,
        helper_uid: u32,
        protocol_major: u16,
        protocol_minor: u16,
        capabilities: Vec<String>,
        disconnect_notify: tokio::sync::Notify,
    }

    impl RemoteHelperClient {
        pub fn connect(socket: &Path, session_file: &Path, expected_peer_uid: u32) -> Result<Self> {
            let runtime_directory = socket
                .parent()
                .context("root-helper socket has no parent directory")?;
            if session_file.parent() != Some(runtime_directory) {
                bail!("root-helper socket and proof do not share a runtime directory");
            }
            let directory_metadata = fs::symlink_metadata(runtime_directory)
                .context("inspect root-helper runtime directory")?;
            if !directory_metadata.file_type().is_dir()
                || directory_metadata.uid() != expected_peer_uid
                || directory_metadata.mode() & 0o077 != 0
            {
                bail!("root-helper runtime directory is not private and app-owned");
            }
            let session_metadata =
                fs::symlink_metadata(session_file).context("inspect helper session proof")?;
            if !session_metadata.file_type().is_file()
                || session_metadata.uid() != expected_peer_uid
                || session_metadata.mode() & 0o077 != 0
            {
                bail!("helper session proof is not a private app-owned regular file");
            }
            let proof = fs::read(session_file).context("read helper session proof")?;
            if proof.len() != SESSION_PROOF_SIZE {
                bail!("helper session proof has invalid length");
            }
            let deadline = Instant::now() + CONNECT_TIMEOUT;
            let mut stream = loop {
                match UnixStream::connect(socket) {
                    Ok(stream) => break stream,
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::NotFound | ErrorKind::ConnectionRefused
                        ) && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(error) => return Err(error).context("connect to root helper"),
                }
            };
            let socket_metadata = fs::symlink_metadata(socket).context("inspect helper socket")?;
            if !socket_metadata.file_type().is_socket()
                || socket_metadata.uid() != expected_peer_uid
                || socket_metadata.mode() & 0o077 != 0
            {
                bail!("helper socket is not a private app-owned Unix socket");
            }
            let kernel_peer = peer_credentials(&stream)?;
            if kernel_peer.uid != 0 {
                bail!("helper Unix socket peer is not UID 0");
            }
            write_frame(
                &mut stream,
                &Frame::new(
                    1,
                    Message::Hello(Hello {
                        session_proof: proof,
                        data_plane_pid: std::process::id(),
                        build_version: env!("CARGO_PKG_VERSION").into(),
                    }),
                ),
            )
            .context("send helper hello")?;
            let accepted = read_frame(&mut stream).context("read helper hello response")?;
            if accepted.request_id != 1 {
                bail!("root helper returned a mismatched hello request identifier");
            }
            let accepted = match accepted.message {
                Message::HelloAccepted(accepted) => accepted,
                Message::HelperFatal { message, .. } => {
                    bail!("root helper rejected session: {message}")
                }
                _ => bail!("root helper returned an unexpected hello response"),
            };
            if accepted.peer_uid != expected_peer_uid {
                bail!("root helper authenticated an unexpected data-plane UID");
            }
            if accepted.helper_uid != 0 {
                bail!("root helper did not report UID 0");
            }
            if accepted.helper_pid != kernel_peer.pid {
                bail!("root helper PID did not match Unix peer credentials");
            }

            let mut reader = stream.try_clone().context("clone helper control socket")?;
            let inner = Arc::new(Inner {
                writer: Mutex::new(stream),
                pending: Mutex::new(HashMap::new()),
                flows: Mutex::new(HashMap::new()),
                flow_ids: Mutex::new(HashMap::new()),
                next_request_id: AtomicU32::new(2),
                next_flow_id: AtomicU64::new(1),
                disconnected: AtomicBool::new(false),
                helper_pid: accepted.helper_pid,
                helper_uid: accepted.helper_uid,
                protocol_major: accepted.protocol_major,
                protocol_minor: accepted.protocol_minor,
                capabilities: accepted.capabilities,
                disconnect_notify: tokio::sync::Notify::new(),
            });
            let reader_inner = inner.clone();
            std::thread::Builder::new()
                .name("zerodpi-helper-events".into())
                .spawn(move || loop {
                    match read_frame(&mut reader) {
                        Ok(frame) => reader_inner.handle_frame(frame),
                        Err(error) => {
                            reader_inner.disconnect(error.to_string());
                            break;
                        }
                    }
                })
                .context("spawn helper event reader")?;
            let heartbeat_inner = inner.clone();
            std::thread::Builder::new()
                .name("zerodpi-helper-heartbeat".into())
                .spawn(move || loop {
                    std::thread::sleep(HEARTBEAT_INTERVAL);
                    if heartbeat_inner.disconnected.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Err(error) = heartbeat_inner.write(0, Message::Ping) {
                        heartbeat_inner.disconnect(error.to_string());
                        break;
                    }
                })
                .context("spawn helper heartbeat")?;
            Ok(Self { inner })
        }

        pub fn helper_pid(&self) -> u32 {
            self.inner.helper_pid
        }

        pub fn helper_uid(&self) -> u32 {
            self.inner.helper_uid
        }

        pub fn protocol_version(&self) -> (u16, u16) {
            (self.inner.protocol_major, self.inner.protocol_minor)
        }

        pub fn capabilities(&self) -> &[String] {
            &self.inner.capabilities
        }

        pub async fn configure(&self, config: InterceptorConfig) -> Result<()> {
            match self.request(Message::ConfigureInterceptor(config)).await? {
                Message::Configured => Ok(()),
                other => bail!("unexpected helper configure response: {other:?}"),
            }
        }

        pub async fn open(&self) -> Result<()> {
            match self.request(Message::OpenInterceptor).await? {
                Message::InterceptorReady => Ok(()),
                other => bail!("unexpected helper open response: {other:?}"),
            }
        }

        pub async fn close(&self) -> Result<()> {
            match self.request(Message::CloseInterceptor).await? {
                Message::InterceptorClosed => Ok(()),
                other => bail!("unexpected helper close response: {other:?}"),
            }
        }

        /// Update the live `low_ttl` TTL used by the helper's interceptor
        /// (part of `LOW_TTL_DISCOVER`).
        pub async fn set_low_ttl_value(&self, value: u8) -> Result<()> {
            match self.request(Message::SetLowTtlValue { value }).await? {
                Message::SetLowTtlAck => Ok(()),
                other => bail!("unexpected helper set-low-ttl response: {other:?}"),
            }
        }

        pub async fn shutdown(&self) -> Result<()> {
            match self.request(Message::Shutdown).await? {
                Message::ShutdownComplete => Ok(()),
                other => bail!("unexpected helper shutdown response: {other:?}"),
            }
        }

        pub async fn wait_disconnected(&self) {
            if self.inner.disconnected.load(Ordering::SeqCst) {
                return;
            }
            self.inner.disconnect_notify.notified().await;
        }

        async fn request(&self, message: Message) -> Result<Message> {
            if self.inner.disconnected.load(Ordering::SeqCst) {
                bail!("root helper is disconnected");
            }
            let request_id = self.inner.allocate_request_id()?;
            let (tx, rx) = oneshot::channel();
            {
                let mut pending = self.inner.pending.lock().expect("pending mutex poisoned");
                if pending.len() >= MAX_PENDING_REQUESTS {
                    bail!("too many outstanding root-helper requests");
                }
                pending.insert(request_id, tx);
            }
            if let Err(error) = self.inner.write(request_id, message) {
                self.inner
                    .pending
                    .lock()
                    .expect("pending mutex poisoned")
                    .remove(&request_id);
                return Err(error);
            }
            match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
                Ok(Ok(Ok(message))) => Ok(message),
                Ok(Ok(Err(message))) => bail!("{message}"),
                Ok(Err(_)) => bail!("root helper response channel closed"),
                Err(_) => {
                    self.inner
                        .pending
                        .lock()
                        .expect("pending mutex poisoned")
                        .remove(&request_id);
                    bail!("root helper request timed out")
                }
            }
        }
    }

    impl Inner {
        fn allocate_request_id(&self) -> Result<u32> {
            self.next_request_id
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| anyhow::anyhow!("helper request identifier space exhausted"))
        }

        fn write(&self, request_id: u32, message: Message) -> Result<()> {
            let mut writer = self.writer.lock().expect("writer mutex poisoned");
            write_frame(&mut *writer, &Frame::new(request_id, message))
                .context("write root-helper request")
        }

        fn handle_frame(&self, frame: Frame) {
            match frame.message {
                Message::FlowProgress { flow_id, progress } => {
                    let entry = self
                        .flows
                        .lock()
                        .expect("flows mutex poisoned")
                        .get(&flow_id)
                        .cloned();
                    if let Some(entry) = entry {
                        match progress {
                            Progress::ReadyForData => {
                                entry.state.lock().waiting_for_data = true;
                                entry.ready_for_data.notify_waiters();
                            }
                            Progress::FakeDataAcked => entry.finish(BypassOutcome::FakeDataAcked),
                            Progress::UnexpectedClose => {
                                entry.finish(BypassOutcome::UnexpectedClose)
                            }
                        }
                    }
                }
                Message::HelperWarning { message, .. } => {
                    tracing::warn!(message, "root helper warning");
                }
                Message::HelperFatal { message, .. } => self.disconnect(message),
                message => {
                    if let Some(sender) = self
                        .pending
                        .lock()
                        .expect("pending mutex poisoned")
                        .remove(&frame.request_id)
                    {
                        let _ = sender.send(Ok(message));
                    }
                }
            }
        }

        fn disconnect(&self, reason: String) {
            if self.disconnected.swap(true, Ordering::SeqCst) {
                return;
            }
            // There is one runtime liveness waiter. `notify_one` stores a
            // permit when disconnect races with waiter creation.
            self.disconnect_notify.notify_one();
            for (_, sender) in self.pending.lock().expect("pending mutex poisoned").drain() {
                let _ = sender.send(Err(format!("root helper disconnected: {reason}")));
            }
            for entry in self.flows.lock().expect("flows mutex poisoned").values() {
                entry.finish(BypassOutcome::UnexpectedClose);
            }
        }
    }

    impl FlowController for RemoteHelperClient {
        fn register_flow(&self, key: FlowKey, fake_data: Vec<u8>) -> FlowRegistrationFuture<'_> {
            Box::pin(async move {
                let flow_id = self.inner.next_flow_id.fetch_add(1, Ordering::SeqCst);
                if flow_id == 0 {
                    bail!("helper flow identifier space exhausted");
                }
                let entry = FlowEntry::new(Vec::new());
                self.inner
                    .flows
                    .lock()
                    .expect("flows mutex poisoned")
                    .insert(flow_id, entry.clone());
                self.inner
                    .flow_ids
                    .lock()
                    .expect("flow IDs mutex poisoned")
                    .insert(key, flow_id);
                let wire_key = zerodpi_helper_protocol::FlowKey {
                    src_ip: key.src_ip,
                    src_port: key.src_port,
                    dst_ip: key.dst_ip,
                    dst_port: key.dst_port,
                };
                let response = self
                    .request(Message::RegisterFlow {
                        flow_id,
                        key: wire_key,
                        fake_data,
                    })
                    .await;
                match response {
                    Ok(Message::FlowRegistered {
                        flow_id: acknowledged,
                    }) if acknowledged == flow_id => Ok(entry),
                    Ok(other) => {
                        self.remove_flow(key);
                        bail!("unexpected flow registration response: {other:?}")
                    }
                    Err(error) => {
                        self.remove_flow(key);
                        Err(error)
                    }
                }
            })
        }

        fn remove_flow(&self, key: FlowKey) {
            let flow_id = self
                .inner
                .flow_ids
                .lock()
                .expect("flow IDs mutex poisoned")
                .remove(&key);
            if let Some(flow_id) = flow_id {
                self.inner
                    .flows
                    .lock()
                    .expect("flows mutex poisoned")
                    .remove(&flow_id);
                if let Err(error) = self.inner.write(0, Message::RemoveFlow { flow_id }) {
                    tracing::warn!(%error, flow_id, "failed to release helper flow");
                }
            }
        }
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
            return Err(std::io::Error::last_os_error())
                .context("read root-helper Unix peer credentials");
        }
        if credentials.pid <= 0 {
            bail!("root-helper Unix peer credentials contained an invalid PID");
        }
        Ok(PeerCredentials {
            pid: credentials.pid as u32,
            uid: credentials.uid,
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use unix::RemoteHelperClient;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[derive(Clone)]
pub struct RemoteHelperClient;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl RemoteHelperClient {
    pub fn connect(_socket: &Path, _session_file: &Path, _expected_peer_uid: u32) -> Result<Self> {
        bail!("external root helper mode is only available on Android/Linux")
    }

    pub fn helper_pid(&self) -> u32 {
        0
    }
    pub fn helper_uid(&self) -> u32 {
        0
    }
    pub fn protocol_version(&self) -> (u16, u16) {
        (0, 0)
    }
    pub fn capabilities(&self) -> &[String] {
        &[]
    }
    pub async fn configure(&self, _config: InterceptorConfig) -> Result<()> {
        bail!("external root helper is unavailable")
    }
    pub async fn open(&self) -> Result<()> {
        bail!("external root helper is unavailable")
    }
    pub async fn close(&self) -> Result<()> {
        bail!("external root helper is unavailable")
    }
    pub async fn set_low_ttl_value(&self, _value: u8) -> Result<()> {
        bail!("external root helper is unavailable")
    }
    pub async fn shutdown(&self) -> Result<()> {
        bail!("external root helper is unavailable")
    }
    pub async fn wait_disconnected(&self) {}
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl FlowController for RemoteHelperClient {
    fn register_flow(&self, _key: FlowKey, _fake_data: Vec<u8>) -> FlowRegistrationFuture<'_> {
        Box::pin(async { bail!("external root helper is unavailable") })
    }

    fn remove_flow(&self, _key: FlowKey) {}
}

pub fn interceptor_config(
    cfg: &Config,
    interface_ip: std::net::Ipv4Addr,
    remote_ip: Option<std::net::Ipv4Addr>,
    remote_port: u16,
) -> InterceptorConfig {
    InterceptorConfig {
        interface_ip,
        remote_ip,
        remote_port,
        queue_num: cfg.NFQUEUE_NUM,
        firewall_backend: match cfg.linux_firewall_backend() {
            zerodpi_core::interceptor::LinuxFirewallBackend::Iptables => FirewallBackend::Iptables,
            zerodpi_core::interceptor::LinuxFirewallBackend::Nftables => FirewallBackend::Nftables,
        },
        method: MethodConfig {
            name: cfg.BYPASS_METHOD.clone(),
            wrong_seq_extra_offset: cfg.WRONG_SEQ_EXTRA_OFFSET,
            wrong_seq_set_psh: cfg.WRONG_SEQ_SET_PSH,
            wrong_seq_bump_ip_ident: cfg.WRONG_SEQ_BUMP_IP_IDENT,
            wrong_checksum_delta: cfg.WRONG_CHECKSUM_DELTA,
            wrong_checksum_set_psh: cfg.WRONG_CHECKSUM_SET_PSH,
            wrong_checksum_bump_ip_ident: cfg.WRONG_CHECKSUM_BUMP_IP_IDENT,
            wrong_checksum_complete_immediately: cfg.WRONG_CHECKSUM_COMPLETE_IMMEDIATELY,
            wrong_md5_set_psh: cfg.WRONG_MD5_SET_PSH,
            wrong_md5_bump_ip_ident: cfg.WRONG_MD5_BUMP_IP_IDENT,
            wrong_md5_complete_immediately: cfg.WRONG_MD5_COMPLETE_IMMEDIATELY,
            wrong_ack_offset: cfg.WRONG_ACK_OFFSET,
            wrong_ack_set_psh: cfg.WRONG_ACK_SET_PSH,
            wrong_ack_bump_ip_ident: cfg.WRONG_ACK_BUMP_IP_IDENT,
            wrong_ack_complete_immediately: cfg.WRONG_ACK_COMPLETE_IMMEDIATELY,
            wrong_timestamp_offset: cfg.WRONG_TIMESTAMP_OFFSET,
            wrong_timestamp_set_psh: cfg.WRONG_TIMESTAMP_SET_PSH,
            wrong_timestamp_bump_ip_ident: cfg.WRONG_TIMESTAMP_BUMP_IP_IDENT,
            wrong_timestamp_complete_immediately: cfg.WRONG_TIMESTAMP_COMPLETE_IMMEDIATELY,
            tls_record_frag_size: cfg.TLS_RECORD_FRAG_SIZE,
            tls_record_frag_set_psh: cfg.TLS_RECORD_FRAG_SET_PSH,
            tls_record_frag_bump_ip_ident: cfg.TLS_RECORD_FRAG_BUMP_IP_IDENT,
            low_ttl_value: cfg.LOW_TTL_VALUE,
            low_ttl_set_psh: cfg.LOW_TTL_SET_PSH,
            low_ttl_bump_ip_ident: cfg.LOW_TTL_BUMP_IP_IDENT,
            low_ttl_complete_immediately: cfg.LOW_TTL_COMPLETE_IMMEDIATELY,
        },
    }
}
