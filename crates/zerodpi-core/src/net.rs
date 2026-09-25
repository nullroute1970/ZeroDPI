//! Network helpers shared by core and platform crates.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::watch;

/// Discover the local IPv4 address the kernel would use to reach `target`.
///
/// Mirrors upstream's `get_default_interface_ipv4`: we open an unconnected
/// UDP socket and call `connect()` to a well-known address so the kernel
/// fills in the source address; no packets are actually sent.
pub fn default_interface_ipv4(target: Ipv4Addr) -> anyhow::Result<Ipv4Addr> {
    let sock = UdpSocket::bind(SocketAddr::from(([0u8, 0, 0, 0], 0)))?;
    sock.connect(SocketAddr::from((target, 53)))?;
    match sock.local_addr()?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => anyhow::bail!("unexpected IPv6 local address"),
    }
}

/// The physical interface ZeroDPI must use for its own outbound traffic.
///
/// The address prevents the kernel from choosing a TUN source address. The
/// interface identity lets the platform socket binder enforce the egress
/// device as well; source-address binding alone is not sufficient on systems
/// with policy routes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InterfaceBinding {
    pub ip: Ipv4Addr,
    pub if_index: u32,
    pub if_name: Arc<str>,
}

impl InterfaceBinding {
    pub fn new(ip: Ipv4Addr, if_index: u32, if_name: impl AsRef<str>) -> Self {
        Self {
            ip,
            if_index,
            if_name: Arc::from(if_name.as_ref()),
        }
    }

    /// A binding suitable for core-only tests that use loopback or a mocked
    /// socket binder. Production code must use a platform-resolved binding.
    pub fn fixed(ip: Ipv4Addr) -> Self {
        Self::new(ip, 0, "")
    }
}

/// Platform hook used to enforce an outbound interface before a TCP connect.
pub trait OutboundSocketBinder: Send + Sync {
    fn configure(&self, socket: &TcpSocket, binding: &InterfaceBinding) -> anyhow::Result<()>;

    fn configure_v6(&self, socket: &TcpSocket, binding: &InterfaceBinding) -> anyhow::Result<()> {
        self.configure(socket, binding)
    }
}

/// A fixed binding plus the platform policy used to enforce it. Scanner and
/// probe tasks clone this small context so every concurrent connect follows
/// the same physical uplink.
#[derive(Clone)]
pub struct OutboundNetwork {
    pub binding: InterfaceBinding,
    pub binder: Arc<dyn OutboundSocketBinder>,
}

impl OutboundNetwork {
    pub fn new(binding: InterfaceBinding, binder: Arc<dyn OutboundSocketBinder>) -> Self {
        Self { binding, binder }
    }

    pub fn socket(&self) -> anyhow::Result<TcpSocket> {
        bound_tcp_socket(self.binder.as_ref(), &self.binding)
    }

    pub async fn connect(&self, target: SocketAddr) -> anyhow::Result<TcpStream> {
        connect_bound(self.binder.as_ref(), &self.binding, target).await
    }
}

/// No-op binder for core tests and platform-independent callers that provide
/// their own socket policy. Runtime entry points must use the platform binder.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSocketBinder;

impl OutboundSocketBinder for NoopSocketBinder {
    fn configure(&self, _socket: &TcpSocket, _binding: &InterfaceBinding) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Create an IPv4 socket that is configured and bound to `binding` but not yet
/// connected. Callers that need socket options such as TTL can configure them
/// before invoking `TcpSocket::connect`.
pub fn bound_tcp_socket(
    binder: &dyn OutboundSocketBinder,
    binding: &InterfaceBinding,
) -> anyhow::Result<TcpSocket> {
    let socket = TcpSocket::new_v4()?;
    binder.configure(&socket, binding)?;
    socket.bind(SocketAddr::from((binding.ip, 0)))?;
    Ok(socket)
}

/// Connect an IPv4 TCP socket through the selected physical interface.
pub async fn connect_bound(
    binder: &dyn OutboundSocketBinder,
    binding: &InterfaceBinding,
    target: SocketAddr,
) -> anyhow::Result<TcpStream> {
    if target.is_ipv4() {
        return Ok(bound_tcp_socket(binder, binding)?.connect(target).await?);
    }

    let socket = TcpSocket::new_v6()?;
    binder.configure_v6(&socket, binding)?;
    Ok(socket.connect(target).await?)
}

/// Which kind of platform event produced a network change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkChangeSource {
    /// An interface address was added, removed, or changed.
    Address,
    /// A route was added, removed, or changed.
    Route,
    /// A link went up or down.
    Link,
    /// The periodic safety-net probe observed a difference.
    Poll,
}

/// Read-only handle to the current outbound interface address.
///
/// Clone it into tasks that need the address at use time (proxy connections,
/// LOW_TTL discovery). The value is swapped by the recovery coordinator after
/// a rebuild succeeds.
#[derive(Clone, Debug)]
pub struct InterfaceIp {
    rx: watch::Receiver<Ipv4Addr>,
}

impl InterfaceIp {
    /// The current interface address.
    pub fn current(&self) -> Ipv4Addr {
        *self.rx.borrow()
    }

    /// A handle that never changes. Used by scanners and tests.
    pub fn fixed(ip: Ipv4Addr) -> Self {
        let (_tx, rx) = watch::channel(ip);
        Self { rx }
    }

    /// Resolves when the value changes. A fixed handle resolves only when its
    /// internal sender is dropped.
    pub async fn changed(&mut self) -> Result<(), tokio::sync::watch::error::RecvError> {
        self.rx.changed().await
    }
}

/// Write side of [`InterfaceIp`], owned by the recovery coordinator.
#[derive(Clone, Debug)]
pub struct InterfaceIpHandle {
    tx: watch::Sender<Ipv4Addr>,
}

impl InterfaceIpHandle {
    /// Store a new interface address. Never fails; receivers may simply be gone.
    pub fn set(&self, ip: Ipv4Addr) {
        self.tx.send_replace(ip);
    }

    /// A read handle for tasks.
    pub fn receiver(&self) -> InterfaceIp {
        InterfaceIp {
            rx: self.tx.subscribe(),
        }
    }
}

/// Create the shared interface-address channel.
pub fn interface_ip_channel(initial: Ipv4Addr) -> (InterfaceIpHandle, InterfaceIp) {
    let (tx, rx) = watch::channel(initial);
    (InterfaceIpHandle { tx }, InterfaceIp { rx })
}

/// Read-only handle to the current physical interface binding.
#[derive(Clone, Debug)]
pub struct InterfaceBindingWatch {
    rx: watch::Receiver<InterfaceBinding>,
}

impl InterfaceBindingWatch {
    pub fn current(&self) -> InterfaceBinding {
        self.rx.borrow().clone()
    }

    pub fn fixed(binding: InterfaceBinding) -> Self {
        let (_tx, rx) = watch::channel(binding);
        Self { rx }
    }

    pub async fn changed(&mut self) -> Result<(), tokio::sync::watch::error::RecvError> {
        self.rx.changed().await
    }
}

/// Write side of [`InterfaceBindingWatch`], owned by network recovery.
#[derive(Clone, Debug)]
pub struct InterfaceBindingHandle {
    tx: watch::Sender<InterfaceBinding>,
}

impl InterfaceBindingHandle {
    pub fn set(&self, binding: InterfaceBinding) {
        self.tx.send_replace(binding);
    }

    pub fn receiver(&self) -> InterfaceBindingWatch {
        InterfaceBindingWatch {
            rx: self.tx.subscribe(),
        }
    }
}

pub fn interface_binding_channel(
    initial: InterfaceBinding,
) -> (InterfaceBindingHandle, InterfaceBindingWatch) {
    let (tx, rx) = watch::channel(initial);
    (InterfaceBindingHandle { tx }, InterfaceBindingWatch { rx })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_ip_channel_reads_latest_value() {
        let (handle, rx) = interface_ip_channel(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(rx.current(), Ipv4Addr::new(10, 0, 0, 1));
        handle.set(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(rx.current(), Ipv4Addr::new(10, 0, 0, 2));
    }

    #[tokio::test]
    async fn interface_ip_watch_notifies_on_set() {
        let (handle, mut rx) = interface_ip_channel(Ipv4Addr::LOCALHOST);
        handle.set(Ipv4Addr::new(192, 0, 2, 10));
        rx.changed().await.unwrap();
        assert_eq!(rx.current(), Ipv4Addr::new(192, 0, 2, 10));
    }

    #[test]
    fn interface_ip_fixed_is_usable_without_a_sender() {
        let rx = InterfaceIp::fixed(Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(rx.current(), Ipv4Addr::new(203, 0, 113, 7));
    }

    #[test]
    fn network_change_source_serializes_snake_case() {
        let json = serde_json::to_string(&NetworkChangeSource::Address).unwrap();
        assert_eq!(json, "\"address\"");
        let json = serde_json::to_string(&NetworkChangeSource::Poll).unwrap();
        assert_eq!(json, "\"poll\"");
    }

    #[test]
    fn interface_binding_equality_includes_interface_identity() {
        let first = InterfaceBinding::new(Ipv4Addr::new(192, 0, 2, 10), 7, "Wi-Fi");
        let same = InterfaceBinding::new(Ipv4Addr::new(192, 0, 2, 10), 7, "Wi-Fi");
        let different_index = InterfaceBinding::new(Ipv4Addr::new(192, 0, 2, 10), 8, "Ethernet");

        assert_eq!(first, same);
        assert_ne!(first, different_index);
    }

    #[tokio::test]
    async fn interface_binding_channel_publishes_complete_binding() {
        let initial = InterfaceBinding::new(Ipv4Addr::LOCALHOST, 1, "lo");
        let (handle, mut receiver) = interface_binding_channel(initial.clone());
        let next = InterfaceBinding::new(Ipv4Addr::new(192, 0, 2, 10), 7, "Wi-Fi");

        handle.set(next.clone());
        receiver.changed().await.unwrap();

        assert_eq!(receiver.current(), next);
    }

    #[tokio::test]
    async fn connect_bound_uses_the_requested_ipv4_source() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });

        let stream = connect_bound(
            &NoopSocketBinder,
            &InterfaceBinding::fixed(Ipv4Addr::LOCALHOST),
            target,
        )
        .await
        .unwrap();
        let accepted = accept.await.unwrap();

        assert_eq!(stream.local_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(accepted.peer_addr().unwrap().ip(), Ipv4Addr::LOCALHOST);
    }
}
