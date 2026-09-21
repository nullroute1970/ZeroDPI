//! Network helpers shared by core and platform crates.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

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
}
