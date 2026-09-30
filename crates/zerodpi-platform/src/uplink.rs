//! Physical-uplink discovery and outbound socket binding.
//!
//! ZeroDPI must not use the source address selected by the process-wide
//! default route: a proxy TUN can intentionally replace that route. This
//! module resolves an operational non-virtual uplink and exposes the native
//! socket option needed to keep outbound connections on that uplink.

use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpSocket;
use zerodpi_core::net::{InterfaceBinding, OutboundSocketBinder};

#[cfg(windows)]
mod imp {
    use super::*;
    use anyhow::Context;
    use std::mem::{size_of, MaybeUninit};
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, IF_TYPE_ETHERNET_CSMACD,
        IF_TYPE_IEEE80211, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, AF_INET, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKADDR_IN,
        SOCKET_ADDRESS,
    };

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Candidate {
        binding: InterfaceBinding,
        metric: u32,
    }

    pub fn resolve_physical_binding(_target: Ipv4Addr) -> Result<InterfaceBinding> {
        let mut candidates = enumerate_candidates()?;
        candidates.sort_by(|left, right| {
            left.metric
                .cmp(&right.metric)
                .then_with(|| left.binding.if_index.cmp(&right.binding.if_index))
        });
        candidates
            .into_iter()
            .next()
            .map(|candidate| candidate.binding)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no operational physical Wi-Fi/Ethernet adapter with an IPv4 address was found"
                )
            })
    }

    fn enumerate_candidates() -> Result<Vec<Candidate>> {
        let mut size = 15_000_u32;
        loop {
            let element_count = (size as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
            let mut buffer: Vec<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>> =
                Vec::with_capacity(element_count.max(1));
            let buffer_size = (buffer.capacity() * size_of::<IP_ADAPTER_ADDRESSES_LH>()) as u32;
            let mut returned_size = buffer_size;
            let status = unsafe {
                GetAdaptersAddresses(
                    AF_INET as u32,
                    GAA_FLAG_INCLUDE_GATEWAYS,
                    ptr::null(),
                    buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut returned_size,
                )
            };

            if status == ERROR_BUFFER_OVERFLOW {
                size = returned_size;
                continue;
            }
            if status != ERROR_SUCCESS {
                anyhow::bail!("GetAdaptersAddresses failed with Windows error {status}");
            }

            return Ok(unsafe { collect_candidates(buffer.as_ptr() as *const _, buffer_size) });
        }
    }

    unsafe fn collect_candidates(
        mut current: *const IP_ADAPTER_ADDRESSES_LH,
        _buffer_size: u32,
    ) -> Vec<Candidate> {
        let mut candidates = Vec::new();
        while !current.is_null() {
            let adapter = &*current;
            let if_type = adapter.IfType;
            let if_index = adapter.Anonymous1.Anonymous.IfIndex;
            let name = wide_string(adapter.FriendlyName);

            if adapter.OperStatus == IfOperStatusUp
                && if_index != 0
                && is_physical_type(if_type)
                && !looks_virtual(&name)
            {
                if let Some(ip) = first_ipv4(adapter.FirstUnicastAddress) {
                    if is_usable_ipv4(ip) {
                        candidates.push(Candidate {
                            binding: InterfaceBinding::new(ip, if_index, name),
                            metric: adapter.Ipv4Metric,
                        });
                    }
                }
            }

            current = adapter.Next;
        }
        candidates
    }

    fn is_physical_type(if_type: u32) -> bool {
        matches!(if_type, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211)
    }

    fn looks_virtual(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        [
            "virtual",
            "wintun",
            "wireguard",
            "tun",
            "tap",
            "vpn",
            "loopback",
            "host-only",
            "hyper-v",
            "docker",
            "sing-box",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
    }

    fn is_usable_ipv4(ip: Ipv4Addr) -> bool {
        !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local()
    }

    unsafe fn first_ipv4(
        mut current: *const windows_sys::Win32::NetworkManagement::IpHelper::
            IP_ADAPTER_UNICAST_ADDRESS_LH,
    ) -> Option<Ipv4Addr> {
        while !current.is_null() {
            let address = &*current;
            if let Some(ip) = sockaddr_ipv4(&address.Address) {
                if is_usable_ipv4(ip) {
                    return Some(ip);
                }
            }
            current = address.Next;
        }
        None
    }

    unsafe fn sockaddr_ipv4(address: &SOCKET_ADDRESS) -> Option<Ipv4Addr> {
        if address.lpSockaddr.is_null() || address.iSockaddrLength < size_of::<SOCKADDR_IN>() as i32
        {
            return None;
        }
        let sockaddr = &*(address.lpSockaddr as *const SOCKADDR_IN);
        if sockaddr.sin_family != AF_INET {
            return None;
        }
        let bytes = sockaddr.sin_addr.S_un.S_addr.to_ne_bytes();
        Some(Ipv4Addr::from(bytes))
    }

    unsafe fn wide_string(pointer: windows_sys::core::PWSTR) -> String {
        if pointer.is_null() {
            return String::new();
        }
        let mut length = 0;
        while *pointer.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(pointer, length))
    }

    #[derive(Clone, Copy, Debug, Default)]
    pub struct PlatformSocketBinder;

    impl OutboundSocketBinder for PlatformSocketBinder {
        fn configure(&self, socket: &TcpSocket, binding: &InterfaceBinding) -> Result<()> {
            configure_interface(socket, binding, IPPROTO_IP, IP_UNICAST_IF)
        }

        fn configure_v6(&self, socket: &TcpSocket, binding: &InterfaceBinding) -> Result<()> {
            configure_interface(socket, binding, IPPROTO_IPV6, IPV6_UNICAST_IF)
        }
    }

    fn configure_interface(
        socket: &TcpSocket,
        binding: &InterfaceBinding,
        level: i32,
        option: i32,
    ) -> Result<()> {
        use std::os::windows::io::AsRawSocket;

        if binding.if_index == 0 {
            anyhow::bail!("physical interface binding has no Windows interface index");
        }

        // Windows expects the interface index in network byte order for
        // IP_UNICAST_IF and IPV6_UNICAST_IF.
        let interface_index = binding.if_index.to_be();
        let result = unsafe {
            setsockopt(
                socket.as_raw_socket() as usize,
                level,
                option,
                &interface_index as *const u32 as *const u8,
                size_of::<u32>() as i32,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "set interface option for {} (index {})",
                    binding.ip, binding.if_index
                )
            });
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn accepts_only_ethernet_and_wifi_adapter_types() {
            assert!(is_physical_type(IF_TYPE_ETHERNET_CSMACD));
            assert!(is_physical_type(IF_TYPE_IEEE80211));
            assert!(!is_physical_type(131));
        }

        #[test]
        fn rejects_virtual_adapter_names() {
            assert!(looks_virtual("sing-box TUN"));
            assert!(looks_virtual("WireGuard Tunnel"));
            assert!(!looks_virtual("Intel(R) Wi-Fi 6E"));
        }

        #[test]
        fn rejects_non_routable_ipv4_addresses() {
            assert!(!is_usable_ipv4(Ipv4Addr::UNSPECIFIED));
            assert!(!is_usable_ipv4(Ipv4Addr::LOCALHOST));
            assert!(!is_usable_ipv4(Ipv4Addr::new(169, 254, 1, 2)));
            assert!(is_usable_ipv4(Ipv4Addr::new(192, 0, 2, 10)));
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use super::*;
    use anyhow::Context;
    use std::collections::HashMap;
    use std::ffi::CStr;
    use std::ffi::CString;
    use std::fs;
    #[cfg(target_os = "android")]
    use std::mem::{size_of, MaybeUninit};
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "android")]
    use std::os::fd::{FromRawFd, OwnedFd};
    #[cfg(target_os = "linux")]
    use std::ptr;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Candidate {
        binding: InterfaceBinding,
        metric: u32,
        kind_rank: u8,
    }

    pub fn resolve_physical_binding(_target: Ipv4Addr) -> Result<InterfaceBinding> {
        let route_metrics = read_route_metrics();
        let mut candidates = enumerate_candidates(&route_metrics)?;
        candidates.sort_by(|left, right| {
            left.metric
                .cmp(&right.metric)
                .then_with(|| left.kind_rank.cmp(&right.kind_rank))
                .then_with(|| left.binding.if_index.cmp(&right.binding.if_index))
        });
        candidates
            .into_iter()
            .next()
            .map(|candidate| candidate.binding)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no operational physical Wi-Fi/Ethernet uplink with an IPv4 address was found"
                )
            })
    }

    #[cfg(target_os = "linux")]
    fn enumerate_candidates(route_metrics: &HashMap<String, u32>) -> Result<Vec<Candidate>> {
        let mut addresses = ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut addresses) } != 0 {
            return Err(std::io::Error::last_os_error()).context("getifaddrs");
        }
        let guard = IfAddrsGuard(addresses);
        let mut current = addresses;
        let mut candidates = Vec::new();

        while !current.is_null() {
            let entry = unsafe { &*current };
            if !entry.ifa_name.is_null()
                && !entry.ifa_addr.is_null()
                && (entry.ifa_flags & libc::IFF_UP as u32) != 0
            {
                let name = unsafe { CStr::from_ptr(entry.ifa_name) }
                    .to_string_lossy()
                    .into_owned();
                if let Some(ip) = unsafe { sockaddr_ipv4(entry.ifa_addr) } {
                    if !is_physical_interface(&name) || !is_usable_ipv4(ip) {
                        continue;
                    }
                    let if_index = unsafe {
                        libc::if_nametoindex(
                            CString::new(name.as_str())
                                .expect("interface names cannot contain NUL")
                                .as_ptr(),
                        )
                    };
                    if if_index != 0 {
                        let kind_rank = interface_kind_rank(&name);
                        let metric = route_metrics.get(&name).copied().unwrap_or(u32::MAX / 2);
                        candidates.push(Candidate {
                            binding: InterfaceBinding::new(ip, if_index, name),
                            metric,
                            kind_rank,
                        });
                    }
                }
            }
            current = unsafe { (*current).ifa_next };
        }

        drop(guard);
        Ok(candidates)
    }

    #[cfg(target_os = "android")]
    fn enumerate_candidates(route_metrics: &HashMap<String, u32>) -> Result<Vec<Candidate>> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("open interface query socket");
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut candidates = Vec::new();

        for (name, ip) in enumerate_interface_addresses()? {
            if !is_physical_interface(&name) {
                continue;
            }

            let name_c = CString::new(name.as_str()).context("interface name contains NUL")?;
            let if_index = unsafe { libc::if_nametoindex(name_c.as_ptr()) };
            if if_index == 0 {
                continue;
            }

            let mut flags_request = interface_request(&name)?;
            let flags_result = unsafe {
                libc::ioctl(
                    socket.as_raw_fd(),
                    libc::SIOCGIFFLAGS as libc::Ioctl,
                    &mut flags_request,
                )
            };
            if flags_result != 0 {
                continue;
            }
            let flags = unsafe { flags_request.ifr_ifru.ifru_flags } as libc::c_int;
            if flags & libc::IFF_UP == 0 {
                continue;
            }

            if !is_usable_ipv4(ip) {
                continue;
            }

            let kind_rank = interface_kind_rank(&name);
            let metric = route_metrics.get(&name).copied().unwrap_or(u32::MAX / 2);
            candidates.push(Candidate {
                binding: InterfaceBinding::new(ip, if_index, name),
                metric,
                kind_rank,
            });
        }

        Ok(candidates)
    }

    /// Enumerate IPv4 interface addresses through the socket ioctl API.
    ///
    /// Android denies direct access to `/proc/net/dev` for ordinary app
    /// processes. `SIOCGIFCONF` is available with the API-23 NDK baseline and
    /// returns the same interface/address pairs without requiring procfs.
    #[cfg(target_os = "android")]
    fn enumerate_interface_addresses() -> Result<Vec<(String, Ipv4Addr)>> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("open interface query socket");
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut capacity = 16usize;

        loop {
            let mut buffer: Vec<MaybeUninit<libc::ifreq>> =
                std::iter::repeat_with(MaybeUninit::uninit)
                    .take(capacity)
                    .collect();
            let buffer_len = buffer
                .len()
                .checked_mul(size_of::<libc::ifreq>())
                .context("interface query buffer size overflow")?;
            let buffer_len =
                libc::c_int::try_from(buffer_len).context("interface query buffer is too large")?;
            let mut request = libc::ifconf {
                ifc_len: buffer_len,
                ifc_ifcu: unsafe { std::mem::zeroed() },
            };
            request.ifc_ifcu.ifcu_req = buffer.as_mut_ptr().cast();

            let result = unsafe {
                libc::ioctl(
                    socket.as_raw_fd(),
                    libc::SIOCGIFCONF as libc::Ioctl,
                    &mut request,
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error()).context("enumerate interfaces");
            }

            let reported_len = usize::try_from(request.ifc_len)
                .context("interface query returned a negative length")?;
            let entry_size = size_of::<libc::ifreq>();
            let entry_count = (reported_len.min(buffer_len as usize)) / entry_size;
            let mut interfaces = Vec::with_capacity(entry_count);
            for entry in buffer.iter().take(entry_count) {
                let entry = unsafe { entry.assume_init_ref() };
                let name = unsafe { CStr::from_ptr(entry.ifr_name.as_ptr()) }
                    .to_string_lossy()
                    .into_owned();
                if let Some(ip) = unsafe { sockaddr_ipv4(&entry.ifr_ifru.ifru_addr) } {
                    interfaces.push((name, ip));
                }
            }

            if reported_len < buffer_len as usize {
                return Ok(interfaces);
            }
            capacity = capacity
                .checked_mul(2)
                .context("interface query returned too many interfaces")?;
        }
    }

    #[cfg(target_os = "android")]
    fn interface_request(name: &str) -> Result<libc::ifreq> {
        if name.len() >= libc::IFNAMSIZ {
            anyhow::bail!("interface name is too long: {name}");
        }

        let mut request = unsafe { std::mem::zeroed::<libc::ifreq>() };
        for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *slot = byte as libc::c_char;
        }
        Ok(request)
    }

    #[cfg(target_os = "linux")]
    struct IfAddrsGuard(*mut libc::ifaddrs);

    #[cfg(target_os = "linux")]
    impl Drop for IfAddrsGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { libc::freeifaddrs(self.0) };
            }
        }
    }

    unsafe fn sockaddr_ipv4(address: *const libc::sockaddr) -> Option<Ipv4Addr> {
        if (*address).sa_family as i32 != libc::AF_INET {
            return None;
        }
        let address = &*(address as *const libc::sockaddr_in);
        Some(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)))
    }

    fn read_route_metrics() -> HashMap<String, u32> {
        let mut metrics = HashMap::new();
        let Ok(contents) = fs::read_to_string("/proc/net/route") else {
            return metrics;
        };

        for line in contents.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 8 || fields[1] != "00000000" {
                continue;
            }
            let Ok(flags) = u32::from_str_radix(fields[3], 16) else {
                continue;
            };
            if flags & 0x1 == 0 {
                continue;
            }
            let Ok(metric) = fields[6].parse::<u32>() else {
                continue;
            };
            metrics
                .entry(fields[0].to_owned())
                .and_modify(|current| *current = (*current).min(metric))
                .or_insert(metric);
        }
        metrics
    }

    fn is_physical_interface(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        if [
            "lo",
            "tun",
            "tap",
            "wg",
            "utun",
            "ppp",
            "docker",
            "br-",
            "veth",
            "virbr",
            "zt",
            "tailscale",
            "sing",
            "clash",
            "meta",
        ]
        .iter()
        .any(|prefix| lower == *prefix || lower.starts_with(prefix))
        {
            return false;
        }

        let type_path = format!("/sys/class/net/{name}/type");
        if fs::read_to_string(type_path)
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            == Some(1)
        {
            return true;
        }

        // Some Android builds expose interface addresses but restrict access
        // to /sys/class/net. Keep the usual Wi-Fi/Ethernet names usable in
        // that case, after the virtual-device exclusions above.
        ["eth", "en", "wlan", "wifi"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
            ||
        // Android cellular interfaces generally do not report ARPHRD_ETHER,
        // but they are real upstream links rather than proxy TUN devices.
        ["rmnet", "ccmni", "wwan"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
    }

    fn interface_kind_rank(name: &str) -> u8 {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("rmnet") || lower.starts_with("ccmni") || lower.starts_with("wwan") {
            1
        } else {
            0
        }
    }

    fn is_usable_ipv4(ip: Ipv4Addr) -> bool {
        !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local()
    }

    #[cfg(target_os = "android")]
    fn should_fallback_to_source_binding(error: &std::io::Error) -> bool {
        error.kind() == std::io::ErrorKind::PermissionDenied
    }

    #[derive(Clone, Copy, Debug, Default)]
    pub struct PlatformSocketBinder;

    impl OutboundSocketBinder for PlatformSocketBinder {
        fn configure(&self, socket: &TcpSocket, binding: &InterfaceBinding) -> Result<()> {
            if binding.if_name.is_empty() {
                anyhow::bail!("physical interface binding has no Linux interface name");
            }
            let name = CString::new(binding.if_name.as_bytes())
                .context("physical interface name contains NUL")?;
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    name.as_ptr().cast(),
                    (name.as_bytes_with_nul().len()) as libc::socklen_t,
                )
            };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                #[cfg(target_os = "android")]
                if should_fallback_to_source_binding(&error) {
                    tracing::debug!(
                        interface = %binding.if_name,
                        source = %binding.ip,
                        error = %error,
                        "SO_BINDTODEVICE unavailable; using source-address binding"
                    );
                    return Ok(());
                }

                return Err(error).with_context(|| {
                    format!(
                        "bind outbound socket to {} ({})",
                        binding.if_name, binding.ip
                    )
                });
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[cfg(target_os = "android")]
        #[test]
        fn enumerates_ipv4_interfaces_with_ioctl_without_proc_net_dev() {
            let interfaces = enumerate_interface_addresses().expect("enumerate interfaces");

            assert!(interfaces
                .iter()
                .any(|(name, ip)| name == "lo" && *ip == Ipv4Addr::LOCALHOST));
        }

        #[cfg(target_os = "android")]
        #[test]
        fn treats_bind_to_device_permission_error_as_source_binding_fallback() {
            let permission_denied = std::io::Error::from_raw_os_error(libc::EPERM);
            let missing_device = std::io::Error::from_raw_os_error(libc::ENODEV);

            assert!(should_fallback_to_source_binding(&permission_denied));
            assert!(!should_fallback_to_source_binding(&missing_device));
        }

        #[test]
        fn rejects_virtual_interface_names() {
            assert!(!is_physical_interface("tun0"));
            assert!(!is_physical_interface("sing-tun"));
            assert!(!is_physical_interface("wg0"));
        }

        #[test]
        fn recognizes_physical_and_cellular_name_fallbacks() {
            assert!(is_physical_interface("wlan0"));
            assert!(is_physical_interface("rmnet_data0"));
        }

        #[test]
        fn route_metrics_keep_the_lowest_default_route_metric() {
            let mut text =
                String::from("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n");
            text.push_str("wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n");
            text.push_str("wlan0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n");
            let path =
                std::env::temp_dir().join(format!("zerodpi-route-test-{}", std::process::id()));
            std::fs::write(&path, text).unwrap();
            let contents = std::fs::read_to_string(&path).unwrap();
            let mut metrics: HashMap<String, u32> = HashMap::new();
            for line in contents.lines().skip(1) {
                let fields: Vec<_> = line.split_whitespace().collect();
                let metric = fields[6].parse::<u32>().unwrap();
                metrics
                    .entry(fields[0].to_owned())
                    .and_modify(|current| *current = (*current).min(metric))
                    .or_insert(metric);
            }
            std::fs::remove_file(path).unwrap();
            assert_eq!(metrics.get("wlan0"), Some(&100));
        }
    }
}

pub use imp::{resolve_physical_binding, PlatformSocketBinder};

pub fn platform_socket_binder() -> Arc<dyn OutboundSocketBinder> {
    Arc::new(PlatformSocketBinder)
}
