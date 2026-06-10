//! Platform packet-interception backends.
//!
//! Pick the right backend at compile time:
//! - on Linux/Android: [`linux::NfqInterceptor`]
//! - on Windows: [`windows::WinDivertInterceptor`]
//!
//! Both implement [`zerodpi_core::interceptor::PacketInterceptor`].

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod linux;
#[cfg(windows)]
pub mod windows;

use anyhow::Result;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::NfqInterceptor as DefaultInterceptor;

#[cfg(windows)]
pub use windows::WinDivertInterceptor as DefaultInterceptor;

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
compile_error!("zerodpi-platform: no interceptor backend for this target OS");

/// Return an actionable startup error when the current process cannot use the
/// platform packet interception backend.
pub fn ensure_packet_interception_access() -> Result<()> {
    if has_packet_interception_access() {
        return Ok(());
    }

    anyhow::bail!("{}", packet_interception_access_error())
}

#[cfg(windows)]
fn packet_interception_access_error() -> &'static str {
    "ZeroDPI needs Administrator privileges for packet interception via WinDivert. \
     Start PowerShell or Command Prompt with \"Run as administrator\" and run ZeroDPI again. \
     To run without Administrator privileges, use BYPASS_METHOD = \"tls_frag\" \
     or MODE = \"ip_bypass\"."
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn packet_interception_access_error() -> &'static str {
    "ZeroDPI needs root privileges or CAP_NET_ADMIN for packet interception via NFQUEUE. \
     Run ZeroDPI with sudo/root, grant CAP_NET_ADMIN to the binary, or use \
     BYPASS_METHOD = \"tls_frag\" or MODE = \"ip_bypass\"."
}

#[cfg(windows)]
fn has_packet_interception_access() -> bool {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr::null_mut;

    type Bool = i32;
    type Dword = u32;
    type Handle = *mut c_void;

    const TOKEN_QUERY: Dword = 0x0008;
    const TOKEN_ELEVATION_CLASS: Dword = 20;

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: Dword,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            process_handle: Handle,
            desired_access: Dword,
            token_handle: *mut Handle,
        ) -> Bool;
        fn GetTokenInformation(
            token_handle: Handle,
            token_information_class: Dword,
            token_information: *mut c_void,
            token_information_length: Dword,
            return_length: *mut Dword,
        ) -> Bool;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn CloseHandle(object: Handle) -> Bool;
    }

    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation = TokenElevation {
            token_is_elevated: 0,
        };
        let mut return_length = 0;
        let ok = GetTokenInformation(
            token,
            TOKEN_ELEVATION_CLASS,
            &mut elevation as *mut TokenElevation as *mut c_void,
            size_of::<TokenElevation>() as Dword,
            &mut return_length,
        ) != 0;
        let _ = CloseHandle(token);

        ok && elevation.token_is_elevated != 0
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn has_packet_interception_access() -> bool {
    extern "C" {
        fn geteuid() -> u32;
    }

    (unsafe { geteuid() == 0 }) || has_effective_cap_net_admin()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn has_effective_cap_net_admin() -> bool {
    effective_capabilities_from_status("/proc/self/status")
        .map(|caps| caps & (1_u64 << 12) != 0)
        .unwrap_or(false)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn effective_capabilities_from_status(path: &str) -> Option<u64> {
    let status = std::fs::read_to_string(path).ok()?;
    status.lines().find_map(parse_effective_capabilities_line)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_effective_capabilities_line(line: &str) -> Option<u64> {
    let value = line.strip_prefix("CapEff:")?.trim();
    u64::from_str_radix(value, 16).ok()
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::parse_effective_capabilities_line;

    #[test]
    fn parses_effective_capabilities_line() {
        assert_eq!(
            parse_effective_capabilities_line("CapEff:\t0000000000001000"),
            Some(1 << 12)
        );
    }

    #[test]
    fn ignores_non_effective_capabilities_line() {
        assert_eq!(
            parse_effective_capabilities_line("CapPrm:\t0000000000001000"),
            None
        );
    }
}
