//! Owned WinDivert handle with shared receive shutdown and explicit close.
//!
//! windivert 0.6 neither closes its handle on Drop nor exposes shared shutdown.
//! Keep packet/address helpers, but own the native handle here so an idle recv
//! can be interrupted without racing a close against capture or send workers.

use std::borrow::Cow;
use std::ffi::CString;

use anyhow::{Context, Result};
use windivert::address::WinDivertAddress;
use windivert::layer::NetworkLayer;
use windivert::prelude::{WinDivertFlags, WinDivertPacket};
use windivert_sys::{WinDivertLayer, WinDivertShutdownMode};
use windivert_windows::Win32::Foundation::HANDLE as WinDivertHandle;
use windows::Win32::Foundation::HANDLE;

// WinDivert's published FFI uses windows 0.48's integer HANDLE, while current
// windows bindings wrap a pointer. This is an opaque OS token, never a Rust
// memory address to dereference. Retain its integer representation so existing
// capture/send/shutdown workers can share it without unsafe Send/Sync impls.
#[derive(Clone, Copy)]
struct HandleValue(isize);

impl HandleValue {
    fn from_windivert(handle: WinDivertHandle) -> Self {
        Self(handle.0)
    }

    fn as_windows(self) -> HANDLE {
        HANDLE(self.0 as *mut std::ffi::c_void)
    }

    fn as_windivert(self) -> WinDivertHandle {
        WinDivertHandle(self.0)
    }
}

pub(super) struct DivertHandle(Option<HandleValue>);

impl DivertHandle {
    pub fn network(filter: impl AsRef<str>, priority: i16, flags: WinDivertFlags) -> Result<Self> {
        let filter = CString::new(filter.as_ref())?;
        // SAFETY: filter is NUL-terminated and lives through the native call.
        let handle = unsafe {
            windivert_sys::WinDivertOpen(filter.as_ptr(), WinDivertLayer::Network, priority, flags)
        };
        let handle = HandleValue::from_windivert(handle);
        if handle.as_windows().is_invalid() {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(Some(handle)))
    }

    pub fn recv<'a>(&self, buffer: &'a mut [u8]) -> Result<WinDivertPacket<'a, NetworkLayer>> {
        let mut length = 0;
        let capacity = buffer
            .len()
            .try_into()
            .context("capture buffer too large")?;
        // SAFETY: the zeroed address is filled by WinDivert before being used.
        let mut address = unsafe { WinDivertAddress::<NetworkLayer>::new() };
        // SAFETY: all output pointers refer to writable storage of the stated
        // sizes. This handle remains owned throughout the blocking call.
        let received = unsafe {
            windivert_sys::WinDivertRecv(
                self.0.unwrap().as_windivert(),
                buffer.as_mut_ptr().cast(),
                capacity,
                &mut length,
                address.as_mut(),
            )
        };
        if !received.as_bool() {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(WinDivertPacket {
            address,
            data: Cow::Borrowed(&buffer[..length as usize]),
        })
    }

    pub fn send(&self, packet: &WinDivertPacket<'_, NetworkLayer>) -> Result<u32> {
        let mut length = 0;
        let size = packet.data.len().try_into().context("packet too large")?;
        // SAFETY: WinDivert reads the packet/address only during this call.
        let sent = unsafe {
            windivert_sys::WinDivertSend(
                self.0.unwrap().as_windivert(),
                packet.data.as_ptr().cast(),
                size,
                &mut length,
                packet.address.as_ref(),
            )
        };
        if !sent.as_bool() {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(length)
    }

    pub fn shutdown_recv(&self) -> Result<()> {
        // SAFETY: WinDivert supports receive shutdown concurrently with recv.
        // Closing is deferred until every user of this handle has been joined.
        let stopped = unsafe {
            windivert_sys::WinDivertShutdown(
                self.0.unwrap().as_windivert(),
                WinDivertShutdownMode::Recv,
            )
        };
        if !stopped.as_bool() {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    pub fn close(mut self) -> Result<()> {
        // SAFETY: ownership is exclusive here; all capture/send users are gone.
        let closed = unsafe { windivert_sys::WinDivertClose(self.0.unwrap().as_windivert()) };
        if !closed.as_bool() {
            return Err(std::io::Error::last_os_error().into());
        }
        self.0 = None;
        Ok(())
    }
}

impl Drop for DivertHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            // SAFETY: this is the last owner, including on partial startup.
            if !unsafe { windivert_sys::WinDivertClose(handle.as_windivert()) }.as_bool() {
                tracing::warn!(error = %std::io::Error::last_os_error(), "close WinDivert handle failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windivert_windows::Win32::Foundation::HANDLE as WinDivertHandle;

    #[test]
    fn handle_values_preserve_all_bits_across_windows_versions() {
        for raw in [0, 1, 0x1234, isize::MAX, isize::MIN, -1] {
            let handle = HandleValue::from_windivert(WinDivertHandle(raw));
            assert_eq!(handle.as_windows().0 as isize, raw);
            assert_eq!(handle.as_windivert().0, raw);
        }
    }

    #[test]
    fn invalid_handle_checks_match_the_windivert_bindings() {
        for (raw, invalid) in [(0, true), (-1, true), (1, false), (0x1234, false)] {
            let legacy = WinDivertHandle(raw);
            let handle = HandleValue::from_windivert(legacy);
            assert_eq!(handle.as_windows().is_invalid(), invalid);
            assert_eq!(handle.as_windows().is_invalid(), legacy.is_invalid());
        }
    }

    #[test]
    fn handle_owner_can_be_shared_with_capture_and_shutdown_workers() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DivertHandle>();
        assert_send_sync::<std::sync::Arc<DivertHandle>>();
    }
}
