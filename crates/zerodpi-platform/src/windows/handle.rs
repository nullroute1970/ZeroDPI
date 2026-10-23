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
use windows::Win32::Foundation::HANDLE;

pub(super) struct DivertHandle(Option<HANDLE>);

impl DivertHandle {
    pub fn network(filter: impl AsRef<str>, priority: i16, flags: WinDivertFlags) -> Result<Self> {
        let filter = CString::new(filter.as_ref())?;
        // SAFETY: filter is NUL-terminated and lives through the native call.
        let handle = unsafe {
            windivert_sys::WinDivertOpen(filter.as_ptr(), WinDivertLayer::Network, priority, flags)
        };
        if handle.is_invalid() {
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
                self.0.unwrap(),
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
                self.0.unwrap(),
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
            windivert_sys::WinDivertShutdown(self.0.unwrap(), WinDivertShutdownMode::Recv)
        };
        if !stopped.as_bool() {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    pub fn close(mut self) -> Result<()> {
        // SAFETY: ownership is exclusive here; all capture/send users are gone.
        let closed = unsafe { windivert_sys::WinDivertClose(self.0.unwrap()) };
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
            if !unsafe { windivert_sys::WinDivertClose(handle) }.as_bool() {
                tracing::warn!(error = %std::io::Error::last_os_error(), "close WinDivert handle failed");
            }
        }
    }
}
