//! Native event sources.

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::source;

#[cfg(windows)]
pub(crate) use windows_impl::source;

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
pub(crate) fn source() -> anyhow::Result<super::SourceParts<super::PollOnlySource>> {
    Ok(super::SourceParts {
        source: super::PollOnlySource,
        waker: std::sync::Arc::new(super::NoopWaker),
    })
}

#[cfg(windows)]
mod windows_impl {
    use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{HANDLE, WIN32_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, MibInitialNotification, NotifyIpInterfaceChange, NotifyRouteChange2,
        MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetMessageW, PeekMessageW, PostThreadMessageW, MSG, PM_NOREMOVE, WM_QUIT,
    };

    use zerodpi_core::net::NetworkChangeSource;

    use crate::netmon::{NetworkSource, NetworkWaker, SourceEvent, SourceParts};

    const ERROR_SUCCESS: WIN32_ERROR = 0;

    pub(crate) struct WindowsSource {
        rx: Receiver<NetworkChangeSource>,
    }

    impl NetworkSource for WindowsSource {
        fn wait(&mut self, timeout: Duration) -> SourceEvent {
            match self.rx.recv_timeout(timeout) {
                Ok(kind) => SourceEvent::Change(kind),
                Err(RecvTimeoutError::Timeout) => SourceEvent::Timeout,
                Err(RecvTimeoutError::Disconnected) => SourceEvent::Shutdown,
            }
        }
    }

    pub(crate) fn source() -> anyhow::Result<SourceParts<WindowsSource>> {
        let (tx, rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<u32, WIN32_ERROR>>();
        std::thread::Builder::new()
            .name("zerodpi-netmon-win".into())
            .spawn(move || notifier_thread(tx, ready_tx))?;
        let thread_id = ready_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("windows netmon thread exited during registration"))?
            .map_err(|code| {
                anyhow::anyhow!("windows network notification registration failed: {code}")
            })?;
        Ok(SourceParts {
            source: WindowsSource { rx },
            waker: Arc::new(WindowsWaker { thread_id }),
        })
    }

    struct WindowsWaker {
        thread_id: u32,
    }

    impl NetworkWaker for WindowsWaker {
        fn wake(&self) {
            unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0) };
        }
    }

    struct NotifyContext {
        tx: Mutex<Sender<NetworkChangeSource>>,
    }

    unsafe extern "system" fn on_interface_change(
        caller_context: *const core::ffi::c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        if notification_type == MibInitialNotification {
            return;
        }
        notify(caller_context, NetworkChangeSource::Address);
    }

    unsafe extern "system" fn on_route_change(
        caller_context: *const core::ffi::c_void,
        _row: *const MIB_IPFORWARD_ROW2,
        notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        if notification_type == MibInitialNotification {
            return;
        }
        notify(caller_context, NetworkChangeSource::Route);
    }

    fn notify(caller_context: *const core::ffi::c_void, source: NetworkChangeSource) {
        // The context outlives every callback: notifications are cancelled
        // before the box is dropped.
        let context = unsafe { &*(caller_context as *const NotifyContext) };
        if let Ok(tx) = context.tx.lock() {
            let _ = tx.send(source);
        }
    }

    fn notifier_thread(tx: Sender<NetworkChangeSource>, ready_tx: Sender<Result<u32, WIN32_ERROR>>) {
        let context = Box::into_raw(Box::new(NotifyContext { tx: Mutex::new(tx) }));
        let caller_context = context as *const core::ffi::c_void;
        let mut interface_handle: HANDLE = std::ptr::null_mut();
        let mut route_handle: HANDLE = std::ptr::null_mut();

        let interface_result = unsafe {
            NotifyIpInterfaceChange(
                AF_INET,
                Some(on_interface_change),
                caller_context,
                false,
                &mut interface_handle,
            )
        };
        if interface_result != ERROR_SUCCESS {
            unsafe { drop(Box::from_raw(context)) };
            let _ = ready_tx.send(Err(interface_result));
            return;
        }

        let route_result = unsafe {
            NotifyRouteChange2(
                AF_INET,
                Some(on_route_change),
                caller_context,
                false,
                &mut route_handle,
            )
        };
        if route_result != ERROR_SUCCESS {
            unsafe { CancelMibChangeNotify2(interface_handle) };
            unsafe { drop(Box::from_raw(context)) };
            let _ = ready_tx.send(Err(route_result));
            return;
        }

        // Force creation of this thread's message queue before publishing the
        // thread id, so an early wake cannot be lost.
        let mut msg: MSG = unsafe { std::mem::zeroed() };
        unsafe { PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_NOREMOVE) };
        let thread_id = unsafe { GetCurrentThreadId() };
        let _ = ready_tx.send(Ok(thread_id));

        loop {
            let result = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
            if result <= 0 {
                break;
            }
        }

        unsafe { CancelMibChangeNotify2(interface_handle) };
        unsafe { CancelMibChangeNotify2(route_handle) };
        unsafe { drop(Box::from_raw(context)) };
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::time::Duration;

    use crate::netmon::{NetworkSource, SourceEvent};

    use super::source;

    #[test]
    fn notifier_shutdown_is_prompt() {
        let parts = source().expect("start windows notification source");
        let mut source = parts.source;
        // Wait briefly so registration is live before shutdown.
        std::thread::sleep(Duration::from_millis(50));
        parts.waker.wake();
        let started = std::time::Instant::now();
        let event = source.wait(Duration::from_secs(5));
        assert!(matches!(event, SourceEvent::Shutdown));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result};

    use crate::netmon::{classify_nlmsg, NetworkSource, NetworkWaker, SourceEvent, SourceParts};

    const NETLINK_ROUTE: i32 = 0;
    const RTMGRP_LINK: u32 = 1;
    const RTMGRP_IPV4_IFADDR: u32 = 0x10;
    const RTMGRP_IPV4_ROUTE: u32 = 0x40;

    pub(crate) fn source() -> Result<SourceParts<NetlinkSource>> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("open netlink route socket");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
        let bind_result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bind_result < 0 {
            return Err(io::Error::last_os_error()).context("bind netlink route socket");
        }

        let (wake_read, wake_write) = wake_pipe()?;
        let stop = Arc::new(AtomicBool::new(false));
        Ok(SourceParts {
            source: NetlinkSource {
                fd,
                wake_read,
                stop: stop.clone(),
            },
            waker: Arc::new(PipeWaker {
                fd: wake_write,
                stop,
            }),
        })
    }

    fn wake_pipe() -> Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0 as RawFd; 2];
        let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if result < 0 {
            return Err(io::Error::last_os_error()).context("create netmon wake pipe");
        }
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Ok((read, write))
    }

    pub(crate) struct NetlinkSource {
        fd: OwnedFd,
        wake_read: OwnedFd,
        stop: Arc<AtomicBool>,
    }

    impl NetworkSource for NetlinkSource {
        fn wait(&mut self, timeout: Duration) -> SourceEvent {
            if self.stop.load(Ordering::SeqCst) {
                return SourceEvent::Shutdown;
            }
            let mut fds = [
                libc::pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.wake_read.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
            let polled = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    return SourceEvent::Timeout;
                }
                tracing::debug!(%error, "netlink poll failed");
                return SourceEvent::Timeout;
            }
            if fds[1].revents != 0 {
                let mut byte = [0u8; 1];
                unsafe {
                    libc::read(
                        self.wake_read.as_raw_fd(),
                        byte.as_mut_ptr() as *mut libc::c_void,
                        1,
                    )
                };
                return SourceEvent::Shutdown;
            }
            if fds[0].revents & libc::POLLIN == 0 {
                return SourceEvent::Timeout;
            }
            self.drain()
        }
    }

    impl NetlinkSource {
        fn drain(&mut self) -> SourceEvent {
            let mut buf = [0u8; 8192];
            loop {
                let read = unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                if read <= 0 {
                    return SourceEvent::Timeout;
                }
                let mut offset = 0usize;
                let total = read as usize;
                while offset + 16 <= total {
                    let msg_type = u16::from_ne_bytes([buf[offset + 4], buf[offset + 5]]);
                    if let Some(kind) = classify_nlmsg(msg_type) {
                        return SourceEvent::Change(kind);
                    }
                    let len = u32::from_ne_bytes([
                        buf[offset],
                        buf[offset + 1],
                        buf[offset + 2],
                        buf[offset + 3],
                    ]) as usize;
                    if len < 16 || offset + len > total {
                        break;
                    }
                    offset += len;
                }
            }
        }
    }

    struct PipeWaker {
        fd: OwnedFd,
        stop: Arc<AtomicBool>,
    }

    impl NetworkWaker for PipeWaker {
        fn wake(&self) {
            self.stop.store(true, Ordering::SeqCst);
            let byte = [1u8; 1];
            unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    byte.as_ptr() as *const libc::c_void,
                    1,
                )
            };
        }
    }
}
