# Physical uplink binding for ZeroDPI

## Status

Design approved by the user. Implementation is pending a plan review.

## Problem

ZeroDPI currently derives a single IPv4 address by asking the kernel which source
address it would use for a UDP socket. When sing-box installs an automatic TUN
route, that query can return the sing-box TUN address (`172.19.0.1`) instead of
the address assigned to the physical uplink. The value is then reused for
outbound TCP binding, interception filters, and network recovery.

This creates two problems:

1. New ZeroDPI connections can be bound to the sing-box TUN instead of the
   physical Wi-Fi/Ethernet uplink.
2. A TUN route notification can cause ZeroDPI to rebuild around the wrong
   address and keep making the same choice.

The fix must apply on Windows, Linux, and Android. Existing non-targeted
platform behavior should remain unchanged.

## Goals

- Select an active, non-virtual physical uplink for ZeroDPI's own outbound
  traffic.
- Never select a TUN, TAP, WireGuard, loopback, container, or other virtual
  interface as the ZeroDPI uplink.
- Enforce the selected interface at socket level, not only by choosing a local
  source address.
- Use the same binding for all ZeroDPI-generated connections: proxy relays,
  SNI/IP bypass paths, scanners, probes, and low-TTL discovery.
- Keep WinDivert/NFQUEUE flow matching and recovery consistent with the selected
  physical binding.
- Ignore sing-box TUN-only route changes when the physical binding has not
  changed.
- Make a failure to enforce the physical binding explicit instead of silently
  falling back to a TUN route.

## Non-goals

- Do not modify sing-box configuration automatically.
- Do not change the user's final proxy routing policy.
- Do not force all Android traffic through Wi-Fi when the device has no Wi-Fi;
  an available real cellular uplink may be used as the physical upstream where
  the platform exposes one.
- Do not change existing connections in place. A binding change affects new
  connections; recovery may close/rebuild flows through the existing recovery
  mechanism.

## Proposed design

### 1. Replace the IP-only network state

Introduce a platform-neutral `InterfaceBinding` value containing at least:

- IPv4 address used for the local bind;
- numeric interface index;
- interface name where the platform requires a name for socket binding.

The watch channel, recovery environment, data-plane filter specification,
network monitor, proxy code, and low-TTL discovery will carry this binding
instead of only `Ipv4Addr`. The binding remains copyable and cheap to read for
each accepted connection.

The TUI will continue to display the binding's IPv4 address, but that value
will now represent the physical uplink selected by the resolver.

### 2. Add a physical-uplink resolver per supported OS

The resolver will not use the process's ordinary default-route source selection
because that is precisely what sing-box changes.

- Windows: use IP Helper data and route/interface metadata to select an
  operational Ethernet or IEEE 802.11 adapter with a usable IPv4 address. TUN,
  Wintun, loopback, and other virtual adapters are rejected.
- Linux/Android: enumerate interface/address/link data and the non-virtual
  uplink route using native OS interfaces. Prefer operational Wi-Fi/Ethernet
  interfaces; permit a real cellular uplink on Android when it is the only
  usable physical upstream. TUN/TAP/WireGuard/loopback/container interfaces
  are rejected.

When multiple physical uplinks are available, choose the one with the best
usable route to the target, with stable interface/address tie-breaking. The
resolver must return both the address and the interface identity so later
socket operations do not have to rediscover it.

### 3. Enforce the binding on every outbound socket

Centralize creation/configuration of ZeroDPI outbound TCP sockets so all call
paths apply the same binding before `connect`:

- bind the local socket to `InterfaceBinding.ip`;
- Windows: set the IPv4 unicast interface socket option using the selected
  interface index;
- Linux/Android: bind the socket to the selected interface using the native
  interface-binding socket option and the selected interface name;
- then connect to the target.

The common core will expose the binding data and a socket-binding abstraction;
platform-specific socket-option implementations will live in the platform
crate. This keeps OS-specific system calls out of the shared proxy logic while
ensuring the core cannot accidentally bypass the binding by calling a raw
`TcpStream::connect` path.

If the platform cannot enforce the selected interface, the connection attempt
will fail with a clear error. It must not silently retry through the kernel's
possibly TUN-backed default route.

### 4. Apply the binding consistently to interception and recovery

- Proxy relay paths will use the centralized bound-connect helper.
- SNI spoof, IP bypass, TLS fragmentation, scanners, probes, and low-TTL
  discovery will use the same helper or equivalent platform binder.
- WinDivert and NFQUEUE filter construction will use the physical binding's
  address/interface identity.
- Recovery will compare complete bindings, not only an IPv4 string, so an
  interface change with the same address is detected.
- Network-monitor callbacks will resolve physical uplink state. Notifications
  caused only by sing-box's TUN route will produce no rebuild when the physical
  binding is unchanged.

### 5. Failure and lifecycle behavior

- If no usable physical uplink exists, startup/recovery reports a clear
  `physical interface unavailable` error and does not start new outbound
  connections.
- If the physical interface changes, the existing recovery coordinator rebuilds
  interception state and publishes the new binding before accepting new work.
- Existing TCP sockets are not rebound; they are handled by the current flow
  lifecycle and recovery behavior.
- Shutdown and cancellation behavior remains unchanged.

## Alternatives considered

### Route exclusions only

Adding host routes or sing-box process rules is smaller, but it depends on
external route state, does not guarantee the source address chosen by every
ZeroDPI socket, and is fragile when target IPs or interfaces change. It is not
sufficient for the requirement.

### Bind only to the physical IPv4 address

This prevents the TUN address from appearing as the local source in common
cases, but source binding alone does not guarantee the selected egress
interface on every OS or policy-routing setup. The interface-level socket
option is required for a reliable fix.

## Verification strategy

- Unit-test physical-interface classification and selection, including explicit
  rejection of TUN/virtual records and acceptance of Wi-Fi/Ethernet records.
- Unit-test binding equality/change detection for address and interface index.
- Unit-test that every outbound connection helper receives a binding.
- Add platform-specific tests for socket option setup where the OS test
  environment permits it; otherwise keep the low-level option code small and
  validate it with a Windows/Linux/Android smoke test.
- With sing-box `auto_route` active, start ZeroDPI and verify that the TUI and
  logs show the physical IP, not `172.19.0.1`.
- Create new ZeroDPI connections after sing-box starts and inspect their local
  addresses/interfaces; none may use the sing-box TUN address.
- Exercise a physical adapter change and verify recovery selects the new
  physical binding while a TUN-only route notification does not trigger a
  false rebuild.
- Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets
  -- -D warnings`, and `cargo test --workspace`.

## Self-review

- The design covers the user's Windows, Linux, and Android requirement.
- It fixes both incorrect source-address selection and incorrect egress
  interface selection.
- It covers direct-connect paths as well as the interception path, avoiding a
  partial fix.
- It avoids automatic edits to sing-box configuration.
- It explicitly handles the fact that existing sockets cannot be rebound.
- The main implementation risk is platform socket-option and interface
  discovery API variation; that risk is isolated behind the platform binding
  abstraction and covered by targeted smoke tests.
