# Physical uplink binding implementation plan

> This plan implements the approved design in
> `docs/superpowers/specs/2026-09-25-physical-uplink-binding-design.md`.

## Outcome

ZeroDPI will resolve a non-virtual physical uplink on Windows, Linux, and
Android, carry its address and interface identity through runtime recovery,
and enforce that binding on every ZeroDPI-created outbound TCP socket. A
sing-box TUN route or address will not replace the physical binding.

## 1. Add shared binding and socket-configuration contracts

Files:

- `crates/zerodpi-core/src/net.rs`
- `crates/zerodpi-core/src/lib.rs` if exports need updating

Changes:

1. Replace the IP-only watch state with an `InterfaceBinding` containing the
   IPv4 address, interface index, and interface name needed by the target OS.
2. Replace `InterfaceIp`/`InterfaceIpHandle` and
   `interface_ip_channel` with binding equivalents, preserving cheap cloned
   read handles and atomic watch updates.
3. Add an `OutboundSocketBinder` trait implemented by the platform crate. The
   trait receives a `tokio::net::TcpSocket` and an `InterfaceBinding` and must
   configure the platform-specific egress constraint before connect.
4. Add a shared bound-connect helper that creates an IPv4 `TcpSocket`, invokes
   the binder, binds the selected local IPv4 address, and connects to the
   target. It will be the only normal path for ZeroDPI-generated IPv4 TCP
   connections.
5. Keep a deliberately explicit no-op binder for isolated core tests only;
   production entry points must construct the platform binder.
6. Update unit tests for watch updates, fixed bindings, full-binding equality,
   and the bound-connect helper using a local test listener.

## 2. Implement physical-uplink discovery and socket enforcement

Files:

- `crates/zerodpi-platform/src/uplink.rs` (new)
- `crates/zerodpi-platform/src/lib.rs`
- `crates/zerodpi-platform/Cargo.toml` if an OS API dependency is needed

Changes:

1. Add a public resolver such as `resolve_physical_binding(target)` and a
   platform binder constructor.
2. On Windows, enumerate adapter/address metadata through IP Helper APIs,
   accept operational Ethernet and IEEE 802.11 adapters with usable IPv4
   addresses, reject TUN/Wintun/loopback/virtual adapters, and select the
   physical candidate with the best usable route to the target.
3. On Linux and Android, use native interface/address and route metadata to
   select an operational Wi-Fi/Ethernet uplink. Permit a real cellular uplink
   when it is the only usable Android upstream, while rejecting loopback,
   TUN/TAP, WireGuard, container, and other virtual interfaces.
4. Implement `OutboundSocketBinder` for Windows with the IPv4 unicast
   interface socket option and the selected interface index.
5. Implement it for Linux/Android with the native interface-binding socket
   option and selected interface name. Preserve the existing privilege model
   (WinDivert administrator access or Linux/Android root/CAP access).
6. Fail closed with an actionable error if no physical binding exists or if
   the interface-level socket option cannot be applied; do not silently fall
   back to ordinary route selection.
7. Keep OS-specific discovery and socket calls in this platform module. Add
   pure helper tests for interface-type classification, virtual-interface
   rejection, candidate ordering, and error formatting.

## 3. Make network monitoring and recovery binding-aware

Files:

- `crates/zerodpi-platform/src/netmon/mod.rs`
- `crates/zerodpi/src/network_recovery.rs`
- `crates/zerodpi/src/data_plane.rs`
- `crates/zerodpi-core/src/interceptor.rs` if `FilterSpec` needs binding
  metadata
- `crates/zerodpi-root-helper/src/unix.rs` if the filter contract changes

Changes:

1. Change `ChangeFilter`, `run_loop`, and `NetworkMonitor::start` to compare
   `Option<InterfaceBinding>` rather than only `Option<Ipv4Addr>`.
2. Make the monitor probe use the platform physical-uplink resolver instead of
   `default_interface_ipv4`. A notification caused only by sing-box's TUN
   route must be ignored when the physical binding is unchanged.
3. Update `RecoveryEnv`, `MainRecoveryEnv`, and the recovery coordinator to
   probe, rebuild, publish, and apply complete bindings. Keep the public TUI
   network event text based on the binding's IPv4 address for compatibility.
4. Change `DataPlane::rebuild` and `interceptor_filter` to accept a binding;
   use its physical IPv4 address for packet matching and retain interface
   identity where the platform backend can enforce it.
5. Ensure local and remote data-plane rebuilds apply the new binding before
   accepting new flows, and that a same-IP/different-interface change is not
   lost.
6. Update recovery tests for TUN-only probe results, physical address changes,
   same-address interface changes, and failed physical-interface resolution.

## 4. Route every proxy-generated connection through the bound helper

Files:

- `crates/zerodpi-core/src/proxy.rs`
- `crates/zerodpi-core/src/low_ttl_discover.rs`
- `crates/zerodpi/src/main.rs`

Changes:

1. Change `run_proxy`, `run_ip_bypass_plus_proxy`, and
   `run_ip_bypass_proxy` to receive the binding watch and platform binder.
2. Update `handle_intercept_connection` to use the complete binding and the
   bound-connect helper before flow registration/connect.
3. Fix the socket-only TLS-fragment path, which currently bypasses the
   interface handle, by snapshotting the current binding before spawning the
   connection task.
4. Replace direct upstream `TcpStream::connect` calls in IP bypass and other
   proxy paths with the bound helper. IPv4-only paths must fail explicitly for
   an unsupported target instead of leaking through an unbound connection.
5. Update low-TTL discovery to bind every probe to the physical binding and
   include the same source address in its flow key.
6. Construct the platform binder once in each CLI runtime and pass it to all
   proxy modes. Resolve the initial binding before opening the interceptor or
   accepting proxy work.

## 5. Cover scanners, candidate tests, and probes

Files:

- `crates/zerodpi-core/src/ip_scanner.rs`
- `crates/zerodpi-core/src/sni_scanner.rs`
- `crates/zerodpi-core/src/method_scanner.rs`
- `crates/zerodpi-core/src/proxy_tester.rs`
- `crates/zerodpi/src/main.rs`

Changes:

1. Add the binding/binder context to scanner and proxy-test entry points.
2. Replace their raw `TcpStream::connect` calls with the shared bound-connect
   helper, including SNI probes, IP probes, method scans, SOCKS5 probes, and
   candidate validation.
3. Pass the current physical binding into proxy-test `FilterSpec` and fixed
   test handles, so scans cannot accidentally rediscover the sing-box TUN.
4. Ensure startup scan modes resolve a physical binding before launching
   concurrent probes and report a clear error if it is unavailable.
5. Keep test-only APIs usable with a local no-op binder and loopback binding;
   no unit test may require a real Wi-Fi/Ethernet adapter.

## 6. Update all callers and remove the old route-derived contract

Files:

- `crates/zerodpi/src/main.rs`
- `crates/zerodpi/src/network_recovery.rs`
- `crates/zerodpi/src/data_plane.rs`
- all core call sites found by `rg` for `InterfaceIp`,
  `default_interface_ipv4`, and raw outbound `TcpStream::connect`

Changes:

1. Replace startup calls to `default_interface_ipv4` with the platform
   physical resolver for normal runtime and scan modes.
2. Update both SNI-spoof and IP-bypass-plus startup/recovery wiring, including
   monitor seeds and target-probe closures.
3. Audit every remaining `TcpStream::connect` and `TcpSocket::new_v4` in
   production code. Each outbound ZeroDPI connection must use the binding
   helper or an explicitly documented control-plane exception.
4. Retain `default_interface_ipv4` only where it is still valid as a generic
   non-runtime utility, or remove it after all callers are migrated.
5. Correct stale comments and the TUI network label if needed so they describe
   a physical binding rather than a kernel-selected default address.

## 7. Test and verify incrementally

After each logical group:

1. Run focused core/platform tests for binding state, resolver helpers,
   network-monitor filtering, and recovery behavior.
2. Run `cargo fmt --all -- --check`.
3. Run `cargo test --workspace`.
4. Run `cargo clippy --workspace --all-targets -- -D warnings`.
5. Build the Windows release target and, where available, Linux/Android
   targets to catch conditional-compilation errors.

Runtime verification on the affected Windows setup:

1. Keep sing-box TUN `auto_route` enabled.
2. Start ZeroDPI and confirm its network status remains the Wi-Fi/Ethernet IP,
   not `172.19.0.1`.
3. Create new proxy connections after sing-box starts and inspect local
   addresses and interface selection; none may use the TUN address.
4. Trigger a TUN-only route change and confirm no false ZeroDPI rebuild.
5. Disable/re-enable the physical adapter and confirm recovery selects the new
   physical binding and new connections recover.

## Risks and mitigations

- Native interface discovery differs across Linux distributions and Android;
  isolate it behind small OS-specific functions and test classification with
  synthetic records.
- Interface-level socket binding can fail without the required privilege;
  fail closed with a clear error rather than silently using the TUN route.
- The API change touches proxy, scanners, recovery, and packet interception;
  migrate the shared binding type first, then compile after each group.
- Existing TCP sockets cannot be rebound; document and verify that the
  guarantee applies to new connections and that recovery handles future flows.
