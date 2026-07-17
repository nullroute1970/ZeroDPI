# Android Privilege Separation

Full Android builds use two native processes for interception-based modes.
The ordinary `zerodpi` data plane always runs as the application UID. A
separate `zerodpi-root-helper` is started through `su` and owns only firewall,
NFQUEUE, packet-handler, and helper-side flow-table work. There is no
production fallback that starts the complete data plane as root.

## Trust boundary

The application-UID data plane owns configuration parsing, DNS, scanners,
local listeners, upstream TCP/UDP sockets, proxy tests, and relaying. The root
helper must not resolve names, download configuration, open Internet sockets,
or accept commands, executable names, shell fragments, or firewall arguments
over IPC.

The helper accepts one filesystem Unix-domain socket connection in a fresh
0700 app-owned runtime directory. The 32-byte session proof is stored in an
app-owned 0600 file and is never put on the command line or in logs. Both
processes validate the socket and proof ownership. Both sides authenticate
the other with kernel `SO_PEERCRED`; the helper requires the configured app UID
and matching data-plane PID, while the data plane requires helper UID 0 and a
matching helper PID. The data plane also verifies its real, effective, and
saved UIDs all equal the Android app UID.

## Protocol and lifecycle

The stream protocol has a fixed 20-byte big-endian header (`ZDHP`, major and
minor version, message type, flags, request ID, and payload length). Frames
are limited to 256 KiB, fake flow data to 64 KiB, live flows to 4096, and
outstanding client requests to 1024. Version 1 rejects nonzero reserved flags,
unknown messages, malformed fields, incompatible versions, illegal state
transitions, truncated frames, and oversized declared lengths.

The lifecycle is `Created -> Authenticated -> Configured -> InterceptorOpen`.
The helper acknowledges interceptor readiness only after firewall/NFQUEUE
setup succeeds. It acknowledges each flow registration before the data plane
starts the upstream TCP connect. Closing returns to `Configured`; shutdown or
control-socket loss requests the interceptor thread to stop, joins it, and
drops its firewall guard. A heartbeat bounds detection of a stalled control
plane.

`proxy_scan` performs an acknowledged configure/open/test/close cycle for each
candidate. Normal interception modes keep one helper interceptor open for the
proxy lifetime. Rootless modes and `tls_frag` do not start or connect to the
helper.

## Firewall ownership and recovery

Helper iptables rules carry an internal `zerodpi-<helper-pid>` comment.
Helper nftables tables use `zerodpi_<helper-pid>_<counter>`. On authenticated
configuration, the helper lists only the selected backend's state. It removes
matching state whose PID no longer names a ZeroDPI helper and refuses to start
when a live helper owns matching state. Untagged rules and unrelated tables
are never recovery targets. Partial iptables installation is rolled back, and
all cleanup paths are idempotent.

SIGKILL cannot execute in-process cleanup. Such a stop is reported as
unconfirmed; the next authenticated start performs the targeted recovery
above. Device reboot behavior remains controlled by the device firewall
implementation and must be covered by rooted-device acceptance tests.

## Socket ownership audit

| Socket category | Owner |
|---|---|
| SNI/IP/proxy scanner TCP and UDP | App-UID data plane |
| DNS and interface discovery | App-UID data plane |
| Local proxy listener and relay sockets | App-UID data plane |
| Helper control Unix socket | Root helper, chowned/mode-limited to app UID |
| NFQUEUE/netlink | Root helper |

Rooted release validation must inspect `/proc/<pid>/fd` while scanning and
relaying to confirm that the helper has no Internet TCP or UDP descriptors.

## Compatibility unit

The Android controller, `libzerodpi_exec.so`,
`libzerodpi_root_helper_exec.so`, and helper protocol major version are one
compatibility unit. Full APKs contain both ABI-matched native artifacts;
rootless APKs omit the helper. A missing artifact or protocol mismatch fails
closed before packet rules or upstream connections are opened.
