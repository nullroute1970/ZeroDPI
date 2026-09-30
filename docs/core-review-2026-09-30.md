# Core stability and performance review

Reviewed and updated `zerodpi-core` against baseline commit `fd74cb1`.
The work focuses on connection lifetime, flow registration and signalling,
scanner scheduling, HTTP sampling, and configuration validation. Existing
packet construction and bypass-method tests were also run across the workspace.

## Corrections

| Area | Previous failure | Result |
| --- | --- | --- |
| Configuration | Zero concurrency could stall scanners; excessive semaphore capacities could panic. | Reject capacities outside `1..=Semaphore::MAX_PERMITS`. |
| Scoring configuration | Zero, negative, NaN, and infinite latency caps produced invalid scoring inputs. | Reject non-positive or non-finite caps for both scanner and proxy-test latency metrics. |
| Flow registration | Registering the same key silently replaced an active flow. | Atomically reject duplicates and preserve the original entry. |
| Bypass signalling | The intercept thread could call `notify_waiters` between the state check and subscription, causing an unnecessary timeout. | Construct notification futures before checking state in the proxy and TTL discovery waits. |
| Proxy cancellation | Aborting a listener left its accepted connection tasks running. | All three proxy listeners own and reap their workers through `JoinSet`; cancellation aborts them. |
| Relay cancellation | Copy workers and the progress ticker outlived a cancelled relay and retained sockets. | Poll copy futures and progress reporting inside the connection task. |
| Relay errors | One direction could fail while the other direction waited indefinitely. | End the relay immediately on an I/O error; preserve normal TCP half-close responses. |
| Scanner cancellation and scheduling | Detached probes continued after scan cancellation; a task was allocated for every candidate. SNI DNS fanout was not bounded. | Own workers through `JoinSet`, bound task creation, bound concurrent DNS work, and apply backpressure between IP scan phases. |
| IP scoring | Failure to reconnect for TLS discarded the successful TCP phase's score. | Retain and score the TCP-only result consistently. |
| Download timeout | Every received chunk restarted the timeout, allowing a trickling peer to occupy a probe for a very long time. | Use one deadline covering the HTTP download sample. |
| HTTP status | Status parsing examined only the first chunk and required that entire chunk to be UTF-8. | Accumulate the status line across reads and parse it independently of the response body. |
| Listener retry | Repeated accept errors could cause a tight retry and logging loop. | Back off briefly after an accept error. |

## Resource improvements

- IP probes share one lazily constructed TLS connector per scan, avoiding
  rebuilding the certificate root store for every candidate.
- IP scanning keeps at most the configured number of TCP and TLS worker tasks;
  a bounded pending queue prevents a slow TLS phase from accumulating one
  waiting task per input address.
- Relays no longer spawn two copy tasks and an optional ticker task per session.
- Both scanners share download sampling. The receive buffer is at most 8 KiB,
  with a separate bounded status-line buffer, independently of the sample cap.

A scheduling probe used 100,000 candidates with TCP concurrency set to 16
and TLS concurrency set to 4. It polled the scan once on a single-threaded
Tokio runtime and inspected `RuntimeMetrics::num_alive_tasks` before letting
workers execute. Each source snapshot was compiled separately; core artifacts
were cleared between snapshots to avoid shared-target cache reuse.

| Measurement | Baseline | Updated |
| --- | ---: | ---: |
| Tasks created by initial dispatch | 100,000 | 16 |
| Initial dispatch time, one debug-build sample | 68,363 microseconds | 97 microseconds |

These measurements describe startup scheduling overhead, not VPN throughput
or internet bandwidth. Timing is machine-dependent and was not a statistical
benchmark. The probe snapshots and harness are generated under `target/`.

## Verification

Using Windows x86-64 MSVC and Rust 1.98.1:

- `cargo test --workspace --locked --offline -- --quiet`: 565 tests passed,
  including 455 core tests. Core previously had 442 tests; 13 focused tests
  were added for cancellation, configuration, flow collisions, scoring,
  DNS concurrency, HTTP parsing, and deadlines.
- `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`:
  passed.
- `cargo fmt --all -- --check`: passed.
- `cargo build --workspace --release --locked --offline`: passed.
- `git diff --check`: passed.

Regression tests reproduced configuration acceptance, duplicate flow
replacement, leaked relay/listener tasks, continued scanner work, unbounded DNS
fanout, lost TCP scores, fragmented HTTP status parsing, and extended download
timeouts before their respective fixes.

The signalling race was corrected by inspecting the state/notification ordering
and Tokio's notification implementation; no deterministic race reproducer was
added. Tests retain coverage for the existing bypass methods and normal relay
behavior.

The changed core code is shared by Windows, Linux/NFQUEUE, and Android/Termux.
Only Windows compilation and local automated tests were executed in this review;
live DPI bypass, long-duration VPN traffic, and Linux/Android runtime behavior
require testing on those networks and devices. No new configuration options or
dependency versions were introduced.
