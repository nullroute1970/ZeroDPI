# Relay performance: connection options and shared progress sampling

Measured on 2026-10-19 against baseline commit `330be85`.

## Changes

- `TCP_NODELAY = true` now applies to both accepted and upstream sockets in all
  proxy modes. Set it to `false` for A/B testing. Upstream requirements from
  `tls_frag` with `TCP_SEG_NODELAY = true`, `sni_boundary_frag`, `tls_record_split`,
  and `ccs_prefix` still enable upstream TCP_NODELAY.
- Relay sockets use borrowed halves in the same task. The two 64 KiB copy
  buffers, cancellation, half-close behavior and final byte accounting remain.
  Socket-half/counter heap allocations per relay fall from four to zero without
  progress, or one grouped counter allocation with progress; the shared registry
  has additional amortized storage for active connections.
- Progress is sampled by the receiver at most every 500 ms, replacing each
  connection's timer and progress queue entries. A slow reader gets current
  counters, including unchanged counters for idle-rate calculation. Registration
  guards remove completed/cancelled relays and protect a reused port's new entry.
- The TUI processes a batch together. Headless JSON keeps one v1 `relay_bytes`
  line per connection, buffering the batch under one stdout lock and flush.
  Headless runs without JSON disable progress sampling.

## Core API compatibility

Construct event channels with `zerodpi_core::proxy::proxy_event_channel(true)`;
pass `false` for lifecycle-only consumption. The returned `ProxyEventSender` and
`ProxyEventReceiver` replace direct `mpsc::unbounded_channel::<ProxyEvent>()`
construction. The sender supports `send`, `clone` and `is_closed`; the receiver
supports asynchronous `recv` and synchronous `try_recv` with Tokio's usual error
types. Public proxy functions still accept `Option<ProxyEventSender>`.

`ProxyEvent::RelayProgressBatch { sampled_at, entries }` contains one sampling
time and `RelayProgress { src_port, c2s_bytes, s2c_bytes }` records. Consumers must
handle this added variant. Legacy `RelayProgress` events remain supported.
Lifecycle events are queued separately and received before a due sample. The
Android/headless JSON contract remains at version 1, including `final: true` on
the existing final byte-count event.

## Method

- Windows build 26300; Intel Core i9-12900H, 14 cores / 20 logical processors.
- Rust `1.99.0`, locked Tokio `1.52.1`, release profile with thin LTO and one
  codegen unit. Both benchmark binaries enable Tokio's test utilities so their
  dependency features match.
- Four Tokio workers; 1, 32 or 128 loopback relays; progress and TCP_NODELAY each
  independently on/off. The clients and echo endpoints always use TCP_NODELAY.
- Each client measures its first twenty 64-byte echo round trips, then all
  clients synchronize and exchange 64 KiB chunks for 750 ms. The reported
  throughput sums both directions. RTT includes initial relay startup and
  concurrent connection setup; it is not a warmed-up steady-state latency test.
- Three repetitions per scenario and binary, alternating binary order: 72 runs.
  Tables show the median of the three run summaries. No builds ran concurrently
  with this comparison. [Raw per-run CSV](relay-benchmark.csv) contains all flags,
  RTT percentiles, CPU time, peak RSS, elapsed process time and progress counts.
- CPU seconds and peak RSS cover the entire test process, including its clients
  and echo endpoints. Memory is sampled during execution; CPU includes startup
  and teardown as well as the fixed-duration bulk phase.

## Bulk throughput

MiB/s, summing upload and download. `Progress` is live telemetry, not packet shaping.

| Connections | Progress | NODELAY | Baseline | Updated | Change |
|---:|:---:|:---:|---:|---:|---:|
| 1 | false | false | 1475.5 | 1430.0 | -3.08% |
| 1 | false | true | 1450.8 | 1454.3 | +0.24% |
| 1 | true | false | 1495.9 | 1513.4 | +1.17% |
| 1 | true | true | 1460.7 | 1501.0 | +2.76% |
| 32 | false | false | 2895.4 | 2997.6 | +3.53% |
| 32 | false | true | 3139.1 | 3142.5 | +0.11% |
| 32 | true | false | 3133.3 | 3025.7 | -3.44% |
| 32 | true | true | 3086.5 | 3167.1 | +2.61% |
| 128 | false | false | 2134.9 | 2146.9 | +0.56% |
| 128 | false | true | 2120.7 | 2043.4 | -3.64% |
| 128 | true | false | 2128.7 | 2125.3 | -0.16% |
| 128 | true | true | 2152.3 | 2120.0 | -1.50% |

## RTT with NODELAY enabled

Microseconds for the initial round trips, including startup. These are medians
of per-run percentiles, rather than percentiles pooled across all runs.

| Connections | Progress | Baseline p50 | Updated p50 | Baseline p95 | Updated p95 |
|---:|:---:|---:|---:|---:|---:|
| 1 | false | 43.7 | 42.8 | 9835.1 | 156.9 |
| 1 | true | 45.3 | 39.9 | 8333.8 | 124.1 |
| 32 | false | 294.2 | 278.7 | 477.1 | 397.5 |
| 32 | true | 306.5 | 290.9 | 486.0 | 403.1 |
| 128 | false | 187.8 | 298.7 | 318.3 | 398.5 |
| 128 | true | 153.9 | 106.8 | 478.3 | 165.9 |

## CPU and memory with NODELAY enabled

CPU is cumulative process CPU time in seconds. RSS is peak process working set
in MiB, including both ends of the benchmark traffic.

| Connections | Progress | Baseline CPU | Updated CPU | Baseline RSS | Updated RSS |
|---:|:---:|---:|---:|---:|---:|
| 1 | false | 0.688 | 0.719 | 6.688 | 6.684 |
| 1 | true | 0.734 | 0.734 | 6.703 | 6.715 |
| 32 | false | 2.547 | 2.453 | 14.613 | 14.566 |
| 32 | true | 2.422 | 2.391 | 14.594 | 14.582 |
| 128 | false | 2.469 | 2.531 | 39.434 | 39.320 |
| 128 | true | 2.609 | 2.547 | 39.410 | 39.387 |

Bulk throughput changes ranged from -3.64% to +3.53%; these short loopback runs
do not establish a bandwidth increase. Most initial-RTT cases improved, but the
128-connection case without progress regressed in this run. Peak memory changed
only slightly because the copy and endpoint buffers dominate the test process.
The measured values describe this local workload and do not measure VPN/DPI
success, WAN throughput, or Android battery use.

## Reproduce

Build the ignored test binary with
`cargo test -p zerodpi-core --release --lib --no-run`; Cargo prints its executable
path. Preserve the baseline executable before rebuilding the updated revision.
Enable the same `tokio/test-util` dependency feature when building an older
baseline. The harness in `crates/zerodpi-core/src/proxy/perf_tests.rs` is identical
apart from the old/new event-channel adapter and the additional batch match arm.

```text
python tools/relay_benchmark.py --executable <updated-test-executable> --label optimized --compare-executable <baseline-test-executable> --compare-label baseline --output target/relay-comparison.csv
```

The runner uses Python's standard library. Defaults are three repetitions and
750 ms per bulk phase; `--connections`, `--repeats` and `--duration-ms` override
them. It measures process CPU and memory on Windows or Linux.

## Verification

The workspace regression suite covers TCP_NODELAY defaults and overrides,
accepted/upstream options, bypass-required overrides, coalescing and slow
receivers, idle rates, port reuse, cancellation, half-close, reset and lifetime
rotation, and unchanged JSON lines. The performance test is ignored by the
normal test suite and run explicitly by the benchmark runner.

Final Windows verification: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace` (666 passed, one ignored benchmark), and
`cargo build --workspace --release` all passed. The benchmark runner also passed
Python bytecode compilation. Final code review was performed in-session because
no separate reviewer-agent tool was available.
