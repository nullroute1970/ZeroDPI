"""Measure the ignored Rust loopback relay benchmark without external packages."""

import argparse
import csv
import ctypes
import itertools
import json
import os
from pathlib import Path
import statistics
import subprocess
import time


def process_usage(process):
    if os.name == "nt":
        from ctypes import wintypes

        class MemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD), ("faults", wintypes.DWORD),
                ("peak_rss", ctypes.c_size_t), ("rss", ctypes.c_size_t),
                ("peak_paged", ctypes.c_size_t), ("paged", ctypes.c_size_t),
                ("peak_nonpaged", ctypes.c_size_t), ("nonpaged", ctypes.c_size_t),
                ("pagefile", ctypes.c_size_t), ("peak_pagefile", ctypes.c_size_t),
            ]

        memory = MemoryCounters()
        memory.cb = ctypes.sizeof(memory)
        handle = wintypes.HANDLE(int(process._handle))
        ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb)
        times = [wintypes.FILETIME() for _ in range(4)]
        ctypes.windll.kernel32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times))
        cpu = sum((t.dwHighDateTime << 32) | t.dwLowDateTime for t in times[2:]) / 1e7
        return cpu, memory.peak_rss / (1024 * 1024)
    try:
        status = Path(f"/proc/{process.pid}/status").read_text()
        rss = next(float(line.split()[1]) / 1024 for line in status.splitlines()
                   if line.startswith("VmHWM:"))
        stat = Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()
        cpu = (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK")
        return cpu, rss
    except (OSError, StopIteration):
        return 0.0, 0.0


def measure(args, connections, progress, nodelay):
    env = os.environ.copy()
    env.update(ZERODPI_BENCH_CONNECTIONS=str(connections),
               ZERODPI_BENCH_PROGRESS=str(int(progress)),
               ZERODPI_BENCH_NODELAY=str(int(nodelay)),
               ZERODPI_BENCH_DURATION_MS=str(args.duration_ms))
    start = time.perf_counter()
    process = subprocess.Popen(
        [args.executable, "--ignored", "--exact", "proxy::perf_tests::relay_benchmark", "--nocapture"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    cpu = peak_rss = 0.0
    while process.poll() is None:
        sample_cpu, sample_rss = process_usage(process)
        cpu, peak_rss = max(cpu, sample_cpu), max(peak_rss, sample_rss)
        if time.perf_counter() - start > 60:
            process.kill()
            raise RuntimeError("relay benchmark exceeded 60 seconds")
        time.sleep(0.02)
    sample_cpu, sample_rss = process_usage(process)
    cpu, peak_rss = max(cpu, sample_cpu), max(peak_rss, sample_rss)
    output = process.communicate()[0]
    if process.returncode:
        raise RuntimeError(output)
    line = next(line for line in output.splitlines() if line.startswith("RELAY_BENCH "))
    row = json.loads(line.removeprefix("RELAY_BENCH "))
    row.update(label=args.label, cpu_seconds=cpu, peak_rss_mib=peak_rss,
               wall_seconds=time.perf_counter() - start)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True, help="release zerodpi_core test executable")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--label", required=True)
    parser.add_argument("--compare-executable", help="alternate runs with this baseline executable")
    parser.add_argument("--compare-label", default="baseline")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--duration-ms", type=int, default=750)
    parser.add_argument("--connections", default="1,32,128")
    args = parser.parse_args()
    if args.repeats < 1 or args.duration_ms < 1:
        parser.error("repeats and duration must be positive")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as output:
        writer = None
        for connections, progress, nodelay in itertools.product(
            map(int, args.connections.split(",")), (False, True), (False, True)
        ):
            variants = [args]
            if args.compare_executable:
                variants.append(argparse.Namespace(**{
                    **vars(args), "executable": args.compare_executable, "label": args.compare_label,
                }))
            rows = []
            for repeat in range(args.repeats):
                # Alternate order to reduce effects of CPU temperature and host drift.
                order = variants if repeat % 2 == 0 else list(reversed(variants))
                rows.extend(measure(variant, connections, progress, nodelay) for variant in order)
            if writer is None:
                writer = csv.DictWriter(output, fieldnames=list(rows[0]))
                writer.writeheader()
            writer.writerows(rows)
            output.flush()
            for variant in variants:
                samples = [row for row in rows if row["label"] == variant.label]
                print(json.dumps({"label": variant.label, "connections": connections,
                                  "progress": progress, "nodelay": nodelay,
                                  **{key: round(statistics.median(row[key] for row in samples), 3)
                                     for key in ("mib_per_sec", "p50_us", "p95_us",
                                                 "cpu_seconds", "peak_rss_mib")}}), flush=True)


if __name__ == "__main__":
    main()
