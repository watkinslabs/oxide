# 37 Observability

FROZEN 2026-05-02. Dep:`01`,`02`,`04`,`13`,`19`,`23`,`38`. Provides:userspace tools (`dmesg`,`perf`,`bpftrace` per phase 25).

## Revision 2026-05-09 (R01)

- Changed: pinned the initial tracefs root + control-file shape. Boot
  registers a synthetic `/sys/kernel/tracing` directory whose
  lookup yields static read-only inodes for `available_events`,
  `tracing_on`, `trace`, `trace_pipe`, `current_tracer`. Bodies
  match Linux's empty-trace defaults so userspace tools
  (`bpftrace`, `perf record`, `trace-cmd`) probe the surface
  without panicking. Real per-CPU ring buffers + tracepoint
  registration land in phase 25.
- Why: phase 25 (perf_event_open + tracefs/ftrace + ebpf
  tracepoints) needs the tracefs root before any tracepoint
  framework lands. The static-files-only first slice unblocks
  feature-probe paths.
- Affected code: `kernel/src/dev_tracefs.rs` (new — directory inode
  + leaf static files); `kernel/src/lib.rs` boot init.

## 1 Purpose

Logging surface (`klog`), tracing (static tracepoints, function tracer), perf counters (PMU), eBPF (deferred). Crash dump (defer).

## 2 Invariants (frozen)

1. One logger (`klog`); structured records; per-target levels; format-string interning per `04§4`.
2. Records ring per-CPU MPSC; drained by `klogd`-equivalent kthread.
3. `dmesg`/`/dev/kmsg` exposes records in Linux-compatible binary format.
4. Tracepoints emit binary record with timestamp, cpu, tid, fixed-fields-by-id.

## 3 Public ifc

```rust
// klog macros (already in `04`).
trace!(target:"...", k:v, ..., "fmt {}", arg);
debug!(...); info!(...); warn!(...); error!(...); fatal!(...);

// Tracepoints
tracepoint!(sched_switch, prev_tid:Tid, next_tid:Tid);

// PMU
pub fn perf_event_open(attr:&PerfAttr, pid:Pid, cpu:i32, group_fd:RawFd, flags:u32) -> KR<RawFd>;
```

## 4 Levels + targets per `04§4`.

## 5 Ring buffer

Per-CPU MPSC, lockless on the producer side using `Acquire`/`Release` atomics for head/tail. Capacity 64 KiB per CPU default.

Drain: `klogd` kthread polls per-CPU rings and writes to (a) UART (during boot/early), (b) `/dev/kmsg` ringlet, (c) `journald`-equivalent socket if registered.

## 6 Tracepoints

Static. Defined in source via `tracepoint!` macro:

```rust
tracepoint! {
    sched_switch {
        prev_tid: Tid,
        next_tid: Tid,
        prev_state: u8,
    }
}
```

Macro generates:
- `&'static str` site id in `.tracepoints` linker section.
- `static AtomicBool ENABLED_<name>` (cheap branch when off).
- A `tp_<name>(args...)` function: if enabled, push binary record onto per-CPU trace ring.

Userspace `tracefs` (mounted at `/sys/kernel/tracing`) controls per-tracepoint enable; reading `/sys/kernel/tracing/trace_pipe` drains the ring.

## 7 Function tracer (`ftrace`-like)

Tracked as phase 25 (mcount/fentry hooks; recompile cost). Initial substrate: tracepoints only.

## 8 PMU + perf

`perf_event_open` opens a counter (cycles, instructions, cache miss, branch miss, sample-period for sampling). Backed by:
- x86: PMC MSRs (PMUv3+).
- arm: PMUv3 (same name, different mechanism; PMCNTENSET_EL0 etc.).

`perf` userspace from Linux works against `perf_event_open` ABI.

Now: subset (cycles, instructions, cache events). Phase 25: full.

## 9 eBPF

Tracked as phase 23 per `00§3`. Currently `bpf()` returns ENOSYS.

Once landed: verifier, BPF subset (sockets, kprobes, tracepoint progs, cgroup hooks). Maps: HASH, ARRAY, PERCPU_HASH, RINGBUF, LPM_TRIE.

## 10 Crash dump (kdump)

Tracked as later phase. Requires functional disk in panic path; complicates kernel.

## 11 Concurrency

Per-CPU rings: SPSC (writer = current CPU, reader = klogd). Cross-CPU drain by klogd merging in timestamp order.

PMU access: per-CPU MSR; group locking when multiple counters share a group.

## 12 Perf budget

| Op | p99 cy |
|---|---|
| `klog::trace!` (level off) | ≤ 5 (one atomic load + branch) |
| `klog::info!` (level on) | ≤ 200 (push record) |
| Tracepoint (off) | ≤ 5 |
| Tracepoint (on) | ≤ 150 |
| PMU read self-counters | ≤ 100 |

## 13 Test contract (frozen)

- `klog::trace!` with level `info`: zero-cost (verified via `cargo asm` snapshot).
- `dmesg` output matches expected substrings on a known boot.
- Tracepoint enable: `echo 1 > /sys/kernel/tracing/events/sched/sched_switch/enable`; pipe contains records.
- `perf stat busybox echo` reports nonzero cycles + instructions.
- Coverage ≥80%.

## 14 Failure modes

- Ring full: increment `dropped` counter, log it once per minute at `warn`.
- PMU not available (rare): perf_event_open returns ENODEV.

## 15 Debug

`debug-obs`: dump ring stats every 10s; tracepoint-enable history.

## 16 Cross-spec

`04` (logger spec), `19` (`/dev/kmsg`,`/sys/kernel/tracing`), `15` (perf_event_open), `38` (panic→klog drain to UART).

