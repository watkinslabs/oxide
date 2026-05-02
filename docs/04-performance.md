# 04 Performance + Debug + Logging

DRAFT 2026-05-02. Dep:`02`,`08`.

Sister of `03`. Modernity = what; this = how-fast. Perf is design constraint, not tuning phase. Debug per-feature, free-when-off. One logger, structured, per-target levels.

## 1 Hot paths (frozen budgets)

Reference: Zen 4 / Cortex-X3, freq-locked. p99 cycles. Note: A1 (KPTI) per `05§A1` — adjust budgets when KPTI verified.

| Path | p99 cy | Why |
|---|---|---|
| Syscall entry → dispatch → return (no I/O) | 800 | KPTI eats ~150–300; `getpid`/`clock_gettime` mostly via vDSO |
| Page fault → anon COW → return | 3000 | fork-heavy |
| Ctxsw same-AS | 500 | thread pool ping-pong |
| Ctxsw cross-AS (KPTI on, PCID hit) | 2500 | multi-process pipeline |
| Ctxsw cross-AS (PCID miss, full TLB) | 6000 | tail |
| Spinlock acq+rel uncontended | 30 | everywhere |
| `kmalloc(64)`+`kfree` magazine hit | 80 | net, VFS |
| TCP RX (NIC IRQ → socket q) | 5000 | line-rate |
| `epoll_wait` 1 ready FD | 1500 | servers |
| io_uring SQE submit + CQE reap (no I/O) | 1000 | modern async |

CI bench gates: PR regress >5% on any → fail unless commit has `Performance-Regression-Justification:` trailer.

## 1.1 Cost rules (forbidden on hot path absent justification)

1. Heap alloc. Use stack/per-CPU/preallocated.
2. Indirect call in inner loop. Hoist or generic-monomorphize, never `dyn` per-iter.
3. Lock in loop body. Acquire outside.
4. `Arc::clone` in tight loop. Use `&Arc`.
5. String formatting. Use interned format strings (§4).
6. Syscall/hypercall/IPI from fast path unless that's its purpose.

## 1.2 Loops-of-loops rule

Antipattern: `f` `O(n)` calls `g` per iter; `g` `O(m)`; caller pays `O(n·m)` invisibly.

Rule: every `pub fn` carries `# C: O(...)` (`# C: trivial` allowed). Composite cost stated when calling `O(n)` fn in loop, e.g. `# C: O(n·m) n=...,m=...`. Missing → build fail.

## 2 Build profiles

| Profile | opt | dbg-asserts | overflow | KASAN | Use |
|---|---|---|---|---|---|
| `release` | 3, lto=fat, cgu=1 | off | off | off | prod, soak, bench |
| `dev` | 1 | on | on | off | day-to-day |
| `debug` | 1 | on | on | on (poison/shadow) | bug, fuzz |

`opt-level=0` not used (10–50× slower; kernel unrunnable). `release` IS the perf profile; never a separate one.

## 3 Per-feature debug

Compile-time Cargo features. Off = absent from binary. Verified by `cargo asm` snapshot tests.

```toml
[features]
default = []
debug-alloc=[]    # heap/slab redzones, double-free, leak track
debug-lockdep=[]  # lock graph + cycle detector
debug-preempt=[]  # preempt_count audit at IRQ exit
debug-sched=[]    # per-switch trace, runqueue invariants
debug-vmm=[]      # PTE walker + AS invariants
debug-pmm=[]      # buddy invariant audit per op
debug-vfs=[]      # inode/dentry refcount audit
debug-net=[]      # packet trace, socket FSM asserts
debug-irq=[]      # IRQ flag audit, edge/level mismatch
debug-syscalls=[] # log every syscall (very expensive)
debug-all=["debug-alloc","debug-lockdep","debug-preempt",
           "debug-sched","debug-vmm","debug-pmm","debug-vfs",
           "debug-net","debug-irq"]  # not debug-syscalls
```

Independence: `debug-sched` doesn't pull `debug-vmm`. (Catalog: `41`.)

Macro:
```rust
kdebug!(feature="debug-sched", { self.runqueue.audit_invariants(); });
```
Off → `()`, no asm. On → `#[cold]`-wrapped block.

`debug_assert!` ok (profile-bound). `kdebug!` for profile-independent control.

CI matrix: release no-features, release `debug-all`, dev each `debug-*` solo.

## 4 Logging

One logger. `klog`. Not `println!`/`log`/three traits.

Surface:
```rust
use klog::{trace,debug,info,warn,error,fatal};
info!(target:"sched", cpu=cpu_id, pid=t.pid, "context switch");
warn!(target:"vmm", va=?va, "TLB shootdown took {} us", us);
```

- 6 levels. `fatal` panics.
- Structured kv pairs (typed; backend gets fields, not strings).
- `target` mandatory = subsystem (`"sched"`,`"vmm"`,`"net::tcp"`).
- Format strings compile-time interned in `.klog_strings` ELF section. Userspace decoder resolves by addr.

Per-target levels: cmdline `oxide.log=info,sched=debug,vmm=trace,net::tcp=warn`. Runtime change = single Relaxed store. Below-threshold call: macro short-circuits without touching args.

Levels:
| Lvl | Use | Hot? |
|---|---|---|
| trace | per-event flow ("pkt entered drv") | feature-gated only |
| debug | subsystem state changes | no |
| info | one-shot notable events | boot only |
| warn | recoverable anomaly | rate-limited |
| error | op failed, kernel continues | rate-limited |
| fatal | invariant violated; panic+halt | n/a |

Rate limit: ≤N events/source-line/sec (default N=10), suppressed-counter logged hourly. Non-negotiable.

Backend: per-CPU MPSC ring drained by kthread. Early boot → UART. Post-init → `dmesg`+`/dev/kmsg`+netlink-style sock for journald-equivalent. Records binary (subsys-id, level, fmt-string-id, typed args); userspace decoder.

Hot-path: never above `trace`; `trace` feature-gated; off = `.klog_strings` entry not even emitted.

Forbidden: runtime-parsed printk format strings; separate debug/info buffers; severity numbers >7; logging from NMI ctx (use NMI-safe ringlet, drained later).

## 5 Bench / regression

`crates/bench/` + `tools/perfrunner/`. Two modes:
1. Hosted (arch-free policies): criterion vs oracle.
2. In-kernel: special boot mode runs bench, prints to serial, perfrunner extracts.

Commit results to `bench-history/<commit>.json`.

Per-tag artifacts in `perf-history/<tag>/`: perf flame for syscall-pingpong + net-RX line + kernel-build-self; dmesg boot log; slab cache pop after 1h soak.

5%-rule: release tag mayn't regress any §1 budget >5% vs prior tag. Hold tag until fix or spec-revision renegotiates budget.

## 6 Data-structure defaults

| Need | Default | Avoid |
|---|---|---|
| Map, hot, N<32 | linear scan `[(K,V);N]` | BTree/HashMap (alloc, cache-cold) |
| Map, larger, ordered iter | `BTreeMap` | `HashMap` (no order) |
| Map, larger, unordered, freq insert/lookup | open-addr quadratic, `ahash` | `HashMap` default hasher (DoS) |
| Sparse int keys (PID, FD) | `IDR` (radix-tree-of-arrays) | `HashMap<u32,_>` |
| Per-CPU counter | `[CachelinePad<AtomicU64>;NCPU]` | single `AtomicU64` (false-sharing) |
| Intrusive linked list | hand-rolled w/ pointer arith | `LinkedList<T>` (alloc) |
| SPSC FIFO lockless | crossbeam SPSC or hand-roll | `VecDeque`+mutex |
| MPSC | lockless ring + backoff | mutex+`VecDeque` |
| Read-mostly shared | RCU | `RwLock` (writer starvation, NUMA bad) |
| Refcount | `Arc<T>`; intrusive refcount on hot | `Rc<T>` (not Sync) |

Defaults not laws; spec may override with rationale.

## 7 Standing rules

1. Every `pub fn` has `# C:`. No exception.
2. Hot path has cycle budget; bench gates regress.
3. Debug instr is compile-time feature; off ⇒ absent.
4. One logger, structured, per-target, interned strings.
5. No alloc/lock/indirect-call in hot inner loop without comment naming reason.
6. `# C:` `O(n²)`+ on hot path requires subsystem-spec sign-off.

Per-subsystem spec frozen-section inherits these.

## 8 Changelog

(none)

## 9 OQ

- vDSO `clock_gettime`+`getcpu` v1 day-1 vs eat-syscall? Lean: day-1; impl small, savings huge.
- Format interning: defmt-style linker section vs tracing-style runtime registry? Lean: linker section (zero runtime cost; custom decoder fine).
- Bench harness: criterion enough vs custom cycle-accurate (`rdtsc`,`cntvct_el0`)? Lean: criterion policies + custom for hot-path cycles.
- Adopt `tracing` ecosystem types? Lean: own, smaller; port-on-decode.
- PerCpu primitive ergonomics in `06§4` settled; HAL impl detail.
