# 04 Performance + Debug + Logging

FROZEN 2026-05-02. Dep:`02`,`08`.

## Revision 2026-05-03 (R06)

- Changed: §3 + §4 lock in the **klog-must-be-gated** invariant. Every `klog::*` call site (macros `kinfo!`/`kdebug!`/`kerror!`/`kfatal!`/`klog!` and the byte-emit helpers `write_raw`/`write_hex_u64`/`write_dec_u64`/`set_byte_sink`) MUST be inside a per-subsystem `#[cfg(feature = "debug-<sub>")]` gate or one of the `debug_<sub>!` per-crate macros that erase to `()` when the feature is off. Default builds emit zero log bytes; the call site is absent from the binary, not "filtered at runtime".
- Why: the runtime level filter described in §4 still costs a load+branch per call site and pulls the format-string entry into `.klog_strings`. For a kernel-class hot path (timer ISR, syscall fast-path, PMM alloc), even that is too much. A user-reported drift on the boot trace (PMM stress dumps + ACPI walks unconditionally compiled in even when nobody wanted them) made it concrete: gating policy belongs at the call site, not inside the logger.
- Added: `debug-boot` feature for the operational-pulse trace (`init started`, `pmm: ready`, `gic: enabled`, `lapic: enabled`, `boot: kernel ready`, `pl011: switched klog sink`, etc.) so even those lines disappear in production. `debug-all` aggregate adds it.
- Affected code: `kernel/Cargo.toml` features list; `kernel/src/lib.rs` + every kernel-side `klog::*` call site; per-crate `debug_<sub>!` macro pairs (cfg-on → body, cfg-off → `()`).
- Test contract: spec-lint adds `code/klog-ungated` rule — flags any `klog::` use whose enclosing scope is not under one of the allowed `cfg(feature = "debug-...")` forms (direct `cfg`, the macro pair pattern, or a function/module that itself carries a matching cfg attr). Initial sweep done in branch `D03-klog-must-be-gated`; lint enforcement lands alongside.

## Revision 2026-05-03 (R05)

- Changed: §3 feature list adds `debug-acpi` (RSDP/XSDT/MADT/HPET/SPCR/MCFG/GTDT decoder traces) and folds it into `debug-all`. The existing `debug-pmm`/`debug-vmm`/`debug-irq` buckets stay; ACPI table walking is its own surface and needed its own gate.
- Why: aarch64 + x86_64 boot-time bring-up needed per-subsystem trace gates so a developer chasing an IRQ-routing bug isn't paying for PMM stress dumps + ACPI walks + memmap pretty-print on every boot. Single `debug-boot` would have collapsed signals across subsystems and is rejected.
- Affected code: `kernel/Cargo.toml` features; `kernel/src/lib.rs` call-site `cfg(feature=…)`-elided diagnostic blocks (PMM smoke + memmap dump under `debug-pmm`; HPET-cap + GICD-typer device-map dumps under `debug-vmm`; LAPIC/GIC enable diags + polled-timer + IRQ soak under `debug-irq`; ACPI walk under `debug-acpi`).
- Test contract change: none. CI matrix in `40` already runs no-features + `debug-all`; the new `debug-acpi` rides the same matrix.

## Revision 2026-05-02 (R04)

- Changed: §4 backend description tightened. Adds the frozen invariant **"klog producer-side macros are safe in any context"** (process, IRQ, NMI, spinlock-held, preempt-disabled, RCU read-side); pins the per-CPU lockless ring + deferred-drain design so callers don't have to context-audit every call site.
- Why: Linux's `printk` discipline. Without this contract, every klog call site needs review for "is my caller holding a spinlock? am I in NMI? am I in IRQ?" — which scales linearly with the call graph and silently rots. Locking it down at the producer-API level eliminates the audit burden and matches `printk` semantics.
- Affected code: `crates/klog/` re-implements the producer + per-CPU ring + drainer kthread once `crates/sync/percpu.rs` lands. Existing call sites stay valid (already pure macro use). Boot-path UART sink unchanged.
- Test contract change: §4 adds a loom MPSC test (P-ctx + IRQ + NMI producers per CPU) + a stress drop-counter test.

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
debug-irq=[]      # IRQ flag audit, edge/level mismatch, timer-IRQ soak
debug-acpi=[]     # RSDP/XSDT walk + per-table decoder traces
debug-boot=[]     # operational-pulse trace (init started, pmm: ready, …)
debug-syscalls=[] # log every syscall (very expensive)
debug-all=["debug-alloc","debug-lockdep","debug-preempt",
           "debug-sched","debug-vmm","debug-pmm","debug-vfs",
           "debug-net","debug-irq","debug-acpi","debug-boot"]  # not debug-syscalls
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

### 4.0 Call-site gating (frozen, R06)

**Every `klog::*` call site is `cfg`-elidable.** Default builds emit zero log bytes. The runtime per-target level filter (§4.5) layers on top — it is *not* a substitute for compile-time elision. Specifically:

- Each call to `kinfo!` / `kdebug!` / `kerror!` / `kfatal!` / `klog!` / `write_raw` / `write_hex_u64` / `write_dec_u64` / `set_byte_sink` MUST be inside one of:
  - a `#[cfg(feature = "debug-<sub>")]` block, attribute on enclosing fn/mod, or
  - one of the `debug_<sub>!` macro pairs (cfg-on → `$($t)*`, cfg-off → empty).
- The `<sub>` is the subsystem the message belongs to (the §3 catalog: `pmm`, `vmm`, `irq`, `acpi`, `boot`, `sched`, …).
- `fatal!` is the lone exception (panics; spec calls for unconditional emission — but even there the body is a single literal, not a hot path).
- Spec-lint enforces this via `code/klog-ungated`: any `klog::` use whose enclosing scope is not under one of the allowed cfg forms is a build failure.

Why: the runtime threshold check is one atomic Relaxed load (§4.5). For the kernel's hottest call sites (timer tick, syscall fast-path) one atomic per ungated emit is the difference between perf-budgeted and perf-blown. The discipline is "if you don't need this trace in production, the binary doesn't carry it." Per-feature gates enable a developer to dial in *exactly* the subsystem they're chasing without paying for the rest.

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

### 4.1 Producer-side safety contract (frozen)

**klog producer macros (`trace!`/`debug!`/`info!`/`warn!`/`error!`/`fatal!`) are safe to call in any context** — process, IRQ, soft-IRQ, NMI, spinlock-held, `lock_irqsave`-held, preempt-disabled, RCU read-side. Consumers may invoke freely; no context audit at the call site.

Mechanism: producer path is fixed-bound work, no allocation, no lock acquired anywhere on this CPU.

| Step | Cost | Notes |
|---|---|---|
| `level >= per-target threshold` check | 1 atomic Relaxed load | short-circuit below threshold |
| Acquire slot in per-CPU ring | 1 atomic CAS (Acquire) | Release-fenced on commit |
| Copy fixed-size record (≤80 B) | inline `memcpy` | record = `[u16 level, u16 target_id, u32 fmt_id, [u64;8] args]` |
| Release slot | 1 atomic store (Release) | drainer reads with Acquire |

Per-CPU ring entry count: 4096 records (320 KiB/CPU). Power-of-two; head/tail wrap via mask. Configurable at build per `04§3` debug feature.

`fatal!` is the lone exception: instead of enqueueing, it panics + halts after best-effort flush — by definition unrecoverable, no deferred drain.

### 4.2 Backend (drainer + sinks)

Drainer = per-CPU kthread (post-SMP-init); pre-SMP, the boot CPU's idle loop polls all rings between work. Drainer reads tail with Acquire, decodes records (resolves `fmt_id` against `.klog_strings`, formats typed args), emits to active sinks.

Sinks (priority order on init):

| Stage | Sink | Cost |
|---|---|---|
| Pre-paging boot | UART direct write | bounded; serial port speed |
| Post-paging boot | UART + dmesg ring | dmesg = single global lock-free ring |
| Post-SMP init | dmesg + `/dev/kmsg` (procfs) + netlink-style socket | journald-equivalent userspace consumer |

Records remain binary across the kernel boundary; userspace decoder maps `fmt_id` → format string + arg types. No runtime format-string parsing in kernel.

### 4.3 NMI ringlet

NMI context cannot share the main per-CPU ring (NMI can preempt a CAS in progress, leaving the slot half-claimed). NMI gets a dedicated 64-entry per-CPU ringlet with the same record format. SPSC: NMI is the sole producer (NMIs don't nest); main-IRQ-exit path drains ringlet → main ring on first opportunity.

### 4.4 Drop policy

Ring full at producer ⇒ increment per-CPU `dropped` counter (Relaxed), abandon record, return. **Producer never spins, never blocks.** Counter is itself logged hourly via a dedicated dropped-records record consumed by drainer.

### 4.5 Per-target thresholds

Per-target levels: cmdline `oxide.log=info,sched=debug,vmm=trace,net::tcp=warn`. Runtime change = single Relaxed store. Below-threshold call: macro short-circuits without touching args (the fixed-bound CAS is the second cost; threshold check is the first).

### 4.6 Forbidden

- Runtime-parsed printk format strings.
- Separate debug/info buffers (one ring per CPU; level is a record field).
- Severity numbers >7 (Linux klog convention; we cap at fatal=0..trace=5 + reserved).
- Acquiring any lock in the producer path. Drainer may take the dmesg ring's lock; producer never does.
- `Box`/`Vec` in the producer path (no allocation).

Hot-path: never above `trace`; `trace` feature-gated; off = `.klog_strings` entry not even emitted.

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

