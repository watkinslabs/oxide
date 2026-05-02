# 06 Memory Model

DRAFT 2026-05-02. Dep:`01`,`02`,`08`,`09`.

Rust C++11/20 atomics only. No Linux LKMM. No `READ_ONCE`/address-dependency tricks. Pay `Acquire`/`Release` where Linux pays `READ_ONCE`. Trade: ~1–2% on RCU-heavy paths for spec simplicity.

## 1 Atomic ordering

| Order | Use |
|---|---|
| `Relaxed` | counters, "number went up"; never for correctness |
| `Acquire` (load) | sync-with paired `Release`; prior writes visible |
| `Release` (store) | publish prior writes |
| `AcqRel` (RMW) | both |
| `SeqCst` | cross-variable total order; **avoid**; PR comment naming the two atomics required |

`Consume` not used (deprecated; lowers to `Acquire`).

Defaults: lock-protected → `Relaxed`; cross-thread published pointer → `Acquire`/`Release` paired; "roughly current" counter → `Relaxed`.

## 2 Platform models (informational)

| Arch | Model | Cost |
|---|---|---|
| x86_64 | TSO; only Store-Load reorders | `Acq`/`Rel` ≈ plain `mov`; `SeqCst` `mfence` ≈ 30cy |
| aarch64 | weak | `Acq`/`Rel` = `ldar`/`stlr` 1 instr; `SeqCst` adds `dmb sy` 10–30cy |

Test concurrent code on aarch64 first; x86 follows for free.

## 3 Locks

### 3.1 Spinlock
```rust
Spinlock<T>::new(val) -> Self                       // const
.lock() -> Guard      .try_lock() -> Option<Guard>
.lock_irqsave() -> IrqGuard                         // disables IRQs
.lock_bh() -> BhGuard                               // disables soft-IRQs
```

Rules: any context. Lock shared with IRQ ⇒ `lock_irqsave` everywhere. Shared with softIRQ ⇒ `lock_bh` everywhere. Never held across `await` (no async in kernel) or `# Sleeps:y` fns. Guard `Drop` releases + restores IRQ/BH state. Uncontended `lock`+`unlock` ≤ 30cy (`04§1.1`).

### 3.2 RwLock
`RwLock<T>` — used sparingly. Writers can starve. Prefer RCU for read-mostly.

### 3.3 Mutex
No sleeping mutex in v1. Wait via wait-queue (§6).

### 3.4 SeqLock
```rust
SeqLock<T:Copy>: read()->T (retries), write(T) (internal spinlock)
```
`T` cacheline-sized or smaller. Reader: `Acquire` seq, `Acquire` data, `Acquire` re-read seq, retry on change. Writer: spinlock + counter odd→write→even. Used: monotonic clock, jiffies-equivalent, possibly task creds.

### 3.5 RCU
```rust
rcu_read_lock(); rcu_read_unlock();   // disables preempt this CPU
synchronize_rcu();                    // # Sleeps:y; waits all readers
call_rcu(FnOnce+Send+'static);        // post-grace free
```
Reader: lock → `AtomicPtr::load(Acquire)` → unlock. No sleep inside. Writer: build copy → `Release` store ptr → `synchronize_rcu`/`call_rcu`. Quiescent states: ctxsw, idle, return-to-user. Default for read-mostly cross-CPU sharing; scales linearly with readers.

### 3.6 Lock ordering

```rust
enum LockClass {  // partial order, lowest→highest rank
  Buddy, Slab, PageTable, AddressSpace, Inode, Dentry, Superblock,
  MountTable, FdTable, SignalQueue, TaskList, Runqueue, Tty,
  SocketTable, Socket, Driver(DriverId),
}
```

Every Spinlock tagged at construct. `debug-lockdep`: per-CPU acq stack; rank N while ≥N held → panic with cycle. Specs declare classes used; CI checks subset of `LockClass`. Adding a class = spec revision.

### 3.7 Lockless

MPSC rings (klog, RCU callback q, workq). SPSC rings (per-CPU NIC TX/RX, virtio). Open-addressed hash + RCU resize (FD lookup). Each has a `loom` test. No exceptions.

## 4 Per-CPU

```rust
PerCpu<T>::new(default:fn()->T) -> Self            // const
.with(|&T|->R)->R   .with_mut(|&mut T|->R)->R      // disables preempt
.for_each(|CpuId,&T|)
```

Storage: per-CPU section in BSS, replicated `MAX_CPUS`. Access via `gs:` (x86) / `tpidr_el1` (arm) base + offset. `with_mut` disables preempt around `f`. `Sync` not `Send`.

```rust
PerCpuCounter: add(u64) /*Relaxed local slot*/, sum()->u64 /*Relaxed sum*/
```

Cacheline-padded. False-sharing kills; static_assert `size_of::<PerCpuSlot<T>>() % 64 == 0`.

## 5 IRQ ↔ thread sync

- Thread shares with IRQ → `lock_irqsave` on thread side; IRQ side plain `lock` (IRQs already off).
- Per-CPU + local IRQ + local thread → IRQ-disable suffices; no spinlock.
- Per-CPU + thread-on-CPU-A + IRQ-on-CPU-B → spinlock too.

CI lint: bare `lock()` on a class flagged as IRQ-shared = build fail.

## 6 Wait queues

```rust
WaitQueue: wait_on(C:Fn->bool)              // # Sleeps:y
           wait_on_timeout(C, Duration)->bool
           wake_one()  wake_all()
```

Wait: register, set state INTERRUPTIBLE/UNINTERRUPTIBLE, recheck condition under lock (lost-wakeup defense), call sched. Wake: walk queue, set RUNNABLE, kick sched. Forbidden in atomic ctx.

Mandatory loom: 2 threads (1 wait, 1 signal); no lost wakeup; depth 6.

## 7 Memory barriers (drivers only)

```rust
mb()      // SeqCst fence; mfence/dsb sy
rmb() wmb() // load/store; lfence,sfence/dsb ld,dsb st
dma_wmb() // CPU writes before DMA reads; arm: dmb oshst; x86: compiler fence
dma_rmb() // DMA writes before CPU reads;  arm: dmb oshld; x86: compiler fence
```

Driver descriptor-rings only. Arch-free code uses Rust atomics.

## 8 compiler_fence

`core::sync::atomic::compiler_fence(Ordering)` — compiler-only, no CPU barrier. Use: between two `volatile` MMIO ops, around `asm!` touching invisible globals. Never as substitute for atomic ordering.

## 9 volatile

```rust
read_volatile<T>(*const T)->T
write_volatile<T>(*mut T, T)
```

MMIO only. No atomicity, no ordering, no anti-tearing. Multi-byte MMIO needing order: pair with `mb`/`rmb`/`wmb`. Never for inter-thread; use atomics.

## 10 LKMM idioms forbidden → replacement

| LKMM | Ours |
|---|---|
| `READ_ONCE(p)` + deref via addr-dep | `AtomicPtr::load(Acquire)` + deref |
| `WRITE_ONCE` no-tear | `AtomicXX::store(Relaxed)` |
| `smp_store_release`/`smp_load_acquire` | `store(Release)`/`load(Acquire)` |
| `barrier()` compiler-only | `compiler_fence(SeqCst)` |
| `smp_mb__before_atomic` | none; Rust atomics specify own barrier |
| Address-dependency / control-dependency ordering | explicit `Acquire` |
| `rcu_dereference()` | `AtomicPtr::load(Acquire)` inside `rcu_read_lock` |

Cost: `dmb ld` (~5cy) arm in RCU read-side; ~1–2% on RCU-heavy. Accepted.

## 11 No `static mut`

`static mut` outside `#[cfg(test)]` = build fail.

Replacements: `static FOO: AtomicXX | Spinlock<T> | RwLock<T> | PerCpu<T> | OnceLock<T>`.

## 12 Boot ordering

Pre-SMP: 1 CPU, IRQs off, trivially sequential. Post-`smp_init()`: this doc applies. Pre-SMP code initializes locks correctly (no-op at the time). `OnceLock` covers boot-time-initialized state without `static mut`.

## 13 Test contract (frozen)

- Loom Spinlock: 2 threads, mutex; depth 8.
- Loom SeqLock: writer + 2 readers; reader retry catches every torn write.
- Loom WaitQueue lost-wakeup: 1+1, depth 6.
- Loom RCU publish/free: 1W+2R; reader never sees freed payload.
- Loom PerCpuCounter: 4 adders + 1 summer; total invariant.
- Kernel SMP stress: 8 vCPU × 100 threads × random spinlock+IRQ+RCU+PerCpu mix × 1h; no deadlock/lost wakeup/torn read.
- `debug-lockdep` catches injected inversion in <1s.

## 14 Changelog

(none)

## 15 OQ

- Spinlock impl: ticket vs MCS vs CLH. Ticket thrashes >16 CPU. Lean: MCS.
- RCU impl: tree (~6KLOC) vs task-RCU (simple, slower grace). Lean: task-RCU v1; tree v2.
- Cacheline: hardcode 64 vs detect (Apple 128). Lean: const, default 64, HAL overrides.
- DMA barriers at HAL level vs per-driver asm. Lean: HAL.
- `SeqCst` audit lint requiring justification comment. Yes; write.
