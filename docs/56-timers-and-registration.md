# 56 Timers and subsystem self-registration

DRAFT (living). Dep: `02`,`06`,`07`,`08`,`13`,`23`,`52`,`53`.

How periodic work is scheduled and how subsystems wire themselves into the
kernel. Two rules, one theme: **the kernel hardcodes no system-wide lists** —
each subsystem owns its periodic work and registers itself. Linux model
(timer wheel + `*_initcall`), not a monolithic system tick.

## 1 Layers of periodic work

| Layer | Context | Mechanism | For |
|---|---|---|---|
| hardware tick | IRQ | `hal` TimerOps + per-arch timer IRQ | preemption, monotonic clock |
| tick hook | IRQ (post-EOI) | `arch_irq::set_tick_poll_hook` → `tick_poll_combined` | lock-free drains: UART RX, vDSO vvar publish, zombie reap, deadline wake |
| software timers | **process** (kthread) | `crates/kernel/timer` wheel + `ktimers` driver | work that takes runqueue/subsystem locks |

The IRQ/post-EOI tick MUST NOT take the runqueue or any lock a preempted task
may hold (deadlock). Anything that needs those locks (load balance, cpu.max
throttle) runs in the **software-timer** layer (process context).

## 2 Software timer wheel — `crates/kernel/timer`

Generic registry. Owns the mechanism only; **zero subsystem knowledge**.

| Item | Signature | Note |
|---|---|---|
| register | `register_periodic(interval_ns: u64, f: fn(u64))` | called once per timer by the owning subsystem |
| fire | `run_due(now_ns: u64)` | fires every elapsed timer; callbacks run with the registry lock released |
| lock | `sync::Timer` class (rank 5) | leaf — released before any callback runs, so callbacks may take any lock |

Driver: `kernel/src/periodic.rs` spawns one `ktimers` kthread that loops
`timer::run_due(now); park_with_deadline(now + tick)`. The driver is generic —
it never names a subsystem. Per-timer intervals are honored by `run_due`; the
driver granularity only bounds latency.

Forbidden: a kthread (or any site) that hardcodes a list of subsystem ticks
(the pre-R state — `periodic.rs` calling cgroup + tcp-retx + balance + arp by
name). That is the monolithic-tick anti-pattern this doc abolishes.

## 3 Self-registration — the hard rule

Every subsystem registers its **own** periodic work + integration hooks from
**its own init** (the fn the kernel already calls to bring that subsystem up).
The kernel never enumerates "who has timers/hooks." Linux `subsys_initcall`.

| Subsystem | Registers from | Registers |
|---|---|---|
| net | `net::sock::init` | TCP retransmit/RTO timer |
| sched | `install_default_runqueue` | cpu.max bandwidth + SMP load-balance timers |
| virtio-net driver | `set_softirq_iface` (probe) | ARP-cache GC timer |

Each `register_*` is **idempotent** (once-guard: `AtomicBool::swap`), so a
per-CPU or re-entrant init path registers exactly once.

## 4 The hook pattern (leaf crate ↔ owning subsystem)

A leaf crate (no upward deps) that needs a higher subsystem exposes a
`set_<x>_hook(fn …)`. The **owning subsystem** supplies the impl and registers
it from its own init — never the leaf, never a hardcoded kernel block. Cgroup
controllers live in the subsystem they control (`53§`), wired this way:

| Leaf hook | Owner that registers it | Where |
|---|---|---|
| `cgroup::set_freeze/weight/cpuset/signal/pid_resolve_hook` | sched | `sched::cgroup::install` |
| `cgroup` io.stat | block | `block::charge_io` (direct; blk-cgroup) |
| `cgroup::set_notify_hook` | fs (inotify) | kernel boot wiring (cross-crate) |
| `devfs::set_current_hooks` | sched (current ns/root) | kernel boot wiring |
| `klog::set_byte_sink` | the detected console driver (`drv-serial`/fbcon) | on device probe |

A leaf crate MUST NOT depend on the subsystem that fills its hook (that is the
cycle the hook exists to break — e.g. `cgroup`→`devfs`→`sched` once forced the
cpu controller into a kernel glue file; resolved by hooks + correct ownership).

## 5 Forbidden patterns

| Pattern | Why | Instead |
|---|---|---|
| kernel-side hardcoded timer list | monolithic tick; kernel knows every subsystem | `timer::register_periodic` from each subsystem's init |
| one catch-all periodic kthread doing named work | not Linux; couples unrelated subsystems | generic `ktimers` driver + self-registered timers |
| taking runqueue/subsystem locks in the IRQ/post-EOI tick | deadlock vs a preempted lock holder | register a software timer (process ctx) |
| kernel enumerating `X::register_timers()` for each subsystem | kernel hardcodes the membership | subsystem self-registers from its own init |
| leaf crate depending on the subsystem that fills its hook | dependency cycle | hook + register from the owner's init |
