# 13 Scheduler

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`08`,`09`,`14`. Provides: every kernel thread.

Pick which task runs which CPU when. Drive ctxsw via `Context`. Implement `sched_*` syscalls.

Sched core arch-free, hosted-testable, oracle-modeled. Preempt gated by per-CPU `preempt_count`. SMP added only after UP works under stress for ≥1wk. Cross-CPU migration bounded.

## 1 Inputs/outputs

- Deps: `Context::switch` (HAL `14`), Spinlock+PerCpu (`06`), TimerOps (HAL `23`), `Pid`/`Tid` (`01`).
- Provides: `spawn_kernel_thread`, `yield_to_scheduler`, `wake_up`, `block_on`, `sched_*` syscalls.
- HW: timer (TimerOps), IPI (`IrqOps::send_ipi`).

## 2 Frozen invariants

1. Single-runnability: runnable task on exactly one CPU's runqueue at quiescence.
2. Current-task accuracy: per-CPU `current_task` ptr == task whose ctx is loaded in regs.
3. Preempt-count discipline: `preempt_count>0` ⇒ no switch. Zero only at well-defined states (kernel-return-to-user, idle, end-of-softirq).
4. No lost wakeups: `wake_up(t)` after `t` set Sleeping + registered on WQ ⇒ `t` made Runnable. Per `06§6`.
5. vruntime monotonicity: within CFS, runnable task's vruntime never decreases relative to RQ's `min_vruntime`.
6. RT preemption: runnable RT task always preempts Normal-class.
7. Idle uniqueness: each CPU has exactly 1 idle task; never on RQ except when nothing else runnable.
8. Migration bound: task migrates between CPUs ≤1× per tick (default 1ms).

## 3 Classes (high→low prio)

| Class | Notes |
|---|---|
| RT | POSIX SCHED_FIFO+RR. Prio 1..=99 (higher=higher). FIFO=run-until-block. RR=round-robin per priority within quantum (default 100ms). Picked first if any runnable. |
| Normal (CFS) | POSIX SCHED_OTHER+SCHED_BATCH. vruntime fair sched. Task accumulates vruntime ∝ wall_dt scaled by nice weight. RQ = `BTreeMap<Vruntime,&Task>` (RB-tree); leftmost runs. Nice -20..=19; weight = Linux's exact table. |
| Idle | 1/CPU. Runs only when nothing else runnable. Halts CPU until next IRQ. |

## 4 Public ifc

```rust
pub fn init(num_cpus:usize);                     // # Ctx: boot only

pub fn spawn_kernel_thread(name:&'static str, entry:fn(usize)->!, arg:usize) -> Tid;
pub fn yield_to_scheduler();                      // # Sleeps:y
pub fn schedule_now() -> !;                       // thread exit
pub fn wake_up(t:&Task);                          // # Ctx: any
pub fn block_on(wq:&WaitQueue);                   // # Sleeps:y

pub fn current() -> &'static Task;
pub fn current_cpu() -> CpuId;

pub fn sys_sched_yield(_:&SyscallArgs) -> KR<u64>;
pub fn sys_sched_setscheduler(args:&SyscallArgs) -> KR<u64>;
pub fn sys_sched_setaffinity(args:&SyscallArgs) -> KR<u64>;
// ... rest in `15`

pub fn timer_tick();                              // per-CPU timer ISR
```

## 5 Task

```rust
pub struct Task {
  pub tid: Tid, pub pid: Pid, pub name: ArrayString<16>,

  // Shared via Arc per CLONE_* flags at clone3 time:
  pub mm: Arc<AddressSpace>, pub fd_table: Arc<FdTable>,
  pub sig: Arc<SigHandlers>, pub creds: Credentials,
  pub ns: Arc<Namespaces>, pub cgroup: Arc<CgroupNode>,

  // Sched state:
  pub state: AtomicU8,           // Runnable|Sleeping|Stopped|Zombie
  pub class: SchedClass,         // RT{prio,policy} | Normal{weight,vruntime} | Idle
  pub cpu: AtomicU16, pub affinity: CpuMask, pub on_rq: AtomicBool,

  pub kernel_stack: NonNull<u8>,
  pub context: ArchContext,

  pub fpu_state: Option<Box<FpuState>>, pub fpu_owner_cpu: AtomicU16,

  pub pidfd_waiters: WaitQueue, pub exit_status: AtomicI32,

  rq_link: RbTreeLink,           // CFS intrusive
  rt_link: ListLink,             // RT intrusive
}
```

Allocated via slab. `current()` reads per-CPU `current_task` ptr.

## 6 Runqueue (per-CPU)

```rust
struct Runqueue {
  cpu: CpuId,
  nr_running: AtomicU32,
  rt: RtRunqueue,                // 100 prio buckets + nonempty bitmap
  cfs: CfsRunqueue,              // RB-tree by vruntime + min_vruntime
  idle: &'static Task,
  current: AtomicPtr<Task>,
  preempt_count: AtomicU32,      // 0=preemptable
  need_resched: AtomicBool,      // checked at preempt-enable
  lock: Spinlock<RunqueueInner>,
}
```

`lock` covers class struct mutations. `nr_running`/`current`/`preempt_count` lock-free atomic reads. `Runqueue` lives in `PerCpu<Runqueue>`.

## 7 Pick

```
pick_next_task(rq):
  if rq.rt.has_runnable(): return rq.rt.pick_highest_priority()  # O(1) bitmap
  if rq.cfs.has_runnable(): return rq.cfs.pick_leftmost()         # O(log N)
  return rq.idle
```

## 8 schedule()

```
schedule():
  kassert!(current_cpu_preempt_count() > 0, "schedule outside preempt-disabled region")
  rq = current_runqueue()
  prev = rq.current.load(); next = pick_next_task(rq)
  if next == prev: return
  update_vruntime(prev)
  rq.current.store(next); update_per_cpu_pointers(next)
  if next.mm != prev.mm: switch_address_space(&next.mm)            # CR3/TTBR
  Context::switch(&mut prev.context, &next.context)
```

**Lock-held-across-switch**: RQ lock acquired before `pick_next_task`; **next thread drops it** as its first post-switch instruction. Trickiest piece; loom-tested §11.2.

## 9 Preempt

```rust
struct PreemptGuard;                                 // RAII: ++preempt_count on construct
fn preempt_disable() -> PreemptGuard;                // + barrier
fn preempt_enable_no_check();                        // -- only
fn preempt_enable();                                 // --; if 0 && need_resched: schedule()
```

Preemption points: every IRQ exit (after softirq, `preempt_count==0` && `need_resched`); syscall return path (before user); voluntary `yield_to_scheduler`; `preempt_enable` decrement to zero with `need_resched`.

`need_resched` sources: timer tick advances `prev.vruntime` past next-leftmost; wakeup of RT outranking `current`; wakeup of Normal w/ smaller vruntime than `current`; `sched_setscheduler` promoting a task above `current`.

## 10 wake_up

```
wake_up(t):
  target = pick_target_cpu(t); rq = runqueue_of(target)
  rq.lock.lock_irqsave(); {
    if t.state.compare_exchange(Sleeping, Runnable).is_ok():
      insert_into_class(rq, t)
      if t outranks rq.current:
        rq.need_resched.store(true)
        if target != current_cpu(): send_ipi(target, IPI_RESCHED)
  } rq.unlock()
```

IPI handler: only `need_resched=true`. Actual schedule at receiver's IRQ-exit when `preempt_count` returns to 0.

## 11 SMP load balance

Periodic 10ms or on-idle. Pick busiest peer (`nr_running`). If imbalance>threshold, migrate non-current, non-FPU-owner, non-pinned task. Both RQ locks; ordered by CPU id (low-first). Constraints (inv 8): ≤1 migrate/tick window; FPU-owner of any CPU can't migrate (avoids cross-CPU FPU IPI; `14§7.1`); affinity respected.

## 12 Concurrency

- Per-CPU RQ spinlock class `Runqueue` (`06§3.6`); `irqsave` (timer ISR + IPI handler touch).
- Cross-CPU ops (wakeup, migration) take both RQ locks ordered by CPU id.
- `current` ptr + `preempt_count`: atomics, lock-free reads.
- Lock-held-across-switch: schedule() acquires; next task drops.
- `wake_up` callable any context.

Lock order: `Runqueue` < none higher; can't be held while taking PMM/slab/VFS/etc. WQ mechanism handles dependent waits (disk I/O parks WQ; completion releases relevant lock then `wake_up` re-takes RQ fresh).

## 13 Perf budget

| Op | p99 cy |
|---|---|
| `pick_next_task` (CFS) | 200 |
| `pick_next_task` (RT) | 80 |
| `schedule` no-switch | 100 |
| `schedule` same-AS switch | 500 (200 pick + 200 ctxsw + 100 misc) |
| `schedule` cross-AS (KPTI on, PCID hit) | 1500 |
| `wake_up` local | 300 |
| `wake_up` cross-CPU (IPI dominates) | 1200 |
| `timer_tick` | 200 |

Bench: `bench/sched_bench.rs` vs oracle.

## 14 Test contract (frozen)

- Oracle (`tools/oracle-sched/`): single global RQ, per-task vruntime+weight+state, pick=lowest-vruntime-Runnable (RT short-circuit), tick increments curr's vruntime by `wall_dt/weight`, wake = state→Runnable + recompute min_vruntime. Proptest 1M ops `{spawn,wake,sleep,tick,yield,set_nice}`; lockstep prod vs oracle; per-event assert agreement on runnable-set + picked-next.
- Loom lock-cross-switch: 2 CPUs × 4 tasks × 50 events; mutual exclusion across switch boundary; no deadlock under concurrent migration; depth 6.
- Loom wake/sleep: 2 threads (T1 sleep on WQ, T2 wake T1); T1 always Runnable; depth 8.
- Kernel canary: 64 tasks per `14§8`; 1h @ 1ms tick; no canary corruption.
- SMP migration soak 1h: 4 vCPU × 1000 tasks random sleep/wake/CPU-bound mix; no deadlock, no zombie linger, no unaccounted vruntime, total CPU-time ≈ 4 × wall.
- RT correctness: 16 SCHED_OTHER spinners + 4 RT-prio-50 periodic (1ms work / 9ms sleep); RT wake-to-first-instr p99 ≤ 50µs on 4-CPU.
- Soak (bg, not gate per `40§3`): 4h cycles, kernel-build loop + iperf3 + fs_mark tmpfs; zero panic/deadlock/canary-corruption, RT tail bounded, CPU accounting reconciles. PR-time gate uses `paranoid-ci` (`debug-sched`+`debug-sched-canary`+`debug-preempt`).
- Coverage ≥95% `crates/sched/src/`. Every `unsafe` SAFETY ≥30ch.

## 15 Failure modes

- Lock-cross-switch invariant violated: panic.
- Migration of FPU owner: silently refused; load balancer skips; debug-level log.
- `current` ptr ≠ loaded ctx: kassert; checked per-tick by canary harness.
- RQ lock contention >50% on bench: regression triage, not panic.
- vruntime overflow: impossible in 5000y of ns-scale; not guarded.

## 16 Debug

- `debug-sched`: per-switch trace ring (16B/switch, 4096/CPU); `audit_runqueue` per event; `current` ptr canary per preempt-enable.
- `debug-preempt`: assert preempt_count in valid range at every entry/exit.
- `debug-sched-canary`: per-task `[u64;16]` canary checked every yield; the bug-from-last-time guard (`14§8`).

## 17 Log

`target="sched"`, `"sched::rt"`,`"sched::cfs"`,`"sched::balance"`,`"sched::wake"`.

## 18 Cross-spec

`14` (`Context::switch`), `01` (`Tid`,`Pid`), `06` (locks/atomics/RCU for task list, WQ), `15` (`sched_*` syscalls), `27` (`CAP_SYS_NICE` for RT), `26` (cgroup v2 `cpu.weight`/`cpu.max`), `30` (sqpoll = scheduler-spawned kthread).

## 19 Changelog

(none)

