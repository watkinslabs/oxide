# 13 Scheduler

FROZEN 2026-09-03. Dep:`01`,`02`,`06`,`08`,`09`,`13a`,`14`. Provides: every kernel thread.

## 1

Choose which task runs on each CPU, account execution, implement Linux scheduling
semantics, and provide one execution model for other personalities. Oxide follows
Linux 7.2's task priority, class entity, PI, stable task/runqueue lock, EEVDF, and
fair task-group architecture. Native Windows scheduling is a real class in that
owner, not a Wine relay, host-nice mapping, or parallel scheduler.

Canonical structures and field meanings are in `13a`; this spec owns mutation,
locking, selection, wakeup, migration, and verification.

## 2

- Inputs: context switch (`14`), locks/per-CPU storage (`06`), timer/reschedule
  IPI HAL operations, `Pid`/`Tid` (`01`), opaque scheduling-group operations,
  and typed native scheduling requests.
- Outputs: task creation/exit, schedule/wake/block, Linux nice/policy/affinity,
  fair-group operations, native process/thread scheduling operations, and
  coherent snapshots for procfs, coredump, IPC PI, and native queries.
- `crates/kernel/sched` owns all scheduling execution state. Syscall, cgroup,
  procfs, coredump, IPC, and native-object code submits typed requests or renders
  snapshots; it never writes task scheduling fields.
- `sched` depends on neither cgroup nor a Linux/native ABI crate. Callers map
  opaque group ids and neutral scheduler errors to identities/status codes.

## 3

1. A runnable task is current on one CPU or queued on exactly one class runqueue
   at quiescence, never both and never neither.
2. Each per-CPU current pointer identifies the task whose context is loaded.
3. Canonical configured, normal, effective, entity, PI, affinity, and task-group
   state has the exact ownership and derivation in `13a§3`–`13a§8`.
4. A class tag identifies behavior only. No encoded class parameter, standalone
   task weight, saved base class, or ABI-owned scheduler result exists.
5. Every live priority/class/entity/affinity/group mutation uses stable task and
   runqueue locking plus the scheduler-change transaction where §6 requires it.
6. PI leaves requested/base configuration unchanged while updating PI donor,
   effective priority/class, and borrowed class runtime state. Final deboost
   reveals the current normal priority, including changes made while boosted.
7. Task nice controls its fair entity. `cpu.weight` controls a parent group
   entity. They are independent and compose hierarchically.
8. Fair selection implements Linux EEVDF eligibility/deadline, run-to-parity,
   buddy, and hierarchy rules. A leftmost-vruntime task tree is not an oracle.
9. Native levels `1..=31` use strict fixed-priority FIFO/RR, dynamic boost/decay
   only in `1..=15`, and the process/thread rules in `13a§8`.
10. Requested, cpuset, native-process/thread, online, and effective affinity are
    one coherent locked result; no reader sees a hybrid multiword mask.
11. Wake after Sleeping publication and wait-queue registration makes the task
    runnable per `06§6`.
12. `preempt_count > 0` prevents switching. Class order is Deadline, PosixRt,
    NtFixed, Fair, Idle; within a class its canonical priority order applies.
13. Each CPU has one idle task, never queued on an ordinary class runqueue.
14. CPU/runqueue ownership changes only under migration protocol. Stable lock
    acquisition retries while `on_rq == Migrating`.

## 4

```rust
pub fn init(num_cpus: usize);
pub fn spawn_kernel_thread(name: &'static str, entry: fn(usize) -> !, arg: usize) -> Tid;
pub fn yield_to_scheduler();
pub fn schedule_now() -> !;
pub fn wake_up(task: &Task);
pub fn block_on(waitq: &WaitQueue);
pub fn current() -> &'static Task;
pub fn current_cpu() -> CpuId;

pub fn priority_snapshot(task: &Task) -> PrioritySnapshot;
pub fn affinity_snapshot(task: &Task) -> AffinitySnapshot;
pub fn set_user_nice(task: &Task, nice: i8) -> SchedResult<()>;
pub fn set_scheduler(task: &Task, attr: SchedAttr) -> SchedResult<()>;
pub fn set_task_affinity(task: &Task, request: AffinityRequest) -> SchedResult<()>;
pub fn set_cpuset_affinity(task: &Task, allowed: CpuMask) -> SchedResult<()>;
pub fn prepare_task_group_attach(task: &Task, group: &TaskGroup) -> SchedResult<TaskGroupAttach>;
pub fn commit_task_group_attach(prepared: TaskGroupAttach);
pub fn set_group_shares(group: &TaskGroup, shares: u64) -> SchedResult<()>;
pub fn apply_nt_process(group: &ThreadGroup, request: NtProcessSchedRequest) -> SchedResult<()>;
pub fn apply_nt_thread(task: &Task, request: NtThreadSchedRequest) -> SchedResult<()>;
pub fn timer_tick();
```

ABI adapters validate immutable structure/rights requirements and translate
`SchedError::{Invalid,Denied,NoCpu,Busy,Admission,Terminating}`. State-dependent
authorization/admission and mutation remain inside typed scheduler operations;
scheduler imports neither Linux `Errno` nor `NTSTATUS`.

## 5

`task_rq_lock(task)` is the external mutation primitive when the caller does not
hold `task.pi_lock`:

1. disable local IRQs and acquire `task.pi_lock`;
2. read `task.cpu` and acquire that runqueue lock;
3. accept only if it remains the task's runqueue and the task is not Migrating;
4. otherwise release both, wait while Migrating, and retry.

`__task_rq_lock(task)` requires `pi_lock` already held, acquires/revalidates only
the actual runqueue, and retries migration. PI/RT-mutex paths use this form and
never recursively acquire `pi_lock`.

Lock order is TaskPi before Runqueue. Two-runqueue operations acquire runqueues
in ascending CPU order after TaskPi. The existing wake lock is folded into or
renamed TaskPi; two task locks for wake/PI/migration are forbidden.

An RT mutex waiter lock precedes owner TaskPi. A chain walk encountering the
reverse order uses try-lock, drop, and retry as Linux does; it cannot block while
holding a later lock. Native process-wide mutation takes ThreadGroupSched before
each member's TaskPi/runqueue pair and holds no runqueue while advancing members.

## 6

`sched_change(task, flags)` runs under the stable locks. Begin:

Class change requires matched `DEQUEUE_CLASS|ENQUEUE_CLASS`; changing class
without both is an invariant failure. A same-class change sets neither.

1. update runqueue clock and add `DEQUEUE_NOCLOCK`;
2. for `DEQUEUE_CLASS`, call old class `switching_from` before any snapshot;
3. snapshot old class and queued/running state;
4. without `DEQUEUE_CLASS`, snapshot old class `get_prio`, or effective `prio`
   when that callback is absent;
5. dequeue a queued task and call `put_prev_task` for a running task;
6. for `DEQUEUE_CLASS`, call old class `switched_from`.

The body changes one coherent requested/derived/entity state. End:

1. with `ENQUEUE_CLASS`, call new class `switching_to`;
2. enqueue a formerly queued task and `set_next_task` for a formerly running one;
3. with `ENQUEUE_CLASS`, call new class `switched_to`;
4. with `ENQUEUE_CLASS`, perform class-change preemption/balance logic; otherwise
   `prio_changed(old_prio)`;
5. run deferred balance callbacks after unlock.

Queue/current state is idempotent across failure. Linux nice, policy, RT/DL
parameters, reset-on-fork, utilization clamps, PI priority/class, native
priority/boost, task entity reweight, task-group attachment, and affinity changes
that migrate a task use this transaction. Group-share reweight does not: it uses
the distinct per-CPU operation in `13a§7`.

`set_user_nice` changes latent Linux static priority for RT/DL tasks without
immediate class effect. For a fair task it reweights and recomputes priority in
the transaction. Fork snapshots the parent's normal/configured state under lock,
never effective PI state. Deadline fork without reset fails; reset-on-fork moves
RT/DL to normal policy, clears RT priority, clamps negative nice to zero, clears
the flag, and recomputes entity state before first enqueue.

## 7

Each task owns `pi_waiters`, `pi_top_task`, and `pi_blocked_on` (`13a§5`). Each
waiter participates in its mutex waiter tree and the owner's aggregate waiter
tree. Donation propagates recursively, requeues a blocked waiter when its sort
key changes, detects cycles, and aggregates all PI locks owned by the task.

Linux fair nice/weight is not donated through RT mutexes: a non-RT/non-DL waiter
contributes DefaultPrio. RT/DL ordering remains exact. An NtFixed waiter donates
its exact native class/level through the cross-class ordering; configured base
changes cannot erase it. DL donation installs the borrowed `pi_entity`; a class
tag without borrowed deadline state is forbidden.

PI mutation uses TaskPi plus `__task_rq_lock` and §6. It may update top donor,
effective priority/class, DL PI/replenishment state, and RT timeout/runtime; it
never changes policy, static/base priority, RT parameters, native configuration,
or reset-on-fork. Deboost precedes waking a successor. Timeout, owner exit,
waiter transfer, and chain unwind leave no stale donation.

## 8

Linux effective affinity is `requested & cpuset & online`. Native state contains
full process/thread group sets plus explicit process/thread primary groups;
effective affinity additionally intersects cpuset and online. A processor group
contains at most 64 active logical CPUs and `KAFFINITY` bit N means group-local
CPU N. Group topology is one scheduler-owned translation into global CPU ids.

On systems with more than 64 CPUs, a new native process defaults to every active
group; process primary group is selected round-robin and initial thread primary
matches it. A new thread inherits creator primary group. An unrestricted thread
may execute across process groups; primary group controls single-group legacy
APIs and ideal-CPU preference, not a hidden group-zero limit.

`ProcessAffinityMask` names process primary group. It rejects zero or a bit
outside that group's active system mask. It fails when a thread was explicitly
moved outside process primary group; otherwise it replaces process affinity with
that one group and overwrites every existing thread with the exact new mask.
Shrinking and later expansion both reset/widen thread affinity. New threads
inherit this process restriction.

`ThreadAffinityMask` applies to thread primary group. Its native adapter first
strips bits outside that group's active system mask, then rejects zero or any bit
outside process affinity for that group. It atomically replaces the thread mask
and returns old primary-group mask. `ThreadGroupInformation` instead names one
active group and requires nonzero mask with no unavailable bit; success restricts
thread to that group, makes it thread primary, returns old group+mask, and marks
process multi-group when group differs from process primary. Group-aware query
returns exact pair. Scheduler code never assumes group zero.

Process-affinity query for current process projects process/system masks through
calling thread primary group. Query of another process returns its masks only
when all threads occupy one group; with threads in multiple groups both masks are
zero. Process-group query returns the sorted unique group ids represented by
assigned threads, including every group in default all-group state, and reports
required count without truncation when output capacity is insufficient.

If a task's current CPU becomes disallowed, the transaction migrates to an
allowed CPU and waits for completion before success. Queries copy one locked
snapshot.

## 9

Scheduler task-group structures, EEVDF hierarchy, shares conversion, and
per-CPU reweight are in `13a§7`. Group creation publishes complete per-CPU state;
weak back-links avoid cycles. Destruction waits for task/group references.

Cgroup migration performs all checks/resource reservation before CSS commit,
publishes CSS membership under `css_set_lock`, releases that lock, then consumes
prepared `TaskGroupAttach` in infallible scheduler callback before releasing the
migration token. `TaskSched::group` is Linux's scheduler placement
cache, not competing cgroup identity. RCU membership readers may observe new CSS
during the bounded interval before cache update; scheduling continues from the
locked cache. Commit uses §5/§6 to change entity parent and restore queued or
running state. No allocation, error return, or rollback exists after CSS commit.

## 10

`schedule` runs preemption-disabled with local runqueue locked, updates clock and
previous entities, then picks Deadline, PosixRt, NtFixed, Fair, Idle. It updates
current/address-space pointers and switches via `Context`. The selected task
drops the inherited runqueue lock at its first post-switch instruction.

Fair selection follows `13a§7`. NtFixed selects its highest nonempty level and
FIFO head. Equal-level quantum expiration rotates to tail; higher level preempts.
Native boost/decrement/quantum rules are `13a§8`.

Wake takes TaskPi, selects from coherent effective affinity, then takes the target
runqueue. It transitions Sleeping to Runnable, enqueues through current class and
group, and requests local/remote rescheduling if it outranks current. The IPI
sets `need_resched`; switching waits for a valid preemption point.

Preemption points are IRQ exit, syscall/user return, voluntary yield, and
preempt-enable reaching zero with `need_resched`. POSIX RR defaults to 100ms;
FIFO runs until block/yield or higher-priority preemption.

## 11

Balancing uses class entities and hierarchical load, not raw task count. It
respects effective affinity, task group, migration-disabled state, and class
rules. Migration sets OnRq::Migrating before CPU ownership, publishes the new CPU
with release ordering, then restores Queued/Off state. Cross-CPU locks are ordered
by CPU id. A task migrates at most once per tick window.

## 12

- Task mutation: TaskPi, then stable Runqueue.
- PI: RTMutexWait, TaskPi, then `__task_rq_lock`; reverse chain edges retry.
- Native process mutation: ThreadGroupSched, then one TaskPi/Runqueue pair.
- Cross-CPU migration: TaskPi, then runqueues ordered by CPU id.
- Group shares: GroupShares, then one runqueue at a time; attach never takes
  GroupShares while runqueue-locked.
- Cgroup attach: cgroup migration token publishes membership before the infallible
  scheduler callback and remains held until scheduler placement agrees.
- Runqueue locks are IRQ-safe. ABI snapshots and multi-field decisions lock;
  only documented statistics permit lockless reads.
- Runqueue locks cannot nest inside MM, slab, VFS, cgroup-tree, handle-table, or
  object-manager locks.

## 13

| Operation | Complexity |
|---|---|
| RT/NtFixed enqueue and pick | O(1) bitmap/bucket |
| fair enqueue/dequeue/pick | O(depth × log entities-at-level) |
| task priority/entity change | O(depth × log entities-at-level) |
| affinity change | O(retries + optional migration) |
| group shares change | O(CPUs × depth × log entities-at-level) |
| cgroup attach | O(depth × log entities-at-level) |

No single task/group ABI operation scans all tasks.

## 14

| Operation | p99 budget |
|---|---|
| RT or NtFixed pick | 80 cycles |
| fair pick, depth 1 | 250 cycles |
| schedule, no switch | 120 cycles |
| schedule, same address space | 600 cycles |
| local wake | 350 cycles |
| cross-CPU wake excluding IPI transport | 500 cycles |
| timer tick, root task | 250 cycles |

Hierarchy benchmarks may not regress over 10% without spec revision.

## 15

- A lockstep model contains every configured/normal/effective priority field,
  class/entity runtime, top PI waiter, requested/cpuset/effective affinity,
  native group masks, task group, and EEVDF state. Run at least 1,000,000
  generated spawn/fork/exit/sleep/wake/tick/yield/mutate/migrate operations.
- Exercise each mutation off-rq, queued, running, sleeping, PI-boosted, and
   migrating. Assert runnable set, selected task, snapshot, class/entity placement,
   accounting, and pre-publication unwind. Independently corrupt each field as a
   positive control and require the intended failure.
- Exhaust Linux nice/RT conversions and native process classes, relative/direct
  levels `1..=31`, boosts, boost-disable, quantum modes, process/thread affinity,
   and processor groups. Verify exact table values, strict preemption, FIFO/RR,
   both adjustment paths, base-delta preservation, realtime privilege, process
   boost overwrite/thread override, new-thread inheritance, and band boundaries.
- Native affinity tests cover unavailable-bit rejection, legacy thread-mask
  stripping, zero-after-strip, process-subset rejection, process reset/widen of
  every thread, explicit cross-primary process failure, primary-group changes,
  old-value returns, default all-group execution, and more than 64 CPUs.
  Query tests cover caller-primary projection, other-process multi-group zeros,
  sorted group enumeration, and insufficient-capacity required count.
- EEVDF tests distinguish it from leftmost vruntime and cover eligibility,
  run-to-parity, buddy, deadlines, reweight rescale, hierarchy descent, and old
  weight accounting.
- Fair-group tests cover equal groups with 2 tasks versus 1 (aggregate 1:1),
  unequal/nested shares, nice within a group, attach/fork/migration, live
  reweight, differential load-avg updates, parent PELT propagation, hierarchical
  task load, leaf-list balance, quota throttle/unthrottle, concurrent
  attach/reweight/exit, pre-commit failure, and post-commit infallibility.
- PI tests cover multiple owned locks, chains, reverse-lock retry, native donor,
  DL borrowed entity, deboost-before-wake, timeout/exit, and fork while boosted.
- Loom depth at least 8 covers task-rq retry, PI/wakeup, queue restoration,
  two-rq order, group attach, and multiword affinity readers.
- Source-ownership tests reject direct scheduler writes outside `sched`, encoded
  class parameters, standalone task weight, saved base class, cgroup member
  weight fanout, and ABI types in scheduler APIs.
- Hosted scheduler coverage is at least 95%; every `unsafe` has a specific proof;
  both target architectures compile shared paths. Final implementation runs one
  x86-64 and AArch64 scheduler canary; docs/hosted-only changes do not boot.

## 16

- Invalid/unauthorized requests return the personality's translated error with
  no partial scheduler mutation.
- Scheduler-change unwind restores exact queue/current state or panics before
  publication; duplicate/lost enqueue is forbidden.
- Current/context mismatch, duplicate membership, invalid entity placement,
  lock-order violation, or fallible post-CSS attach is a debug panic.
- Migration races retry; no unlocked fallback exists.
- Group destruction with live scheduler references is rejected.
- Runtime arithmetic is checked/saturating unless Linux bounds prove safety.

## 17

`debug-sched` audits switches/runqueues/entities/current; `debug-sched-locks`
traces retry/migration/order; `debug-sched-prio` traces derivation/PI/native;
`debug-sched-group` traces hierarchy/shares/attach. Traces are observations, not
state. Log targets: `sched`, `sched::fair`, `sched::rt`, `sched::dl`, `sched::nt`,
`sched::prio`, `sched::group`, `sched::affinity`, `sched::balance`, `sched::wake`.

## 18

Consumers: context switch, Linux ABI, IPC PI, cgroup CPU controller, security,
native process/thread ABI, repository ownership, and syscall layering.

## 19

(none)
