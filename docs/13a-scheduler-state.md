# 13a Scheduler state and entities

FROZEN 2026-09-03. Dep:`01`,`02`,`06`,`08`,`09`. Provides: canonical scheduler state and entities.

## 1

Linux 7.2-shaped task, entity, runqueue, and fair-group state, plus
native fixed-priority extension. Rust ownership replaces C pointers without
flattening protected state into unrelated atomics. Linux and Windows derive one
scheduler-owned priority; no ABI/controller stores a competing result.

## 2

- Inputs: lock/RCU primitives (`06`), task/thread-group identity (`01`), time,
  CPU topology, typed Linux/native configuration, and cgroup scheduler ids.
- Outputs: scheduler-owned task/class/entity/runqueue/group state and coherent
  Linux/native snapshots consumed through typed mutation operations.
- Scheduler mutation owner consumes these types; controller/native ABI adapters
  own identity/validation and translate neutral results.

## 3

1. Every non-CPU-idle task owns `static_prio`, `normal_prio`, effective `prio`,
   `rt_priority`, policy, reset-on-fork, class entities, PI state, affinity, CPU,
   on-rq state, and task-group placement under its scheduler/PI lock.
2. Linux tasks retain exact Linux priority constants and conversions. Native
   tasks retain exact Windows dispatcher levels `1..=31`; neither is silently
   converted into the other's ABI.
3. `SchedClassId` identifies behavior only. It stores no nice, weight, policy,
   RT priority, deadline, vruntime, or native level.
4. Normal/Batch fair load derives from Linux `static_prio`; `SCHED_IDLE` fair
   policy uses idle weight. Group shares and task load never overwrite each other.
5. PI leaves configured/base state unchanged and folds one top donor into
   effective priority/class. Fork starts from normal state, never a PI result.
6. Configured/normal/effective observer snapshots use one generation-checked
   publication. Runtime/entity tuples and scheduler decisions are runqueue-locked;
   several independent atomics are not a coherent replacement for either rule.
7. Owning links point down; back-links from entities/runqueues to groups are
   weak/non-owning, so the graph has no reference cycle.

## 4

Public types: `TaskSched`, priority/policy/class ids, four class entities,
`Runqueue`, `CfsRunqueue`, `TaskGroup`, `GroupFair`, `CfsBandwidth`, and snapshot
types. Constructors/mutators stay private; callers receive opaque
snapshots/references through scheduler operations.

## 5

```rust
pub struct TaskSched {
    pub prio: SchedPriority,
    pub static_prio: SchedPriority,
    pub normal_prio: SchedPriority,
    pub rt_priority: u8,
    pub policy: SchedPolicy,
    pub reset_on_fork: bool,
    pub sched_class: SchedClassId,
    pub se: SchedEntity,
    pub rt: SchedRtEntity,
    pub dl: SchedDlEntity,
    pub nt: SchedNtEntity,
    pub cpu: CpuId,
    pub on_rq: OnRq,
    pub affinity: AffinityState,
    pub group: Arc<TaskGroup>,
    pub pi_waiters: PiWaiterTree,
    pub pi_top_task: Option<TaskRef>,
    pub pi_blocked_on: Option<PiWaiterRef>,
}
```

`OnRq` is Off, Queued, or Migrating. `Task::pi_lock` serializes this state with
wakeup, PI, affinity, and migration. Task lifecycle may expose documented atomic
state observations through a versioned snapshot: readers retry an odd or changed
generation, and writers publish the whole configured/normal/effective tuple while
holding `pi_lock`. This observer protocol does not replace the stable runqueue lock
for scheduling decisions, live reweight, queue placement, PI recomputation, or
runtime/entity state.

Linux constants and projections are exact:

```text
MIN_NICE=-20, MAX_NICE=19, NICE_WIDTH=40
MAX_DL_PRIO=0, MAX_RT_PRIO=100, MAX_PRIO=140, DEFAULT_PRIO=120
NICE_TO_PRIO(nice)=nice+DEFAULT_PRIO
PRIO_TO_NICE(prio)=prio-DEFAULT_PRIO

normal Linux deadline = -1
normal Linux RT       = 99-rt_priority
normal Linux fair     = static_prio
```

`SchedPriority` is a total cross-class ordering: Deadline, PosixRt, NtFixed,
Fair, Idle. Linux constructors/projections preserve the values above. NtFixed
stores dispatcher level `1..=31` directly. Recompute writes `normal_prio`, folds
`pi_top_task`, writes `prio`, then selects effective class. A live Deadline,
PosixRt, NtFixed, or normalized-fair donation survives configured/base changes.

## 6

```rust
pub struct LoadWeight { pub weight: u64, pub inv_weight: u32 }

pub struct SchedEntity {
    pub load: LoadWeight,
    pub run_node: EevdfNode,
    pub deadline: u64,
    pub min_vruntime: u64,
    pub min_slice: u64,
    pub max_slice: u64,
    pub group_node: GroupNode,
    pub on_rq: bool,
    pub sched_delayed: bool,
    pub relative_deadline: bool,
    pub custom_slice: bool,
    pub exec_start: u64,
    pub sum_exec_runtime: u64,
    pub prev_sum_exec_runtime: u64,
    pub vruntime: u64,
    pub vlag: i64,
    pub protected_deadline: u64,
    pub slice: u64,
    pub nr_migrations: u64,
    pub depth: u16,
    pub parent: Option<GroupEntityRef>,
    pub cfs_rq: CfsRqRef,
    pub owned_rq: Option<CfsRqRef>,
    pub runnable_weight: u64,
    pub avg: SchedAvg,
}

pub struct SchedRtEntity {
    pub run_list: RtListNode,
    pub timeout: u64,
    pub watchdog_stamp: u64,
    pub time_slice: u64,
    pub on_rq: bool,
    pub on_list: bool,
    pub back: Option<RtEntityRef>,
    pub parent: Option<RtEntityRef>,
    pub rt_rq: RtRqRef,
    pub owned_rq: Option<RtRqRef>,
}

pub struct SchedDlEntity {
    pub run_node: DlTreeNode,
    pub configured_runtime: u64,
    pub relative_deadline: u64,
    pub relative_period: u64,
    pub bandwidth: u64,
    pub density: u64,
    pub remaining_runtime: i64,
    pub absolute_deadline: u64,
    pub flags: u32,
    pub throttled: bool,
    pub yielded: bool,
    pub non_contending: bool,
    pub overrun: bool,
    pub server: bool,
    pub server_active: bool,
    pub defer: bool,
    pub defer_armed: bool,
    pub defer_running: bool,
    pub defer_idle: bool,
    pub bandwidth_attached: bool,
    pub replenishment_timer: HrTimer,
    pub inactive_timer: HrTimer,
    pub server_runqueue: Option<RunqueueRef>,
    pub server_pick_task: Option<DlServerPickFn>,
    pub pi_entity: Option<DlEntityRef>,
}
```

Normal/Batch use exact nice weight/inverse tables. `SCHED_IDLE` remains in Fair
with `WEIGHT_IDLEPRIO=3`, `WMULT_IDLEPRIO=1431655765`, independent of nice;
`SchedClassId::Idle` is reserved for per-CPU idle task. Live reweight accounts
old runtime/load, rescales lag/deadline, changes weight, updates averages, and
restores entity. DL requested/live runtime/deadline, flags, bandwidth, timers,
server state, and PI entity form one runqueue-locked group.

## 7

```rust
pub struct Runqueue {
    pub cpu: CpuId,
    pub nr_running: u32,
    pub current: TaskRef,
    pub idle: TaskRef,
    pub cfs: CfsRunqueue,
    pub rt: RtRunqueue,
    pub dl: DlRunqueue,
    pub nt: NtRunqueue,
    pub need_resched: bool,
    pub nr_switches: u64,
    pub leaf_cfs_rqs: LeafCfsRqList,
    pub tmp_alone_branch: Option<LeafCfsRqLink>,
    pub lock: RawSpinlock,
}

pub struct CfsRunqueue {
    pub load: LoadWeight,
    pub nr_queued: u32,
    pub h_nr_queued: u32,
    pub h_nr_runnable: u32,
    pub h_nr_idle: u32,
    pub sum_w_vruntime: i64,
    pub sum_weight: u64,
    pub zero_vruntime: u64,
    pub sum_shift: u8,
    pub tasks_timeline: EevdfTree<EntityRef>,
    pub curr: Option<EntityRef>,
    pub next: Option<EntityRef>,
    pub avg: SchedAvg,
    pub removed: RemovedSchedAvg,
    pub last_update_tg_load_avg: u64,
    pub tg_load_avg_contrib: u64,
    pub propagate: bool,
    pub prop_runnable_sum: i64,
    pub h_load: u64,
    pub last_h_load_update: u64,
    pub h_load_next: Option<EntityRef>,
    pub on_list: bool,
    pub leaf_cfs_rq_list: LeafCfsRqLink,
    pub idle: bool,
    pub runtime_enabled: bool,
    pub runtime_remaining: i64,
    pub throttled_pelt_idle: u64,
    pub throttled_clock: u64,
    pub throttled_clock_pelt: u64,
    pub throttled_clock_pelt_time: u64,
    pub throttled_clock_self: u64,
    pub throttled_clock_self_time: u64,
    pub throttled: bool,
    pub pelt_clock_throttled: bool,
    pub throttle_count: u32,
    pub throttled_list: ThrottledCfsRqLink,
    pub throttled_csd_list: ThrottledCfsRqLink,
    pub throttled_limbo_list: ThrottledCfsRqLink,
    pub rq: WeakRunqueueRef,
    pub owner: Weak<TaskGroup>,
}

pub struct RemovedSchedAvg {
    pub lock: RawSpinlock,
    pub nr: u32,
    pub load_avg: u64,
    pub util_avg: u64,
    pub runnable_avg: u64,
}

pub struct TaskGroup {
    pub id: SchedGroupId,
    pub parent: Option<Weak<TaskGroup>>,
    pub children: GroupChildren,
    pub sibling_link: TaskGroupLink,
    pub global_link: TaskGroupLink,
    pub idle: bool,
    pub shares: u64,
    pub load_avg: AtomicLong,
    pub per_cpu: PerCpu<GroupFair>,
    pub cfs_bandwidth: CfsBandwidth,
}

pub enum GroupFair {
    Root { cfs_rq: WeakCfsRunqueueRef },
    Node { entity: SchedEntity, child_rq: Box<CfsRunqueue> },
}

pub struct CfsBandwidth {
    pub lock: RawSpinlock,
    pub period: Duration,
    pub quota: u64,
    pub runtime: u64,
    pub burst: u64,
    pub runtime_snapshot: u64,
    pub hierarchical_quota: i64,
    pub idle: bool,
    pub period_active: bool,
    pub slack_started: bool,
    pub period_timer: HrTimer,
    pub slack_timer: HrTimer,
    pub throttled_rqs: ThrottledCfsRqList,
    pub periods: u64,
    pub throttled_periods: u64,
    pub bursts: u64,
    pub throttled_time: u64,
    pub burst_time: u64,
}
```

The class order is Deadline, PosixRt, NtFixed, Fair, Idle. NtFixed has 31 FIFO
buckets and a nonempty bitmap. Root `GroupFair::Root.cfs_rq` aliases that CPU's
`Runqueue::cfs` and has no group entity. Each non-root `Node` owns one child
`cfs_rq` and parent-facing entity per CPU. Weak root/runqueue/group back-links
avoid ownership cycles.

`RemovedSchedAvg` is a separately locked count plus removed load/util/runnable
averages. Each CPU leaf list contains task-bearing `cfs_rq`s in hierarchy order;
`tmp_alone_branch` maintains that order during throttling and group insertion.
Each `cfs_rq` carries local bandwidth runtime, throttling clocks/state/list link,
idle cache, group-load propagation deltas, and hierarchical-load cursor.
`TaskGroup::cfs_bandwidth` owns quota, timers, global runtime, and statistics.

Fair enqueue walks the task and parent entities. Selection starts at root:
run-to-parity may retain protected current, an eligible buddy may precede the
eligible-earliest-virtual-deadline search, and group entities descend through
`owned_rq` to a task. Eligibility uses `sum_w_vruntime`, `sum_weight`,
`zero_vruntime`, and `sum_shift`. Tick/accounting updates every ancestor.

PELT rate-limits differential `TaskGroup::load_avg` contribution updates, copies
child runnable/util sums into parent entity, propagates weighted-load deltas to
ancestors, and calculates per-task hierarchical load from `h_load` and
`h_load_next`. Balance iterates leaf list; throttling removes and
unthrottling restores affected hierarchy branch.

`cpu.weight` converts with `round_closest(weight*1024/100)`; reads use
`clamp(round_closest(shares*100/1024),1,10000)`. `shares_mutex` updates canonical
group shares, then each CPU runqueue is locked separately and `load_avg`, the
per-CPU contribution, entity weight, and ancestors are updated. It performs no
task `sched_change`, member enumeration, or task-load write.

## 8

```rust
pub struct SchedNtEntity {
    pub base_priority: u8,
    pub dynamic_priority: u8,
    pub relative_priority: NtRelativePriority,
    pub boost_disabled: bool,
    pub primary_group: u16,
    pub affinity: ProcessorGroupSet,
    pub explicit_group_restriction: bool,
    pub priority_decrement: u8,
    pub adjust_increment: u8,
    pub adjust_reason: NtAdjustReason,
    pub quantum_reset: u8,
    pub quantum_remaining: u64,
    pub on_rq: bool,
}

pub struct NtProcessSchedConfig {
    pub class: NtPriorityClass,
    pub base_priority: u8,
    pub boost_disabled: bool,
    pub foreground: bool,
    pub primary_group: u16,
    pub process_affinity: ProcessorGroupSet,
    pub explicit_outside_primary_threads: u32,
    pub members: StableMemberSet,
}
```

Process class bases are Idle 4, Below 6, Normal 8, Above 10, High 13, Realtime
24. The class/relative table is:

| Class | Idle | Lowest | Below | Normal | Above | Highest | Critical |
|---|---:|---:|---:|---:|---:|---:|---:|
| Idle | 1 | 2 | 3 | 4 | 5 | 6 | 15 |
| Below | 1 | 4 | 5 | 6 | 7 | 8 | 15 |
| Normal | 1 | 6 | 7 | 8 | 9 | 10 | 15 |
| Above | 1 | 8 | 9 | 10 | 11 | 12 | 15 |
| High | 1 | 11 | 12 | 13 | 14 | 15 | 15 |
| Realtime | 16 | 22 | 23 | 24 | 25 | 26 | 31 |

Ordinary relative ranges are `-2..=2`, or `-7..=6` for Realtime; Idle `-15`
and TimeCritical `+15` are valid in both. Direct priority is `1..=31`; zero
fails. `ThreadPriority` levels `16..=31` require an
`IncreaseBasePriorityPermit`; process-class membership is not authorization. It
changes dynamic/current non-PI priority only and leaves base/relative unchanged.

`ThreadBasePriority` retains requested relative increment and saturation. For a
realtime process, derived base clamps to `16..=31` and current becomes base.
Otherwise base clamps to `1..=15`; saturation makes current equal base, while an
ordinary change computes decayed old current, adds `new_base-old_base`, and
clamps to `1..=15`. It clears decrement and resets quantum when current changes,
preserving an existing dynamic adjustment as a delta instead of discarding it.

`ProcessBasePriority` accepts `1..=31`; increasing it requires an
`IncreaseBasePriorityPermit`. Process-class changes first choose table base.
Both operations compute `delta=new_process_base-old_process_base` and add it to
every member base. Realtime process base clamps member base/current to
`16..=31`; variable base clamps to `1..=15`; saturation pins its band edge.
Each member clears decrement, resets quantum, and sets current to new base, so a
direct `ThreadPriority` value is overwritten. Retained relative/saturation drive
later thread-base operations.

`ProcessPriorityBoost` sets process boost-disable and overwrites every existing
member flag. Later `ThreadPriorityBoost` changes one thread; a later process
request overwrites member overrides again. New threads start relative Normal,
inherit process affinity/boost-disable, and never inherit creator
relative/direct/dynamic/PI priority.

Variable levels `1..=15` execute two adjustment paths:

| Reason | Eligibility | Priority result | Quantum/decrement result |
|---|---|---|---|
| Boost | current `<= increment`, current `<13`, boost enabled | `min(increment+1,13)` | add gained levels to decrement; `quantum=max(quantum,4)-1` |
| Unwait | variable; boost enabled; decrement zero | `max(current,min(base+increment+foreground_separation,15))` | foreground excess over `base+increment` becomes decrement |

Unwait resets quantum when base is `14..=15`, or when decrement is zero and
increment nonzero. Except for kernel-APC completion it consumes one quantum;
expiration resets quantum and computes `max(current-(decrement+1),base)`, then
clears decrement. Realtime levels reset quantum without boost/decay. Every path
clears adjustment reason after application. Boost-disable blocks future boosts
without cancelling current boost or PI. Equal levels are FIFO/RR; higher
preempts.

`NtQuantumPolicy` contains fixed-short `[18,18,18]`, fixed-long `[36,36,36]`,
variable-short `[6,12,18]`, and variable-long `[12,24,36]` for separation
`0..=2`; Idle uses 6 and client default is variable-short. Foreground selects
the configured separation entry and adds separation to eligible Unwait boosts.

## 9

Configuration-only views consume one generation-checked scheduler snapshot;
writers hold `pi_lock` across its publication. Runtime/entity views and scheduler
decisions additionally use the stable runqueue lock. Linux nice is
`PRIO_TO_NICE(static_prio)`, `task_prio` is effective Linux priority minus
`MAX_RT_PRIO`, and RT priority/policy are requested fields. Proc stat fields 18,
19, 40, and 41, proc sched, coredump, and I/O-priority fallback use these
accessors. Native basic information reports dynamic/effective dispatcher
priority and retained relative base; process/thread class, base, boost, and
affinity queries read their canonical configuration owner.

## 10

| Operation | Complexity |
|---|---|
| priority/class derivation or snapshot | O(1) |
| class enqueue/dequeue | O(1) fixed class; O(log entities) fair |
| fair hierarchy walk | O(depth × log entities-at-level) |
| group-share propagation | O(CPUs × depth × log entities-at-level) |
| native process-wide mutation | O(member threads × class queue cost) |

## 11

| State | Lock/read protocol |
|---|---|
| configured/normal/effective observer view | generation-checked snapshot |
| task priority mutation/entity/affinity/group cache | TaskPi then stable Runqueue |
| PI waiter state | RTMutexWait then TaskPi then Runqueue |
| `cfs_rq`, class queues, entity runtime | owning Runqueue |
| task-group shares/bandwidth | group lock then one Runqueue at a time |
| native process config/member set | ThreadGroupSched then one task pair |
| CSS identity | cgroup locks/RCU; not scheduler-owned |

Weak back-links are upgraded only under owning lock/RCU lifetime protection.
Snapshot readers use the lock row; statistics marked approximate may use atomic
loads and never drive scheduling decisions.

## 12

`debug-sched-prio` audits configured/normal/effective derivation and PI donor;
`debug-sched-group` audits entity ancestry, leaf lists, PELT propagation, shares,
runtime, and throttle transitions. Debug builds reject root group entities,
strong ownership cycles, stale parent links, and class/entity mismatches.

## 13

Log targets: `sched::prio`, `sched::pi`, `sched::fair`, `sched::group`,
`sched::bandwidth`, `sched::nt`, and `sched::affinity`. Logs contain snapshots
and transitions only; no log-derived state or string-key control path exists.

## 14

Priority derivation and root alias access: ≤20 cycles each. Disabled-controller
tick overhead: zero. PELT/hierarchical-load/bandwidth additions together consume
≤120 cycles per root-task tick and ≤40 cycles per additional hierarchy level.

## 15

- Exhaust all Linux constant conversions and nice weight/inverse-weight tables;
  one-bit/one-entry perturbations must fail positive controls.
- Model every `TaskSched` transition off-rq, queued, current, migrating, PI/DL
  donated, and exiting; compare all configured/normal/effective/entity fields.
- Distinguish EEVDF from leftmost-vruntime; cover lag/deadline rescale and every
  `cfs_rq` sum/cursor update through nested group enqueue/dequeue/reweight.
- Cover root alias/no-entity, leaf-list order, removed averages, differential
  group load, parent PELT propagation, hierarchical load, and idle-group counts.
- Cover quota/burst refill, period/slack timers, nested throttle/unthrottle, all
  clocks/lists/statistics, migration while throttled, and disabled fast path.
- Exhaust native class/relative/direct tables, privilege, process/thread base
  deltas, both boost paths, decay, quantum tables, propagation, and group masks.
- Ownership test rejects mutable scheduler fields outside `sched`, ABI errors,
  duplicate cgroup identity, strong back-links, and non-aliased root `cfs_rq`.
- Hosted state/model coverage ≥95%; loom covers lock rows through depth 8.

## 16

- Invalid constants, impossible class/entity tuples, duplicate queue placement,
  root entity, stale group parent, or bandwidth-list mismatch are invariant bugs.
- Arithmetic checks/saturates only where bounded semantics permit; no wrap changes ordering.
- Failed validation/admission publishes no state. Infallible post-CSS attach has
  no allocation/error path and panics before continuing on invariant violation.
- Weak-link upgrade failure means object teardown; operation retries or returns
  neutral terminating/busy error before mutation.

## 17

Consumers: scheduler mutation/locking/selection; cgroup CPU controller; native
process/thread ABI adapters; ownership/layering enforcement.

## 18

(none)
