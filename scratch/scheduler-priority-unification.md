# Scheduler priority unification

The implementation sequence follows `docs/13` after R135. Every row is a
separate fresh branch from the then-current `origin/main`, merged and deleted
before its dependent row begins. Parallel rows have disjoint write ownership.

| Status | Branch | Change | Exit evidence |
|---|---|---|---|
| MERGED | `Z20-scheduler-state` | Freeze extracted canonical scheduler state/entity contract before revising its existing dependents | PR #7134; standalone freeze template; no ratchet growth |
| IN-PROGRESS | `R135-scheduler-priority-model` | Replace the obsolete scheduler/cgroup contracts with the Linux 7.2 priority, lock, EEVDF, task-group, PI, affinity, and native fixed-priority model | spec/manifest/xref checks; no ratchet growth versus clean main |
| CLAIMED | `B3319-unify-scheduler-priority` | Add canonical configured/normal/effective priority, class entities, coherent snapshots, and remove encoded class parameters/standalone task weight | all conversions and snapshots; queued/running/blocked mutation controls; both-arch build |
| PENDING | unclaimed | Add `TaskPi` + stable `task_rq_lock` retry and the RAII scheduler-change transaction; route Linux policy/nice/fork writers through it | migration/queued/running/wakeup loom controls; source-writer gate |
| PENDING | unclaimed | Rebuild PI around owner-wide waiter aggregation, blocked-on propagation, and canonical effective priority | multi-lock/chained PI, deboost, timeout, exit, and fork controls |
| PENDING | unclaimed | Replace flat leftmost-vruntime scheduling with Linux EEVDF task entities | oracle lockstep; discriminating EEVDF positive controls |
| PENDING | unclaimed | Add per-CPU fair task-group entities/runqueues and replace cgroup member-weight fanout | equal-group unequal-task-count, nested shares, attach/reweight/exit races |
| PENDING | `B3318-windows-thread-information` | Rebase the preserved native thread-information/affinity work onto canonical scheduler APIs; do not retain its provisional field-level mutations | x86-64 NT ABI/error tests and coherent affinity races |
| PENDING | unclaimed | Add `ThreadGroup` native process scheduling configuration and `NtFixed` queues, quantum, boosts, decay, and process-wide transactions | exhaustive 1..31/table tests, strict-preemption/RR/decay controls, Wine/native differential tests |
| PENDING | unclaimed | Cut procfs, coredump, I/O-priority, cgroup, syscall, IPC, and native readers/writers over; delete every shadow representation and compatibility hook | exhaustive source ownership scan; full hosted suite; both architectures; one final scheduler boot/canary |

`KI-0321` owns the split scheduler-state/cgroup-weight defect, `KI-0322` owns
the flat non-EEVDF fair scheduler, and `KI-0323` owns the missing native fixed
dispatcher class. A row is complete only after its PR is merged and its branch
and worktree are deleted.
