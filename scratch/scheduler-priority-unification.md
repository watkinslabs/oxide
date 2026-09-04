# Scheduler priority unification

Snapshot: `origin/main` `d9f3504e3` after PR #7146. `MERGED` means only the
behavior named in that row landed; it does not mean the complete `docs/13`
model is implemented.

| Status | Branch | PR | Merged behavior | Boundary still open |
|---|---|---|---|---|
| MERGED | `F1531-scheduler-eevdf-foundation` | #7138 | Canonical configured/normal/effective task priority, coherent snapshots, `TaskPi`, stable task-rq acquisition, RAII scheduler-change transactions, owner waiter trees and blocked-chain propagation, scheduler writer cutovers, EEVDF task selection, and deadline lifecycle integration | Deadline PI still borrows only scalar ordering fields; nested fair groups and native fixed process semantics are separate rows below |
| MERGED | `F1532-scheduler-ntfixed-dispatcher` | #7139 | Native fixed class identity, 32 strict FIFO ready levels, class-chain preemption rank, encoding, and fork inheritance | No tick-driven native quantum rotation, variable-priority boost/decay, or process-wide scheduling transaction; `KI-0330` |
| MERGED | `F1533-scheduler-task-group-eevdf` | #7140 | Scheduler-owned group id/share publication, queued-task rekeying, and live flat group-weight selection | The standalone hierarchy has no production caller and the live scheduler has no per-CPU nested child runqueue/entity descent; `KI-0329` |
| MERGED | `F1534-scheduler-ledger-close` | #7141 | Archived the then-stated `KI-0322` EEVDF/group and `KI-0323` native dispatcher blockers | Later source audit narrowed the unimplemented residuals into `KI-0329` and `KI-0330` |
| MERGED | `F1535-scheduler-priority-blocker-close` | #7142 | Archived the broad split-state defect `KI-0321` after the canonical state and transaction merge | The closure did not implement donor deadline-entity/CBS ownership; active `KI-0326` remains |
| MERGED | `B3322-ntfixed-pi-donor-order` | #7143 | Strict native fixed-level PI donor ordering and deboost coverage | Its final smoke exposed cross-CPU runnable ownership failure `KI-0327` |
| MERGED | `B3323-scheduler-transaction-regressions` | #7144 | Deterministic real-runqueue coverage for rejected/unwound mutations, group rekey, post-migration ownership, and PI rekey/preemption | Test-only change; no production scheduler semantics were added |
| MERGED | `B3323-scheduler-transaction-regressions` | #7145 | Restored the `KI-0326`/`KI-0327` ledger rows displaced by #7144 and archived transaction coverage as `KI-0328` | No production scheduler semantics were added |

| Status | Branch | Change | Exit evidence |
|---|---|---|---|
| IN-PROGRESS | `B3321-deadline-pi-entity` | `KI-0326`: replace scalar deadline donation with effective donor-entity ownership for ready-node ordering, CBS runtime charging, throttling, replenishment, and deboost | Fair/RT owner executes against donor budget and ready node; timeout/handoff/deboost restore the owner entity; focused deadline/PI and transaction controls |
| IN-PROGRESS | `B3325-scheduler-smp-ownership` | `KI-0327`: prevent any CPU from selecting a runnable task whose execution ownership is still held by another CPU | Barrier-controlled wake/migrate/switch-tail regression plus both-architecture final smoke |
| OPEN | unclaimed | `KI-0329`: connect nested fair task groups to per-CPU child runqueues and schedulable parent entities | Production call-site proof; nested unequal-share and attach/reweight/exit transaction controls |
| OPEN | unclaimed | `KI-0330`: complete native quantum, variable-priority boost/decay, and process-wide scheduling configuration | Tick-driven same-level rotation, exhaustive level transitions, process transaction rollback, and native ABI integration controls |
| IN-PROGRESS | `B3318-windows-thread-information` | Rebase native thread-information and affinity operations onto canonical scheduler transactions without field-level shadow mutations | Native ABI/error tests and coherent affinity races |
| PENDING | unclaimed | Complete scheduler source-ownership audit and final integration verification after all open rows merge | No shadow reader/writer paths; full hosted suites; both architectures; one final scheduler boot canary |

`KI-0326` currently has two ledger meanings across lanes: merged `main` archives
it for the native fixed donor-order defect from #7143, while the active
`B3321-deadline-pi-entity` lane claims it for the deadline entity/CBS gap above.
The active lane must resolve that identifier collision before merging.
