# B2059 SMP wait audit

| Class | Contract | Current audit result |
|---|---|---|
| Generic predicate | enqueue, recheck predicate, sleep, recheck, finish | FIFO open rendezvous converted in B2059. FUSE replies, autofs replies and userfault queue predicates remain to verify and convert where their predicate has no lock-coupled requirement. |
| Prepared resource wait | hold resource gate, enqueue, recheck, unlock, sleep, finish | Pipe ring, eventfd, socket receive/accept, POSIX MQ and rwsems. Each must use the named prepared API; raw publication is not an acceptable public call site. |
| Scheduler-owned transition | scheduler owns task state and wakeup ordering | kthread parking, migration, quota, inode freeze and worker internals. Retain only after owner-specific review. |

The inventory command includes scheduler internals, wait-wrapper implementations and hosted tests. It is not a count of independent defects. Every production call site must be classified before the raw API is restricted.
