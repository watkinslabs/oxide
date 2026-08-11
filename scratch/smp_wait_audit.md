# B2059 SMP wait audit

| Class | Contract | Current audit result |
|---|---|---|
| Generic predicate | enqueue, recheck predicate, sleep, recheck, finish | FIFO open rendezvous, FUSE replies/daemon queue, autofs completion, userfault queues, pipe core-dump reader wait, splice input/output, SQPOLL park request, kswapd requests and namespace reaper are converted in B2059. |
| Prepared resource wait | hold resource gate, enqueue, recheck, unlock, sleep, finish | Pipe ring and eventfd now use the named prepared API. Socket receive/accept, POSIX MQ, tty, rwsems and comparable lock-coupled callers remain to rename and validate individually. |
| Scheduler-owned transition | scheduler owns task state and wakeup ordering | kthread parking, migration, quota, inode freeze and worker internals. Retain only after owner-specific review. |

The remaining raw-publication inventory has 50 Rust files, including scheduler internals, wait-wrapper implementations and hosted tests. It is not a count of independent defects. Every production call site must be classified before the raw API is restricted.
