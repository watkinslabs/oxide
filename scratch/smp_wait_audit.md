# B2059 SMP wait audit

| Class | Contract | Current audit result |
|---|---|---|
| Generic predicate | enqueue, recheck predicate, sleep, recheck, finish | FIFO open rendezvous, FUSE replies/daemon queue, autofs completion, userfault queues, pipe core-dump reader wait, splice input/output, netlink receive/retry, SQPOLL park request, IO-wq worker work/deadline, kswapd requests and namespace/socket reapers are converted in B2059. |
| Prepared resource wait | hold resource gate, enqueue, recheck, unlock, sleep, finish | Pipe ring, eventfd, timerfd, POSIX MQ, all socket receive/send/connect/accept families, TTY, and the scheduler rwsem now use named prepared APIs. The hook-based mmap/inode rwsems and comparable lock-coupled callers remain to validate and remediate individually. |
| Scheduler-owned transition | scheduler owns task state and wakeup ordering | kthread parking, migration, quota, inode freeze and worker internals. Retain only after owner-specific review. |

The remaining raw-publication inventory has 22 Rust files, including scheduler internals, wait-wrapper implementations and hosted tests. It is not a count of independent defects. Every production call site must be classified before the raw API is restricted.
