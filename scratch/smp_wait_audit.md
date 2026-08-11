# B2059 SMP wait audit

| Class | Contract | Current audit result |
|---|---|---|
| Generic predicate | enqueue, recheck predicate, sleep, recheck, finish | FIFO open rendezvous, FUSE replies/daemon queue, autofs completion, userfault queues, pipe core-dump reader wait, splice input/output, netlink receive/retry, SQPOLL park request, IO-wq worker work/deadline, kswapd requests, namespace/socket reapers, CRNG readiness, syslog reader and VT activation wait are converted in B2059. |
| Prepared resource wait | hold resource gate, enqueue, recheck, unlock, sleep, finish | Pipe ring, eventfd, timerfd, POSIX MQ, all socket receive/send/connect/accept families, TTY, scheduler rwsem, SysV IPC, nanosleep and sigtimedwait now use named prepared APIs. mmap/inode rwsems use keyed reader/writer FIFOs: wake one writer while writers wait, otherwise wake the reader phase. |
| Scheduler-owned transition | scheduler owns task state and wakeup ordering | kthread parking, migration, quota, inode freeze and worker internals. Retain only after owner-specific review. |

The raw scheduler publication is now confined to `WaitList` and the shared
predicate helper. The remaining six textual `park` hits are rwsem/SQPOLL
owner methods and scheduler documentation, not direct `WaitList` calls.
