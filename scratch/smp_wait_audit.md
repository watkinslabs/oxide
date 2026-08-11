# B2059 SMP wait audit

| Class | Contract | Current audit result |
|---|---|---|
| Generic predicate | enqueue, recheck predicate, sleep, recheck, finish | FIFO open rendezvous, FUSE replies/daemon queue, autofs completion, userfault queues, pipe core-dump reader wait, splice input/output, netlink receive/retry, SQPOLL park request, IO-wq worker work/deadline, AHCI/virtio-blk/IRQ-thread/vfork completion, kswapd requests, namespace/socket reapers, CRNG readiness, syslog reader and VT activation wait are converted in B2059. Vfork uses a child-keyed completion queue, so one child departure does not wake unrelated parents. |
| Prepared resource wait | hold resource gate, enqueue, recheck, unlock, sleep, finish | Pipe ring, eventfd, timerfd, POSIX MQ, all socket receive/send/connect/accept families, TTY, scheduler rwsem, SysV IPC, nanosleep, sigtimedwait, DRM event, zram, evdev and module-KPI waits now use named prepared APIs. mmap/inode rwsems use keyed reader/writer FIFOs: wake one writer while writers wait, otherwise wake the reader phase. |
| Scheduler-owned transition | scheduler owns task state and wakeup ordering | kthread parking, migration, quota, inode freeze and worker internals. Retain only after owner-specific review. |
| State-owned protocol | private waiter state and a dedicated wake owner | Futex waits retain their keyed queue and priority-inheritance handoff; `pause(2)` retains the signal-state sleep. Both are Linux-shaped special protocols, not resource waits. |

The raw scheduler publication is now confined to `WaitList` and the shared
predicate helper. The remaining six textual `park` hits are rwsem/SQPOLL
owner methods and scheduler documentation, not direct `WaitList` calls.
