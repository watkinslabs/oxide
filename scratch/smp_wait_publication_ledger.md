# B2059 wait-publication ledger

This is the review ledger for the raw-publication finding.  It is deliberately
separate from the short status summary in `smp_wait_audit.md`: a grep total is
not proof that every wait was judged against its owning protocol.

## Baseline and reconciliation

The reproducible source baseline is revision `982ac870bc1d7eb651be6c7220e4a07bc95d1aff`:

```text
git grep -n -E '\.(park|park_interruptible|park_with_deadline|park_interruptible_with_deadline)\(' 982ac870bc1d7eb651be6c7220e4a07bc95d1aff -- crates
```

It returns 101 source publications in the 65 grouped rows below (the row count is the
number of calls, not the number of files).  The historical issue says 105, but
does not preserve the command or revision that produced that total.  The extra
four must not be silently claimed as closed: this ledger records the
reproducible 101-call source set, and the issue count remains a reconciliation
item until its original scanner can be recovered.

`DONE` means the raw publication from the baseline no longer exists at that
consumer. `OWNER` means the consumer is an intentional scheduler/state owner;
the raw operation remains confined to that owner's named API, not exposed to a
resource caller. `TEST` means hosted test-only code, not a kernel path.

| Calls | Baseline consumer | Final contract | Status |
|---:|---|---|---|
| 1 | drivers/drm/crtc | prepared DRM-event wait | DONE |
| 1 | drivers/drv-ahci/wait | generic predicate completion | DONE |
| 1 | drivers/drv-virtio-blk/modern/state | generic predicate completion/deadline | DONE |
| 1 | drivers/drv-virtio-input/devfs/fileops | prepared input queue wait | DONE |
| 3 | drivers/drv-zram/{state,writeback,writeback/batch} | prepared zram writeback waits | DONE |
| 1 | fs/autofs | generic predicate completion | DONE |
| 2 | fs/fuse/conn | generic reply/daemon predicates | DONE |
| 2 | fs/inotify/{group,perm} | prepared inotify queue waits | DONE |
| 2 | fs/pipe | generic core-dump reader/writer predicates | DONE |
| 2 | fs/pipe/eventfd/file | prepared eventfd waits | DONE |
| 2 | fs/pipe/ring | prepared pipe-ring waits | DONE |
| 2 | fs/pipe/splice_ops | generic splice predicates | DONE |
| 1 | fs/signalfd/wait | signal-state predicate wait | DONE |
| 1 | fs/timerfd/file | prepared timerfd deadline wait | DONE |
| 3 | fs/userfaultfd/{events,msg} | generic queue/fault predicates | DONE |
| 2 | ipc/live/posix_mq/sendrecv | prepared message-queue waits | DONE |
| 1 | ipc/sysv/block | prepared SysV IPC wait | DONE |
| 1 | mm-pmm/kswapd | generic work-request predicate | DONE |
| 2 | mm-vmm/address_space/rwsem | keyed reader/writer prepared wait | DONE |
| 1 | modules/linux_sync_wait | generic predicate wait | DONE |
| 1 | net/net_ns/teardown | generic reaper-work predicate | DONE |
| 1 | net/raw4/types | prepared socket receive wait | DONE |
| 1 | net/raw6/types | prepared socket receive wait | DONE |
| 1 | net/sock_io/tcp_read | prepared TCP receive wait | DONE |
| 2 | net/sock_recv | prepared socket receive wait | DONE |
| 1 | net/sock_rtnl_defer | generic reaper-work predicate | DONE |
| 1 | net/sock_wait/kernel | named prepared socket wait API | DONE |
| 5 | net/sock_wait/tests | test-only raw-API tests | TEST |
| 1 | net/stack/tcp_listener | prepared accept wait | DONE |
| 2 | net/stack/types/tcp_entry_wait | prepared TCP receive wait | DONE |
| 1 | net/stack/udp_endpoint | prepared UDP receive wait | DONE |
| 1 | net/stack_ipv6/types | prepared IPv6 receive wait | DONE |
| 3 | net/unix_sock/dgram | prepared UNIX datagram read/write waits | DONE |
| 2 | net/unix_sock/listener | prepared UNIX accept/connect waits | DONE |
| 3 | net/unix_sock/msg_pair/wait | prepared UNIX pair read/write waits | DONE |
| 2 | net/unix_sock/stream/lifecycle | prepared UNIX stream lifecycle waits | DONE |
| 1 | net/unix_sock/stream/read | prepared UNIX stream read wait | DONE |
| 1 | net/vsock/accept | prepared VSOCK accept wait | DONE |
| 1 | net/vsock/conn/wait | prepared VSOCK connection wait | DONE |
| 2 | net/vsock/transaction | prepared VSOCK transaction waits | DONE |
| 2 | net/vsock_socket{,/io} | prepared VSOCK socket waits | DONE |
| 1 | netlink/ports | prepared netlink-space wait | DONE |
| 1 | netlink/receive | generic receive predicate | DONE |
| 1 | sched/live/inode_wait | keyed rwsem owner API | OWNER |
| 3 | sched/live/kthread | kthread state-transition owner | OWNER |
| 1 | sched/live/migration_wait | migration state-transition owner | OWNER |
| 1 | sched/live/mutex | prepared mutex wait | DONE |
| 1 | sched/live/quota_wait | quota state-transition owner | OWNER |
| 1 | sched/live/sb_freeze | superblock-freeze state-transition owner | OWNER |
| 1 | sched/live/timer_driver | timer deadline-transition owner | OWNER |
| 2 | sched/live/wait_event | generic helper implementation | OWNER |
| 4 | sched/live/wait_list | raw primitive implementation | OWNER |
| 2 | sched/rwsem/sleep | prepared rwsem wait | DONE |
| 1 | syscalls/016_ioctl/vt | generic VT-active predicate | DONE |
| 1 | syscalls/035_nanosleep | prepared deadline wait | DONE |
| 1 | syscalls/103_syslog | generic log-reader predicate | DONE |
| 1 | syscalls/128_rt_sigtimedwait | prepared signal wait | DONE |
| 1 | syscalls/130_rt_sigsuspend | signal-state wait | OWNER |
| 1 | syscalls/318_getrandom | generic CRNG-ready predicate | DONE |
| 1 | syscalls/io_uring/iowq/worker | generic worker-work predicate | DONE |
| 1 | syscalls/io_uring/register/iowq | SQPOLL state owner API | OWNER |
| 2 | syscalls/io_uring/sqpoll | generic SQPOLL park predicate | DONE |
| 2 | tty/wait | prepared TTY wait/deadline API | DONE |
| 1 | umh/spawn/queue | generic worker-idle predicate | DONE |
| 2 | vfs/inode/rwsem | keyed reader/writer prepared wait | DONE |

## Closure rule

The current source scan has no resource or driver use of the raw `WaitList`
publication methods. Its only matches are the `WaitList`/generic-helper
implementations and named rwsem/SQPOLL owner methods. Any new production caller
must use either a generic predicate helper or a named prepared/owner API and
add a row here before it can be considered audited.
