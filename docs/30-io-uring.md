# 30 io_uring

FROZEN 2026-05-02 (tracked as phase 22 per `00§3`; full ring substrate ships then). Dep:`01`,`02`,`06`,`11`,`13`,`15`,`16`,`17`,`23`,`25`. Provides:`15` syscalls 425/426/427.

## 1 Purpose

Async I/O surface compatible with Linux io_uring. Submission/completion rings shared with userspace; kernel worker threads perform the work; results returned without per-op syscall.

## 2 Invariants (frozen)

1. SQ + CQ rings are mmap'd shared memory between user and kernel; kernel writes CQ, user writes SQ.
2. SQE/CQE layout matches Linux exactly (struct sizes, field offsets) — verified by `static_assertions`.
3. Kernel processes SQEs in FIFO order from ring; out-of-order completion is normal.
4. SQE chained via `IOSQE_IO_LINK`: next runs only if prior succeeded; `IOSQE_IO_HARDLINK` runs regardless.
5. CQE never lost: completion always pushed; if CQ full, kernel sets `CQ_OVERFLOW` flag and stashes overflow in kernel-side ring.
6. Buffer registration: pages pinned for ring lifetime; refcount held.

## 3 Public ifc

```rust
sys_io_uring_setup(entries:u32, params:UVA<&IoUringParams>) -> KR<RawFd>;
sys_io_uring_enter(fd:RawFd, to_submit:u32, min_complete:u32, flags:u32, sig:UVA<&Sigset>) -> KR<u32>;
sys_io_uring_register(fd:RawFd, opcode:u32, arg:UVA<&u8>, nr_args:u32) -> KR<u32>;
```

`IoUringParams`,`io_uring_sqe`,`io_uring_cqe`: layout matches the Linux io_uring UAPI byte-for-byte.

## 4 Opcodes

| Family | Operations |
|---|---|
| Ring | NOP, NOP128, FILES_UPDATE, MSG_RING, PROVIDE_BUFFERS, REMOVE_BUFFERS, FIXED_FD_INSTALL |
| Read/write | READ, WRITE, READV, WRITEV, READ_FIXED, WRITE_FIXED, READV_FIXED, WRITEV_FIXED, FSYNC, SYNC_FILE_RANGE, FALLOCATE, FTRUNCATE, FADVISE, MADVISE |
| Filesystem | OPENAT, OPENAT2, CLOSE, STATX, RENAMEAT, UNLINKAT, MKDIRAT, SYMLINKAT, LINKAT, SETXATTR, FSETXATTR, GETXATTR, FGETXATTR, SPLICE, TEE, PIPE, EPOLL_CTL, EPOLL_WAIT |
| Network | SEND, RECV, SENDMSG, RECVMSG, SEND_ZC, SENDMSG_ZC, RECV_ZC, ACCEPT, CONNECT, BIND, LISTEN, SHUTDOWN, SOCKET |
| Async | ASYNC_CANCEL, TIMEOUT_REMOVE, POLL_REMOVE |
| Armed | TIMEOUT, LINK_TIMEOUT, POLL_ADD |
| Driver | URING_CMD, URING_CMD128 |
| Process | WAITID, FUTEX_WAIT, FUTEX_WAKE, FUTEX_WAITV |

`IORING_REGISTER_PROBE` reports exactly this executable set. Every defined opcode through `URING_CMD128` is supported except `READ_MULTISHOT`; the probe/dispatch bidirectional test prevents either side from drifting.

## 5 Architecture

Per-ring state:
- `sq_ring`,`cq_ring` userspace-mmap'd pages.
- `sqes` array (separate mmap region).
- `tail` (kernel head of SQ; userspace head of CQ).
- `head` (vice versa).
- Per-ring `WaitQueue` for `io_uring_enter` blocking.

`io_uring_enter`:
1. If `to_submit > 0`: drain SQ from current head to head+to_submit; for each SQE, dispatch.
2. Dispatch path: small ops complete inline (e.g., NOP, fast-path read from page-cache hit). Slow ops queue to per-ring kthread (`io_wq`) or per-CPU pool.
3. If `min_complete > 0`: block until CQ has ≥min_complete entries (with optional sig mask via `pselect`-like).

SQPOLL mode (`IORING_SETUP_SQPOLL`): kernel kthread polls SQ continuously; userspace doesn't need `io_uring_enter` for submit.

## 6 Worker pool

Per-ring `io_wq` thread pool. Bounded threads; new threads spawn under load up to limit. Each thread runs blocking ops.

For ops that don't naturally block (NOP, page-cache hit), inline completion saves a hop.

## 7 Buffer registration

`io_uring_register(IORING_REGISTER_BUFFERS, iovec[], nr)`: pins pages, records `Vec<RegBuf>`. `READ_FIXED`/`WRITE_FIXED` reference these by index, skipping per-op pin/unpin.

## 8 Concurrency

- SQ tail (kernel-read): atomic, Acquire.
- CQ tail (kernel-write): atomic, Release.
- Per-ring spinlock for cq_overflow stash, op-queue.
- Per-ring `WaitQueue` for completion waiters.

## 9 Perf budget

| Op | p99 cy |
|---|---|
| SQE submit (NOP, inline complete) | ≤ 600 |
| SQE submit + slow-op dispatch | ≤ 3000 |
| CQE reap | ≤ 200 |
| Roundtrip (submit + reap with no I/O) | ≤ 1000 |

## 10 Test contract (frozen)

- ABI: `static_assertions::assert_eq_size!(io_uring_sqe, [u8;64])` etc.
- NOP throughput: 10M ops in 1s on 4-CPU.
- READ_FIXED: register 64 buffers, read from tmpfs, verify content.
- POLL_ADD on socket: works as epoll replacement.
- Cancel: queue 100 timeouts, cancel half, verify CQEs (success or ECANCELED) for all.
- Linked SQEs: open→read→close chain; if open fails, others get ECANCELED.
- nginx with `aio threads io_uring;` (when nginx in test image) serves pages.
- Coverage ≥80%.

## 11 Failure modes

- CQ full + overflow: set CQ_OVERFLOW; subsequent submit returns EBUSY until drained.
- Unsupported opcode: CQE with `-ENOSYS`.
- Cancel of completed op: success (op already done; cancel is idempotent).

## 12 Debug

`debug-iouring`: per-op trace; ring state dump.

## 13 Cross-spec

`16`/`17` (file ops), `25` (socket ops), `15` (syscalls), `13` (worker threads), `23` (timeouts).
