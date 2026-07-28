// io_uring per `30` — kernel-side manifest.
//
// Linux io_uring shares two regions between kernel and userspace, mapped from
// the io_uring fd at fixed magic offsets: the rings region (SQ/CQ headers, CQE
// array, SQ index array) at `IORING_OFF_SQ_RING`/`IORING_OFF_CQ_RING`, and the
// SQE array at `IORING_OFF_SQES`. Userspace fills SQEs, advances the SQ tail
// and calls `io_uring_enter`; the kernel drains SQ head→tail, executes each
// opcode, and posts CQEs advancing the CQ tail.
//
// Module manifest:
//   ring     — the two shared regions, their lifetime, the inode, mmap routing
//   dispatch — `IORING_OP_*` → per-op syscall handler
//   register — the `io_uring_register(2)` op implementations
// The ABI numbers, the setup admission ladder and the register-opcode ladder
// live in `crate::io_uring_abi` (`io_uring/abi/`), which is NOT target-gated so
// `cargo test` can reach the decisions (CLAUDE.md phantom-test rule).
//
// Ops honoured, and the handler each runs: NOP → 0; READ/WRITE → pread64 /
// pwrite64; READV/WRITEV → readv/writev; READ_FIXED/WRITE_FIXED → the same
// through a registered buffer; FSYNC → fsync/fdatasync; CLOSE → close;
// OPENAT → openat; SEND/RECV → sendto/recvfrom; ACCEPT → accept4;
// CONNECT → connect. Every other opcode is `EINVAL`, and
// `IORING_REGISTER_PROBE` reports exactly this set (`abi::ops::op_supported`).
//
// Not implemented, and refused rather than ignored: SQPOLL/IOPOLL rings,
// linked/drained SQEs (`IOSQE_IO_LINK`, `IOSQE_IO_DRAIN`), buffer-select
// (`IOSQE_BUFFER_SELECT`, `BUF_RING`), multishot ops, timeout/cancel ops,
// tagged resource registration, personalities and restrictions.

#![cfg(target_os = "oxide-kernel")]
#![allow(dead_code)]

pub mod ring;
pub mod dispatch;
pub mod register;

pub(crate) use dispatch::dispatch_op;
pub use ring::{
    make_io_uring_inode, mmap_backing, ring_of, IoUring, IoUringInode, IoUringReg,
    INO_TAG_MASK, IO_URING_INO_TAG,
};

// The three io_uring syscall handlers live in per-syscall files per docs/53§0;
// re-exported here so the dispatch.rs call sites keep resolving:
//   * sys_io_uring_setup    (425) → s425_io_uring_setup
//   * sys_io_uring_enter    (426) → s426_io_uring_enter
//   * sys_io_uring_register (427) → s427_io_uring_register
pub use crate::s425_io_uring_setup::sys_io_uring_setup;
pub use crate::s426_io_uring_enter::sys_io_uring_enter;
pub use crate::s427_io_uring_register::sys_io_uring_register;
