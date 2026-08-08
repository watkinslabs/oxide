// io_uring per `30` — kernel-side manifest.
//
// A ring shares two regions with userspace, mapped from the ring fd at fixed
// magic offsets: the rings region (SQ/CQ headers, CQE array, SQ index array)
// and the SQE array. Userspace fills SQEs, advances the SQ tail and calls
// `io_uring_enter`; the kernel drains SQ head→tail, executes each entry, and
// posts completions.
//
// Module manifest:
//   ring        — the two shared regions, their lifetime, the inode, mmap routing
//   ctx         — one ring's state and its three locks
//   cqe         — completion posting and the overflow backlog
//   submit      — the submission engine: links, drain, silent success
//   wait        — the `min_complete` wait
//   dispatch    — `IORING_OP_*` → the work each opcode does
//   register    — the `io_uring_register(2)` work functions
//   rsrc        — registered files, buffers, personalities, buffer groups
//   pin         — pinned user memory behind registered buffers
//   personality — credentials an entry runs under
//
// The ABI numbers, the setup admission ladder, the enter argument forms, the
// register-opcode ladder and the restriction tables live in
// `crate::io_uring_abi` (`io_uring/abi/`), which is NOT target-gated so
// `cargo test` can reach the decisions (CLAUDE.md phantom-test rule).

#![cfg(target_os = "oxide-kernel")]
#![allow(dead_code)]

pub mod ring;
pub mod ctx;
pub mod cqe;
pub mod submit;
pub mod wait;
pub mod dispatch;
pub mod register;
pub mod rsrc;
pub mod pin;
pub mod personality;

pub use ctx::IoUringInode;
pub use ring::{make_io_uring_inode, mmap_backing, ring_ctx, ring_of, IoUring};
pub use rsrc::IoUringReg;

// The three io_uring syscall handlers live in per-syscall files per docs/53§0;
// re-exported here so the dispatch.rs call sites keep resolving:
//   * sys_io_uring_setup    (425) → s425_io_uring_setup
//   * sys_io_uring_enter    (426) → s426_io_uring_enter
//   * sys_io_uring_register (427) → s427_io_uring_register
pub use crate::s425_io_uring_setup::sys_io_uring_setup;
pub use crate::s426_io_uring_enter::sys_io_uring_enter;
pub use crate::s427_io_uring_register::sys_io_uring_register;
