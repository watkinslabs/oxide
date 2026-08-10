// io_uring ABI + ring-geometry decisions shared by slots 425/426/427.
//
// Module manifest:
// uapi — the io_uring UAPI numbers + the
//                 `struct io_uring_params` wire form (encode/decode).
//   layout      — oxide's SQ/CQ/SQE region geometry + the `io_uring_setup`
//                 admission ladder (`io_uring_sanitise_params`,
//                 `io_uring_fill_params`, `rings_size`).
//   allowed     — who may create a ring at all (`kernel.io_uring_disabled`,
//                 `kernel.io_uring_group`, CAP_SYS_ADMIN) → EPERM.
//   enter       — `io_uring_enter` flag/argument decode, CQ-occupancy and
//                 SQ-index decisions, and the wait ladder.
//   sqpoll      — `IORING_SETUP_SQPOLL`/`SQ_AFF`: the idle window, the pin-CPU
//                 ladder, the poll loop's transitions and the
//                 `IORING_SQ_NEED_WAKEUP` handshake.
//   ops         — `IORING_OP_*` / `IOSQE_*` and which opcodes dispatch runs.
//   link        — link chains, drain barriers and silent success.
//   restriction — the per-ring register/SQE allow-lists.
//   iopoll      — the polled-ring admission ladders and the poll-wait loop.
//   resize      — what moves between the old and new rings on
//                 `IORING_REGISTER_RESIZE_RINGS`, and when it is refused.
//   bpf_filter  — `IORING_REGISTER_BPF_FILTER`: the record a filter reads,
//                 the import ladder, and a ring's installed filter set.
//   napi        — `IORING_REGISTER_NAPI`: the busy-poll window, the tracking
//                 mode and the receive queues a wait drives.
//   mem_region  — `IORING_REGISTER_MEM_REGION`: the region descriptor, its
//                 admission ladder, and the registered-wait offset check.
//   register_op — the `io_uring_register(2)` opcode + argument ladder
//                 (the Linux `__io_uring_register` admission ladder).
//   timeout     — `IORING_OP_TIMEOUT`/`LINK_TIMEOUT`/`TIMEOUT_REMOVE` decode.
//   cancel      — cancellation keys and the match rule.
//   poll        — `IORING_OP_POLL_ADD`/`POLL_REMOVE` decode + mask arithmetic.
//
// Deliberately NOT kernel-gated: the three slot files are
// `#![cfg(target_os = "oxide-kernel")]`, so any decision left in them is
// invisible to `cargo test` (CLAUDE.md phantom-test rule). Slots parse,
// call one of these, and encode (docs/53).

pub mod uapi;
pub mod allowed;
pub mod layout;
pub mod enter;
pub mod sqpoll;
pub mod ops;
pub mod link;
pub mod bpf_filter;
pub mod mem_region;
pub mod napi;
pub mod register_op;
pub mod resize;
pub mod restriction;
pub mod iopoll;
pub mod timeout;
pub mod cancel;
pub mod poll;
pub mod zcrx;
