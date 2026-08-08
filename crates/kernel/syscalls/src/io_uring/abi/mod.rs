// io_uring ABI + ring-geometry decisions shared by slots 425/426/427.
//
// Module manifest:
//   uapi        — Linux `include/uapi/linux/io_uring.h` numbers + the
//                 `struct io_uring_params` wire form (encode/decode).
//   layout      — oxide's SQ/CQ/SQE region geometry + the `io_uring_setup`
//                 admission ladder (`io_uring_sanitise_params`,
//                 `io_uring_fill_params`, `rings_size`).
//   allowed     — who may create a ring at all (`kernel.io_uring_disabled`,
//                 `kernel.io_uring_group`, CAP_SYS_ADMIN) → EPERM.
//   enter       — `io_uring_enter` flag/argument decode, CQ-occupancy and
//                 SQ-index decisions, and the wait ladder.
//   ops         — `IORING_OP_*` / `IOSQE_*` and which opcodes dispatch runs.
//   restriction — the per-ring register/SQE allow-lists.
//   register_op — the `io_uring_register(2)` opcode + argument ladder
//                 (Linux `io_uring/register.c` `__io_uring_register`).
//
// Deliberately NOT kernel-gated: the three slot files are
// `#![cfg(target_os = "oxide-kernel")]`, so any decision left in them is
// invisible to `cargo test` (CLAUDE.md phantom-test rule). Slots parse,
// call one of these, and encode (docs/53).

pub mod uapi;
pub mod allowed;
pub mod layout;
pub mod enter;
pub mod ops;
pub mod register_op;
pub mod restriction;
