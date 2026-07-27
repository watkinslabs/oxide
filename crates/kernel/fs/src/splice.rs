// Linux `fs/splice.c` + the `copy_file_range` half of `fs/read_write.c`.
// Module manifest. Work fns only — the `SyscallArgs` shims live in
// `syscalls/{275_splice,326_copy_file_range}.rs` per `docs/53`.
//
//   flags.rs        — SPLICE_F_* values and the pure admission decisions
//                     (`do_splice` case selection, `do_tee` gate, vmsplice
//                     direction). No fd/task access, unit tested hosted.
//   pipe_xfer.rs    — the three transfer legs (file->pipe, pipe->file,
//                     pipe->pipe) over the ring primitives in `crate::pipe`.
//   splice_sys.rs   — `do_splice` (slot 275).
//   tee_sys.rs      — `do_tee` (slot 276): duplicates, never consumes.
//   vmsplice_sys.rs — `do_vmsplice_to_pipe` / `do_vmsplice_to_user` (slot 278).
//   copy_range.rs   — `copy_file_range` (slot 326) + `generic_copy_file_checks`.

mod flags;
mod pipe_xfer;
mod splice_sys;
mod tee_sys;
mod vmsplice_sys;
mod copy_range;

pub use flags::{splice_case, tee_admit, vmsplice_dir, SpliceCase, SpliceIn, VmspliceDir,
    SPLICE_F_ALL, SPLICE_F_GIFT, SPLICE_F_MORE, SPLICE_F_MOVE, SPLICE_F_NONBLOCK};
pub use copy_range::{copy_file_range, copy_file_range_checks, CopyCheckIn};
pub use splice_sys::do_splice;
pub use tee_sys::do_tee;
pub use vmsplice_sys::{do_vmsplice_to_pipe, do_vmsplice_to_user};
