// Linux `fs/splice.c` + the `copy_file_range` half of `fs/read_write.c`.
// Module manifest.
//
//   flags.rs      — SPLICE_F_* values and the pure admission decisions
//                   (`do_splice` case selection, `do_tee` gate, vmsplice
//                   direction). No fd/task access, unit tested hosted.
//   pipe_xfer.rs  — the pipe-side primitives the syscalls need that a plain
//                   read/write cannot express: non-consuming duplication
//                   (`link_pipe`) and the space/EOF wait states
//                   (`ipipe_prep`/`opipe_prep`/`wait_for_space`).
//   splice_sys.rs — `sys_splice` (slot 275): the three pipe cases.
//   tee_sys.rs    — `sys_tee` (slot 276).
//   vmsplice_sys.rs — `sys_vmsplice` (slot 278), both directions.
//   copy_range.rs — `sys_copy_file_range` (slot 326) + the
//                   `generic_copy_file_checks` ladder.

mod flags;
mod pipe_xfer;
mod splice_sys;
mod tee_sys;
mod vmsplice_sys;
mod copy_range;

pub use flags::{splice_case, tee_admit, vmsplice_dir, SpliceCase, VmspliceDir,
    SPLICE_F_ALL, SPLICE_F_GIFT, SPLICE_F_MORE, SPLICE_F_MOVE, SPLICE_F_NONBLOCK};
pub use copy_range::{copy_file_range_checks, sys_copy_file_range, CopyCheckIn};
pub use splice_sys::sys_splice;
pub use tee_sys::sys_tee;
pub use vmsplice_sys::sys_vmsplice;
