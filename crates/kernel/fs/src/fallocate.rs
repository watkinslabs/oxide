// Linux `fs/open.c` `vfs_fallocate()` (`fs/open.c:250-352`). Module manifest.
//
//   mode.rs — `FALLOC_FL_*` values + the mode-combination decision
//             (`fs/open.c:259-285`), unit tested hosted.
//   vfs.rs  — the full `vfs_fallocate` ladder over a live description.

mod mode;
mod vfs;

pub use mode::{falloc_mode_ok, FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE,
    FALLOC_FL_KEEP_SIZE, FALLOC_FL_MODE_MASK, FALLOC_FL_NO_HIDE_STALE,
    FALLOC_FL_PUNCH_HOLE, FALLOC_FL_UNSHARE_RANGE, FALLOC_FL_WRITE_ZEROES,
    FALLOC_FL_ZERO_RANGE};
pub use vfs::vfs_fallocate;
