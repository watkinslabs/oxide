// Byte-faithful 9P wire codec.
//
// Module manifest:
//   * `dec`    — bounds-checked read cursor + frame header split.
//   * `enc`    — outgoing message builder with `msize` enforcement.
//   * `types`  — dialect selector, `qid`, `.L` directory entries.
//   * `dotl`   — `.L` composite bodies: getattr, setattr, statfs, locks.
//   * `legacy` — the 9P2000(.u) `stat` and its POSIX mode translation.
//
// No policy lives here: the codec never decides what to send, only how a value
// is spelled on the wire.

pub mod dec;
pub mod enc;
pub mod types;
pub mod dotl;
pub mod legacy;

pub use dec::{split_header, peek_size, Dec, MsgHeader};
pub use enc::Enc;
pub use types::{encode_dirent, Dialect, DirEntries, DirEntry, Qid};
pub use dotl::{Flock, GetLock, IattrDotl, StatDotl, StatFs};
pub use legacy::{p9mode_to_posix, Wstat, DONT_TOUCH_U16, DONT_TOUCH_U32, DONT_TOUCH_U64};
