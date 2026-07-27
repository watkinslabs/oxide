// Module manifest: `model` owns the table bitmap/state layout and low-level
// allocation helpers; `ops` owns public operations; `close` owns the shared
// `filp_close` tail (flush + record-lock release + fput); `hooks` owns
// post-drop notification; `limits` owns `fs.nr_open` (Linux `sysctl_nr_open`).

mod close;
mod hooks;
mod limits;
mod model;
mod ops;
#[cfg(feature = "debug-fdlife")]
pub mod debug;
#[cfg(test)]
mod tests;

pub use hooks::set_file_ref_drop_hook;
pub(crate) use hooks::fire_file_ref_drop_hook;
pub use limits::{NR_OPEN_DEFAULT, NR_OPEN_MAX, NR_OPEN_MIN, nr_open, set_nr_open};
pub use model::{FD_TABLE_MAX, FdTable};
