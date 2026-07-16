// Module manifest: `model` owns the table bitmap/state layout and low-level
// allocation helpers; `ops` owns public operations; `hooks` owns post-drop notification.

mod hooks;
mod model;
mod ops;
#[cfg(feature = "debug-fdlife")]
pub mod debug;
#[cfg(test)]
mod tests;

pub use hooks::set_file_ref_drop_hook;
pub(crate) use hooks::fire_file_ref_drop_hook;
pub use model::{FD_TABLE_MAX, FdTable};
