// Module manifest: `model` owns the table bitmap/state layout and low-level
// allocation helpers; `ops` owns the public fd-table operations.

mod model;
mod ops;

pub use model::{FD_TABLE_MAX, FdTable};
