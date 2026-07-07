// Module manifest: `core` owns Linux configfs KPI structs, exports, and VFS backing.

mod core;
mod util;

pub use core::*;
