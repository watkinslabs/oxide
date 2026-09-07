//! Module manifest: per-DC path recording owner.
//! `record` holds the point/flag state machine, `bezier` the flattening subdivision,
//! `flatten` Bezier removal plus region conversion, `ops` the DC-level path operations.
use super::{GdiError, GdiManager, DeviceContext};
use alloc::vec::Vec;

#[path = "path/record.rs"]
pub mod record;
#[path = "path/bezier.rs"]
pub mod bezier;
#[path = "path/flatten.rs"]
pub mod flatten;
#[path = "path/ops.rs"]
pub mod ops;

pub use record::{GdiPath, PT_BEZIERTO, PT_CLOSEFIGURE, PT_LINETO, PT_MOVETO};
pub use ops::{ALTERNATE, WINDING};
