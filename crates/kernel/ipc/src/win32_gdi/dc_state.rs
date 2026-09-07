//! Device-context state services on the canonical GDI owner; 31fk§8.
//!
//! Module manifest:
//! - `save`: the save/restore stack and the state each level carries.
//! - `attrs`: attribute reads and writes the state ordinals project.
//! - `print`: document and page job results the null print driver reports.
//! - `client_obj`: opaque client-owned object handles.

use super::{GdiError, GdiManager, DcAttr, Rect, TextAttributes};

#[path = "dc_state/save.rs"]
mod save;
pub use save::SavedDc;
#[path = "dc_state/attrs.rs"]
mod attrs;
#[path = "dc_state/print.rs"]
mod print;
pub use print::{SP_ERROR, START_PAGE_RESULT, JOB_RESULT, INIT_SPOOL_RESULT, SPOOL_MESSAGE_RESULT, EXT_ESCAPE_RESULT};
#[path = "dc_state/client_obj.rs"]
mod client_obj;

/// What a device context draws on. The reference distinguishes these by GDI
/// object type; the distinction decides gamma-ramp admission and whether a
/// transform change reselects the font and pen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DcKind { Display, Memory, EnhMetafile }
