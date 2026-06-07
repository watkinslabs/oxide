// select / pselect6 — per-syscall modules (docs/53 §0). This file is
// now the module root: each handler lives in its own `<NNN>_<name>.rs`
// (slot 23 select, slot 270 pselect6). Re-exported here so
// `crate::select::sys_select` / `sys_pselect6` keep resolving in
// dispatch.rs.

#![cfg(target_os = "oxide-kernel")]

#[path = "023_select.rs"]   pub mod s023_select;
#[path = "270_pselect6.rs"] pub mod s270_pselect6;

pub use s023_select::sys_select;
pub use s270_pselect6::sys_pselect6;
