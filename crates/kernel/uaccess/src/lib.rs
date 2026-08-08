#![no_std]

extern crate alloc;

// Module manifest: range owns access_ok arithmetic; copy owns arch raw-copy
// policy; cstr owns the NUL-terminated string scan built on it.

mod copy;
mod cstr;
mod range;

pub use copy::{copy_from_user, copy_to_user, raw_copy_from_user, raw_copy_to_user};
pub use cstr::{scan_cstr, strncpy_from_user, strndup_user, strndup_verdict};
pub use range::{access_ok, MAX_RW_COUNT};
