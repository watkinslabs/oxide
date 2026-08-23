#![no_std]

extern crate alloc;

// Module manifest: range owns access_ok arithmetic; copy owns arch raw-copy
// policy; atomic owns fault-recovering user RMW; cstr owns NUL string scans.

mod atomic;
mod copy;
mod cstr;
mod range;
mod scalar;

pub use copy::{copy_from_user, copy_to_user, raw_copy_from_user, raw_copy_to_user};
pub use atomic::cmpxchg_user_u32;
pub use cstr::{scan_cstr, strncpy_from_user, strndup_user, strndup_verdict};
pub use range::{access_ok, MAX_RW_COUNT};
pub use scalar::{get_user_u32, get_user_u64, put_user_u32, put_user_u64};
