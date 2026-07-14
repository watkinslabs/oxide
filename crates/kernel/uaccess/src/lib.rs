#![no_std]

// Module manifest: range owns access_ok arithmetic; copy owns arch raw-copy policy.

mod copy;
mod range;

pub use copy::{copy_from_user, copy_to_user, raw_copy_from_user, raw_copy_to_user};
pub use range::{access_ok, MAX_RW_COUNT};
