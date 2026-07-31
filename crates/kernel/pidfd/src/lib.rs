#![no_std]

extern crate alloc;

mod file;
mod info;
mod open;

pub use file::{
    identity_from_inode, task_and_flags_from_fd, task_from_inode, tid_from_fd,
    ResolveError,
};
pub use open::{file_for_pid, open, prepare, OpenError, OpenOptions, Prepared};
pub use info::snapshot;

#[cfg(all(test, feature = "hosted"))]
mod tests;
