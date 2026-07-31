//! eventfd(2) — a counting event object exposed as a file descriptor.
//!
//! Module manifest:
//!   `counter` — ungated: flag admission, counter arithmetic, poll mask.
//!   `file`    — inode, blocking read/write parking, fdinfo.

pub mod counter;
pub mod file;

pub use counter::{EFD_CLOEXEC, EFD_FLAGS_SET, EFD_NONBLOCK, EFD_SEMAPHORE, EVENTFD_RECORD,
    LEGACY_FLAGS, flags_valid};
pub use file::{EventfdData, make_eventfd_inode};
