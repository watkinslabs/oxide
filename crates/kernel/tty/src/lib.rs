// TTY + PTY.
//
// Skeleton per docs/28 (FROZEN). Public surface placeholder; method
// bodies land in subsequent P1-N branches.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod pty;
pub use pty::{Pair, Ring, PTY_BUF_BYTES};

pub mod ldisc;
pub use ldisc::{LdiscOps, NTty, Sig, TtyDriverHooks};

pub mod jobctl;

pub mod wait;
pub use wait::TtyWait;

pub mod core;
pub use core::{ReadOutcome, TtyDriver, TtyFlow, TtyFlush, TtyStruct};

pub mod ioctl;

pub mod registry;
pub use registry::{DevId, TtyRegistry};

// No subsystem-level `init()` entrypoint: the line discipline, pty pairs,
// and tty_struct are constructed by their consumers (console::install,
// devpts::allocate_pair, the VT registry). Per-module results use the
// VfsError / ReadOutcome types in their own files.

#[cfg(target_os = "oxide-kernel")]
pub mod live;
