//! Linux timerfd surface.
//!
//! - `model`: inode identity, clock domains, and wall-step observation.
//! - `file`: poll, read, and expiration consumption.
//! - `state`: the sole lock-protected timer transaction state.
//! - `syscalls`: Linux ABI transactions and errno ordering.
//! - `uapi`: native itimerspec copies and TFD flags.
//! - `ioctl`: `TFD_IOC_SET_TICKS`.
//! - `fdinfo`: `/proc/<pid>/fdinfo/<n>` body.
//! - `debug`: feature-gated compositor diagnostics.

#[cfg(any(feature = "debug-desktop", feature = "debug-mutter-timer-verbose"))]
#[path = "timerfd/debug.rs"]
mod debug;

#[path = "timerfd/fdinfo.rs"]
mod fdinfo;

#[path = "timerfd/file.rs"]
mod file;

#[path = "timerfd/ioctl.rs"]
mod ioctl;

#[path = "timerfd/model.rs"]
mod model;

#[path = "timerfd/state.rs"]
mod state;

#[path = "timerfd/syscalls.rs"]
mod syscalls;

#[path = "timerfd/uapi.rs"]
mod uapi;

#[cfg(target_os = "oxide-kernel")]
pub use model::install_clock_was_set_hook;
pub use ioctl::handle_timerfd_ioctl;
pub use syscalls::{sys_timerfd_create, sys_timerfd_gettime, sys_timerfd_settime};

#[cfg(test)]
use file::{TimerfdFileOps, timerfd_take_expirations};
#[cfg(test)]
use model::{
    CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM, CLOCK_MONOTONIC, CLOCK_REALTIME,
    CLOCK_REALTIME_ALARM, TimerfdData, make_timerfd_inode,
    monotonic_deadline_from_value, monotonic_ns, realtime_deadline,
    timerfd_clock_was_set, timerfd_namespace_clock,
};
#[cfg(test)]
use state::TimerfdState;
#[cfg(test)]
use sync::{Spinlock, Timer as TimerLockClass};
#[cfg(test)]
use uapi::TFD_TIMER_ABSTIME;
#[cfg(test)]
use vfs::{FileOps, InodeRef, VfsError};

#[cfg(test)]
#[path = "timerfd/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "timerfd/state_tests.rs"]
mod state_tests;

#[cfg(test)]
#[path = "timerfd/fdinfo_tests.rs"]
mod fdinfo_tests;
