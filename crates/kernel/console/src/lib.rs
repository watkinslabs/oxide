#![cfg(target_os = "oxide-kernel")]  // kernel-only crate (uses static_console/sched::live)
#![no_std]
#[macro_use]
extern crate kmacros;
extern crate alloc;

// `/dev/console` + `/dev/tty<N>` char-devices per docs/16 + docs/28.
//
// `/dev/console`, `/dev/tty`, and `/dev/tty0` resolve to the foreground
// video VT by default. `/dev/ttyS0` is a separate serial tty. This mirrors
// Linux's device split: a machine can run a framebuffer console login and
// an independent serial login at the same time without mirroring user I/O.
//
// printk stays SEPARATE: kernel logs reach the UART via klog's serial
// sink (and mirror to fbcon); a tty write here goes TtyStruct → UART, NOT
// into the kmsg ring — the dmesg/shell-output split.

pub mod devnodes;
mod devnum;
mod ids;
pub mod routing;
pub mod serial;
pub mod static_console;
pub mod vcs;
pub mod vt_console;
pub mod vt_tty;

pub use devnodes::{register_devnodes, try_register_devnodes};
pub use routing::{
    FG_VT_INO_LB, SERIAL_INO_LB, TTY_ALIAS_INO_LB, TTY_INO_BASE, TtyTarget, acquire_ctty_on_open,
    foreground_vt, is_console_tty_ino, route,
};
pub use serial::{kbd_input, make_serial_inode, system_console_inode, vt_reply_sink};
pub use vcs::make_vcs_inode;
pub use vt_console::{ConsoleData, init_console_fd_table, make_console_inode, make_system_console_inode, make_tty_alias_inode};
