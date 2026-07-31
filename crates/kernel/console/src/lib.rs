#![no_std]
// Host builds compile only the identity/number modules; the kernel-only ones
// are cfg'd out, which leaves their helpers unreferenced.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
#[cfg(target_os = "oxide-kernel")]
#[macro_use]
extern crate kmacros;
extern crate alloc;

// `/dev/console` + `/dev/tty<N>` char-devices per docs/16 + docs/28.
//
// `/dev/tty` and `/dev/tty0` resolve to the foreground video VT; `/dev/console`
// follows the preferred console; `/dev/ttyS0` is a separate serial tty. This
// mirrors Linux's device split: a machine can run a framebuffer console login
// and an independent serial login at the same time without mirroring user I/O.
//
// printk stays SEPARATE: kernel logs reach the UART via klog's serial
// sink (and mirror to fbcon); a tty write here goes TtyStruct → UART, NOT
// into the kmsg ring — the dmesg/shell-output split.
//
// Module manifest:
// - `ids`:       inode NUMBERS + selectors, from `vfs::pseudo_ino`.
// - `identity`:  what a console tty inode IS — `i_private`, never its number.
// - `nodes`:     the ONE console tty inode constructor.
// - `devnum`:    Linux major/minor device numbers.
// - `routing`:   live `binding → tty` resolution + open-time ctty acquisition.
// - `serial`/`static_console`: the UART line.
// - `vt_console`/`vt_tty`/`vt_input`: the video VTs.
// - `vcs`:       `/dev/vcs*` screen dumps.
// - `devnodes`:  device-model registration of every node above.
//
// Everything but `ids`/`identity`/`nodes`/`devnum` reaches `tty::live`,
// `sched::live` or a UART driver, so it exists only in a kernel build; the
// identity DECISION is ungated and host-tested.

mod devnum;
pub mod identity;
pub mod ids;
pub mod nodes;

#[cfg(target_os = "oxide-kernel")] pub mod devnodes;
#[cfg(target_os = "oxide-kernel")] pub mod routing;
#[cfg(target_os = "oxide-kernel")] pub mod serial;
#[cfg(target_os = "oxide-kernel")] pub mod static_console;
#[cfg(target_os = "oxide-kernel")] pub mod vcs;
#[cfg(target_os = "oxide-kernel")] pub mod vt_console;
#[cfg(target_os = "oxide-kernel")] mod vt_input;
#[cfg(target_os = "oxide-kernel")] pub mod vt_tty;

pub use identity::{binding_of, is_console_tty, ConsoleData, TtyBinding, TtyTarget};
pub use ids::{FG_VT_INO_LB, MAX_VT_INO_LB, SERIAL_INO_LB, SYSTEM_CONSOLE_INO_LB,
              TTY_ALIAS_INO_LB, TTY_INO_BASE};
pub use nodes::{make_console_inode, make_serial_inode, make_system_console_inode,
                make_tty_alias_inode};

#[cfg(target_os = "oxide-kernel")]
pub use devnodes::{register_devnodes, try_register_devnodes};
#[cfg(target_os = "oxide-kernel")]
pub use routing::{acquire_ctty_on_open, foreground_vt, route};
#[cfg(target_os = "oxide-kernel")]
pub use serial::{kbd_input, system_console_inode, vt_reply_sink};
#[cfg(target_os = "oxide-kernel")]
pub use vcs::make_vcs_inode;
#[cfg(target_os = "oxide-kernel")]
pub use vt_console::init_console_fd_table;
