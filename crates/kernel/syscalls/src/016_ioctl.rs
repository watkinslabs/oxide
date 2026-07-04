// `sys_ioctl` per `15§5` / `28§5`. Split from `syscall_glue_fs.rs`.

#![cfg(target_os = "oxide-kernel")]

mod autofs;
mod core;
mod font;
mod tioclinux;
mod tty_ioctl;
mod vt;

pub use self::core::sys_ioctl;
pub use self::vt::vt_switch_wake;
