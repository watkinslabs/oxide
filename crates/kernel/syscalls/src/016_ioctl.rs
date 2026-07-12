// `sys_ioctl` per `15§5` / `28§5`. Split from `syscall_glue_fs.rs`.

#![cfg(target_os = "oxide-kernel")]

#[path = "016_ioctl/autofs.rs"] mod autofs;
#[path = "016_ioctl/blk.rs"] mod blk;
#[path = "016_ioctl/common.rs"] mod common;
#[path = "016_ioctl/core.rs"] mod core;
#[path = "016_ioctl/fiemap.rs"] mod fiemap;
#[path = "016_ioctl/font.rs"] mod font;
#[path = "016_ioctl/netns.rs"] mod netns;
#[path = "016_ioctl/tioclinux.rs"] mod tioclinux;
#[path = "016_ioctl/tty_ioctl.rs"] mod tty_ioctl;
#[path = "016_ioctl/vt.rs"] mod vt;

pub use self::core::sys_ioctl;
pub use self::vt::vt_switch_wake;
