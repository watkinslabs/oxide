#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;

pub(super) fn handle_autofs_dev_ioctl(inode: &vfs::InodeRef, req: u64, arg: u64) -> Option<i64> {
    let is_dev = inode.rdev() == devfs::uapi::DEV_MISC_AUTOFS;
    let ctl = ::fs::autofs::ctl_from_inode(inode);
    if !is_dev && ctl.is_none() {
        return None;
    }
    const AUTOFS_IOCTL: u64 = 0x93;
    const VERSION: u64 = 0x71;
    const PROTOVER: u64 = 0x72;
    const PROTOSUBVER: u64 = 0x73;
    const OPENMOUNT: u64 = 0x74;
    const CLOSEMOUNT: u64 = 0x75;
    const READY: u64 = 0x76;
    const FAIL: u64 = 0x77;
    const SETPIPEFD: u64 = 0x78;
    const CATATONIC: u64 = 0x79;
    const TIMEOUT: u64 = 0x7a;
    const REQUESTER: u64 = 0x7b;
    const EXPIRE: u64 = 0x7c;
    const ASKUMOUNT: u64 = 0x7d;
    const ISMOUNTPOINT: u64 = 0x7e;
    const DEV_IOCTL_SIZE: u64 = 24;

    let ty = (req >> 8) & 0xff;
    let nr = req & 0xff;
    if ty != AUTOFS_IOCTL || !(VERSION..=ISMOUNTPOINT).contains(&nr) {
        return Some(-(Errno::Enotty.as_i32() as i64));
    }
    if let Err(rv) = validate_user_buf_writable(arg, DEV_IOCTL_SIZE, 1) {
        return Some(rv);
    }

    unsafe {
        core::ptr::write_volatile(arg as *mut u32, 1);
        core::ptr::write_volatile((arg + 4) as *mut u32, 1);
    }

    let rv = match nr {
        VERSION => 0,
        OPENMOUNT if is_dev => {
            let devid = unsafe { core::ptr::read_volatile((arg + 16) as *const u32) };
            let Some(ctl_inode) = ::fs::autofs::openmount(devid) else {
                return Some(-(Errno::Enoent.as_i32() as i64));
            };
            let fd = crate::fsmount_common::install_fd(ctl_inode, "[autofs]", true);
            if fd < 0 { return Some(fd); }
            // OPENMOUNT yields the new control fd in `param.ioctlfd` (struct
            // offset 12) and returns 0 — NOT the fd as the ioctl retval. systemd
            // treats `ioctlfd < 0` after the call as -EIO, so a 0-retval without
            // writing this field aborted automount setup (the EIO that followed
            // the ENOENT fix). # SAFETY: arg..arg+24 validated writable above.
            unsafe { core::ptr::write_volatile((arg + 12) as *mut i32, fd as i32); }
            0
        }
        PROTOVER => {
            let version = ctl.map(::fs::autofs::ctl_protover).unwrap_or(5);
            unsafe { core::ptr::write_volatile((arg + 16) as *mut u32, version); }
            0
        }
        PROTOSUBVER => {
            let sub = ctl.map(::fs::autofs::ctl_protosubver).unwrap_or(6);
            unsafe { core::ptr::write_volatile((arg + 16) as *mut u32, sub); }
            0
        }
        TIMEOUT => {
            let cur = unsafe { core::ptr::read_volatile((arg + 16) as *const u64) };
            let out = match ctl {
                Some(c) => ::fs::autofs::ctl_timeout(c, cur),
                None => if cur == 0 { 300 } else { cur },
            };
            unsafe {
                core::ptr::write_volatile((arg + 16) as *mut u64, out);
            }
            0
        }
        ASKUMOUNT => {
            unsafe { core::ptr::write_volatile((arg + 16) as *mut u32, 1); }
            0
        }
        ISMOUNTPOINT => {
            unsafe {
                core::ptr::write_volatile((arg + 16) as *mut u32, 0);
                core::ptr::write_volatile((arg + 20) as *mut u32, ::fs::autofs::AUTOFS_SUPER_MAGIC as u32);
            }
            0
        }
        READY => match ctl {
            Some(c) => {
                let token = unsafe { core::ptr::read_volatile((arg + 16) as *const u32) };
                ::fs::autofs::ctl_ready(c, token)
            }
            None => -(Errno::Einval.as_i32() as i64),
        },
        FAIL => match ctl {
            Some(c) => {
                let token = unsafe { core::ptr::read_volatile((arg + 16) as *const u32) };
                let status = unsafe { core::ptr::read_volatile((arg + 20) as *const i32) };
                ::fs::autofs::ctl_fail(c, token, status)
            }
            None => -(Errno::Einval.as_i32() as i64),
        },
        SETPIPEFD => match ctl {
            Some(c) => {
                let fd = unsafe { core::ptr::read_volatile((arg + 16) as *const i32) };
                match ::fs::autofs::ctl_setpipefd(c, fd) {
                    Ok(()) => 0,
                    Err(e) => crate::namei_common::errno_from_vfs(e),
                }
            }
            None => -(Errno::Einval.as_i32() as i64),
        },
        CLOSEMOUNT | CATATONIC => 0,
        REQUESTER | EXPIRE => {
            -(Errno::Enoent.as_i32() as i64)
        }
        _ => -(Errno::Enotty.as_i32() as i64),
    };
    Some(rv)
}
