#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;

const EFAULT: i64 = -(Errno::Efault.as_i32() as i64);

/// Field accessors for the `autofs_dev_ioctl` parameter block. Linux copies the
/// whole struct in and out with `copy_{from,to}_user`; a direct `*mut u32`
/// through a user address would additionally require the caller's pointer to be
/// naturally aligned, which the ABI does not promise.
fn put_u32(arg: u64, off: u64, v: u32) -> Result<(), i64> {
    uaccess::copy_to_user(arg + off, &v.to_ne_bytes()).map_err(|_| EFAULT)
}

fn put_i32(arg: u64, off: u64, v: i32) -> Result<(), i64> {
    uaccess::copy_to_user(arg + off, &v.to_ne_bytes()).map_err(|_| EFAULT)
}

fn put_u64(arg: u64, off: u64, v: u64) -> Result<(), i64> {
    uaccess::copy_to_user(arg + off, &v.to_ne_bytes()).map_err(|_| EFAULT)
}

fn get_u32(arg: u64, off: u64) -> Result<u32, i64> {
    let mut b = [0u8; 4];
    uaccess::copy_from_user(&mut b, arg + off).map_err(|_| EFAULT)?;
    Ok(u32::from_ne_bytes(b))
}

fn get_i32(arg: u64, off: u64) -> Result<i32, i64> {
    Ok(get_u32(arg, off)? as i32)
}

fn get_u64(arg: u64, off: u64) -> Result<u64, i64> {
    let mut b = [0u8; 8];
    uaccess::copy_from_user(&mut b, arg + off).map_err(|_| EFAULT)?;
    Ok(u64::from_ne_bytes(b))
}

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

    // Struct offsets in `autofs_dev_ioctl`: ver_major@0, ver_minor@4,
    // size@8, ioctlfd@12, then the per-command union@16.
    const VER_MAJOR: u64 = 0;
    const VER_MINOR: u64 = 4;
    const IOCTLFD: u64 = 12;
    const ARG1: u64 = 16;
    const ARG2: u64 = 20;
    const PROTO_VERSION: u32 = 1;
    const PROTO_SUBVERSION: u32 = 1;
    const DEFAULT_PROTOVER: u32 = 5;
    const DEFAULT_PROTOSUBVER: u32 = 6;
    const DEFAULT_TIMEOUT_S: u64 = 300;

    if let Err(rv) = put_u32(arg, VER_MAJOR, PROTO_VERSION) { return Some(rv); }
    if let Err(rv) = put_u32(arg, VER_MINOR, PROTO_SUBVERSION) { return Some(rv); }

    let rv = match nr {
        VERSION => 0,
        OPENMOUNT if is_dev => {
            let devid = match get_u32(arg, ARG1) { Ok(v) => v, Err(rv) => return Some(rv) };
            let Some(ctl_inode) = ::fs::autofs::openmount(devid) else {
                return Some(-(Errno::Enoent.as_i32() as i64));
            };
            let fd = crate::fsmount_common::install_fd(ctl_inode, "[autofs]", true);
            if fd < 0 { return Some(fd); }
            // OPENMOUNT yields the new control fd in `param.ioctlfd` (struct
            // offset 12) and returns 0 — NOT the fd as the ioctl retval. systemd
            // treats `ioctlfd < 0` after the call as -EIO, so a 0-retval without
            // writing this field aborted automount setup (the EIO that followed
            // the ENOENT fix).
            if let Err(rv) = put_i32(arg, IOCTLFD, fd as i32) { return Some(rv); }
            0
        }
        PROTOVER => {
            let version = ctl.map(::fs::autofs::ctl_protover).unwrap_or(DEFAULT_PROTOVER);
            if let Err(rv) = put_u32(arg, ARG1, version) { return Some(rv); }
            0
        }
        PROTOSUBVER => {
            let sub = ctl.map(::fs::autofs::ctl_protosubver).unwrap_or(DEFAULT_PROTOSUBVER);
            if let Err(rv) = put_u32(arg, ARG1, sub) { return Some(rv); }
            0
        }
        TIMEOUT => {
            let cur = match get_u64(arg, ARG1) { Ok(v) => v, Err(rv) => return Some(rv) };
            let out = match ctl {
                Some(c) => ::fs::autofs::ctl_timeout(c, cur),
                None => if cur == 0 { DEFAULT_TIMEOUT_S } else { cur },
            };
            if let Err(rv) = put_u64(arg, ARG1, out) { return Some(rv); }
            0
        }
        ASKUMOUNT => {
            if let Err(rv) = put_u32(arg, ARG1, 1) { return Some(rv); }
            0
        }
        ISMOUNTPOINT => {
            if let Err(rv) = put_u32(arg, ARG1, 0) { return Some(rv); }
            if let Err(rv) = put_u32(arg, ARG2, ::fs::autofs::AUTOFS_SUPER_MAGIC as u32) { return Some(rv); }
            0
        }
        READY => match ctl {
            Some(c) => {
                let token = match get_u32(arg, ARG1) { Ok(v) => v, Err(rv) => return Some(rv) };
                ::fs::autofs::ctl_ready(c, token)
            }
            None => -(Errno::Einval.as_i32() as i64),
        },
        FAIL => match ctl {
            Some(c) => {
                let token = match get_u32(arg, ARG1) { Ok(v) => v, Err(rv) => return Some(rv) };
                let status = match get_i32(arg, ARG2) { Ok(v) => v, Err(rv) => return Some(rv) };
                ::fs::autofs::ctl_fail(c, token, status)
            }
            None => -(Errno::Einval.as_i32() as i64),
        },
        SETPIPEFD => match ctl {
            Some(c) => {
                let fd = match get_i32(arg, ARG1) { Ok(v) => v, Err(rv) => return Some(rv) };
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
