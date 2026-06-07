// 133 mknod — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.
// Hosts the shared mknod_impl core (also used by 259_mknodat).

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_path, resolve, errno_from_vfs, resolve_parent};

/// `mknod(path, mode, dev)` slot 133.
/// # C: O(N parent entries)
pub fn sys_mknod(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    mknod_impl(raw, args.a1 as u16, args.a2 as u32)
}

/// # C: O(N parent entries)
pub(crate) fn mknod_impl(raw: String, mode: u16, dev: u32) -> i64 {
    let p = resolve(&raw).unwrap_or(raw);
    // Map mode's type bits to the Landlock access needed.
    const S_IFMT:  u16 = 0xF000;
    const S_IFREG: u16 = 0x8000;
    const S_IFCHR: u16 = 0x2000;
    const S_IFBLK: u16 = 0x6000;
    const S_IFIFO: u16 = 0x1000;
    const S_IFSOCK: u16 = 0xC000;
    let ftype = mode & S_IFMT;
    // POSIX: mknod with no type bits ⇒ regular file (≡ create).
    let real_ftype = if ftype == 0 { S_IFREG } else { ftype };
    let la = match real_ftype {
        S_IFREG  => ::security::landlock::access::MAKE_REG,
        S_IFCHR  => ::security::landlock::access::MAKE_CHAR,
        S_IFBLK  => ::security::landlock::access::MAKE_BLOCK,
        S_IFIFO  => ::security::landlock::access::MAKE_FIFO,
        S_IFSOCK => ::security::landlock::access::MAKE_SOCK,
        _        => return -(Errno::Einval.as_i32() as i64),
    };
    if let Err(rv) = crate::landlock::check(&p, la) { return rv; }
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    let r = if real_ftype == S_IFREG {
        // POSIX-compat: mknod-with-regular-type = open(O_CREAT) equivalent.
        pino.create_child(&name, (mode & 0x0FFF) as u32).map(|_| ())
    } else {
        pino.mknod_child(&name, (real_ftype | (mode & 0x0FFF)) as u16, dev)
    };
    match r { Ok(())  => 0, Err(e)  => errno_from_vfs(e) }
}
