use syscall::errno::Errno;

use crate::ioctl_user as user;
use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

use super::remap::{remap_verify_area, vfs_clone_file_range, vfs_dedupe_file_range_one};
use super::uapi::*;

const INODE_BLOCK_BYTES: u64 = 512;

/// Linux `do_vfs_ioctl`: the generic stage. Answers ONLY the commands
/// [`super::ioctl_owner`] assigns to it; everything else returns `None`
/// (Linux `-ENOIOCTLCMD`) so the file's own operations answer. It never
/// invents `ENOTTY` on a file's behalf. # C: O(1)
pub(super) fn handle_common_ioctl(
    cur: &sched::Task,
    file: &alloc::sync::Arc<vfs::File>,
    fdt: &alloc::sync::Arc<vfs::FdTable>,
    fd: i32,
    req: u64,
    arg: u64,
) -> Option<i64> {
    if super::ioctl_owner(req, super::ioctl_file(file)) == super::IoctlOwner::FileOps {
        return None;
    }
    match req {
        FIOCLEX => Some(match fdt.set_cloexec(fd, true) {
            Ok(()) => 0,
            Err(e) => -(e as i64),
        }),
        FIONCLEX => Some(match fdt.set_cloexec(fd, false) {
            Ok(()) => 0,
            Err(e) => -(e as i64),
        }),
        FIONBIO => Some(ioctl_fionbio(file, arg)),
        FIOASYNC => Some(ioctl_fioasync(file, fd, arg)),
        FIOQSIZE => Some(ioctl_fioqsize(file, arg)),
        FIGETBSZ => Some(ioctl_figetbsz(file, arg)),
        FICLONE => Some(ioctl_file_clone(file, fdt, arg as i64, 0, 0, 0)),
        FICLONERANGE => Some(ioctl_file_clone_range(file, fdt, arg)),
        FIDEDUPERANGE => Some(ioctl_file_dedupe_range(cur, file, fdt, arg)),
        // Type/anon guards already passed in `ioctl_owner`; reaching an arm
        // here means the generic stage owns the command for this file.
        FIBMAP => Some(ioctl_fibmap(cur, file, arg)),
        FS_IOC_RESVSP | FS_IOC_RESVSP64 => Some(ioctl_preallocate(cur, file, 0, arg)),
        FS_IOC_UNRESVSP | FS_IOC_UNRESVSP64 => {
            Some(ioctl_preallocate(cur, file, vfs::uapi::FALLOC_FL_PUNCH_HOLE, arg))
        }
        FS_IOC_ZERO_RANGE => Some(ioctl_preallocate(cur, file, vfs::uapi::FALLOC_FL_ZERO_RANGE, arg)),
        FS_IOC_GETFLAGS => Some(super::fileattr::ioctl_getflags(file, arg)),
        FS_IOC_SETFLAGS => Some(super::fileattr::ioctl_setflags(cur, file, arg)),
        FS_IOC_FSGETXATTR => Some(super::fileattr::ioctl_fsgetxattr(file, arg)),
        FS_IOC_FSSETXATTR => Some(super::fileattr::ioctl_fssetxattr(cur, file, arg)),
        FS_IOC_GETFSUUID => Some(ioctl_getfsuuid(file, arg)),
        FS_IOC_GETFSSYSFSPATH => Some(ioctl_getfssysfspath(file, arg)),
        FIONREAD => Some(ioctl_regular_fionread(file, arg)),
        _ => None,
    }
}

/// Socket/pipe queue-count ioctls used after regular-file common handling.
/// # C: O(1)
pub(super) fn handle_nonchar_queue_ioctl(file: &vfs::File, req: u64, arg: u64) -> Option<i64> {
    let cmd = match req {
        FIONREAD => vfs::IoctlIntCmd::Fionread,
        SIOCOUTQ => vfs::IoctlIntCmd::Siocoutq,
        SIOCOUTQNSD => vfs::IoctlIntCmd::Siocoutqnsd,
        SIOCATMARK => vfs::IoctlIntCmd::Siocatmark,
        _ => return None,
    };
    let n = match file.ioctl_int(cmd) {
        Ok(n) => n,
        Err(e) => return Some(-(e as i64)),
    };
    if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return Some(rv); }
    match user::put_u32(arg, n) { Ok(()) => Some(0), Err(rv) => Some(rv) }
}

/// Linux `sock_ioctl` f_owner commands. `FIOSETOWN`/`SIOCSPGRP` import one
/// signed owner id; `FIOGETOWN`/`SIOCGPGRP` export the shared open-file
/// description's owner. The caller must establish that `file` is a socket
/// before invoking this helper. # C: O(1)
pub(super) fn handle_socket_owner_ioctl(file: &vfs::File, req: u64, arg: u64) -> Option<i64> {
    match req {
        FIOSETOWN | SIOCSPGRP => {
            if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return Some(rv); }
            let owner = match user::get_i32(arg) { Ok(v) => v, Err(rv) => return Some(rv) };
            install_sigio_hook();
            let (uid, euid) = socket_owner_creds();
            // Linux `sock_ioctl` routes these through `f_setown(.., who, ..)`,
            // so a negative id names a process GROUP exactly as `F_SETOWN` does.
            use vfs::file::owner_type::{F_OWNER_PGRP, F_OWNER_PID};
            let (id, ty) = if owner < 0 { (owner.saturating_neg(), F_OWNER_PGRP) }
                           else { (owner, F_OWNER_PID) };
            file.f_setown(id, ty, uid, euid);
            Some(0)
        }
        FIOGETOWN | SIOCGPGRP => {
            if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return Some(rv); }
            match user::put_i32(arg, file.f_getown()) { Ok(()) => Some(0), Err(rv) => Some(rv) }
        }
        _ => None,
    }
}

/// Linux `ioctl_fionbio`: read caller int and toggle `O_NONBLOCK`. # C: O(1)
fn ioctl_fionbio(file: &vfs::File, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
    let on = match user::get_i32(arg) { Ok(v) => v != 0, Err(rv) => return rv };
    let mut fl = file.flags();
    if on { fl |= vfs::OpenFlags::O_NONBLOCK; } else { fl &= !vfs::OpenFlags::O_NONBLOCK; }
    // FIONBIO only ever toggles O_NONBLOCK, never O_DIRECT, so `set_fl`'s
    // direct-I/O admission cannot reject it.
    let _ = file.set_fl(fl);
    0
}

/// Linux `ioctl_fioasync`: read caller int and toggle `FASYNC`. # C: O(1)
fn ioctl_fioasync(file: &alloc::sync::Arc<vfs::File>, fd: i32, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
    let on = match user::get_i32(arg) { Ok(v) => v != 0, Err(rv) => return rv };
    if file.is_async() == on { return 0; }
    match file.fasync(fd, on) {
        Ok(()) => {
            if on { install_sigio_hook(); }
            0
        }
        Err(e) => -(e as i64),
    }
}

/// Kernel target wires SIGIO delivery before adding the file to fasync. Hosted
/// tests do not build `sched::live`, but still exercise the flag/registry path.
/// # C: O(1)
#[cfg(not(test))]
fn install_sigio_hook() {
    sched::live::sigpend::install_sigio_hook();
}

/// # C: O(1)
#[cfg(test)]
fn install_sigio_hook() {}

/// `f_setown` captures the caller's (real, effective) uid for the deferred
/// `sigio_perm` check — Linux `f_modown(…, current_uid(), current_euid(), …)`.
/// Hosted shape tests have no running task, so they use root solely to
/// exercise the VFS owner-state transaction. # C: O(1)
#[cfg(not(test))]
fn socket_owner_creds() -> (u32, u32) {
    use core::sync::atomic::Ordering;
    sched::live::current()
        .map(|t| (t.creds.ruid.load(Ordering::Acquire), t.creds.euid.load(Ordering::Acquire)))
        .unwrap_or((0, 0))
}

/// # C: O(1)
#[cfg(test)]
fn socket_owner_creds() -> (u32, u32) { (0, 0) }

/// Linux `FIOQSIZE`: dirs, symlinks, and non-anon regular files copy `loff_t`
/// bytes. Every other shape is `ENOTTY` FROM THIS STAGE — the one generic
/// command that answers for a file it cannot measure instead of handing the
/// call to the file's own operations. # C: O(1)
fn ioctl_fioqsize(file: &vfs::File, arg: u64) -> i64 {
    if !super::ioctl_file(file).has_allocated_size() {
        return -(Errno::Enotty.as_i32() as i64);
    }
    if let Err(rv) = validate_user_buf_writable(arg, LOFF_BYTES, 1) { return rv; }
    let bytes = file.inode().blocks() * INODE_BLOCK_BYTES;
    match user::put_i64(arg, bytes as i64) { Ok(()) => 0, Err(rv) => rv }
}

/// Linux `FIGETBSZ`: copy superblock `s_blocksize`, or `EINVAL` if absent.
/// # C: O(1)
fn ioctl_figetbsz(file: &vfs::File, arg: u64) -> i64 {
    let bs = match file.inode().i_sb() {
        Some(sb) if sb.s_blocksize != 0 => sb.s_blocksize,
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return rv; }
    match user::put_i32(arg, bs as i32) { Ok(()) => 0, Err(rv) => rv }
}

/// Linux `FICLONERANGE`: copy `struct file_clone_range`, then clone. # C: FS-dependent
fn ioctl_file_clone_range(file: &alloc::sync::Arc<vfs::File>, fdt: &vfs::FdTable, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, FILE_CLONE_RANGE_BYTES, 1) { return rv; }
    let r = match user::get_bytes::<{ FILE_CLONE_RANGE_BYTES as usize }>(arg) {
        Ok(b) => b, Err(rv) => return rv,
    };
    ioctl_file_clone(file, fdt, ld_i64(&r, 0), ld_u64(&r, 8), ld_u64(&r, 16), ld_u64(&r, 24))
}

/// Linux `ioctl_file_clone`: fd lookup plus `vfs_clone_file_range`. # C: FS-dependent
fn ioctl_file_clone(file: &alloc::sync::Arc<vfs::File>, fdt: &vfs::FdTable, src_fd: i64, src_off: u64, src_len: u64, dst_off: u64) -> i64 {
    let src_fd = match i32::try_from(src_fd) {
        Ok(fd) => fd,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let src = match fdt.get(src_fd) {
        Ok(f) => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    match vfs_clone_file_range(&src, src_off, file, dst_off, src_len, 0) {
        Ok(done) if src_len != 0 && done != src_len => -(Errno::Einval.as_i32() as i64),
        Ok(_) => 0,
        Err(e) => -(e as i64),
    }
}

/// Linux `FIDEDUPERANGE`: variable-length input with per-destination status.
/// The reference reads `dest_count`, bounds the payload at one page, copies the
/// WHOLE `struct file_dedupe_range` into kernel memory, runs the dedupe against
/// that copy, and writes it back once — so a caller cannot race a page away
/// mid-walk, and an error leaves the caller's buffer untouched.
/// # C: FS-dependent
fn ioctl_file_dedupe_range(cur: &sched::Task, file: &vfs::File, fdt: &vfs::FdTable, arg: u64) -> i64 {
    let count = match user::get_u16(arg + DEDUPE_DEST_COUNT) { Ok(v) => v, Err(rv) => return rv };
    let size = match user::dedupe_payload_bytes(count) { Ok(v) => v, Err(rv) => return rv };
    let mut same = alloc::vec![0u8; size as usize];
    if let Err(rv) = user::get_into(arg, &mut same) { return rv; }
    let src_off = ld_u64(&same, DEDUPE_SRC_OFFSET);
    let src_len_in = ld_u64(&same, DEDUPE_SRC_LENGTH);
    if !file.f_mode().contains(vfs::Fmode::READ) { return -(Errno::Einval.as_i32() as i64); }
    if ld_u16(&same, DEDUPE_RESERVED1) != 0 || ld_u32(&same, DEDUPE_RESERVED2) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    match file.inode().file_type() {
        vfs::FileType::Directory => return -(Errno::Eisdir.as_i32() as i64),
        vfs::FileType::Regular => {}
        _ => return -(Errno::Einval.as_i32() as i64),
    }
    if !file.supports_remap_file_range() { return -(Errno::Eopnotsupp.as_i32() as i64); }
    if let Err(e) = remap_verify_area(src_off, src_len_in) { return -(e as i64); }
    if src_off.checked_add(src_len_in).is_none_or(|end| end > file.inode().size()) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let len = core::cmp::min(src_len_in, user::DEDUPE_MAX_LEN);
    for i in 0..count as u64 {
        let base = DEDUPE_RANGE_BYTES + i * DEDUPE_INFO_BYTES;
        st_u64(&mut same, base + DEDUPE_INFO_BYTES_DEDUPED, 0);
        st_i32(&mut same, base + DEDUPE_INFO_STATUS, FILE_DEDUPE_RANGE_SAME);
    }
    for i in 0..count as u64 {
        let base = DEDUPE_RANGE_BYTES + i * DEDUPE_INFO_BYTES;
        let dst_fd = ld_i64(&same, base + DEDUPE_INFO_DEST_FD);
        let dst_off = ld_u64(&same, base + DEDUPE_INFO_DEST_OFFSET);
        let reserved = ld_u32(&same, base + DEDUPE_INFO_RESERVED);
        let status = match i32::try_from(dst_fd).ok().and_then(|fd| fdt.get(fd).ok()) {
            None => -(Errno::Ebadf.as_i32()),
            Some(_) if reserved != 0 => -(Errno::Einval.as_i32()),
            Some(dst) => match vfs_dedupe_file_range_one(cur, file, src_off, &dst, dst_off, len) {
                Ok(()) => {
                    st_u64(&mut same, base + DEDUPE_INFO_BYTES_DEDUPED, len);
                    FILE_DEDUPE_RANGE_SAME
                }
                Err(vfs::VfsError::Ebade) => FILE_DEDUPE_RANGE_DIFFERS,
                Err(e) => -(e as i32),
            },
        };
        st_i32(&mut same, base + DEDUPE_INFO_STATUS, status);
    }
    match user::put_bytes(arg, &same) { Ok(()) => 0, Err(rv) => rv }
}

/// Linux regular-file `FIONREAD`: `i_size - f_pos` copied as an int. # C: O(1)
fn ioctl_regular_fionread(file: &vfs::File, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return rv; }
    let n = (file.inode().size() as i64).wrapping_sub(file.pos() as i64) as i32;
    match user::put_i32(arg, n) { Ok(()) => 0, Err(rv) => rv }
}

/// Linux `FIBMAP`: capability-gated logical block to disk block query. # C: FS-dependent
fn ioctl_fibmap(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    if !cur.has_cap(sched::cap::SYS_RAWIO) { return -(Errno::Eperm.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
    let logical = match user::get_i32(arg) { Ok(v) => v, Err(rv) => return rv };
    if logical < 0 { return -(Errno::Einval.as_i32() as i64); }
    let mapped = file.inode().bmap(logical as u64);
    let (out, rv) = match mapped {
        Ok(block) if block <= i32::MAX as u64 => (block as i32, 0),
        Ok(_) => (0, -(Errno::Erange.as_i32() as i64)),
        Err(e) => (0, -(e as i64)),
    };
    if let Err(fault) = validate_user_buf_writable(arg, INT_BYTES, 1) { return fault; }
    if let Err(fault) = user::put_i32(arg, out) { return fault; }
    rv
}

/// `ioctl_preallocate` — the legacy XFS space-reservation
/// ioctls. Only the `l_whence` fixup belongs here; the range, mode, writability
/// and inode-flag ladder is `vfs_fallocate`'s, and duplicating it produced the
/// wrong errno (`EINVAL` where Linux reports `EFBIG` on wraparound).
/// `FALLOC_FL_KEEP_SIZE` is always added: these ioctls reserve space, never
/// move the file's end. # C: FS-dependent
fn ioctl_preallocate(cur: &sched::Task, file: &vfs::File, mode: u32, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, SPACE_RESV_BYTES, 1) { return rv; }
    let resv = match user::get_bytes::<{ SPACE_RESV_BYTES as usize }>(arg) {
        Ok(b) => b, Err(rv) => return rv,
    };
    let whence = ld_u16(&resv, SPACE_RESV_L_WHENCE) as i16;
    let mut start = ld_i64(&resv, SPACE_RESV_L_START);
    let len = ld_i64(&resv, SPACE_RESV_L_LEN);
    match whence {
        SEEK_SET => {}
        SEEK_CUR => start = match start.checked_add(file.pos() as i64) {
            Some(v) => v, None => return -(Errno::Einval.as_i32() as i64),
        },
        SEEK_END => start = match start.checked_add(file.inode().size() as i64) {
            Some(v) => v, None => return -(Errno::Einval.as_i32() as i64),
        },
        _ => return -(Errno::Einval.as_i32() as i64),
    }
    fs::fallocate::vfs_fallocate(cur, file, mode | vfs::uapi::FALLOC_FL_KEEP_SIZE, start, len)
}

/// Linux `FS_IOC_GETFSUUID`: expose superblock UUID or `ENOTTY`. # C: O(1)
fn ioctl_getfsuuid(file: &vfs::File, arg: u64) -> i64 {
    let sb = match file.inode().i_sb() {
        Some(sb) => sb,
        None => return -(Errno::Enotty.as_i32() as i64),
    };
    let len = sb.s_uuid_len();
    if len == 0 { return -(Errno::Enotty.as_i32() as i64); }
    let uuid = sb.s_uuid();
    if let Err(rv) = validate_user_buf_writable(arg, FSUUID2_BYTES, 1) { return rv; }
    let mut out = [0u8; FSUUID2_BYTES as usize];
    out[0] = len;
    out[1..].copy_from_slice(&uuid[..16]);
    match user::put_bytes(arg, &out) { Ok(()) => 0, Err(rv) => rv }
}

/// Linux `FS_IOC_GETFSSYSFSPATH`: expose `fstype/s_sysfs_name`. # C: O(len name)
fn ioctl_getfssysfspath(file: &vfs::File, arg: u64) -> i64 {
    let sb = match file.inode().i_sb() {
        Some(sb) => sb,
        None => return -(Errno::Enotty.as_i32() as i64),
    };
    let name = sb.s_sysfs_name();
    if name.is_empty() { return -(Errno::Enotty.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_writable(arg, FS_SYSFS_PATH_BYTES, 1) { return rv; }
    let ty = sb.s_type.name().as_bytes();
    let sys = name.as_bytes();
    let mut out = [0u8; FS_SYSFS_PATH_NAME_BYTES];
    let mut n = 0usize;
    for b in ty.iter().chain(core::iter::once(&b'/')).chain(sys.iter()) {
        if n + 1 >= FS_SYSFS_PATH_NAME_BYTES { break; }
        out[n] = *b;
        n += 1;
    }
    let mut buf = [0u8; FS_SYSFS_PATH_BYTES as usize];
    buf[0] = n as u8;
    buf[1..].copy_from_slice(&out);
    match user::put_bytes(arg, &buf) { Ok(()) => 0, Err(rv) => rv }
}

// Field accessors on a KERNEL copy of a caller payload. The copy in and the
// copy out are the only caller-memory touches; every field read/write between
// them is ordinary kernel memory and cannot fault.

fn ld_u16(b: &[u8], off: u64) -> u16 {
    u16::from_ne_bytes([b[off as usize], b[off as usize + 1]])
}

fn ld_u32(b: &[u8], off: u64) -> u32 {
    let o = off as usize;
    u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn ld_u64(b: &[u8], off: u64) -> u64 {
    let o = off as usize;
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_ne_bytes(v)
}

fn ld_i64(b: &[u8], off: u64) -> i64 { ld_u64(b, off) as i64 }

fn st_u64(b: &mut [u8], off: u64, val: u64) {
    let o = off as usize;
    b[o..o + 8].copy_from_slice(&val.to_ne_bytes());
}

fn st_i32(b: &mut [u8], off: u64, val: i32) {
    let o = off as usize;
    b[o..o + 4].copy_from_slice(&val.to_ne_bytes());
}
