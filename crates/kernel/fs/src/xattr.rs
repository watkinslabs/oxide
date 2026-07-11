// xattr (extended-attribute) syscall layer (setxattr/getxattr/listxattr/
// removexattr + the f/l/*at variants). This is the VFS-policy half (Linux
// `vfs_setxattr` → `xattr_permission` → `handler->set`): it receives an already
// resolved inode, enforces namespace permission model + name/size limits + the
// XATTR_CREATE/XATTR_REPLACE meaning, then dispatches STORAGE to the owning
// filesystem's per-inode backend (`Inode::{get,set,remove,list}xattr` →
// `i_op` → `vfs::xattr::SimpleXattrs`). Each fs OWNS its xattrs (D45):
//   * tmpfs  — `SimpleXattrs` on every tmpfs inode (Linux shmem_inode_info).
//   * ext4   — `SimpleXattrs` on every ext4 inode (in-core ownership; on-disk
//              ibody/xattr-block PERSISTENCE is a residual, see fix-ledger).
//
// Filesystems with no backend store return EOPNOTSUPP. There is no global
// fallback table: xattrs must belong to the inode's owning filesystem or fail.
//
// Linux semantics honoured:
//   * setxattr flags: XATTR_CREATE (1) — fail with EEXIST if name already
//     exists; XATTR_REPLACE (2) — fail with ENODATA if name absent.
//     Both clear → unconditional set.
//   * getxattr returns the value's length when buflen=0 (probe pattern).
//   * listxattr writes NUL-separated names; returns total length when
//     buflen=0.
//   * removexattr returns ENODATA if name absent.


use alloc::string::String;
use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::InodeRef;
use vfs::xattr::XattrError;

const ENODATA: i32 = 61;
const EEXIST:  i32 = 17;
const EOPNOTSUPP: i32 = 95;

pub const XATTR_CREATE:  u32 = 1;
pub const XATTR_REPLACE: u32 = 2;

/// Linux XATTR_NAME_MAX (255) / XATTR_SIZE_MAX (64 KiB).
const XATTR_NAME_MAX: usize = 255;
const XATTR_SIZE_MAX: usize = 65536;

/// Effective fsuid + the file-related caps for the running task. Early
/// boot (no task) is treated as fully privileged (root).
fn cred_snapshot() -> (u32, bool /*sys_admin*/, bool /*setfcap*/, bool /*fowner*/) {
    use core::sync::atomic::Ordering;
    match sched::current() {
        Some(c) => (
            c.creds.fsuid.load(Ordering::Acquire),
            c.has_cap(sched::cap::SYS_ADMIN),
            c.has_cap(sched::cap::SETFCAP),
            c.has_cap(sched::cap::FOWNER),
        ),
        None => (0, true, true, true),
    }
}

/// Owning uid of `inode` (per-FS first, then the inode_times overlay, then 0).
fn inode_owner(inode: &InodeRef) -> u32 {
    if let Some(u) = inode.uid() { return u; }
    vfs::inode_times::get(inode)
        .map(|o| if o.owner_set { o.uid } else { 0 })
        .unwrap_or(0)
}

/// Validate xattr name length (Linux ERANGE past XATTR_NAME_MAX).
fn check_name_len(name: &str) -> Result<(), i64> {
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(-(Errno::Erange.as_i32() as i64));
    }
    Ok(())
}

/// Enforce the Linux xattr namespace permission model for a WRITE
/// (setxattr/removexattr):
///   * `security.capability` → CAP_SETFCAP; other `security.*` → CAP_SYS_ADMIN
///   * `trusted.*`           → CAP_SYS_ADMIN
///   * `system.*` / `user.*` → owner (fsuid==i_uid) or CAP_FOWNER;
///     `user.*` is further restricted to regular files and directories
///   * any other namespace    → EOPNOTSUPP
/// Without this, an unprivileged `setxattr(file,"security.capability",…)`
/// is a privilege-escalation vector (execve reads file caps).
/// # C: O(1)
fn check_write_perm(inode: &InodeRef, name: &str) -> Result<(), i64> {
    let (fsuid, sys_admin, setfcap, fowner) = cred_snapshot();
    let owner_ok = fowner || fsuid == inode_owner(inode);
    if name == "security.capability" {
        return if setfcap { Ok(()) } else { Err(-(Errno::Eperm.as_i32() as i64)) };
    }
    if name.starts_with("security.") {
        return if sys_admin { Ok(()) } else { Err(-(Errno::Eperm.as_i32() as i64)) };
    }
    if name.starts_with("trusted.") {
        return if sys_admin { Ok(()) } else { Err(-(Errno::Eperm.as_i32() as i64)) };
    }
    if name.starts_with("system.") {
        return if owner_ok { Ok(()) } else { Err(-(Errno::Eperm.as_i32() as i64)) };
    }
    if name.starts_with("user.") {
        match inode.file_type() {
            vfs::FileType::Regular | vfs::FileType::Directory => {}
            _ => return Err(-(Errno::Eperm.as_i32() as i64)),
        }
        return if owner_ok { Ok(()) } else { Err(-(Errno::Eperm.as_i32() as i64)) };
    }
    Err(-(EOPNOTSUPP as i64))
}

/// `trusted.*` xattrs are invisible to a task without CAP_SYS_ADMIN
/// (Linux): a read reports ENODATA as if absent.
/// # C: O(1)
fn read_hidden(name: &str) -> bool {
    if name.starts_with("trusted.") {
        let (_, sys_admin, _, _) = cred_snapshot();
        return !sys_admin;
    }
    false
}

fn read_user_cstr_owned(p: u64, max: usize) -> Result<String, i64> {
    if p == 0 || p >= hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: p validated < USER_VA_END; bounded read via existing helper.
    let bytes = unsafe { devfs::read_user_cstr(p, max) };
    let s = bytes.and_then(|b| core::str::from_utf8(b).ok())
        .ok_or(-(Errno::Einval.as_i32() as i64))?;
    Ok(String::from(s))
}

fn read_user_bytes(p: u64, len: usize) -> Result<Vec<u8>, i64> {
    if len == 0 { return Ok(Vec::new()); }
    if p == 0 || p >= hal::USER_VA_END
        || p.checked_add(len as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let mut out = alloc::vec![0u8; len];
    // SAFETY: p+len validated < USER_VA_END; CPL=0 byte reads through caller's AS into kernel-owned buffer.
    unsafe {
        for i in 0..len {
            out[i] = core::ptr::read_volatile((p + i as u64) as *const u8);
        }
    }
    Ok(out)
}

fn write_user_bytes(p: u64, src: &[u8]) -> Result<(), i64> {
    if src.is_empty() { return Ok(()); }
    if p == 0 || p >= hal::USER_VA_END
        || p.checked_add(src.len() as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: p+src.len() validated < USER_VA_END; CPL=0 byte writes through caller's AS, src is kernel-owned.
    unsafe {
        for i in 0..src.len() {
            core::ptr::write_volatile((p + i as u64) as *mut u8, src[i]);
        }
    }
    Ok(())
}

fn do_set(inode: &InodeRef, name: String, value: Vec<u8>, flags: u32) -> i64 {
    // XATTR_CREATE | XATTR_REPLACE together is invalid (Linux EINVAL).
    if flags & XATTR_CREATE != 0 && flags & XATTR_REPLACE != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if let Err(rv) = check_name_len(&name) { return rv; }
    if value.len() > XATTR_SIZE_MAX { return -(Errno::E2big.as_i32() as i64); }
    if let Err(rv) = check_write_perm(inode, &name) { return rv; }
    let create  = flags & XATTR_CREATE  != 0;
    let replace = flags & XATTR_REPLACE != 0;
    match inode.setxattr(&name, value, create, replace) {
        Ok(())                    => 0,
        Err(XattrError::Exists)   => -(EEXIST as i64),
        Err(XattrError::NotFound) => -(ENODATA as i64),
        Err(XattrError::NotSup)   => -(EOPNOTSUPP as i64),
    }
}

fn do_get(inode: &InodeRef, name: &str, buf_p: u64, buflen: usize) -> i64 {
    if let Err(rv) = check_name_len(name) { return rv; }
    if read_hidden(name) { return -(ENODATA as i64); }
    let val = match inode.getxattr(name) {
        Ok(v)                    => v,
        Err(XattrError::NotFound) => return -(ENODATA as i64),
        Err(XattrError::NotSup)   => return -(EOPNOTSUPP as i64),
        Err(XattrError::Exists)   => return -(EOPNOTSUPP as i64),
    };
    let want = val.len();
    if buflen == 0 { return want as i64; }
    if buflen < want { return -(Errno::Erange.as_i32() as i64); }
    if let Err(rv) = write_user_bytes(buf_p, &val) { return rv; }
    want as i64
}

fn do_list(inode: &InodeRef, buf_p: u64, buflen: usize) -> i64 {
    // Hide trusted.* names from a task lacking CAP_SYS_ADMIN (Linux).
    let names: Vec<String> = match inode.listxattr() {
        Ok(ns) => ns.into_iter().filter(|n| !read_hidden(n)).collect(),
        Err(XattrError::NotSup) => return -(EOPNOTSUPP as i64),
        Err(XattrError::NotFound) | Err(XattrError::Exists) => return -(EOPNOTSUPP as i64),
    };
    let mut total = 0usize;
    for n in &names { total += n.len() + 1; }
    if buflen == 0 { return total as i64; }
    if buflen < total { return -(Errno::Erange.as_i32() as i64); }
    let mut tmp = Vec::with_capacity(total);
    for n in &names { tmp.extend_from_slice(n.as_bytes()); tmp.push(0); }
    if let Err(rv) = write_user_bytes(buf_p, &tmp) { return rv; }
    total as i64
}

fn do_remove(inode: &InodeRef, name: &str) -> i64 {
    if let Err(rv) = check_name_len(name) { return rv; }
    if let Err(rv) = check_write_perm(inode, name) { return rv; }
    match inode.removexattr(name) {
        Ok(())                    => 0,
        Err(XattrError::NotFound) => -(ENODATA as i64),
        Err(XattrError::NotSup)   => -(EOPNOTSUPP as i64),
        Err(XattrError::Exists)   => -(EOPNOTSUPP as i64),
    }
}

/// Kernel-side xattr query (no user-buffer hop). Returns the value's
/// length, or 0 if absent. Used by F103 file-cap probe at execve.
/// # C: O(log N)
pub fn query_len(inode: &InodeRef, name: &str) -> usize {
    inode.getxattr(name).map(|v| v.len()).unwrap_or(0)
}

/// Kernel-side xattr read into a buffer. Returns true on hit.
/// # C: O(log N) + O(value len)
pub fn query_into(inode: &InodeRef, name: &str, buf: &mut [u8]) -> bool {
    let v = match inode.getxattr(name) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let n = v.len().min(buf.len());
    buf[..n].copy_from_slice(&v[..n]);
    true
}

/// setxattr work — read name + value, set on `inode`.
/// # C: O(N_xattrs)
pub fn setxattr_on(inode: &InodeRef, name_ptr: u64, value_ptr: u64, size: usize, flags: u32) -> i64 {
    let name  = match read_user_cstr_owned(name_ptr, 256) { Ok(s) => s, Err(rv) => return rv };
    let value = match read_user_bytes(value_ptr, size) { Ok(v) => v, Err(rv) => return rv };
    do_set(inode, name, value, flags)
}

/// getxattr work — read xattr value into `buf_ptr`.
/// # C: O(N_xattrs)
pub fn getxattr_on(inode: &InodeRef, name_ptr: u64, buf_ptr: u64, size: usize) -> i64 {
    let name = match read_user_cstr_owned(name_ptr, 256) { Ok(s) => s, Err(rv) => return rv };
    do_get(inode, &name, buf_ptr, size)
}

/// listxattr work — list names into `buf_ptr`.
/// # C: O(N_xattrs)
pub fn listxattr_on(inode: &InodeRef, buf_ptr: u64, size: usize) -> i64 {
    do_list(inode, buf_ptr, size)
}

/// removexattr work — read name, remove from `inode`.
/// # C: O(N_xattrs)
pub fn removexattr_on(inode: &InodeRef, name_ptr: u64) -> i64 {
    let name = match read_user_cstr_owned(name_ptr, 256) { Ok(s) => s, Err(rv) => return rv };
    do_remove(inode, &name)
}

// --- *xattrat (slots 463-466): the dirfd-relative xattr family (Linux 6.13).
// The path/dirfd resolution happens in the syscall shim (syscalls crate, which
// owns pathresolve); these take the already-resolved inode + the user pointers.
// xattr_args (uapi): { __u64 value; __u32 size; __u32 flags; } = 16 bytes.

/// Read a `struct xattr_args` from user → (value_ptr, size, flags).
/// # C: O(1)
fn read_xattr_args(args_ptr: u64, args_size: usize) -> Result<(u64, u32, u32), i64> {
    if args_size < 16 { return Err(-(Errno::Einval.as_i32() as i64)); }
    let b = read_user_bytes(args_ptr, 16)?;
    let value = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let size  = u32::from_le_bytes(b[8..12].try_into().unwrap());
    let flags = u32::from_le_bytes(b[12..16].try_into().unwrap());
    Ok((value, size, flags))
}

/// setxattrat work — read xattr_args + name + value, set on `inode`.
/// # C: O(N_xattrs)
pub fn setxattrat_on(inode: &InodeRef, name_ptr: u64, args_ptr: u64, args_size: usize) -> i64 {
    let (value_ptr, size, flags) = match read_xattr_args(args_ptr, args_size) { Ok(t) => t, Err(e) => return e };
    setxattr_on(inode, name_ptr, value_ptr, size as usize, flags)
}

/// getxattrat work — read into xattr_args.value (size buffer).
/// # C: O(N_xattrs)
pub fn getxattrat_on(inode: &InodeRef, name_ptr: u64, args_ptr: u64, args_size: usize) -> i64 {
    let (value_ptr, size, _flags) = match read_xattr_args(args_ptr, args_size) { Ok(t) => t, Err(e) => return e };
    getxattr_on(inode, name_ptr, value_ptr, size as usize)
}

/// listxattrat work — list names into xattr_args.value (size buffer). No name arg.
/// # C: O(N_xattrs)
pub fn listxattrat_on(inode: &InodeRef, args_ptr: u64, args_size: usize) -> i64 {
    let (value_ptr, size, _flags) = match read_xattr_args(args_ptr, args_size) { Ok(t) => t, Err(e) => return e };
    listxattr_on(inode, value_ptr, size as usize)
}

/// removexattrat work — remove `name`. No xattr_args.
/// # C: O(N_xattrs)
pub fn removexattrat_on(inode: &InodeRef, name_ptr: u64) -> i64 {
    removexattr_on(inode, name_ptr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inode(with_xattrs: bool) -> InodeRef {
        let b = vfs::InodeBuilder::new(
            1,
            vfs::mk_mode(vfs::FileType::Regular, 0o644),
            vfs::default_inode_ops(),
            vfs::default_file_ops(),
        );
        if with_xattrs { b.xattrs(vfs::SimpleXattrs::new()).build() } else { b.build() }
    }

    #[test]
    fn unsupported_fs_reports_eopnotsupp_without_fallback_store() {
        let i = inode(false);
        assert_eq!(do_set(&i, String::from("user.a"), alloc::vec![1], 0), -(EOPNOTSUPP as i64));
        assert_eq!(do_get(&i, "user.a", 0, 0), -(EOPNOTSUPP as i64));
        assert_eq!(do_list(&i, 0, 0), -(EOPNOTSUPP as i64));
        assert_eq!(do_remove(&i, "user.a"), -(EOPNOTSUPP as i64));
    }

    #[test]
    fn fs_owned_xattrs_still_round_trip_without_user_buffer_write() {
        let i = inode(true);
        assert_eq!(do_set(&i, String::from("user.a"), alloc::vec![1, 2, 3], 0), 0);
        assert_eq!(do_get(&i, "user.a", 0, 0), 3);
        assert_eq!(do_list(&i, 0, 0), 7);
        assert_eq!(query_len(&i, "user.a"), 3);
        assert_eq!(do_remove(&i, "user.a"), 0);
        assert_eq!(do_get(&i, "user.a", 0, 0), -(ENODATA as i64));
    }
}
