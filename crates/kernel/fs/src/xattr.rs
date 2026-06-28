// Per-inode xattr (extended-attribute) overlay backed by a global
// BTreeMap keyed by inode pointer identity (same identity scheme as
// `inode_times`). Replaces the ENOTSUP stub for the xattr family
// with a real round-trip: programs (tar/rsync/cp -a, getfattr/setfattr,
// SELinux/POSIX-ACL/cap-bit consumers) now see the values they wrote.
//
// v1 limit: in-memory overlay only. ext4-on-disk xattr storage rides
// v2 phase 26.
//
// Linux semantics honoured:
//   * setxattr flags: XATTR_CREATE (1) — fail with EEXIST if name already
//     exists; XATTR_REPLACE (2) — fail with ENODATA if name absent.
//     Both clear → unconditional set.
//   * getxattr returns the value's length when buflen=0 (probe pattern).
//   * listxattr writes NUL-separated names; returns total length when
//     buflen=0.
//   * removexattr returns ENODATA if name absent.


use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

const ENODATA: i32 = 61;
const EEXIST:  i32 = 17;
const EOPNOTSUPP: i32 = 95;

pub const XATTR_CREATE:  u32 = 1;
pub const XATTR_REPLACE: u32 = 2;

/// Linux XATTR_NAME_MAX (255) / XATTR_SIZE_MAX (64 KiB).
const XATTR_NAME_MAX: usize = 255;
const XATTR_SIZE_MAX: usize = 65536;

#[derive(Default)]
struct InodeXattrs(BTreeMap<String, Vec<u8>>);

/// Keyed by `(fsid, ino)` — a STABLE filesystem identity. The old
/// Arc-pointer-address key leaked xattrs to an unrelated file when an
/// inode Arc was freed and its address reused.
static TABLE: Spinlock<BTreeMap<(u64, u64), InodeXattrs>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

fn inode_key(inode: &InodeRef) -> (u64, u64) {
    (inode.fsid(), inode.ino())
}

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

fn resolve_path_inode(p: u64) -> Result<InodeRef, i64> {
    if p == 0 || p >= hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: p in user range; bounded read via existing helper.
    let bytes = unsafe { devfs::read_user_cstr(p, 256) };
    let s = bytes.and_then(|b| if b.is_empty() { None } else { core::str::from_utf8(b).ok() })
        .ok_or(-(Errno::Einval.as_i32() as i64))?;
    let resolved = if s.starts_with('/') {
        vfs::path::lexical_normalize(s).unwrap_or_else(|| s.into())
    } else if let Some(cur) = sched::current() {
        // SAFETY: current task is the sole writer of its cwd slot on this CPU.
        let cwd = unsafe { (*cur.cwd.get()).clone() };
        vfs::path::resolve_against_cwd(&cwd, s).unwrap_or_else(|| s.into())
    } else {
        s.into()
    };
    vfs::mount::lookup(&resolved).map_err(|_| -(Errno::Enoent.as_i32() as i64))
}

fn resolve_fd_inode(fd: i32) -> Result<InodeRef, i64> {
    let cur = sched::current().ok_or(-(Errno::Ebadf.as_i32() as i64))?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(-(Errno::Ebadf.as_i32() as i64))?.clone();
    let f = fdt.get(fd).map_err(|_| -(Errno::Ebadf.as_i32() as i64))?;
    Ok(f.inode().clone())
}

fn do_set(inode: &InodeRef, name: String, value: Vec<u8>, flags: u32) -> i64 {
    // XATTR_CREATE | XATTR_REPLACE together is invalid (Linux EINVAL).
    if flags & XATTR_CREATE != 0 && flags & XATTR_REPLACE != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if let Err(rv) = check_name_len(&name) { return rv; }
    if value.len() > XATTR_SIZE_MAX { return -(Errno::E2big.as_i32() as i64); }
    if let Err(rv) = check_write_perm(inode, &name) { return rv; }
    let k = inode_key(inode);
    let mut g = TABLE.lock();
    let entry = g.entry(k).or_insert_with(InodeXattrs::default);
    let exists = entry.0.contains_key(&name);
    if flags & XATTR_CREATE  != 0 && exists  { return -(EEXIST as i64); }
    if flags & XATTR_REPLACE != 0 && !exists { return -(ENODATA as i64); }
    entry.0.insert(name, value);
    0
}

fn do_get(inode: &InodeRef, name: &str, buf_p: u64, buflen: usize) -> i64 {
    if let Err(rv) = check_name_len(name) { return rv; }
    if read_hidden(name) { return -(ENODATA as i64); }
    let g = TABLE.lock();
    let entry = match g.get(&inode_key(inode)) {
        Some(e) => e, None => return -(ENODATA as i64),
    };
    let val = match entry.0.get(name) {
        Some(v) => v, None => return -(ENODATA as i64),
    };
    let want = val.len();
    if buflen == 0 { return want as i64; }
    if buflen < want { return -(Errno::Erange.as_i32() as i64); }
    if let Err(rv) = write_user_bytes(buf_p, val) { return rv; }
    want as i64
}

fn do_list(inode: &InodeRef, buf_p: u64, buflen: usize) -> i64 {
    let g = TABLE.lock();
    // Hide trusted.* names from a task lacking CAP_SYS_ADMIN (Linux).
    let names: Vec<&String> = match g.get(&inode_key(inode)) {
        Some(e) => e.0.keys().filter(|n| !read_hidden(n)).collect(),
        None    => return 0,
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
    let mut g = TABLE.lock();
    let entry = match g.get_mut(&inode_key(inode)) {
        Some(e) => e, None => return -(ENODATA as i64),
    };
    if entry.0.remove(name).is_some() { 0 } else { -(ENODATA as i64) }
}

/// Kernel-side xattr query (no user-buffer hop). Returns the value's
/// length, or 0 if absent. Used by F103 file-cap probe at execve.
/// # C: O(log N)
pub fn query_len(inode: &InodeRef, name: &str) -> usize {
    let g = TABLE.lock();
    g.get(&inode_key(inode))
        .and_then(|e| e.0.get(name))
        .map(|v| v.len())
        .unwrap_or(0)
}

/// Kernel-side xattr read into a buffer. Returns true on hit.
/// # C: O(log N) + O(value len)
pub fn query_into(inode: &InodeRef, name: &str, buf: &mut [u8]) -> bool {
    let g = TABLE.lock();
    let v = match g.get(&inode_key(inode)).and_then(|e| e.0.get(name)) {
        Some(v) => v, None => return false,
    };
    let n = v.len().min(buf.len());
    buf[..n].copy_from_slice(&v[..n]);
    true
}

/// `sys_setxattr / lsetxattr` (slots 188/189). path / name / value / size / flags.
/// # C: O(N_xattrs)
pub fn sys_setxattr(args: &SyscallArgs) -> i64 {
    let inode = match resolve_path_inode(args.a0) { Ok(i) => i, Err(rv) => return rv };
    let name  = match read_user_cstr_owned(args.a1, 256) { Ok(s) => s, Err(rv) => return rv };
    let value = match read_user_bytes(args.a2, args.a3 as usize) { Ok(v) => v, Err(rv) => return rv };
    do_set(&inode, name, value, args.a4 as u32)
}

/// `sys_fsetxattr` (slot 190). fd / name / value / size / flags. 
/// # C: O(N_xattrs)
pub fn sys_fsetxattr(args: &SyscallArgs) -> i64 {
    let inode = match resolve_fd_inode(args.a0 as i32) { Ok(i) => i, Err(rv) => return rv };
    let name  = match read_user_cstr_owned(args.a1, 256) { Ok(s) => s, Err(rv) => return rv };
    let value = match read_user_bytes(args.a2, args.a3 as usize) { Ok(v) => v, Err(rv) => return rv };
    do_set(&inode, name, value, args.a4 as u32)
}

/// `sys_getxattr / lgetxattr` (slots 191/192). path / name / value / size.
/// # C: O(N_xattrs)
pub fn sys_getxattr(args: &SyscallArgs) -> i64 {
    let inode = match resolve_path_inode(args.a0) { Ok(i) => i, Err(rv) => return rv };
    let name  = match read_user_cstr_owned(args.a1, 256) { Ok(s) => s, Err(rv) => return rv };
    do_get(&inode, &name, args.a2, args.a3 as usize)
}

/// `sys_fgetxattr` (slot 193). fd / name / value / size.
/// # C: O(N_xattrs)
pub fn sys_fgetxattr(args: &SyscallArgs) -> i64 {
    let inode = match resolve_fd_inode(args.a0 as i32) { Ok(i) => i, Err(rv) => return rv };
    let name  = match read_user_cstr_owned(args.a1, 256) { Ok(s) => s, Err(rv) => return rv };
    do_get(&inode, &name, args.a2, args.a3 as usize)
}

/// `sys_listxattr / llistxattr` (slots 194/195). path / list / size.
/// # C: O(N_xattrs)
pub fn sys_listxattr(args: &SyscallArgs) -> i64 {
    let inode = match resolve_path_inode(args.a0) { Ok(i) => i, Err(rv) => return rv };
    do_list(&inode, args.a1, args.a2 as usize)
}

/// `sys_flistxattr` (slot 196). fd / list / size.
/// # C: O(N_xattrs)
pub fn sys_flistxattr(args: &SyscallArgs) -> i64 {
    let inode = match resolve_fd_inode(args.a0 as i32) { Ok(i) => i, Err(rv) => return rv };
    do_list(&inode, args.a1, args.a2 as usize)
}

/// `sys_removexattr / lremovexattr` (slots 197/198). path / name.
/// # C: O(N_xattrs)
pub fn sys_removexattr(args: &SyscallArgs) -> i64 {
    let inode = match resolve_path_inode(args.a0) { Ok(i) => i, Err(rv) => return rv };
    let name  = match read_user_cstr_owned(args.a1, 256) { Ok(s) => s, Err(rv) => return rv };
    do_remove(&inode, &name)
}

/// `sys_fremovexattr` (slot 199). fd / name.
/// # C: O(N_xattrs)
pub fn sys_fremovexattr(args: &SyscallArgs) -> i64 {
    let inode = match resolve_fd_inode(args.a0 as i32) { Ok(i) => i, Err(rv) => return rv };
    let name  = match read_user_cstr_owned(args.a1, 256) { Ok(s) => s, Err(rv) => return rv };
    do_remove(&inode, &name)
}

/// Single-arm dispatch helper for syscall_glue.rs. Returns None if
/// `nr` is not an xattr slot.
/// # C: O(1)
pub fn xattr_dispatch(nr: u64, args: &SyscallArgs) -> Option<i64> {
    use syscall::nrs::*;
    let rv = match nr {
        NR_SETXATTR | NR_LSETXATTR  => sys_setxattr(args),
        NR_FSETXATTR                => sys_fsetxattr(args),
        NR_GETXATTR | NR_LGETXATTR  => sys_getxattr(args),
        NR_FGETXATTR                => sys_fgetxattr(args),
        NR_LISTXATTR | NR_LLISTXATTR => sys_listxattr(args),
        NR_FLISTXATTR               => sys_flistxattr(args),
        NR_REMOVEXATTR | NR_LREMOVEXATTR => sys_removexattr(args),
        NR_FREMOVEXATTR             => sys_fremovexattr(args),
        _ => return None,
    };
    Some(rv)
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
    let name  = match read_user_cstr_owned(name_ptr, 256) { Ok(s) => s, Err(rv) => return rv };
    let value = match read_user_bytes(value_ptr, size as usize) { Ok(v) => v, Err(rv) => return rv };
    do_set(inode, name, value, flags)
}

/// getxattrat work — read into xattr_args.value (size buffer).
/// # C: O(N_xattrs)
pub fn getxattrat_on(inode: &InodeRef, name_ptr: u64, args_ptr: u64, args_size: usize) -> i64 {
    let (value_ptr, size, _flags) = match read_xattr_args(args_ptr, args_size) { Ok(t) => t, Err(e) => return e };
    let name = match read_user_cstr_owned(name_ptr, 256) { Ok(s) => s, Err(rv) => return rv };
    do_get(inode, &name, value_ptr, size as usize)
}

/// listxattrat work — list names into xattr_args.value (size buffer). No name arg.
/// # C: O(N_xattrs)
pub fn listxattrat_on(inode: &InodeRef, args_ptr: u64, args_size: usize) -> i64 {
    let (value_ptr, size, _flags) = match read_xattr_args(args_ptr, args_size) { Ok(t) => t, Err(e) => return e };
    do_list(inode, value_ptr, size as usize)
}

/// removexattrat work — remove `name`. No xattr_args.
/// # C: O(N_xattrs)
pub fn removexattrat_on(inode: &InodeRef, name_ptr: u64) -> i64 {
    let name = match read_user_cstr_owned(name_ptr, 256) { Ok(s) => s, Err(rv) => return rv };
    do_remove(inode, &name)
}
