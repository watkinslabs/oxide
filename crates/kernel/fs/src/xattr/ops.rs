// The `vfs_{set,get,list,remove}xattr` work-fns: policy (`super::policy`) then
// STORAGE through the owning filesystem's `i_op` xattr hooks
// (`vfs::xattr::SimpleXattrs`). No user-buffer access here, so hosted tests
// drive these against real tmpfs/ext4 inodes.
//
// Each fs OWNS its xattrs (D45): tmpfs keeps `SimpleXattrs` in memory, ext4
// writes the same set through to the on-disk ibody / external xattr block.
// A filesystem with no store reports `EOPNOTSUPP` — except for listxattr,
// which Linux answers with an empty list (`vfs_listxattr` has no `i_op` hook to
// call and returns 0).

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::xattr::XattrError;
use vfs::InodeRef;

use super::acl;
use super::policy::{cap_remove_gate, cap_set_gate, err, list_payload, resolve_name,
                    xattr_permission, XattrCred, XATTR_CREATE, XATTR_REPLACE};

/// Storage-backend outcome → negative errno. `ENODATA` (61) has no `VfsError`
/// variant, hence the dedicated mapping. # C: O(1)
pub fn xattr_errno(e: XattrError) -> i64 {
    match e {
        XattrError::Exists   => err(Errno::Eexist),
        XattrError::NotFound => err(Errno::Enodata),
        XattrError::NotSup   => err(Errno::Eopnotsupp),
        XattrError::Fs(e)    => -(e as i32 as i64),
    }
}

/// `vfs_setxattr` (with `do_setxattr`'s POSIX-ACL detour). Flag/name/size
/// validation already happened at import time, matching `setxattr_copy`, which
/// Linux runs BEFORE path resolution. # C: O(N_xattr) + backend I/O
pub fn vfs_setxattr(inode: &InodeRef, name: &str, value: Vec<u8>, flags: u32, c: &XattrCred)
    -> Result<(), i64>
{
    if acl::is_acl_name(name) { return acl::set_acl(inode, name, value, c); }
    cap_set_gate(name, &value, c)?;
    xattr_permission(inode, name, vfs::MAY_WRITE, c)?;
    resolve_name(name)?;
    inode.setxattr(name, value, flags & XATTR_CREATE != 0, flags & XATTR_REPLACE != 0)
        .map_err(xattr_errno)?;
    notify_xattr(inode);
    Ok(())
}

/// `fsnotify_xattr` — a committed xattr change is an ATTRIB event on the
/// object, exactly like chmod/chown. # C: O(N_groups * N_watches)
pub(super) fn notify_xattr(inode: &InodeRef) { crate::inotify::fire_attrib(inode); }

/// `vfs_getxattr`. An absent attribute is `ENODATA`, never `ENOENT`; an empty
/// value is a legal, DISTINCT result from absent. # C: O(N_xattr)
pub fn vfs_getxattr(inode: &InodeRef, name: &str, c: &XattrCred) -> Result<Vec<u8>, i64> {
    // POSIX ACLs bypass `xattr_permission` entirely (`do_get_acl`).
    if !acl::is_acl_name(name) {
        xattr_permission(inode, name, vfs::MAY_READ, c)?;
        resolve_name(name)?;
    }
    inode.getxattr(name).map_err(xattr_errno)
}

/// `vfs_listxattr` — no permission check (Linux consults only the LSM), and no
/// `i_op->listxattr` means an EMPTY list rather than an error. `trusted.*`
/// names are hidden from a caller without CAP_SYS_ADMIN. # C: O(N_xattr)
pub fn vfs_listxattr(inode: &InodeRef, c: &XattrCred) -> Result<Vec<u8>, i64> {
    let names: Vec<String> = match inode.listxattr() {
        Ok(ns) => ns,
        Err(XattrError::NotSup) => Vec::new(),
        Err(e) => return Err(xattr_errno(e)),
    };
    Ok(list_payload(&names, c.sys_admin))
}

/// `vfs_removexattr` (with `removexattr`'s POSIX-ACL detour). Removing an
/// absent attribute is `ENODATA`. # C: O(N_xattr) + backend I/O
pub fn vfs_removexattr(inode: &InodeRef, name: &str, c: &XattrCred) -> Result<(), i64> {
    if acl::is_acl_name(name) { return acl::remove_acl(inode, name, c); }
    xattr_permission(inode, name, vfs::MAY_WRITE, c)?;
    cap_remove_gate(name, c)?;
    resolve_name(name)?;
    inode.removexattr(name).map_err(xattr_errno)?;
    notify_xattr(inode);
    Ok(())
}

/// Kernel-side xattr query (no user-buffer hop, no permission check — Linux
/// `__vfs_getxattr`). Returns the value's length, or 0 if absent. Used by the
/// F103 file-capability probe at execve. # C: O(log N)
pub fn query_len(inode: &InodeRef, name: &str) -> usize {
    inode.getxattr(name).map(|v| v.len()).unwrap_or(0)
}

/// Kernel-side xattr read into a buffer. Returns true on hit. # C: O(log N)
pub fn query_into(inode: &InodeRef, name: &str, buf: &mut [u8]) -> bool {
    let v = match inode.getxattr(name) { Ok(v) => v, Err(_) => return false };
    let n = v.len().min(buf.len());
    buf[..n].copy_from_slice(&v[..n]);
    true
}
