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
                    xattr_permission, XattrCred, SECURITY_PREFIX, XATTR_CREATE, XATTR_REPLACE};

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
    if acl::is_acl_name(name) {
        super::policy::lsm_set_gate(inode, name, &value)?;
        return acl::set_acl(inode, name, value, c);
    }
    cap_set_gate(name, &value, c)?;
    xattr_permission(inode, name, vfs::MAY_WRITE, c)?;
    // The label write is priced where the VALUE is known: which label the
    // object is moving to decides two of the three permissions it costs.
    super::policy::lsm_set_gate(inode, name, &value)?;
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
/// value is a legal, DISTINCT result from absent.
///
/// A `security.*` name is answered by the label module FIRST and only reaches
/// the filesystem's store if no module claims it (`lsm_declined`). That order is
/// the contract: the live label is kernel state, the stored attribute is where
/// it was last persisted, and the two differ on every object whose label was
/// computed rather than written — every device node, pipe and socket, and every
/// file on a mount that cannot store attributes at all.
/// # C: O(N_xattr)
pub fn vfs_getxattr(inode: &InodeRef, name: &str, c: &XattrCred) -> Result<Vec<u8>, i64> {
    // POSIX ACLs bypass `xattr_permission` entirely (`do_get_acl`).
    if acl::is_acl_name(name) {
        if inode.i_sb().is_some_and(|sb| !sb.is_posixacl()) { return Err(err(Errno::Eopnotsupp)); }
        super::policy::lsm_read_gate(inode, name, vfs::MAY_READ)?;
        return inode.getxattr(name).map_err(xattr_errno);
    }
    xattr_permission(inode, name, vfs::MAY_READ, c)?;
    if let Some(suffix) = name.strip_prefix(SECURITY_PREFIX) {
        match crate::selinux::inode_getsecurity(inode, suffix) {
            Err(rv) if lsm_declined(rv) => {}
            answer => return answer,
        }
    }
    resolve_name(name)?;
    inode.getxattr(name).map_err(xattr_errno)
}

/// Whether a `security.*` read falls through to the filesystem's own store.
///
/// `EOPNOTSUPP` is the ONE answer that means "no module owns this attribute";
/// every other error is a real answer about a claimed attribute and must not be
/// papered over with whatever the disk holds. # C: O(1)
pub fn lsm_declined(rv: i64) -> bool { rv == err(Errno::Eopnotsupp) }

/// `vfs_listxattr` — no permission check (Linux consults only the LSM), and no
/// `i_op->listxattr` means an EMPTY list rather than an error. `trusted.*`
/// names are hidden from a caller without CAP_SYS_ADMIN. # C: O(N_xattr)
pub fn vfs_listxattr(inode: &InodeRef, c: &XattrCred) -> Result<Vec<u8>, i64> {
    super::policy::lsm_list_gate(inode)?;
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
    if acl::is_acl_name(name) {
        super::policy::lsm_remove_gate(inode, name)?;
        return acl::remove_acl(inode, name, c);
    }
    xattr_permission(inode, name, vfs::MAY_WRITE, c)?;
    cap_remove_gate(name, c)?;
    super::policy::lsm_remove_gate(inode, name)?;
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
