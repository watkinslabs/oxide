//! What a create DECIDES before the volume writes anything, and the rewrite a
//! `chmod` owes the ACL afterwards.
//!
//! Three steps in one order, which is the order the decisions compose in: the
//! owner ids and the mode a new object may carry, then the permission bits its
//! parent's default ACL folds into that mode, then the records to store on the
//! object once it exists. Kept out of `ops` because each one reads or writes an
//! attribute region the size of a block, and a create already spends most of the
//! kernel stack on the write path below it.

use vfs::{CreateCtx, FileType, Inode, KResult};

use syscall::errno::Errno;

use super::node::F2fsNode;
use super::ops::F2fsOps;
use super::errno_to_vfs;

/// `vfs_prepare_mode` + `inode_init_owner`: the owner ids a new object is
/// recorded with, and the mode the default ACL is then folded into.
///
/// It runs BEFORE the ACL work because the two decisions compose in one
/// direction only — a set-group-id directory decides the new object's group
/// and (for a directory) re-adds the set-group-id bit, the per-kind clamp
/// drops bits the caller may not set, and only then does the parent's
/// default ACL decide the permission bits. The umask is left to that step,
/// so a zero one is passed here: a parent carrying a default ACL overrides
/// the umask entirely.
///
/// `mask_perms` per kind: a directory may keep the sticky bit and nothing
/// else above the nine permission bits, a regular file may keep all of
/// them, and a device/FIFO/socket node is bounded by the mode it was asked
/// for. A symlink is exempt from all of it and takes only its owner ids.
/// # C: O(1)
pub(super) fn owner_mode(dir: &Inode, ftype: FileType, mode: u16, ctx: &CreateCtx) -> (u32, u32, u16) {
    if ftype == FileType::Symlink {
        let (uid, gid) = vfs::prepare_symlink_owner(ctx.idmap, dir, ctx.cred);
        return (uid, gid, mode);
    }
    let (mask_perms, type_bits) = match ftype {
        FileType::Directory => (vfs::types::S_IRWXUGO | vfs::types::S_ISVTX, vfs::types::S_IFDIR),
        FileType::Regular   => (vfs::S_IALLUGO, vfs::types::S_IFREG),
        // A `mknod` mode carries its own type, and bounds itself.
        _                   => (mode, mode),
    };
    let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, dir, mode, mask_perms,
                                                      type_bits, ctx.cred, 0);
    (uid, gid, m)
}

/// The parent's default ACL, folded with the requested mode and the umask
/// into what the new object gets.
///
/// Kept out of line: the attribute region it reads is assembled in a buffer
/// the size of a block, and a create already spends most of the kernel stack
/// on the write path below it. # C: O(region bytes)
#[inline(never)]
pub(super) fn inherited(node: &F2fsNode, dir: &crate::Inode, perm: u16, umask: u16,
             kind: vfs::posix_acl::NewKind) -> KResult<crate::acl::Inherited> {
    let (enabled, parent) = {
        let v = node.fs.volume.lock();
        let enabled = v.options().acl;
        let parent = if enabled && kind != vfs::posix_acl::NewKind::Symlink {
            match v.get_xattr(dir, node.ino, crate::acl::name_default()) {
                Ok(bytes) => Some(bytes),
                Err(Errno::Enodata) | Err(Errno::Eopnotsupp) => None,
                Err(e) => return Err(errno_to_vfs(e)),
            }
        } else {
            None
        };
        (enabled, parent)
    };
    crate::acl::inherit(parent.as_deref(), perm, umask, kind, enabled).map_err(errno_to_vfs)
}

/// `posix_acl_chmod` — fold the new mode into this object's access ACL and
/// store it back.
///
/// An ACL that ends up saying exactly what the mode bits say is REMOVED
/// rather than stored: the mode alone then carries the whole answer, which
/// is the state `getfacl` reports as having no extended entries.
/// # C: O(N_entries) + one attribute write
pub(super) fn acl_chmod(inode: &Inode) -> KResult<()> {
    let mode = inode.perm().unwrap_or(0);
    let Some(entries) = inode.posix_acl_chmod(mode)? else { return Ok(()); };
    let mut folded = mode;
    let keep = vfs::posix_acl::equiv_mode(&entries, &mut folded).map_err(errno_to_vfs)?;
    let node = F2fsOps::node(inode)?;
    let record = if keep { Some(crate::acl::to_disk(&entries).map_err(errno_to_vfs)?) }
                 else { None };
    let name = crate::acl::name_access();
    let r = match &record {
        Some(bytes) => node.fs.volume_now().set_xattr(node.ino, name, Some(bytes), false, false),
        None => node.fs.volume_now().remove_xattr(node.ino, name),
    };
    match r {
        Ok(()) | Err(Errno::Enodata) => {}
        Err(e) => return Err(errno_to_vfs(e)),
    }
    inode.forget_cached_acl(vfs::posix_acl::AclType::Access);
    Ok(())
}

/// Put the inherited ACLs on the object once it exists, the default one
/// first. Out of line for the same reason as `inherited`. # C: O(region bytes)
#[inline(never)]
pub(super) fn store_inherited(node: &F2fsNode, ino: u32, got: &crate::acl::Inherited) -> KResult<()> {
    for (name, value) in [(crate::acl::name_default(), &got.default),
                          (crate::acl::name_access(),  &got.access)] {
        let Some(bytes) = value else { continue };
        node.fs.volume_now().set_xattr(ino, name, Some(bytes), false, false)
            .map_err(errno_to_vfs)?;
    }
    Ok(())
}
