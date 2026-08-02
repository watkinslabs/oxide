//! Creating a name in a directory, as one operation.
//!
//! Linux `vfs_create` is inseparable from `d_instantiate`: the backend makes
//! the object and the same call publishes it under the negative dentry the
//! lookup left behind. Anything that creates through the directory inode alone
//! leaves that negative in place, and every later lookup of the name reports
//! `ENOENT` for an object that is sitting in the directory.
//!
//! Every in-kernel creator goes through here so there is one place that
//! sequence lives, and no caller has to remember to repair the cache after the
//! fact.

use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::inode_ops::CreateCtx;
use crate::types::KResult;

use super::may_create::may_create;
use super::types::VfsPath;

/// Create `name` in `dir` and publish it.
///
/// The permission gate, the directory lock the backend runs under, the cache
/// publication and the notification are one unit: a caller cannot take the
/// object without the name being reachable.
/// # C: O(1) + backend create
pub fn vfs_create_at(dir: &VfsPath, name: &str, mode: u32, ctx: &CreateCtx<'_>)
    -> KResult<(InodeRef, Arc<Dentry>)>
{
    may_create(&dir.inode, ctx.cred)?;
    // The parent's `i_rwsem` is held EXCLUSIVE across the backend create, so a
    // second creator of the same name sees the first one's entry.
    let inode = { let _g = dir.inode.inode_lock(); dir.inode.create_child(name, mode, ctx)? };
    let dentry = publish(dir, name, &inode);
    Ok((inode, dentry))
}

/// `d_instantiate` for a freshly created object: splice it onto the negative
/// dentry the lookup left, or add a new one.
///
/// The extra `d_drop_child` is this tree's existing behaviour on the open
/// path — it forces the next lookup through the backend rather than trusting
/// the dentry just built. Kept identical here so moving the open path onto
/// this owner changes nothing about what it does.
/// # C: O(1)
fn publish(dir: &VfsPath, name: &str, inode: &InodeRef) -> Arc<Dentry> {
    let d = crate::file::open_dentry_at(&dir.dentry, name, inode);
    crate::dcache::d_drop_child(&dir.dentry, name);
    crate::file::fire_dirent_create(&dir.inode, name, false);
    d
}
