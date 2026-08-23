// Resolving one inode's label from the object's own state.

extern crate alloc;

use alloc::string::{String, ToString};

use selinux_runtime::inode::{existing_inode_sid, new_inode_sid, MountOptions, SuperblockSecurity};
use selinux_runtime::label::{inode_class, XATTR_NAME_SELINUX};

use vfs::InodeRef;

/// Filesystem type name of the inode's mount. # C: O(1)
fn fstype(inode: &InodeRef) -> Option<String> {
    inode.i_sb().map(|sb| sb.s_type.name().to_string())
}

/// The written label an inode carries, if it carries one. # C: O(xattrs)
///
/// A value with a trailing NUL is the same label as one without: userspace
/// writes the terminator with the string, and comparing the two forms as
/// different labels would make a file relabelled by one tool unreadable to the
/// rules written for the other.
fn written_label(inode: &InodeRef) -> Option<String> {
    let raw = inode.getxattr(XATTR_NAME_SELINUX).ok()?;
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    core::str::from_utf8(&raw[..end]).ok().map(ToString::to_string)
}

/// Labelling decision of the inode's mount. # C: O(fs_use entries)
///
/// Recomputed from the policy and the filesystem type rather than stored
/// beside the mount: the superblock has no slot for it yet, and a table here
/// keyed by superblock identity would be a second owner of mount state that
/// could outlive the mount and disagree with it.
pub fn superblock_security(srv: &mut selinux::SecurityServer, fstype: &str)
    -> SuperblockSecurity
{
    selinux_runtime::inode::superblock_security(srv, fstype, &MountOptions::default())
}

/// The inode's label, resolving and caching it on first use. # C: O(xattrs)
///
/// `None` while the module has no policy: there is no label to compute before
/// one is loaded, and inventing one would have to be undone on load.
pub fn inode_sid(inode: &InodeRef) -> Option<u32> {
    let seq = selinux_runtime::policy_seq();
    if let Some(sid) = inode.security_sid_at(seq) { return Some(sid); }
    if !selinux_runtime::active() { return None; }
    let superblock = inode.i_sb()?;
    let fstype = fstype(inode)?;
    let class = inode_class(inode.i_mode() as u32)?;
    let written = written_label(inode);
    let task = selinux_runtime::task::current_sid();
    let sid = selinux_runtime::with(|s| {
        let sb = superblock.security_as::<SuperblockSecurity>()
            .unwrap_or_else(|| alloc::sync::Arc::new(superblock_security(s, &fstype)));
        if superblock.s_root_inode().is_some_and(|root| alloc::sync::Arc::ptr_eq(&root, inode)) {
            if let Some(root_sid) = sb.root_sid { return root_sid; }
        }
        existing_inode_sid(s, &sb, task, class, written.as_deref(), None)
    })?;
    inode.set_security_sid_at(sid, seq);
    Some(sid)
}

/// Label a newly created inode, from its creator and its parent directory.
/// # C: O(rules)
///
/// The NAME is passed through: a policy's filename rules are keyed by it, and
/// a caller that omits it gets the parent's ordinary transition instead of the
/// rule the policy actually wrote.
pub fn label_new_inode(dir: &InodeRef, inode: &InodeRef, name: &str) -> Option<u32> {
    if !selinux_runtime::active() { return None; }
    let seq = selinux_runtime::policy_seq();
    let fstype = fstype(inode).or_else(|| fstype(dir))?;
    let class = inode_class(inode.i_mode() as u32)?;
    let dir_sid = inode_sid(dir)?;
    let task = selinux_runtime::task::current_sid();
    let staged = selinux_runtime::task::fscreate_sid();
    let sid = selinux_runtime::with(|s| {
        let sb = inode.i_sb().and_then(|sb| sb.security_as::<SuperblockSecurity>())
            .unwrap_or_else(|| alloc::sync::Arc::new(superblock_security(s, &fstype)));
        new_inode_sid(s, &sb, staged, task, dir_sid, class, Some(name))
    })?;
    inode.set_security_sid_at(sid, seq);
    Some(sid)
}
