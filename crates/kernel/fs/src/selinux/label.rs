// Resolving one inode's label from the object's own state.

extern crate alloc;

use alloc::string::{String, ToString};

use selinux::uapi::classmap::{class_by_name, perm_bit};
use selinux_runtime::inode::{existing_inode_sid, new_inode_sid, MountOptions, SuperblockSecurity};
use selinux_runtime::label::{inode_class, XATTR_NAME_SELINUX};

use vfs::{Dentry, InodeRef};

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
    let dentry = superblock.i_aliases(inode.ino()).into_iter().next();
    label_at(inode, dentry.as_deref(), seq, &fstype, &superblock, class)
}

/// Class selected for this inode, including secure anonymous classes. # C: O(1)
pub fn inode_security_class(inode: &InodeRef) -> Option<u16> {
    let seq = selinux_runtime::policy_seq();
    inode.security_class_at(seq).or_else(|| inode_class(inode.i_mode() as u32))
}

/// Initialize one Linux secure anonymous inode before publication. # C: O(rules)
pub fn inode_init_security_anon(inode: &InodeRef, name: &str,
                                context_inode: Option<&InodeRef>) -> vfs::KResult<()> {
    if !selinux_runtime::active() { return Ok(()); }
    let current = selinux_runtime::task::current_sid();
    let seq = selinux_runtime::policy_seq();
    if name == "[memfd]" && !selinux_runtime::with(|s| {
        s.policycap(selinux::uapi::policycap::POLICYDB_CAP_MEMFD_CLASS)
    }).unwrap_or(false) { return Ok(()); }
    let (class, sid) = if let Some(context) = context_inode {
        let sid = inode_sid(context).ok_or(vfs::VfsError::Eacces)?;
        let class = inode_security_class(context).ok_or(vfs::VfsError::Eacces)?;
        (class, sid)
    } else {
        let is_memfd = name == "[memfd]";
        let class_name = if is_memfd { "memfd_file" } else { "anon_inode" };
        let class = class_by_name(class_name).ok_or(vfs::VfsError::Eacces)?;
        let sid = selinux_runtime::with(|s| s.transition_sid(current, current, class, Some(name)).ok())
            .flatten().ok_or(vfs::VfsError::Eacces)?;
        (class, sid)
    };
    inode.set_security_sid_class_at(sid, class, seq);
    let create = perm_bit(class, "create").ok_or(vfs::VfsError::Eacces)?;
    selinux_runtime::check::has_perm(current, sid, class, create)
        .map_err(|_| vfs::VfsError::Eacces)
}

/// Resolve an inode with the dentry that supplied its genfs path. # C: O(paths + categories)
pub fn label_instantiated(dentry: &Dentry, inode: &InodeRef) {
    if !selinux_runtime::active() { return; }
    let Some(superblock) = inode.i_sb() else { return };
    let Some(fstype) = fstype(inode) else { return };
    let Some(class) = inode_class(inode.i_mode() as u32) else { return };
    let _ = label_at(inode, Some(dentry), selinux_runtime::policy_seq(), &fstype,
        &superblock, class);
}

fn label_at(inode: &InodeRef, dentry: Option<&Dentry>, seq: u32, fstype: &str,
    superblock: &alloc::sync::Arc<vfs::SuperBlock>, class: u16) -> Option<u32> {
    if inode.security_sid_at(seq).is_some() { return inode.security_sid_at(seq); }
    let written = written_label(inode);
    let task = selinux_runtime::task::current_sid();
    let path = dentry.map(|d| d.dentry_path(superblock.s_root().as_ref()));
    let sid = selinux_runtime::with(|s| {
        let sb = superblock.security_as::<SuperblockSecurity>()
            .unwrap_or_else(|| alloc::sync::Arc::new(superblock_security(s, fstype)));
        if superblock.s_root_inode().is_some_and(|root| alloc::sync::Arc::ptr_eq(&root, inode)) {
            if let Some(root_sid) = sb.root_sid { return root_sid; }
        }
        existing_inode_sid(s, &sb, task, class, written.as_deref(), path.as_deref())
    })?;
    inode.set_security_sid_class_at(sid, class, seq);
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
    inode.set_security_sid_class_at(sid, class, seq);
    Some(sid)
}
