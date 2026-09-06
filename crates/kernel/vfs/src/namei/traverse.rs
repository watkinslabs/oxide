extern crate alloc;
use alloc::borrow::Cow;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::{KResult, VfsError};

/// Negative-dentry caching safety gate for filesystem-backed directories.
/// # C: O(1)
pub(crate) fn neg_cache_ok(dir: &InodeRef, name: &str) -> bool {
    stable_negative_cache(dir) || dir.i_op().negative_dentry_ok(dir, name)
}

fn stable_negative_cache(dir: &InodeRef) -> bool {
    dir.i_sb().is_some_and(|sb| matches!(sb.s_type.name(), "ext4" | "tmpfs" | "ramfs"))
}

/// Whether a negative miss needs the bounded dynamic-filesystem recheck.
/// Stable filesystem implementations are ordered by the parent inode lock, so
/// their miss and negative publication are one lookup transaction.  An inode
/// operation that explicitly opts into negative dentries may instead have
/// namespace changes outside that ordinary VFS create path; retain one
/// backend recheck for that contract (the kernfs-style case).
/// # C: O(1)
pub(crate) fn neg_cache_recheck(dir: &InodeRef, name: &str) -> bool {
    !stable_negative_cache(dir) && dir.i_op().negative_dentry_ok(dir, name)
}

/// Follow stacked mountpoints DOWN from `d`: while `d` is a mountpoint, switch
/// to the mounted fs's `s_root` dentry (Linux `__follow_mount`). Returns the
/// final dentry, its inode, and the deepest crossed mount id. # C: O(stack)
pub(crate) fn follow_mount_down(mut d: Arc<Dentry>, mut mnt_id: u64) -> KResult<(Arc<Dentry>, InodeRef, u64)> {
    // [D24] Cross stacked mounts via the strict `(parent_mnt_id, dentry)` mount
    // hash (Linux `__lookup_mnt`): while a mount is attached on `d` whose PARENT
    // is the current mount `mnt_id`, switch to that child mount's root dentry and
    // adopt its id, looping for stacked overmounts. The parent-keyed hash is
    // ns-correct (every namespace mints ns-private mnt_ids), so the legacy
    // parent-agnostic `dentry.mounted_mounts` map is no longer consulted (deleted).
    while let Some(m) = crate::mount::__lookup_mnt(mnt_id, &d) {
        match m.mnt_root() {
            Some(sr) => { d = sr; mnt_id = m.mnt_id; }
            None => break,
        }
    }
    let inode = d.inode().ok_or(VfsError::Enoent)?;
    Ok((d, inode, mnt_id))
}

/// `..` step with `follow_dotdot` mount-crossing (Linux). Clamps at the
/// resolution root (`/.. == /`, chroot/BENEATH/IN_ROOT confinement). At a
/// mounted fs root that is not the resolution root, cross back to the
/// mountpoint in the parent mount (looping for stacked roots), THEN take the
/// normal parent step. Returns `true` when the step was an ESCAPE attempt —
/// `..` at the resolution root, which is clamped (held at root) here but which
/// `RESOLVE_BENEATH` (`beneath_exdev`) turns into `EXDEV`. # C: O(stack)
pub(crate) fn dotdot_step(
    cur_dentry: &mut Arc<Dentry>,
    cur_mnt: &mut u64,
    cur_inode: &mut InodeRef,
    root_dentry: &Arc<Dentry>,
    root_mnt: u64,
) -> bool {
    loop {
        if Arc::ptr_eq(cur_dentry, root_dentry) { return true; }
        if cur_dentry.is_root() && *cur_mnt != root_mnt {
            if let Some((mp, parent_mnt)) = crate::mount::mountpoint_of(*cur_mnt) {
                *cur_dentry = mp;
                *cur_mnt = parent_mnt;
                if let Some(i) = cur_dentry.inode() { *cur_inode = i; }
                continue;
            }
        }
        break;
    }
    if let Some(par) = cur_dentry.parent() {
        let par = par.clone();
        if let Some(pi) = par.inode() { *cur_inode = pi; *cur_dentry = par; }
    }
    false
}

/// One active Linux `nameidata` pathname frame. The frame owns its pathname,
/// but keeps the component cursor as a byte offset, so ordinary components are
/// borrowed directly from the pathname instead of becoming one heap `String`
/// each. Symlink targets create a new frame; the suspended remainder is kept
/// in the walker's frame stack just like Linux `nd->stack`. # C: O(1)
pub(crate) struct WalkFrame<'a> {
    pub(crate) path: Cow<'a, str>,
    pub(crate) pos: usize,
    next_component: Option<(usize, usize)>,
}

impl<'a> WalkFrame<'a> {
    pub(crate) fn borrowed(path: &'a str) -> Self {
        let next_component = Self::next_range(path.as_bytes(), 0).map(|(start, end, _)| (start, end));
        Self { path: Cow::Borrowed(path), pos: 0, next_component }
    }

    pub(crate) fn owned(path: String) -> Self {
        let next_component = Self::next_range(path.as_bytes(), 0).map(|(start, end, _)| (start, end));
        Self { path: Cow::Owned(path), pos: 0, next_component }
    }

    fn next_range(bytes: &[u8], mut pos: usize) -> Option<(usize, usize, usize)> {
        while pos < bytes.len() {
            while pos < bytes.len() && bytes[pos] == b'/' { pos += 1; }
            let start = pos;
            while pos < bytes.len() && bytes[pos] != b'/' { pos += 1; }
            if start == pos { continue; }
            if &bytes[start..pos] == b"." { continue; }
            return Some((start, pos, pos));
        }
        None
    }

    /// Return the next non-empty, non-dot component as a byte range and move
    /// the cursor past it. `..` remains a control component for the walker.
    /// # C: O(component length)
    pub(crate) fn next(&mut self) -> Option<(usize, usize)> {
        let (start, end) = self.next_component?;
        self.pos = end;
        self.next_component = Self::next_range(self.path.as_bytes(), self.pos)
            .map(|(next_start, next_end, _)| (next_start, next_end));
        Some((start, end))
    }

    pub(crate) fn rewind(&mut self, pos: usize) {
        self.pos = pos;
        self.next_component = Self::next_range(self.path.as_bytes(), pos)
            .map(|(start, end, _)| (start, end));
    }

    /// Whether another semantic component remains after the current cursor.
    /// # C: O(remaining component prefix)
    pub(crate) fn has_next(&self) -> bool {
        self.next_component.is_some()
    }
}

/// Split a path for the mount-root helper, whose callers need an owned list
/// because they iterate outside the main nameidata walker.
pub(crate) fn components(path: &str) -> Vec<String> {
    crate::path::components(path).into_iter().filter_map(|c| match c {
        crate::path::Component::Root      => None,
        crate::path::Component::ParentDir => Some(String::from("..")),
        crate::path::Component::Normal(s) => Some(String::from(s)),
    }).collect()
}
