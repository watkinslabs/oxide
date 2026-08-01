// Reparenting admission for link and rename.
//
// Moving a file changes which hierarchy its rights are inherited from, so the
// check is not "may I create here" but "would the file gain rights it did not
// have". Two comparisons run at once: the source and destination hierarchies
// must each explicitly allow the removal/creation being asked for, and the
// destination must be at least as restricted as the source. The first failure
// is reported as a permission error, the second as a cross-device error, and
// permission wins when both apply so a caller can tell "never possible" from
// "copy instead of move".

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::{Dentry, FileType, InodeRef, VfsPath};

use crate::domain::Domain;
use crate::eval::{no_more_access, LayerMasks};
use crate::uapi::*;
use crate::walk::{self, Node};

/// A rename/link endpoint that exists.
#[derive(Clone)]
pub struct Target {
    pub dentry: Arc<Dentry>,
    pub inode:  InodeRef,
}

impl Target {
    /// # C: O(1)
    pub fn is_dir(&self) -> bool { self.inode.file_type() == FileType::Directory }
}

/// Creation right implied by an object's type.
/// # C: O(1)
pub fn mode_access(ft: FileType) -> AccessMask {
    match ft {
        FileType::Symlink   => ACCESS_FS_MAKE_SYM,
        FileType::Directory => ACCESS_FS_MAKE_DIR,
        FileType::CharDev   => ACCESS_FS_MAKE_CHAR,
        FileType::BlockDev  => ACCESS_FS_MAKE_BLOCK,
        FileType::Fifo      => ACCESS_FS_MAKE_FIFO,
        FileType::Socket    => ACCESS_FS_MAKE_SOCK,
        _                   => ACCESS_FS_MAKE_REG,
    }
}

/// Removal right implied by an endpoint that exists.
/// # C: O(1)
fn maybe_remove(t: Option<&Target>) -> AccessMask {
    match t {
        None => 0,
        Some(t) if t.is_dir() => ACCESS_FS_REMOVE_DIR,
        Some(_) => ACCESS_FS_REMOVE_FILE,
    }
}

/// Collect the rights the domain still withholds walking from `dir` up to the
/// mount root. Returns true when every filtered right is granted before the
/// walk ends, meaning this hierarchy imposes nothing further.
/// # C: O(depth × N_layers × N_rules)
fn collect_domain_accesses(dom: &Domain, mnt_id: u64, dir: Arc<Dentry>,
                           mnt_root: &Arc<Dentry>, masks: &mut LayerMasks) -> bool
{
    let (m, req) = LayerMasks::init(&dom.fs_masks(), MASK_ACCESS_FS);
    *masks = m;
    if req == 0 { return true; }
    for n in walk::up_to(mnt_id, dir, mnt_root).iter() {
        if masks.unmask(&dom.granted_at(n)) { return true; }
    }
    false
}

/// Rights withheld at one object, used as the "what the child already has"
/// side of the comparison.
/// # C: O(N_layers × N_rules)
fn child_masks(dom: &Domain, mnt_id: u64, t: &Target) -> LayerMasks {
    let (mut m, req) = LayerMasks::init(&dom.fs_masks(), MASK_ACCESS_FS);
    if req != 0 {
        let node = Node { mnt_id, dentry: t.dentry.clone(), inode: t.inode.clone() };
        m.unmask(&dom.granted_at(&node));
    }
    m
}

/// The dual hierarchy walk. Both sides start by asking for every right the
/// domain filters; once the destination is provably no less restricted than the
/// source the question narrows to the rights actually requested.
/// # C: O(depth × N_layers × N_rules)

fn dual_walk(dom: &Domain, chain: &[Node],
             req1: AccessMask, m1: &mut LayerMasks,
             req2: AccessMask, m2: &mut LayerMasks,
             child1: &LayerMasks, child1_is_dir: bool,
             child2: Option<&LayerMasks>, child2_is_dir: bool) -> bool
{
    let mut dom_check = true;
    let mut allowed1 = m1.all_clear();
    let mut allowed2 = m2.all_clear();
    for n in chain.iter() {
        if dom_check && no_more_access(m1, child1, child1_is_dir, m2, child2, child2_is_dir) {
            dom_check = false;
            allowed1 = allowed1 || m1.scope_to_request(req1);
            allowed2 = allowed2 || m2.scope_to_request(req2);
            if allowed1 && allowed2 { return true; }
        }
        let granted = dom.granted_at(n);
        let a1 = m1.unmask(&granted);
        let a2 = m2.unmask(&granted);
        allowed1 = allowed1 || a1;
        allowed2 = allowed2 || a2;
        if allowed1 && allowed2 { return true; }
    }
    allowed1 && allowed2
}

/// Admit a link or rename. `removable` marks a rename (the source name goes
/// away); `exchange` marks an atomic swap, which is a reparenting in both
/// directions at once.
/// # C: O(depth × N_layers × N_rules)
pub fn check(dom: &Domain, old_dir: &VfsPath, old: &Target,
             new_dir: &VfsPath, new: Option<&Target>,
             removable: bool, exchange: bool) -> Result<(), Errno>
{
    let mut req1: AccessMask = 0;
    if exchange {
        let n = new.ok_or(Errno::Enoent)?;
        req1 = mode_access(n.inode.file_type());
    }
    let mut req2 = mode_access(old.inode.file_type());
    if removable {
        req1 |= maybe_remove(Some(old));
        req2 |= maybe_remove(new);
    }

    // Same directory: no hierarchy changes, so no reparenting right is needed
    // and one ordinary check on that directory answers both sides.
    let same_dir = old_dir.mnt_id == new_dir.mnt_id
        && Arc::ptr_eq(&old_dir.dentry, &new_dir.dentry);
    if same_dir {
        return dom.check_fs(new_dir, req1 | req2);
    }

    req1 |= ACCESS_FS_REFER;
    req2 |= ACCESS_FS_REFER;

    let mnt_root = walk::mount_root(new_dir.mnt_id, &new_dir.dentry);
    let old_parent = if Arc::ptr_eq(&old.dentry, &mnt_root) {
        old.dentry.clone()
    } else {
        match old.dentry.parent() { Some(p) => p.clone(), None => old.dentry.clone() }
    };

    let mut m1 = LayerMasks::default();
    let mut m2 = LayerMasks::default();
    let allow1 = collect_domain_accesses(dom, old_dir.mnt_id, old_parent, &mnt_root, &mut m1);
    let allow2 = collect_domain_accesses(dom, new_dir.mnt_id, new_dir.dentry.clone(),
                                         &mnt_root, &mut m2);
    if allow1 && allow2 { return Ok(()); }

    let c1 = child_masks(dom, old_dir.mnt_id, old);
    let c2 = if exchange { new.map(|n| child_masks(dom, new_dir.mnt_id, n)) } else { None };
    let chain: Vec<Node> = walk::from(new_dir.mnt_id, mnt_root);
    let ok = dual_walk(dom, &chain, req1, &mut m1, req2, &mut m2,
                       &c1, old.is_dir(),
                       c2.as_ref(), new.map(|n| n.is_dir()).unwrap_or(false));
    if ok { return Ok(()); }
    if m1.is_eacces(req1) || m2.is_eacces(req2) { return Err(Errno::Eacces); }
    Err(Errno::Exdev)
}

#[cfg(test)]
#[path = "tests/refer.rs"]
mod tests;
