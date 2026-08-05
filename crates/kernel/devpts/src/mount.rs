// Resolve the devpts instance associated with an opened ptmx path.
//
// A ptmx node inside devpts uses that mount directly. A ptmx node in a parent
// filesystem uses the `pts` child mount beside it. Single-file bind mounts are
// walked upward first, preserving the opened path's mount identity.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use vfs::{Dentry, KResult, VfsError};
use vfs::mount::Mount;

use crate::DevptsFs;

/// The devpts state and mount selected for one ptmx open.
pub struct DevptsMount { fs: Arc<DevptsFs>, mnt_id: u64 }

impl DevptsMount {
    /// Selected superblock state. # C: O(1)
    pub fn fs(&self) -> &Arc<DevptsFs> { &self.fs }
    /// Mount identity used by a peer-open file. # C: O(1)
    pub fn mnt_id(&self) -> u64 { self.mnt_id }
}

fn binding(m: &Arc<Mount>) -> Option<DevptsMount> {
    if m.sb().s_magic != crate::DEVPTS_MAGIC { return None; }
    m.sb().fs_info_as::<DevptsFs>().map(|fs| DevptsMount { fs, mnt_id: m.mnt_id })
}

/// Resolve the devpts superblock that owns a ptmx path. # C: O(bind depth + log N)
pub fn devpts_for_ptmx(mut mnt_id: u64, dentry: &Arc<Dentry>) -> KResult<DevptsMount> {
    let mut d = Arc::clone(dentry);
    loop {
        let m = vfs::mount::mount_by_id(mnt_id).ok_or(VfsError::Enodev)?;
        if let Some(found) = binding(&m) { return Ok(found); }
        let at_root = m.mnt_root().map(|r| Arc::ptr_eq(&r, &d)).unwrap_or(false);
        if !at_root || m.is_root() { break; }
        d = m.mountpoint().ok_or(VfsError::Enodev)?;
        mnt_id = m.parent_id.load(Ordering::Acquire);
    }
    let parent = d.parent().ok_or(VfsError::Enodev)?;
    let pts = vfs::dcache::d_lookup(&parent, "pts").ok_or(VfsError::Enodev)?;
    let child = vfs::mount::__lookup_mnt(mnt_id, &pts);
    child.and_then(|m| binding(&m)).ok_or(VfsError::Enodev)
}
