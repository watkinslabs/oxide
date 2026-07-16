use alloc::sync::Arc;

use vfs::fs::FileSystem;
use vfs::{Dentry, InodeRef, KResult};

use crate::{inode, is_mounted, state::TREE, tree};

/// cgroup2 filesystem for the unified mount table (`16§7`). Mounted
/// at `/sys/fs/cgroup`; VFS namei routes paths here. cgroupfs
/// OWNS its inodes: `lookup` strips the mount prefix, resolves the
/// relative cgroup path through the hierarchy (`tree.rs`), and SYNTHESIZES
/// a `CgDir`/`CgFile` inode — no registry, ZERO devfs dependency.
pub struct CgroupFs;

/// Linux CGROUP2_SUPER_MAGIC (`linux/magic.h`).
pub const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

impl CgroupFs {
    /// Create a cgroup2 filesystem instance. The backing hierarchy is
    /// global; resolution is per-component from the mount root `CgDir`
    /// (`root()` → `CgDir::lookup`), so the instance carries no path prefix.
    /// # C: O(1)
    pub fn new(_mount_point: &str) -> Self { Self }
}

impl FileSystem for CgroupFs {
    /// # C: O(1)
    fn name(&self) -> &str { "cgroup2" }
    /// CGROUP2_SUPER_MAGIC (linux/magic.h) — systemd's `cg_all_unified()`
    /// detects the unified hierarchy by this `statfs` f_type.
    /// # C: O(1)
    fn magic(&self) -> u64 { CGROUP2_SUPER_MAGIC }
    /// Resolve a `/sys/fs/cgroup/...` path by synthesizing from the
    /// hierarchy.
    /// # C: O(components · log n)
    fn root(&self) -> Option<InodeRef> {
        if !is_mounted() { return None; }
        Some(inode::make_cg_dir(tree::ROOT))
    }
}

/// Mount the shared unified cgroup2 hierarchy on the caller-walked mountpoint.
/// # C: O(N_mounts)
pub fn mount_at(mount_point: &str, mp: Option<Arc<Dentry>>) -> KResult<()> {
    if mount_point != "/" && mp.is_none() { return Err(vfs::VfsError::Enoent); }
    let first = TREE.lock().mount_root();
    let fs = Arc::new(CgroupFs::new(mount_point));
    let root = inode::make_cg_dir(tree::ROOT);
    let ty = vfs::fs::get_fs_type("cgroup2").ok_or(vfs::VfsError::Enodev)?;
    match vfs::mount::register_bind_typed(ty, mp, fs, root) {
        Ok(()) => Ok(()),
        Err(vfs::VfsError::Eexist) if !first => Ok(()),
        Err(e) => Err(e),
    }
}

/// fs_context `get_tree` realize for the unified cgroup2 hierarchy.
/// # C: O(1)
pub fn realize_tree() -> (Arc<dyn FileSystem>, InodeRef) {
    let _ = TREE.lock().mount_root();
    let fs: Arc<dyn FileSystem> = Arc::new(CgroupFs::new(""));
    let root = inode::make_cg_dir(tree::ROOT);
    (fs, root)
}
