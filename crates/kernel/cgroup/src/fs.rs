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

/// Linux `CGROUP2_SUPER_MAGIC` — the cgroup2 statfs `f_type`.
pub const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

impl CgroupFs {
    /// Create a cgroup2 filesystem instance. The backing hierarchy is
    /// global; resolution is per-component from the mount root `CgDir`
    /// (`root()` → `CgDir::lookup`), so the instance carries no path prefix.
    /// # C: O(1)
    pub fn new(_mount_point: &str) -> Self { Self }
}

impl FileSystem for CgroupFs {
    /// `/proc/mounts` shows the hierarchy-root flags in force (Linux
    /// `cgroup_show_options`). They are hierarchy-wide, so every cgroup2 mount
    /// reports the same set — as the reference does. # C: O(1)
    fn show_options(&self) -> alloc::string::String {
        crate::state::root_flags().show_options()
    }
    /// # C: O(1)
    fn name(&self) -> &str { "cgroup2" }
    /// cgroup2 exports kernfs file handles (`crate::export`), so `s_op` is its
    /// own — the generic fallback would mint a 12-byte handle the cgroup-id
    /// readers in userspace cannot receive. # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> { Some(crate::export::super_ops()) }
    /// CGROUP2_SUPER_MAGIC (the statfs f_type value) — systemd's `cg_all_unified()`
    /// detects the unified hierarchy by this `statfs` f_type.
    /// # C: O(1)
    fn magic(&self) -> u64 { CGROUP2_SUPER_MAGIC }
    /// The unified hierarchy is one kernfs tree, so mounts reuse its owning
    /// superblock instead of attaching one inode tree to competing owners. # C: O(1)
    fn dev_id(&self) -> Option<u64> { Some(CGROUP2_SUPER_MAGIC) }
    /// Resolve a `/sys/fs/cgroup/...` path by synthesizing from the
    /// hierarchy.
    /// # C: O(components · log n)
    fn root(&self) -> Option<InodeRef> {
        if !is_mounted() { return None; }
        Some(inode::make_cg_dir(tree::ROOT))
    }
}

/// The cgroup the CALLER's mount of the hierarchy is rooted at: the caller's
/// cgroup-namespace root, not the hierarchy root. A task inside
/// `CLONE_NEWCGROUP` that mounts cgroup2 must see only its namespace's
/// subtree — mount-root selection is where that containment happens; `/proc`
/// path rendering alone cannot hide ancestors from a mounted tree. A namespace
/// root path that no longer resolves (its cgroup was removed) falls back to
/// the hierarchy root rather than failing the mount, matching the
/// already-dead-namespace behaviour of the rendering path.
/// # C: O(components · log n) + hook
fn caller_mount_root_cg() -> u64 {
    let ns_root = crate::state::caller_ns_root();
    if ns_root == "/" { return tree::ROOT; }
    TREE.lock().resolve(&ns_root).unwrap_or(tree::ROOT)
}

/// Mount the shared unified cgroup2 hierarchy on the caller-walked mountpoint,
/// rooted at the caller's cgroup-namespace root.
/// # C: O(N_mounts)
pub fn mount_at(mount_point: &str, mp: Option<Arc<Dentry>>) -> KResult<()> {
    if mount_point != "/" && mp.is_none() { return Err(vfs::VfsError::Enoent); }
    let first = TREE.lock().mount_root();
    let fs = Arc::new(CgroupFs::new(mount_point));
    let root = inode::make_cg_dir(caller_mount_root_cg());
    let ty = vfs::fs::get_fs_type("cgroup2").ok_or(vfs::VfsError::Enodev)?;
    match vfs::mount::register_bind_typed(ty, mp, fs, root) {
        Ok(()) => Ok(()),
        Err(vfs::VfsError::Eexist) if !first => Ok(()),
        Err(e) => Err(e),
    }
}

/// fs_context `get_tree` realize for the unified cgroup2 hierarchy, rooted at
/// the caller's cgroup-namespace root.
/// # C: O(1)
pub fn realize_tree() -> (Arc<dyn FileSystem>, InodeRef) {
    let _ = TREE.lock().mount_root();
    let fs: Arc<dyn FileSystem> = Arc::new(CgroupFs::new(""));
    let root = inode::make_cg_dir(caller_mount_root_cg());
    (fs, root)
}
