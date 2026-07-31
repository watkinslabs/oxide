//! sysfs's OWN `kernfs::PseudoDir` root (D1c). Replaces the shared devfs
//! ROOTS write-bus: every `/sys/*` node is inserted into `SYS_ROOT` and
//! `SysfsFs::root()` returns it, so sysfs owns its tree under its own mount
//! instead of reading its subtree back out of the global devfs registry.
//! `overlay = false` — there is no on-disk `/sys` to merge.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use kernfs::PseudoDir;
use sync::{Spinlock, TaskList as LockClass};
use vfs::{Dentry, InodeRef, SuperBlock};

/// sysfs filesystem identity for stat(2) `st_dev` (distinct from devfs so
/// `/sys` and `/dev` no longer alias the same `st_dev`).
pub const SYSFS_FSID: u64 = 0x0102_1994_0000_0002;

/// The single sysfs tree root (mount root of every `/sys` mount). Lazily
/// built on first `register`/`root()`. `path == ""` represents `/sys`.
static SYS_ROOT: Spinlock<Option<Arc<PseudoDir>>, LockClass> = Spinlock::new(None);

/// Get-or-create the `/sys` root `PseudoDir`. # C: O(1)
pub fn sys_root() -> Arc<PseudoDir> {
    let mut g = SYS_ROOT.lock();
    if let Some(r) = g.as_ref() { return Arc::clone(r); }
    let r = PseudoDir::new_root(kernfs::dir_ino("/sys"), SYSFS_FSID);
    *g = Some(Arc::clone(&r));
    r
}

/// Strip the `/sys` mount prefix so `full` becomes root-relative (SYS_ROOT
/// already represents `/sys`). # C: O(len)
fn rel(full: &str) -> &str {
    full.strip_prefix("/sys/").or_else(|| full.strip_prefix("/sys")).unwrap_or(full)
}

/// Register `full_path` (absolute `/sys/...`) → `inode` in sysfs's own tree.
/// Cross-crate writers (procfs `/sys/kernel/*`) call this instead of
/// `devfs::register`. # C: O(depth)
pub fn register(full_path: &str, inode: InodeRef) {
    sys_root().insert_path(rel(full_path), inode);
}

/// Create an empty `/sys/...` directory chain (mount points without leaves,
/// e.g. `/sys/fs/cgroup`, `/sys/kernel/tracing`). # C: O(components)
pub fn register_dir(full_path: &str) {
    sys_root().ensure_dir_path(rel(full_path));
}

/// Every live sysfs superblock. `/sys` is mounted more than once — each mount
/// realizes a fresh superblock over the same kernfs tree and owns its own
/// dentry cache — and the kernfs root retains only the most recent one for
/// inode construction. Invalidation that consults that single slot walks a
/// dentry tree nobody is using and silently drops nothing, so the set is
/// tracked here and every live mount is invalidated.
static SYS_SUPERS: Spinlock<Vec<Weak<SuperBlock>>, LockClass> = Spinlock::new(Vec::new());

/// Record one realized sysfs superblock. Called from `SysfsFs::set_sb`.
/// # C: O(N_sysfs_mounts)
pub(crate) fn record_super(sb: Weak<SuperBlock>) {
    let mut supers = SYS_SUPERS.lock();
    supers.retain(|entry| entry.strong_count() != 0);
    if !supers.iter().any(|entry| Weak::ptr_eq(entry, &sb)) {
        supers.push(sb);
    }
}

/// Root dentry of every live sysfs mount. # C: O(N_sysfs_mounts)
fn sysfs_roots() -> Vec<Arc<Dentry>> {
    let live: Vec<Arc<SuperBlock>> = {
        let mut supers = SYS_SUPERS.lock();
        supers.retain(|entry| entry.strong_count() != 0);
        supers.iter().filter_map(|entry| entry.upgrade()).collect()
    };
    live.iter().filter_map(|sb| sb.s_root()).collect()
}

/// Drop a cached sysfs dentry subtree by walking only sysfs's own superblock
/// roots. `full_path` may be absolute `/sys/...` or sysfs-root relative
/// `/...`; no global root lookup, mount traversal, or slow fs lookup is
/// performed. # C: O(N_sysfs_mounts * components)
pub fn drop_cached(full_path: &str) {
    let rel = rel(full_path);
    if rel.is_empty() { return; }
    for root in sysfs_roots() {
        drop_cached_under(root, rel);
    }
}

fn drop_cached_under(root: Arc<Dentry>, rel: &str) {
    let mut cur = root;
    let mut comps = rel.split('/').filter(|c| !c.is_empty()).peekable();
    while let Some(comp) = comps.next() {
        if comps.peek().is_none() {
            vfs::d_drop_child(&cur, comp);
            return;
        }
        cur = match cur.cached_child(comp).or_else(|| vfs::d_lookup(&cur, comp)) {
            Some(d) => d,
            None => return,
        };
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::sync::Arc;
    use vfs::fs::FileSystem;
    use vfs::superblock::FileSystemType;
    use vfs::LookupFlags;

    // Both tests realize sysfs superblocks, and realizing one resets the kernfs
    // root's cached inodes for every mount, so they cannot overlap.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct SysfsType;
    impl FileSystemType for SysfsType {
        fn name(&self) -> &str { "sysfs" }
        fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> { Err(vfs::VfsError::Enodev) }
    }

    fn realize(name: &str) -> Arc<vfs::SuperBlock> {
        let fs: Arc<dyn vfs::fs::FileSystem> = Arc::new(crate::SysfsFs);
        vfs::fs::superblock_from_filesystem(
            Arc::new(SysfsType), fs, crate::SysfsFs.root(), String::from(name),
        ).expect("realize sysfs")
    }

    fn cache_leaf(sb: &Arc<vfs::SuperBlock>, parent_path: &str, path: &str) -> Arc<vfs::Dentry> {
        let root = sb.s_root().expect("sysfs root dentry");
        let (_, parent) = vfs::path_lookup(
            root.clone(), root.clone(), parent_path, LookupFlags::default(),
        ).expect("parent cached");
        vfs::path_lookup(root.clone(), root, path, LookupFlags::default())
            .expect("leaf cached");
        assert!(vfs::d_lookup(&parent, "leaf").is_some(), "leaf cached before invalidation");
        parent
    }

    // A later `/sys` mount replaces the kernfs root's superblock slot, so an
    // invalidation that consulted only that slot dropped nothing from the
    // dentry cache the earlier mount is still serving.
    #[test]
    fn drop_cached_invalidates_every_live_sysfs_mount() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let path = "/sys/drop-cache-multi/leaf";
        crate::register(path, crate::make_body_inode(b"stale\n".to_vec(), crate::ids::STALE_UEVENT));
        let first = realize("sysfs-multi-first");
        let second = realize("sysfs-multi-second");
        let first_parent = cache_leaf(&first, "/drop-cache-multi", "/drop-cache-multi/leaf");
        let second_parent = cache_leaf(&second, "/drop-cache-multi", "/drop-cache-multi/leaf");

        super::drop_cached(path);

        assert!(vfs::d_lookup(&first_parent, "leaf").is_none(), "first mount kept a stale leaf");
        assert!(vfs::d_lookup(&second_parent, "leaf").is_none(), "second mount kept a stale leaf");
    }

    #[test]
    fn drop_cached_invalidates_under_sysfs_root_without_global_walk() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let path = "/sys/drop-cache-test/leaf";
        crate::register(path, crate::make_body_inode(b"stale\n".to_vec(), crate::ids::STALE_UEVENT));
        let fs: Arc<dyn vfs::fs::FileSystem> = Arc::new(crate::SysfsFs);
        let sb = vfs::fs::superblock_from_filesystem(Arc::new(SysfsType), fs, crate::SysfsFs.root(), String::from("sysfs-test")).expect("realize sysfs");
        let root = sb.s_root().expect("sysfs root dentry");
        let (_, parent) = vfs::path_lookup(root.clone(), root.clone(), "/drop-cache-test", LookupFlags::default()).expect("parent cached");
        assert!(vfs::path_lookup(root.clone(), root, "/drop-cache-test/leaf", LookupFlags::default()).is_ok());
        assert!(vfs::d_lookup(&parent, "leaf").is_some(), "leaf cached before invalidation");
        super::drop_cached(path);
        assert!(vfs::d_lookup(&parent, "leaf").is_none(), "leaf dropped by sysfs-root dcache walk");
    }
}
