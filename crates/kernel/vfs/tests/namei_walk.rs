//! path_lookup walker tests on a synthetic inode tree (docs/16§9:
//! ".."/symlinks/depth-limit/mount-transitions/NO_SYMLINKS). No real
//! filesystem — just `Inode` impls — so this exercises the walker in
//! isolation.

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::fs::FileSystem;
use vfs::{Dentry, FileType, InodeRef, LookupFlags, VfsError};

struct Dir { ino: u64, kids: BTreeMap<String, InodeRef> }
impl Inode for Dir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> vfs::KResult<InodeRef> {
        self.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}

struct F { ino: u64 }
impl Inode for F {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<InodeRef> { Err(VfsError::Enotdir) }
}

struct Sym { ino: u64, target: String }
impl Inode for Sym {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.target.len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> vfs::KResult<Vec<u8>> { Ok(self.target.clone().into_bytes()) }
}

fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    Arc::new(Dir { ino, kids: m })
}
fn file(ino: u64) -> InodeRef { Arc::new(F { ino }) }
fn sym(ino: u64, t: &str) -> InodeRef { Arc::new(Sym { ino, target: t.to_string() }) }

struct TestMountFs;
impl FileSystem for TestMountFs {
    fn name(&self) -> &str { "testfs" }
}

fn mount_id_for(path: &str, root: InodeRef) -> u64 {
    vfs::mount::register_bind(path, Arc::new(TestMountFs), root).expect("register test mount");
    vfs::mount::snapshot_all()
        .into_iter()
        .filter(|m| m.mount_point_str() == path)
        .last()
        .expect("registered mount visible")
        .mnt_id
}

// Synthetic tree:
//   /etc/hostname            (file, ino 11)
//   /etc/localtime -> /usr/share/zoneinfo/UTC   (abs symlink)
//   /usr/share/zoneinfo/UTC  (file, ino 21)
//   /link_rel -> etc/hostname   (rel symlink at root)
//   /loopa -> loopb, /loopb -> loopa  (mutual loop)
fn build_root() -> (Arc<Dentry>, u64, u64) {
    let hostname = file(11);
    let utc = file(21);
    let etc = dir(10, &[
        ("hostname", hostname),
        ("localtime", sym(12, "/usr/share/zoneinfo/UTC")),
    ]);
    let zoneinfo = dir(22, &[("UTC", utc)]);
    let share = dir(23, &[("zoneinfo", zoneinfo)]);
    let usr = dir(24, &[("share", share)]);
    let root_inode = dir(2, &[
        ("etc", etc),
        ("usr", usr),
        ("link_rel", sym(30, "etc/hostname")),
        ("loopa", sym(31, "loopb")),
        ("loopb", sym(32, "loopa")),
    ]);
    let root = Dentry::new_root(root_inode);
    (root, 11, 21)
}

fn look(root: &Arc<Dentry>, path: &str, f: LookupFlags) -> vfs::KResult<(InodeRef, Arc<Dentry>)> {
    vfs::path_lookup(root.clone(), root.clone(), path, f)
}

#[test]
fn descends_to_file() {
    let (root, host_ino, _) = build_root();
    let (i, _) = look(&root, "/etc/hostname", LookupFlags::default()).expect("resolve");
    assert_eq!(i.ino(), host_ino);
}

#[test]
fn dot_and_dotdot() {
    let (root, host_ino, _) = build_root();
    let (i, _) = look(&root, "/etc/./hostname", LookupFlags::default()).expect("dot");
    assert_eq!(i.ino(), host_ino);
    let (j, _) = look(&root, "/etc/../etc/hostname", LookupFlags::default()).expect("dotdot");
    assert_eq!(j.ino(), host_ino);
    // `..` at root stays at root.
    let (k, _) = look(&root, "/../etc/hostname", LookupFlags::default()).expect("dotdot-root");
    assert_eq!(k.ino(), host_ino);
}

#[test]
fn follows_relative_symlink() {
    let (root, host_ino, _) = build_root();
    let (i, _) = look(&root, "/link_rel", LookupFlags::default()).expect("rel symlink");
    assert_eq!(i.ino(), host_ino, "link_rel → etc/hostname");
}

#[test]
fn follows_absolute_symlink() {
    let (root, _, utc_ino) = build_root();
    let (i, _) = look(&root, "/etc/localtime", LookupFlags::default()).expect("abs symlink");
    assert_eq!(i.ino(), utc_ino, "localtime → /usr/share/zoneinfo/UTC");
}

#[test]
fn o_nofollow_returns_symlink() {
    let (root, _, _) = build_root();
    let mut f = LookupFlags::default();
    f.no_follow_final = true;
    let (i, _) = look(&root, "/link_rel", f).expect("nofollow");
    assert_eq!(i.file_type(), FileType::Symlink, "final symlink returned, not followed");
}

#[test]
fn resolve_no_symlinks_errors() {
    let (root, _, _) = build_root();
    let mut f = LookupFlags::default();
    f.no_symlinks = true;
    assert_eq!(look(&root, "/link_rel", f).err(), Some(VfsError::Eloop));
}

#[test]
fn symlink_loop_is_eloop() {
    let (root, _, _) = build_root();
    assert_eq!(look(&root, "/loopa", LookupFlags::default()).err(), Some(VfsError::Eloop));
}

#[test]
fn missing_component_enoent() {
    let (root, _, _) = build_root();
    assert_eq!(look(&root, "/etc/nope", LookupFlags::default()).err(), Some(VfsError::Enoent));
}

// Mount crossing: /mnt whose root holds `file` is crossed by DENTRY
// IDENTITY plus namespace-scoped covering mount id; resolution below the
// mount root is per-component (`d_lookup → i_op->lookup`).
#[test]
fn crosses_mount_point() {
    let mnt_file = file(99);
    let mnt_root = dir(98, &[("file", mnt_file)]);

    // Root tree gains an empty `/mnt` directory the fs is mounted over.
    let empty_mnt = dir(50, &[]);
    let root_inode = dir(2, &[("mnt", empty_mnt)]);
    let root = Dentry::new_root(root_inode);

    // Resolve /mnt to its canonical dentry, then mark it covered by the
    // test mount id. The dentry stores only the covering mount identity;
    // the mount table owns the mounted root.
    let (_, mnt_d) = vfs::path_lookup(root.clone(), root.clone(), "/mnt", LookupFlags::default())
        .expect("resolve /mnt");
    let mnt_id = mount_id_for("/mnt", mnt_root);
    mnt_d.set_mounted_mount(0, Some(mnt_id));

    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/mnt/file", LookupFlags::default())
        .expect("cross into mount");
    assert_eq!(i.ino(), 99, "resolved file inside the mounted fs, not the underlay");
}

// Deep crossing into a mounted (procfs-style) filesystem: the walker
// crosses at `/proc` by dentry identity, then resolves `123 → stat`
// per-component through the mount root's inode tree — NO whole-path
// delegate (WP2 deleted it).
#[test]
fn crosses_into_mount_and_resolves_per_component() {
    let stat = file(301);
    let pid_dir = dir(124, &[("stat", stat)]);
    let proc_root = dir(123, &[("123", pid_dir)]);

    let empty_proc = dir(60, &[]);
    let root_inode = dir(2, &[("proc", empty_proc)]);
    let root = Dentry::new_root(root_inode);

    let (_, proc_d) = vfs::path_lookup(root.clone(), root.clone(), "/proc", LookupFlags::default())
        .expect("resolve /proc");
    let mnt_id = mount_id_for("/proc", proc_root);
    proc_d.set_mounted_mount(0, Some(mnt_id));

    let (i, _) = vfs::path_lookup(root.clone(), root, "/proc/123/stat", LookupFlags::default())
        .expect("cross into procfs mount + resolve per-component");
    assert_eq!(i.ino(), 301, "resolved /proc/123/stat per-component across the mount");
}

// Per-fs conformance: a multi-component path resolves PURELY via
// `d_lookup → i_op->lookup → d_add`. This is the WP2 end-state contract for
// every SuperBlock-owned fs (ext4/tmpfs/devfs/sysfs/procfs/cgroup): the first
// walk populates the (parent,name)-keyed dcache from each directory inode's
// per-component `lookup`, and a second walk is served from that cache.
#[test]
fn multi_component_resolves_via_dlookup_iop_lookup_dadd() {
    // A real fs-root shape: / → a → b → c (regular file), all per-component.
    let c = file(0xC);
    let b = dir(0xB, &[("c", c)]);
    let a = dir(0xA, &[("b", b)]);
    let root_inode = dir(2, &[("a", a)]);
    let root = Dentry::new_root(root_inode);

    // First walk: the dcache for each component starts empty, so each step
    // takes the slow path `i_op->lookup(parent_inode, name)` then `d_add`.
    assert!(vfs::d_lookup(&root, "a").is_none(), "cache cold before the walk");
    let (i, leaf_d) = vfs::path_lookup(root.clone(), root.clone(), "/a/b/c", LookupFlags::default())
        .expect("multi-component per-component resolve");
    assert_eq!(i.ino(), 0xC, "resolved /a/b/c to the file inode");

    // d_add populated every (parent,name) edge along the path: the dcache
    // fast path `d_lookup` now returns the SAME dentry objects (by identity).
    let a_d = vfs::d_lookup(&root, "a").expect("a cached by d_add");
    assert!(!a_d.is_negative());
    let b_d = vfs::d_lookup(&a_d, "b").expect("b cached by d_add");
    let c_d = vfs::d_lookup(&b_d, "c").expect("c cached by d_add");
    assert!(alloc_ptr_eq(&c_d, &leaf_d), "second lookup returns the walk's leaf dentry");

    // Second walk is served from the dcache (fast path) and agrees.
    let (i2, _) = vfs::path_lookup(root.clone(), root, "/a/b/c", LookupFlags::default())
        .expect("cached re-resolve");
    assert_eq!(i2.ino(), 0xC, "cached resolution matches");
}

fn alloc_ptr_eq(a: &Arc<Dentry>, b: &Arc<Dentry>) -> bool { Arc::ptr_eq(a, b) }

// Regression (B53): a mount on a TREE-BACKED directory reached only by
// FIRST crossing an outer mount — the `/sys` (devfs sub-tree) → then
// `/sys/fs/cgroup` (cgroupfs) shape. The inner mountpoint dentry is
// produced lazily during the walk (cached under the crossed-into
// sub-tree's dentry), so marking it via the covering mount id must be
// visible to a SUBSEQUENT walk of a CHILD path — proving the dcache is
// canonical: one dentry per (parent,name) shared by the marking walk and
// the child-resolving walk. This is exactly what the boot cgroupfs
// (mounted before the resolver) needs once `rewire_all_crossings` runs.
#[test]
fn crosses_mount_on_tree_backed_subtree() {
    // Inner mounted fs (cgroupfs analogue): root holds `init.scope`.
    let cg_scope = dir(0x301, &[]);
    let cg_root: InodeRef = dir(0x300, &[("init.scope", cg_scope)]);

    // The crossed-into sub-tree (devfs `/sys` analogue): a tree-backed
    // directory whose own children are produced per-component by lookup.
    // `/sys` underlay dir on the ext4 root, mounted over by `sys_tree`.
    let sys_tree_fs: InodeRef = dir(0x200, &[("fs", dir(0x201, &[("cgroup", dir(0x202, &[]))]))]);
    let sys_underlay = dir(0x100, &[]);
    let root_inode = dir(2, &[("sys", sys_underlay)]);
    let root = Dentry::new_root(root_inode);

    // Mount the sub-tree fs ON `/sys` by dentry identity (outer mount).
    let (_, sys_d) = vfs::path_lookup(root.clone(), root.clone(), "/sys", LookupFlags::default())
        .expect("resolve /sys");
    let sys_mnt = mount_id_for("/sys", sys_tree_fs);
    sys_d.set_mounted_mount(0, Some(sys_mnt));

    // Now resolve the INNER mountpoint dentry the way the late
    // rewire does — a full walk that crosses `/sys` then descends the
    // sub-tree. The landed dentry is the canonical one cached under the
    // sub-tree's `fs` dentry.
    let (_, cg_mp) = vfs::path_lookup(root.clone(), root.clone(), "/sys/fs/cgroup", LookupFlags::default())
        .expect("resolve /sys/fs/cgroup mountpoint");
    let cg_mnt = mount_id_for("/sys/fs/cgroup", cg_root);
    cg_mp.set_mounted_mount(0, Some(cg_mnt));

    // A SUBSEQUENT child-path walk must cross into cgroupfs by hitting the
    // SAME cached dentry — proving the mark is canonical / visible.
    let (i, _) = vfs::path_lookup(root.clone(), root, "/sys/fs/cgroup/init.scope", LookupFlags::default())
        .expect("cross into cgroupfs and resolve init.scope");
    assert_eq!(i.ino(), 0x301, "resolved init.scope inside the cgroupfs mount, not the underlay");
}

// chroot confinement (the mechanism pathresolve::resolution_root uses):
// with a sub-dentry as the resolution root + RESOLVE_BENEATH, absolute
// paths restart at that root and `..` cannot ascend above it.
#[test]
fn beneath_confines_dotdot_to_root() {
    let (root, host_ino, _) = build_root();
    // /etc is the "chroot" root.
    let (_, etc_d) = look(&root, "/etc", LookupFlags::default()).expect("etc");
    let mut f = LookupFlags::default();
    f.beneath = true;
    // Absolute path restarts at the chroot root: "/hostname" → etc/hostname.
    let (i, _) = vfs::path_lookup(etc_d.clone(), etc_d.clone(), "/hostname", f).expect("confined");
    assert_eq!(i.ino(), host_ino, "absolute path confined to the chroot root");
    // `..` cannot escape above the chroot root: "/../hostname" stays in etc.
    let (j, _) = vfs::path_lookup(etc_d.clone(), etc_d.clone(), "/../hostname", f).expect("dotdot confined");
    assert_eq!(j.ino(), host_ino, ".. clamped at the chroot root (no escape)");
    // Sanity: the chroot root has no "etc" child, so "/etc/x" must NOT
    // resolve (proves we're rooted at /etc, not the global root).
    assert!(vfs::path_lookup(etc_d.clone(), etc_d.clone(), "/etc/hostname", f).is_err(),
        "global tree not visible from inside the chroot");
}
