//! path_lookup walker tests on a synthetic inode tree (docs/16§9:
//! ".."/symlinks/depth-limit/mount-transitions/NO_SYMLINKS). No real
//! filesystem — just `Inode` impls — so this exercises the walker in
//! isolation.

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::fs::FileSystem;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

/// Backend state (`i_private`): the static child table this directory resolves.
struct DirData { kids: BTreeMap<String, InodeRef> }

/// `i_op->lookup` over the static `DirData` child table (shared by the plain
/// and perm-bearing directory builders).
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Enotdir)?;
        d.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn dir_data(kids: &[(&str, InodeRef)]) -> Arc<DirData> {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    Arc::new(DirData { kids: m })
}

fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops())
        .private(dir_data(kids)).build()
}
fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}
/// Symlink inode: the target body is stored inline (`i_link`), so `get_link`
/// returns it directly (the walker's symlink fast path).
fn sym(ino: u64, t: &str) -> InodeRef {
    sym_bytes(ino, t.as_bytes())
}
fn sym_bytes(ino: u64, t: &[u8]) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops())
        .size(t.len() as u64)
        .link(t.to_vec().into_boxed_slice())
        .build()
}

struct TestMountFs;
impl FileSystem for TestMountFs {
    fn name(&self) -> &str { "testfs" }
}

// `register_bind` resolves its filesystem type by NAME through the real
// global `get_fs_type` registry — it never accepts an explicit type, so
// "testfs" must be registered once before the first bind. Idempotent: later
// calls in the same test binary see it already present and no-op.
fn ensure_testfs_type() {
    if vfs::fs::get_fs_type("testfs").is_some() { return; }
    let ty = vfs::fs::FsType::new("testfs", 0, vfs::fs::FsFlags::empty(),
        Box::new(|_, _, _, _| unreachable!("testfs is mounted explicitly via register_bind")));
    let _ = vfs::fs::register_fs(ty);
}

fn mount_id_for(mp: &Arc<Dentry>, root: InodeRef) -> u64 {
    ensure_testfs_type();
    vfs::mount::register_bind(Some(mp.clone()), Arc::new(TestMountFs), root).expect("register test mount");
    vfs::mount::snapshot_all()
        .into_iter()
        .filter(|m| m.mountpoint().map(|d| Arc::ptr_eq(&d, mp)).unwrap_or(false))
        .last()
        .expect("registered mount visible")
        .mnt_id
}

// Synthetic tree:
//   /etc/hostname            (file, ino 11)
//   /etc/localtime -> /usr/share/zoneinfo/UTC   (abs symlink)
//   /usr/share/zoneinfo/UTC  (file, ino 21)
//   /link_rel -> etc/hostname   (rel symlink at root)
//   /link_raw -> raw invalid-UTF8 target bytes
//   /loopa -> loopb, /loopb -> loopa  (mutual loop)
fn build_root() -> (Arc<Dentry>, u64, u64) {
    let hostname = file(11);
    let utc = file(21);
    let raw_name = vfs::path_from_bytes(b"raw-\xff");
    let raw_target = file(41);
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
        ("link_raw", sym_bytes(40, b"raw-\xff")),
        (&raw_name, raw_target),
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
fn follows_non_utf8_symlink_target_without_lossy_decode() {
    let (root, _, _) = build_root();
    let (i, _) = look(&root, "/link_raw", LookupFlags::default()).expect("raw-byte symlink target");
    assert_eq!(i.ino(), 41, "symlink target bytes must not be replaced by U+FFFD");
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

    // Resolve /mnt to its canonical dentry, then mount the test fs there
    // (`register_bind` inserts the `(parent,dentry)` crossing into the strict
    // mount hash — the walk crosses via `__lookup_mnt`).
    let (_, mnt_d) = vfs::path_lookup(root.clone(), root.clone(), "/mnt", LookupFlags::default())
        .expect("resolve /mnt");
    let _mnt_id = mount_id_for(&mnt_d, mnt_root);

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
    let _mnt_id = mount_id_for(&proc_d, proc_root);

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

// ===========================================================================
// B4 KEYSTONE + flags + dots + may_lookup acceptance.
// ===========================================================================

// A directory inode that carries explicit POSIX perm (uid/gid 0) so `may_lookup`
// has per-fs perm info. Reuses `DirOps`; only the mode bits differ from `dir`.
fn perm_dir(ino: u64, perm: u16, kids: &[(&str, InodeRef)]) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, perm), Arc::new(DirOps), default_file_ops())
        .owner(0, 0).private(dir_data(kids)).build()
}

// THE KEYSTONE: crossing a mountpoint returns the mounted superblock's `s_root`
// DENTRY (Linux `__follow_mount`) — Arc::ptr_eq to `Mount.sb().s_root()` — NOT
// the covered underlay dentry. Both walking exactly the mountpoint and walking
// a child under it land on the mounted-fs dentry chain.
#[test]
fn crossing_returns_mounted_s_root_not_underlay() {
    let mnt_file = file(99);
    let mnt_root = dir(98, &[("file", mnt_file)]);

    let empty_mnt = dir(50, &[]);
    let root_inode = dir(2, &[("mnt", empty_mnt)]);
    let root = Dentry::new_root(root_inode);

    let (_, underlay_mnt) = vfs::path_lookup(root.clone(), root.clone(), "/mnt", LookupFlags::default())
        .expect("resolve /mnt underlay");
    let mnt_id = mount_id_for(&underlay_mnt, mnt_root);
    let s_root = vfs::mount::root_dentry_for_mount_id(mnt_id).expect("mount s_root");

    // Walking exactly the mountpoint returns the mounted s_root, not underlay.
    let (i, d) = vfs::path_lookup(root.clone(), root.clone(), "/mnt", LookupFlags::default())
        .expect("cross at mountpoint");
    assert_eq!(i.ino(), 98, "inode is the mounted-fs root");
    assert!(Arc::ptr_eq(&d, &s_root), "dentry IS the mount s_root (keystone)");
    assert!(!Arc::ptr_eq(&d, &underlay_mnt), "dentry is NOT the underlay mountpoint");
    assert!(d.is_root(), "mounted dentry is a D_ROOT");

    // A child under the mount is parented on the mounted s_root chain.
    let (ci, cd) = vfs::path_lookup(root.clone(), root, "/mnt/file", LookupFlags::default())
        .expect("resolve child in mount");
    assert_eq!(ci.ino(), 99);
    assert!(Arc::ptr_eq(cd.parent().expect("child parent"), &s_root),
        "child's parent is the mount s_root, not the underlay");
}

// d_path / absolute_path is mount-aware (Linux `prepend_path`): a file inside a
// mount reconstructs the GLOBAL path `/dev/null`, crossing from the mounted
// `s_root` back to the `/dev` mountpoint — not the collapsed `/null`.
#[test]
fn d_path_is_mount_aware_across_crossing() {
    let null = file(0xF0);
    let dev_root = dir(0xD0, &[("null", null)]);
    let underlay_dev = dir(0x10, &[]);
    let root_inode = dir(2, &[("dev", underlay_dev)]);
    let root = Dentry::new_root(root_inode);

    let (_, underlay) = vfs::path_lookup(root.clone(), root.clone(), "/dev", LookupFlags::default())
        .expect("resolve /dev");
    let _mnt = mount_id_for(&underlay, dev_root);

    let (_, nulld) = vfs::path_lookup(root.clone(), root, "/dev/null", LookupFlags::default())
        .expect("resolve /dev/null");
    assert_eq!(nulld.absolute_path(), b"/dev/null",
        "global path reconstructed across the mount, not collapsed to /null");
}

// `..` across a mount (`follow_dotdot`): from inside a mount at `/mnt`, `..`
// crosses back to the mountpoint's PARENT in the underlay tree — landing on the
// global `/` (ino 2), not stuck at the parentless mounted s_root.
#[test]
fn dotdot_crosses_back_over_mount() {
    let mnt_file = file(99);
    let mnt_root = dir(98, &[("file", mnt_file)]);
    let empty_mnt = dir(50, &[]);
    let root_inode = dir(2, &[("mnt", empty_mnt)]);
    let root = Dentry::new_root(root_inode);

    let (_, underlay_mnt) = vfs::path_lookup(root.clone(), root.clone(), "/mnt", LookupFlags::default())
        .expect("resolve /mnt");
    let _mnt_id = mount_id_for(&underlay_mnt, mnt_root);

    // /mnt/.. : cross into the mount (s_root), then `..` crosses back over the
    // mountpoint to the underlay parent = global root.
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/mnt/..", LookupFlags::default())
        .expect("dotdot across mount");
    assert_eq!(i.ino(), 2, ".. from a mount root lands on the global / (underlay parent)");

    // /mnt/../mnt/file resolves the child again after crossing back.
    let (j, _) = vfs::path_lookup(root.clone(), root, "/mnt/../mnt/file", LookupFlags::default())
        .expect("dotdot then re-descend");
    assert_eq!(j.ino(), 99);
}

// ELOOP at MAXSYMLINKS=40 (nd.depth): a chain of >40 symlinks exhausts the
// budget and returns Eloop.
#[test]
fn eloop_at_max_symlink_depth() {
    // s0 -> s1 -> ... -> s49 -> target(file). 50 symlink follows > 40.
    let target = file(0x7777);
    let mut kids: Vec<(String, InodeRef)> = Vec::new();
    kids.push(("target".to_string(), target));
    for i in 0..50u32 {
        let next = if i + 1 < 50 { format!("s{}", i + 1) } else { "target".to_string() };
        kids.push((format!("s{}", i), sym(1000 + i as u64, &next)));
    }
    let refs: Vec<(&str, InodeRef)> = kids.iter().map(|(n, i)| (n.as_str(), i.clone())).collect();
    let root_inode = dir(2, &refs);
    let root = Dentry::new_root(root_inode);
    assert_eq!(look(&root, "/s0", LookupFlags::default()).err(), Some(VfsError::Eloop),
        "chain of >40 symlinks is ELOOP");
}

// RESOLVE_NO_SYMLINKS rejects an INTERMEDIATE-component symlink (not just the
// final), complementing `resolve_no_symlinks_errors`.
#[test]
fn resolve_no_symlinks_errors_on_intermediate() {
    let leaf = file(0x88);
    let real = dir(0x80, &[("leaf", leaf)]);
    let root_inode = dir(2, &[("real", real), ("lnk", sym(0x81, "real"))]);
    let root = Dentry::new_root(root_inode);
    // Sanity: without the flag, /lnk/leaf resolves via the symlink.
    assert_eq!(look(&root, "/lnk/leaf", LookupFlags::default()).map(|(i, _)| i.ino()), Ok(0x88));
    let mut f = LookupFlags::default();
    f.no_symlinks = true;
    assert_eq!(look(&root, "/lnk/leaf", f).err(), Some(VfsError::Eloop),
        "intermediate symlink rejected under RESOLVE_NO_SYMLINKS");
}

// may_lookup (MAY_EXEC per directory): a non-root cred is denied search on a
// directory lacking the exec bit; root (CAP_DAC_OVERRIDE) and exec-able dirs
// resolve.
#[test]
fn may_lookup_denies_non_exec_dir() {
    let secret = file(0x91);
    // /priv perm 0600 (no exec/search), owned by uid 0; /open perm 0755.
    let priv_dir = perm_dir(0x90, 0o600, &[("secret", secret.clone())]);
    let open_dir = perm_dir(0x95, 0o755, &[("secret", secret)]);
    let root_inode = perm_dir(2, 0o755, &[("priv", priv_dir), ("open", open_dir)]);
    let root = Dentry::new_root(root_inode);

    let user = vfs::namei::Cred { uid: 1000, gid: 1000, cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false, groups: vfs::GroupList::empty() };

    // Non-root user: search through /priv (no exec bit) is EACCES.
    let denied = vfs::namei::path_lookup_cred(root.clone(), root.clone(), "/priv/secret",
        LookupFlags::default(), user.clone());
    assert_eq!(denied.err(), Some(VfsError::Eacces), "non-exec dir denies search for non-root");

    // Same user CAN search /open (0755).
    let ok = vfs::namei::path_lookup_cred(root.clone(), root.clone(), "/open/secret",
        LookupFlags::default(), user.clone());
    assert_eq!(ok.map(|p| p.inode.ino()), Ok(0x91), "exec dir permits search");

    // Root (default cred, CAP_DAC_OVERRIDE) bypasses the missing exec bit.
    assert_eq!(look(&root, "/priv/secret", LookupFlags::default()).map(|(i, _)| i.ino()), Ok(0x91),
        "root bypasses DAC via CAP_DAC_OVERRIDE");
}

// LOOKUP_DIRECTORY: the final component must be a directory.
#[test]
fn lookup_directory_requires_dir() {
    let (root, _, _) = build_root();
    let mut f = LookupFlags::default();
    f.directory = true;
    assert_eq!(look(&root, "/etc/hostname", f).err(), Some(VfsError::Enotdir),
        "LOOKUP_DIRECTORY on a file is ENOTDIR");
    assert!(look(&root, "/etc", f).is_ok(), "LOOKUP_DIRECTORY on a dir resolves");
}

// LOOKUP_PARENT: stop before the final component, returning the parent dir +
// the leaf name (the mknod/rename/create shape).
#[test]
fn lookup_parent_returns_parent_and_leaf() {
    let (root, _, _) = build_root();
    let mut f = LookupFlags::default();
    f.parent = true;
    let p = vfs::path_lookup_path(root.clone(), root, "/etc/newfile", f).expect("parent walk");
    assert_eq!(p.inode.ino(), 10, "returned dentry is the parent dir /etc (ino 10)");
    assert_eq!(p.last_component.as_deref(), Some("newfile"), "leaf name carried out");
}

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
    let _sys_mnt = mount_id_for(&sys_d, sys_tree_fs);

    // Now resolve the INNER mountpoint dentry the way the late
    // rewire does — a full walk that crosses `/sys` then descends the
    // sub-tree. The landed dentry is the canonical one cached under the
    // sub-tree's `fs` dentry.
    let (_, cg_mp) = vfs::path_lookup(root.clone(), root.clone(), "/sys/fs/cgroup", LookupFlags::default())
        .expect("resolve /sys/fs/cgroup mountpoint");
    let _cg_mnt = mount_id_for(&cg_mp, cg_root);

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
