//! REGRESSION COVERAGE — sysfs reachability across a sandbox relocation
//! (live-gnome greeter path). logind runs in a sandbox mount namespace; after
//! systemd's `copy_mnt_ns` + recursive-bind + relocate (MS_MOVE / pivot_root),
//! resolving `/sys/dev/char/226:0` must CROSS INTO the sysfs mount — not fall
//! through to the empty ext4 `/sys` underlay. A fall-through is the greeter
//! blocker: `/sys/dev/char/226:0` ENOENT → `sd_device_new_from_device_id`
//! fails → card0 never attached → seat0 never CanGraphical → no gdm greeter.
//!
//! STATUS: these PASS — the modeled core sequence (copy_mnt_ns + rbind +
//! MS_MOVE/pivot, incl. a stacked fresh sysfs) resolves `/sys` correctly. The
//! LIVE boot still fails (logind's `/sys` observed as fsid 0x1 / ext4), so the
//! real trigger is a subtler wrinkle NOT yet captured here — candidates: the
//! MS_SHARED→MS_SLAVE propagation systemd sets up first (`mount --make-rslave
//! /`), the RO bind-remount pass, or a `d_drop`-driven re-creation of the `/sys`
//! mountpoint dentry that orphans the mount keyed on the old pointer. Extend
//! these with those steps to turn the live failure into a red test.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

static CUR_NS: AtomicU64 = AtomicU64::new(0);
fn cur_ns() -> u64 { CUR_NS.load(Ordering::Acquire) }
fn set_ns(ns: u64) { CUR_NS.store(ns, Ordering::Release); }

struct DirData { kids: BTreeMap<String, InodeRef> }
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Enotdir)?;
        d.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops())
        .private(Arc::new(DirData { kids: m })).build()
}
fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o755), default_inode_ops(), default_file_ops()).build()
}

static FAC_INO: AtomicU64 = AtomicU64::new(0x9000);
struct FacOps;
impl InodeOps for FacOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(facdir(FAC_INO.fetch_add(1, Ordering::Relaxed))) }
}
fn facdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(FacOps), default_file_ops()).build()
}

struct NamedFs { n: &'static str, root: InodeRef }
impl FileSystem for NamedFs {
    fn name(&self) -> &str { self.n }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}

static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
fn root_provider() -> Option<Arc<Dentry>> { ROOT.get().cloned() }
static HOST_ROOT_INODE: OnceLock<InodeRef> = OnceLock::new();

// The device index chain logind chases: /sys/dev/char/226:0 (a leaf here).
const INO_CARD0: u64 = 0xC_A2D;

/// sysfs mount root: holds dev/char/226:0 — the seat-device chase target.
fn sysfs_root() -> InodeRef {
    dir(0x500, &[("dev", dir(0x501, &[("char", dir(0x502, &[("226:0", file(INO_CARD0))]))]))])
}

fn setup_host(host: u64) -> Arc<Dentry> {
    set_ns(host);
    // ext4 root: /sys is an EMPTY mountpoint dir (real content is the sysfs
    // mount). A fall-through to this empty dir is the bug.
    let root_inode = dir(2, &[("sys", dir(0x10, &[])), ("run", dir(0x13, &[]))]);
    let root = ROOT.get_or_init(|| Dentry::new_root(root_inode.clone())).clone();
    let _ = HOST_ROOT_INODE.set(root_inode.clone());
    vfs::set_root_dentry_provider(root_provider);
    vfs::mount::register(None, Arc::new(NamedFs { n: "ext4", root: root_inode })).expect("root mount");

    let mount = |path: &str, fs: NamedFs| {
        let (_, d) = vfs::path_lookup(root.clone(), root.clone(), path, LookupFlags::default())
            .unwrap_or_else(|e| panic!("lookup {path}: {e:?}"));
        vfs::mount::register(Some(d), Arc::new(fs)).unwrap_or_else(|e| panic!("mount {path}: {e:?}"));
    };
    mount("/sys", NamedFs { n: "sysfs", root: sysfs_root() });
    mount("/run", NamedFs { n: "tmpfs", root: run_root() });

    // Sanity: host crosses into sysfs at /sys.
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/sys/dev/char/226:0", LookupFlags::default()).expect("host card0");
    assert_eq!(i.ino(), INO_CARD0, "host /sys must be sysfs");
    root
}
fn run_root() -> InodeRef { facdir(0x400) }

fn recursive_bind_root_onto(root: &Arc<Dentry>, stage_path: &str) -> Arc<Dentry> {
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), stage_path, LookupFlags::default()).expect("stage dir");
    let host_root_inode = HOST_ROOT_INODE.get().expect("host root inode").clone();
    vfs::mount::register_bind(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: host_root_inode.clone() }), host_root_inode)
        .expect("top bind");
    vfs::mount::bind_submounts_rec(root, &stage_d);
    stage_d
}

/// After systemd relocates the sandbox root (MS_MOVE stage -> /), logind resolves
/// /sys/dev/char/226:0. It MUST cross into sysfs (ino CARD0), never the underlay.
#[test]
fn logind_resolves_sysdev_after_msmove_relocation() {
    let _g = guard();
    const HOST: u64 = 0x6EE7_1000;
    const SANDBOX: u64 = 0x6EE7_1001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(HOST);

    vfs::mount::copy_mnt_ns(HOST, SANDBOX);
    set_ns(SANDBOX);

    let stage = "/run/mount-rootfs";
    let stage_d = recursive_bind_root_onto(&root, stage);
    let stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("staging mount").mnt_id;
    vfs::mount::move_mount_by_id(stage_id, &root).expect("MS_MOVE(stage, /)");

    // logind's chase: openat(/sys, "dev") ... must land in sysfs, not the ext4
    // /sys underlay dir (which is empty → ENOENT → the greeter blocker).
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/sys/dev/char/226:0", LookupFlags::default())
        .unwrap_or_else(|e| panic!("post-relocate /sys/dev/char/226:0: {e:?} — sysfs not crossed (GREETER BLOCKER)"));
    assert_eq!(i.ino(), INO_CARD0, "/sys resolved to the ext4 underlay, not sysfs (GREETER BLOCKER)");
}

/// Closer to the boot: after relocation, systemd mounts a FRESH sysfs at /sys
/// (mount_private_sysfs) — stacking a second sysfs over the cloned one. The
/// observed tree had TWO `[/sys fs=sysfs]` (mnt 403/404). Resolve must cross
/// into the TOPMOST sysfs, not fall through to the ext4 underlay.
#[test]
fn logind_resolves_sysdev_with_stacked_fresh_sysfs() {
    let _g = guard();
    const HOST: u64 = 0x6EE7_3000;
    const SANDBOX: u64 = 0x6EE7_3001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(HOST);
    vfs::mount::copy_mnt_ns(HOST, SANDBOX);
    set_ns(SANDBOX);
    let stage = "/run/mount-rootfs";
    let stage_d = recursive_bind_root_onto(&root, stage);
    let stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("staging mount").mnt_id;
    vfs::mount::move_mount_by_id(stage_id, &root).expect("MS_MOVE(stage, /)");

    // systemd mount_private_sysfs: a FRESH sysfs at /sys in the sandbox. The
    // mountpoint dentry is re-resolved here (fresh walk) — the exact spot the
    // boot produced a second /sys dentry the earlier mount wasn't keyed on.
    let (_, sys_d) = vfs::path_lookup(root.clone(), root.clone(), "/sys", LookupFlags::default()).expect("/sys dentry");
    vfs::mount::register(Some(sys_d), Arc::new(NamedFs { n: "sysfs", root: sysfs_root() })).expect("fresh sysfs at /sys");

    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/sys/dev/char/226:0", LookupFlags::default())
        .unwrap_or_else(|e| panic!("stacked-sysfs /sys/dev/char/226:0: {e:?} — sysfs not crossed (GREETER BLOCKER)"));
    assert_eq!(i.ino(), INO_CARD0, "/sys resolved to underlay, not the stacked sysfs (GREETER BLOCKER)");
}

/// Closest to the boot: systemd PID1 makes the whole tree SHARED
/// (`mount --make-rshared /`) before any sandbox. `copy_mnt_ns` then demotes
/// each clone to SLAVE of its source peer group. Exercise that path, then
/// rbind + relocate, and resolve `/sys`.
#[test]
fn logind_resolves_sysdev_with_shared_propagation() {
    let _g = guard();
    const HOST: u64 = 0x6EE7_7000;
    const SANDBOX: u64 = 0x6EE7_7001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(HOST);

    // make-rshared /: mark root + sysfs shared (systemd PID1 does this at boot).
    for p in ["/", "/sys", "/run"] {
        let (_, d) = vfs::path_lookup(root.clone(), root.clone(), p, LookupFlags::default()).unwrap();
        let _ = vfs::mount::set_propagation(&d, vfs::mount::Propagation::Shared);
    }

    vfs::mount::copy_mnt_ns(HOST, SANDBOX);
    set_ns(SANDBOX);

    // make-rslave / in the sandbox (systemd private-namespace setup).
    let (_, rd) = vfs::path_lookup(root.clone(), root.clone(), "/", LookupFlags::default()).unwrap();
    let _ = vfs::mount::set_propagation(&rd, vfs::mount::Propagation::Slave);

    let stage = "/run/mount-rootfs";
    let stage_d = recursive_bind_root_onto(&root, stage);
    let stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("staging mount").mnt_id;
    vfs::mount::move_mount_by_id(stage_id, &root).expect("MS_MOVE(stage, /)");

    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/sys/dev/char/226:0", LookupFlags::default())
        .unwrap_or_else(|e| panic!("shared-prop /sys/dev/char/226:0: {e:?} — sysfs not crossed (GREETER BLOCKER)"));
    assert_eq!(i.ino(), INO_CARD0, "/sys resolved to underlay, not sysfs (GREETER BLOCKER)");
}

/// Same, via pivot_root (systemd's preferred relocation).
#[test]
fn logind_resolves_sysdev_after_pivot_root() {
    let _g = guard();
    const HOST: u64 = 0x6EE7_5000;
    const SANDBOX: u64 = 0x6EE7_5001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(HOST);
    vfs::mount::copy_mnt_ns(HOST, SANDBOX);
    set_ns(SANDBOX);
    let stage = "/run/mount-rootfs";
    let stage_d = recursive_bind_root_onto(&root, stage);
    let (_, put_old) = vfs::path_lookup(root.clone(), root.clone(), "/run/mount-rootfs/run/oldroot", LookupFlags::default()).expect("put_old");
    let stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("staging mount").mnt_id;
    vfs::mount::pivot_root(&stage_d, &put_old).expect("pivot_root");
    let new_root_d = vfs::mount::root_dentry_for_mount_id(stage_id).expect("new root s_root");
    let (i, _) = vfs::path_lookup(new_root_d.clone(), new_root_d.clone(), "/sys/dev/char/226:0", LookupFlags::default())
        .unwrap_or_else(|e| panic!("post-pivot /sys/dev/char/226:0: {e:?} — sysfs not crossed (GREETER BLOCKER)"));
    assert_eq!(i.ino(), INO_CARD0, "/sys resolved to underlay, not sysfs (GREETER BLOCKER)");
}
