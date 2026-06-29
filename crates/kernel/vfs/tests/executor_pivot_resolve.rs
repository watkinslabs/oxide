//! B286 REPRO (systemd sd-executor 203/EXEC gate). The executor sets up a
//! private mount namespace for udevd, then `execve`s the service binary. Model
//! the FULL sequence deterministically and assert SYNCHRONOUS visibility (no
//! retry) of the binary AND a lib that live across SEPARATE submounts:
//!
//!   1. host tree: `/` (ext4) with SEPARATE mounts `/usr` (holds
//!      lib/systemd/systemd-udevd) and `/lib64` (holds ld-linux), plus
//!      `/proc`, `/run`.
//!   2. `copy_mnt_ns(host -> sandbox)` (unshare CLONE_NEWNS), switch ns.
//!   3. recursive bind host `/` onto a staging dir under `/run`
//!      (`mount("/",stage,MS_BIND|MS_REC)` = top bind + `bind_submounts_rec`).
//!   4a. `pivot_root(stage, stage)`  — systemd's preferred relocation; OR
//!   4b. `chroot(stage)`             — the fallback the release boot used
//!       (captured trace: pivot_root=-22 EINVAL → chroot=0 → openat=-2 → 203).
//!   5. IMMEDIATELY resolve `/usr/lib/systemd/systemd-udevd` AND
//!      `/lib64/ld-linux-x86-64.so.2` and assert the EXACT inodes — never
//!      ENOENT, never a retry. A miss here is the 203/EXEC.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

// Mutable "current ns" the provider reads, so the test can switch host->sandbox.
static CUR_NS: AtomicU64 = AtomicU64::new(0);
fn cur_ns() -> u64 { CUR_NS.load(Ordering::Acquire) }
fn set_ns(ns: u64) { CUR_NS.store(ns, Ordering::Release); }

/// Static child-table directory backend (a real `i_op->lookup`, ENOENT on miss
/// — NOT a directory-factory, so a genuine resolution miss is observable).
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

/// tmpfs-style factory dir: any name resolves to a fresh child dir (models
/// `mkdir` of the staging path under /run). Strict backends elsewhere keep a
/// genuine resolution miss observable.
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

// Inode numbers of the two things the executor must reach post-relocation.
const INO_UDEVD: u64 = 0xD_E5D;
const INO_LD: u64 = 0x1_D11;

fn usr_root() -> InodeRef {
    dir(0x100, &[("lib", dir(0x101, &[("systemd", dir(0x102, &[("systemd-udevd", file(INO_UDEVD))]))]))])
}
fn lib64_root() -> InodeRef { dir(0x200, &[("ld-linux-x86-64.so.2", file(INO_LD))]) }
fn proc_root() -> InodeRef { dir(0x300, &[("self", dir(0x301, &[]))]) }
fn run_root() -> InodeRef { facdir(0x400) }

/// Build the host mount tree in `host` ns and return the global root dentry.
fn setup_host(host: u64) -> Arc<Dentry> {
    set_ns(host);
    // ext4 root: usr/lib64/proc/run are empty mountpoint dirs (real content is
    // a SEPARATE mount per dir — exactly Fedora's /usr & /lib split tree).
    let root_inode = dir(2, &[
        ("usr", dir(0x10, &[])), ("lib64", dir(0x11, &[])),
        ("proc", dir(0x12, &[])), ("run", dir(0x13, &[])),
    ]);
    let root = ROOT.get_or_init(|| Dentry::new_root(root_inode.clone())).clone();
    let _ = HOST_ROOT_INODE.set(root_inode.clone());
    vfs::set_root_dentry_provider(root_provider);
    vfs::mount::register(None, Arc::new(NamedFs { n: "ext4", root: root_inode })).expect("root mount");

    let mount = |path: &str, fs: NamedFs| {
        let (_, d) = vfs::path_lookup(root.clone(), root.clone(), path, LookupFlags::default())
            .unwrap_or_else(|e| panic!("lookup {path}: {e:?}"));
        vfs::mount::register(Some(d), Arc::new(fs)).unwrap_or_else(|e| panic!("mount {path}: {e:?}"));
    };
    mount("/usr",   NamedFs { n: "usr",   root: usr_root() });
    mount("/lib64", NamedFs { n: "lib64", root: lib64_root() });
    mount("/proc",  NamedFs { n: "proc",  root: proc_root() });
    mount("/run",   NamedFs { n: "tmpfs", root: run_root() });

    // Sanity: host resolves the binary + lib across their submounts.
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/usr/lib/systemd/systemd-udevd", LookupFlags::default()).expect("host udevd");
    assert_eq!(i.ino(), INO_UDEVD);
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/lib64/ld-linux-x86-64.so.2", LookupFlags::default()).expect("host ld");
    assert_eq!(i.ino(), INO_LD);
    root
}

/// The executor's recursive bind of host `/` onto a staging dir under /run:
/// `mount("/", stage, MS_BIND|MS_REC)` = top bind + submount mirror.
fn recursive_bind_root_onto(root: &Arc<Dentry>, stage_path: &str) -> Arc<Dentry> {
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), stage_path, LookupFlags::default()).expect("stage dir");
    let host_root_inode = HOST_ROOT_INODE.get().expect("host root inode").clone();
    // Top bind: host "/" fs onto the staging dentry.
    vfs::mount::register_bind(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: host_root_inode.clone() }), host_root_inode)
        .expect("top bind");
    // Recursively clone every submount (/usr,/lib64,/proc,/run) under staging.
    vfs::mount::bind_submounts_rec(root, &stage_d);
    stage_d
}

fn assert_reaches(root: &Arc<Dentry>, base: &str) {
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(),
        &format!("{base}/usr/lib/systemd/systemd-udevd"), LookupFlags::default())
        .unwrap_or_else(|e| panic!("post-relocate udevd resolve: {e:?} (this is the 203/EXEC)"));
    assert_eq!(i.ino(), INO_UDEVD, "udevd inode");
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(),
        &format!("{base}/lib64/ld-linux-x86-64.so.2"), LookupFlags::default())
        .unwrap_or_else(|e| panic!("post-relocate ld resolve: {e:?} (this is the 203/EXEC)"));
    assert_eq!(i.ino(), INO_LD, "ld inode");
}

// 4a. systemd `mount_move_root`: `MS_MOVE(stage -> "/")` then `chroot(".")` —
// the real relocation the release boot used (the b283 trace: pivot_root=-22,
// then mount(MS_MOVE)=0, chroot=0). The MS_MOVE source resolves THROUGH the
// staging mount (lands on its s_root), so systemd keys it by the crossed-into
// mnt_id (`move_mount_by_id`). Resolve the binary/lib from the new "/".
#[test]
fn executor_msmove_root_then_resolve_binary_and_lib() {
    let _g = guard();
    const HOST: u64 = 0xB286_1000;
    const SANDBOX: u64 = 0xB286_1001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(HOST);

    vfs::mount::copy_mnt_ns(HOST, SANDBOX);
    set_ns(SANDBOX);

    let stage = "/run/mount-rootfs";
    let stage_d = recursive_bind_root_onto(&root, stage);

    // MS_MOVE(stage, "/"): the staging bind (+ its cloned submounts) becomes the
    // ns root in place. Keyed by the moved mount's id (systemd `mount_move_root`
    // does `mount(".", "/", MS_MOVE)` after chdir into it).
    let stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("staging mount").mnt_id;
    vfs::mount::move_mount_by_id(stage_id, &root).expect("MS_MOVE(stage, /)");

    // chroot(".") = resolve with `root` as the resolution root. The binary/lib
    // resolve at their canonical absolute paths through the moved root — no retry.
    assert_reaches(&root, "");
}

// 4a'. pivot_root with a distinct put_old (the non-stacking pivot, exercising
// the commit_retree in-subtree identity preservation directly).
#[test]
fn executor_pivot_root_distinct_putold_resolves() {
    let _g = guard();
    const HOST: u64 = 0xB286_5000;
    const SANDBOX: u64 = 0xB286_5001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(HOST);
    vfs::mount::copy_mnt_ns(HOST, SANDBOX);
    set_ns(SANDBOX);
    let stage = "/run/mount-rootfs";
    let stage_d = recursive_bind_root_onto(&root, stage);
    // put_old is a dir INSIDE the new root (created via the factory under the
    // bind's tmpfs-style staging), as Linux pivot_root requires.
    let (_, put_old) = vfs::path_lookup(root.clone(), root.clone(), "/run/mount-rootfs/run/oldroot", LookupFlags::default()).expect("put_old");
    let stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("staging mount").mnt_id;
    vfs::mount::pivot_root(&stage_d, &put_old).expect("pivot_root(stage, stage/run/oldroot)");
    // After pivot the task root becomes the new root mount's s_root (Linux
    // pivot_root sets root+cwd to new_root). Resolve from THAT dentry, as the
    // executor would post-pivot.
    let new_root_d = vfs::mount::root_dentry_for_mount_id(stage_id).expect("new root s_root");
    let (i, _) = vfs::path_lookup(new_root_d.clone(), new_root_d.clone(),
        "/usr/lib/systemd/systemd-udevd", LookupFlags::default())
        .unwrap_or_else(|e| panic!("post-pivot udevd resolve: {e:?} (this is the 203/EXEC)"));
    assert_eq!(i.ino(), INO_UDEVD, "udevd inode (pivot)");
    let (i, _) = vfs::path_lookup(new_root_d.clone(), new_root_d.clone(),
        "/lib64/ld-linux-x86-64.so.2", LookupFlags::default())
        .unwrap_or_else(|e| panic!("post-pivot ld resolve: {e:?} (this is the 203/EXEC)"));
    assert_eq!(i.ino(), INO_LD, "ld inode (pivot)");
}

// 4b. chroot fallback path: resolve with `root` = staging dentry (chroot).
#[test]
fn executor_chroot_then_resolve_binary_and_lib() {
    let _g = guard();
    const HOST: u64 = 0xB286_2000;
    const SANDBOX: u64 = 0xB286_2001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(HOST);

    vfs::mount::copy_mnt_ns(HOST, SANDBOX);
    set_ns(SANDBOX);

    let stage = "/run/mount-rootfs";
    let stage_d = recursive_bind_root_onto(&root, stage);

    // chroot(stage): subsequent resolution uses stage as the resolution root.
    // The cross-mount binary/lib must resolve relative to the chrooted root.
    let (i, _) = vfs::path_lookup(stage_d.clone(), stage_d.clone(),
        "/usr/lib/systemd/systemd-udevd", LookupFlags::default())
        .unwrap_or_else(|e| panic!("chroot udevd resolve: {e:?} (this is the 203/EXEC)"));
    assert_eq!(i.ino(), INO_UDEVD, "udevd inode (chroot)");
    let (i, _) = vfs::path_lookup(stage_d.clone(), stage_d.clone(),
        "/lib64/ld-linux-x86-64.so.2", LookupFlags::default())
        .unwrap_or_else(|e| panic!("chroot ld resolve: {e:?} (this is the 203/EXEC)"));
    assert_eq!(i.ino(), INO_LD, "ld inode (chroot)");
}

// Also resolve from WITHIN staging via the global root BEFORE pivot/chroot, to
// catch a recursive-bind submount-clone miss directly.
#[test]
fn executor_recursive_bind_submounts_reach_binary_and_lib() {
    let _g = guard();
    const HOST: u64 = 0xB286_3000;
    const SANDBOX: u64 = 0xB286_3001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(HOST);
    vfs::mount::copy_mnt_ns(HOST, SANDBOX);
    set_ns(SANDBOX);
    let stage = "/run/mount-rootfs";
    let _ = recursive_bind_root_onto(&root, stage);
    assert_reaches(&root, stage);
}
