//! B138 REPRO (udevd CLONE_NEWNS sandbox, status=226/NAMESPACE): a
//! singleton-`s_root` pseudo-fs (procfs) mounted at /proc with a CHILD mount
//! (binfmt_misc at /proc/sys/fs/binfmt_misc), `snapshot_ns` into a private
//! mount namespace, then the procfs subtree MS_MOVEd under a staging dir — the
//! deep leaves under BOTH procfs (`.../proc/sys/kernel/domainname`) and the
//! child mount (`.../proc/sys/fs/binfmt_misc/status`) MUST still resolve in the
//! new ns via the REAL resolver.
//!
//! Root cause: procfs uses a SINGLETON root inode, so every mount of it shares
//! ONE `s_root` dentry (and its whole child subtree). The pre-fix engine
//! recomputes the moved subtree's parent links by WALKING DENTRIES
//! (`parent_by_dentry` -> `mount_with_root_dentry` -> `.find()` on the `s_root`
//! POINTER); with two procfs mounts sharing one `s_root` in one ns the
//! `.find()` returns an ARBITRARY mount, so the child mount is mis-attributed
//! and the MS_MOVE orphans it -> the leaf under it ENOENTs.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

struct Dir { ino: u64, kids: BTreeMap<String, InodeRef> }
impl Inode for Dir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        self.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
struct FacDir(u64);
impl Inode for FacDir {
    fn ino(&self) -> vfs::Ino { self.0 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Ok(Arc::new(FacDir(0x9000))) }
}
struct F(u64);
impl Inode for F {
    fn ino(&self) -> vfs::Ino { self.0 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}
fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    Arc::new(Dir { ino, kids: m })
}

struct NamedFs { n: &'static str, root: InodeRef }
impl FileSystem for NamedFs {
    fn name(&self) -> &str { self.n }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}

static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
fn root_provider() -> Option<Arc<Dentry>> { ROOT.get().cloned() }

// procfs singleton subtree: sys/kernel/domainname (file 0x103) +
// sys/fs/binfmt_misc (dir 0x110 — the binfmt_misc mountpoint).
fn proc_root() -> InodeRef {
    dir(0x100, &[
        ("sys", dir(0x101, &[
            ("kernel", dir(0x102, &[ ("domainname", Arc::new(F(0x103))) ])),
            ("fs",     dir(0x104, &[ ("binfmt_misc", dir(0x110, &[])) ])),
        ])),
    ])
}
// binfmt_misc mount root: a "status" file.
fn binfmt_root() -> InodeRef { dir(0x200, &[ ("status", Arc::new(F(0x201))) ]) }

fn setup_host() -> (Arc<Dentry>, Arc<Dentry>) {
    let root_inode = dir(2, &[ ("proc", Arc::new(FacDir(0x10))), ("run", Arc::new(FacDir(0x20))) ]);
    let root = ROOT.get_or_init(|| Dentry::new_root(root_inode.clone())).clone();
    vfs::set_root_dentry_provider(root_provider);

    vfs::mount::register(None, Arc::new(NamedFs { n: "ext4", root: root_inode })).expect("root mount");
    let (_, proc_d) = vfs::path_lookup(root.clone(), root.clone(), "/proc", LookupFlags::default()).expect("/proc");
    vfs::mount::register(Some(proc_d.clone()), Arc::new(NamedFs { n: "proc", root: proc_root() })).expect("mount /proc");
    let (_, run_d) = vfs::path_lookup(root.clone(), root.clone(), "/run", LookupFlags::default()).expect("/run");
    vfs::mount::register(Some(run_d), Arc::new(NamedFs { n: "tmpfs", root: Arc::new(FacDir(0x21)) })).expect("mount /run");
    // binfmt_misc as a CHILD mount inside procfs.
    let (_, bm_d) = vfs::path_lookup(root.clone(), root.clone(), "/proc/sys/fs/binfmt_misc", LookupFlags::default()).expect("binfmt dir");
    vfs::mount::register(Some(bm_d), Arc::new(NamedFs { n: "binfmt_misc", root: binfmt_root() })).expect("mount binfmt");

    // Host leaves resolve (sanity + populate the shared procfs dcache subtree).
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/proc/sys/kernel/domainname", LookupFlags::default()).expect("host domainname");
    assert_eq!(i.ino(), 0x103);
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/proc/sys/fs/binfmt_misc/status", LookupFlags::default()).expect("host binfmt status");
    assert_eq!(i.ino(), 0x201);
    (root, proc_d)
}

fn assert_staged_leaves(root: &Arc<Dentry>) {
    let (li, _) = vfs::path_lookup(root.clone(), root.clone(),
        "/run/stage/proc/sys/kernel/domainname", LookupFlags::default())
        .expect("staged procfs leaf (domainname) must resolve");
    assert_eq!(li.ino(), 0x103, "domainname leaf");
    let (bi, _) = vfs::path_lookup(root.clone(), root.clone(),
        "/run/stage/proc/sys/fs/binfmt_misc/status", LookupFlags::default())
        .expect("staged binfmt child-mount leaf (status) must resolve");
    assert_eq!(bi.ino(), 0x201, "binfmt child leaf");
}

// Single snapshot: one of each mount in the sandbox (no shared-s_root dup).
#[test]
fn single_snapshot_move_keeps_child_leaf() {
    let _g = guard();
    const HOST: u64 = 0xB138_1000;
    const SANDBOX: u64 = 0xB138_1001;
    vfs::mount::set_current_ns_provider(|| HOST);
    let (root, proc_d) = setup_host();
    vfs::mount::snapshot_ns(HOST, SANDBOX);
    vfs::mount::set_current_ns_provider(|| SANDBOX);
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/stage/proc", LookupFlags::default()).expect("stage dir");
    vfs::mount::move_mount(&proc_d, &stage_d).expect("MS_MOVE /proc -> stage");
    assert_staged_leaves(&root);
}

// Double snapshot: two procfs mounts share one s_root in the sandbox ns — the
// udevd singleton precondition. The pre-fix `.find()` mis-attributes the child.
#[test]
fn double_snapshot_move_keeps_child_leaf() {
    let _g = guard();
    const HOST: u64 = 0xB138_2000;
    const SANDBOX: u64 = 0xB138_2001;
    vfs::mount::set_current_ns_provider(|| HOST);
    let (root, proc_d) = setup_host();
    vfs::mount::snapshot_ns(HOST, SANDBOX);
    vfs::mount::snapshot_ns(HOST, SANDBOX);
    vfs::mount::set_current_ns_provider(|| SANDBOX);
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/stage/proc", LookupFlags::default()).expect("stage dir");
    vfs::mount::move_mount(&proc_d, &stage_d).expect("MS_MOVE /proc -> stage");
    assert_staged_leaves(&root);
}
