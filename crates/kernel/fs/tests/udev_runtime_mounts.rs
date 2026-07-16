use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use boot_info::{BootInfo, BootMemKind, BootMemRegion};
use fs::tmpfs::TmpfsFs;
use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::superblock::{FileSystemType, SuperBlock};
use vfs::{default_file_ops, mk_mode, CreateCtx, Cred, Dentry, FileType, InodeBuilder, InodeOps};
use vfs::{InodeRef, KResult, LookupFlags, VfsError};
use vfs::mount::Propagation;

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);
static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
static HOST_ROOT_INODE: OnceLock<InodeRef> = OnceLock::new();
static PMM: OnceLock<()> = OnceLock::new();

const HOSTED_PMM_POOL: usize = 16 * 1024 * 1024;

fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }
fn cur_ns() -> vfs::mntns::MntNamespaceRef {
    CUR_NS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().expect("current namespace owner").clone()
}
fn set_ns(namespace: &vfs::mntns::MntNamespaceRef) {
    *CUR_NS.lock().unwrap_or_else(|e| e.into_inner()) = Some(namespace.clone());
}
fn new_ns() -> vfs::mntns::MntNamespaceRef {
    let init = vfs::mntns::initial();
    vfs::mntns::allocate(init.owner_user_namespace()).expect("allocate mount namespace")
}
fn root_provider() -> Option<Arc<Dentry>> { ROOT.get().cloned() }

fn boot_hosted_pmm() {
    PMM.get_or_init(|| {
        let layout = std::alloc::Layout::from_size_align(HOSTED_PMM_POOL, 4096).unwrap();
        // SAFETY: non-zero, page-aligned host allocation leaked for test lifetime.
        let buf = unsafe { std::alloc::alloc_zeroed(layout) } as u64;
        assert!(buf != 0, "hosted PMM pool allocation failed");
        let regions = [BootMemRegion { base_pa: 0, len: HOSTED_PMM_POOL as u64, kind: BootMemKind::Usable }];
        let info = BootInfo {
            memmap_count: 1,
            memmap_ptr: regions.as_ptr(),
            seed: [0u8; 32],
            boot_ns: 0,
            rsdp_pa: 0,
            hhdm_offset: buf,
            smp_info_array: 0,
            smp_count: 0,
            bsp_lapic_id: 0,
            _pad: 0,
        };
        // SAFETY: BootInfo points at a live region slice for this call; HHDM maps to leaked host memory.
        unsafe { pmm::setup::init_from_boot_info(&info).expect("pmm init"); }
        pmm::setup::init_page_meta((HOSTED_PMM_POOL as u64) / 4096);
    });
}

struct Ext4DirData { kids: BTreeMap<String, InodeRef> }
struct Ext4DirOps;
impl InodeOps for Ext4DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        inode.private::<Ext4DirData>().ok_or(VfsError::Enotdir)?
            .kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
    fn create(&self, _inode: &Inode, _name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        Err(VfsError::Eio)
    }
    fn mkdir(&self, _inode: &Inode, _name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        Err(VfsError::Eio)
    }
    fn symlink(&self, _inode: &Inode, _name: &str, _target: &[u8], _ctx: &CreateCtx) -> KResult<()> {
        Err(VfsError::Eio)
    }
}

fn ext4_dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(Ext4DirOps), default_file_ops())
        .private(Arc::new(Ext4DirData { kids: m })).build()
}

struct NamedFs { n: &'static str, root: InodeRef }
impl FileSystem for NamedFs {
    fn name(&self) -> &str { self.n }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}
struct NamedType(&'static str);
impl FileSystemType for NamedType {
    fn name(&self) -> &str { self.0 }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Enodev) }
}
fn fs_type(n: &'static str) -> Arc<dyn FileSystemType> { Arc::new(NamedType(n)) }

fn lookup_root(root: Arc<Dentry>, root_mnt: u64, path: &str) -> vfs::VfsPath {
    vfs::path_lookup_at_root_cred(root.clone(), root_mnt, root, root_mnt, path,
        LookupFlags::default(), Cred::root()).expect(path)
}

fn lookup_parent(root: Arc<Dentry>, root_mnt: u64, path: &str) -> vfs::VfsPath {
    vfs::path_lookup_at_root_cred(root.clone(), root_mnt, root, root_mnt, path,
        LookupFlags { parent: true, ..Default::default() }, Cred::root()).expect(path)
}

fn fs_name_for(mnt_id: u64) -> String {
    vfs::mount::mount_by_id(mnt_id).expect("mount id").sb.s_type.name().to_string()
}

fn setup_host(host: &vfs::mntns::MntNamespaceRef) -> (Arc<Dentry>, Arc<TmpfsFs>, Arc<TmpfsFs>) {
    set_ns(host);
    let dev_underlay = ext4_dir(0x17, &[("char", ext4_dir(0x18, &[])), ("block", ext4_dir(0x19, &[]))]);
    let root_inode = ext4_dir(2, &[("run", ext4_dir(0x13, &[])), ("dev", dev_underlay),
        ("proc", ext4_dir(0x15, &[])), ("sys", ext4_dir(0x16, &[])), ("etc", ext4_dir(0x14, &[]))]);
    let root = ROOT.get_or_init(|| Dentry::new_root(root_inode.clone())).clone();
    let _ = HOST_ROOT_INODE.set(root_inode.clone());
    vfs::set_root_dentry_provider(root_provider);
    vfs::mount::register_typed(fs_type("ext4"), None, Arc::new(NamedFs { n: "ext4", root: root_inode })).expect("root mount");

    let root_id = vfs::mount::root_mount_id(host.id()).expect("root id");
    let run_mp = lookup_root(root.clone(), root_id, "/run").dentry;
    let run_fs = TmpfsFs::new(String::from("run"));
    vfs::mount::register_typed(fs_type("tmpfs"), Some(run_mp), run_fs.clone()).expect("mount /run tmpfs");
    let run_root = run_fs.root_inode();
    let systemd = run_root.mkdir("systemd", 0o755, &CreateCtx::root()).expect("mkdir /run/systemd");
    systemd.mkdir("mount-rootfs", 0o755, &CreateCtx::root()).expect("mkdir mount-rootfs");
    run_root.mkdir("udev", 0o755, &CreateCtx::root()).expect("mkdir /run/udev");

    let dev_mp = lookup_root(root.clone(), root_id, "/dev").dentry;
    let dev_fs = TmpfsFs::new(String::from("dev"));
    vfs::mount::register_typed(fs_type("tmpfs"), Some(dev_mp), dev_fs.clone()).expect("mount /dev tmpfs");
    let dev_root = dev_fs.root_inode();
    dev_root.mkdir("char", 0o755, &CreateCtx::root()).expect("mkdir /dev/char");
    dev_root.mkdir("block", 0o755, &CreateCtx::root()).expect("mkdir /dev/block");
    (root, run_fs, dev_fs)
}

fn service_switched_root(host: &vfs::mntns::MntNamespaceRef,
    sandbox: &vfs::mntns::MntNamespaceRef) -> (Arc<Dentry>, u64) {
    vfs::mount::set_current_ns_provider(cur_ns);
    let (root, _run_fs, _dev_fs) = setup_host(host);
    switch_prepared_host_root(root, host, sandbox)
}

fn switch_prepared_host_root(root: Arc<Dentry>, host: &vfs::mntns::MntNamespaceRef,
    sandbox: &vfs::mntns::MntNamespaceRef) -> (Arc<Dentry>, u64) {
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    vfs::mount::copy_mnt_ns(host, sandbox).expect("copy mount namespace");
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let source_root = vfs::mount::root_mount_id(sandbox.id()).expect("source root id");
    let stage = lookup_root(root.clone(), source_root, "/run/systemd/mount-rootfs");
    vfs::mount::register_bind_clone_at(Some(stage.dentry.clone()), source_root, root.clone(), Some(stage.mnt_id))
        .expect("bind-clone / to stage");
    let stage_id = vfs::mount::mount_at_path_exact(&stage.dentry).expect("stage mount").mnt_id;
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage.dentry, Some(stage.mnt_id));
    vfs::mount::move_mount_by_id(stage_id, &root).expect("MS_MOVE stage to /");
    (root, stage_id)
}

fn read_abs(root: Arc<Dentry>, root_mnt: u64, path: &str) -> Vec<u8> {
    let p = lookup_root(root, root_mnt, path);
    let mut body = [0u8; 512];
    let n = p.inode.read(0, &mut body).expect(path);
    body[..n].to_vec()
}

fn user_cred(uid: u32, gid: u32) -> Cred {
    Cred {
        uid, gid,
        cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        ngroups: 0, groups: [0u32; vfs::CRED_NGROUPS],
    }
}

fn mkdir_abs(root: Arc<Dentry>, root_mnt: u64, path: &str) {
    let parent = lookup_parent(root, root_mnt, path);
    parent.inode.mkdir(parent.last_component.as_deref().unwrap(), 0o755, &CreateCtx::root())
        .expect(path);
}

fn mkdir_abs_ctx(root: Arc<Dentry>, root_mnt: u64, path: &str, mode: u32, ctx: &CreateCtx) -> InodeRef {
    let parent = lookup_parent(root, root_mnt, path);
    parent.inode.mkdir(parent.last_component.as_deref().unwrap(), mode, ctx)
        .expect(path)
}

fn create_abs(root: Arc<Dentry>, root_mnt: u64, path: &str, mode: u32) -> InodeRef {
    let parent = lookup_parent(root, root_mnt, path);
    parent.inode.create_child(parent.last_component.as_deref().unwrap(), mode, &CreateCtx::root())
        .expect(path)
}

fn create_abs_ctx(root: Arc<Dentry>, root_mnt: u64, path: &str, mode: u32, ctx: &CreateCtx) -> InodeRef {
    let parent = lookup_parent(root, root_mnt, path);
    parent.inode.create_child(parent.last_component.as_deref().unwrap(), mode, ctx)
        .expect(path)
}

#[test]
fn udev_runtime_creates_after_service_root_switch_use_tmpfs_mounts() {
    let _g = guard();
    let host = new_ns();
    let sandbox = new_ns();
    let (root, stage_id) = service_switched_root(&host, &sandbox);
    let new_root_id = vfs::mount::root_mount_id(sandbox.id()).expect("post-MS_MOVE root id");
    assert_eq!(new_root_id, stage_id,
        "MS_MOVE(stage, /) must make the moved mount the namespace root");
    let new_root = root.clone();

    let stat_run = vfs::path_lookup_at_root_cred(
        new_root.clone(), new_root_id, new_root.clone(), new_root_id,
        "/run",
        LookupFlags { no_follow_final: true, follow: false, ..Default::default() },
        Cred::root(),
    ).expect("fstatat-style /run lookup after MS_MOVE");
    assert_eq!(fs_name_for(stat_run.mnt_id), "tmpfs",
        "fstatat /run must agree with mkdirat EEXIST on tmpfs /run");

    let run = lookup_root(new_root.clone(), new_root_id, "/run");
    assert_eq!(fs_name_for(run.mnt_id), "tmpfs", "post-MS_MOVE /run must cross into tmpfs");

    let queue_parent = lookup_parent(new_root.clone(), new_root_id, "/run/udev/queue");
    assert_eq!(fs_name_for(queue_parent.mnt_id), "tmpfs", "openat-create /run/udev/queue must stay on tmpfs");
    queue_parent.inode.create_child(queue_parent.last_component.as_deref().unwrap(), 0o644, &CreateCtx::root())
        .expect("tmpfs create /run/udev/queue");

    let data_parent = lookup_parent(new_root.clone(), new_root_id, "/run/udev/data");
    assert_eq!(fs_name_for(data_parent.mnt_id), "tmpfs", "mkdirat /run/udev/data must stay on tmpfs");
    data_parent.inode.mkdir(data_parent.last_component.as_deref().unwrap(), 0o755, &CreateCtx::root())
        .expect("tmpfs mkdir /run/udev/data");

    let journal_parent = lookup_parent(new_root.clone(), new_root_id, "/run/systemd/journal");
    assert_eq!(fs_name_for(journal_parent.mnt_id), "tmpfs",
        "RuntimeDirectory=systemd/journal parent must resolve on tmpfs /run after MS_MOVE");
    journal_parent.inode.mkdir(journal_parent.last_component.as_deref().unwrap(), 0o755, &CreateCtx::root())
        .expect("tmpfs mkdir /run/systemd/journal");
    let journal = lookup_root(new_root.clone(), new_root_id, "/run/systemd/journal");
    assert_eq!(fs_name_for(journal.mnt_id), "tmpfs",
        "fstatat /run/systemd/journal must see the tmpfs RuntimeDirectory target");

    let char_parent = lookup_parent(new_root.clone(), new_root_id, "/dev/char/.#c226:0");
    assert_eq!(fs_name_for(char_parent.mnt_id), "tmpfs", "symlink /dev/char temp must stay on tmpfs");
    char_parent.inode.symlink_child(char_parent.last_component.as_deref().unwrap(), b"../dri/card0", &CreateCtx::root())
        .expect("tmpfs symlink /dev/char temp");

    let block_parent = lookup_parent(new_root.clone(), new_root_id, "/dev/block/.#b253:0");
    assert_eq!(fs_name_for(block_parent.mnt_id), "tmpfs", "symlink /dev/block temp must stay on tmpfs");
    block_parent.inode.symlink_child(block_parent.last_component.as_deref().unwrap(), b"../vda", &CreateCtx::root())
        .expect("tmpfs symlink /dev/block temp");
}

#[test]
fn udev_db_and_seat_tag_materialize_after_service_root_switch() {
    let _g = guard();
    boot_hosted_pmm();
    let host = new_ns();
    let sandbox = new_ns();
    let (root, root_mnt) = service_switched_root(&host, &sandbox);

    mkdir_abs(root.clone(), root_mnt, "/run/udev/data");
    let tmp = "/run/udev/data/.#c226:0baa2a261115984a9";
    let final_db = "/run/udev/data/c226:0";
    let inode = create_abs(root.clone(), root_mnt, tmp, 0o600);
    let db_body = b"G:master-of-seat\nQ:master-of-seat\nV:259\n";
    assert_eq!(inode.write(0, db_body).expect("write udev db"), db_body.len());
    inode.set_perm(0o644).expect("chmod udev db temp");
    let old_parent = lookup_parent(root.clone(), root_mnt, tmp);
    let new_parent = lookup_parent(root.clone(), root_mnt, final_db);
    old_parent.inode.rename_child(
        old_parent.last_component.as_deref().unwrap(),
        &new_parent.inode,
        new_parent.last_component.as_deref().unwrap(),
        0,
        &CreateCtx::root(),
    ).expect("rename temp db to final db");
    let db = lookup_root(root.clone(), root_mnt, final_db);
    assert_eq!(fs_name_for(db.mnt_id), "tmpfs", "udev db final name must live on tmpfs /run");
    let mut body = [0u8; 64];
    let n = db.inode.read(0, &mut body).expect("read final udev db");
    assert_eq!(&body[..n], db_body);
    assert!(vfs::path_lookup_at_root_cred(
        root.clone(), root_mnt, root.clone(), root_mnt, tmp,
        LookupFlags::default(), Cred::root(),
    ).is_err(), "temp database name must be gone after rename");

    mkdir_abs(root.clone(), root_mnt, "/run/udev/tags");
    mkdir_abs(root.clone(), root_mnt, "/run/udev/tags/master-of-seat");
    let tag = create_abs(root.clone(), root_mnt, "/run/udev/tags/master-of-seat/c226:0", 0o444);
    assert_eq!(tag.file_type(), FileType::Regular);
    let tag_path = lookup_root(root.clone(), root_mnt, "/run/udev/tags/master-of-seat/c226:0");
    assert_eq!(fs_name_for(tag_path.mnt_id), "tmpfs", "udev seat tag must live on tmpfs /run");
}

#[test]
fn udev_db_written_in_one_service_namespace_is_visible_to_another() {
    let _g = guard();
    boot_hosted_pmm();
    let host = new_ns();
    let udev_ns = new_ns();
    let logind_ns = new_ns();
    let late_ns = new_ns();

    vfs::mount::set_current_ns_provider(cur_ns);
    let (root, _run_fs, _dev_fs) = setup_host(&host);

    let (udev_root, udev_root_mnt) = switch_prepared_host_root(root.clone(), &host, &udev_ns);
    let (logind_root, logind_root_mnt) = switch_prepared_host_root(root.clone(), &host, &logind_ns);

    set_ns(&udev_ns);
    mkdir_abs(udev_root.clone(), udev_root_mnt, "/run/udev/data");
    mkdir_abs(udev_root.clone(), udev_root_mnt, "/run/udev/tags");
    mkdir_abs(udev_root.clone(), udev_root_mnt, "/run/udev/tags/seat");
    mkdir_abs(udev_root.clone(), udev_root_mnt, "/run/udev/tags/uaccess");
    mkdir_abs(udev_root.clone(), udev_root_mnt, "/run/udev/tags/master-of-seat");

    let tmp = "/run/udev/data/.#c226:0aa55aa55aa55aa55";
    let final_db = "/run/udev/data/c226:0";
    let db_body = b"G:seat\nG:uaccess\nG:master-of-seat\nQ:seat\nQ:uaccess\nQ:master-of-seat\nV:259\n";
    let tmp_inode = create_abs(udev_root.clone(), udev_root_mnt, tmp, 0o600);
    assert_eq!(tmp_inode.write(0, db_body).expect("write temp udev db"), db_body.len());
    tmp_inode.set_perm(0o644).expect("chmod temp udev db");
    let old_parent = lookup_parent(udev_root.clone(), udev_root_mnt, tmp);
    let new_parent = lookup_parent(udev_root.clone(), udev_root_mnt, final_db);
    old_parent.inode.rename_child(
        old_parent.last_component.as_deref().unwrap(),
        &new_parent.inode,
        new_parent.last_component.as_deref().unwrap(),
        0,
        &CreateCtx::root(),
    ).expect("rename temp udev db across same tmpfs dir");

    let db = lookup_root(udev_root.clone(), udev_root_mnt, final_db);
    let hard_parent = lookup_parent(udev_root.clone(), udev_root_mnt, "/run/udev/data/by-card0");
    hard_parent.inode.link_child(&db.inode, hard_parent.last_component.as_deref().unwrap(), &CreateCtx::root())
        .expect("hardlink db alias in tmpfs");
    let link_parent = lookup_parent(udev_root.clone(), udev_root_mnt, "/run/udev/card0-db");
    link_parent.inode.symlink_child(link_parent.last_component.as_deref().unwrap(), b"data/c226:0", &CreateCtx::root())
        .expect("relative symlink into /run/udev/data");
    create_abs(udev_root.clone(), udev_root_mnt, "/run/udev/tags/seat/c226:0", 0o444);
    create_abs(udev_root.clone(), udev_root_mnt, "/run/udev/tags/uaccess/c226:0", 0o444);
    create_abs(udev_root.clone(), udev_root_mnt, "/run/udev/tags/master-of-seat/c226:0", 0o444);

    assert!(vfs::path_lookup_at_root_cred(
        udev_root.clone(), udev_root_mnt, udev_root.clone(), udev_root_mnt, tmp,
        LookupFlags::default(), Cred::root(),
    ).is_err(), "rename must remove the temp udev db name");
    assert_eq!(read_abs(udev_root.clone(), udev_root_mnt, final_db), db_body);
    assert_eq!(read_abs(udev_root.clone(), udev_root_mnt, "/run/udev/data/by-card0"), db_body);
    assert_eq!(read_abs(udev_root.clone(), udev_root_mnt, "/run/udev/card0-db"), db_body);
    assert_eq!(db.inode.nlink(), 2, "hardlink alias must share and bump the tmpfs inode link count");

    set_ns(&logind_ns);
    let logind_db = lookup_root(logind_root.clone(), logind_root_mnt, final_db);
    assert_eq!(fs_name_for(logind_db.mnt_id), "tmpfs",
        "logind namespace must resolve /run/udev/data through the shared tmpfs, not ext4 underlay");
    assert_eq!(read_abs(logind_root.clone(), logind_root_mnt, final_db), db_body,
        "logind namespace must see the udev worker's renamed device database");
    assert_eq!(read_abs(logind_root.clone(), logind_root_mnt, "/run/udev/data/by-card0"), db_body,
        "hardlink alias must resolve to the same tmpfs inode from another namespace");
    assert_eq!(read_abs(logind_root.clone(), logind_root_mnt, "/run/udev/card0-db"), db_body,
        "relative symlink must resolve from another namespace without losing mount identity");
    let logind_tag = lookup_root(logind_root.clone(), logind_root_mnt, "/run/udev/tags/master-of-seat/c226:0");
    assert_eq!(fs_name_for(logind_tag.mnt_id), "tmpfs",
        "logind namespace must see the master-of-seat tag on tmpfs /run");

    let service_uid = user_cred(1000, 1000);
    let other_uid = user_cred(1001, 1001);
    set_ns(&udev_ns);
    mkdir_abs(udev_root.clone(), udev_root_mnt, "/run/user");
    let user_ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &service_uid, umask: 0o077 };
    let user_dir = mkdir_abs_ctx(udev_root.clone(), udev_root_mnt, "/run/user/1000", 0o777, &user_ctx);
    assert_eq!((user_dir.uid(), user_dir.gid(), user_dir.perm()), (Some(1000), Some(1000), Some(0o700)),
        "tmpfs mkdir must stamp caller ownership and apply umask");
    let secret = create_abs_ctx(udev_root.clone(), udev_root_mnt, "/run/user/1000/secret", 0o666, &user_ctx);
    assert_eq!((secret.uid(), secret.gid(), secret.perm()), (Some(1000), Some(1000), Some(0o600)),
        "tmpfs create must stamp caller ownership and apply umask");
    assert!(vfs::may_open(&secret, true, true, &service_uid).is_ok(),
        "file owner must have rw access to a 0600 file");
    assert!(matches!(vfs::may_open(&secret, true, false, &other_uid), Err(VfsError::Eacces)),
        "unrelated user must not read another user's 0600 runtime file");

    let sticky = mkdir_abs_ctx(udev_root.clone(), udev_root_mnt, "/run/sticky", 0o777, &CreateCtx::root());
    sticky.set_perm(0o1777).expect("chmod sticky dir");
    let victim = create_abs_ctx(udev_root.clone(), udev_root_mnt, "/run/sticky/user-owned", 0o666, &user_ctx);
    assert_eq!((sticky.uid(), sticky.gid(), sticky.perm()), (Some(0), Some(0), Some(0o1777)),
        "sticky directory must preserve root ownership and S_ISVTX");
    assert_eq!((victim.uid(), victim.gid(), victim.perm()), (Some(1000), Some(1000), Some(0o600)),
        "sticky-dir child must preserve creator ownership");
    assert!(matches!(vfs::namei::may_delete(&sticky, &victim, false, &other_uid), Err(VfsError::Eperm)),
        "sticky directory must block deletion by a non-owner user");
    assert!(vfs::namei::may_delete(&sticky, &victim, false, &service_uid).is_ok(),
        "sticky directory must allow deletion by the victim owner");
    assert!(vfs::namei::may_delete(&sticky, &victim, false, &Cred::root()).is_ok(),
        "sticky directory must allow deletion by CAP_FOWNER/root");

    set_ns(&logind_ns);
    let logind_user_dir = lookup_root(logind_root.clone(), logind_root_mnt, "/run/user/1000");
    assert_eq!((logind_user_dir.inode.uid(), logind_user_dir.inode.gid(), logind_user_dir.inode.perm()),
        (Some(1000), Some(1000), Some(0o700)),
        "service runtime directory ownership/mode must be visible from another namespace");
    let logind_secret = lookup_root(logind_root.clone(), logind_root_mnt, "/run/user/1000/secret");
    assert_eq!((logind_secret.inode.uid(), logind_secret.inode.gid(), logind_secret.inode.perm()),
        (Some(1000), Some(1000), Some(0o600)),
        "user-owned file metadata must survive cross-namespace lookup");
    assert!(matches!(vfs::may_open(&logind_secret.inode, true, false, &other_uid), Err(VfsError::Eacces)),
        "cross-namespace lookup must not bypass mode/owner permissions");
    let logind_sticky = lookup_root(logind_root.clone(), logind_root_mnt, "/run/sticky");
    let logind_victim = lookup_root(logind_root.clone(), logind_root_mnt, "/run/sticky/user-owned");
    assert!(matches!(vfs::namei::may_delete(&logind_sticky.inode, &logind_victim.inode, false, &other_uid),
        Err(VfsError::Eperm)),
        "sticky deletion decision must be identical from the peer namespace");

    set_ns(&host);
    let host_root_mnt = vfs::mount::root_mount_id(host.id()).expect("host root id");
    assert_eq!(read_abs(root.clone(), host_root_mnt, final_db), db_body,
        "host namespace must also see the file because copy_mnt_ns shares the tmpfs superblock");

    let (late_root, late_root_mnt) = switch_prepared_host_root(root.clone(), &host, &late_ns);
    set_ns(&late_ns);
    assert_eq!(read_abs(late_root.clone(), late_root_mnt, final_db), db_body,
        "a namespace copied after udev processing must inherit the same visible tmpfs contents");
    let late_tag = lookup_root(late_root, late_root_mnt, "/run/udev/tags/master-of-seat/c226:0");
    assert_eq!(fs_name_for(late_tag.mnt_id), "tmpfs",
        "late service namespace must inherit the master-of-seat tag mount identity");
}
