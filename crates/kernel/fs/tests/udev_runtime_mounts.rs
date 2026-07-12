use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use fs::tmpfs::TmpfsFs;
use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{default_file_ops, mk_mode, CreateCtx, Cred, Dentry, FileType, InodeBuilder, InodeOps};
use vfs::{InodeRef, KResult, LookupFlags, VfsError};
use vfs::mount::Propagation;

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: AtomicU64 = AtomicU64::new(0);
static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
static HOST_ROOT_INODE: OnceLock<InodeRef> = OnceLock::new();

fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }
fn cur_ns() -> u64 { CUR_NS.load(Ordering::Acquire) }
fn set_ns(ns: u64) { CUR_NS.store(ns, Ordering::Release); }
fn root_provider() -> Option<Arc<Dentry>> { ROOT.get().cloned() }

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

fn setup_host(host: u64) -> (Arc<Dentry>, Arc<TmpfsFs>, Arc<TmpfsFs>) {
    set_ns(host);
    let dev_underlay = ext4_dir(0x17, &[("char", ext4_dir(0x18, &[])), ("block", ext4_dir(0x19, &[]))]);
    let root_inode = ext4_dir(2, &[("run", ext4_dir(0x13, &[])), ("dev", dev_underlay),
        ("proc", ext4_dir(0x15, &[])), ("sys", ext4_dir(0x16, &[])), ("etc", ext4_dir(0x14, &[]))]);
    let root = ROOT.get_or_init(|| Dentry::new_root(root_inode.clone())).clone();
    let _ = HOST_ROOT_INODE.set(root_inode.clone());
    vfs::set_root_dentry_provider(root_provider);
    vfs::mount::register(None, Arc::new(NamedFs { n: "ext4", root: root_inode })).expect("root mount");

    let root_id = vfs::mount::root_mount_id(host).expect("root id");
    let run_mp = lookup_root(root.clone(), root_id, "/run").dentry;
    let run_fs = TmpfsFs::new(String::from("run"));
    vfs::mount::register(Some(run_mp), run_fs.clone()).expect("mount /run tmpfs");
    let run_root = run_fs.root_inode();
    let systemd = run_root.mkdir("systemd", 0o755, &CreateCtx::root()).expect("mkdir /run/systemd");
    systemd.mkdir("mount-rootfs", 0o755, &CreateCtx::root()).expect("mkdir mount-rootfs");
    run_root.mkdir("udev", 0o755, &CreateCtx::root()).expect("mkdir /run/udev");

    let dev_mp = lookup_root(root.clone(), root_id, "/dev").dentry;
    let dev_fs = TmpfsFs::new(String::from("dev"));
    vfs::mount::register(Some(dev_mp), dev_fs.clone()).expect("mount /dev tmpfs");
    let dev_root = dev_fs.root_inode();
    dev_root.mkdir("char", 0o755, &CreateCtx::root()).expect("mkdir /dev/char");
    dev_root.mkdir("block", 0o755, &CreateCtx::root()).expect("mkdir /dev/block");
    (root, run_fs, dev_fs)
}

#[test]
fn udev_runtime_creates_after_service_root_switch_use_tmpfs_mounts() {
    let _g = guard();
    let host: u64 = 0x7130_1000;
    let sandbox: u64 = 0x7130_1001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let (root, _run_fs, _dev_fs) = setup_host(host);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    vfs::mount::copy_mnt_ns(host, sandbox);
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let source_root = vfs::mount::root_mount_id(sandbox).expect("source root id");
    let stage = lookup_root(root.clone(), source_root, "/run/systemd/mount-rootfs");
    vfs::mount::register_bind_clone_at(Some(stage.dentry.clone()), source_root, root.clone(), Some(stage.mnt_id))
        .expect("bind-clone / to stage");
    let stage_id = vfs::mount::mount_at_path_exact(&stage.dentry).expect("stage mount").mnt_id;
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage.dentry, Some(stage.mnt_id));
    vfs::mount::move_mount_by_id(stage_id, &root).expect("MS_MOVE stage to /");
    let new_root_id = stage_id;
    let new_root = root.clone();

    let run = lookup_root(new_root.clone(), new_root_id, "/run");
    assert_eq!(fs_name_for(run.mnt_id), "tmpfs", "post-MS_MOVE /run must cross into tmpfs");

    let queue_parent = lookup_parent(new_root.clone(), new_root_id, "/run/udev/queue");
    assert_eq!(fs_name_for(queue_parent.mnt_id), "tmpfs", "openat-create /run/udev/queue hit ext4 underlay");
    queue_parent.inode.create_child(queue_parent.last_component.as_deref().unwrap(), 0o644, &CreateCtx::root())
        .expect("tmpfs create /run/udev/queue");

    let data_parent = lookup_parent(new_root.clone(), new_root_id, "/run/udev/data");
    assert_eq!(fs_name_for(data_parent.mnt_id), "tmpfs", "mkdirat /run/udev/data hit ext4 underlay");
    data_parent.inode.mkdir(data_parent.last_component.as_deref().unwrap(), 0o755, &CreateCtx::root())
        .expect("tmpfs mkdir /run/udev/data");

    let char_parent = lookup_parent(new_root.clone(), new_root_id, "/dev/char/.#c226:0");
    assert_eq!(fs_name_for(char_parent.mnt_id), "tmpfs", "symlink /dev/char temp hit ext4 underlay");
    char_parent.inode.symlink_child(char_parent.last_component.as_deref().unwrap(), b"../dri/card0", &CreateCtx::root())
        .expect("tmpfs symlink /dev/char temp");

    let block_parent = lookup_parent(new_root.clone(), new_root_id, "/dev/block/.#b253:0");
    assert_eq!(fs_name_for(block_parent.mnt_id), "tmpfs", "symlink /dev/block temp hit ext4 underlay");
    block_parent.inode.symlink_child(block_parent.last_component.as_deref().unwrap(), b"../vda", &CreateCtx::root())
        .expect("tmpfs symlink /dev/block temp");
}
