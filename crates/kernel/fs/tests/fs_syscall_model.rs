use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use boot_info::{BootInfo, BootMemKind, BootMemRegion};
use fs::tmpfs::TmpfsFs;
use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::Propagation;
use vfs::{default_file_ops, mk_mode, CreateCtx, Cred, Dentry, FileType, InodeBuilder, InodeOps};
use vfs::{FileSystemType, InodeRef, KResult, LookupFlags, SuperBlock, VfsError, VfsPath};

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);
static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
static HOST_ROOT_INODE: OnceLock<InodeRef> = OnceLock::new();
static PMM: OnceLock<()> = OnceLock::new();
const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_EMPTY_PATH: u32 = 0x1000;
const AT_CHMOD_CHOWN_VALID: u32 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
const HOSTED_PMM_POOL: usize = 16 * 1024 * 1024;
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }
fn cur_ns() -> vfs::mntns::MntNamespaceRef {
    CUR_NS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().expect("current namespace owner").clone() }
fn set_ns(namespace: &vfs::mntns::MntNamespaceRef) {
    *CUR_NS.lock().unwrap_or_else(|e| e.into_inner()) = Some(namespace.clone()); }
fn new_ns() -> vfs::mntns::MntNamespaceRef {
    let init = vfs::mntns::initial();
    vfs::mntns::allocate(init.owner_user_namespace()).expect("allocate mount namespace") }
fn root_provider() -> Option<Arc<Dentry>> { ROOT.get().cloned() }

fn boot_hosted_pmm() {
    PMM.get_or_init(|| {
        let layout = std::alloc::Layout::from_size_align(HOSTED_PMM_POOL, 4096).unwrap();
        // SAFETY: non-zero, page-aligned host allocation leaked for test lifetime.
        let buf = unsafe { std::alloc::alloc_zeroed(layout) } as u64;
        assert!(buf != 0, "hosted PMM pool allocation failed");
        let regions = [BootMemRegion { base_pa: 0, len: HOSTED_PMM_POOL as u64, kind: BootMemKind::Usable }];
        let info = BootInfo { memmap_count: 1, memmap_ptr: regions.as_ptr(), seed: [0u8; 32],
            boot_ns: 0, rsdp_pa: 0, hhdm_offset: buf, smp_info_array: 0, smp_count: 0,
            bsp_lapic_id: 0, _pad: 0 };
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
        Err(VfsError::Eio) }
    fn mkdir(&self, _inode: &Inode, _name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        Err(VfsError::Eio) }
    fn symlink(&self, _inode: &Inode, _name: &str, _target: &[u8], _ctx: &CreateCtx) -> KResult<()> {
        Err(VfsError::Eio) }
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

fn setup_host(host: &vfs::mntns::MntNamespaceRef) -> Arc<Dentry> {
    set_ns(host);
    let dev_underlay = ext4_dir(0x17, &[("char", ext4_dir(0x18, &[])), ("block", ext4_dir(0x19, &[]))]);
    let root_inode = ext4_dir(2, &[("run", ext4_dir(0x13, &[])), ("dev", dev_underlay),
        ("proc", ext4_dir(0x15, &[])), ("sys", ext4_dir(0x16, &[])), ("etc", ext4_dir(0x14, &[]))]);
    let root = ROOT.get_or_init(|| Dentry::new_root(root_inode.clone())).clone();
    let _ = HOST_ROOT_INODE.set(root_inode.clone());
    vfs::set_root_dentry_provider(root_provider);
    vfs::mount::register_typed(fs_type("ext4"), None, Arc::new(NamedFs { n: "ext4", root: root_inode })).expect("root mount");
    let root_id = vfs::mount::root_mount_id(host.id()).expect("root id");
    let run_mp = lookup_at(&root, root_id, &root, root_id, "/run", LookupFlags::default()).dentry;
    let run_fs = TmpfsFs::new(String::from("run"));
    vfs::mount::register_typed(fs_type("tmpfs"), Some(run_mp), run_fs.clone()).expect("mount /run tmpfs");
    let run_root = run_fs.root_inode();
    let systemd = run_root.mkdir("systemd", 0o755, &CreateCtx::root()).expect("mkdir /run/systemd");
    systemd.mkdir("mount-rootfs", 0o755, &CreateCtx::root()).expect("mkdir mount-rootfs");
    run_root.mkdir("udev", 0o755, &CreateCtx::root()).expect("mkdir /run/udev");
    let dev_mp = lookup_at(&root, root_id, &root, root_id, "/dev", LookupFlags::default()).dentry;
    let dev_fs = TmpfsFs::new(String::from("dev"));
    vfs::mount::register_typed(fs_type("tmpfs"), Some(dev_mp), dev_fs.clone()).expect("mount /dev tmpfs");
    let dev_root = dev_fs.root_inode();
    dev_root.mkdir("char", 0o755, &CreateCtx::root()).expect("mkdir /dev/char");
    dev_root.mkdir("block", 0o755, &CreateCtx::root()).expect("mkdir /dev/block");
    root
}

fn lookup_at(start: &Arc<Dentry>, start_mnt: u64, root: &Arc<Dentry>, root_mnt: u64,
    path: &str, flags: LookupFlags) -> VfsPath {
    vfs::path_lookup_at_root_cred(start.clone(), start_mnt, root.clone(), root_mnt, path, flags, Cred::root())
        .expect(path) }
fn fs_name_for(mnt_id: u64) -> String {
    vfs::mount::mount_by_id(mnt_id).expect("mount id").sb.s_type.name().to_string() }

fn switch_prepared_host_root(root: Arc<Dentry>, host: &vfs::mntns::MntNamespaceRef,
    sandbox: &vfs::mntns::MntNamespaceRef) -> u64 {
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    vfs::mount::copy_mnt_ns(host, sandbox).expect("copy mount namespace");
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");
    let source_root = vfs::mount::root_mount_id(sandbox.id()).expect("source root id");
    let stage = lookup_at(&root, source_root, &root, source_root, "/run/systemd/mount-rootfs", LookupFlags::default());
    vfs::mount::register_bind_clone_at(Some(stage.dentry.clone()), source_root, root.clone(), Some(stage.mnt_id))
        .expect("bind-clone / to stage");
    let stage_id = vfs::mount::mount_at_path_exact(&stage.dentry).expect("stage mount").mnt_id;
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage.dentry, Some(stage.mnt_id));
    vfs::mount::move_mount_by_id(stage_id, &root).expect("MS_MOVE stage to /");
    stage_id
}

#[derive(Clone)]
struct Fd { p: VfsPath, _readable: bool, writable: bool }
struct Proc {
    namespace: vfs::mntns::MntNamespaceRef,
    root: Arc<Dentry>,
    root_mnt: u64,
    cwd: Arc<Dentry>,
    cwd_mnt: u64,
    cred: Cred,
    umask: u16,
    fds: Vec<Option<Fd>>,
}
impl Proc {
    fn new(namespace: vfs::mntns::MntNamespaceRef, root: Arc<Dentry>, root_mnt: u64, cred: Cred) -> Self {
        Proc { namespace, root: root.clone(), root_mnt, cwd: root, cwd_mnt: root_mnt, cred, umask: 0, fds: Vec::new() } }
    fn enter(&self) { set_ns(&self.namespace); }
    fn start(&self, dirfd: i32) -> (Arc<Dentry>, u64) {
        if dirfd == AT_FDCWD {
            (self.cwd.clone(), self.cwd_mnt)
        } else {
            let fd = self.fds[dirfd as usize].as_ref().expect("fd");
            (fd.p.dentry.clone(), fd.p.mnt_id)
        }
    }
    fn lookup(&self, dirfd: i32, path: &str, flags: LookupFlags) -> KResult<VfsPath> {
        self.enter();
        let (s, sm) = self.start(dirfd);
        vfs::path_lookup_at_root_cred(s, sm, self.root.clone(), self.root_mnt, path, flags, self.cred.clone())
    }
    fn parent(&self, dirfd: i32, path: &str) -> KResult<VfsPath> {
        self.lookup(dirfd, path, LookupFlags { parent: true, ..Default::default() }) }
    fn install(&mut self, p: VfsPath, readable: bool, writable: bool) -> i32 {
        let fd = self.fds.len() as i32;
        self.fds.push(Some(Fd { p, _readable: readable, writable }));
        fd
    }
    fn openat(&mut self, dirfd: i32, path: &str, create: bool, mode: u32, readable: bool, writable: bool) -> KResult<i32> {
        self.enter();
        if create {
            let p = self.parent(dirfd, path)?;
            let name = p.last_component.as_deref().ok_or(VfsError::Einval)?;
            let inode = match p.inode.lookup(name) {
                Ok(i) => {
                    if i.file_type() == FileType::Directory { return Err(VfsError::Eisdir); }
                    vfs::may_create_in_sticky(&p.inode, &i, &self.cred)?;
                    vfs::may_open(&i, readable, writable, &self.cred)?;
                    i
                }
                Err(VfsError::Enoent) => {
                    vfs::may_create(&p.inode, &self.cred)?;
                    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &self.cred, umask: self.umask };
                    p.inode.create_child(name, mode, &ctx)?
                }
                Err(e) => return Err(e),
            };
            let d = match vfs::d_lookup(&p.dentry, name) {
                Some(d) if !d.is_negative() => d,
                _ => vfs::d_add(&p.dentry, name, inode.clone()),
            };
            return Ok(self.install(VfsPath { mnt_id: p.mnt_id, dentry: d, inode, last_component: None }, readable, writable));
        }
        let p = self.lookup(dirfd, path, LookupFlags::default())?;
        vfs::may_open(&p.inode, readable, writable, &self.cred)?;
        Ok(self.install(p, readable, writable))
    }
    fn mkdirat(&self, dirfd: i32, path: &str, mode: u32) -> KResult<()> {
        self.enter();
        let p = self.parent(dirfd, path)?;
        vfs::may_create(&p.inode, &self.cred)?;
        let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &self.cred, umask: self.umask };
        p.inode.mkdir(p.last_component.as_deref().unwrap(), mode, &ctx).map(|_| ())
    }
    fn write(&self, fd: i32, off: u64, buf: &[u8]) -> KResult<usize> {
        self.enter();
        let f = self.fds[fd as usize].as_ref().expect("fd");
        if !f.writable { return Err(VfsError::Ebadf); }
        f.p.inode.write(off, buf)
    }
    fn read_path(&self, path: &str) -> KResult<Vec<u8>> {
        self.enter();
        let p = self.lookup(AT_FDCWD, path, LookupFlags::default())?;
        vfs::may_open(&p.inode, true, false, &self.cred)?;
        let mut body = [0u8; 512];
        let n = p.inode.read(0, &mut body)?;
        Ok(body[..n].to_vec())
    }
    fn stat(&self, path: &str, follow: bool) -> KResult<vfs::Kstat> {
        let flags = if follow { LookupFlags::default() }
            else { LookupFlags { no_follow_final: true, follow: false, ..Default::default() } };
        let p = self.lookup(AT_FDCWD, path, flags)?;
        Ok(vfs::vfs_getattr(&p.inode, &vfs::IDENTITY))
    }
    fn access(&self, path: &str, read: bool, write: bool, exec: bool) -> KResult<()> {
        let p = self.lookup(AT_FDCWD, path, LookupFlags::default())?;
        let mut mask = 0;
        if read { mask |= vfs::MAY_READ; }
        if write { mask |= vfs::MAY_WRITE; }
        if exec { mask |= vfs::MAY_EXEC; }
        vfs::inode_permission(&p.inode, mask, &self.cred)
    }
    fn readlink(&self, path: &str) -> KResult<Vec<u8>> {
        let p = self.lookup(AT_FDCWD, path,
            LookupFlags { no_follow_final: true, follow: false, ..Default::default() })?;
        p.inode.readlink()
    }
    fn readlinkat_empty(&self, dirfd: i32) -> KResult<Vec<u8>> {
        let p = if dirfd == AT_FDCWD {
            VfsPath { mnt_id: self.cwd_mnt, dentry: self.cwd.clone(), inode: self.cwd.inode().unwrap(), last_component: None }
        } else {
            self.fds[dirfd as usize].as_ref().expect("fd").p.clone()
        };
        if p.inode.file_type() != FileType::Symlink { return Err(VfsError::Enoent); }
        p.inode.readlink()
    }
    fn truncate(&self, path: &str, size: u64) -> KResult<()> {
        let p = self.lookup(AT_FDCWD, path, LookupFlags::default())?;
        let mut ia = vfs::Iattr { valid: vfs::ATTR_SIZE, size, ..Default::default() };
        vfs::notify_change(&vfs::IDENTITY, &p.inode, &mut ia, &self.cred)
    }
    fn mknodat(&self, path: &str, mode: u16, rdev: u32) -> KResult<()> {
        self.enter();
        let t = mode & vfs::S_IFMT as u16; if t == vfs::S_IFDIR as u16 { return Err(VfsError::Eperm); }
        let p = self.parent(AT_FDCWD, path)?;
        vfs::may_create(&p.inode, &self.cred)?;
        p.inode.mknod_child(p.last_component.as_deref().unwrap(), mode, rdev,
            &CreateCtx { idmap: &vfs::IDENTITY, cred: &self.cred, umask: self.umask })
    }
    fn getdents(&self, path: &str) -> KResult<Vec<String>> {
        let p = self.lookup(AT_FDCWD, path, LookupFlags::default())?;
        let mut sink = NameSink(Vec::new());
        let mut ctx = vfs::DirContext::new(0, &mut sink);
        p.inode.readdir(&mut ctx)?;
        Ok(sink.0)
    }
    fn fchmod(&self, fd: i32, mode: u16) -> KResult<()> {
        self.enter();
        let f = self.fds[fd as usize].as_ref().expect("fd");
        vfs::may_chmod(&f.p.inode, &self.cred)?;
        f.p.inode.set_perm(vfs::chmod_sgid_strip(mode, &f.p.inode, &self.cred))
    }
    fn chmod(&self, path: &str, mode: u16) -> KResult<()> {
        let p = self.lookup(AT_FDCWD, path, LookupFlags::default())?;
        vfs::may_chmod(&p.inode, &self.cred)?;
        p.inode.set_perm(vfs::chmod_sgid_strip(mode, &p.inode, &self.cred))
    }
    fn chmodat_flags(&self, path: &str, mode: u16, flags: u32) -> KResult<()> {
        if flags & !AT_CHMOD_CHOWN_VALID != 0 { return Err(VfsError::Einval); }
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        let p = self.lookup(AT_FDCWD, path, LookupFlags { no_follow_final: !follow, follow, ..Default::default() })?;
        vfs::may_chmod(&p.inode, &self.cred)?;
        p.inode.set_perm(vfs::chmod_sgid_strip(mode, &p.inode, &self.cred))
    }
    fn fchown(&self, fd: i32, uid: u32, gid: u32) -> KResult<()> {
        self.enter();
        let f = self.fds[fd as usize].as_ref().expect("fd");
        vfs::may_chown(&f.p.inode, Some(uid), Some(gid), &self.cred)?;
        f.p.inode.set_owner(uid, gid)
    }
    fn chown(&self, path: &str, uid: u32, gid: u32) -> KResult<()> {
        let p = self.lookup(AT_FDCWD, path, LookupFlags::default())?;
        vfs::may_chown(&p.inode, Some(uid), Some(gid), &self.cred)?;
        p.inode.set_owner(uid, gid)
    }
    fn chownat_flags(&self, path: &str, uid: u32, gid: u32, flags: u32) -> KResult<()> {
        if flags & !AT_CHMOD_CHOWN_VALID != 0 { return Err(VfsError::Einval); }
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        let p = self.lookup(AT_FDCWD, path, LookupFlags { no_follow_final: !follow, follow, ..Default::default() })?;
        vfs::may_chown(&p.inode, Some(uid), Some(gid), &self.cred)?;
        p.inode.set_owner(uid, gid)
    }
    fn renameat(&self, olddir: i32, old: &str, newdir: i32, new: &str) -> KResult<()> {
        self.enter();
        let op = self.parent(olddir, old)?;
        let np = self.parent(newdir, new)?;
        let on = op.last_component.as_deref().unwrap();
        let nn = np.last_component.as_deref().unwrap();
        let victim = op.inode.lookup(on)?;
        let target = np.inode.lookup(nn).ok();
        vfs::namei::may_rename(&op.inode, &victim, &np.inode, target.as_ref(), 0, Arc::ptr_eq(&op.dentry, &np.dentry), &self.cred)?;
        op.inode.rename_child(on, &np.inode, nn, 0, &CreateCtx { idmap: &vfs::IDENTITY, cred: &self.cred, umask: self.umask })
    }
    fn linkat(&self, src: &str, dst: &str) -> KResult<()> {
        self.enter();
        let s = self.lookup(AT_FDCWD, src, LookupFlags { no_follow_final: true, follow: false, ..Default::default() })?;
        let p = self.parent(AT_FDCWD, dst)?;
        let name = p.last_component.as_deref().ok_or(VfsError::Eexist)?;
        vfs::may_create(&p.inode, &self.cred)?;
        if s.mnt_id != p.mnt_id { return Err(VfsError::Exdev); }
        p.inode.link_child(&s.inode, name, &CreateCtx { idmap: &vfs::IDENTITY, cred: &self.cred, umask: self.umask })
    }
    fn symlinkat(&self, target: &[u8], dst: &str) -> KResult<()> {
        self.enter();
        let p = self.parent(AT_FDCWD, dst)?;
        let name = p.last_component.as_deref().ok_or(VfsError::Eexist)?;
        vfs::may_create(&p.inode, &self.cred)?;
        p.inode.symlink_child(name, target, &CreateCtx { idmap: &vfs::IDENTITY, cred: &self.cred, umask: self.umask })
    }
    fn unlinkat(&self, path: &str) -> KResult<()> {
        self.enter();
        let p = self.parent(AT_FDCWD, path)?;
        let name = p.last_component.as_deref().unwrap();
        let victim = p.inode.lookup(name)?;
        if vfs::path::requires_dir(path) { return Err(if victim.file_type() == FileType::Directory { VfsError::Eisdir } else { VfsError::Enotdir }); }
        vfs::namei::may_delete(&p.inode, &victim, false, &self.cred)?;
        p.inode.unlink_child(name)
    }
    fn rmdir(&self, path: &str) -> KResult<()> {
        self.enter();
        let p = self.parent(AT_FDCWD, path)?;
        let name = p.last_component.as_deref().unwrap();
        let victim = p.inode.lookup(name)?;
        vfs::namei::may_delete(&p.inode, &victim, true, &self.cred)?;
        p.inode.rmdir(name)
    }
    fn chdir(&mut self, path: &str) -> KResult<()> {
        let p = self.lookup(AT_FDCWD, path, LookupFlags::default())?;
        if p.inode.file_type() != FileType::Directory { return Err(VfsError::Enotdir); }
        self.cwd = p.dentry; self.cwd_mnt = p.mnt_id; Ok(())
    }
    fn fchdir(&mut self, fd: i32) -> KResult<()> {
        let f = self.fds[fd as usize].as_ref().expect("fd");
        if f.p.inode.file_type() != FileType::Directory { return Err(VfsError::Enotdir); }
        self.cwd = f.p.dentry.clone(); self.cwd_mnt = f.p.mnt_id; Ok(())
    }
    fn setxattr_at(&self, dirfd: i32, path: &str, follow: bool, name: &str, value: &[u8]) -> KResult<()> {
        let flags = LookupFlags { no_follow_final: !follow, follow, ..Default::default() };
        let p = self.lookup(dirfd, path, flags)?;
        if let Some(m) = vfs::mount::mount_by_id(p.mnt_id) {
            if (m.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 { return Err(VfsError::Erofs); }
        }
        p.inode.setxattr(name, value.to_vec(), false, false).map_err(|_| VfsError::Eio)
    }
    fn getxattr_at(&self, dirfd: i32, path: &str, follow: bool, name: &str) -> KResult<Vec<u8>> {
        let flags = LookupFlags { no_follow_final: !follow, follow, ..Default::default() };
        let p = self.lookup(dirfd, path, flags)?;
        p.inode.getxattr(name).map_err(|_| VfsError::Enoent)
    }
}

fn cred(uid: u32, gid: u32) -> Cred { Cred { uid, gid, cap_dac_override: false, cap_dac_read_search: false,
    cap_fowner: false, cap_chown: false, cap_fsetid: false, groups: vfs::GroupList::empty() } }
struct NameSink(Vec<String>);
impl vfs::DirEmit for NameSink {
    fn emit(&mut self, name: &str, _ino: u64, _d_type: FileType, _next_pos: u64) -> bool { self.0.push(name.to_string()); true }
}

#[test]
fn syscall_shape_covers_udev_runtime_and_user_permissions() {
    let _g = guard();
    boot_hosted_pmm();
    let host = new_ns();
    let udev_ns = new_ns();
    let logind_ns = new_ns();
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(&host);
    let udev_root_mnt = switch_prepared_host_root(root.clone(), &host, &udev_ns);
    let logind_root_mnt = switch_prepared_host_root(root.clone(), &host, &logind_ns);
    let mut udev = Proc::new(udev_ns.clone(), root.clone(), udev_root_mnt, Cred::root());
    let logind = Proc::new(logind_ns.clone(), root.clone(), logind_root_mnt, Cred::root());
    udev.mkdirat(AT_FDCWD, "/run/udev/data", 0o755).expect("mkdir data");
    assert!(matches!(udev.mkdirat(AT_FDCWD, "/run/udev/data", 0o755), Err(VfsError::Eexist)));
    assert!(matches!(udev.mkdirat(AT_FDCWD, "/run/missing/leaf", 0o755), Err(VfsError::Enoent)));
    udev.mkdirat(AT_FDCWD, "/run/udev/tags", 0o755).expect("mkdir tags");
    udev.mkdirat(AT_FDCWD, "/run/udev/tags/master-of-seat", 0o755).expect("mkdir master tag");
    let fd = udev.openat(AT_FDCWD, "/run/udev/data/.#c226:0tmp", true, 0o600, true, true).expect("open temp");
    let body = b"G:master-of-seat\nQ:master-of-seat\nV:259\n";
    assert_eq!(udev.write(fd, 0, body).expect("write db"), body.len());
    udev.fchmod(fd, 0o644).expect("fchmod db");
    udev.renameat(AT_FDCWD, "/run/udev/data/.#c226:0tmp", AT_FDCWD, "/run/udev/data/c226:0").expect("rename db");
    udev.linkat("/run/udev/data/c226:0", "/run/udev/data/by-card0").expect("link db");
    udev.symlinkat(b"data/c226:0", "/run/udev/card0-db").expect("symlink db");
    assert!(matches!(udev.linkat("/run/udev/data/c226:0", "/"), Err(VfsError::Eexist)));
    udev.mkdirat(AT_FDCWD, "/run/udev/binddata", 0o755).expect("mkdir binddata");
    let data_path = udev.lookup(AT_FDCWD, "/run/udev/data", LookupFlags::default()).expect("data path");
    let bind_mp = udev.lookup(AT_FDCWD, "/run/udev/binddata", LookupFlags::default()).expect("binddata path");
    vfs::mount::register_bind_clone_at(Some(bind_mp.dentry.clone()), data_path.mnt_id, data_path.dentry.clone(), Some(bind_mp.mnt_id)).expect("bind clone data");
    assert!(matches!(udev.linkat("/run/udev/data/c226:0", "/run/udev/binddata/cross"), Err(VfsError::Exdev)));
    udev.openat(AT_FDCWD, "/run/udev/tags/master-of-seat/c226:0", true, 0o444, true, true).expect("tag");

    let db = udev.lookup(AT_FDCWD, "/run/udev/data/c226:0", LookupFlags::default()).expect("db");
    assert_eq!(fs_name_for(db.mnt_id), "tmpfs");
    assert_eq!(db.inode.nlink(), 2);
    assert_eq!(logind.read_path("/run/udev/data/c226:0").expect("logind reads db"), body);
    assert_eq!(logind.read_path("/run/udev/data/by-card0").expect("logind reads hardlink"), body);
    assert_eq!(logind.read_path("/run/udev/card0-db").expect("logind reads symlink"), body);
    assert_eq!(logind.readlink("/run/udev/card0-db").expect("readlink symlink"), b"data/c226:0");
    assert!(matches!(udev.symlinkat(b"x", "/"), Err(VfsError::Eexist)));
    assert!(matches!(logind.readlink("/run/udev/data/c226:0"), Err(VfsError::Einval)));
    let link_path = udev.lookup(AT_FDCWD, "/run/udev/card0-db", LookupFlags { no_follow_final: true, follow: false, ..Default::default() }).expect("link path");
    let link_fd = udev.install(link_path, true, false);
    assert_eq!(udev.readlinkat_empty(link_fd).expect("empty symlink fd"), b"data/c226:0");
    assert!(matches!(udev.readlinkat_empty(fd), Err(VfsError::Enoent)));
    assert!(matches!(udev.readlinkat_empty(AT_FDCWD), Err(VfsError::Enoent)));
    assert_eq!(logind.stat("/run/udev/card0-db", false).expect("lstat symlink").mode & vfs::S_IFMT, vfs::S_IFLNK);
    assert_eq!(logind.stat("/run/udev/card0-db", true).expect("stat symlink").mode & vfs::S_IFMT, vfs::S_IFREG);
    udev.setxattr_at(AT_FDCWD, "/run/udev/card0-db", true, "user.follow", b"target").expect("xattr follows final symlink");
    assert_eq!(udev.getxattr_at(AT_FDCWD, "/run/udev/data/c226:0", true, "user.follow").expect("target xattr"), b"target");
    udev.setxattr_at(AT_FDCWD, "/run/udev/card0-db", false, "user.nofollow", b"link").expect("xattr nofollow hits symlink");
    assert_eq!(udev.getxattr_at(AT_FDCWD, "/run/udev/card0-db", false, "user.nofollow").expect("symlink xattr"), b"link");
    let tag = logind.lookup(AT_FDCWD, "/run/udev/tags/master-of-seat/c226:0", LookupFlags::default()).expect("tag visible");
    assert_eq!(fs_name_for(tag.mnt_id), "tmpfs");
    let data_names = logind.getdents("/run/udev/data").expect("getdents data");
    assert!(data_names.iter().any(|n| n == "c226:0") && data_names.iter().any(|n| n == "by-card0"));
    assert!(matches!(logind.unlinkat("/run/udev/data"), Err(VfsError::Eisdir)));
    assert!(matches!(logind.rmdir("/run/udev/data"), Err(VfsError::Enotempty)));
    let user = cred(1000, 1000); let other = cred(1001, 1001);
    let mut user_proc = Proc::new(udev_ns, root.clone(), udev_root_mnt, user);
    user_proc.umask = 0o077;
    udev.mkdirat(AT_FDCWD, "/run/user", 0o755).expect("mkdir /run/user");
    udev.mkdirat(AT_FDCWD, "/run/user/1000", 0o700).expect("root creates user runtime");
    let user_dir_fd = udev.openat(AT_FDCWD, "/run/user/1000", false, 0, true, false).expect("open user runtime");
    udev.fchown(user_dir_fd, 1000, 1000).expect("chown user runtime");
    let secret_fd = user_proc.openat(AT_FDCWD, "/run/user/1000/secret", true, 0o666, true, true).expect("secret");
    let secret = user_proc.fds[secret_fd as usize].as_ref().unwrap().p.inode.clone();
    assert_eq!((secret.uid(), secret.gid(), secret.perm()), (Some(1000), Some(1000), Some(0o600)));
    let mut other_proc = Proc::new(logind_ns, root.clone(), logind_root_mnt, other);
    assert!(matches!(other_proc.read_path("/run/user/1000/secret"), Err(VfsError::Eacces)));
    assert!(matches!(other_proc.mkdirat(AT_FDCWD, "/run/user/1000/nope", 0o755), Err(VfsError::Eacces)));
    assert!(matches!(other_proc.symlinkat(b"x", "/run/user/1000/nope-sym"), Err(VfsError::Eacces)));
    assert!(matches!(other_proc.mknodat("/run/user/1000/nope-node", vfs::S_IFIFO as u16 | 0o600, 0), Err(VfsError::Eacces)));
    assert!(matches!(other_proc.access("/run/user/1000/secret", true, false, false), Err(VfsError::Eacces)));
    assert!(matches!(other_proc.truncate("/run/user/1000/secret", 0), Err(VfsError::Eacces)));
    assert!(matches!(other_proc.chmod("/run/udev/data/c226:0", 0o600), Err(VfsError::Eperm)));
    other_proc.openat(AT_FDCWD, "/run/udev/data/c226:0", true, 0o600, true, false).expect("O_CREAT existing skips parent write");
    assert!(matches!(other_proc.chown("/run/udev/data/c226:0", 1001, 1001), Err(VfsError::Eperm)));
    assert!(matches!(udev.chmodat_flags("/run/udev/data/c226:0", 0o600, 0x8000_0000), Err(VfsError::Einval)));
    assert_eq!(udev.stat("/run/udev/data/c226:0", true).expect("bad chmodat flags did not mutate").mode & 0o777, 0o644);
    assert!(matches!(udev.chownat_flags("/run/udev/data/c226:0", 4242, 4242, 0x8000_0000), Err(VfsError::Einval)));
    let unchanged = udev.lookup(AT_FDCWD, "/run/udev/data/c226:0", LookupFlags::default()).expect("bad chownat flags lookup").inode;
    assert_eq!((unchanged.uid(), unchanged.gid()), (Some(0), Some(0)));

    udev.mkdirat(AT_FDCWD, "/run/sticky", 0o777).expect("mkdir sticky");
    let sticky = udev.lookup(AT_FDCWD, "/run/sticky", LookupFlags::default()).expect("sticky");
    sticky.inode.set_perm(0o1777).expect("chmod sticky");
    let owned = user_proc.openat(AT_FDCWD, "/run/sticky/owned", true, 0o666, true, true).expect("owned");
    user_proc.fchmod(owned, 0o600).expect("chmod owned");
    assert!(matches!(other_proc.openat(AT_FDCWD, "/run/sticky/owned", true, 0o600, true, false), Err(VfsError::Eacces)));
    assert!(matches!(other_proc.openat(AT_FDCWD, "/run/sticky", true, 0o600, true, false), Err(VfsError::Eisdir)));
    user_proc.openat(AT_FDCWD, "/run/sticky/owned", true, 0o600, true, true).expect("owner O_CREAT existing in sticky");
    assert!(matches!(other_proc.unlinkat("/run/sticky/owned"), Err(VfsError::Eperm)));
    assert!(matches!(user_proc.unlinkat("/run/sticky/owned/"), Err(VfsError::Enotdir)));
    user_proc.unlinkat("/run/sticky/owned").expect("owner unlink in sticky");
    udev.mkdirat(AT_FDCWD, "/run/sticky/empty", 0o755).expect("mkdir empty sticky child");
    assert!(matches!(udev.unlinkat("/run/sticky/empty/"), Err(VfsError::Eisdir)));
    assert!(matches!(udev.unlinkat("/run/sticky/empty"), Err(VfsError::Eisdir)));
    udev.rmdir("/run/sticky/empty").expect("rmdir empty dir");
    assert!(matches!(udev.rmdir("/run/sticky/empty"), Err(VfsError::Enoent)));

    udev.mknodat("/run/devnull", vfs::S_IFCHR as u16 | 0o600, vfs::Devt::new(1, 3).raw()).expect("mknod char");
    assert!(matches!(udev.mknodat("/run/dirnode", vfs::S_IFDIR as u16 | 0o700, 0), Err(VfsError::Eperm)));
    let devnull = udev.stat("/run/devnull", false).expect("stat mknod");
    assert_eq!(devnull.mode & vfs::S_IFMT, vfs::S_IFCHR);

    let dirfd = udev.openat(AT_FDCWD, "/run/udev", false, 0, true, false).expect("open dir");
    udev.setxattr_at(dirfd, "data/c226:0", true, "user.dirfd", b"mounted").expect("dirfd-relative xattr");
    assert_eq!(udev.getxattr_at(AT_FDCWD, "/run/udev/data/c226:0", true, "user.dirfd").expect("dirfd xattr visible"), b"mounted");
    udev.fchdir(dirfd).expect("fchdir /run/udev");
    assert_eq!(udev.read_path("data/c226:0").expect("relative cwd read after fchdir"), body);
    udev.chdir("/run").expect("chdir /run");
    assert_eq!(udev.read_path("udev/data/c226:0").expect("relative cwd read after chdir"), body);

    udev.unlinkat("/run/udev/data/by-card0").expect("unlink hardlink");
    assert_eq!(udev.lookup(AT_FDCWD, "/run/udev/data/c226:0", LookupFlags::default()).expect("db remains").inode.nlink(), 1);
    udev.truncate("/run/udev/data/c226:0", 7).expect("truncate final db");
    assert_eq!(logind.read_path("/run/udev/data/c226:0").expect("truncated db visible"), b"G:maste");
    let db_mnt = udev.lookup(AT_FDCWD, "/run/udev/data/c226:0", LookupFlags::default()).expect("db mnt").mnt_id;
    let m = vfs::mount::mount_by_id(db_mnt).expect("db mount");
    m.flags.fetch_or(vfs::mount::MNT_RDONLY, Ordering::AcqRel);
    assert!(matches!(udev.setxattr_at(AT_FDCWD, "/run/udev/data/c226:0", true,
        "user.ro", b"blocked"), Err(VfsError::Erofs)));
}
