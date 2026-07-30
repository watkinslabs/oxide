extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};

use crate::inode::InodeRef;
use crate::superblock::{FileSystemType, SimpleSuperOps, SuperBlock, SuperOps, next_anon_dev, sget_result};
use crate::types::VfsError;

use super::flags::FsFlags;

pub type KResult<T> = core::result::Result<T, VfsError>;

pub trait FileSystem: Send + Sync {
    fn name(&self) -> &str;
    fn magic(&self) -> u64 { 0 }
    fn fs_flags(&self) -> FsFlags { FsFlags::empty() }
    /// `sb->s_iflags` this backend stamps at fill-super (Linux does it inline in
    /// each `fill_super`: `fs/proc/root.c` and `fs/kernfs/mount.c` both set
    /// `SB_I_NOEXEC | SB_I_NODEV`, `fs/libfs.c` `init_pseudo` sets the same pair
    /// for every pseudo filesystem). A backend marked
    /// `FS_USERNS_MOUNT_RESTRICTED` MUST return at least
    /// [`crate::superblock::SB_I_USERNS_REQUIRED`] or `mount_too_revealing`
    /// refuses every user-namespace mount of it. # C: O(1)
    fn s_iflags(&self) -> u64 { 0 }
    fn requires_dev(&self) -> bool { self.fs_flags().contains(FsFlags::FS_REQUIRES_DEV) }
    fn dev_id(&self) -> Option<u64> { None }
    fn rename_does_d_move(&self) -> bool { self.fs_flags().contains(FsFlags::FS_RENAME_DOES_D_MOVE) }
    fn proc_filesystems_line(&self) -> String {
        let mut s = String::new();
        if !self.requires_dev() { s.push_str("nodev"); }
        s.push('\t');
        s.push_str(self.name());
        s.push('\n');
        s
    }
    fn block_size(&self) -> u32 { 4096 }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { None }
    fn root(&self) -> Option<InodeRef> { None }
    fn set_sb(&self, _sb: Weak<SuperBlock>) -> KResult<()> { Ok(()) }
    fn sysfs_name(&self) -> Option<String> { None }
    fn show_options(&self) -> String { String::new() }
}

/// Realize a not-yet-converted filesystem implementation into a Linux
/// `SuperBlock`. This is a fill-super compatibility boundary only: the returned
/// SB carries all live authority in `s_type`, `s_op`, `s_root`, and
/// `s_fs_info`; no `Arc<dyn FileSystem>` is retained behind it or consulted by
/// the mount namespace. # C: O(N_sb) for device-backed reuse.
pub fn superblock_from_filesystem(s_type: Arc<dyn FileSystemType>, fs: Arc<dyn FileSystem>,
    root_inode: Option<InodeRef>, s_id: String) -> KResult<Arc<SuperBlock>> {
    let root = root_inode.or_else(|| fs.root());
    let s_op: Arc<dyn SuperOps> = fs.super_ops().unwrap_or_else(|| {
        Arc::new(SimpleSuperOps {
            magic: fs.magic(),
            block_size: fs.block_size(),
            options: fs.show_options(),
        })
    });
    let s_magic = fs.magic();
    let s_blocksize = fs.block_size();
    // Linux stamps `s_iflags` inside `fill_super`, before the instance is
    // published — so it is set on every path that can reach `mount_too_revealing`.
    let s_iflags = fs.s_iflags();
    match fs.dev_id() {
        Some(dev) => {
            let fs_for_stamp = fs.clone();
            sget_result(dev, move || {
                let sb = SuperBlock::from_ops(s_type, s_op, root, s_magic, dev, s_blocksize, s_id, Arc::new(()));
                sb.set_s_iflags(s_iflags);
                fs_for_stamp.set_sb(Arc::downgrade(&sb))?;
                if let Some(name) = fs_for_stamp.sysfs_name() { sb.set_sysfs_name(&name); }
                Ok(sb)
            })
        }
        None => {
            let sb = SuperBlock::from_ops(s_type, s_op, root, s_magic, next_anon_dev(), s_blocksize, s_id, Arc::new(()));
            sb.set_s_iflags(s_iflags);
            fs.set_sb(Arc::downgrade(&sb))?;
            if let Some(name) = fs.sysfs_name() { sb.set_sysfs_name(&name); }
            Ok(sb)
        }
    }
}

pub type FsConstructor = dyn Fn(Arc<dyn FileSystemType>, Option<&str>, &str, &str) -> KResult<Arc<SuperBlock>> + Send + Sync;
pub type FsFlagConstructor = dyn Fn(Arc<dyn FileSystemType>, Option<&str>, &str, &str, u64) -> KResult<Arc<SuperBlock>> + Send + Sync;

pub(super) enum Constructor {
    Basic(Box<FsConstructor>),
    Flags(Box<FsFlagConstructor>),
}

pub struct FsType {
    pub(super) name:  String,
    pub(super) magic: u64,
    pub(super) flags: FsFlags,
    self_ref:          Weak<FsType>,
    pub(super) ctor:  Constructor,
}

impl FsType {
    pub fn new(name: &str, magic: u64, flags: FsFlags, ctor: Box<FsConstructor>) -> Arc<Self> {
        Arc::new_cyclic(|self_ref| Self {
            name: name.to_string(), magic, flags, self_ref: self_ref.clone(),
            ctor: Constructor::Basic(ctor),
        })
    }
    /// Register a filesystem constructor that consumes superblock flags.
    /// # C: O(1)
    pub fn new_with_flags(
        name: &str,
        magic: u64,
        flags: FsFlags,
        ctor: Box<FsFlagConstructor>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|self_ref| Self {
            name: name.to_string(), magic, flags, self_ref: self_ref.clone(),
            ctor: Constructor::Flags(ctor),
        })
    }
    fn as_type(&self) -> Arc<dyn FileSystemType> {
        self.self_ref.upgrade().expect("registered filesystem type self-ref") as Arc<dyn FileSystemType>
    }
    pub fn construct(&self, source: Option<&str>, target: &str, data: &str) -> KResult<Arc<SuperBlock>> {
        self.construct_with_flags(source, target, data, 0)
    }
    /// Construct a superblock while preserving mount-derived superblock flags.
    /// # C: O(constructor)
    pub fn construct_with_flags(
        &self,
        source: Option<&str>,
        target: &str,
        data: &str,
        sb_flags: u64,
    ) -> KResult<Arc<SuperBlock>> {
        match &self.ctor {
            Constructor::Basic(ctor) => ctor(self.as_type(), source, target, data),
            Constructor::Flags(ctor) => ctor(self.as_type(), source, target, data, sb_flags),
        }
    }
    pub fn magic(&self) -> u64 { self.magic }
    pub fn fs_flags(&self) -> FsFlags { self.flags }
}

impl FileSystemType for FsType {
    fn name(&self) -> &str { &self.name }
    fn mount(&self, src: Option<&str>, opts: &str) -> KResult<Arc<SuperBlock>> {
        self.construct_with_flags(src, "", opts, 0)
    }
    fn mount_with_flags(
        &self,
        src: Option<&str>,
        opts: &str,
        sb_flags: u64,
    ) -> KResult<Arc<SuperBlock>> {
        self.construct_with_flags(src, "", opts, sb_flags)
    }
    fn fs_flags(&self) -> FsFlags { self.flags }
}
