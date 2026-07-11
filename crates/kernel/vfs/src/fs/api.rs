extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};

use crate::inode::InodeRef;
use crate::superblock::{FileSystemType, SimpleSuperOps, SuperBlock, SuperOps, next_anon_dev, sget};
use crate::types::VfsError;

use super::flags::FsFlags;

pub type KResult<T> = core::result::Result<T, VfsError>;

pub trait FileSystem: Send + Sync {
    fn name(&self) -> &str;
    fn magic(&self) -> u64 { 0 }
    fn fs_flags(&self) -> FsFlags { FsFlags::empty() }
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
    fn set_sb(&self, _sb: Weak<SuperBlock>) {}
    fn show_options(&self) -> String { String::new() }
}

pub struct MountSpec {
    pub sb:     Arc<SuperBlock>,
    pub strict: bool,
}

impl MountSpec {
    /// Realize a constructor object into a Linux mounted superblock before
    /// it crosses into the mount engine. # C: O(N_sb) for device-backed reuse.
    pub fn from_filesystem(s_type: Arc<dyn FileSystemType>, fs: Arc<dyn FileSystem>,
        bind_root: Option<InodeRef>, strict: bool, s_id: String) -> Self {
        let root = bind_root.or_else(|| fs.root());
        let s_op: Arc<dyn SuperOps> = fs.super_ops().unwrap_or_else(|| {
            Arc::new(SimpleSuperOps {
                magic: fs.magic(),
                block_size: fs.block_size(),
                options: fs.show_options(),
            })
        });
        let s_magic = fs.magic();
        let s_blocksize = fs.block_size();
        let sb = match fs.dev_id() {
            Some(dev) => {
                let fs_for_stamp = fs.clone();
                sget(dev, move || {
                    let sb = SuperBlock::from_ops(s_type, s_op, root, s_magic, dev, s_blocksize, s_id, Arc::new(()));
                    fs_for_stamp.set_sb(Arc::downgrade(&sb));
                    sb
                })
            }
            None => {
                let sb = SuperBlock::from_ops(s_type, s_op, root, s_magic, next_anon_dev(), s_blocksize, s_id, Arc::new(()));
                fs.set_sb(Arc::downgrade(&sb));
                sb
            }
        };
        Self { sb, strict }
    }
}

pub type FsConstructor = dyn Fn(Arc<dyn FileSystemType>, Option<&str>, &str, &str) -> KResult<MountSpec> + Send + Sync;

pub struct FsType {
    pub(super) name:  String,
    pub(super) magic: u64,
    pub(super) flags: FsFlags,
    self_ref:          Weak<FsType>,
    pub(super) ctor:  Box<FsConstructor>,
}

impl FsType {
    pub fn new(name: &str, magic: u64, flags: FsFlags, ctor: Box<FsConstructor>) -> Arc<Self> {
        Arc::new_cyclic(|self_ref| Self { name: name.to_string(), magic, flags, self_ref: self_ref.clone(), ctor })
    }
    fn as_type(&self) -> Arc<dyn FileSystemType> {
        self.self_ref.upgrade().expect("registered filesystem type self-ref") as Arc<dyn FileSystemType>
    }
    pub fn construct(&self, source: Option<&str>, target: &str, data: &str) -> KResult<MountSpec> { (self.ctor)(self.as_type(), source, target, data) }
    pub fn magic(&self) -> u64 { self.magic }
    pub fn fs_flags(&self) -> FsFlags { self.flags }
}

impl FileSystemType for FsType {
    fn name(&self) -> &str { &self.name }
    fn mount(&self, src: Option<&str>, opts: &str) -> KResult<Arc<SuperBlock>> {
        let spec = (self.ctor)(self.as_type(), src, "", opts)?;
        Ok(spec.sb)
    }
    fn fs_flags(&self) -> FsFlags { self.flags }
}
