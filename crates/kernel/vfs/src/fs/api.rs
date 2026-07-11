extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};

use crate::inode::InodeRef;
use crate::superblock::{FileSystemType, SuperBlock, SuperOps};
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
    fn mounts_line(&self, mount_point: &str, sb: Option<&SuperBlock>) -> String {
        let mut s = String::new();
        s.push_str(self.name());
        s.push(' ');
        s.push_str(mount_point);
        s.push(' ');
        s.push_str(self.name());
        s.push_str(" rw,relatime");
        match sb {
            Some(sb) => s.push_str(&sb.show_options()),
            None => s.push_str(&self.show_options()),
        }
        s.push_str(" 0 0\n");
        s
    }
}

pub struct MountSpec {
    pub fs:        Arc<dyn FileSystem>,
    pub bind_root: Option<InodeRef>,
    pub strict:    bool,
}

pub type FsConstructor = dyn Fn(&str, &str, &str) -> KResult<MountSpec> + Send + Sync;

pub struct FsType {
    pub(super) name:  String,
    pub(super) magic: u64,
    pub(super) flags: FsFlags,
    pub(super) ctor:  Box<FsConstructor>,
}

impl FsType {
    pub fn new(name: &str, magic: u64, flags: FsFlags, ctor: Box<FsConstructor>) -> Arc<Self> {
        Arc::new(Self { name: name.to_string(), magic, flags, ctor })
    }
    pub fn construct(&self, source: &str, target: &str, data: &str) -> KResult<MountSpec> { (self.ctor)(source, target, data) }
    pub fn magic(&self) -> u64 { self.magic }
    pub fn fs_flags(&self) -> FsFlags { self.flags }
}

impl FileSystemType for FsType {
    fn name(&self) -> &str { &self.name }
    fn mount(&self, src: &str, opts: &str) -> KResult<Arc<SuperBlock>> {
        let spec = (self.ctor)(src, "", opts)?;
        let root = spec.bind_root.or_else(|| spec.fs.root());
        Ok(SuperBlock::for_backend(spec.fs, root, crate::superblock::next_anon_dev(), self.name.clone()))
    }
    fn fs_flags(&self) -> FsFlags { self.flags }
}
