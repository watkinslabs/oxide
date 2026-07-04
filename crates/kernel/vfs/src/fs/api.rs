extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};

use crate::inode::InodeRef;
use crate::superblock::{FileSystemType, SuperBlock, SuperOps};
use crate::types::VfsError;

use super::flags::FsFlags;

pub type KResult<T> = core::result::Result<T, VfsError>;

fn push_u32(s: &mut String, n: u32) {
    if n == 0 { s.push('0'); return; }
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    let mut v = n;
    while v > 0 { i -= 1; buf[i] = b'0' + (v % 10) as u8; v /= 10; }
    // SAFETY: buf[i..] holds only ASCII digits, valid UTF-8.
    s.push_str(unsafe { core::str::from_utf8_unchecked(&buf[i..]) });
}

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
    fn create(&self, path: &str, mode: u32) -> KResult<InodeRef> { let _ = (path, mode); Err(VfsError::Erofs) }
    fn create_anonymous(&self, dir: &str, mode: u32) -> KResult<InodeRef> { let _ = (dir, mode); Err(VfsError::Erofs) }
    fn unlink(&self, path: &str) -> KResult<()> { let _ = path; Err(VfsError::Erofs) }
    fn link(&self, target: &str, link: &str) -> KResult<()> { let _ = (target, link); Err(VfsError::Erofs) }
    fn link_inode(&self, inode: InodeRef, link: &str) -> KResult<()> { let _ = (inode, link); Err(VfsError::Erofs) }
    fn rename(&self, from: &str, to: &str) -> KResult<()> { let _ = (from, to); Err(VfsError::Erofs) }
    fn lookup_path(&self, path: &str) -> Option<InodeRef> {
        let mut cur = self.root()?;
        for comp in path.split('/').filter(|c| !c.is_empty() && *c != ".") { cur = cur.lookup(comp).ok()?; }
        Some(cur)
    }
    fn exchange(&self, a: &str, b: &str) -> KResult<()> {
        if self.lookup_path(a).is_none() || self.lookup_path(b).is_none() { return Err(VfsError::Enoent); }
        let mut tmp = alloc::string::String::new();
        let mut n: u32 = 0;
        loop {
            tmp.clear();
            tmp.push_str(a);
            tmp.push_str(".oxexch");
            push_u32(&mut tmp, n);
            if self.lookup_path(&tmp).is_none() { break; }
            n = n.checked_add(1).ok_or(VfsError::Eexist)?;
            if n > 65536 { return Err(VfsError::Eexist); }
        }
        self.rename(a, &tmp)?;
        if let Err(e) = self.rename(b, a) {
            let _ = self.rename(&tmp, a);
            return Err(e);
        }
        if let Err(e) = self.rename(&tmp, b) {
            let _ = self.rename(a, b);
            let _ = self.rename(&tmp, a);
            return Err(e);
        }
        Ok(())
    }
    fn whiteout(&self, from: &str, to: &str) -> KResult<()> {
        const S_IFCHR: u16 = 0x2000;
        self.rename(from, to)?;
        let from = from.strip_suffix('/').unwrap_or(from);
        let (parent, name) = match from.rfind('/') { Some(i) => (&from[..i], &from[i + 1..]), None => ("", from) };
        let pino = match self.lookup_path(parent) {
            Some(p) => p,
            None => { let _ = self.rename(to, from); return Err(VfsError::Enoent); }
        };
        if let Err(e) = pino.mknod_child(name, S_IFCHR, 0, &crate::CreateCtx::root()) {
            let _ = self.rename(to, from);
            return Err(e);
        }
        Ok(())
    }
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
