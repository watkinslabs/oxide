//! The VFS-facing filesystem, driven through a real block device.
//!
//! Everything below `mount` is tested against an image in memory. This is the
//! layer that turns that into a filesystem the rest of the kernel can use, and
//! until now nothing exercised it — a rename in a signature or a missing
//! override here would have shown up only once a real program ran.
//!
//! Durability is checked the only way it can be: write, take the bytes off the
//! device, and mount them again.

use super::*;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::superblock::{SimpleSuperOps, SuperBlock, SuperOps};
use vfs::{CreateCtx, DirEmit, File, FileOps, FileType, OpenFlags, VfsError};

const BS: u32 = BLKSIZE as u32;

/// A device holding `bytes`.
fn disk(bytes: &[u8]) -> Arc<MemDisk<TaskList>> {
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes.to_vec());
    dev.submit_sync(&mut req).expect("device write");
    dev
}

/// Everything currently on the device.
fn drain(dev: &Arc<MemDisk<TaskList>>) -> Vec<u8> {
    let blocks = dev.capacity_blocks();
    let mut req = BlockRequest::new_read(0, blocks as u32, BS);
    dev.submit_sync(&mut req).expect("device read");
    req.buffer
}

/// A writable filesystem over a fresh fixture image, and its device.
fn mounted() -> (Arc<F2fs>, Arc<MemDisk<TaskList>>) {
    let dev = disk(&test_image::with_root().finish());
    let fs = F2fs::open_with(dev.clone(), "/dev/fake", true, Options::defaults()).expect("mount");
    (fs, dev)
}

/// Mount whatever is on `dev` now.
fn remount(dev: &Arc<MemDisk<TaskList>>) -> Arc<F2fs> {
    let fresh = disk(&drain(dev));
    F2fs::open_with(fresh, "/dev/fake", true, Options::defaults()).expect("remount")
}

/// Realize `fs` into the inode cache the VFS lookup path owns. # C: O(1)
fn realize(fs: &Arc<F2fs>) -> Arc<SuperBlock> {
    let any: Arc<dyn FileSystem> = fs.clone();
    let root = Some(fs.root_inode().expect("root inode"));
    let s_op: Arc<dyn SuperOps> = any.super_ops().unwrap_or_else(|| Arc::new(SimpleSuperOps {
        magic: any.magic(), block_size: any.block_size(), options: any.show_options(),
    }));
    let ty: Arc<dyn vfs::FileSystemType> = vfs::fs::FsType::new(
        any.name(), any.magic(), any.fs_flags(),
        Box::new(|_, _, _, _, _, _| unreachable!("fixture is already mounted")));
    let sb = SuperBlock::from_ops(ty, s_op, root, any.magic(), 0xF2F5_0002, any.block_size(),
                                 String::from("f2fs"), Arc::new(()));
    sb.set_s_flags(any.sb_flags(), 0);
    any.set_sb(Arc::downgrade(&sb)).expect("set superblock");
    sb
}

fn list(dir: &vfs::InodeRef) -> Vec<alloc::string::String> {
    struct Sink(Vec<alloc::string::String>);
    impl DirEmit for Sink {
        fn emit(&mut self, name: &str, _ino: u64, _t: FileType, _next: u64) -> bool {
            self.0.push(name.into());
            true
        }
    }
    let mut sink = Sink(Vec::new());
    let mut ctx = vfs::DirContext::new(0, &mut sink);
    dir.readdir(&mut ctx).unwrap();
    sink.0
}

fn freezing(fs: &Arc<F2fs>) -> bool {
    fs.volume.lock().sb_status() & (1 << crate::sbflags::bits::IS_FREEZING) != 0
}

/// A mounted filesystem with one empty file, and that file's number.
fn with_file() -> (Arc<F2fs>, Arc<MemDisk<TaskList>>, u32) {
    let (fs, dev) = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("f", 0o644, &CreateCtx::root()).unwrap();
    let ino = file.ino() as u32;
    (fs, dev, ino)
}



#[path = "adapter/mount.rs"]
mod mount;
#[path = "adapter/dirs.rs"]
mod dirs;
#[path = "adapter/policy.rs"]
mod policy;
#[path = "adapter/writeback.rs"]
mod writeback;
