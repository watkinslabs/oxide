//! Mounted exFAT lifetime tests over a writable in-memory block device.

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;

use block::{BlockDevice, BlockError, BlockOp, BlockRequest};
use vfs::SuperBlock;

use crate::test_image::{Builder, SECTOR};
use crate::{ExfatFs, Options};

struct Disk {
    bytes: sync::Spinlock<Vec<u8>, sync::TaskList>,
}

impl BlockDevice for Disk {
    fn block_size(&self) -> u32 { SECTOR as u32 }
    fn capacity_blocks(&self) -> u64 {
        self.bytes.lock().len() as u64 / u64::from(self.block_size())
    }
    fn submit_sync(&self, req: &mut BlockRequest) -> block::KResult<()> {
        let mut bytes = self.bytes.lock();
        let at = usize::try_from(req.start_block)
            .ok().and_then(|n| n.checked_mul(SECTOR)).ok_or(BlockError::Einval)?;
        let len = usize::try_from(req.len_blocks)
            .ok().and_then(|n| n.checked_mul(SECTOR)).ok_or(BlockError::Einval)?;
        if at.checked_add(len).is_none_or(|end| end > bytes.len()) {
            return Err(BlockError::Eio);
        }
        match req.op {
            BlockOp::Read => {
                req.buffer = bytes[at..at + len].to_vec();
                Ok(())
            }
            BlockOp::Write => {
                if req.buffer.len() < len { return Err(BlockError::Eio); }
                bytes[at..at + len].copy_from_slice(&req.buffer[..len]);
                Ok(())
            }
            BlockOp::Flush => Ok(()),
            _ => Err(BlockError::Eopnotsupp),
        }
    }
    fn flush(&self) -> block::KResult<()> { Ok(()) }
}

fn mounted() -> (Arc<ExfatFs>, Arc<SuperBlock>) {
    let mut builder = Builder::new();
    let cluster = builder.write_run(b"hello");
    builder.push_name("HELLO.TXT", false, cluster, 5, crate::uapi::ALLOC_NO_FAT_CHAIN);
    let image = builder.finish();
    let disk = Arc::new(Disk { bytes: sync::Spinlock::new(image.snapshot()) });
    let mut opts = Options::defaults();
    opts.settle();
    let fs = ExfatFs::open_with(disk, "/dev/loop0", true, opts).expect("mount");
    let any: Arc<dyn vfs::fs::FileSystem> = fs.clone();
    let root = Some(fs.root_inode());
    let s_op = any.super_ops().expect("exFAT super operations");
    let ty: Arc<dyn vfs::FileSystemType> = vfs::fs::FsType::new(
        any.name(), any.magic(), any.fs_flags(),
        alloc::boxed::Box::new(|_, _, _, _, _, _| unreachable!("fixture is already mounted")));
    let sb = SuperBlock::from_ops(ty, s_op, root, any.magic(), 0xEF_A7_0001,
                                  any.block_size(), String::from("exfatfs"), Arc::new(()));
    any.set_sb(Arc::downgrade(&sb)).expect("set superblock");
    (fs, sb)
}

#[test]
fn an_open_unlinked_file_keeps_its_clusters_until_final_eviction() {
    let (fs, sb) = mounted();
    let root = sb.s_root_inode().expect("root");
    let inode = root.lookup("HELLO.TXT").expect("file");
    let dentry = vfs::Dentry::new_root(inode.clone());
    let file = vfs::File::new(inode.clone(), dentry.clone(), vfs::OpenFlags::O_RDONLY);
    let before = fs.volume.lock().free_clusters();

    root.unlink_child_with_victim("HELLO.TXT", &inode).expect("unlink");
    assert_eq!(fs.volume.lock().free_clusters(), before,
        "unlink released a cluster still owned by the open file");
    let mut bytes = [0u8; 5];
    assert_eq!(file.pread(&mut bytes, 0).expect("read after unlink"), bytes.len());
    assert_eq!(&bytes, b"hello");

    drop(file);
    drop(dentry);
    vfs::file::iput(inode);
    assert_eq!(fs.volume.lock().free_clusters(), before + 1,
        "final eviction did not release the unlinked file's cluster");
}
