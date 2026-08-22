//! An unlinked file that something still has open, driven through the whole
//! chain the kernel uses rather than through the volume's own methods.
//!
//! This is the file that can fail when the lifecycle is wrong. The volume suite
//! proves that parking and eviction do the right thing when they are CALLED; it
//! cannot tell whether anything calls them, and for a long time nothing did:
//! the parking was gated on a record only an atomic-write span ever wrote, so an
//! ordinary `open` recorded no hold and the unlink freed the file under its own
//! reader. Every assertion here therefore goes through `unlink_child` and
//! `iput` — the entry points the syscall layer reaches — and reads the bytes
//! back through a handle held across the unlink.
//!
//! The chain under test, and the reason each link is here:
//!   `unlink_child`   -> `mount/ops.rs::unlink`   -> `Volume::remove` (parks)
//!   `iput` last ref  -> `drop_inode` (nlink == 0) -> `mount/sb.rs::evict_inode`
//!                    -> `Volume::evict_inode`     (frees)

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;

use vfs::file::File;
use vfs::superblock::{SimpleSuperOps, SuperBlock, SuperOps};
use vfs::fs::FileSystem;
use vfs::{CreateCtx, Dentry, InodeRef, OpenFlags};

use crate::mount::F2fs;
use crate::opts::Options;
use crate::test_image;
use crate::uapi::BLKSIZE;
use crate::volume::NewInode;

const BS: u32 = BLKSIZE as u32;

/// A mounted volume and the superblock the layer above drives it through.
/// # C: O(image bytes)
fn mounted() -> (Arc<F2fs>, Arc<SuperBlock>) {
    let bytes = test_image::with_root().finish();
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    let fs = F2fs::open_with(dev, "/dev/fake", true, Options::defaults()).expect("mount");
    let any: Arc<dyn FileSystem> = fs.clone();
    // `FileSystem::root` is not the filesystem's own entry point for this, so the
    // root is taken from where it lives; a superblock realized without one has
    // no `s_root_inode` and nothing below can be reached through it.
    let root = Some(fs.root_inode().expect("root inode"));
    let s_op: Arc<dyn SuperOps> = any.super_ops().unwrap_or_else(|| {
        Arc::new(SimpleSuperOps {
            magic: any.magic(),
            block_size: any.block_size(),
            options: any.show_options(),
        })
    });
    let ty: Arc<dyn vfs::FileSystemType> = vfs::fs::FsType::new(
        any.name(), any.magic(), any.fs_flags(),
        alloc::boxed::Box::new(|_, _, _, _, _, _| unreachable!("not mounted through ->mount")));
    let sb = SuperBlock::from_ops(ty, s_op, root, any.magic(), 0xF2F5_0001, any.block_size(),
                                 String::from("f2fs"), Arc::new(()));
    any.set_sb(Arc::downgrade(&sb)).expect("set_sb");
    (fs, sb)
}

/// A handle on `inode`, as `open` produces one. # C: O(1)
fn open_file(inode: &InodeRef) -> (Arc<File>, Arc<Dentry>) {
    let dentry = Dentry::new_root(inode.clone());
    (File::new(inode.clone(), dentry.clone(), OpenFlags::O_RDWR), dentry)
}

/// Where a file's first block lives, or `None` once it holds none. # C: O(depth)
fn first_block(fs: &Arc<F2fs>, ino: u32) -> Option<u32> {
    let v = fs.volume.lock();
    let inode = v.read_inode(ino).ok()?;
    match v.map_block(&inode, ino, 0).ok()? {
        crate::volume::map::Mapped::At(a) => Some(a),
        _ => None,
    }
}

fn payload() -> Vec<u8> { (0..2 * BLKSIZE).map(|i| (i % 251) as u8).collect() }

#[test]
fn a_parked_inode_built_fresh_from_the_medium_keeps_zero_links() {
    let (fs, sb) = mounted();
    let ino = {
        let mut v = fs.volume.lock();
        let root = v.root_ino();
        v.tmpfile(root, &NewInode {
            mode: crate::mode::S_IFREG | 0o600, uid: 0, gid: 0, rdev: 0, now: (0, 0),
        }).expect("park inode")
    };
    assert!(sb.ilookup(u64::from(ino)).is_none(), "fixture accidentally cached the inode");
    let inode = crate::mount::node::node_inode(Arc::clone(&fs), ino).expect("read parked inode");
    assert_eq!(inode.nlink(), 0, "the stored zero link count must reach the fresh inode");
    assert!(fs.volume.lock().is_orphan(ino), "the fixture inode is not parked");
}

#[test]
fn a_handle_held_across_the_unlink_still_reads_what_it_wrote() {
    let (fs, sb) = mounted();
    let root = sb.s_root_inode().expect("root");
    let inode = root.create_child("keepopen", 0o644, &CreateCtx::root()).expect("create");
    let ino = inode.ino() as u32;
    let (file, _dentry) = open_file(&inode);

    let want = payload();
    assert_eq!(file.pwrite(&want, 0).expect("write"), want.len());
    sb.sync_fs(true).expect("sync");
    let addr = first_block(&fs, ino).expect("the fixture file has no block of its own");

    root.unlink_child("keepopen").expect("unlink");

    // The name is gone the instant the unlink returns...
    assert!(root.lookup("keepopen").is_err(), "the name outlived the unlink");
    assert_eq!(inode.nlink(), 0, "the in-core count must follow the stored one");
    // ... and the file is parked, not freed: still on the list, still holding
    // the block it wrote, still charged for it.
    {
        let v = fs.volume.lock();
        assert!(v.is_orphan(ino), "the unlink did not park the inode");
        assert_eq!(v.read_inode(ino).expect("still there").links, 0);
        assert!(v.block_is_live(addr).expect("liveness"), "the block was freed under the reader");
    }

    // THE assertion: the handle reads back exactly what it wrote. With the
    // inode freed at unlink, this block is on the free list and the read either
    // fails or answers with whatever took it.
    let mut back = vec![0u8; want.len()];
    assert_eq!(file.pread(&mut back, 0).expect("read after unlink"), want.len());
    assert_eq!(back, want, "an unlinked-but-open file must keep its contents");

    // ... and it still takes writes.
    let more: Vec<u8> = (0..BLKSIZE).map(|i| (i % 97) as u8 ^ 0xA5).collect();
    assert_eq!(file.pwrite(&more, 2 * BLKSIZE as i64).expect("write after unlink"), more.len());
    let mut back2 = vec![0u8; more.len()];
    assert_eq!(file.pread(&mut back2, 2 * BLKSIZE as i64).expect("read back"), more.len());
    assert_eq!(back2, more, "writes through the handle must survive the unlink");
}

#[test]
fn the_last_reference_going_is_what_frees_the_unlinked_file() {
    let (fs, sb) = mounted();
    let root = sb.s_root_inode().expect("root");
    let before_inodes = fs.volume.lock().valid_inode_count;

    let inode = root.create_child("closeme", 0o644, &CreateCtx::root()).expect("create");
    let ino = inode.ino() as u32;
    let (file, dentry) = open_file(&inode);
    let want = payload();
    assert_eq!(file.pwrite(&want, 0).expect("write"), want.len());
    sb.sync_fs(true).expect("sync");
    let addr = first_block(&fs, ino).expect("no block of its own");

    root.unlink_child("closeme").expect("unlink");
    // Measured with the file parked and the handle open. The directory's own
    // growth is a permanent cost and is already paid by this point, so the only
    // thing between here and the figure after the eviction is what the FILE
    // holds — which is what makes the comparison below exact.
    let free_while_open = {
        let v = fs.volume.lock();
        assert!(v.block_is_live(addr).expect("liveness"), "freed while the handle was open");
        assert_eq!(v.valid_inode_count, before_inodes + 1, "the inode was freed at unlink");
        v.space().free
    };

    // The close: `File::drop` -> the dentry's `iput` -> `SuperBlock::iput` ->
    // `drop_inode` (this inode has no links) -> `F2fsSuperOps::evict_inode`.
    drop(file);
    drop(dentry);
    vfs::file::iput(inode);

    {
        let v = fs.volume.lock();
        assert!(!v.is_orphan(ino), "the inode is still parked after its last reference went");
        assert!(v.read_inode(ino).is_err(), "the inode was not freed at eviction");
        assert!(!v.block_is_live(addr).expect("liveness"), "the block was not given back");
        assert_eq!(v.valid_inode_count, before_inodes, "the inode count did not come back");
    }
    // A checkpoint, because a freed block is not FREE space until one retires
    // it: until then the segment holding it is only pre-free, which is what
    // stops a crash from handing out a block the last checkpoint still calls
    // live. So the space is checked on the far side of one.
    sb.sync_fs(true).expect("sync");
    let v = fs.volume.lock();
    // Its two data blocks at least; the node blocks holding their addresses go
    // with them, so this is a floor rather than an equality.
    assert!(v.space().free >= free_while_open + 2,
            "the eviction gave back {} blocks, not the file's own",
            v.space().free.saturating_sub(free_while_open));
}

#[test]
fn a_block_freed_at_eviction_is_not_handed_out_while_the_handle_lives() {
    // The corruption the defect produced: the unlink frees the blocks, the next
    // create is given the SAME blocks, and the first reader — whose handle is
    // still open — reads the second file's bytes.
    let (fs, sb) = mounted();
    let root = sb.s_root_inode().expect("root");

    let victim = root.create_child("victim", 0o644, &CreateCtx::root()).expect("create victim");
    let (vfile, _vdentry) = open_file(&victim);
    let want = payload();
    assert_eq!(vfile.pwrite(&want, 0).expect("write"), want.len());
    sb.sync_fs(true).expect("sync");
    let vino = victim.ino() as u32;
    let vaddr = first_block(&fs, vino).expect("no block");

    root.unlink_child("victim").expect("unlink");

    // Whatever the allocator does next, it must not be given the victim's block
    // while the handle is open. Several files' worth of writes is enough to
    // reach it if it were on the free list.
    for i in 0..4 {
        let name = alloc::format!("thief{i}");
        let t = root.create_child(&name, 0o644, &CreateCtx::root()).expect("create thief");
        let (tf, _td) = open_file(&t);
        tf.pwrite(&vec![0xEE; 2 * BLKSIZE], 0).expect("thief write");
        sb.sync_fs(true).expect("sync");
        assert_ne!(first_block(&fs, t.ino() as u32), Some(vaddr),
                   "the allocator handed out a block an open handle still reads");
    }

    let mut back = vec![0u8; want.len()];
    assert_eq!(vfile.pread(&mut back, 0).expect("read after unlink"), want.len());
    assert_eq!(back, want, "the unlinked file's bytes were overwritten by a later file");
}

#[test]
fn a_name_arriving_before_the_last_reference_goes_saves_the_file() {
    // `linkat` of an unlinked-but-open file. The eviction must leave alone what
    // is no longer on the list, or a file with a name is freed under it.
    let (fs, sb) = mounted();
    let root = sb.s_root_inode().expect("root");
    let inode = root.create_child("first", 0o644, &CreateCtx::root()).expect("create");
    let ino = inode.ino() as u32;
    let (file, dentry) = open_file(&inode);
    assert_eq!(file.pwrite(b"kept", 0).expect("write"), 4);
    sb.sync_fs(true).expect("sync");

    root.unlink_child("first").expect("unlink");
    assert!(fs.volume.lock().is_orphan(ino), "the unlink did not park it");
    root.link_child(&inode, "second", &CreateCtx::root()).expect("link");
    assert!(!fs.volume.lock().is_orphan(ino), "the new name did not lift it off the list");

    drop(file);
    drop(dentry);
    vfs::file::iput(inode);

    let v = fs.volume.lock();
    assert!(v.read_inode(ino).is_ok(), "a file with a name was freed at eviction");
    assert_eq!(v.read_inode(ino).unwrap().links, 1);
}
