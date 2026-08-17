//! REACHABILITY: what an OPEN of this filesystem's file owes, driven through a
//! real handle.
//!
//! `on_open_file` is this filesystem's `f2fs_file_open`, and it is the belt that
//! catches an entry point nobody wired: a writable handle brings the file's
//! quota records in, and a sealed file's metadata is established and its
//! signature checked. Both halves are covered at the volume layer, but the HOOK
//! itself needs a `vfs::File` — so before these tests, deleting either line from
//! it left the whole suite green.
//!
//! The handle is built the way an open builds one: the inode the mount hands
//! out, an alias dentry over it, and the open flags. That is what makes these
//! fail when the hook stops doing its work.

use alloc::sync::Arc;
use alloc::vec;

use vfs::{File, FileOps, InodeOps, InodeRef, OpenFlags};

use crate::mount::ops::F2fsOps;
use crate::mount::F2fs;
use crate::opts::Options;
use crate::test_image;
use crate::uapi::BLKSIZE;
use crate::verity::uapi::HASH_ALG_SHA256;
use crate::volume::quotas::USRQUOTA;

const OWNER: u32 = 4242;

type Disk = Arc<block::MemDisk<sync::TaskList>>;

/// Everything currently on `dev`.
fn drain(dev: &Disk) -> alloc::vec::Vec<u8> {
    let blocks = block::BlockDevice::capacity_blocks(&**dev);
    let mut req = block::BlockRequest::new_read(0, blocks as u32, BLKSIZE as u32);
    block::BlockDevice::submit_sync(&**dev, &mut req).expect("device read");
    req.buffer
}

/// Mount whatever is on `dev` now, with user accounting on.
fn mount_on(dev: Disk) -> Arc<F2fs> {
    let mut o = Options::defaults();
    o.usrquota = true;
    F2fs::open_with(dev, "/dev/fake", true, o).expect("mount")
}

/// A writable mount over the fixture image, with user accounting on, and its
/// device.
fn mounted() -> (Arc<F2fs>, Disk) {
    let file = crate::test_image::quota_image::user_file(OWNER, 0, 0);
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_QUOTA_INO;
    b.qf_ino[USRQUOTA] = QUOTA_INO;
    let blocks: alloc::vec::Vec<(u64, alloc::vec::Vec<u8>)> =
        file.chunks(BLKSIZE).enumerate().map(|(i, c)| (i as u64, c.to_vec())).collect();
    crate::test_image::nodes::add_sparse_file(&mut b, QUOTA_INO, file.len() as u64, &blocks);
    let bytes = b.finish();
    let bs = BLKSIZE as u32;
    let dev: Disk = block::MemDisk::new(bs, bytes.len() as u64 / u64::from(bs));
    let mut req = block::BlockRequest::new_write(0, (bytes.len() / BLKSIZE) as u32, bytes);
    block::BlockDevice::submit_sync(&*dev, &mut req).expect("device write");
    (mount_on(dev.clone()), dev)
}

/// A volume holding one file owned by `OWNER`, mounted FRESH: nothing is held,
/// which is the only state in which an acquisition the hook makes is visible.
fn fresh_with_file(name: &str) -> (Arc<F2fs>, InodeRef) {
    let (fs, dev) = mounted();
    file_of(&fs, name);
    fs.mark_clean().expect("checkpoint");
    drop(fs);
    let bs = BLKSIZE as u32;
    let bytes = drain(&dev);
    let fresh: Disk = block::MemDisk::new(bs, bytes.len() as u64 / u64::from(bs));
    let mut req = block::BlockRequest::new_write(0, (bytes.len() / BLKSIZE) as u32, bytes);
    block::BlockDevice::submit_sync(&*fresh, &mut req).expect("device write");
    let fs = mount_on(fresh);
    let root = fs.root_inode().expect("root");
    let f = F2fsOps.lookup(&root, name).expect("lookup");
    (fs, f)
}

/// The quota inode the fixture plants.
const QUOTA_INO: u32 = 9;

/// A regular file under the root owned by `OWNER`.
fn file_of(fs: &Arc<F2fs>, name: &str) -> InodeRef {
    let root = fs.root_inode().expect("root");
    let ctx = vfs::CreateCtx::root();
    F2fsOps.create(&root, name, vfs::mk_mode(vfs::FileType::Regular, 0o644), &ctx).expect("create");
    let child = F2fsOps.lookup(&root, name).expect("lookup");
    let ino = F2fsOps::node(&child).expect("node").ino;
    fs.volume.lock().set_attr(ino, None, Some((OWNER, OWNER)), (1, 0)).expect("chown");
    child
}

/// A mount with no accounting at all, for the verity half: the quota half is
/// measured on its own fixture above, and a volume whose quota file has not
/// been through a checkpoint cannot serve a record.
fn plain_mount() -> Arc<F2fs> {
    let bytes = test_image::with_root().finish();
    let bs = BLKSIZE as u32;
    let dev: Disk = block::MemDisk::new(bs, bytes.len() as u64 / u64::from(bs));
    let mut req = block::BlockRequest::new_write(0, (bytes.len() / BLKSIZE) as u32, bytes);
    block::BlockDevice::submit_sync(&*dev, &mut req).expect("device write");
    F2fs::open_with(dev, "/dev/fake", true, Options::defaults()).expect("mount")
}

/// A handle over `inode`, built the way an open builds one.
fn handle(inode: &InodeRef, flags: OpenFlags) -> Arc<File> {
    File::new(inode.clone(), vfs::dcache::d_obtain_alias(inode.clone()), flags)
}

/// A writable handle is where the reference brings a file's quota records in,
/// once, before anything the handle does can allocate. This is the ONLY test
/// that drives that through the hook rather than through the volume.
#[test]
fn a_writable_handle_brings_this_files_quota_records_in() {
    let (fs, f) = fresh_with_file("w");
    assert!(!fs.volume.lock().dquot_is_held(USRQUOTA, OWNER),
            "the fixture already holds the record, so the hook cannot be measured");

    F2fsOps.on_open_file(&handle(&f, OpenFlags::O_WRONLY)).expect("open");

    assert!(fs.volume.lock().dquot_is_held(USRQUOTA, OWNER),
            "the open did not acquire the owner's record");
}

/// A read-only handle allocates nothing, so the reference acquires nothing for
/// it: doing so would put a quota-file read under every open of every file.
#[test]
fn a_read_only_handle_acquires_nothing() {
    let (fs, f) = fresh_with_file("r");

    F2fsOps.on_open_file(&handle(&f, OpenFlags::empty())).expect("open");

    assert!(!fs.volume.lock().dquot_is_held(USRQUOTA, OWNER),
            "a read handle acquired a record it cannot need");
}

/// A sealed file refuses a writable handle, and the refusal belongs to the open
/// — a read that discovered it at whichever offset first needed a hash would
/// report a broken file instead of a refused permission.
#[test]
fn a_sealed_file_refuses_a_writable_handle_through_the_hook() {
    let fs = plain_mount();
    let root = fs.root_inode().expect("root");
    F2fsOps.create(&root, "sealed", vfs::mk_mode(vfs::FileType::Regular, 0o644),
                   &vfs::CreateCtx::root()).expect("create");
    let f = F2fsOps.lookup(&root, "sealed").expect("lookup");
    let ino = F2fsOps::node(&f).expect("node").ino;
    {
        let mut v = fs.volume.lock();
        v.write_file(ino, 0, &vec![7u8; BLKSIZE]).expect("write");
        v.sync_data().expect("sync");
        v.enable_verity(ino, HASH_ALG_SHA256, 12, b"").expect("seal");
    }
    let live = F2fsOps::node(&f).expect("node").live().expect("live");
    assert!(crate::verity::access::is_verity(live.flags), "the file was not sealed");

    assert_eq!(F2fsOps.on_open_file(&handle(&f, OpenFlags::O_WRONLY)).err(),
               Some(vfs::VfsError::Eperm),
               "a sealed file's writable open must be a refusal of permission, not an I/O error");
    F2fsOps.on_open_file(&handle(&f, OpenFlags::empty())).expect("a read handle is allowed");
}
