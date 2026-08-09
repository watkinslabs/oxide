extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::blockdev::{BlockDevice, MemDisk};
use crate::registry::{self, dev_t_of, opener_count};
use sync::Inode as InodeClass;
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{File, FileType, KResult, OpenFlags, make_device_node_inode};

struct TestFs;
impl FileSystemType for TestFs {
    fn name(&self) -> &str { "block-test" }
    fn mount(&self, _s: Option<&str>, _o: &str) -> KResult<Arc<SuperBlock>> { unreachable!() }
}
struct TestSbOps;
impl SuperOps for TestSbOps { fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) } }
fn test_sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TestFs), Arc::new(TestSbOps), 0, 0, 4096, "block-test".into(), Arc::new(()))
}

// A `vd*` disk: 8 sectors of 512 B = 4096 B, major 254 (virtio-blk).
fn disk(cap_blocks: u64) -> Arc<dyn BlockDevice> {
    MemDisk::<InodeClass>::new(512, cap_blocks)
}

// The core regression: before registration a `/dev/vdX` open would find no
// BLKDEV region → ENXIO; registration must publish one, and unregister must
// remove it. This is exactly what `open("/dev/vda")` in blkid/udev hits.
#[test]
fn register_publishes_blkdev_region_open_resolves() {
    let idx = registry::register("vdq", disk(8));
    assert_ne!(idx, 0, "register should succeed in hosted mode");
    let devt = vfs::Devt(dev_t_of("vdq", idx).unwrap());
    // Was ENXIO before this fix; must resolve to a driver now.
    let ops = vfs::lookup_blkdev(devt).expect("BLKDEV region published on register");
    ops.open(devt).expect("open dispatches to the disk");
    registry::unregister("vdq");
    assert!(vfs::lookup_blkdev(devt).is_none(), "region dropped on unregister");
}

// The published ops must actually move bytes to/from the backing device,
// including a write that straddles two sectors (RMW correctness).
#[test]
fn published_ops_read_write_roundtrip_across_sectors() {
    let idx = registry::register("vdr", disk(8));
    let devt = vfs::Devt(dev_t_of("vdr", idx).unwrap());
    let ops = vfs::lookup_blkdev(devt).unwrap();
    let data: Vec<u8> = (0..600u32).map(|i| i as u8).collect(); // 600 B spans 2 sectors
    assert_eq!(ops.write(devt, 100, &data).unwrap(), 600);
    let mut buf = vec![0u8; 600];
    assert_eq!(ops.read(devt, 100, &mut buf).unwrap(), 600);
    assert_eq!(buf, data, "RMW write then read returns the same bytes");
    // A neighbouring untouched byte stays zero (no over-write of the RMW head).
    let mut head = vec![0u8; 100];
    ops.read(devt, 0, &mut head).unwrap();
    assert!(head.iter().all(|&b| b == 0));
    registry::unregister("vdr");
}

// Reads at/after end-of-device are short/EOF, never an error (Linux).
#[test]
fn read_past_end_is_eof_not_error() {
    let idx = registry::register("vdu", disk(2)); // 1024 B
    let devt = vfs::Devt(dev_t_of("vdu", idx).unwrap());
    let ops = vfs::lookup_blkdev(devt).unwrap();
    let mut buf = [0u8; 512];
    assert_eq!(ops.read(devt, 1024, &mut buf).unwrap(), 0);
    // A read straddling the end returns only the in-bounds tail.
    assert_eq!(ops.read(devt, 1000, &mut buf).unwrap(), 24);
    registry::unregister("vdu");
}

// `fsync` on a block-device fd is writeback THEN barrier: the bytes a
// buffered write left in the device's page cache must be on the medium
// when it returns, not merely ordered behind a flush of nothing.
#[test]
fn blockdev_fsync_writes_back_the_cache_then_flushes() {
    let idx = registry::register("vdv", disk(8));
    let devt = vfs::Devt(dev_t_of("vdv", idx).unwrap());
    let ops = vfs::lookup_blkdev(devt).unwrap();
    let d = registry::by_dev(devt.raw()).unwrap();
    assert_eq!(ops.write(devt, 0, &[0xC3; 64]).unwrap(), 64);
    assert_eq!(d.mapping.dirty_pages(), 1, "buffered, not written through");
    ops.flush_cache(devt).unwrap();
    assert_eq!(d.mapping.dirty_pages(), 0, "fsync wrote it back");
    registry::unregister("vdv");
}

// Closing the LAST description writes the device's dirty pages back
// (Linux `bdev_release`) — the device pass of `sync(2)` skips a disk with
// no opener, so nothing else would.
#[test]
fn final_close_writes_back_the_device_cache() {
    let idx = registry::register("vdw", disk(8));
    let devt = vfs::Devt(dev_t_of("vdw", idx).unwrap());
    let ops = vfs::lookup_blkdev(devt).unwrap();
    let sb = test_sb();
    let node = make_device_node_inode(1, FileType::BlockDev, devt, 0o660, Arc::downgrade(&sb));
    let file = File::new(node.clone(), vfs::dcache::d_obtain_alias(node), OpenFlags::empty());
    ops.open_file(devt, &file).unwrap();
    let d = registry::by_dev(devt.raw()).unwrap();
    ops.write(devt, 0, &[0xD4; 32]).unwrap();
    assert_eq!(d.mapping.dirty_pages(), 1);
    ops.release_file(devt, &file);
    assert_eq!(d.mapping.dirty_pages(), 0, "final close flushed the cache");
    registry::unregister("vdw");
}

// Size ioctl helpers report capacity in bytes + the logical sector size.
#[test]
fn size_and_sector_helpers() {
    let idx = registry::register("vds", disk(8));
    let raw = dev_t_of("vds", idx).unwrap();
    assert_eq!(super::size_bytes(raw), Some(4096));
    assert_eq!(super::sector_size(raw), Some(512));
    assert_eq!(super::size_bytes(0xDEAD), None, "unknown dev_t → None");
    registry::unregister("vds");
}

// `f_op->iopoll == NULL` for a device whose driver installs no poll
// operation. This is the exact distinction io_uring's IOPOLL admission
// ladder keys its EOPNOTSUPP on, so `None` must not degrade to `Some(0)`.
#[test]
fn iopoll_is_absent_for_a_device_with_no_poll_operation() {
    let idx = registry::register("vdp1", disk(8));
    let devt = vfs::Devt(dev_t_of("vdp1", idx).unwrap());
    let ops = vfs::lookup_blkdev(devt).unwrap();
    assert_eq!(ops.iopoll(devt), None, "no poll op → no iopoll slot");
    registry::unregister("vdp1");
}

// A pollable driver reaches `f_op->iopoll` through the registry's decorator
// stack (stats / admission / coherence). A decorator taking the trait
// default instead of forwarding would report every disk unpollable here.
#[test]
fn iopoll_reports_the_count_a_pollable_device_reaped() {
    let dev = crate::tests::PollableDisk::new(2);
    let idx = registry::register("vdp2", dev);
    let devt = vfs::Devt(dev_t_of("vdp2", idx).unwrap());
    let ops = vfs::lookup_blkdev(devt).unwrap();
    assert_eq!(ops.iopoll(devt), Some(2), "polled, two completions reaped");
    assert_eq!(ops.iopoll(devt), Some(0), "polled, none left — NOT None");
    registry::unregister("vdp2");
}

// The whole chain a caller actually walks: `file->f_op->iopoll` on an open
// `/dev/vdX` description → the device node's block dispatch → this bridge →
// the driver's poll. Each link is defaulted to "no poll op", so a missing
// link anywhere collapses this to `None`.
#[test]
fn f_op_iopoll_on_an_open_block_description_reaches_the_driver() {
    let dev = crate::tests::PollableDisk::new(1);
    let idx = registry::register("vdp3", dev);
    let devt = vfs::Devt(dev_t_of("vdp3", idx).unwrap());
    let sb = test_sb();
    let node = make_device_node_inode(1, FileType::BlockDev, devt, 0o660, Arc::downgrade(&sb));
    let file = File::new(node.clone(), vfs::dcache::d_obtain_alias(node), OpenFlags::empty());
    file.open_hook().expect("block description opens");
    let fop = file.inode().i_fop().clone();
    assert_eq!(fop.iopoll(&file), Some(1), "f_op->iopoll reaches the driver's poll");
    assert_eq!(fop.iopoll(&file), Some(0));
    drop(file);
    registry::unregister("vdp3");
}

/// Shorthand for the completion evidence a deferral test needs: whether the
/// transfer has completed, and with what.
fn direct_probe() -> (Arc<sync::Spinlock<Option<(Vec<u8>, KResult<usize>)>, sync::Inode>>,
                      vfs::file_ops::DirectDone)
{
    let slot: Arc<sync::Spinlock<Option<(Vec<u8>, KResult<usize>)>, sync::Inode>> =
        Arc::new(sync::Spinlock::new(None));
    let w = Arc::clone(&slot);
    (slot, alloc::boxed::Box::new(move |buf, res| {
        let mut g = w.lock();
        assert!(g.is_none(), "a queued transfer completes exactly once");
        *g = Some((buf, res));
    }))
}

// THE point of submit-then-poll: the transfer is accepted and the call
// returns having completed NOTHING. A backend that finished inline would
// have posted its result before any poll could look for it, which is why
// IOPOLL previously paid for nothing.
#[test]
fn a_queued_direct_read_returns_without_completing() {
    let dev = crate::tests::QueuedDisk::new();
    let idx = registry::register("vdq1", Arc::clone(&dev) as Arc<dyn BlockDevice>);
    let devt = vfs::Devt(dev_t_of("vdq1", idx).unwrap());
    let ops = vfs::lookup_blkdev(devt).unwrap();
    let (slot, done) = direct_probe();
    let r = ops.submit_direct(devt, vfs::file_ops::DirectIo {
        write: false, off: 0, buf: vec![0u8; 512], done,
    });
    assert!(r.is_queued(), "the backend took the transfer");
    assert!(slot.lock().is_none(), "NOT completed by the submitting call");
    assert_eq!(dev.outstanding(), 1, "the device holds it");
    // Only the poll completes it — the reference's `io_do_iopoll`.
    assert_eq!(ops.iopoll(devt), Some(1));
    let g = slot.lock();
    let (buf, res) = g.as_ref().expect("the poll completed it");
    assert_eq!(*res, Ok(512));
    assert_eq!(buf.len(), 512);
    drop(g);
    registry::unregister("vdq1");
}

// The bytes a direct write carries reach the medium, and a later read of
// the same range sees them — a deferral that lost the payload would still
// "complete" and would still report the byte count.
#[test]
fn a_queued_direct_write_lands_and_a_later_read_sees_it() {
    let dev = crate::tests::QueuedDisk::new();
    let idx = registry::register("vdq2", Arc::clone(&dev) as Arc<dyn BlockDevice>);
    let devt = vfs::Devt(dev_t_of("vdq2", idx).unwrap());
    let ops = vfs::lookup_blkdev(devt).unwrap();
    let (wslot, done) = direct_probe();
    assert!(ops.submit_direct(devt, vfs::file_ops::DirectIo {
        write: true, off: 512, buf: vec![0xA7u8; 512], done,
    }).is_queued());
    assert!(wslot.lock().is_none());
    assert_eq!(ops.iopoll(devt), Some(1));
    assert_eq!(wslot.lock().as_ref().unwrap().1, Ok(512));

    let (rslot, done) = direct_probe();
    assert!(ops.submit_direct(devt, vfs::file_ops::DirectIo {
        write: false, off: 512, buf: vec![0u8; 512], done,
    }).is_queued());
    assert_eq!(ops.iopoll(devt), Some(1));
    let g = rslot.lock();
    assert!(g.as_ref().unwrap().0.iter().all(|&b| b == 0xA7), "the write's bytes came back");
    drop(g);
    registry::unregister("vdq2");
}

// The alignment and end-of-device rules refuse BEFORE anything is queued,
// so a refused transfer leaves nothing outstanding for a poll to chase.
#[test]
fn a_refused_direct_transfer_queues_nothing() {
    let dev = crate::tests::QueuedDisk::new();
    let idx = registry::register("vdq3", Arc::clone(&dev) as Arc<dyn BlockDevice>);
    let devt = vfs::Devt(dev_t_of("vdq3", idx).unwrap());
    let ops = vfs::lookup_blkdev(devt).unwrap();
    let (slot, done) = direct_probe();
    let r = ops.submit_direct(devt, vfs::file_ops::DirectIo {
        write: false, off: 1, buf: vec![0u8; 512], done,
    });
    assert!(matches!(r, vfs::file_ops::DirectSubmit::Failed(vfs::types::VfsError::Einval)));
    assert!(slot.lock().is_none(), "a refusal does not run the completion");
    assert_eq!(dev.outstanding(), 0);
    assert_eq!(ops.iopoll(devt), Some(0));
    registry::unregister("vdq3");
}

// A backend with no poll operation must not accept work it finishes later:
// the completion would have nothing to find it. It hands the request back
// intact so the caller can serve it the ordinary way.
#[test]
fn an_unpollable_backend_hands_the_direct_request_back() {
    let idx = registry::register("vdq4", disk(8));
    let devt = vfs::Devt(dev_t_of("vdq4", idx).unwrap());
    let ops = vfs::lookup_blkdev(devt).unwrap();
    let (slot, done) = direct_probe();
    let r = ops.submit_direct(devt, vfs::file_ops::DirectIo {
        write: false, off: 0, buf: vec![0u8; 512], done,
    });
    match r {
        vfs::file_ops::DirectSubmit::Unsupported(io) => assert_eq!(io.len(), 512),
        _ => panic!("an unpollable backend queues nothing"),
    }
    assert!(slot.lock().is_none());
    registry::unregister("vdq4");
}

// The whole chain a polled ring walks: `file->f_op->submit_direct` on an
// open `/dev/vdX` description → the device node's block dispatch → this
// bridge → the driver's queue. Every link defaults to "queues nothing", so
// a missing one collapses this to `Unsupported`.
#[test]
fn f_op_submit_direct_on_an_open_block_description_reaches_the_driver() {
    let dev = crate::tests::QueuedDisk::new();
    let idx = registry::register("vdq5", Arc::clone(&dev) as Arc<dyn BlockDevice>);
    let devt = vfs::Devt(dev_t_of("vdq5", idx).unwrap());
    let sb = test_sb();
    let node = make_device_node_inode(1, FileType::BlockDev, devt, 0o660, Arc::downgrade(&sb));
    let file = File::new(node.clone(), vfs::dcache::d_obtain_alias(node), OpenFlags::empty());
    file.open_hook().expect("block description opens");
    let (slot, done) = direct_probe();
    assert!(file.submit_direct(vfs::file_ops::DirectIo {
        write: false, off: 0, buf: vec![0u8; 1024], done,
    }).is_queued(), "f_op->submit_direct reaches the driver's queue");
    assert!(slot.lock().is_none(), "still outstanding after the submitting call");
    assert_eq!(file.iopoll(), Some(1));
    assert_eq!(slot.lock().as_ref().unwrap().1, Ok(1024));
    drop(file);
    registry::unregister("vdq5");
}

#[test]
fn real_block_file_lifecycle_blocks_unregister_until_final_fput() {
    let idx = registry::register("vdt", disk(8));
    let devt = vfs::Devt(dev_t_of("vdt", idx).unwrap());
    let sb = test_sb();
    let node = make_device_node_inode(1, FileType::BlockDev, devt, 0o660, Arc::downgrade(&sb));
    let file = File::new(node.clone(), vfs::dcache::d_obtain_alias(node), OpenFlags::empty());
    file.open_hook().expect("block File ->open acquires generic opener");
    assert_eq!(opener_count("vdt"), Some(1));
    assert!(!registry::unregister("vdt"), "open file description blocks del_gendisk");
    let duplicate = file.clone();
    drop(file);
    assert_eq!(opener_count("vdt"), Some(1), "dup is one opener");
    drop(duplicate);
    assert_eq!(opener_count("vdt"), Some(0));
    assert!(registry::unregister("vdt"));
}
