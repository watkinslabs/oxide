//! A store through a SHARED WRITABLE mapping of an f2fs file, and whether it
//! reaches the medium.
//!
//! The decisive test in this file is
//! `a_store_through_the_mapping_survives_a_flush_and_a_remount`, and it is
//! written so it CAN fail. Nothing is asserted about the mapping's own state:
//! the bytes are written through the frame a page table would point at, flushed
//! the way an `msync` flushes, and then read back from a filesystem mounted
//! FRESH over the device's bytes. A test that asserted the page was dirty, or
//! that the frame held the pattern, would pass whether or not the write ever
//! left memory — which is exactly the defect this path was built to remove.
//!
//! The frame allocator has to be up for any of it, because a shared mapping's
//! whole requirement is a machine frame: a heap buffer is not something a user
//! page table can address. `boot_hosted_frames` brings a real PMM up over a
//! host pool once per test binary, which is the same allocator the running
//! kernel installs.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use vfs::fs::FileSystem;
use vfs::FileType;

use crate::mount::F2fs;
use crate::opts::Options;
use crate::uapi::BLKSIZE;

const FILE_INO: u32 = 11;
const HOLE_INO: u32 = 12;
/// Pages the hosted pool holds. Enough for the fixture's pages plus the buddy's
/// own bitmaps, which are carved off the front of it.
const POOL_PAGES: usize = 4096;

/// Bring a real PMM up over a leaked host pool, once per test binary, so
/// `alloc_object_frame` hands out frames whose `frame_ptr` is live memory.
///
/// The HHDM is the identity-with-offset the PMM already understands: with
/// `hhdm_offset` set to the pool's base, `frame_ptr(pa)` is `base + pa`.
fn boot_hosted_frames() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static READY: AtomicUsize = AtomicUsize::new(0);
    // 0 = untouched, 1 = a thread is bringing it up, 2 = up.
    if READY.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_err() {
        while READY.load(Ordering::Acquire) != 2 { core::hint::spin_loop(); }
        return;
    }
    let span = (POOL_PAGES + 1) * BLKSIZE;
    let raw = alloc::boxed::Box::leak(vec![0u8; span].into_boxed_slice()).as_mut_ptr() as u64;
    // The PMM addresses its pool in whole pages from a page-aligned base.
    let base = (raw + BLKSIZE as u64 - 1) & !(BLKSIZE as u64 - 1);
    let regions = [boot_info::BootMemRegion {
        base_pa: 0, len: (POOL_PAGES * BLKSIZE) as u64, kind: boot_info::BootMemKind::Usable }];
    let info = boot_info::BootInfo {
        memmap_count: 1,
        memmap_ptr: regions.as_ptr(),
        seed: [0u8; 32],
        boot_ns: 0,
        rsdp_pa: 0,
        hhdm_offset: base,
        framebuffer: boot_info::BootFramebuffer::EMPTY,
        dtb_pa: 0, dtb_len: 0, dtb_crc32: 0, bsp_lapic_id: 0,
        _pad: 0,
    };
    // SAFETY: `regions` outlives the call; `hhdm_offset` is the live,
    // page-aligned base of a leaked host pool of exactly that length; this runs
    // once, serialised by the state word above.
    unsafe { pmm::setup::init_from_boot_info(&info).expect("hosted pmm"); }
    pmm::setup::init_page_meta(POOL_PAGES as u64);
    READY.store(2, Ordering::Release);
}

fn filled(byte: u8) -> Vec<u8> { vec![byte; BLKSIZE] }

type Disk = Arc<block::MemDisk<sync::TaskList>>;

/// A device holding `bytes`. # C: O(bytes)
fn disk(bytes: Vec<u8>) -> Disk {
    let blocks = bytes.len() as u64 / BLKSIZE as u64;
    let dev: Disk = block::MemDisk::new(BLKSIZE as u32, blocks);
    let mut req = block::BlockRequest::new_write(0, blocks as u32, bytes);
    block::BlockDevice::submit_sync(&*dev, &mut req).expect("device write");
    dev
}

/// Everything on `dev` right now. # C: O(device)
fn drain(dev: &Disk) -> Vec<u8> {
    let blocks = block::BlockDevice::capacity_blocks(&**dev);
    let mut req = block::BlockRequest::new_read(0, blocks as u32, BLKSIZE as u32);
    block::BlockDevice::submit_sync(&**dev, &mut req).expect("device read");
    req.buffer
}

/// A mounted volume holding a two-block file with real blocks, and a
/// two-block file that is ALL HOLE — the case where a mapped write is what
/// makes the file's storage exist.
fn mounted() -> (Arc<F2fs>, Disk) {
    boot_hosted_frames();
    let mut b = crate::test_image::with_root();
    let data: Vec<(u64, Vec<u8>)> = (0..2u64).map(|i| (i, filled(0xA0 + i as u8))).collect();
    crate::test_image::nodes::add_sparse_file(&mut b, FILE_INO, 2 * BLKSIZE as u64, &data);
    crate::test_image::nodes::add_sparse_file(&mut b, HOLE_INO, 2 * BLKSIZE as u64, &[]);
    let dev = disk(b.finish());
    let fs = F2fs::open_with(dev.clone(), "/dev/fake", true, Options::defaults()).expect("mount");
    fs.volume.lock().set_iostat_enabled(true);
    (fs, dev)
}

fn remount(dev: &Disk) -> Arc<F2fs> {
    let fresh = disk(drain(dev));
    F2fs::open_with(fresh, "/dev/fake", true, Options::defaults()).expect("remount")
}

fn mapping_of(fs: &Arc<F2fs>, ino: u32) -> Arc<dyn vfs::mapping::AddressSpaceOps> {
    crate::mount::mapping::address_space(fs, ino, FileType::Regular).expect("address space")
}

/// What the memory manager does with the frame a mapping handed it: a plain CPU
/// store, no syscall, nothing the filesystem is told about.
fn store_through_frame(pa: u64, at: usize, bytes: &[u8]) {
    let base = pmm::setup::frame_ptr(pa).expect("frame pointer");
    // SAFETY: `pa` is the frame the mapping published for this page; the write
    // stays inside its BLKSIZE span.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(at), bytes.len()); }
}

/// The fault's own order: tell the filesystem the page is about to be written,
/// then take the frame the page table will point at.
fn fault_write(m: &Arc<dyn vfs::mapping::AddressSpaceOps>, off: u64) -> u64 {
    m.page_mkwrite(off).expect("page_mkwrite");
    m.shared_frame(off).expect("shared_frame").expect("a shared mapping needs a frame").pa
}

/// A shared writable mapping of a file has a frame at all.
///
/// The wire everything else rests on: with no frame the fault path falls back to
/// a private copy-on-write page, the store lands in that copy, and no flush ever
/// reaches it.
#[test]
fn a_shared_mapping_of_a_file_has_a_frame_to_point_at() {
    let (fs, _dev) = mounted();
    let m = mapping_of(&fs, FILE_INO);
    let pa = m.shared_frame(0).expect("frame").expect("a file's page must be mappable");
    assert_ne!(pa.pa, 0);
    assert!(!pa.map_ref_held, "the caller takes the mapping's reference when it installs the PTE");
}

/// Both asks for one page answer the SAME frame, which is what "one copy"
/// means: two mappers of one file write the same memory.
#[test]
fn two_asks_for_one_page_answer_the_same_frame() {
    let (fs, _dev) = mounted();
    let m = mapping_of(&fs, FILE_INO);
    let a = m.shared_frame(0).expect("a").expect("a present");
    let b = m.shared_frame(0).expect("b").expect("b present");
    assert_eq!(a.pa, b.pa, "a page's frame is chosen once, so a mapper's address is stable");
}

/// The frame a mapping hands out holds the file's bytes, not zeroes.
#[test]
fn the_frame_a_mapping_hands_out_holds_the_files_bytes() {
    let (fs, _dev) = mounted();
    let m = mapping_of(&fs, FILE_INO);
    let pa = m.shared_frame(0).expect("frame").expect("present").pa;
    let base = pmm::setup::frame_ptr(pa).expect("frame pointer");
    // SAFETY: the mapping's own frame for page 0, read within its span.
    let seen = unsafe { core::slice::from_raw_parts(base, BLKSIZE) };
    assert!(seen.iter().all(|&b| b == 0xA0), "a mapper must see the file, not an empty page");
}

/// THE test. A store through the mapping survives a flush and a remount.
///
/// Falsifiable by construction: the bytes are read back from a filesystem
/// mounted fresh over the device's own contents, so nothing in memory can make
/// it pass. Before this lane it failed — `shared_frame` answered `None`, so
/// there was no frame to store into at all.
#[test]
fn a_store_through_the_mapping_survives_a_flush_and_a_remount() {
    let (fs, dev) = mounted();
    let pattern = *b"MAPPED-WRITE";
    {
        let m = mapping_of(&fs, FILE_INO);
        let pa = fault_write(&m, 0);
        store_through_frame(pa, 0, &pattern);
        // An `msync`, which has no descriptor and reaches the mapping directly.
        m.writeback().expect("msync writeback");
        m.sync_backing().expect("msync durability");
    }
    let fresh = remount(&dev);
    let whole = fresh.read_all(FILE_INO).expect("read after remount");
    assert_eq!(&whole[..pattern.len()], &pattern[..], "the mapped store reached the medium");
}

/// The same for a page the file had no block for. A shared-writable fault is
/// where a HOLE gets storage, so this is the case that needs the reservation.
#[test]
fn a_store_into_a_hole_through_the_mapping_reserves_a_block_and_persists() {
    let (fs, dev) = mounted();
    let pattern = *b"HOLE-FILLED";
    {
        let m = mapping_of(&fs, HOLE_INO);
        let pa = fault_write(&m, 0);
        store_through_frame(pa, 0, &pattern);
        m.writeback().expect("msync writeback");
        m.sync_backing().expect("msync durability");
    }
    let fresh = remount(&dev);
    let whole = fresh.read_all(HOLE_INO).expect("read after remount");
    assert_eq!(&whole[..pattern.len()], &pattern[..],
               "a mapped store over a hole was given a block and kept");
}

/// The reservation is already a claim on free space before writeback places
/// the block, so `statfs` must publish it at the write fault itself.
#[test]
fn statfs_counts_a_mapped_write_reservation_before_writeback() {
    let (fs, _dev) = mounted();
    let before = fs.super_ops().expect("superblock operations").statfs().unwrap().f_bfree;
    let m = mapping_of(&fs, HOLE_INO);
    fault_write(&m, 0);
    let after = fs.super_ops().expect("superblock operations").statfs().unwrap().f_bfree;
    assert_eq!(after, before - 1, "the unplaced reservation already occupies one block");
}

/// A `read` and the mapping are the same page, in both directions.
#[test]
fn a_read_sees_the_mapped_store_and_the_mapping_sees_the_write() {
    let (fs, _dev) = mounted();
    let m = mapping_of(&fs, FILE_INO);
    let pa = fault_write(&m, 0);
    store_through_frame(pa, 0, b"ONECOPY");
    let whole = fs.read_all(FILE_INO).expect("read");
    assert_eq!(&whole[..7], b"ONECOPY", "a read of a mapped file goes through the mapper's page");

    // And the other way: a write(2) is visible through the frame the mapper
    // already holds, without the frame moving.
    fs.write(FILE_INO, 0, b"WROTE!!").expect("write");
    let again = m.shared_frame(0).expect("frame").expect("present").pa;
    assert_eq!(again, pa, "a write did not move the page out from under the mapper");
    let base = pmm::setup::frame_ptr(pa).expect("frame pointer");
    // SAFETY: still the mapping's own frame for page 0.
    let seen = unsafe { core::slice::from_raw_parts(base, 7) };
    assert_eq!(seen, b"WROTE!!", "the mapper sees a write through a descriptor");
}

/// A hint may not drop a page a page table is pointing at: the mapper would go
/// on writing a frame the mapping had stopped tracking, and the next reader of
/// the offset would fill a second, different one.
#[test]
fn a_hint_spares_a_page_a_mapper_is_holding() {
    let (fs, _dev) = mounted();
    let m = mapping_of(&fs, FILE_INO);
    let pa = fault_write(&m, 0);
    // Take the mapping's reference the way the fault path does when it installs
    // the page-table entry, so the frame is genuinely user-mapped.
    // SAFETY: `pa` is a live object frame the mapping published; this models the
    // one reference a PTE install takes and the block below returns.
    unsafe { pmm::setup::inc_ref(pa); }
    // A page dirtied THROUGH the fault is spared on the dirty rule, which is
    // the case that could not be constructed at all before this lane: no page
    // could be dirtied through a mapping.
    assert_eq!(m.try_invalidate_pages(0, 1), 0, "a page dirtied through a fault is not spared away");
    // Then clean it, so what the rest of this test measures is the MAPPED rule
    // rather than the dirty one.
    m.writeback().expect("flush");
    let dropped = m.try_invalidate_pages(0, 1);
    let after = m.shared_frame(0).expect("frame").expect("present").pa;
    // SAFETY: returning the reference taken above.
    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
    assert_eq!(dropped, 0, "a mapped page is not a page a hint may spare");
    assert_eq!(after, pa, "and the mapper's address did not change under it");
}

/// A mapped write is charged where the report can see it. Before this lane the
/// two WRITE-side mapped rows had no charge site anywhere and read zero.
#[test]
fn a_mapped_write_is_charged_to_the_mapped_layer() {
    let (fs, _dev) = mounted();
    let m = mapping_of(&fs, FILE_INO);
    let before = fs.volume.lock().counters().iostat;
    fault_write(&m, 0);
    let after = fs.volume.lock().counters().iostat;
    let idx = crate::stats::iostat::Io::AppMapped as usize;
    assert_eq!(after.bytes[idx] - before.bytes[idx], BLKSIZE as u64,
               "a mapped write charges one block to the mapped layer");
    assert_eq!(after.count[idx] - before.count[idx], 1);
}

/// The refusals, each of which is a store that must NOT be accepted. A fault
/// that accepted one of these would either corrupt a file the filesystem
/// refuses to change or lose the write at the flush.
#[test]
fn a_mapped_write_past_the_end_of_the_file_is_refused() {
    let (fs, _dev) = mounted();
    let m = mapping_of(&fs, FILE_INO);
    // The file is two blocks; page 2 begins at its end.
    assert!(m.page_mkwrite(2 * BLKSIZE as u64).is_err(),
            "a fault past the end of a mapping's object is not a write the object accepts");
}

#[test]
fn a_mapped_write_to_an_immutable_file_is_refused() {
    let (fs, _dev) = mounted();
    {
        let mut v = fs.volume.lock();
        let mut block = v.inode_bytes(FILE_INO).expect("inode bytes");
        crate::volume::dnode::put32(&mut block, crate::uapi::I_FLAGS,
                                    crate::flags::F2FS_IMMUTABLE_FL);
        v.put_inode(FILE_INO, block).expect("stamp immutable");
    }
    let m = mapping_of(&fs, FILE_INO);
    assert_eq!(m.page_mkwrite(0), Err(vfs::VfsError::Eperm),
               "a file whose contents are fixed is fixed however it is reached");
}

/// A range flush writes the pages in the range and LEAVES the rest dirty.
///
/// The whole-file flush is a correct superset and would pass an assertion that
/// only checked the named page landed, so what is asserted is the OTHER page:
/// it must still be dirty afterwards.
#[test]
fn a_range_flush_writes_the_range_and_leaves_the_rest_dirty() {
    let (fs, _dev) = mounted();
    let m = mapping_of(&fs, FILE_INO);
    let pa0 = fault_write(&m, 0);
    let pa1 = fault_write(&m, BLKSIZE as u64);
    store_through_frame(pa0, 0, b"PAGE-ZERO");
    store_through_frame(pa1, 0, b"PAGE-ONE");
    assert_eq!(fs.volume.lock().data_cache().dirty_pages(FILE_INO), 2, "both pages are dirty");

    m.writeback_range(0, BLKSIZE as u64).expect("range flush");

    assert_eq!(fs.volume.lock().data_cache().dirty_pages(FILE_INO), 1,
               "a range flush placed the page in the range and only that page");
    let states = fs.volume.lock().data_cache().states(FILE_INO, 0, 1);
    let still_dirty: Vec<u64> = states.iter().filter(|s| s.dirty).map(|s| s.index).collect();
    assert_eq!(still_dirty, vec![1], "the page outside the range kept its dirty state");
}

/// The block a mapped store over a HOLE needs is claimed at the FAULT, not at
/// the flush.
///
/// This is what the reservation buys, and persistence alone does not prove it:
/// the flush chooses an address for any dirty page it meets, so a store can
/// reach the medium with nothing ever charged for it. What that costs is the
/// refusal — `ENOSPC` and the owner's quota are decided at the reservation, and
/// a volume that only discovers it is full at writeback has already told the
/// caller the store succeeded. So what is asserted is the volume's own free
/// count, before any flush runs.
#[test]
fn a_mapped_store_over_a_hole_claims_its_block_at_the_fault() {
    let (fs, _dev) = mounted();
    let m = mapping_of(&fs, HOLE_INO);
    let before = fs.volume.lock().read_inode(HOLE_INO).expect("inode").blocks;
    m.page_mkwrite(0).expect("page_mkwrite");
    let after = fs.volume.lock().read_inode(HOLE_INO).expect("inode").blocks;
    assert_eq!(after - before, 1,
               "a hole's block is claimed while the fault can still be refused");
    // And a second fault on the same page claims nothing more: the slot is
    // already paid for, and charging twice would report the file bigger on the
    // medium than it is.
    m.page_mkwrite(0).expect("page_mkwrite again");
    assert_eq!(fs.volume.lock().read_inode(HOLE_INO).expect("inode").blocks, after,
               "a slot already reserved is not paid for twice");
}

/// A mapped store into the last page of a file whose length is not a whole
/// number of blocks does not publish the bytes past the end.
///
/// The page is written back WHOLE, so whatever the frame held past `i_size`
/// reaches the medium; it becomes visible the moment the file grows over it,
/// which is what this reads back.
///
/// HONEST about what this pins: removing the fault's own tail-zeroing leaves it
/// GREEN, because the shortening already zeroed the cached page's tail, so on
/// every ordering reachable from here the tail is zero before the fault sees it.
/// The zeroing stays because the reference does it and because a page filled
/// before a CONCURRENT shortening would not be covered by the truncate — but
/// that ordering is not constructible from a single thread, so this test pins
/// the OUTCOME and not the step. Recorded in `scratch/known_issues.md`.
#[test]
fn the_tail_past_the_end_of_the_file_is_not_published_by_a_mapped_store() {
    let (fs, dev) = mounted();
    // A one-and-a-bit block file: the last page's tail is not part of it.
    let short = BLKSIZE as u64 + 100;
    fs.truncate(FILE_INO, short).expect("shorten");
    {
        let m = mapping_of(&fs, FILE_INO);
        let pa = fault_write(&m, BLKSIZE as u64);
        // A store INSIDE the file, in the page whose tail is outside it.
        store_through_frame(pa, 0, b"INSIDE");
        m.writeback().expect("flush");
        m.sync_backing().expect("durability");
    }
    let fresh = remount(&dev);
    // Grow the file over the tail: what was past the end reads as a hole would,
    // which is zero — never the 0xA1 the page held before the mapping wrote it.
    fresh.truncate(FILE_INO, 2 * BLKSIZE as u64).expect("grow over the old tail");
    let whole = fresh.read_all(FILE_INO).expect("read after remount");
    assert_eq!(&whole[BLKSIZE..BLKSIZE + 6], b"INSIDE", "the store inside the file landed");
    assert!(whole[BLKSIZE + 100..].iter().all(|&b| b == 0),
            "the bytes past the old end of the file were never published");
}

/// A page already mapped for READING keeps its frame across the write fault
/// that reserves its block.
///
/// This is the re-fault the memory manager takes when a shared mapping was
/// faulted in read-only and is then written: it holds a page-table entry for a
/// frame it already has, and the write-fault arm only re-installs that entry if
/// the address it is offered MATCHES. A reservation that dropped the mapping's
/// page would hand back a different frame, the arm would fall through to a
/// private copy-on-write page, and the store would be lost exactly as it was
/// before any of this existed.
#[test]
fn a_page_mapped_for_reading_keeps_its_frame_across_the_write_fault() {
    let (fs, _dev) = mounted();
    let m = mapping_of(&fs, HOLE_INO);
    // The read fault: a frame, no reservation.
    let read_pa = m.shared_frame(0).expect("read fault").expect("frame present").pa;
    // The write fault on the SAME page, which is what takes the block.
    m.page_mkwrite(0).expect("page_mkwrite");
    let write_pa = m.shared_frame(0).expect("write fault").expect("frame present").pa;
    assert_eq!(write_pa, read_pa,
               "reserving the block must not move the page the mapper is already pointing at");
}
