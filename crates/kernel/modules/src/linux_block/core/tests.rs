extern crate alloc;
use super::bio::{bio_add_page, bio_alloc, bio_put, BIO_ADD_REJECTED};
use super::disk::{add_disk, alloc_disk, put_disk, write_disk_name, DEFAULT_MINORS};
use super::queue::{blk_alloc_queue, blk_cleanup_queue, blk_queue_logical_block_size, blk_queue_make_request, GFP_KERNEL};
use crate::linux_block::types::*;
use alloc::vec::Vec;
use block::BlockRequest;
use core::ffi::c_void;
use core::ptr::{copy_nonoverlapping, null_mut};
use sync::{Modules as ModulesLockClass, Spinlock};

const TEST_BLOCK_SIZE: u32 = LINUX_SECTOR_SIZE;
const TEST_BLOCKS: u64 = 8;
const TEST_DISK_NAME: &[u8] = b"kblk0";
const TEST_PUT_DISK_NAME: &[u8] = b"kblkput0";
const TEST_WRITE: &[u8] = b"oxide-block";
const TEST_PAGE_ORDER: u32 = 0;
const TEST_PAGE_LEN: u32 = 4096;
const TEST_BIO_VECS: u32 = 1;
const TEST_BOUNCE_LEN: u32 = 1024;

static BACKING: Spinlock<Vec<u8>, ModulesLockClass> = Spinlock::new(Vec::new());

unsafe extern "C" fn test_make_request(_q: *mut LinuxRequestQueue, bio: *mut LinuxBio) -> i32 {
    if bio.is_null() { return -LINUX_EINVAL; }
    // SAFETY: test calls with a live bio allocated by this module.
    let (op, off, len, data) = unsafe {
        ((*bio).bi_opf, ((*bio).bi_sector as usize) * (LINUX_SECTOR_SIZE as usize),
            (*bio).bi_size as usize, (*bio).bi_data)
    };
    let mut g = BACKING.lock();
    let end = off + len;
    if g.len() < end { g.resize(end, 0); }
    match op {
        REQ_OP_READ => {
            // SAFETY: data points to bi_size bytes owned by the bio.
            unsafe { copy_nonoverlapping(g[off..end].as_ptr(), data, len); }
        }
        REQ_OP_WRITE => {
            // SAFETY: data points to bi_size bytes owned by the bio.
            let src = unsafe { core::slice::from_raw_parts(data, len) };
            g[off..end].copy_from_slice(src);
        }
        REQ_OP_FLUSH => {}
        REQ_OP_DISCARD => {
            for b in &mut g[off..end] { *b = 0; }
        }
        _ => {
            // SAFETY: bio is live for the callback duration.
            unsafe { (*bio).bi_status = BLK_STS_IOERR; }
            return -LINUX_EIO;
        }
    }
    // SAFETY: bio is live for the callback duration.
    unsafe { (*bio).bi_status = BLK_STS_OK; }
    LINUX_OK
}

#[test]
fn export_symbols_registers_block_surface() {
    let _modules = crate::test_serial::claim();
    super::export_symbols();
    for name in [
        "blk_alloc_queue", "blk_cleanup_queue", "blk_queue_make_request",
        "blk_queue_logical_block_size", "alloc_disk", "add_disk",
        "del_gendisk", "submit_bio", "bio_alloc", "bio_put",
        "blk_mq_alloc_tag_set", "blk_mq_init_queue",
    ] {
        assert!(crate::symtab::is_exported(name));
    }
}

#[test]
fn gendisk_registers_adapter_and_submits_bio_io() {
    let _modules = crate::test_serial::claim();
    *BACKING.lock() = alloc::vec![0u8; (TEST_BLOCKS as usize) * (TEST_BLOCK_SIZE as usize)];
    let q = blk_alloc_queue(GFP_KERNEL);
    assert!(!q.is_null());
    // SAFETY: q is newly allocated by blk_alloc_queue.
    unsafe {
        blk_queue_make_request(q, Some(test_make_request));
        blk_queue_logical_block_size(q, TEST_BLOCK_SIZE);
    }
    let disk = alloc_disk(DEFAULT_MINORS);
    assert!(!disk.is_null());
    write_disk_name(disk, TEST_DISK_NAME);
    // SAFETY: disk and queue are live allocations owned by this test.
    unsafe {
        (*disk).queue = q;
        (*disk).capacity = TEST_BLOCKS;
        add_disk(disk);
    }
    let reg = block::registry::by_name("kblk0").expect("gendisk published");
    assert_eq!(reg.dev.block_size(), TEST_BLOCK_SIZE);
    assert_eq!(reg.dev.capacity_blocks(), TEST_BLOCKS);

    let mut w = BlockRequest::new_write(0, 1, alloc::vec![0u8; TEST_BLOCK_SIZE as usize]);
    w.buffer[..TEST_WRITE.len()].copy_from_slice(TEST_WRITE);
    reg.dev.submit_sync(&mut w).expect("write request");
    let mut r = BlockRequest::new_read(0, 1, TEST_BLOCK_SIZE);
    reg.dev.submit_sync(&mut r).expect("read request");
    assert_eq!(&r.buffer[..TEST_WRITE.len()], TEST_WRITE);

    drop(reg);
    // SAFETY: disk and queue are live allocations owned by this test; put_disk withdraws the registry
    // publication before freeing, which the assertion below checks.
    unsafe {
        put_disk(disk);
        blk_cleanup_queue(q);
    }
    assert!(block::registry::by_name("kblk0").is_none());
}

// Releasing a gendisk without del_gendisk must not leave the registry holding an adapter that
// dereferences the freed allocation from safe code.
#[test]
fn put_disk_withdraws_the_registry_publication() {
    let _modules = crate::test_serial::claim();
    let q = blk_alloc_queue(GFP_KERNEL);
    let disk = alloc_disk(DEFAULT_MINORS);
    write_disk_name(disk, TEST_PUT_DISK_NAME);
    // SAFETY: disk and q are the fresh allocations above, owned by this test and not yet published.
    unsafe {
        (*disk).queue = q;
        add_disk(disk);
    }
    assert!(block::registry::by_name("kblkput0").is_some(), "add_disk publishes");
    // SAFETY: same live gendisk; put_disk is the only release path taken here — del_gendisk is
    // deliberately skipped, which is the ownership hole this test pins.
    unsafe { put_disk(disk); }
    assert!(block::registry::by_name("kblkput0").is_none(), "put_disk unregisters");
    // SAFETY: q is still the test's own queue allocation; put_disk does not free it.
    unsafe { blk_cleanup_queue(q); }
}

// A page's capacity comes from the page: a resolvable page lends its whole run, not the bio owner's
// bounce buffer, and an over-long or misplaced window is refused outright rather than truncated.
#[test]
fn bio_add_page_bounds_by_the_page_not_the_bounce_buffer() {
    let _modules = crate::test_serial::claim();
    let page = crate::linux_alloc::alloc_pages(0, TEST_PAGE_ORDER);
    assert!(!page.is_null());
    let bio = bio_alloc(0, TEST_BIO_VECS);
    assert!(!bio.is_null());
    // SAFETY: bio is the live BioOwner interior from bio_alloc and page is the live descriptor from
    // alloc_pages; bio_add_page's precondition is exactly that pair.
    let added = unsafe { bio_add_page(bio, page as *mut c_void, TEST_PAGE_LEN, 0) };
    assert_eq!(added, TEST_PAGE_LEN as i32, "a 4K page lends 4K, not the 1K bounce buffer");
    // SAFETY: bio is still live and bi_size/bi_data are plain fields written by the call above.
    unsafe {
        assert_eq!((*bio).bi_size, TEST_PAGE_LEN);
        assert_eq!((*bio).bi_data, crate::linux_alloc::page_address(page));
    }
    // SAFETY: same live bio/page pair; this window runs one byte past the page end.
    let over = unsafe { bio_add_page(bio, page as *mut c_void, TEST_PAGE_LEN + 1, 0) };
    assert_eq!(over, BIO_ADD_REJECTED, "a length past the page end adds nothing");
    // SAFETY: same live bio/page pair; the offset alone already reaches the page end.
    let past = unsafe { bio_add_page(bio, page as *mut c_void, 1, TEST_PAGE_LEN) };
    assert_eq!(past, BIO_ADD_REJECTED, "an offset at the page end adds nothing");
    // SAFETY: same live bio/page pair; a tail window inside the page is accepted whole.
    let tail = unsafe { bio_add_page(bio, page as *mut c_void, TEST_PAGE_LEN / 2, TEST_PAGE_LEN / 2) };
    assert_eq!(tail, (TEST_PAGE_LEN / 2) as i32);
    // SAFETY: bio is the sole owner-interior pointer from bio_alloc and page is the descriptor from
    // alloc_pages; neither is read after its reclaim here.
    unsafe {
        bio_put(bio);
        crate::linux_alloc::__free_pages(page, TEST_PAGE_ORDER);
    }
}

// With no resolvable page the bio falls back to its owner's bounce buffer, whose length is then the
// honest bound — and an add longer than it is refused rather than silently truncated.
#[test]
fn bio_add_page_without_a_page_is_bounded_by_the_bounce_buffer() {
    let _modules = crate::test_serial::claim();
    let bio = bio_alloc(0, TEST_BIO_VECS);
    assert!(!bio.is_null());
    // SAFETY: bio is the live BioOwner interior from bio_alloc; a null page is the descriptor case
    // page_address rejects, which is bio_add_page's documented fallback arm.
    let added = unsafe { bio_add_page(bio, null_mut(), TEST_BOUNCE_LEN, 0) };
    assert_eq!(added, TEST_BOUNCE_LEN as i32);
    // SAFETY: same live bio; this add is one byte longer than the owner's bounce buffer.
    let over = unsafe { bio_add_page(bio, null_mut(), TEST_BOUNCE_LEN + 1, 0) };
    assert_eq!(over, BIO_ADD_REJECTED, "no partial count past the bounce buffer");
    // SAFETY: bio is the sole owner-interior pointer from bio_alloc and is not read after this reclaim.
    unsafe { bio_put(bio); }
}
