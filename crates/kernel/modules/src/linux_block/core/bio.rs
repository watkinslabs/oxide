extern crate alloc;
use crate::linux_alloc::{page_address, page_run_len, LinuxPage};
use crate::linux_block::contract::addable_bytes;
use crate::linux_block::types::*;
use alloc::boxed::Box;
use alloc::vec::Vec;
use block::{BlockOp, BlockRequest};
use core::ffi::c_void;
use core::ptr::{copy_nonoverlapping, null_mut};

const DEFAULT_BIO_VEC_COUNT: u32 = 1;
const BYTES_PER_KIB: u32 = 1024;
pub(super) const BIO_ADD_REJECTED: i32 = 0;

pub(super) struct BioOwner {
    pub(super) bio: LinuxBio,
    pub(super) buf: Vec<u8>,
    pub(super) bdev: LinuxBlockDevice,
}

/// Register the BIO half of the block KPI.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("submit_bio",   submit_bio   as *const () as usize, false);
    export("bio_alloc",    bio_alloc    as *const () as usize, false);
    export("bio_put",      bio_put      as *const () as usize, false);
    export("bio_set_dev",  bio_set_dev  as *const () as usize, false);
    export("bio_add_page", bio_add_page as *const () as usize, false);
}

pub(in crate::linux_block) unsafe extern "C" fn submit_bio(bio: *mut LinuxBio) -> i32 {
    if bio.is_null() { return -LINUX_EINVAL; }
    // SAFETY: bio is null-checked above; every bio reaching this KPI comes from bio_alloc (interior of a
    // BioOwner Box) or from bio_init on module-owned storage, both of which initialise bi_disk to a gendisk
    // pointer or null. The null cases are rejected on the next lines before any further dereference.
    let disk = unsafe { (*bio).bi_disk };
    if disk.is_null() { return -LINUX_EINVAL; }
    // SAFETY: disk is the non-null gendisk the bio names; `queue` is a plain field alloc_disk_node
    // initialises to null, and the null case is rejected on the next line.
    let q = unsafe { (*disk).queue };
    if q.is_null() { return -LINUX_EINVAL; }
    // SAFETY: q is the non-null queue of that gendisk; make_request_fn is an Option<fn> field of the
    // blk_alloc_queue Box, so the load is defined even when no module ever installed a callback.
    let make = unsafe { (*q).make_request_fn };
    let Some(f) = make else { return -LINUX_EIO; };
    // SAFETY: queue callback owns the bio for the duration of submit_bio.
    unsafe { f(q, bio) }
}

pub(in crate::linux_block) extern "C" fn bio_alloc(_gfp_mask: u32, nr_iovecs: u32) -> *mut LinuxBio {
    let len = (nr_iovecs.max(DEFAULT_BIO_VEC_COUNT) as usize) * BYTES_PER_KIB as usize;
    bio_alloc_with_len(len)
}

pub(super) unsafe extern "C" fn bio_put(bio: *mut LinuxBio) {
    if bio.is_null() { return; }
    // SAFETY: owner was installed by bio_alloc_with_len.
    let owner = unsafe { (*bio).owner as *mut BioOwner };
    if owner.is_null() { return; }
    // SAFETY: owner is uniquely reclaimed by bio_put.
    unsafe { drop(Box::from_raw(owner)); }
}

unsafe extern "C" fn bio_set_dev(bio: *mut LinuxBio, bdev: *mut LinuxBlockDevice) {
    if bio.is_null() { return; }
    // SAFETY: bio is live and bdev may be NULL.
    unsafe {
        (*bio).bi_bdev = bdev;
        (*bio).bi_disk = if bdev.is_null() { null_mut() } else { (*bdev).bd_disk };
    }
}

/// Add `len` bytes at `off` of `page` to `bio`, returning the bytes added (all of `len`, or none).
///
/// The capacity a bio may take is a property of the region it will point at, never of the bio: when
/// the page descriptor resolves, the bound is the page run's own length; otherwise the bio falls back
/// to its owner's bounce buffer and the bound is that buffer. Both are all-or-nothing, so a caller can
/// never mistake a truncated count for a completed add.
/// # C: O(1)
pub(in crate::linux_block) unsafe extern "C" fn bio_add_page(bio: *mut LinuxBio, page: *mut c_void, len: u32, off: u32) -> i32 {
    if bio.is_null() { return BIO_ADD_REJECTED; }
    // SAFETY: bio is null-checked; `owner` is the BioOwner back-pointer bio_alloc_with_len installed (null
    // for bio_init storage, rejected below), so the load is defined for every bio this shim hands out.
    let owner = unsafe { (*bio).owner as *mut BioOwner };
    if owner.is_null() { return BIO_ADD_REJECTED; }
    let page = page as *mut LinuxPage;
    // SAFETY: page_address' precondition is a NULL pointer or an alloc_pages descriptor, which is exactly
    // bio_add_page's `page` argument; it validates the descriptor magic and yields null for anything else.
    let page_data = page_address(page);
    if !page_data.is_null() {
        // page_run_len shares page_address' precondition and is called on the same descriptor, so when
        // page_address resolved a mapping this returns the run length recorded for it.
        let Some(page_len) = page_run_len(page) else { return BIO_ADD_REJECTED; };
        let n = addable_bytes(page_len, off as usize, len as usize);
        if n == 0 { return BIO_ADD_REJECTED; }
        // SAFETY: addable_bytes returned non-zero, so off + n <= page_len and the whole [off, off + n)
        // window lies inside the page run page_address mapped; bi_data/bi_size are plain fields of the
        // null-checked bio, and every reader of bi_data (zero_fill_bio_iter, the module's make_request_fn)
        // is bounded by the bi_size written on the same line.
        unsafe {
            (*bio).bi_data = page_data.add(off as usize);
            (*bio).bi_size = n as u32;
        }
        return n as i32;
    }
    // SAFETY: owner is the non-null BioOwner interior established above; its `buf` is the Vec allocated by
    // bio_alloc_with_len and still owned by that Box, so reading its length is defined.
    let buf_len = unsafe { (*owner).buf.len() };
    // The descriptor did not resolve, so this bio cannot point into the caller's page and falls back to the
    // owner's bounce buffer, which starts at offset zero — `off` names a position in the page, not in it.
    let n = addable_bytes(buf_len, 0, len as usize);
    if n == 0 { return BIO_ADD_REJECTED; }
    // SAFETY: addable_bytes returned non-zero, so n <= buf_len and bi_data..bi_data+n stays inside the
    // owner's bounce buffer, which outlives the bio because both are fields of the same BioOwner Box.
    unsafe {
        (*bio).bi_data = (*owner).buf.as_mut_ptr();
        (*bio).bi_size = n as u32;
    }
    n as i32
}

pub(super) fn bio_alloc_with_len(len: usize) -> *mut LinuxBio {
    let mut owner = Box::new(BioOwner {
        bio: LinuxBio {
            bi_disk: null_mut(),
            bi_bdev: null_mut(),
            bi_private: null_mut(),
            bi_sector: 0,
            bi_opf: REQ_OP_READ,
            bi_status: BLK_STS_OK,
            bi_size: len as u32,
            bi_data: null_mut(),
            bi_end_io: None,
            owner: null_mut(),
        },
        buf: alloc::vec![0u8; len],
        bdev: LinuxBlockDevice {
            bd_disk: null_mut(),
            bd_queue: null_mut(),
            bd_private: null_mut(),
        },
    });
    owner.bio.bi_data = owner.buf.as_mut_ptr();
    owner.bio.owner = (&mut *owner) as *mut BioOwner as *mut c_void;
    let ptr = &mut owner.bio as *mut LinuxBio;
    let _ = Box::into_raw(owner);
    ptr
}

pub(super) fn bio_from_request(disk: *mut LinuxGendisk, req: &BlockRequest, sector: u64, op: u32) -> *mut LinuxBio {
    let len = request_bytes(disk, req);
    let bio = bio_alloc_with_len(len);
    if bio.is_null() { return null_mut(); }
    // SAFETY: bio owner is newly allocated and uniquely initialized here.
    unsafe {
        let owner = (*bio).owner as *mut BioOwner;
        (*owner).bdev.bd_disk = disk;
        (*owner).bdev.bd_queue = (*disk).queue;
        (*owner).bdev.bd_private = (*disk).private_data;
        (*bio).bi_disk = disk;
        (*bio).bi_bdev = &mut (*owner).bdev;
        (*bio).bi_sector = sector;
        (*bio).bi_opf = op;
        (*bio).bi_status = BLK_STS_OK;
        (*bio).bi_size = len as u32;
        if req.op == BlockOp::Write && len != 0 {
            copy_nonoverlapping(req.buffer.as_ptr(), (*bio).bi_data, len.min(req.buffer.len()));
        }
    }
    bio
}

fn request_bytes(disk: *const LinuxGendisk, req: &BlockRequest) -> usize {
    if !req.buffer.is_empty() { return req.buffer.len(); }
    if req.len_blocks == 0 { return 0; }
    let bs = if disk.is_null() {
        DEFAULT_LOGICAL_BLOCK_SIZE
    } else {
        // SAFETY: disk is live while a request is translated through its adapter.
        let q = unsafe { (*disk).queue };
        if q.is_null() {
            DEFAULT_LOGICAL_BLOCK_SIZE
        } else {
            // SAFETY: q belongs to disk and logical_block_size is plain data.
            let n = unsafe { (*q).logical_block_size };
            if n == 0 { DEFAULT_LOGICAL_BLOCK_SIZE } else { n }
        }
    };
    (req.len_blocks as usize) * (bs as usize)
}

pub(super) unsafe fn bio_status_ok(bio: *const LinuxBio) -> bool {
    // SAFETY: caller guarantees bio points to a live LinuxBio.
    unsafe { !bio.is_null() && (*bio).bi_status == BLK_STS_OK }
}

pub(super) unsafe fn copy_bio_to_request(bio: *const LinuxBio, req: &mut BlockRequest) {
    if bio.is_null() || req.buffer.is_empty() { return; }
    // SAFETY: bio is live and data buffer has at least bi_size bytes.
    let n = unsafe { ((*bio).bi_size as usize).min(req.buffer.len()) };
    // SAFETY: source and destination are valid non-overlapping buffers.
    unsafe { copy_nonoverlapping((*bio).bi_data, req.buffer.as_mut_ptr(), n); }
}
