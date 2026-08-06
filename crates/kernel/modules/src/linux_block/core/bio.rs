extern crate alloc;
use crate::linux_alloc::{alloc_pages, page_address, page_put, page_run_len, LinuxPage, PAGE_SIZE};
use crate::linux_block::contract::addable_bytes;
use crate::linux_block::types::*;
use alloc::boxed::Box;
use alloc::vec::Vec;
use block::{BlockOp, BlockRequest};
use core::ffi::c_void;
use core::ptr::{copy_nonoverlapping, null_mut, write_bytes};

const DEFAULT_BIO_VEC_COUNT: u16 = 1;
const INTERNAL_PAGE_FLAGS: u32 = 0;
pub(super) const BIO_ADD_REJECTED: i32 = 0;

pub(super) struct BioOwner {
    pub(super) bio: LinuxBio,
    vecs: Vec<LinuxBioVec>,
    page: *mut LinuxPage,
    pub(super) bdev: LinuxBlockDevice,
}

impl Drop for BioOwner {
    fn drop(&mut self) {
        if !self.page.is_null() { page_put(self.page); }
    }
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
    // SAFETY: bio is null-checked and names caller storage or a BioOwner interior; both initialise bi_disk.
    let disk = unsafe { (*bio).bi_disk };
    if disk.is_null() { return -LINUX_EINVAL; }
    // SAFETY: disk is the live gendisk named by bio, and its queue field is readable for the submission.
    let q = unsafe { (*disk).queue };
    if q.is_null() { return -LINUX_EINVAL; }
    // SAFETY: q is the live request queue and make_request_fn is an initialised optional callback field.
    let make = unsafe { (*q).make_request_fn };
    let Some(f) = make else { return -LINUX_EIO; };
    // SAFETY: the registered queue callback borrows this live bio for the duration of the synchronous call.
    unsafe { f(q, bio) }
}

pub(in crate::linux_block) extern "C" fn bio_alloc(_gfp_mask: u32, nr_iovecs: u32) -> *mut LinuxBio {
    let nr = nr_iovecs.max(DEFAULT_BIO_VEC_COUNT as u32).min(u16::MAX as u32) as u16;
    bio_alloc_owned(nr)
}

pub(super) unsafe extern "C" fn bio_put(bio: *mut LinuxBio) {
    if bio.is_null() { return; }
    // SAFETY: bio is null-checked and every allocation path initialises owner to a BioOwner pointer or null.
    let owner = unsafe { (*bio).owner as *mut BioOwner };
    if owner.is_null() { return; }
    // SAFETY: BioOwner::bio is the allocation's stable interior and bio_put is its sole reclaim operation.
    unsafe { drop(Box::from_raw(owner)); }
}

unsafe extern "C" fn bio_set_dev(bio: *mut LinuxBio, bdev: *mut LinuxBlockDevice) {
    if bio.is_null() { return; }
    // SAFETY: bio is live and null bdev deliberately clears both device fields.
    unsafe {
        (*bio).bi_bdev = bdev;
        (*bio).bi_disk = if bdev.is_null() { null_mut() } else { (*bdev).bd_disk };
    }
}

/// Add the complete `[off, off + len)` page window as one BIO vector, or add nothing.
/// # C: O(1)
pub(in crate::linux_block) unsafe extern "C" fn bio_add_page(bio: *mut LinuxBio, page: *mut c_void, len: u32, off: u32) -> i32 {
    if bio.is_null() || page.is_null() || len == 0 { return BIO_ADD_REJECTED; }
    let page = page as *mut LinuxPage;
    let Some(page_len) = page_run_len(page) else { return BIO_ADD_REJECTED; };
    if addable_bytes(page_len, off as usize, len as usize) == 0 { return BIO_ADD_REJECTED; }
    // SAFETY: bio is null-checked and all construction paths initialise these scalar/vector fields.
    let (vecs, vcnt, max, size) = unsafe { ((*bio).bi_io_vec, (*bio).bi_vcnt, (*bio).bi_max_vecs, (*bio).bi_size) };
    if vecs.is_null() { return BIO_ADD_REJECTED; }
    let Some(total) = size.checked_add(len) else { return BIO_ADD_REJECTED; };
    if vcnt != 0 {
        // SAFETY: vcnt is bounded by max on every accepted add and vecs names a max-element table.
        let last = unsafe { &mut *vecs.add(vcnt as usize - 1) };
        if last.bv_page == page && last.bv_offset.checked_add(last.bv_len) == Some(off) {
            let Some(merged) = last.bv_len.checked_add(len) else { return BIO_ADD_REJECTED; };
            if addable_bytes(page_len, last.bv_offset as usize, merged as usize) == 0 { return BIO_ADD_REJECTED; }
            last.bv_len = merged;
            // SAFETY: bio is live and total is the checked sum of its old size and this accepted length.
            unsafe { (*bio).bi_size = total; }
            return len as i32;
        }
    }
    if vcnt >= max { return BIO_ADD_REJECTED; }
    // SAFETY: vcnt < max and vecs names max writable LinuxBioVec entries owned by bio or its caller.
    unsafe {
        vecs.add(vcnt as usize).write(LinuxBioVec { bv_page: page, bv_len: len, bv_offset: off });
        (*bio).bi_vcnt = vcnt + 1;
        (*bio).bi_size = total;
    }
    len as i32
}

fn bio_alloc_owned(max_vecs: u16) -> *mut LinuxBio {
    let max_vecs = max_vecs.max(DEFAULT_BIO_VEC_COUNT);
    let empty = LinuxBioVec { bv_page: null_mut(), bv_len: 0, bv_offset: 0 };
    let mut owner = Box::new(BioOwner {
        bio: LinuxBio {
            bi_disk: null_mut(),
            bi_bdev: null_mut(),
            bi_private: null_mut(),
            bi_sector: 0,
            bi_opf: REQ_OP_READ,
            bi_status: BLK_STS_OK,
            bi_size: 0,
            bi_io_vec: null_mut(),
            bi_vcnt: 0,
            bi_max_vecs: max_vecs,
            bi_end_io: None,
            owner: null_mut(),
        },
        vecs: alloc::vec![empty; max_vecs as usize],
        page: null_mut(),
        bdev: LinuxBlockDevice { bd_disk: null_mut(), bd_queue: null_mut(), bd_private: null_mut() },
    });
    owner.bio.bi_io_vec = owner.vecs.as_mut_ptr();
    owner.bio.owner = (&mut *owner) as *mut BioOwner as *mut c_void;
    let ptr = &mut owner.bio as *mut LinuxBio;
    let _ = Box::into_raw(owner);
    ptr
}

fn order_for_bytes(len: usize) -> Option<u32> {
    if len == 0 { return Some(0); }
    let pages = len.checked_add(PAGE_SIZE - 1)? / PAGE_SIZE;
    let run_pages = pages.checked_next_power_of_two()?;
    Some(run_pages.trailing_zeros())
}

pub(super) fn bio_from_request(disk: *mut LinuxGendisk, req: &BlockRequest, sector: u64, op: u32) -> *mut LinuxBio {
    let Some(len) = request_bytes(disk, req) else { return null_mut(); };
    let Ok(len_u32) = u32::try_from(len) else { return null_mut(); };
    let bio = bio_alloc_owned(DEFAULT_BIO_VEC_COUNT);
    if bio.is_null() { return null_mut(); }
    // SAFETY: bio is the live BioOwner interior returned above and its owner back-pointer is initialised.
    let owner = unsafe { (*bio).owner as *mut BioOwner };
    if len != 0 {
        let Some(order) = order_for_bytes(len) else {
            // SAFETY: bio is still solely owned by this frame and has not been published.
            unsafe { bio_put(bio); }
            return null_mut();
        };
        let page = alloc_pages(INTERNAL_PAGE_FLAGS, order);
        if page.is_null() {
            // SAFETY: bio is still solely owned by this frame and has not been published.
            unsafe { bio_put(bio); }
            return null_mut();
        }
        // SAFETY: owner is the BioOwner back-pointer above; recording page transfers its sole reference to Drop.
        unsafe { (*owner).page = page; }
        // SAFETY: bio and page are live owned allocations, and len was bounded to u32 above.
        if unsafe { bio_add_page(bio, page as *mut c_void, len_u32, 0) } != len_u32 as i32 {
            // SAFETY: BioOwner now owns page, so this single reclaim releases both allocations.
            unsafe { bio_put(bio); }
            return null_mut();
        }
    }
    // SAFETY: disk is the live gendisk supplied by the adapter and owner/bio are uniquely owned here.
    unsafe {
        (*owner).bdev.bd_disk = disk;
        (*owner).bdev.bd_queue = if disk.is_null() { null_mut() } else { (*disk).queue };
        (*owner).bdev.bd_private = if disk.is_null() { null_mut() } else { (*disk).private_data };
        (*bio).bi_disk = disk;
        (*bio).bi_bdev = &mut (*owner).bdev;
        (*bio).bi_sector = sector;
        (*bio).bi_opf = op;
        (*bio).bi_status = BLK_STS_OK;
        if req.op == BlockOp::Write && len != 0 { let _ = copy_slice_to_bio(bio, &req.buffer); }
    }
    bio
}

fn request_bytes(disk: *const LinuxGendisk, req: &BlockRequest) -> Option<usize> {
    if !req.buffer.is_empty() { return Some(req.buffer.len()); }
    if req.len_blocks == 0 { return Some(0); }
    let bs = if disk.is_null() {
        DEFAULT_LOGICAL_BLOCK_SIZE
    } else {
        // SAFETY: disk is live while its adapter translates this request and queue is only read here.
        let q = unsafe { (*disk).queue };
        if q.is_null() { DEFAULT_LOGICAL_BLOCK_SIZE } else {
            // SAFETY: q belongs to disk and logical_block_size is initialised queue data.
            let n = unsafe { (*q).logical_block_size };
            if n == 0 { DEFAULT_LOGICAL_BLOCK_SIZE } else { n }
        }
    };
    (req.len_blocks as usize).checked_mul(bs as usize)
}

unsafe fn vec_window(vec: *const LinuxBioVec) -> Option<(*mut u8, usize)> {
    if vec.is_null() { return None; }
    // SAFETY: caller passes an entry inside the live BIO vector table, so its fields are readable.
    let (page, off, len) = unsafe { ((*vec).bv_page, (*vec).bv_offset as usize, (*vec).bv_len as usize) };
    let page_len = page_run_len(page)?;
    if addable_bytes(page_len, off, len) == 0 { return None; }
    let base = page_address(page);
    if base.is_null() { return None; }
    // SAFETY: the checked vector window lies wholly inside the page run rooted at base.
    Some((unsafe { base.add(off) }, len))
}

pub(super) unsafe fn copy_slice_to_bio(bio: *mut LinuxBio, src: &[u8]) -> usize {
    if bio.is_null() { return 0; }
    // SAFETY: bio is live and all construction paths initialise its vector pointer and counts.
    let (vecs, count) = unsafe { ((*bio).bi_io_vec, (*bio).bi_vcnt.min((*bio).bi_max_vecs)) };
    let mut copied = 0usize;
    for i in 0..count as usize {
        // SAFETY: i is below the clamped count and vecs names the live vector table.
        let Some((dst, len)) = (unsafe { vec_window(vecs.add(i)) }) else { break; };
        let n = len.min(src.len().saturating_sub(copied));
        if n == 0 { break; }
        // SAFETY: src has n bytes from copied and dst names an n-byte writable page window.
        unsafe { copy_nonoverlapping(src.as_ptr().add(copied), dst, n); }
        copied += n;
    }
    copied
}

pub(super) unsafe fn copy_bio_to_slice(bio: *const LinuxBio, dst: &mut [u8]) -> usize {
    if bio.is_null() { return 0; }
    // SAFETY: bio is live and all construction paths initialise its vector pointer and counts.
    let (vecs, count) = unsafe { ((*bio).bi_io_vec, (*bio).bi_vcnt.min((*bio).bi_max_vecs)) };
    let mut copied = 0usize;
    for i in 0..count as usize {
        // SAFETY: i is below the clamped count and vecs names the live vector table.
        let Some((src, len)) = (unsafe { vec_window(vecs.add(i)) }) else { break; };
        let n = len.min(dst.len().saturating_sub(copied));
        if n == 0 { break; }
        // SAFETY: src names an n-byte readable page window and dst has n bytes from copied.
        unsafe { copy_nonoverlapping(src, dst.as_mut_ptr().add(copied), n); }
        copied += n;
    }
    copied
}

pub(in crate::linux_block) unsafe fn zero_bio(bio: *mut LinuxBio) {
    if bio.is_null() { return; }
    // SAFETY: bio is live and all construction paths initialise its vector pointer and counts.
    let (vecs, count) = unsafe { ((*bio).bi_io_vec, (*bio).bi_vcnt.min((*bio).bi_max_vecs)) };
    for i in 0..count as usize {
        // SAFETY: i is below the clamped count and vecs names the live vector table.
        if let Some((dst, len)) = unsafe { vec_window(vecs.add(i)) } {
            // SAFETY: dst names exactly len writable bytes within the vector's live page run.
            unsafe { write_bytes(dst, 0, len); }
        }
    }
}

pub(super) unsafe fn bio_status_ok(bio: *const LinuxBio) -> bool {
    // SAFETY: caller guarantees bio points to a live LinuxBio.
    unsafe { !bio.is_null() && (*bio).bi_status == BLK_STS_OK }
}

pub(super) unsafe fn copy_bio_to_request(bio: *const LinuxBio, req: &mut BlockRequest) {
    if bio.is_null() || req.buffer.is_empty() { return; }
    // SAFETY: bio remains live through the adapter call and req.buffer is the destination owned by caller.
    let _ = unsafe { copy_bio_to_slice(bio, &mut req.buffer) };
}
