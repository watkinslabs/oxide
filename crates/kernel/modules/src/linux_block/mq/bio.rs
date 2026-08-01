extern crate alloc;
use crate::linux_block::core;
use crate::linux_block::types::*;
use ::core::ffi::c_void;
use ::core::ptr::{null_mut, write_bytes};

/// Register the blk-mq-side BIO symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("submit_bio_noacct",   submit_bio_noacct   as *const () as usize),
        ("submit_bio_wait",     submit_bio_wait     as *const () as usize),
        ("__bio_add_page",      __bio_add_page      as *const () as usize),
        ("bio_alloc_bioset",    bio_alloc_bioset    as *const () as usize),
        ("bio_init",            bio_init            as *const () as usize),
        ("bio_endio",           bio_endio           as *const () as usize),
        ("bio_chain",           bio_chain           as *const () as usize),
        ("bio_split_to_limits", bio_split_to_limits as *const () as usize),
        ("bio_associate_blkg",  bio_associate_blkg  as *const () as usize),
        ("bio_blkcg_css",       bio_blkcg_css       as *const () as usize),
        ("zero_fill_bio_iter",  zero_fill_bio_iter  as *const () as usize),
        ("__SCK__tp_func_block_bio_remap", trace_block_bio_remap as *const () as usize),
        ("__SCT__tp_func_block_bio_remap", trace_block_bio_remap as *const () as usize),
    ] { export(name, addr, false); }
    export("__tracepoint_block_bio_remap", &TRACEPOINT_BLOCK_BIO_REMAP as *const usize as usize, false);
}

unsafe extern "C" fn submit_bio_noacct(bio: *mut LinuxBio) {
    // SAFETY: submit_bio_noacct forwards the caller-supplied bio.
    let _ = unsafe { core::submit_bio(bio) };
}

unsafe extern "C" fn submit_bio_wait(bio: *mut LinuxBio) -> i32 {
    // SAFETY: submit_bio_wait forwards the caller-supplied bio synchronously.
    unsafe { core::submit_bio(bio) }
}

unsafe extern "C" fn __bio_add_page(bio: *mut LinuxBio, page: *mut c_void, len: u32, off: u32) -> i32 {
    // SAFETY: forwards the caller-supplied bio/page tuple to the shared BIO helper, which derives its
    // bound from the page descriptor itself and refuses any window that leaves the page.
    unsafe { core::bio_add_page(bio, page, len, off) }
}

extern "C" fn bio_alloc_bioset(gfp: u32, nr: u32, _bs: *mut c_void) -> *mut LinuxBio {
    core::bio_alloc(gfp, nr)
}

unsafe extern "C" fn bio_init(bio: *mut LinuxBio, _bdev: *mut LinuxBlockDevice, table: *mut c_void, nr: u32, opf: u32) {
    if bio.is_null() { return; }
    // SAFETY: bio points to caller-provided storage.
    unsafe {
        (*bio).bi_disk = null_mut();
        (*bio).bi_bdev = null_mut();
        (*bio).bi_private = null_mut();
        (*bio).bi_sector = 0;
        (*bio).bi_opf = opf;
        (*bio).bi_status = BLK_STS_OK;
        (*bio).bi_size = nr.saturating_mul(LINUX_SECTOR_SIZE);
        (*bio).bi_data = table as *mut u8;
        (*bio).bi_end_io = None;
        (*bio).owner = null_mut();
    }
}

unsafe extern "C" fn bio_endio(bio: *mut LinuxBio) {
    if bio.is_null() { return; }
    // SAFETY: bio is null-checked; bi_end_io is an Option<fn> field that bio_alloc_with_len and bio_init both
    // initialise to None, so the load is defined even for a bio no module ever touched.
    if let Some(f) = unsafe { (*bio).bi_end_io } {
        // SAFETY: driver callback receives the live bio supplied by caller.
        unsafe { f(bio); }
    }
}

unsafe extern "C" fn bio_chain(_bio: *mut LinuxBio, _parent: *mut LinuxBio) {}
unsafe extern "C" fn bio_split_to_limits(bio: *mut LinuxBio) -> *mut LinuxBio { bio }
unsafe extern "C" fn bio_associate_blkg(_bio: *mut LinuxBio) -> i32 { LINUX_OK }
unsafe extern "C" fn bio_blkcg_css(_bio: *mut LinuxBio) -> *mut c_void { null_mut() }

unsafe extern "C" fn zero_fill_bio_iter(bio: *mut LinuxBio) {
    if bio.is_null() { return; }
    // SAFETY: bio is null-checked; bi_data and bi_size are the pair every writer of this shim sets together —
    // bio_alloc_with_len sizes bi_data from the owner's buffer, and bio_add_page only installs a bi_size the
    // region behind bi_data can hold — so bi_size bytes at bi_data are writable whenever bi_data is non-null.
    unsafe {
        if !(*bio).bi_data.is_null() { write_bytes((*bio).bi_data, 0, (*bio).bi_size as usize); }
    }
}

extern "C" fn trace_block_bio_remap() {}
static TRACEPOINT_BLOCK_BIO_REMAP: usize = 0;
