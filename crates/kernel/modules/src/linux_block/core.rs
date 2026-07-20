extern crate alloc;
use super::types::*;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use block::{BlockDevice, BlockError, BlockOp, BlockRequest};
use core::ffi::{c_char, c_void};
use core::ptr::{copy_nonoverlapping, null_mut};
const DEFAULT_MINORS: i32 = 1;
const DEFAULT_BIO_VEC_COUNT: u32 = 1;
const DEFAULT_NODE_ID: i32 = 0;
const GFP_KERNEL: u32 = 0;
const BYTES_PER_KIB: u32 = 1024;
struct BioOwner {
    bio: LinuxBio,
    buf: Vec<u8>,
    bdev: LinuxBlockDevice,
}
struct LinuxBlockAdapter {
    disk: usize,
}
impl BlockDevice for LinuxBlockAdapter {
    fn block_size(&self) -> u32 {
        let d = self.disk as *const LinuxGendisk;
        if d.is_null() { return DEFAULT_LOGICAL_BLOCK_SIZE; }
        // SAFETY: adapter is registered only while gendisk allocation is live.
        let q = unsafe { (*d).queue };
        if q.is_null() { return DEFAULT_LOGICAL_BLOCK_SIZE; }
        // SAFETY: q belongs to the live gendisk.
        let bs = unsafe { (*q).logical_block_size };
        if bs == 0 { DEFAULT_LOGICAL_BLOCK_SIZE } else { bs }
    }
    fn capacity_blocks(&self) -> u64 {
        let d = self.disk as *const LinuxGendisk;
        if d.is_null() { return 0; }
        // SAFETY: adapter is registered only while gendisk allocation is live.
        let sectors = unsafe { (*d).capacity };
        sectors_to_blocks(sectors, self.block_size())
    }
    fn submit_sync(&self, req: &mut BlockRequest) -> Result<(), BlockError> {
        let d = self.disk as *mut LinuxGendisk;
        if d.is_null() { return Err(BlockError::Enxio); }
        // SAFETY: d belongs to a registered gendisk.
        let q = unsafe { (*d).queue };
        if q.is_null() { return Err(BlockError::Enxio); }
        // SAFETY: q belongs to a registered gendisk.
        let make = unsafe { (*q).make_request_fn };
        let make = match make { Some(f) => f, None => return Err(BlockError::Eopnotsupp) };
        let sectors = blocks_to_sectors(req.start_block, self.block_size());
        let op = match req.op {
            BlockOp::Read => REQ_OP_READ,
            BlockOp::Write => REQ_OP_WRITE,
            // The in-kernel Linux KPI bridge does not yet model bio opflags
            // (notably REQ_NOUNMAP), so it cannot truthfully forward this
            // operation. Its queue limits remain zero and the generic layer
            // uses ordinary writes instead.
            BlockOp::WriteZeroes { .. } => return Err(BlockError::Eopnotsupp),
            BlockOp::Flush => REQ_OP_FLUSH,
            BlockOp::Discard => REQ_OP_DISCARD,
        };
        let bio = bio_from_request(d, req, sectors, op);
        if bio.is_null() { return Err(BlockError::Enomem); }
        // SAFETY: bio is owned for the synchronous make_request callback.
        let r = unsafe { make(q, bio) };
        // SAFETY: bio remains owned by this adapter for submit_sync.
        let ok = unsafe { bio_status_ok(bio) };
        if req.op == BlockOp::Read {
            // SAFETY: bio data buffer has req.buffer.len() bytes.
            unsafe { copy_bio_to_request(bio, req); }
        }
        // SAFETY: reclaim the temporary bio after callback returns.
        unsafe { bio_put(bio); }
        if r == LINUX_OK && ok { Ok(()) } else { Err(BlockError::Eio) }
    }
    fn flush(&self) -> Result<(), BlockError> {
        let mut req = BlockRequest::new_flush();
        self.submit_sync(&mut req)
    }
}

/// Register Linux block KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("blk_alloc_queue",       blk_alloc_queue       as *const () as usize, false);
    export("blk_cleanup_queue",     blk_cleanup_queue     as *const () as usize, false);
    export("blk_queue_make_request", blk_queue_make_request as *const () as usize, false);
    export("blk_queue_logical_block_size", blk_queue_logical_block_size as *const () as usize, false);
    export("alloc_disk",            alloc_disk            as *const () as usize, false);
    export("alloc_disk_node",       alloc_disk_node       as *const () as usize, false);
    export("put_disk",              put_disk              as *const () as usize, false);
    export("add_disk",              add_disk              as *const () as usize, false);
    export("del_gendisk",           del_gendisk           as *const () as usize, false);
    export("set_capacity",          set_capacity          as *const () as usize, false);
    export("get_capacity",          get_capacity          as *const () as usize, false);
    export("submit_bio",            submit_bio            as *const () as usize, false);
    export("bio_alloc",             bio_alloc             as *const () as usize, false);
    export("bio_put",               bio_put               as *const () as usize, false);
    export("bio_set_dev",           bio_set_dev           as *const () as usize, false);
    export("bio_add_page",          bio_add_page          as *const () as usize, false);
    export("blk_mq_alloc_tag_set",  blk_mq_alloc_tag_set  as *const () as usize, false);
    export("blk_mq_free_tag_set",   blk_mq_free_tag_set   as *const () as usize, false);
    export("blk_mq_init_queue",     blk_mq_init_queue     as *const () as usize, false);
}

pub(super) extern "C" fn blk_alloc_queue(_gfp_mask: u32) -> *mut LinuxRequestQueue {
    Box::into_raw(Box::new(LinuxRequestQueue {
        make_request_fn: None,
        request_fn: None,
        queuedata: null_mut(),
        logical_block_size: DEFAULT_LOGICAL_BLOCK_SIZE,
        mq_ops: core::ptr::null(),
        tag_set: null_mut(),
        disk: null_mut(),
        rq_timeout: 0,
        nr_hw_queues: 1,
        freeze_depth: 0,
        quiesce_depth: 0,
        limits: default_limits(),
    }))
}

pub(super) unsafe extern "C" fn blk_cleanup_queue(q: *mut LinuxRequestQueue) {
    if q.is_null() { return; }
    // SAFETY: q was allocated by blk_alloc_queue or blk_mq_init_queue.
    unsafe { drop(Box::from_raw(q)); }
}

unsafe extern "C" fn blk_queue_make_request(q: *mut LinuxRequestQueue, f: Option<MakeRequestFn>) {
    if q.is_null() { return; }
    // SAFETY: q is a live request_queue.
    unsafe { (*q).make_request_fn = f; }
}

unsafe extern "C" fn blk_queue_logical_block_size(q: *mut LinuxRequestQueue, size: u32) {
    if q.is_null() || size == 0 { return; }
    // SAFETY: q is a live request_queue.
    unsafe { (*q).logical_block_size = size; }
}

pub(super) extern "C" fn alloc_disk(minors: i32) -> *mut LinuxGendisk {
    alloc_disk_node(minors, DEFAULT_NODE_ID)
}

pub(super) extern "C" fn alloc_disk_node(minors: i32, _node_id: i32) -> *mut LinuxGendisk {
    let dev = {
        // SAFETY: LinuxDevice is a C POD mirror; zero initialization matches kzalloc.
        unsafe { core::mem::zeroed() }
    };
    Box::into_raw(Box::new(LinuxGendisk {
        major: 0,
        first_minor: 0,
        minors: if minors <= 0 { DEFAULT_MINORS } else { minors },
        disk_name: [0; DISK_NAME_LEN],
        fops: core::ptr::null(),
        queue: null_mut(),
        private_data: null_mut(),
        capacity: 0,
        flags: 0,
        dev,
        registered: 0,
    }))
}

pub(super) unsafe extern "C" fn put_disk(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    // SAFETY: disk was allocated by alloc_disk*.
    unsafe { drop(Box::from_raw(disk)); }
}

pub(super) unsafe extern "C" fn add_disk(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    let name = disk_name(disk);
    if name.is_empty() { return; }
    let adapter = Arc::new(LinuxBlockAdapter { disk: disk as usize }) as Arc<dyn BlockDevice>;
    let idx = block::registry::register_with_driver(
        block::registry::GENERIC_BLOCK_DRIVER, &name, None, adapter);
    // SAFETY: disk is a live gendisk.
    unsafe {
        (*disk).registered = if idx == 0 { 0 } else { 1 };
        if !(*disk).queue.is_null() { (*(*disk).queue).disk = disk; }
    }
}

unsafe extern "C" fn del_gendisk(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    let name = disk_name(disk);
    if !name.is_empty() { let _ = block::registry::unregister(&name); }
    // SAFETY: disk is a live gendisk.
    unsafe { (*disk).registered = 0; }
}

unsafe extern "C" fn set_capacity(disk: *mut LinuxGendisk, sectors: u64) {
    if disk.is_null() { return; }
    // SAFETY: disk is a live gendisk.
    unsafe { (*disk).capacity = sectors; }
}

unsafe extern "C" fn get_capacity(disk: *const LinuxGendisk) -> u64 {
    if disk.is_null() { return 0; }
    // SAFETY: disk is a live gendisk.
    unsafe { (*disk).capacity }
}

pub(super) unsafe extern "C" fn submit_bio(bio: *mut LinuxBio) -> i32 {
    if bio.is_null() { return -LINUX_EINVAL; }
    // SAFETY: bio points to a LinuxBio.
    let disk = unsafe { (*bio).bi_disk };
    if disk.is_null() { return -LINUX_EINVAL; }
    // SAFETY: disk points to a LinuxGendisk.
    let q = unsafe { (*disk).queue };
    if q.is_null() { return -LINUX_EINVAL; }
    // SAFETY: q points to a LinuxRequestQueue.
    let make = unsafe { (*q).make_request_fn };
    let Some(f) = make else { return -LINUX_EIO; };
    // SAFETY: queue callback owns the bio for the duration of submit_bio.
    unsafe { f(q, bio) }
}

pub(super) extern "C" fn bio_alloc(_gfp_mask: u32, nr_iovecs: u32) -> *mut LinuxBio {
    let len = (nr_iovecs.max(DEFAULT_BIO_VEC_COUNT) as usize) * BYTES_PER_KIB as usize;
    bio_alloc_with_len(len)
}

unsafe extern "C" fn bio_put(bio: *mut LinuxBio) {
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

pub(super) unsafe extern "C" fn bio_add_page(bio: *mut LinuxBio, page: *mut c_void, len: u32, off: u32) -> i32 {
    if bio.is_null() { return 0; }
    // SAFETY: bio is live; capacity is owned by BioOwner.
    unsafe {
        let owner = (*bio).owner as *mut BioOwner;
        if owner.is_null() { return 0; }
        let n = (len as usize).min((*owner).buf.len());
        let page_data = crate::linux_alloc::page_address(page as *mut crate::linux_alloc::LinuxPage);
        (*bio).bi_data = if page_data.is_null() { (*owner).buf.as_mut_ptr() } else { page_data.add(off as usize) };
        (*bio).bi_size = n as u32;
        n as i32
    }
}

extern "C" fn blk_mq_alloc_tag_set(_set: *mut LinuxBlkMqTagSet) -> i32 { LINUX_OK }

unsafe extern "C" fn blk_mq_free_tag_set(_set: *mut LinuxBlkMqTagSet) {}

unsafe extern "C" fn blk_mq_init_queue(set: *mut LinuxBlkMqTagSet) -> *mut LinuxRequestQueue {
    let q = blk_alloc_queue(GFP_KERNEL);
    if q.is_null() { return null_mut(); }
    // SAFETY: q is newly allocated and set may be NULL.
    unsafe {
        if !set.is_null() { (*q).queuedata = (*set).driver_data; }
    }
    q
}

fn bio_alloc_with_len(len: usize) -> *mut LinuxBio {
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

fn bio_from_request(disk: *mut LinuxGendisk, req: &BlockRequest, sector: u64, op: u32) -> *mut LinuxBio {
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

unsafe fn bio_status_ok(bio: *const LinuxBio) -> bool {
    // SAFETY: caller guarantees bio points to a live LinuxBio.
    unsafe { !bio.is_null() && (*bio).bi_status == BLK_STS_OK }
}

unsafe fn copy_bio_to_request(bio: *const LinuxBio, req: &mut BlockRequest) {
    if bio.is_null() || req.buffer.is_empty() { return; }
    // SAFETY: bio is live and data buffer has at least bi_size bytes.
    let n = unsafe { ((*bio).bi_size as usize).min(req.buffer.len()) };
    // SAFETY: source and destination are valid non-overlapping buffers.
    unsafe { copy_nonoverlapping((*bio).bi_data, req.buffer.as_mut_ptr(), n); }
}

fn sectors_to_blocks(sectors: u64, block_size: u32) -> u64 {
    let factor = (block_size / LINUX_SECTOR_SIZE).max(1) as u64;
    sectors / factor
}

pub(super) fn default_limits() -> LinuxQueueLimits {
    LinuxQueueLimits {
        logical_block_size: DEFAULT_LOGICAL_BLOCK_SIZE,
        physical_block_size: DEFAULT_LOGICAL_BLOCK_SIZE,
        io_min: DEFAULT_LOGICAL_BLOCK_SIZE,
        io_opt: 0,
        max_hw_sectors: 1024,
        max_segments: 128,
        discard_granularity: 0,
        discard_alignment: 0,
    }
}

fn blocks_to_sectors(blocks: u64, block_size: u32) -> u64 {
    let factor = (block_size / LINUX_SECTOR_SIZE).max(1) as u64;
    blocks.saturating_mul(factor)
}

fn disk_name(disk: *const LinuxGendisk) -> String {
    if disk.is_null() { return String::new(); }
    let mut out = String::new();
    // SAFETY: disk points to a fixed-size NUL-terminated C name field.
    unsafe {
        for c in &(*disk).disk_name {
            if *c == c_char::default() { break; }
            out.push((*c as u8) as char);
        }
    }
    out
}

#[cfg(test)]
fn write_disk_name(disk: *mut LinuxGendisk, name: &[u8]) {
    if disk.is_null() { return; }
    // SAFETY: disk points to a fixed-size C name field owned by the test.
    unsafe {
        (*disk).disk_name = [0; DISK_NAME_LEN];
        let n = name.len().min(DISK_NAME_LEN - 1);
        for (dst, src) in (*disk).disk_name.iter_mut().take(n).zip(name.iter().copied()) {
            *dst = src as c_char;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync::{Modules as ModulesLockClass, Spinlock};

    const TEST_BLOCK_SIZE: u32 = LINUX_SECTOR_SIZE;
    const TEST_BLOCKS: u64 = 8;
    const TEST_DISK_NAME: &[u8] = b"kblk0";
    const TEST_WRITE: &[u8] = b"oxide-block";

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
        crate::symtab::_reset();
        export_symbols();
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
            set_capacity(disk, TEST_BLOCKS);
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

        // SAFETY: disk and queue are live allocations owned by this test.
        unsafe {
            del_gendisk(disk);
            put_disk(disk);
            blk_cleanup_queue(q);
        }
    }
}
