extern crate alloc;
use super::bio::{bio_from_request, bio_put, bio_status_ok, copy_bio_to_request};
use super::disk::{blocks_to_sectors, sectors_to_blocks};
use crate::linux_block::types::*;
use block::{BlockDevice, BlockError, BlockOp, BlockRequest};

/// Bridge that carries block-registry traffic into a module's make_request_fn.
///
/// `disk` is a raw gendisk address held as an integer so the adapter stays Send + Sync. It is kept
/// valid by the publication contract, not by a reference count: `add_disk` publishes the adapter and
/// both `del_gendisk` and `put_disk` withdraw the publication before the gendisk allocation is freed,
/// so a registered adapter never observes a dangling gendisk.
pub(super) struct LinuxBlockAdapter {
    disk: usize,
}

impl LinuxBlockAdapter {
    /// Wrap a live gendisk for publication in the block registry.
    /// # C: O(1)
    pub(super) fn new(disk: *mut LinuxGendisk) -> Self { Self { disk: disk as usize } }
}

impl BlockDevice for LinuxBlockAdapter {
    fn block_size(&self) -> u32 {
        let d = self.disk as *const LinuxGendisk;
        if d.is_null() { return DEFAULT_LOGICAL_BLOCK_SIZE; }
        // SAFETY: the adapter is reachable only through the block registry, and both del_gendisk and
        // put_disk unregister it before freeing the gendisk, so `d` is a live alloc_disk allocation
        // whose `queue` field is either null (rejected below) or a blk_alloc_queue Box.
        let q = unsafe { (*d).queue };
        if q.is_null() { return DEFAULT_LOGICAL_BLOCK_SIZE; }
        // SAFETY: q is the non-null queue the live gendisk above points at; logical_block_size is a u32
        // field blk_alloc_queue initialises, and the zero case falls back to the default below.
        let bs = unsafe { (*q).logical_block_size };
        if bs == 0 { DEFAULT_LOGICAL_BLOCK_SIZE } else { bs }
    }
    fn capacity_blocks(&self) -> u64 {
        let d = self.disk as *const LinuxGendisk;
        if d.is_null() { return 0; }
        // SAFETY: same publication contract as block_size — a registered adapter's gendisk outlives it,
        // and `capacity` is a u64 field alloc_disk_node zero-initialises.
        let sectors = unsafe { (*d).capacity };
        sectors_to_blocks(sectors, self.block_size())
    }
    fn submit_sync(&self, req: &mut BlockRequest) -> Result<(), BlockError> {
        let d = self.disk as *mut LinuxGendisk;
        if d.is_null() { return Err(BlockError::Enxio); }
        // SAFETY: same publication contract as block_size; `queue` is the pointer the module attached
        // to this gendisk before add_disk, and the null case is rejected on the next line.
        let q = unsafe { (*d).queue };
        if q.is_null() { return Err(BlockError::Enxio); }
        // SAFETY: q is the non-null queue of the live gendisk; make_request_fn is an Option<fn> field
        // that blk_alloc_queue initialises to None and only blk_queue_make_request overwrites.
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
        // SAFETY: bio is the non-null BioOwner interior just built for this request and is owned by
        // this frame until bio_put below; make is the module's own make_request_fn, which Linux calls
        // synchronously with a bio it does not free.
        let r = unsafe { make(q, bio) };
        // SAFETY: the callback above returned, so the bio is back under this frame's sole ownership
        // and bi_status is the u8 field the callback wrote.
        let ok = unsafe { bio_status_ok(bio) };
        if req.op == BlockOp::Read {
            // SAFETY: bio is still the live owner-interior bio and its bi_data covers bi_size bytes by
            // construction in bio_alloc_with_len; copy_bio_to_request clamps to the request buffer.
            unsafe { copy_bio_to_request(bio, req); }
        }
        // SAFETY: bio is the interior pointer of the BioOwner Box bio_from_request allocated, nothing
        // else took ownership of it, and it is not read again after this reclaim.
        unsafe { bio_put(bio); }
        if r == LINUX_OK && ok { Ok(()) } else { Err(BlockError::Eio) }
    }
    fn flush(&self) -> Result<(), BlockError> {
        let mut req = BlockRequest::new_flush();
        self.submit_sync(&mut req)
    }
}
