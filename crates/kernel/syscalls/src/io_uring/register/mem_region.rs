// `IORING_REGISTER_MEM_REGION`: give the ring one region of memory, either
// pages this kernel allocates and publishes at a fixed mmap offset or pages
// the caller already owns and this call pins.
//
// A ring accepts exactly one region for its whole life — a second attempt is
// `EBUSY`, checked before the arguments are even read, because re-pointing the
// region under a ring that is already using it would retarget every registered
// wait record at once.
//
// Nothing is installed until the region exists AND the caller has been told
// where to map it: a failed write-back frees the region and leaves the ring
// with none, so the caller cannot end up unable to reach memory the ring
// thinks it registered.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring::ctx::{state, IoUringInode};
use crate::io_uring::mem_region::MemRegion;
use crate::io_uring::pin::PinnedRange;
use crate::io_uring::region::Region;
use crate::io_uring_abi::acct::{Ledgers, RingAcct};
use crate::io_uring_abi::mem_region::*;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Build the region a descriptor asks for. The kernel-allocated arm learns the
/// caller the offset it may map at; the pinned arm reports none, because a
/// caller-provided region is never mappable from the ring fd. # C: O(N_pages)
fn build(rd: &mut RegionDesc, acct: RingAcct) -> Result<MemRegion, Errno> {
    if rd.user_provided() {
        return Ok(MemRegion::User(PinnedRange::pin(rd.user_addr, rd.size, acct, Ledgers::User)?));
    }
    // The contiguous-run allocator is sized in `u32` bytes and bounded well
    // below 4 GiB; a descriptor past that is memory this kernel cannot supply.
    let bytes = u32::try_from(rd.size).map_err(|_| Errno::Enomem)?;
    let r = Region::alloc(bytes, acct).ok_or(Errno::Enomem)?;
    rd.mmap_offset = IORING_MAP_OFF_PARAM_REGION;
    Ok(MemRegion::Kernel(r))
}

/// `IORING_REGISTER_MEM_REGION`. # C: O(N_pages)
pub fn register(inode: &Arc<IoUringInode>, arg: u64) -> i64 {
    // EBUSY first, and from the region itself rather than a flag beside it.
    if inode.param_region.lock().is_some() { return err(Errno::Ebusy); }

    let mut rb = [0u8; MEM_REGION_REG_BYTES as usize];
    if uaccess::copy_from_user(&mut rb, arg).is_err() { return err(Errno::Efault); }
    let reg = MemRegionReg::from_bytes(&rb);

    let mut db = [0u8; REGION_DESC_BYTES as usize];
    if uaccess::copy_from_user(&mut db, reg.region_uptr).is_err() { return err(Errno::Efault); }
    let mut rd = RegionDesc::from_bytes(&db);

    // The reference reads BOTH structs before judging either, so a caller that
    // passes a bad descriptor pointer learns that before it learns its flags
    // were wrong.
    let disabled = inode.test_state(state::DISABLED);
    if let Err(e) = admit_mem_region_reg(&reg, disabled) { return err(e); }
    if let Err(e) = admit_region_desc(&rd, hal::PAGE_SIZE_BYTES) { return err(e); }

    let region = match build(&mut rd, inode.acct) { Ok(r) => r, Err(e) => return err(e) };

    // Report where the region lives BEFORE the ring adopts it: a caller that
    // cannot be told cannot map it, so the region is dropped and the ring is
    // left exactly as it was.
    if uaccess::copy_to_user(reg.region_uptr, &rd.to_bytes()).is_err() {
        drop(region);
        return err(Errno::Efault);
    }

    let wait_size = if reg.flags & IORING_MEM_REGION_REG_WAIT_ARG != 0 { rd.size } else { 0 };
    {
        let mut g = inode.param_region.lock();
        // Re-checked under the lock the install uses: the EBUSY above and this
        // are the same rule, and only this one is race-free.
        if g.is_some() { drop(g); drop(region); return err(Errno::Ebusy); }
        // The wait size is published before the region so no waiter can see a
        // non-zero bound with nothing behind it.
        inode.cq_wait_size.store(wait_size, core::sync::atomic::Ordering::Release);
        *g = Some(region);
    }
    0
}
