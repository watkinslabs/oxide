// Decision-cache and SID-table statistics, and the cache-size control.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{fence, Ordering};

use hal::PAGE_SIZE_BYTES;
use sync::{SecurityPolicy as LockClass, Spinlock};
use vfs::{AddressSpaceOps, InodeRef, KResult, SharedFrame, VfsError};

use crate::format::response::{avc_hash_stats_response, cache_stats_response,
                              sidtab_hash_stats_response, status_page, STATUS_PAGE_BYTES};
use crate::format::scalar::{parse_u32, render_u32, request_text};
use crate::ops::PolicyOps;
use crate::server::with_ops;

use super::plumb::{body_reader, dyn_file, text_file, WriteFn};

/// Permission a change to a cache parameter is checked against.
pub const PERM_SETSECPARAM: &str = "setsecparam";

/// Directory holding the decision-cache nodes.
pub const AVC_DIR: &str = "avc";
/// Directory holding the security-server nodes.
pub const SS_DIR: &str = "ss";
/// Node reporting the cache's bucket shape.
pub const HASH_STATS_NODE: &str = "hash_stats";
/// Node reporting the cache's activity counters.
pub const CACHE_STATS_NODE: &str = "cache_stats";
/// Node holding the cache's reclaim threshold.
pub const CACHE_THRESHOLD_NODE: &str = "cache_threshold";
/// Node reporting the SID table's bucket shape.
pub const SIDTAB_HASH_STATS_NODE: &str = "sidtab_hash_stats";
/// Node carrying the status page.
pub const STATUS_NODE: &str = "status";

const STATUS_PAGE_SIZE: u64 = PAGE_SIZE_BYTES;
static STATUS_MAPPING: Spinlock<Option<Weak<StatusMapping>>, LockClass> = Spinlock::new(None);

/// Mode of a statistics node.
const STATS_MODE: u16 = 0o444;
/// Mode of the threshold control.
const THRESHOLD_MODE: u16 = 0o644;

/// Render the decision cache's bucket shape. # C: O(slots)
pub fn read_avc_hash_stats(ops: &dyn PolicyOps) -> String {
    avc_hash_stats_response(&ops.avc_hash_stats())
}

/// Render the decision cache's activity counters. # C: O(1)
pub fn read_cache_stats(ops: &dyn PolicyOps) -> String {
    cache_stats_response(&ops.avc_cache_stats())
}

/// Render the SID table's bucket shape. # C: O(buckets)
pub fn read_sidtab_hash_stats(ops: &dyn PolicyOps) -> String {
    sidtab_hash_stats_response(&ops.sidtab_hash_stats())
}

/// Render the status page. # C: O(1)
///
/// A caller polls this instead of re-reading `enforce` and the load counter,
/// so the two must come from ONE read of the state: sampling them separately
/// can report an enforcing mode from before a load with a count from after.
///
/// The SEQUENCE word is the page's seqlock, not the policy sequence number.
/// Userspace spins — yielding the CPU — for as long as it reads odd, so the
/// value published here must be even whenever the page is readable.
///
/// The POLICYLOAD word carries the policy sequence number, which is what the
/// reference writes there (`status->policyload = seqno`) and not a count of
/// loads: a boolean commit advances the sequence too, and a reader that
/// compares this word against its cached copy is how it learns to flush after
/// one. A load counter would sit still through every boolean change.
pub fn read_status(ops: &dyn PolicyOps) -> [u8; STATUS_PAGE_BYTES] {
    let facts = ops.facts();
    status_page(facts.status_seq, ops.enforcing(), facts.seqno, facts.deny_unknown)
}

/// The single page Linux maps for libselinux status polling. The inode owns
/// one PMM object reference; each shared mapping receives a separate PTE
/// reference through the PMM's mapping-reference boundary.
struct StatusMapping {
    frame: Spinlock<Option<u64>, LockClass>,
}

impl StatusMapping {
    fn new() -> Arc<Self> { Arc::new(Self { frame: Spinlock::new(None) }) }

    fn ensure_frame(&self) -> Option<u64> {
        if let Some(pa) = *self.frame.lock() { return Some(pa); }
        let pa = pmm::setup::alloc_object_frame()?;
        if !pmm::setup::zero_frame(pa) {
            pmm::setup::release_object_frame(pa);
            return None;
        }
        let page = with_ops(|o| read_status(o));
        if !pmm::setup::copy_frame_from(pa, 0, &page) {
            pmm::setup::release_object_frame(pa);
            return None;
        }
        let mut slot = self.frame.lock();
        if let Some(existing) = *slot {
            pmm::setup::release_object_frame(pa);
            return Some(existing);
        }
        *slot = Some(pa);
        Some(pa)
    }

    fn refresh(&self) {
        let Some(pa) = *self.frame.lock() else { return };
        let page = with_ops(|o| read_status(o));
        let seq_at = crate::format::response::STATUS_FIELD_BYTES;
        let seq = u32::from_le_bytes(page[seq_at..seq_at + 4].try_into().unwrap());
        let odd = (seq | 1).to_le_bytes();
        let even = (seq & !1).to_le_bytes();
        // Match Linux's status-page seqlock: make the page unreadable before
        // changing payload, then publish an even sequence only after all
        // fields have been replaced.
        if !pmm::setup::copy_frame_from(pa, seq_at, &odd) { return; }
        fence(Ordering::Release);
        if !pmm::setup::copy_frame_from(pa, 0, &page[..seq_at]) { return; }
        if !pmm::setup::copy_frame_from(pa, seq_at + 4, &page[seq_at + 4..]) { return; }
        fence(Ordering::Release);
        let _ = pmm::setup::copy_frame_from(pa, seq_at, &even);
    }
}

impl Drop for StatusMapping {
    fn drop(&mut self) {
        if let Some(pa) = self.frame.lock().take() {
            pmm::setup::release_object_frame(pa);
        }
    }
}

impl AddressSpaceOps for StatusMapping {
    fn shared_frame(&self, off: u64) -> KResult<Option<SharedFrame>> {
        if off != 0 { return Ok(None); }
        let Some(pa) = self.ensure_frame() else { return Ok(None) };
        if !pmm::setup::acquire_mapping_ref(pa) { return Err(VfsError::Eio); }
        Ok(Some(SharedFrame { pa, map_ref_held: true }))
    }

    fn read_at(&self, off: u64, dst: &mut [u8]) -> KResult<usize> {
        let page = with_ops(|o| read_status(o));
        let off = usize::try_from(off).map_err(|_| VfsError::Einval)?;
        if off >= page.len() { return Ok(0); }
        let n = dst.len().min(page.len() - off);
        dst[..n].copy_from_slice(&page[off..off + n]);
        Ok(n)
    }

    fn size(&self) -> u64 { STATUS_PAGE_SIZE }
}

/// Refresh the mapped status page after a live security-server update.
pub(crate) fn refresh_status_page() {
    let mapping = STATUS_MAPPING.lock().as_ref().and_then(Weak::upgrade);
    if let Some(mapping) = mapping { mapping.refresh(); }
}

/// Build the `status` node. # C: O(1)
pub fn make_status() -> InodeRef {
    let mapping = StatusMapping::new();
    *STATUS_MAPPING.lock() = Some(Arc::downgrade(&mapping));
    super::plumb::mapped_ro_file(
        STATS_MODE,
        STATUS_PAGE_SIZE,
        mapping,
        super::plumb::body_reader(|| Ok(with_ops(|o| read_status(o)).to_vec())),
    )
}

/// Render the cache's reclaim threshold. # C: O(1)
pub fn read_cache_threshold(ops: &dyn PolicyOps) -> String { render_u32(ops.cache_threshold()) }

/// Apply a written reclaim threshold. # C: O(1)
pub fn write_cache_threshold(ops: &mut dyn PolicyOps, body: &[u8]) -> KResult<usize> {
    let value = parse_u32(request_text(body)?)?;
    ops.check(PERM_SETSECPARAM)?;
    ops.set_cache_threshold(value);
    Ok(body.len())
}

/// Build the `avc/hash_stats` node. # C: O(1)
pub fn make_avc_hash_stats() -> InodeRef {
    text_file(STATS_MODE, || with_ops(|o| read_avc_hash_stats(o)))
}

/// Build the `avc/cache_stats` node. # C: O(1)
pub fn make_cache_stats() -> InodeRef {
    text_file(STATS_MODE, || with_ops(|o| read_cache_stats(o)))
}

/// Build the `ss/sidtab_hash_stats` node. # C: O(1)
pub fn make_sidtab_hash_stats() -> InodeRef {
    text_file(STATS_MODE, || with_ops(|o| read_sidtab_hash_stats(o)))
}

/// Build the `avc/cache_threshold` node. # C: O(1)
pub fn make_cache_threshold() -> InodeRef {
    let read = body_reader(|| Ok(with_ops(|o| read_cache_threshold(o)).into_bytes()));
    let write: WriteFn = Box::new(|_off, buf| with_ops(|o| write_cache_threshold(o, buf)));
    dyn_file(THRESHOLD_MODE, Some(read), Some(write))
}
