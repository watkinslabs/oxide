use crate::vtd_cache::publish;

const PAGE_BYTES: u64 = 4096;
const QI_DONE: u32 = 2;
const QI_DESC_BYTES: u64 = core::mem::size_of::<VtdQiDesc>() as u64;
const QI_DESC_COUNT: u16 = (PAGE_BYTES / QI_DESC_BYTES) as u16;
const QI_STATUS_BYTES: u64 = core::mem::size_of::<u32>() as u64;

fn completion_slot(tail: u16, descriptor_count: usize) -> Option<u16> {
    if descriptor_count == 0 || descriptor_count.checked_add(1)? >= QI_DESC_COUNT as usize { return None; }
    Some((((tail as usize) + descriptor_count) % QI_DESC_COUNT as usize) as u16)
}

/// Hardware-format 16-byte VT-d queued-invalidation descriptor.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VtdQiDesc { words: [u64; 2] }
impl VtdQiDesc {
    /// Build a global context-cache invalidation descriptor. # C: O(1)
    pub const fn global_context() -> Self { Self { words: [1 | (1 << 4), 0] } }
    /// Build a global IOTLB invalidation descriptor. # C: O(1)
    pub const fn global_iotlb(read_drain: bool, write_drain: bool) -> Self {
        let drains = (read_drain as u64) << 7 | (write_drain as u64) << 6;
        Self { words: [2 | (1 << 4) | drains, 0] }
    }
    /// Build a completion-writing wait descriptor for a synchronized submission. # C: O(1)
    pub const fn wait(status_pa: u64) -> Option<Self> {
        if status_pa & 3 != 0 { return None; }
        Some(Self { words: [5 | (1 << 5) | ((QI_DONE as u64) << 32), status_pa] })
    }
    /// Build a global interrupt-entry-cache invalidation descriptor. # C: O(1)
    pub const fn global_interrupt_entry() -> Self { Self { words: [4, 0] } }
    /// Build a selective interrupt-entry-cache invalidation descriptor. # C: O(1)
    pub const fn interrupt_entry(index: u16, mask: u8) -> Self {
        Self { words: [4 | (1 << 4) | ((mask as u64 & 0x1f) << 27) | ((index as u64) << 32), 0] }
    }
    /// Return the little-endian hardware words. # C: O(1)
    #[cfg(test)] pub const fn words(self) -> [u64; 2] { self.words }
}

/// One permanent 256-entry queued-invalidation ring and its matching status
/// records. Each submission uses its wait descriptor's ring slot as a unique
/// completion record, so a later publisher cannot clear an in-flight result.
pub struct VtdQiQueue { pa: u64, status_pa: u64, hhdm_offset: u64, coherent: bool, tail: u16, completion: u16 }
impl VtdQiQueue {
    /// Allocate and clear the IQA.QS=0 ring and per-descriptor status page. # C: O(1)
    pub fn new(hhdm_offset: u64, coherent: bool) -> Option<Self> {
        if hhdm_offset == 0 { return None; }
        let pa = pmm::setup::alloc_contig(pmm::Order(0))?;
        let status_pa = match pmm::setup::alloc_contig(pmm::Order(0)) {
            Some(pa) => pa,
            None => {
                // SAFETY: the unpublished QI ring frame is exclusively owned by this constructor.
                unsafe { pmm::setup::free_one_frame(pa); }
                return None;
            }
        };
        // SAFETY: each allocated page is exclusively owned by this queue before publication.
        unsafe {
            core::ptr::write_bytes(hhdm_offset.wrapping_add(pa) as *mut u8, 0, PAGE_BYTES as usize);
            core::ptr::write_bytes(hhdm_offset.wrapping_add(status_pa) as *mut u8, 0, PAGE_BYTES as usize);
        }
        publish(hhdm_offset, pa, PAGE_BYTES, coherent);
        publish(hhdm_offset, status_pa, PAGE_BYTES, coherent);
        Some(Self { pa, status_pa, hhdm_offset, coherent, tail: 0, completion: 0 })
    }
    /// Physical IQA base. # C: O(1)
    pub const fn pa(&self) -> u64 { self.pa }
    fn status_pa(&self, slot: u16) -> Option<u64> {
        if slot >= QI_DESC_COUNT { return None; }
        self.status_pa.checked_add(u64::from(slot) * QI_STATUS_BYTES)
    }
    fn publish(&mut self, desc: VtdQiDesc) -> Option<u64> {
        let slot = self.tail;
        let va = self.hhdm_offset.checked_add(self.pa)?.checked_add(u64::from(slot) * QI_DESC_BYTES)? as *mut VtdQiDesc;
        // SAFETY: serialized queue ownership writes exactly one descriptor at a valid ring slot.
        unsafe { core::ptr::write_volatile(va, desc); }
        publish(self.hhdm_offset, self.pa + u64::from(slot) * QI_DESC_BYTES, QI_DESC_BYTES, self.coherent);
        self.tail = (self.tail + 1) % QI_DESC_COUNT;
        Some(u64::from(self.tail) * QI_DESC_BYTES)
    }
    /// Publish invalidations plus a slot-owned wait completion record. # C: O(descriptors)
    pub fn submit_sync(&mut self, descs: &[VtdQiDesc]) -> Option<u64> {
        let completion = completion_slot(self.tail, descs.len())?;
        let status_pa = self.status_pa(completion)?;
        let status_va = self.hhdm_offset.checked_add(status_pa)? as *mut u32;
        // SAFETY: each serialized submission owns its wait slot until it has observed completion.
        unsafe { core::ptr::write_volatile(status_va, 0); }
        publish(self.hhdm_offset, status_pa, QI_STATUS_BYTES, self.coherent);
        for desc in descs { self.publish(*desc)?; }
        let tail = self.publish(VtdQiDesc::wait(status_pa)?)?;
        self.completion = completion;
        Some(tail)
    }
    pub(crate) fn completion_value(&self) -> Option<u32> {
        let Some(status_pa) = self.status_pa(self.completion) else { return None; };
        let Some(status_va) = self.hhdm_offset.checked_add(status_pa) else { return None; };
        pmm::dma::invalidate_from_device(status_va, QI_STATUS_BYTES as usize);
        // SAFETY: the current completion slot remains owned until the synchronous poll ends.
        Some(unsafe { core::ptr::read_volatile(status_va as *const u32) })
    }
    /// Return whether the current wait descriptor has observed terminal completion. # C: O(1)
    pub fn completed(&self) -> bool { self.completion_value() == Some(QI_DONE) }
}

#[cfg(test)] mod tests {
    use super::*;

    #[test] fn queued_invalidation_layout_uses_a_distinct_wait_slot_status() {
        assert_eq!(core::mem::size_of::<VtdQiDesc>(), 16);
        assert_eq!(QI_DESC_COUNT, 256);
        assert_eq!(VtdQiDesc::global_context().words(), [1 | (1 << 4), 0]);
        assert_eq!(VtdQiDesc::global_iotlb(true, true).words(), [0xd2, 0]);
        assert_eq!(VtdQiDesc::global_iotlb(false, false).words(), [0x12, 0]);
        assert_eq!(VtdQiDesc::wait(0x1234_5000).unwrap().words(), [0x0000_0002_0000_0025, 0x1234_5000]);
        assert_eq!(VtdQiDesc::wait(0x1234_5008).unwrap().words()[1], 0x1234_5008);
        assert_eq!(VtdQiDesc::wait(0x0010_0000_0000_0000).unwrap().words()[1], 0x0010_0000_0000_0000);
        assert!(VtdQiDesc::wait(0x1234_5002).is_none());
        assert_eq!(VtdQiDesc::global_interrupt_entry().words(), [4, 0]);
        assert_eq!(u64::from(QI_DESC_COUNT) * QI_STATUS_BYTES, 1024);
    }
    #[test] fn each_submission_wait_owns_its_tail_relative_status_slot() {
        assert_eq!(completion_slot(0, 2), Some(2));
        assert_eq!(completion_slot(3, 1), Some(4));
        assert_eq!(completion_slot(255, 1), Some(0));
        assert_eq!(completion_slot(0, 0), None);
        assert_eq!(completion_slot(0, 255), None);
    }
}
