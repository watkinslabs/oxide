use core::sync::atomic::Ordering;

use crate::{VirtQueueResource, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};

const DESC_WORDS: usize = 2;
const AVAIL_RING_OFF: usize = 2;
const USED_RING_OFF: usize = 1;
const DESC_FLAGS_SHIFT: u64 = 32;
const DESC_NEXT_SHIFT: u64 = 48;
const DESC_NEXT_MASK: u64 = 0xffff << DESC_NEXT_SHIFT;

/// One device-visible scatter-gather segment. `dma` is an IOVA supplied by the
/// DMA owner, never a CPU physical address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SplitQueueSeg {
    pub dma: u64,
    pub len: u32,
    pub device_writes: bool,
}

/// Completion returned after the shared split queue retires its descriptor
/// chain back to the queue-owned free list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SplitUsed {
    pub head: u16,
    pub len: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitQueueError {
    InvalidQueue,
    EmptyChain,
    NoDescriptors,
    BadUsedId,
    BadDescriptorChain,
}

/// Shared split-virtqueue owner. It owns descriptor allocation, publication,
/// used-ring retirement, and free-list recovery; child drivers supply only
/// DMA segments and retain protocol-specific request ownership.
pub struct VirtioSplitQueue {
    resource: VirtQueueResource,
    hhdm: u64,
    free_head: u16,
    num_free: u16,
    avail_idx: u16,
    used_seen: u16,
}

impl VirtioSplitQueue {
    /// Adopt one transport-programmed split ring and initialize its descriptor
    /// free list before the child publishes any request. # C: O(queue_size)
    pub fn new(resource: VirtQueueResource, hhdm: u64) -> Result<Self, SplitQueueError> {
        if !resource.is_runtime_valid() || !resource.size.is_power_of_two() {
            return Err(SplitQueueError::InvalidQueue);
        }
        let mut queue = Self {
            resource,
            hhdm,
            free_head: 0,
            num_free: resource.size,
            avail_idx: 0,
            used_seen: 0,
        };
        for index in 0..resource.size {
            let next = if index + 1 == resource.size { 0 } else { index + 1 };
            queue.write_desc(index, 0, 0, 0, next);
        }
        let used_seen = queue.read_used_idx();
        queue.avail_idx = used_seen;
        queue.used_seen = used_seen;
        Ok(queue)
    }

    /// Publish one nonempty scatter-gather chain without notifying the device.
    /// Call [`Self::kick`] after publishing a batch, matching Linux's
    /// `virtqueue_add_*` followed by `virtqueue_kick` contract.
    /// # C: O(segments)
    pub fn submit_no_kick(&mut self, segs: &[SplitQueueSeg]) -> Result<u16, SplitQueueError> {
        if segs.is_empty() { return Err(SplitQueueError::EmptyChain); }
        if segs.len() > self.num_free as usize { return Err(SplitQueueError::NoDescriptors); }
        let head = self.free_head;
        let mut current = head;
        for (index, seg) in segs.iter().enumerate() {
            if seg.dma == 0 || seg.len == 0 { return Err(SplitQueueError::EmptyChain); }
            let next_free = self.read_desc_next(current);
            let has_next = index + 1 != segs.len();
            let flags = (if has_next { VRING_DESC_F_NEXT } else { 0 })
                | (if seg.device_writes { VRING_DESC_F_WRITE } else { 0 });
            self.write_desc(current, seg.dma, seg.len, flags, if has_next { next_free } else { 0 });
            if has_next { current = next_free; } else { self.free_head = next_free; }
        }
        self.num_free -= segs.len() as u16;
        let slot = (self.avail_idx % self.resource.size) as usize;
        // SAFETY: transport allocated the avail frame; slot is bounded by the
        // negotiated ring size and descriptors were written before publication.
        unsafe { core::ptr::write_volatile(self.avail_ptr().add(AVAIL_RING_OFF + slot), head); }
        core::sync::atomic::fence(Ordering::Release);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        // SAFETY: avail.idx follows the release fence that exposes its ring entry.
        unsafe { core::ptr::write_volatile(self.avail_ptr().add(1), self.avail_idx); }
        core::sync::atomic::fence(Ordering::Release);
        Ok(head)
    }

    /// Publish one nonempty scatter-gather chain and notify the device.
    /// # C: O(segments)
    pub fn submit(&mut self, segs: &[SplitQueueSeg]) -> Result<u16, SplitQueueError> {
        let head = self.submit_no_kick(segs)?;
        self.kick();
        Ok(head)
    }

    /// Notify the device after one or more `submit_no_kick` calls.
    /// # C: O(1)
    pub fn kick(&self) {
        // SAFETY: notify_va is the transport-mapped queue notification register.
        unsafe { core::ptr::write_volatile(self.resource.notify_va as *mut u16, self.resource.index); }
    }

    /// Retire one device completion and return the head/request length.
    /// # C: O(descriptors_in_chain)
    pub fn pop_used(&mut self) -> Result<Option<SplitUsed>, SplitQueueError> {
        let used_idx = self.read_used_idx();
        if used_idx == self.used_seen { return Ok(None); }
        if used_idx.wrapping_sub(self.used_seen) > self.resource.size {
            return Err(SplitQueueError::BadUsedId);
        }
        core::sync::atomic::fence(Ordering::Acquire);
        let slot = (self.used_seen % self.resource.size) as usize;
        // SAFETY: the acquire fence follows the device-owned used.idx load;
        // slot is bounded by queue size, and each used element has two u32 words.
        let (id, len) = unsafe {
            (core::ptr::read_volatile(self.used_ptr().add(USED_RING_OFF + slot * DESC_WORDS)),
             core::ptr::read_volatile(self.used_ptr().add(USED_RING_OFF + slot * DESC_WORDS + 1)))
        };
        if id >= self.resource.size as u32 { return Err(SplitQueueError::BadUsedId); }
        self.release_chain(id as u16)?;
        self.used_seen = self.used_seen.wrapping_add(1);
        Ok(Some(SplitUsed { head: id as u16, len }))
    }

    /// Return the queue resource for protocol-level queue identification.
    /// # C: O(1)
    pub const fn resource(&self) -> VirtQueueResource { self.resource }

    /// Return the next available-ring index owned by this queue.
    /// # C: O(1)
    pub const fn avail_idx(&self) -> u16 { self.avail_idx }

    /// Return the next used-ring index this queue will reclaim.
    /// # C: O(1)
    pub const fn used_seen(&self) -> u16 { self.used_seen }

    fn release_chain(&mut self, head: u16) -> Result<(), SplitQueueError> {
        let mut current = head;
        let mut count = 0u16;
        loop {
            if current >= self.resource.size || count >= self.resource.size {
                return Err(SplitQueueError::BadDescriptorChain);
            }
            count += 1;
            let word = self.read_desc_word(current);
            if (word >> DESC_FLAGS_SHIFT) as u16 & VRING_DESC_F_NEXT == 0 {
                let free_word = (word & !DESC_NEXT_MASK) | ((self.free_head as u64) << DESC_NEXT_SHIFT);
                // SAFETY: current names the terminal descriptor in a chain retired from used.
                unsafe { core::ptr::write_volatile(self.desc_ptr().add(current as usize * DESC_WORDS + 1), free_word); }
                self.free_head = head;
                self.num_free += count;
                return Ok(());
            }
            current = (word >> DESC_NEXT_SHIFT) as u16;
        }
    }

    fn read_used_idx(&self) -> u16 {
        // SAFETY: device frame is HHDM-mapped by the transport and used.idx is aligned.
        unsafe { core::ptr::read_volatile(self.used_u16_ptr().add(1)) }
    }

    fn read_desc_word(&self, index: u16) -> u64 {
        // SAFETY: index is validated by queue construction or chain traversal before use.
        unsafe { core::ptr::read_volatile(self.desc_ptr().add(index as usize * DESC_WORDS + 1)) }
    }

    fn read_desc_next(&self, index: u16) -> u16 { (self.read_desc_word(index) >> DESC_NEXT_SHIFT) as u16 }

    fn write_desc(&self, index: u16, dma: u64, len: u32, flags: u16, next: u16) {
        let word = len as u64 | ((flags as u64) << DESC_FLAGS_SHIFT) | ((next as u64) << DESC_NEXT_SHIFT);
        // SAFETY: index is within the queue's negotiated descriptor table; two aligned
        // stores replace exactly one descriptor before its avail publication.
        unsafe {
            core::ptr::write_volatile(self.desc_ptr().add(index as usize * DESC_WORDS), dma);
            core::ptr::write_volatile(self.desc_ptr().add(index as usize * DESC_WORDS + 1), word);
        }
    }

    fn desc_ptr(&self) -> *mut u64 { self.hhdm.wrapping_add(self.resource.desc_pa) as *mut u64 }
    fn avail_ptr(&self) -> *mut u16 { self.hhdm.wrapping_add(self.resource.driver_pa) as *mut u16 }
    fn used_ptr(&self) -> *const u32 { self.hhdm.wrapping_add(self.resource.device_pa) as *const u32 }
    fn used_u16_ptr(&self) -> *const u16 { self.hhdm.wrapping_add(self.resource.device_pa) as *const u16 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4096))]
    struct Page([u8; 4096]);

    fn resource(desc: &Page, avail: &Page, used: &Page, notify: &mut u16) -> VirtQueueResource {
        VirtQueueResource {
            index: 3, size: 8, desc_pa: desc.0.as_ptr() as u64, driver_pa: avail.0.as_ptr() as u64,
            device_pa: used.0.as_ptr() as u64, notify_va: notify as *mut u16 as u64, notify_off: 0,
        }
    }

    #[test]
    fn submit_uses_dma_and_recycles_completed_descriptor_chain() {
        let desc = Page([0; 4096]);
        let avail = Page([0; 4096]);
        let used = Page([0; 4096]);
        let mut notify = 0;
        let mut queue = VirtioSplitQueue::new(resource(&desc, &avail, &used, &mut notify), 0).unwrap();
        let head = queue.submit(&[
            SplitQueueSeg { dma: 0x9000_1000, len: 16, device_writes: false },
            SplitQueueSeg { dma: 0x9000_2000, len: 32, device_writes: true },
        ]).unwrap();
        assert_eq!(head, 0);
        let desc_words = desc.0.as_ptr() as *const u64;
        // SAFETY: test owns the aligned descriptor page and reads words written by submit.
        assert_eq!(unsafe { core::ptr::read_volatile(desc_words) }, 0x9000_1000);
        assert_eq!(unsafe { core::ptr::read_volatile(desc_words.add(2)) }, 0x9000_2000);
        assert_eq!(notify, 3);
        let used_words = used.0.as_ptr() as *mut u32;
        // SAFETY: test emulates one device completion in its private used frame.
        unsafe {
            core::ptr::write_volatile(used_words.add(USED_RING_OFF), head as u32);
            core::ptr::write_volatile(used_words.add(USED_RING_OFF + 1), 48);
            core::ptr::write_volatile((used.0.as_ptr() as *mut u16).add(1), 1);
        }
        assert_eq!(queue.pop_used().unwrap(), Some(SplitUsed { head, len: 48 }));
        assert_eq!(queue.submit(&[SplitQueueSeg { dma: 0x9000_3000, len: 8, device_writes: false }]).unwrap(), head);
    }

    #[test]
    fn batch_submission_defers_notification_until_kick() {
        let desc = Page([0; 4096]);
        let avail = Page([0; 4096]);
        let used = Page([0; 4096]);
        let mut notify = 0;
        let mut queue = VirtioSplitQueue::new(resource(&desc, &avail, &used, &mut notify), 0).unwrap();
        queue.submit_no_kick(&[SplitQueueSeg { dma: 0x9000_1000, len: 8, device_writes: true }]).unwrap();
        queue.submit_no_kick(&[SplitQueueSeg { dma: 0x9000_2000, len: 8, device_writes: true }]).unwrap();
        assert_eq!(notify, 0);
        // SAFETY: test owns the private avail frame and reads its published idx.
        assert_eq!(unsafe { core::ptr::read_volatile((avail.0.as_ptr() as *const u16).add(1)) }, 2);
        queue.kick();
        assert_eq!(notify, 3);
    }
}
