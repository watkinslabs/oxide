// Split virtqueue per Virtio 1.2 §2.6. Three contiguous on-driver-
// memory regions:
//   - Desc[N]   (16 bytes each): scatter-gather descriptors
//   - AvailRing: driver→device "I have N pending heads" ring
//   - UsedRing:  device→driver "I'm done with these heads" ring
//
// Caller (arch HAL) allocates page-aligned DMA-coherent memory
// and hands the layout pointers in. Pure layout/math here; no
// MMIO, no IRQ.

extern crate alloc;
use alloc::vec::Vec;

pub const VRING_DESC_F_NEXT:     u16 = 1;
pub const VRING_DESC_F_WRITE:    u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Desc {
    pub addr:  u64,
    pub len:   u32,
    pub flags: u16,
    pub next:  u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct AvailRing {
    pub flags:  u16,
    pub idx:    u16,
    pub ring:   Vec<u16>,    // length = queue size
    pub used_event: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct UsedElem {
    pub id:  u32,
    pub len: u32,
}

#[derive(Debug)]
pub struct UsedRing {
    pub flags:  u16,
    pub idx:    u16,
    pub ring:   Vec<UsedElem>,
    pub avail_event: u16,
}

#[derive(Debug)]
pub struct VirtQueue {
    pub size:    u16,
    pub desc:    Vec<Desc>,
    pub avail:   AvailRing,
    pub used:    UsedRing,
    /// Index of the next free descriptor in the chain (driver-side).
    pub free_head: u16,
    /// Number of descriptors currently free.
    pub num_free:  u16,
    /// Last seen used.idx — driver advances per-completion.
    pub last_used: u16,
}

impl VirtQueue {
    /// Create an empty queue with `size` descriptors. `size` must
    /// be a power of two, ≥1, ≤32768 per spec.
    /// # C: O(size)
    pub fn new(size: u16) -> Self {
        assert!(size > 0 && (size & (size - 1)) == 0, "size must be power of two");
        let mut desc = alloc::vec![Desc::default(); size as usize];
        // Link every descriptor into the free chain.
        for i in 0..size {
            desc[i as usize].next = if i + 1 < size { i + 1 } else { 0 };
        }
        Self {
            size,
            desc,
            avail: AvailRing {
                flags: 0, idx: 0,
                ring: alloc::vec![0u16; size as usize],
                used_event: 0,
            },
            used: UsedRing {
                flags: 0, idx: 0,
                ring: alloc::vec![UsedElem::default(); size as usize],
                avail_event: 0,
            },
            free_head: 0,
            num_free:  size,
            last_used: 0,
        }
    }

    /// Allocate a chain of `n` descriptors, link them via .next,
    /// fill caller-provided (addr, len, write-from-device) for
    /// each. Returns the chain head.
    /// `Err(Enobufs)` if fewer than `n` descriptors are free.
    /// # C: O(n)
    pub fn alloc_chain(&mut self, segs: &[(u64, u32, bool)]) -> Result<u16, ()> {
        if (segs.len() as u16) > self.num_free { return Err(()); }
        let head = self.free_head;
        let mut prev_idx: i32 = -1;
        let mut cur = head;
        for (i, &(addr, len, dev_write)) in segs.iter().enumerate() {
            let mut flags = 0u16;
            if dev_write { flags |= VRING_DESC_F_WRITE; }
            if i + 1 < segs.len() { flags |= VRING_DESC_F_NEXT; }
            let next_free = self.desc[cur as usize].next;
            self.desc[cur as usize] = Desc { addr, len, flags, next: 0 };
            if prev_idx >= 0 {
                self.desc[prev_idx as usize].next = cur;
            }
            prev_idx = cur as i32;
            if i + 1 < segs.len() { cur = next_free; }
        }
        self.free_head = self.desc[cur as usize].next;
        self.num_free  = self.num_free.saturating_sub(segs.len() as u16);
        Ok(head)
    }

    /// Publish the chain at `head` to the device by appending
    /// to `avail.ring[avail.idx % size]` and bumping idx.
    /// # C: O(1)
    pub fn publish(&mut self, head: u16) {
        let slot = (self.avail.idx as usize) % (self.size as usize);
        self.avail.ring[slot] = head;
        self.avail.idx = self.avail.idx.wrapping_add(1);
    }

    /// Drain one completion if available. Returns the head id +
    /// reported len. Frees the descriptor chain back to the pool.
    /// # C: O(chain length)
    pub fn pop_used(&mut self) -> Option<UsedElem> {
        if self.used.idx == self.last_used { return None; }
        let slot = (self.last_used as usize) % (self.size as usize);
        let elem = self.used.ring[slot];
        self.last_used = self.last_used.wrapping_add(1);
        // Walk the chain back into the free pool.
        let mut cur = elem.id as u16;
        let mut count = 0u16;
        loop {
            count += 1;
            let d = self.desc[cur as usize];
            if (d.flags & VRING_DESC_F_NEXT) == 0 {
                self.desc[cur as usize].next = self.free_head;
                self.free_head = elem.id as u16;
                break;
            }
            cur = d.next;
        }
        self.num_free = self.num_free.saturating_add(count);
        Some(elem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_publish_pop_round_trip() {
        let mut q = VirtQueue::new(8);
        assert_eq!(q.num_free, 8);
        let head = q.alloc_chain(&[(0x1000, 64, false), (0x2000, 32, true)]).unwrap();
        assert_eq!(head, 0);
        assert_eq!(q.num_free, 6);
        q.publish(head);
        assert_eq!(q.avail.idx, 1);
        // Simulate device completion.
        q.used.ring[0] = UsedElem { id: head as u32, len: 96 };
        q.used.idx = 1;
        let e = q.pop_used().unwrap();
        assert_eq!(e.id, 0);
        assert_eq!(e.len, 96);
        // Both descriptors freed.
        assert_eq!(q.num_free, 8);
    }

    #[test]
    fn alloc_chain_enobufs() {
        let mut q = VirtQueue::new(2);
        let _ = q.alloc_chain(&[(0x1000, 1, false), (0x2000, 1, false)]).unwrap();
        let r = q.alloc_chain(&[(0x3000, 1, false)]);
        assert!(r.is_err());
    }

    #[test]
    fn pop_used_returns_none_when_empty() {
        let mut q = VirtQueue::new(4);
        assert!(q.pop_used().is_none());
    }
}
