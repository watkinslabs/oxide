use super::*;

// Memory-backed split-virtqueue TX ring tests. A leaked arena stands in for
// physical memory; `hhdm` is its base so `hhdm + pa` lands inside it. These
// exercise the descriptor/avail indexing, lazy completion reaping, and the
// ring-full back-pressure path of `tx_frame_for` without a real device.

const RING: usize = 4;                 // TX queue size for the test
const DESC_PA:   u64 = 0x1000;
const AVAIL_PA:  u64 = 0x2000;
const USED_PA:   u64 = 0x3000;
const NOTIFY_PA: u64 = 0x4000;         // notify_va is absolute (base + this)
const BUF0_PA:   u64 = 0x5000;         // 4 TX buffers at 0x5000..0x8000
const ARENA_LEN: usize = 0x9000;

struct Arena { base: u64 }

impl Arena {
    fn new() -> Self {
        let v = alloc::vec![0u8; ARENA_LEN].into_boxed_slice();
        // Leak so the base VA stays valid for the whole test; the arena is
        // reclaimed at process exit. Deliberate — a test-only fixture.
        let base = alloc::boxed::Box::leak(v).as_mut_ptr() as u64;
        Arena { base }
    }
    fn r16(&self, off: u64) -> u16 {
        unsafe { core::ptr::read_volatile((self.base + off) as *const u16) }
    }
    fn w16(&self, off: u64, v: u16) {
        unsafe { core::ptr::write_volatile((self.base + off) as *mut u16, v) }
    }
    fn desc_addr(&self, id: usize) -> u64 {
        unsafe { core::ptr::read_volatile((self.base + DESC_PA + (id as u64) * 16) as *const u64) }
    }
    fn desc_len(&self, id: usize) -> u32 {
        unsafe { core::ptr::read_volatile((self.base + DESC_PA + (id as u64) * 16 + 8) as *const u32) }
    }
    // avail.idx at AVAIL_PA+2; ring[k] at AVAIL_PA+4+2k.
    fn avail_idx(&self) -> u16 { self.r16(AVAIL_PA + 2) }
    fn avail_ring(&self, k: usize) -> u16 { self.r16(AVAIL_PA + 4 + (k as u64) * 2) }
    fn notify(&self) -> u16 { self.r16(NOTIFY_PA) }
    // Device side: publish a used.idx to simulate completions.
    fn set_used_idx(&self, v: u16) { self.w16(USED_PA + 2, v) }
}

fn ring_state(arena: &Arena) -> ModernNetState {
    ModernNetState {
        device_key: key(70),
        cfg_va: arena.base,
        hhdm: arena.base,
        rxq: virtio::VirtQueueResource {
            index: 0, size: RING as u16,
            desc_pa: 0xa000, driver_pa: 0xb000, device_pa: 0xc000,
            notify_va: arena.base + 0xd000, notify_off: 0,
        },
        txq: virtio::VirtQueueResource {
            index: 1, size: RING as u16,
            desc_pa: DESC_PA, driver_pa: AVAIL_PA, device_pa: USED_PA,
            notify_va: arena.base + NOTIFY_PA, notify_off: 0,
        },
        rx_bufs: alloc::vec::Vec::new(),
        mac: [0x02, 0, 0, 0, 0, 70],
        tx_bufs: alloc::vec![BUF0_PA, BUF0_PA + 0x1000, BUF0_PA + 0x2000, BUF0_PA + 0x3000],
        tx_last_used: 0, tx_next_avail: 0,
        rx_last_used: 0, rx_next_avail: 0,
    }
}

#[test]
fn tx_ring_posts_across_descriptors_and_cycles() {
    let _guard = TEST_STATE_LOCK.lock();
    clear_test_state();
    let arena = Arena::new();
    MODERN_DEVS.lock().push(ring_state(&arena));

    let body = [0xABu8; 64];
    // Post RING frames — each lands on a distinct descriptor 0..RING-1, avail
    // idx advances, notify carries the TX queue index (1).
    for i in 0..RING {
        assert!(matches!(tx_frame_for(key(70), &body), Ok(TxOutcome::Confirmed)));
        assert_eq!(arena.desc_addr(i), BUF0_PA + (i as u64) * 0x1000);
        assert_eq!(arena.desc_len(i), (VIRTIO_NET_HDR_LEN + body.len()) as u32);
        assert_eq!(arena.avail_ring(i), i as u16);
        assert_eq!(arena.avail_idx(), (i + 1) as u16);
        assert_eq!(arena.notify(), 1);
    }

    // Ring is now full (4 in flight, device reaped none): next post must not
    // advance avail — it times out waiting for a completion.
    assert!(matches!(tx_frame_for(key(70), &body), Ok(TxOutcome::Timeout)));
    assert_eq!(arena.avail_idx(), RING as u16);

    // Device completes 2 frames. Next post reuses descriptor 0, wraps the
    // avail ring slot, and advances idx to 5.
    arena.set_used_idx(2);
    assert!(matches!(tx_frame_for(key(70), &body), Ok(TxOutcome::Confirmed)));
    assert_eq!(arena.desc_addr(0), BUF0_PA);       // descriptor 0 reused
    assert_eq!(arena.avail_ring(0), 0);            // avail slot 4 % 4 == 0
    assert_eq!(arena.avail_idx(), (RING + 1) as u16);

    clear_test_state();
}

#[test]
fn tx_ring_header_is_zeroed_and_body_copied() {
    let _guard = TEST_STATE_LOCK.lock();
    clear_test_state();
    let arena = Arena::new();
    MODERN_DEVS.lock().push(ring_state(&arena));

    let body = [0x5Au8, 0x11, 0x22, 0x33];
    assert!(matches!(tx_frame_for(key(70), &body), Ok(TxOutcome::Confirmed)));

    let buf = arena.base + BUF0_PA;
    for i in 0..VIRTIO_NET_HDR_LEN {
        assert_eq!(unsafe { core::ptr::read_volatile((buf + i as u64) as *const u8) }, 0);
    }
    for (i, b) in body.iter().enumerate() {
        let got = unsafe {
            core::ptr::read_volatile((buf + VIRTIO_NET_HDR_LEN as u64 + i as u64) as *const u8)
        };
        assert_eq!(got, *b);
    }
    clear_test_state();
}
