use core::sync::atomic::Ordering;

use crate::consts::{FRAME_BYTES, TX_POLL_BUDGET};
use crate::registry::CTX;

/// TX hook installed into `net::vsock`.
pub fn tx_packet(owner: net::vsock::VsockOwner, frame: &[u8]) -> bool {
    let mut g = CTX.lock();
    let ctx = match g.iter_mut().find(|ctx| ctx.device_key.raw() == owner.raw()) {
        Some(c) => c,
        None => return false,
    };
    let want = frame.len().min(FRAME_BYTES);
    if want == 0 {
        return false;
    }
    let h = ctx.hhdm;

    let dst = h.wrapping_add(ctx.tx_buf_pa) as *mut u8;
    // SAFETY: HHDM view of the single TX bounce frame this context owns for its
    // whole lifetime (allocated at install, freed only after the context is out
    // of CTX); `want <= FRAME_BYTES` keeps every store inside that one frame,
    // and holding the CTX lock makes this the only writer.
    unsafe {
        for (i, b) in frame.iter().take(want).enumerate() {
            core::ptr::write_volatile(dst.add(i), *b);
        }
    }

    let desc = h.wrapping_add(ctx.txq.desc_pa) as *mut u64;
    // Descriptor 0 = { addr=tx_buf_pa, len=want, flags=0 }: device-readable, so
    // the device never writes back into the frame this request published.
    // SAFETY: HHDM-mapped q1 descriptor table (require_queue accepted desc_pa);
    // two aligned u64 stores at slot 0, present for any negotiated queue size.
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.tx_buf_pa);
        core::ptr::write_volatile(desc.add(1), want as u64);
    }

    let qsz = ctx.txq.size;
    let slot = (ctx.tx_avail_idx % qsz) as usize;
    let avail = h.wrapping_add(ctx.txq.driver_pa) as *mut u16;
    // SAFETY: HHDM-mapped q1 avail ring; ring[slot] is u16 index 2+slot with
    // slot < qsz (`txq.size`, nonzero per require_queue and capped at one
    // ring frame by the transport), idx is index 1, and the release fence
    // publishes descriptor 0 + ring[slot] before the idx store.
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.tx_avail_idx = ctx.tx_avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.tx_avail_idx);
        ctx.tx_avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: q1 notify VA is the Device-attr MMIO window the transport mapped
    // for this child; the kick is one aligned u16 store of the queue index.
    unsafe { core::ptr::write_volatile(ctx.txq.notify_va as *mut u16, ctx.txq.index) };

    let used = h.wrapping_add(ctx.txq.device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped q1 used ring; aligned u16 load of used.idx at
        // index 1, volatile because the device is what advances it.
        let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if uidx == target {
            break;
        }
        if polls >= TX_POLL_BUDGET {
            return false;
        }
        polls += 1;
        core::hint::spin_loop();
    }
    ctx.tx_used_seen = target;
    true
}
