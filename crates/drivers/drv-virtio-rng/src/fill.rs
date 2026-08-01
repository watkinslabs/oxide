use core::sync::atomic::Ordering;

use crate::consts::{FILL_BUFFER_BYTES, FILL_POLL_BUDGET};
use crate::registry::{active_handle, find_handle, RngHandle};

pub fn fill(buf: &mut [u8]) -> usize {
    let Some(record) = active_handle() else {
        return 0;
    };
    fill_record(&record, buf)
}

pub fn fill_from_device(device_key: virtio::VirtioChildDeviceKey, buf: &mut [u8]) -> usize {
    let Some(record) = find_handle(device_key) else {
        return 0;
    };
    fill_record(&record, buf)
}

/// Run one entropy request against a single record, or 0 if it is disarmed.
/// # C: O(want) + bounded device poll (FILL_POLL_BUDGET)
pub(crate) fn fill_record(record: &RngHandle, buf: &mut [u8]) -> usize {
    let mut g = record.lock();
    let ctx = &mut *g;
    let want = buf.len().min(FILL_BUFFER_BYTES);
    if want == 0 || ctx.shutdown || ctx.bounce_pa == 0 {
        return 0;
    }
    let h = ctx.hhdm;
    let q = ctx.requestq;
    let desc = h.wrapping_add(q.desc_pa) as *mut u64;
    // Descriptor 0 = { addr=bounce_pa, len=want, flags=WRITE, next=0 }: the
    // device fills the driver's own frame, never memory it was not handed.
    // SAFETY: HHDM-mapped q0 descriptor table the boot probe programmed and
    // this record still owns (bounce_pa != 0 checked above under the record
    // lock); slot 0 exists for every negotiated queue size, and the two
    // aligned u64 stores cover addr and the len/flags/next word.
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.bounce_pa);
        let w1 = (want as u64) | ((virtio::VRING_DESC_F_WRITE as u64) << 32);
        core::ptr::write_volatile(desc.add(1), w1);
    }

    let qsz = if q.size == 0 { 1u16 } else { q.size };
    let slot = (ctx.avail_idx % qsz) as usize;
    let avail = h.wrapping_add(q.driver_pa) as *mut u16;
    // SAFETY: HHDM-mapped q0 avail ring; ring[slot] is at u16 index 2+slot with
    // slot < qsz <= the transport's one-frame queue-size cap, and idx is at
    // index 1. The release fence orders descriptor 0 and ring[slot] ahead of
    // the idx store so the device never sees a half-built request.
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.avail_idx = ctx.avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.avail_idx);
        ctx.avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: q0 notify VA is the Device-attr MMIO window the transport mapped
    // for this child; the kick is one aligned u16 store of the queue index.
    unsafe { core::ptr::write_volatile(q.notify_va as *mut u16, q.index) };

    let used = h.wrapping_add(q.device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped q0 used ring; aligned u16 load of used.idx at
        // index 1. Volatile because the device, not this CPU, advances it.
        let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if uidx == target {
            break;
        }
        if polls >= FILL_POLL_BUDGET {
            return 0;
        }
        polls += 1;
        core::hint::spin_loop();
    }
    ctx.used_idx_seen = target;
    core::sync::atomic::fence(Ordering::Acquire);

    let elem = ((target.wrapping_sub(1)) % qsz) as usize;
    let used_u32 = h.wrapping_add(q.device_pa) as *const u32;
    // SAFETY: HHDM-mapped q0 used ring; ring[] starts at u32 index 1 and each
    // element is {id,len}, so len of element `elem` is at 1+elem*2+1 with elem
    // < qsz. The acquire fence above orders this after the used.idx load.
    let dev_len = unsafe { core::ptr::read_volatile(used_u32.add(1 + elem * 2 + 1)) } as usize;
    // `dev_len` is DEVICE-supplied and is clamped to `want` before it bounds
    // any access: `want <= FILL_BUFFER_BYTES` (one frame) and `want <= buf.len()`.
    let n = dev_len.min(want);

    let src = h.wrapping_add(ctx.bounce_pa) as *const u8;
    // SAFETY: HHDM-mapped bounce frame this record owns; n <= want <= one frame
    // keeps the reads inside it, and the destination bound comes from the safe
    // iterator over `buf`, not from the device-reported length.
    unsafe {
        for (i, slot) in buf.iter_mut().take(n).enumerate() {
            *slot = core::ptr::read_volatile(src.add(i));
        }
    }
    n
}
