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

fn fill_record(record: &RngHandle, buf: &mut [u8]) -> usize {
    let mut g = record.lock();
    let ctx = &mut *g;
    let want = buf.len().min(FILL_BUFFER_BYTES);
    if want == 0 || ctx.shutdown || ctx.bounce_pa == 0 {
        return 0;
    }
    let h = ctx.hhdm;
    let q = ctx.requestq;
    let desc = h.wrapping_add(q.desc_pa) as *mut u64;
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.bounce_pa);
        let w1 = (want as u64) | ((virtio::VRING_DESC_F_WRITE as u64) << 32);
        core::ptr::write_volatile(desc.add(1), w1);
    }

    let qsz = if q.size == 0 { 1u16 } else { q.size };
    let slot = (ctx.avail_idx % qsz) as usize;
    let avail = h.wrapping_add(q.driver_pa) as *mut u16;
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.avail_idx = ctx.avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.avail_idx);
        ctx.avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);
    unsafe { core::ptr::write_volatile(q.notify_va as *mut u16, q.index) };

    let used = h.wrapping_add(q.device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
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
    let dev_len = unsafe { core::ptr::read_volatile(used_u32.add(1 + elem * 2 + 1)) } as usize;
    let n = dev_len.min(want);

    let src = h.wrapping_add(ctx.bounce_pa) as *const u8;
    unsafe {
        for (i, slot) in buf.iter_mut().take(n).enumerate() {
            *slot = core::ptr::read_volatile(src.add(i));
        }
    }
    n
}
