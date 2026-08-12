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
    if want == 0 || ctx.shutdown || ctx.bounce_pa == 0 || ctx.bounce_dma == 0 {
        return 0;
    }
    let Some(requestq) = ctx.requestq.as_mut() else { return 0 };
    if requestq.submit(&[virtio::SplitQueueSeg {
        dma: ctx.bounce_dma, len: want as u32, device_writes: true,
    }]).is_err() {
        return 0;
    }
    let dev_len = (0..FILL_POLL_BUDGET).find_map(|_| match requestq.pop_used() {
        Ok(Some(used)) => Some(used.len as usize),
        Ok(None) => { core::hint::spin_loop(); None }
        Err(_) => Some(0),
    }).unwrap_or(0);
    // `dev_len` is DEVICE-supplied and is clamped to `want` before it bounds
    // any access: `want <= FILL_BUFFER_BYTES` (one frame) and `want <= buf.len()`.
    let n = dev_len.min(want);

    let src = ctx.hhdm.wrapping_add(ctx.bounce_pa) as *const u8;
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
