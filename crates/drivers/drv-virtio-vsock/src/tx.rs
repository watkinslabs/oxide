use crate::consts::{FRAME_BYTES, TX_POLL_BUDGET};
use crate::registry::CTX;

/// TX hook installed into `net::vsock`.
pub fn tx_packet(owner: net::vsock::VsockOwner, frame: &[u8]) -> bool {
    let mut g = CTX.lock_bh::<crate::registry::VsockBh>();
    let ctx = match g.iter_mut().find(|ctx| ctx.device_key.raw() == owner.raw()) {
        Some(c) => c,
        None => return false,
    };
    let want = frame.len().min(FRAME_BYTES);
    if want == 0 {
        return false;
    }
    let h = ctx.hhdm;

    let dst = h.wrapping_add(ctx.tx_buf.pa) as *mut u8;
    // SAFETY: HHDM view of the single TX bounce frame this context owns for its
    // whole lifetime (allocated at install, freed only after the context is out
    // of CTX); `want <= FRAME_BYTES` keeps every store inside that one frame,
    // and holding the CTX lock makes this the only writer.
    unsafe {
        for (i, b) in frame.iter().take(want).enumerate() {
            core::ptr::write_volatile(dst.add(i), *b);
        }
    }

    let Some(txq) = ctx.txq.as_mut() else { return false; };
    let Ok(target) = txq.submit(&[virtio::SplitQueueSeg {
        dma: virtio::device_dma_addr(ctx.tx_buf), len: want as u32, device_writes: false,
    }]) else { return false; };
    let mut polls = 0u32;
    loop {
        match txq.pop_used() {
            Ok(Some(used)) if used.head == target => return true,
            Ok(Some(_)) => return false,
            Ok(None) => {}
            Err(_) => return false,
        }
        if polls >= TX_POLL_BUDGET {
            return false;
        }
        polls += 1;
        core::hint::spin_loop();
    }
}
