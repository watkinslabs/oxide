// virtio-vsock RX ring mechanics. q0 holds RX_RING_BUFS device-WRITE
// descriptors, one per pre-allocated bounce frame; the device writes an
// inbound virtio_vsock_hdr (+ payload) into a free buffer and bumps
// used.idx. `drain` walks the used ring, parses each completed buffer
// via `net::vsock::hdr::VsockHdr::decode`, dispatches to
// `net::vsock::deliver_rx`, then re-publishes the descriptor so the
// device can refill it.

use core::sync::atomic::Ordering;
use net::vsock::hdr::{VsockHdr, VSOCK_HDR_LEN};
use crate::registry::CTX;
use crate::RX_RING_BUFS;

/// Per-RX-buffer capacity (one 4 KiB frame). # C: O(1)
const RX_BUF_LEN: u32 = crate::consts::FRAME_BYTES as u32;

/// Pre-post every RX descriptor on q0 + bump avail.idx by RX_RING_BUFS,
/// then kick the device. Called once at install. # C: O(RX_RING_BUFS)
pub(crate) fn prepost_all(device_key: virtio::VirtioChildDeviceKey) {
    let mut g = CTX.lock();
    let ctx = match g.iter_mut().find(|ctx| ctx.device_key == device_key) {
        Some(c) => c,
        None => return,
    };
    let h = ctx.hhdm;
    let qsz = ctx.rxq.size;
    let desc = h.wrapping_add(ctx.rxq.desc_pa) as *mut u64;
    let avail = h.wrapping_add(ctx.rxq.driver_pa) as *mut u16;

    for i in 0..RX_RING_BUFS {
        let buf_pa = ctx.rx_bufs[i];
        // Descriptor[i] = { addr=buf_pa, len=4096, flags=WRITE, next=0 }.
        // SAFETY: HHDM-mapped q0 descriptor table programmed by the boot
        // probe; two aligned u64 stores per slot i < RX_RING_BUFS <= rxq.size
        // build a device-writable descriptor over our owned bounce frame.
        unsafe {
            core::ptr::write_volatile(desc.add(i * 2), buf_pa);
            let w1 = (RX_BUF_LEN as u64) | ((virtio::VRING_DESC_F_WRITE as u64) << 32);
            core::ptr::write_volatile(desc.add(i * 2 + 1), w1);
        }
        let slot = (ctx.rx_avail_idx % qsz) as usize;
        // SAFETY: HHDM-mapped q0 avail ring; u16 store at ring(2+slot)
        // publishes descriptor index i; slot bounded by rxq.size.
        unsafe { core::ptr::write_volatile(avail.add(2 + slot), i as u16); }
        ctx.rx_avail_idx = ctx.rx_avail_idx.wrapping_add(1);
    }
    core::sync::atomic::fence(Ordering::Release);
    // SAFETY: HHDM-mapped q0 avail ring; publish idx after the descriptor
    // + ring writes are observable so the device sees complete requests.
    unsafe { core::ptr::write_volatile(avail.add(1), ctx.rx_avail_idx); }
    core::sync::atomic::fence(Ordering::Release);
    // Kick q0 (queue index 0).
    // SAFETY: q0 notify VA is the Device-attr MMIO window mapped by the
    // boot probe; an aligned u16 store of queue index 0 is the kick.
    unsafe { core::ptr::write_volatile(ctx.rxq.notify_va as *mut u16, ctx.rxq.index); }
}

/// Drain completed RX buffers. For each used element since last drain:
/// parse the header, dispatch to net::vsock, then re-post the same
/// descriptor (its buffer is reusable once we've copied/parsed it).
/// # C: O(packets drained)
pub(crate) fn drain() -> usize {
    // Snapshot the work under the lock, copy out the payloads, release
    // the lock, THEN call deliver_rx (which may re-enter the TX hook to
    // send RST/credit — re-entering CTX.lock() would deadlock).
    let mut pkts: alloc::vec::Vec<(net::vsock::VsockOwner, VsockHdr, alloc::vec::Vec<u8>)> = alloc::vec::Vec::new();
    {
        let mut g = CTX.lock();
        for ctx in g.iter_mut() {
            let Some(owner) = net::vsock::VsockOwner::from_raw(ctx.device_key.raw()) else {
                continue;
            };
            let h = ctx.hhdm;
            let qsz = ctx.rxq.size;
            let used = h.wrapping_add(ctx.rxq.device_pa) as *const u16;
            // SAFETY: HHDM-mapped q0 used ring; aligned u16 load of used.idx.
            let cur_used = unsafe { core::ptr::read_volatile(used.add(1)) };
            // virtio 1.2 §2.7.13.2: acquire barrier after observing used.idx so the
            // used-element id/len + RX buffer payload are not read ahead of it.
            core::sync::atomic::fence(Ordering::Acquire);
            let used_u32 = h.wrapping_add(ctx.rxq.device_pa) as *const u32;
            let mut refill_slots: alloc::vec::Vec<u32> = alloc::vec::Vec::new();

            while ctx.rx_used_seen != cur_used {
                let e = (ctx.rx_used_seen % qsz) as usize;
                // used ring[]: starts at byte 4 → u32 index 1; each elem is
                // {id:u32, len:u32}; id at idx 1+e*2, len at 1+e*2+1.
                // SAFETY: HHDM-mapped used ring; aligned u32 loads of the
                // completed element's id+len; e bounded by rxq.size.
                let (desc_id, dev_len) = unsafe {
                    (core::ptr::read_volatile(used_u32.add(1 + e * 2)),
                     core::ptr::read_volatile(used_u32.add(1 + e * 2 + 1)))
                };
                let slot = (desc_id as usize) % RX_RING_BUFS;
                let buf_pa = ctx.rx_bufs[slot];
                let n = (dev_len as usize).min(RX_BUF_LEN as usize);
                if n >= VSOCK_HDR_LEN {
                    let src = h.wrapping_add(buf_pa) as *const u8;
                    let mut raw = alloc::vec![0u8; n];
                    // SAFETY: HHDM-mapped RX bounce frame the device filled;
                    // bounded read of n ≤ 4 KiB bytes the device reported.
                    unsafe { for i in 0..n { raw[i] = core::ptr::read_volatile(src.add(i)); } }
                    if let Some(hdr) = VsockHdr::decode(&raw) {
                        let plen = (hdr.len as usize).min(n - VSOCK_HDR_LEN);
                        let payload = raw[VSOCK_HDR_LEN..VSOCK_HDR_LEN + plen].to_vec();
                        pkts.push((owner, hdr, payload));
                    }
                }
                refill_slots.push(desc_id);
                ctx.rx_used_seen = ctx.rx_used_seen.wrapping_add(1);
            }

            // Re-post the consumed descriptors so the device can refill.
            if !refill_slots.is_empty() {
                let desc = h.wrapping_add(ctx.rxq.desc_pa) as *mut u64;
                let avail = h.wrapping_add(ctx.rxq.driver_pa) as *mut u16;
                for &desc_id in &refill_slots {
                    let slot = (desc_id as usize) % RX_RING_BUFS;
                    let buf_pa = ctx.rx_bufs[slot];
                    // SAFETY: HHDM-mapped q0 descriptor table; rewrite the
                    // device-writable descriptor over our owned bounce frame.
                    unsafe {
                        core::ptr::write_volatile(desc.add(slot * 2), buf_pa);
                        let w1 = (RX_BUF_LEN as u64) | ((virtio::VRING_DESC_F_WRITE as u64) << 32);
                        core::ptr::write_volatile(desc.add(slot * 2 + 1), w1);
                    }
                    let aslot = (ctx.rx_avail_idx % qsz) as usize;
                    // SAFETY: HHDM-mapped q0 avail ring; republish descriptor index.
                    unsafe { core::ptr::write_volatile(avail.add(2 + aslot), slot as u16); }
                    ctx.rx_avail_idx = ctx.rx_avail_idx.wrapping_add(1);
                }
                core::sync::atomic::fence(Ordering::Release);
                // SAFETY: HHDM-mapped q0 avail ring; publish refreshed idx.
                unsafe { core::ptr::write_volatile(avail.add(1), ctx.rx_avail_idx); }
                core::sync::atomic::fence(Ordering::Release);
                // SAFETY: q0 notify VA Device-attr mapped; kick queue index 0.
                unsafe { core::ptr::write_volatile(ctx.rxq.notify_va as *mut u16, ctx.rxq.index); }
            }
        }
    }

    let count = pkts.len();
    for (owner, hdr, payload) in pkts { net::vsock::deliver_rx_from(owner, &hdr, &payload); }
    count
}
