// virtio-vsock RX ring mechanics. q0 holds RX_RING_BUFS device-WRITE
// descriptors, one per pre-allocated bounce frame; the device writes an
// inbound virtio_vsock_hdr (+ payload) into a free buffer and bumps
// used.idx. `drain` walks the used ring, parses each completed buffer
// via `net::vsock::hdr::VsockHdr::decode`, dispatches to
// `net::vsock::deliver_rx`, then re-publishes the descriptor so the
// device can refill it.

use net::vsock::hdr::{VsockHdr, VSOCK_HDR_LEN};
use crate::registry::CTX;
use crate::RX_RING_BUFS;

/// Per-RX-buffer capacity (one 4 KiB frame). # C: O(1)
const RX_BUF_LEN: u32 = crate::consts::FRAME_BYTES as u32;

/// Pre-post every RX descriptor on q0 + bump avail.idx by RX_RING_BUFS,
/// then kick the device. Called once at install. # C: O(RX_RING_BUFS)
pub(crate) fn prepost_all(device_key: virtio::VirtioChildDeviceKey) {
    let mut g = CTX.lock_bh::<crate::registry::VsockBh>();
    let ctx = match g.iter_mut().find(|ctx| ctx.device_key == device_key) {
        Some(c) => c,
        None => return,
    };
    let Some(rxq) = ctx.rxq.as_mut() else { return; };

    for i in 0..RX_RING_BUFS {
        let buf = ctx.rx_bufs[i];
        let Ok(head) = rxq.submit(&[virtio::SplitQueueSeg {
            dma: virtio::device_dma_addr(buf), len: RX_BUF_LEN, device_writes: true,
        }]) else { return; };
        ctx.rx_desc_bufs[head as usize] = i as u16;
    }
}

/// Drain completed RX buffers. For each used element since last drain:
/// parse the header, dispatch to net::vsock, then re-post the same
/// descriptor (its buffer is reusable once we've copied/parsed it).
/// # C: O(packets drained)
pub(crate) fn drain() -> usize {
    // Snapshot the work under the lock, copy out the payloads, release
    // the lock, THEN call deliver_rx (which may re-enter the TX hook to
    // send RST/credit — re-entering CTX.lock_bh::<crate::registry::VsockBh>() would deadlock).
    let mut pkts: alloc::vec::Vec<(net::vsock::VsockOwner, VsockHdr, alloc::vec::Vec<u8>)> = alloc::vec::Vec::new();
    {
        let mut g = CTX.lock_bh::<crate::registry::VsockBh>();
        for ctx in g.iter_mut() {
            let Some(owner) = net::vsock::VsockOwner::from_raw(ctx.device_key.raw()) else {
                continue;
            };
            let h = ctx.hhdm;
            let Some(rxq) = ctx.rxq.as_mut() else { continue; };
            while let Ok(Some(used)) = rxq.pop_used() {
                let desc_id = used.head;
                let dev_len = used.len;
                let slot = ctx.rx_desc_bufs[desc_id as usize] as usize;
                if slot >= RX_RING_BUFS { continue; }
                let buf = ctx.rx_bufs[slot];
                let n = (dev_len as usize).min(RX_BUF_LEN as usize);
                if n >= VSOCK_HDR_LEN {
                    let src = h.wrapping_add(buf.pa) as *const u8;
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
                let Ok(head) = rxq.submit(&[virtio::SplitQueueSeg {
                    dma: virtio::device_dma_addr(buf), len: RX_BUF_LEN, device_writes: true,
                }]) else { continue; };
                ctx.rx_desc_bufs[head as usize] = slot as u16;
            }
        }
    }

    let count = pkts.len();
    for (owner, hdr, payload) in pkts { net::vsock::deliver_rx_from(owner, &hdr, &payload); }
    count
}
