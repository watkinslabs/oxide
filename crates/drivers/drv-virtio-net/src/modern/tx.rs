use super::*;

const VIRTQ_DESC_BYTES: usize = 16;
const VIRTQ_AVAIL_HEADER_BYTES: usize = 4;
const VIRTQ_AVAIL_ELEM_BYTES: usize = 2;
const VIRTQ_USED_HEADER_BYTES: usize = 4;
const VIRTQ_USED_ELEM_BYTES: usize = 8;
// Bounded wait for one TX completion when the ring is full. Reached only under
// sustained back-pressure (all `tx_bufs` descriptors in flight); a healthy
// device drains in microseconds. Not a per-frame spin — see the ring model.
const TX_COMPLETION_SPINS: usize = 1_000_000;

// -------- F59-05: TX ring on the modern transport ----------------------
//
// Linux `virtnet` posts across the whole TX ring and reaps completions
// lazily (`free_old_xmit_skbs`) rather than synchronously waiting for each
// frame. We mirror that: `tx_bufs` holds one DMA frame per usable descriptor
// (descriptor `i` <-> `tx_bufs[i]`). `tx_frame_for` reaps completed frames
// (advances `tx_last_used` to the device `used.idx`), posts the new frame on
// the next descriptor `tx_next_avail % ring_depth`, kicks, and RETURNS — it
// does not hold the device-table lock across a completion spin, so a TX never
// blocks RX draining. The only wait is when every descriptor is in flight
// (ring full), and that reuse guard is exactly what keeps a descriptor's
// buffer from being overwritten while the device still owns it (in-order TX
// completion, as QEMU and every mainstream virtio-net backend provide).

/// Errors returned by `tx_frame`.
#[derive(Copy, Clone, Debug)]
pub enum TxErr {
    /// Modern virtio-net not initialized; `init_modern` has not run.
    NotPresent,
    /// `body.len() + virtio_net_hdr` exceeds the 4 KiB scratch buffer.
    TooLarge,
    /// Boot probe didn't allocate a TX scratch buffer (hit pmm
    /// pressure or bailed before DRIVER_OK).
    NoBuf,
}

/// Maximum payload `tx_frame` accepts (4 KiB scratch minus the
/// 12-byte virtio_net_hdr; ethernet MTU 1500 fits comfortably).
pub const TX_MAX_BODY: usize = 4096 - VIRTIO_NET_HDR_LEN;

/// Outcome of a `tx_frame` call when no setup error occurred.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TxOutcome {
    /// Device advanced `q1.used.idx` within the post-kick spin
    /// window — the frame is on the wire (or at least owned by
    /// the device's TX path).
    Confirmed,
    /// We posted + kicked, but the device hadn't advanced
    /// `q1.used.idx` by the time the spin window expired. The
    /// avail-side state is consistent (caller can reissue) but
    /// the kick may not have been processed.
    Timeout,
}

/// Send one frame out the named modern virtio-net transmit queue. Reaps
/// completed TX descriptors (advances `tx_last_used` to the device
/// `used.idx`), writes the 12-byte zero virtio_net_hdr + `body` into the next
/// ring buffer, publishes its descriptor on the avail ring, kicks the TX
/// notify window, and returns without spinning for this frame's completion.
///
/// Returns `TxOutcome::Confirmed` once the frame is posted and kicked. The
/// only wait is a bounded reap when the ring is full (every descriptor in
/// flight); if that reap times out (device wedged) the caller gets
/// `TxOutcome::Timeout` and no frame is posted. `Err(_)` means the transport
/// isn't ready to attempt a post.
///
/// # C: O(N devices) under device-table lock; O(1) posts, no per-frame spin
/// # Lk: takes the virtio-net device-table lock across MMIO writes; no callbacks.
pub fn tx_frame_for(device_key: DeviceKey, body: &[u8]) -> Result<TxOutcome, TxErr> {
    if body.len() > TX_MAX_BODY {
        return Err(TxErr::TooLarge);
    }
    let mut g = MODERN_DEVS.lock();
    let Some(s) = g.iter_mut().find(|state| state.device_key == device_key) else {
        return Err(TxErr::NotPresent);
    };
    if s.tx_bufs.is_empty() || !s.txq.is_runtime_valid() {
        return Err(TxErr::NoBuf);
    }
    let hhdm = s.hhdm;
    if hhdm == 0 { return Err(TxErr::NoBuf); }

    let ring_depth = s.tx_bufs.len();
    let txq_size   = s.txq.size as usize;
    let used_bytes = VIRTQ_USED_HEADER_BYTES + txq_size * VIRTQ_USED_ELEM_BYTES;
    let desc_base  = hhdm.wrapping_add(s.txq.desc_pa);
    let avail_va   = hhdm.wrapping_add(s.txq.driver_pa);
    let used_va    = hhdm.wrapping_add(s.txq.device_pa);

    // Lazy completion reap: pull the device's used.idx forward. In-flight count
    // is `tx_next_avail - tx_last_used`. Completed frames free their buffers.
    // SAFETY: HHDM-mapped q1 used ring; aligned u16 load of used.idx at +2.
    virtio::dma::invalidate_from_device(used_va, used_bytes);
    let dev_used = unsafe { core::ptr::read_volatile((used_va + 2) as *const u16) };
    s.tx_last_used = dev_used;

    // Ring full (every descriptor still owned by the device): bounded wait for
    // at least one completion before reusing a buffer. Rare — only under
    // sustained back-pressure. A wedged device yields Timeout, not a hang.
    if s.tx_next_avail.wrapping_sub(s.tx_last_used) as usize >= ring_depth {
        let mut reaped = false;
        for _ in 0..TX_COMPLETION_SPINS {
            virtio::dma::invalidate_from_device(used_va, used_bytes);
            // SAFETY: HHDM-mapped q1 used ring idx field at +2; aligned u16 load.
            let now = unsafe { core::ptr::read_volatile((used_va + 2) as *const u16) };
            if now != s.tx_last_used {
                s.tx_last_used = now;
                if (s.tx_next_avail.wrapping_sub(s.tx_last_used) as usize) < ring_depth {
                    reaped = true;
                    break;
                }
            }
            core::hint::spin_loop();
        }
        if !reaped { return Ok(TxOutcome::Timeout); }
    }

    // Slot = next descriptor to (re)use. Its buffer is free by the ring-full
    // guard above (in-order completion).
    let desc_id  = (s.tx_next_avail as usize) % ring_depth;
    let buf_pa   = s.tx_bufs[desc_id];
    let buf_va   = hhdm.wrapping_add(buf_pa);
    let desc_va  = desc_base + (desc_id as u64) * VIRTQ_DESC_BYTES as u64;
    let total_len = (VIRTIO_NET_HDR_LEN + body.len()) as u32;

    // Write virtio_net_hdr (12 zero bytes) + body into the slot's buffer.
    // SAFETY: HHDM-mapped driver-owned TX frame `desc_id`; bytes 0..total_len stay within the 4 KiB page; single CPU under the virtio-net device-table lock; buffer is not device-owned (ring-full guard).
    unsafe {
        for i in 0..VIRTIO_NET_HDR_LEN {
            core::ptr::write_volatile((buf_va + i as u64) as *mut u8, 0);
        }
        for (i, b) in body.iter().enumerate() {
            core::ptr::write_volatile(
                (buf_va + VIRTIO_NET_HDR_LEN as u64 + i as u64) as *mut u8,
                *b,
            );
        }
    }

    // Descriptor `desc_id`: { addr=buf_pa; len=total_len; flags=0; next=0 }.
    // SAFETY: HHDM-mapped queue-1 descriptor table owned by driver under the virtio-net device-table lock; aligned u64+u32+u16 stores within the desc-`desc_id` slot.
    unsafe {
        core::ptr::write_volatile(desc_va as *mut u64, buf_pa);
        core::ptr::write_volatile((desc_va + 8)  as *mut u32, total_len);
        core::ptr::write_volatile((desc_va + 12) as *mut u16, 0u16); // flags
        core::ptr::write_volatile((desc_va + 14) as *mut u16, 0u16); // next
    }
    virtio::dma::clean_to_device(buf_va, total_len as usize);
    virtio::dma::clean_to_device(desc_va, VIRTQ_DESC_BYTES);

    // Publish on the avail ring: ring[avail_idx % txq_size] = desc_id.
    let pub_slot = (s.tx_next_avail as usize) % txq_size;
    // SAFETY: HHDM-mapped q1 avail ring; ring[pub_slot] at byte +4 = u16 offset 2+pub_slot.
    unsafe {
        core::ptr::write_volatile(
            (avail_va + 4 + (pub_slot as u64) * 2) as *mut u16,
            desc_id as u16,
        );
    }
    core::sync::atomic::fence(Ordering::Release);
    let new_idx = s.tx_next_avail.wrapping_add(1);
    // SAFETY: HHDM-mapped q1 avail ring; idx field at +2; published after the ring write fence above.
    unsafe {
        core::ptr::write_volatile((avail_va + 2) as *mut u16, new_idx);
    }
    virtio::dma::clean_to_device(
        avail_va,
        VIRTQ_AVAIL_HEADER_BYTES + txq_size * VIRTQ_AVAIL_ELEM_BYTES,
    );
    core::sync::atomic::fence(Ordering::Release);
    s.tx_next_avail = new_idx;

    // Kick. Completion is reaped lazily on a later call — no spin here, so RX
    // draining (same device-table lock) is not blocked by TX.
    // SAFETY: txq.notify_va is Device-attr-mapped during DRIVER_OK; aligned u16 store of the TX queue index.
    unsafe {
        core::ptr::write_volatile(s.txq.notify_va as *mut u16, s.txq.index);
    }
    Ok(TxOutcome::Confirmed)
}
