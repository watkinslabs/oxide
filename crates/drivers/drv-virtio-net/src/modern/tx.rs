use super::*;

// -------- F59-05: TX on the modern transport ---------------------------
//
// One scratch buffer pinned to queue 1 descriptor 0; tx_frame rewrites
// the buffer (12-byte virtio_net_hdr zeros + caller body) and posts a
// fresh avail.idx entry referring to descriptor 0. The transport probe
// allocates this scratch page but does not send a synthetic packet; first
// real TX starts from avail.idx 0.

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

/// Send one frame out the named modern virtio-net transmit queue. Writes
/// the 12-byte zero virtio_net_hdr followed by `body` into the
/// pinned TX scratch buffer, updates queue-1 descriptor 0 with the
/// new len, posts on avail, and kicks the TX queue notify window. Polls
/// `q1.used.idx` for change relative to the pre-kick value.
///
/// Returns `TxOutcome::Confirmed` only when the device acknowledged
/// completion. `Timeout` means we issued the kick but didn't see
/// `used.idx` advance — distinct from `Err(_)` which means we
/// couldn't even attempt the post.
///
/// # C: O(N devices) under device-table lock
/// # Lk: takes the virtio-net device-table lock across MMIO writes; no callbacks.
pub fn tx_frame_for(device_key: DeviceKey, body: &[u8]) -> Result<TxOutcome, TxErr> {
    if body.len() > TX_MAX_BODY {
        return Err(TxErr::TooLarge);
    }
    let mut g = MODERN_DEVS.lock();
    let Some(s) = g.iter_mut().find(|state| state.device_key == device_key) else {
        return Err(TxErr::NotPresent);
    };
    if s.tx0_buf_pa == 0 || !s.txq.is_runtime_valid() {
        return Err(TxErr::NoBuf);
    }

    let hhdm = s.hhdm;
    if hhdm == 0 { return Err(TxErr::NoBuf); }

    let buf_va   = hhdm.wrapping_add(s.tx0_buf_pa);
    let desc_va  = hhdm.wrapping_add(s.txq.desc_pa);
    let avail_va = hhdm.wrapping_add(s.txq.driver_pa);
    let used_va  = hhdm.wrapping_add(s.txq.device_pa);

    // Write virtio_net_hdr (12 zero bytes) + body into the scratch
    // buffer. Use byte writes via volatile to avoid relying on memcpy
    // ordering; total len fits in one PMM page.
    let total_len = (VIRTIO_NET_HDR_LEN + body.len()) as u32;
    // SAFETY: HHDM-mapped freshly-owned scratch frame; bytes 0..total_len stay within the 4 KiB page; single CPU under the virtio-net device-table lock.
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

    // Update q1 descriptor 0: { addr=tx_buf_pa; len=total_len; flags=0 }.
    // Layout: u64 addr at +0; u32 len at +8; u16 flags at +12; u16 next at +14.
    // SAFETY: HHDM-mapped queue-1 descriptor table owned by driver under the virtio-net device-table lock; aligned u64+u32+u16 stores within the desc-0 slot.
    unsafe {
        core::ptr::write_volatile(desc_va as *mut u64, s.tx0_buf_pa);
        core::ptr::write_volatile((desc_va + 8)  as *mut u32, total_len);
        core::ptr::write_volatile((desc_va + 12) as *mut u16, 0u16); // flags
        core::ptr::write_volatile((desc_va + 14) as *mut u16, 0u16); // next
    }

    // Read q1 used.idx BEFORE the kick so we can poll for a real
    // post-kick change. The device may already have unrelated used.idx
    // movement, so the live pre-kick value is the only reliable cursor.
    // SAFETY: HHDM-mapped q1 used ring; aligned u16 load at +2.
    let pre_used = unsafe {
        core::ptr::read_volatile((used_va + 2) as *const u16)
    };
    s.tx_last_used = pre_used;

    let txq_size = s.txq.size as usize;
    let next_avail = s.tx_next_avail;
    let pub_slot = (next_avail as usize) % txq_size;
    // SAFETY: HHDM-mapped q1 avail ring; ring[pub_slot] at byte +4 = u16 offset 2+pub_slot.
    unsafe {
        core::ptr::write_volatile(
            (avail_va + 4 + (pub_slot as u64) * 2) as *mut u16,
            0u16, // descriptor id 0
        );
    }
    core::sync::atomic::fence(Ordering::Release);
    let new_idx = next_avail.wrapping_add(1);
    // SAFETY: HHDM-mapped q1 avail ring; idx field at +2; published after the ring write fence above.
    unsafe {
        core::ptr::write_volatile((avail_va + 2) as *mut u16, new_idx);
    }
    core::sync::atomic::fence(Ordering::Release);
    s.tx_next_avail = new_idx;

    // SAFETY: txq.notify_va is Device-attr-mapped during DRIVER_OK; aligned u16 store of the TX queue index.
    unsafe {
        core::ptr::write_volatile(s.txq.notify_va as *mut u16, s.txq.index);
    }

    // Brief observation window: poll q1 used.idx for the device to
    // advance past pre_used. Returns Confirmed on real completion,
    // Timeout if the device didn't move.
    for _ in 0..1_000_000usize {
        // SAFETY: HHDM-mapped q1 used ring idx field at +2; aligned u16 load.
        let dev_used = unsafe {
            core::ptr::read_volatile((used_va + 2) as *const u16)
        };
        if dev_used != pre_used {
            s.tx_last_used = dev_used;
            return Ok(TxOutcome::Confirmed);
        }
        core::hint::spin_loop();
    }
    Ok(TxOutcome::Timeout)
}

