use core::sync::atomic::Ordering;

use super::{
    DeviceKey,
    SOFTIRQ_INSTALLED,
    VIRTIO_NET_HDR_LEN,
};

// Module manifest: assignment owns descriptor generations; metadata decodes
// virtio headers; runtime owns per-device RX registration and lifecycle.
pub(super) mod assignment;
mod metadata;
mod runtime;
use assignment::completion;
pub(super) use runtime::{clear_rx_runtime, clear_softirq_ip_for_owner,
    first_iface_ip_for, install_rx_runtime, remove_rx_runtime_for, rx_runtime_empty,
    set_rx_generation_for_owner, set_softirq_iface, set_softirq_ip_for_owner};
#[cfg(test)]
pub(super) use runtime::set_softirq_ip_for_iface;

const VIRTQ_AVAIL_HEADER_BYTES: usize = 4;
const VIRTQ_AVAIL_ELEM_BYTES: usize = 2;
const VIRTQ_USED_HEADER_BYTES: usize = 4;
const VIRTQ_USED_ELEM_BYTES: usize = 8;

/// Install this driver's RX bottom-half handler. The handler belongs to the
/// virtio-net device lifetime, not to boot or the transport layer.
/// # C: O(1)
pub fn install_rx_softirq_handler() {
    if !SOFTIRQ_INSTALLED.swap(true, Ordering::AcqRel) {
        #[cfg(target_os = "oxide-kernel")]
        softirq::set_handler(softirq::Slot::NetRx, rx_drain_softirq);
    }
}

/// Remove this driver's RX bottom-half handler and discard queued stale RX
/// work. Called after the device is reset during remove.
/// # C: O(NCPU)
pub fn uninstall_rx_softirq_handler() {
    if SOFTIRQ_INSTALLED.swap(false, Ordering::AcqRel) {
        #[cfg(target_os = "oxide-kernel")]
        let _ = softirq::clear_handler(softirq::Slot::NetRx);
    }
}

pub(super) fn release_rx_shared_runtime_if_last(last_runtime: bool) {
    if last_runtime {
        uninstall_rx_softirq_handler();
    }
}

/// Softirq slot handler. Drains pending RX into the net stack.
/// Bails fast when no iface stashed (boot ordering) or RX queue empty
/// (poll_into_stack returns 0 in either case).
/// # C: O(rx_drain)
#[cfg(target_os = "oxide-kernel")]
pub fn rx_drain_softirq() {
    for runtime in runtime::snapshot() {
        let _ = poll_into_stack_for(runtime.device_key, runtime.iface, &runtime.owner,
            runtime.generation, runtime.ip);
    }
}

/// Raise the virtio-net RX softirq from device IRQ context. Actual ring walking
/// belongs to `rx_drain_softirq`, which runs as the NetRx bottom half.
/// # C: O(1)
pub fn raise_rx() { softirq::raise(softirq::Slot::NetRx); }

// -------- F59-13: poll RX into the kernel net stack -------------------
//
// `poll_into_stack_for(device_key, iface)` drains one device once and dispatches each
// frame: ARP → arp_cache (with a synchronous reply if it's a
// request for `our_ip`); IPv4 → strip eth header + hand to
// `stack.deliver_rx(iface, l3)`. Intended call site is a periodic
// kthread or per-tick hook; v1 invokes it once at boot for a
// diagnostic line, replacing the explicit ARP+ICMP probes once the
// stack is fully wired (F59-14+). Returns frames consumed.
/// # C: O(N used * frame_len)
#[cfg(target_os = "oxide-kernel")]
pub fn poll_into_stack_for(device_key: DeviceKey, iface: net::NetIfaceId,
                           owner: &alloc::sync::Arc<dyn net::NetDev>, generation: u64,
                           our_ip: [u8; 4]) -> usize {
    let _ = our_ip;
    let stack = net::sock::stack();
    let Some(lease) = stack.ifaces.acquire_ingress_for(iface, owner) else { return 0 };
    if lease.generation() != generation { return 0; }
    rx_poll_for(device_key, owner, generation, |f: &[u8], metadata| {
        if f.len() < 14 { return; }
        let et = ((f[12] as u16) << 8) | (f[13] as u16);
        // F137: tap full L2 frame to AF_PACKET sockets bound on this
        // iface. Done before ARP/IP demux so dhcpcd (ETH_P_ALL) sees
        // every frame regardless of whether the kernel stack also
        // consumes it.
        net::sock::deliver_packet_ingress_meta_in(&lease, f, metadata);
        match et {
            0x0806 => {
                let _ = stack.deliver_arp_in(&lease, &f[14..]);
            }
            net::eth_p::IPV4 => {
                let _ = stack.deliver_rx_in(&lease, &f[14..]);
            }
            net::eth_p::IPV6 => {
                // F180: IPv6. Hand the L3 payload to the stack's
                // IPv6 path; minimum-viable demux handles ICMPv6
                // echo + graceful drop for unbound L4 destinations.
                let _ = stack.deliver_rx_ipv6_in(&lease, &f[14..]);
            }
            _ => {}
        }
    })
}

// -------- F59-02: RX poll on the modern transport ----------------------
//
// Drains queue-0 used-ring entries the device wrote since the last call, hands
// each frame body (Ethernet header + payload, virtio_net_hdr stripped) to `cb`, and re-publishes the completed
// descriptor ID onto the avail ring so the device can fill that buffer again.
// After a non-zero drain we kick the RX queue notify window so the device knows
// the avail-ring advanced.
//
// Cursors live in the per-device runtime record and are incremented only inside
// rx_poll while holding the virtio-net device-table lock.

/// Drain pending RX completions for the named transport and assignment
/// generation, invoking `cb` for each current frame body (Ethernet header +
/// payload, virtio_net_hdr stripped). Re-publishes the same descriptor tagged
/// with the current generation and kicks the device once if any descriptor
/// completed.
///
/// Returns frames delivered. Returns 0 if the device isn't initialized
/// or the device hasn't advanced its used.idx since the last call.
///
/// # C: O(frames_in_flight)
/// # Lk: takes the virtio-net device-table lock across ring read + avail publish, drops it
///       before invoking cb. Required so cb's downstream (e.g. the TCP
///       stack emitting an ACK via tx_frame_for) can re-take the lock
///       without UP self-deadlock. Frames are copied out before unlock
///       so the device can safely overwrite RX buffers once republished.
pub fn rx_poll_for<F: FnMut(&[u8], net::PacketRxMetadata)>(device_key: DeviceKey,
                                    owner: &alloc::sync::Arc<dyn net::NetDev>,
                                    expected_generation: u64, mut cb: F) -> usize {
    let Some(runtime) = runtime::net_runtime_for(device_key, owner, expected_generation)
        else { return 0 };
    let current_generation = runtime.rx_assignments.current();
    if expected_generation != current_generation { return 0; }
    let mut g = super::MODERN_DEVS.lock();
    let Some(s) = g.iter_mut().find(|state| state.device_key == device_key) else {
        return 0;
    };
    if !s.rxq.is_runtime_valid() || s.rx_bufs.is_empty() {
        return 0;
    }

    let hhdm = s.hhdm;
    if hhdm == 0 { return 0; }

    let used_va  = hhdm.wrapping_add(s.rxq.device_pa);
    let avail_va = hhdm.wrapping_add(s.rxq.driver_pa);
    let rxq_size = s.rxq.size as usize;

    // SAFETY: HHDM-mapped device-written used ring; aligned u16 load
    // at offset +2 (idx field). Ordering::Acquire pairs with the
    // device's store of used.idx after writing the ring entry per
    // Virtio 1.2 §2.6.8.
    virtio::dma::invalidate_from_device(
        used_va,
        VIRTQ_USED_HEADER_BYTES + rxq_size * VIRTQ_USED_ELEM_BYTES,
    );
    // SAFETY: used.idx is an aligned device-written u16 in the mapped ring.
    let dev_used_idx = unsafe {
        core::ptr::read_volatile((used_va + 2) as *const u16)
    };
    core::sync::atomic::fence(Ordering::Acquire);
    let mut last = s.rx_last_used;
    if dev_used_idx == last { return 0; }

    let mut delivered = 0usize;
    let mut repost_ids: alloc::vec::Vec<u16> = alloc::vec::Vec::new();
    // Collect frame copies under the lock so we can safely drop the
    // lock before invoking cb (cb's TCP-stack path may re-take it via
    // tx_frame when emitting an ACK — UP spinlock self-deadlock).
    let mut frames: alloc::vec::Vec<(alloc::vec::Vec<u8>, net::PacketRxMetadata)> =
        alloc::vec::Vec::new();
    while last != dev_used_idx {
        let slot = (last as usize) % rxq_size;
        // used.ring[slot] = { u32 id; u32 len; } at +4 + slot*8.
        // SAFETY: device populated this slot before bumping used.idx;
        // the Acquire fence above orders the read after the index check.
        let (id, frame_total) = unsafe {
            let base = used_va + 4 + (slot as u64) * 8;
            (
                core::ptr::read_volatile(base as *const u32),
                core::ptr::read_volatile((base + 4) as *const u32),
            )
        };
        last = last.wrapping_add(1);

        let rx_buf = s
            .rx_bufs
            .iter()
            .find(|buf| buf.desc_id as u32 == id)
            .copied();
        if let Some(rx_buf) = rx_buf {
            repost_ids.push(rx_buf.desc_id);
        }
        let descriptor_generation = rx_buf
            .and_then(|buf| runtime.rx_assignments.descriptor(buf.desc_id))
            .map(|generation| generation.load(Ordering::Acquire));
        let assignment_valid = descriptor_generation
            .is_some_and(|posted| completion(
                posted, expected_generation, current_generation,
            ).0);
        if assignment_valid && rx_buf
            .map(|buf| {
                (frame_total as usize) >= VIRTIO_NET_HDR_LEN
                    && (frame_total as usize) <= buf.len as usize
            })
            .unwrap_or(false)
        {
            let rx_buf = rx_buf.expect("rx buffer was validated above");
            let body_len = frame_total as usize - VIRTIO_NET_HDR_LEN;
            let buf_va = hhdm.wrapping_add(rx_buf.pa);
            virtio::dma::invalidate_from_device(buf_va, rx_buf.len as usize);
            // SAFETY: RX buffer is HHDM-mapped, owned by this driver
            // under the virtio-net device-table lock; the device finished writing
            // before publishing used.ring per Virtio 1.2 §2.6.8. Copy
            // out so we can release the lock before cb runs.
            let body = unsafe {
                core::slice::from_raw_parts(
                    (buf_va + VIRTIO_NET_HDR_LEN as u64) as *const u8,
                    body_len,
                )
            };
            let mut virtio_header = [0u8; VIRTIO_NET_HDR_LEN];
            for (index, byte) in virtio_header.iter_mut().enumerate() {
                // SAFETY: validated RX buffer contains the complete header under the device lock.
                *byte = unsafe { core::ptr::read_volatile((buf_va + index as u64) as *const u8) };
            }
            let metadata = metadata::from_header(&virtio_header);
            // Linux rx accounting: count the L2 ethernet frame (the
            // virtio_net_hdr is excluded from rx_bytes). A frame shorter
            // than a minimum ethernet header is a runt → rx_errors; the
            // (id!=0 / oversized) else-branch below is a dropped frame.
            if body_len >= 14 {
                runtime.rx_packets.fetch_add(1, Ordering::Relaxed);
                runtime.rx_bytes.fetch_add(body_len as u64, Ordering::Relaxed);
            } else {
                runtime.rx_errors.fetch_add(1, Ordering::Relaxed);
            }
            frames.push((body.to_vec(), metadata));
            delivered += 1;
        } else {
            // Device wrote a slot we didn't publish, or a frame too
            // short to even hold the virtio_net_hdr, or one larger than
            // the buffer — dropped, not delivered upward.
            runtime.rx_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    s.rx_last_used = last;

    // Re-publish completed descriptor IDs so the device sees fresh slots.
    // avail.ring lives at +4 (u16 entries).
    let mut next_avail = s.rx_next_avail;
    let mut reposted = false;
    for id in repost_ids {
        let pub_slot = (next_avail as usize) % rxq_size;
        let (_, repost_generation) = completion(
            0, expected_generation, current_generation,
        );
        if let Some(generation) = runtime.rx_assignments.descriptor(id) {
            generation.store(repost_generation, Ordering::Release);
        }
        if let Some(rx_buf) = s.rx_bufs.iter().find(|buf| buf.desc_id == id) {
            virtio::dma::invalidate_from_device(
                hhdm.wrapping_add(rx_buf.pa),
                rx_buf.len as usize,
            );
        }
        // SAFETY: HHDM-mapped avail ring, exclusive under the virtio-net device-table lock.
        unsafe {
            core::ptr::write_volatile(
                (avail_va + 4 + (pub_slot as u64) * 2) as *mut u16,
                id,
            );
        }
        next_avail = next_avail.wrapping_add(1);
        reposted = true;
    }
    if reposted {
        core::sync::atomic::fence(Ordering::Release);
        // SAFETY: avail.idx is u16 at +2 of the avail ring frame; HHDM-mapped exclusive under the virtio-net device-table lock; device reads after the fence.
        unsafe {
            core::ptr::write_volatile((avail_va + 2) as *mut u16, next_avail);
        }
        virtio::dma::clean_to_device(
            avail_va,
            VIRTQ_AVAIL_HEADER_BYTES + rxq_size * VIRTQ_AVAIL_ELEM_BYTES,
        );
        core::sync::atomic::fence(Ordering::Release);
        s.rx_next_avail = next_avail;
        // Kick: u16 queue index 0 to the per-queue notify VA. Modern
        // notify is MMIO; the boot probe has already mapped this VA
        // Device-attr (no-cache, no-reorder).
        // SAFETY: rxq.notify_va is Device-attr-mapped during DRIVER_OK; aligned u16 store of the RX queue index.
        unsafe {
            core::ptr::write_volatile(s.rxq.notify_va as *mut u16, s.rxq.index);
        }
    }
    // Drop the device-table lock before invoking cb — cb may call tx_frame
    // (e.g. TCP stack emitting an ACK from deliver_rx) which re-acquires
    // the same lock. UP spinlock would deadlock if we held it here.
    drop(g);
    for (f, metadata) in frames {
        cb(&f, metadata);
    }
    delivered
}
