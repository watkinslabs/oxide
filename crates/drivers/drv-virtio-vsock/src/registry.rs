use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{consts::VSOCK_CFG_OFF_GUEST_CID, FRAME_BYTES, RX_RING_BUFS};

/// Per-device ring engine. PAs/VA reference the q0(RX)/q1(TX) rings the
/// boot probe programmed. RX buffers are pre-posted at install; TX uses
/// a single bounce frame serialised by the driver Spinlock.
pub struct Ctx {
    pub device_key: virtio::VirtioChildDeviceKey,
    pub cfg_va: u64,
    pub hhdm: u64,
    pub guest_cid: u64,
    pub rxq: virtio::VirtQueueResource,
    pub txq: virtio::VirtQueueResource,
    pub rx_avail_idx: u16,
    pub rx_used_seen: u16,
    pub rx_bufs: [u64; RX_RING_BUFS],
    pub tx_avail_idx: u16,
    pub tx_used_seen: u16,
    pub tx_buf_pa: u64,
}

pub(crate) static CTX: Spinlock<Vec<Ctx>, DriverLockClass> = Spinlock::new(Vec::new());
pub(crate) static SOFTIRQ_INSTALLED: AtomicBool = AtomicBool::new(false);

fn vsock_owner(device_key: virtio::VirtioChildDeviceKey) -> Option<net::vsock::VsockOwner> {
    net::vsock::VsockOwner::from_raw(device_key.raw())
}

struct VsockProbeState {
    device_key: virtio::VirtioChildDeviceKey,
    rx_bufs: [u64; RX_RING_BUFS],
    tx_buf_pa: u64,
    reserved_endpoint: bool,
    owned_frames: bool,
}

impl VsockProbeState {
    fn reserve_and_alloc(device_key: virtio::VirtioChildDeviceKey) -> Option<Self> {
        let owner = vsock_owner(device_key)?;
        if !net::vsock::driver_reserve(owner) {
            return None;
        }
        let mut state = Self {
            device_key,
            rx_bufs: [0u64; RX_RING_BUFS],
            tx_buf_pa: 0,
            reserved_endpoint: true,
            owned_frames: true,
        };
        for slot in state.rx_bufs.iter_mut() {
            *slot = pmm::setup::alloc_one_frame()?;
        }
        state.tx_buf_pa = pmm::setup::alloc_one_frame()?;
        Some(state)
    }

    fn transfer_frames_to_ctx(&mut self) {
        self.owned_frames = false;
    }

    fn transfer_endpoint_to_net(&mut self) {
        self.reserved_endpoint = false;
    }
}

impl Drop for VsockProbeState {
    fn drop(&mut self) {
        if self.owned_frames {
            free_rx_bufs(&mut self.rx_bufs);
            if self.tx_buf_pa != 0 {
                unsafe { pmm::setup::free_one_frame(self.tx_buf_pa); }
                self.tx_buf_pa = 0;
            }
        }
        if self.reserved_endpoint {
            if let Some(owner) = vsock_owner(self.device_key) {
                let _ = net::vsock::driver_cancel_reserved(owner);
            }
        }
    }
}

fn read_guest_cid(resources: virtio::VirtioResources) -> Option<u64> {
    let cfg = resources.device_cfg_va;
    if cfg == 0 {
        return None;
    }
    // SAFETY: virtio transport supplied a mapped device configuration window and the guest CID field is a le64 at offset zero.
    Some(unsafe { core::ptr::read_volatile((cfg + VSOCK_CFG_OFF_GUEST_CID) as *const u64) })
}

pub fn present() -> bool {
    !CTX.lock().is_empty()
}

pub fn present_for(device_key: virtio::VirtioChildDeviceKey) -> bool {
    CTX.lock().iter().any(|ctx| ctx.device_key == device_key)
}

pub fn install(device_key: virtio::VirtioChildDeviceKey, resources: virtio::VirtioResources) -> bool {
    let Some(rxq) = resources.require_queue(0) else {
        return false;
    };
    let Some(txq) = resources.require_queue(1) else {
        return false;
    };
    if !resources.common_cfg_valid() {
        return false;
    }
    let Some(guest_cid) = read_guest_cid(resources) else {
        return false;
    };
    let Some(owner) = vsock_owner(device_key) else {
        return false;
    };
    if CTX.lock().iter().any(|ctx| ctx.device_key == device_key) {
        return false;
    }
    let mut probe = match VsockProbeState::reserve_and_alloc(device_key) {
        Some(probe) => probe,
        None => return false,
    };

    let rx_used = resources.hhdm.wrapping_add(rxq.device_pa) as *const u16;
    let tx_used = resources.hhdm.wrapping_add(txq.device_pa) as *const u16;
    let (rx_used_seen, tx_used_seen) = unsafe {
        (
            core::ptr::read_volatile(rx_used.add(1)),
            core::ptr::read_volatile(tx_used.add(1)),
        )
    };

    let ctx = Ctx {
        device_key,
        cfg_va: resources.cfg_va,
        hhdm: resources.hhdm,
        guest_cid,
        rxq,
        txq,
        rx_avail_idx: rx_used_seen,
        rx_used_seen,
        rx_bufs: probe.rx_bufs,
        tx_avail_idx: tx_used_seen,
        tx_used_seen,
        tx_buf_pa: probe.tx_buf_pa,
    };
    let mut g = CTX.lock();
    if g.iter().any(|ctx| ctx.device_key == device_key) {
        return false;
    }
    g.push(ctx);
    probe.transfer_frames_to_ctx();
    drop(g);

    crate::rx::prepost_all(device_key);

    if !net::vsock::driver_publish_reserved(owner, guest_cid,
        FRAME_BYTES - net::vsock::VSOCK_HDR_LEN, crate::tx_packet, rx_poll_for_owner) {
        let _ = uninstall(device_key);
        return false;
    }
    probe.transfer_endpoint_to_net();
    if !SOFTIRQ_INSTALLED.swap(true, Ordering::AcqRel) {
        softirq::set_handler(softirq::Slot::VsockRx, rx_drain_softirq);
    }
    true
}

fn free_rx_bufs(rx_bufs: &mut [u64; RX_RING_BUFS]) {
    for pa in rx_bufs.iter_mut() {
        if *pa != 0 {
            unsafe { pmm::setup::free_one_frame(*pa); }
            *pa = 0;
        }
    }
}

pub fn uninstall(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let endpoint_removed = vsock_owner(device_key)
        .map(net::vsock::driver_uninstall)
        .unwrap_or(false);
    let Some((mut ctx, empty_after)) = remove_ctx(device_key) else {
        return endpoint_removed;
    };
    if empty_after {
        clear_rx_softirq_handler();
    }
    virtio::reset_device(ctx.cfg_va);
    free_rx_bufs(&mut ctx.rx_bufs);
    if ctx.tx_buf_pa != 0 {
        unsafe { pmm::setup::free_one_frame(ctx.tx_buf_pa); }
    }
    true
}

pub fn shutdown(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let endpoint_quiesced = vsock_owner(device_key)
        .map(net::vsock::driver_quiesce)
        .unwrap_or(false);
    let Some((mut ctx, empty_after)) = remove_ctx(device_key) else {
        return endpoint_quiesced;
    };
    if empty_after {
        clear_rx_softirq_handler();
    }
    virtio::reset_device(ctx.cfg_va);
    free_rx_bufs(&mut ctx.rx_bufs);
    if ctx.tx_buf_pa != 0 {
        unsafe { pmm::setup::free_one_frame(ctx.tx_buf_pa); }
    }
    true
}

pub(crate) fn remove_ctx(device_key: virtio::VirtioChildDeviceKey) -> Option<(Ctx, bool)> {
    let mut g = CTX.lock();
    let pos = g.iter().position(|ctx| ctx.device_key == device_key)?;
    let ctx = g.remove(pos);
    let empty_after = g.is_empty();
    Some((ctx, empty_after))
}

pub(crate) fn clear_rx_softirq_handler() {
    if SOFTIRQ_INSTALLED.swap(false, Ordering::AcqRel) {
        let _ = softirq::clear_handler(softirq::Slot::VsockRx);
    }
}

pub fn guest_cid_for(device_key: virtio::VirtioChildDeviceKey) -> u64 {
    CTX.lock()
        .iter()
        .find(|ctx| ctx.device_key == device_key)
        .map(|ctx| ctx.guest_cid)
        .unwrap_or(0)
}

pub fn guest_cid() -> u64 {
    net::vsock::driver_owner()
        .map(|owner| guest_cid_for(virtio::VirtioChildDeviceKey::from_raw(owner.raw())))
        .unwrap_or(0)
}

pub fn raise_rx() {
    softirq::raise(softirq::Slot::VsockRx);
}

pub fn rx_drain_softirq() {
    let _ = crate::rx::drain();
}

pub fn rx_drain() -> usize {
    crate::rx::drain()
}

fn rx_poll_for_owner(_owner: net::vsock::VsockOwner) -> usize {
    crate::rx::drain()
}

#[cfg(test)]
fn drain_ctxs_for_tests(mut release: impl FnMut(u64)) {
    let mut contexts = {
        let mut registered = CTX.lock();
        core::mem::take(&mut *registered)
    };
    for context in contexts.iter_mut() {
        for frame in context.rx_bufs.iter_mut() {
            if *frame == 0 { continue; }
            release(*frame);
            *frame = 0;
        }
        if context.tx_buf_pa != 0 {
            release(context.tx_buf_pa);
            context.tx_buf_pa = 0;
        }
    }
}

#[cfg(test)]
pub(crate) fn clear_ctxs_for_tests() {
    drain_ctxs_for_tests(|frame| {
        // SAFETY: drained test context exclusively owns each unpublished queue frame.
        unsafe { pmm::setup::free_one_frame(frame); }
    });
}

#[cfg(test)]
pub(crate) fn clear_ctxs_with_for_tests(release: impl FnMut(u64)) {
    drain_ctxs_for_tests(release);
}

#[cfg(test)]
pub(crate) fn read_guest_cid_from_resources_for_tests(resources: virtio::VirtioResources) -> Option<u64> {
    read_guest_cid(resources)
}

#[cfg(test)]
fn test_queue(index: u16) -> virtio::VirtQueueResource {
    virtio::VirtQueueResource {
        index,
        size: 8,
        desc_pa: 0,
        driver_pa: 0,
        device_pa: 0,
        notify_va: 0,
        notify_off: 0,
    }
}

#[cfg(test)]
fn reserve_endpoint_only_for_tests(device_key: virtio::VirtioChildDeviceKey) -> Option<VsockProbeState> {
    let owner = vsock_owner(device_key)?;
    if !net::vsock::driver_reserve(owner) {
        return None;
    }
    Some(VsockProbeState {
        device_key,
        rx_bufs: [0u64; RX_RING_BUFS],
        tx_buf_pa: 0,
        reserved_endpoint: true,
        owned_frames: false,
    })
}

#[cfg(test)]
pub(crate) fn reserved_probe_drop_releases_endpoint_for_tests(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let Some(owner) = vsock_owner(device_key) else {
        return false;
    };
    {
        let Some(_probe) = reserve_endpoint_only_for_tests(device_key) else {
            return false;
        };
        if net::vsock::driver_up_for(owner) || net::vsock::driver_reserve(owner) {
            return false;
        }
    }
    let reservable = net::vsock::driver_reserve(owner);
    if reservable {
        let _ = net::vsock::driver_cancel_reserved(owner);
    }
    reservable
}

#[cfg(test)]
pub(crate) fn publish_failure_releases_context_and_endpoint_for_tests(
    device_key: virtio::VirtioChildDeviceKey,
    guest_cid: u64,
) -> bool {
    let Some(owner) = vsock_owner(device_key) else {
        return false;
    };
    let mut probe = match reserve_endpoint_only_for_tests(device_key) {
        Some(probe) => probe,
        None => return false,
    };
    CTX.lock().push(Ctx {
        device_key,
        cfg_va: 0,
        hhdm: 0,
        guest_cid,
        rxq: test_queue(0),
        txq: test_queue(1),
        rx_avail_idx: 0,
        rx_used_seen: 0,
        rx_bufs: probe.rx_bufs,
        tx_avail_idx: 0,
        tx_used_seen: 0,
        tx_buf_pa: probe.tx_buf_pa,
    });
    probe.transfer_frames_to_ctx();
    if net::vsock::driver_publish_reserved(owner, guest_cid,
        FRAME_BYTES - net::vsock::VSOCK_HDR_LEN, crate::tx_packet, rx_poll_for_owner) {
        return false;
    }
    let removed = uninstall(device_key);
    drop(probe);
    let reservable = net::vsock::driver_reserve(owner);
    if reservable {
        let _ = net::vsock::driver_cancel_reserved(owner);
    }
    removed && reservable && !present_for(device_key) && !net::vsock::driver_up_for(owner)
}
