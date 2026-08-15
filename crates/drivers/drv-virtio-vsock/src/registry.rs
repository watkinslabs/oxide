use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{consts::{FRAME_BYTES, VSOCK_CFG_OFF_GUEST_CID}, RX_RING_BUFS};

/// Per-device ring engine. PAs/VA reference the q0(RX)/q1(TX) rings the
/// boot probe programmed. RX buffers are pre-posted at install; TX uses
/// a single bounce frame serialised by the driver Spinlock.
pub struct Ctx {
    pub device_key: virtio::VirtioChildDeviceKey,
    pub bdf: pci::Bdf,
    pub cfg_va: u64,
    pub hhdm: u64,
    pub guest_cid: u64,
    pub rxq: Option<virtio::VirtioSplitQueue>,
    pub txq: Option<virtio::VirtioSplitQueue>,
    pub rx_bufs: [virtio::VirtioDmaFrame; RX_RING_BUFS],
    pub rx_desc_bufs: [u16; RX_RING_BUFS],
    pub tx_buf: virtio::VirtioDmaFrame,
}

pub(crate) static CTX: Spinlock<Vec<Ctx>, DriverLockClass> = Spinlock::new(Vec::new());
/// Bottom-half gate for the completion/drain-softirq-shared lock: real
/// exclusion in the kernel, a no-op under hosted tests. Every acquisition of
/// the lock goes through `lock_bh`, softirq context included — the disable
/// counts and the enable drains only at the outermost level outside IRQ, i.e.
/// the reference `spin_lock_bh` nesting. A bare process-context hold is the
/// one-CPU deadlock B2007/B2008 fixed: the softirq spins on an owner it
/// interrupted.
#[cfg(target_os = "oxide-kernel")]
pub(crate) type VsockBh = sched::bh::SchedBh;
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) type VsockBh = sync::NoopBh;

pub(crate) static SOFTIRQ_INSTALLED: AtomicBool = AtomicBool::new(false);

fn vsock_owner(device_key: virtio::VirtioChildDeviceKey) -> Option<net::vsock::VsockOwner> {
    net::vsock::VsockOwner::from_raw(device_key.raw())
}

struct VsockProbeState {
    device_key: virtio::VirtioChildDeviceKey,
    bdf: pci::Bdf,
    rx_bufs: [virtio::VirtioDmaFrame; RX_RING_BUFS],
    tx_buf: virtio::VirtioDmaFrame,
    reserved_endpoint: bool,
    owned_frames: bool,
}

impl VsockProbeState {
    fn reserve_and_alloc(device_key: virtio::VirtioChildDeviceKey, bdf: pci::Bdf) -> Option<Self> {
        let owner = vsock_owner(device_key)?;
        if !net::vsock::driver_reserve(owner) {
            return None;
        }
        let mut state = Self {
            device_key,
            bdf,
            rx_bufs: [virtio::VirtioDmaFrame::default(); RX_RING_BUFS],
            tx_buf: virtio::VirtioDmaFrame::default(),
            reserved_endpoint: true,
            owned_frames: true,
        };
        for slot in state.rx_bufs.iter_mut() {
            *slot = virtio::allocate_dma_frame(bdf, FRAME_BYTES)?;
        }
        state.tx_buf = virtio::allocate_dma_frame(bdf, FRAME_BYTES)?;
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
            free_rx_bufs(self.bdf, &mut self.rx_bufs);
            let _ = virtio::release_dma_frame(self.bdf, &mut self.tx_buf, FRAME_BYTES);
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
    !CTX.lock_bh::<crate::registry::VsockBh>().is_empty()
}

pub fn present_for(device_key: virtio::VirtioChildDeviceKey) -> bool {
    CTX.lock_bh::<crate::registry::VsockBh>().iter().any(|ctx| ctx.device_key == device_key)
}

pub fn install(device_key: virtio::VirtioChildDeviceKey, bdf: pci::Bdf, resources: virtio::VirtioResources,
    features: u64) -> bool
{
    let Some(rxq) = resources.require_queue_at_least(0, RX_RING_BUFS as u16) else {
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
    if CTX.lock_bh::<crate::registry::VsockBh>().iter().any(|ctx| ctx.device_key == device_key) {
        return false;
    }
    let mut probe = match VsockProbeState::reserve_and_alloc(device_key, bdf) {
        Some(probe) => probe,
        None => return false,
    };

    let Some(rxq) = virtio::VirtioSplitQueue::new_with_features(
        rxq, resources.hhdm, resources.drv_features,
    ).ok() else { return false; };
    let Some(txq) = virtio::VirtioSplitQueue::new_with_features(
        txq, resources.hhdm, resources.drv_features,
    ).ok() else { return false; };

    let ctx = Ctx {
        device_key,
        bdf,
        cfg_va: resources.cfg_va,
        hhdm: resources.hhdm,
        guest_cid,
        rxq: Some(rxq),
        txq: Some(txq),
        rx_bufs: probe.rx_bufs,
        rx_desc_bufs: [u16::MAX; RX_RING_BUFS],
        tx_buf: probe.tx_buf,
    };
    let mut g = CTX.lock_bh::<crate::registry::VsockBh>();
    if g.iter().any(|ctx| ctx.device_key == device_key) {
        return false;
    }
    g.push(ctx);
    probe.transfer_frames_to_ctx();
    drop(g);

    crate::rx::prepost_all(device_key);

    if !net::vsock::driver_publish_reserved(owner, guest_cid, features,
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

fn free_rx_bufs(bdf: pci::Bdf, rx_bufs: &mut [virtio::VirtioDmaFrame; RX_RING_BUFS]) {
    for frame in rx_bufs.iter_mut() {
        let _ = virtio::release_dma_frame(bdf, frame, FRAME_BYTES);
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
    // SAFETY: ctx was removed from the BH registry before this sleepable reset.
    let _ = unsafe { virtio::reset_device_sleepable(ctx.cfg_va) };
    free_rx_bufs(ctx.bdf, &mut ctx.rx_bufs);
    let _ = virtio::release_dma_frame(ctx.bdf, &mut ctx.tx_buf, FRAME_BYTES);
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
    // SAFETY: ctx was removed from the BH registry before this sleepable reset.
    let _ = unsafe { virtio::reset_device_sleepable(ctx.cfg_va) };
    free_rx_bufs(ctx.bdf, &mut ctx.rx_bufs);
    let _ = virtio::release_dma_frame(ctx.bdf, &mut ctx.tx_buf, FRAME_BYTES);
    true
}

pub(crate) fn remove_ctx(device_key: virtio::VirtioChildDeviceKey) -> Option<(Ctx, bool)> {
    let mut g = CTX.lock_bh::<crate::registry::VsockBh>();
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
    CTX.lock_bh::<crate::registry::VsockBh>()
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
        let mut registered = CTX.lock_bh::<crate::registry::VsockBh>();
        core::mem::take(&mut *registered)
    };
    for context in contexts.iter_mut() {
        for frame in context.rx_bufs.iter_mut() {
            if frame.pa == 0 { continue; }
            release(frame.pa);
            *frame = virtio::VirtioDmaFrame::default();
        }
        if context.tx_buf.pa != 0 {
            release(context.tx_buf.pa);
            context.tx_buf = virtio::VirtioDmaFrame::default();
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
fn reserve_endpoint_only_for_tests(device_key: virtio::VirtioChildDeviceKey) -> Option<VsockProbeState> {
    let owner = vsock_owner(device_key)?;
    if !net::vsock::driver_reserve(owner) {
        return None;
    }
    Some(VsockProbeState {
        device_key,
        bdf: pci::Bdf { segment: 0, bus: 0, device: 0, function: 0 },
        rx_bufs: [virtio::VirtioDmaFrame::default(); RX_RING_BUFS],
        tx_buf: virtio::VirtioDmaFrame::default(),
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
    CTX.lock_bh::<crate::registry::VsockBh>().push(Ctx {
        device_key,
        bdf: pci::Bdf { segment: 0, bus: 0, device: 0, function: 0 },
        cfg_va: 0,
        hhdm: 0,
        guest_cid,
        rxq: None,
        txq: None,
        rx_bufs: probe.rx_bufs,
        rx_desc_bufs: [u16::MAX; RX_RING_BUFS],
        tx_buf: probe.tx_buf,
    });
    probe.transfer_frames_to_ctx();
    if net::vsock::driver_publish_reserved(owner, guest_cid, 0,
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
