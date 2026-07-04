use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::RX_RING_BUFS;

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

struct VsockProbeState {
    device_key: virtio::VirtioChildDeviceKey,
    rx_bufs: [u64; RX_RING_BUFS],
    tx_buf_pa: u64,
    reserved_endpoint: bool,
    owned_frames: bool,
}

impl VsockProbeState {
    fn reserve_and_alloc(device_key: virtio::VirtioChildDeviceKey) -> Option<Self> {
        if !net::vsock::driver_reserve(device_key.raw()) {
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

    fn disarm_frames(&mut self) {
        self.owned_frames = false;
    }

    fn disarm_endpoint(&mut self) {
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
            let _ = net::vsock::driver_cancel_reserved(self.device_key.raw());
        }
    }
}

fn read_guest_cid(resources: virtio::VirtioResources) -> Option<u64> {
    let cfg = resources.device_cfg_va;
    if cfg == 0 {
        return None;
    }
    Some(unsafe { core::ptr::read_volatile(cfg as *const u64) })
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
    if device_key.raw() == 0 || CTX.lock().iter().any(|ctx| ctx.device_key == device_key) {
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
    probe.disarm_frames();
    drop(g);

    crate::rx::prepost_all(device_key);

    if !net::vsock::driver_publish_reserved(device_key.raw(), guest_cid, crate::tx_packet) {
        let _ = uninstall(device_key);
        return false;
    }
    probe.disarm_endpoint();
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
    let endpoint_removed = net::vsock::driver_uninstall(device_key.raw());
    let Some((mut ctx, empty_after)) = remove_ctx(device_key) else {
        return endpoint_removed;
    };
    if empty_after {
        clear_rx_softirq_handler();
    }
    if ctx.cfg_va != 0 {
        unsafe { core::ptr::write_volatile((ctx.cfg_va + 0x14) as *mut u8, 0u8) };
    }
    free_rx_bufs(&mut ctx.rx_bufs);
    if ctx.tx_buf_pa != 0 {
        unsafe { pmm::setup::free_one_frame(ctx.tx_buf_pa); }
    }
    true
}

pub fn shutdown(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let endpoint_quiesced = net::vsock::driver_quiesce(device_key.raw());
    let Some((mut ctx, empty_after)) = remove_ctx(device_key) else {
        return endpoint_quiesced;
    };
    if empty_after {
        clear_rx_softirq_handler();
    }
    if ctx.cfg_va != 0 {
        unsafe { core::ptr::write_volatile((ctx.cfg_va + 0x14) as *mut u8, 0u8) };
    }
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
    guest_cid_for(virtio::VirtioChildDeviceKey::from_raw(net::vsock::driver_owner()))
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

#[cfg(test)]
pub(crate) fn clear_ctxs_for_tests() {
    CTX.lock().clear();
}
