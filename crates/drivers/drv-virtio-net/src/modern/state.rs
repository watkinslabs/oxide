use super::{DeviceKey, MODERN_DEVS, REGISTERED_NETDEVS};

const NET_CFG_MAC_BYTES: usize = 6;

/// TX ring depth: number of TX descriptors/buffers the driver posts across,
/// capped by the negotiated TX queue size. Linux drives the whole ring; a
/// finite pre-allocated pool matches our boot-allocated DMA model. 32 frames
/// (128 KiB) is ample in-flight depth for line-rate small frames while bounding
/// pinned DMA.
const TX_RING_DEPTH: usize = 32;

/// Build the TX buffer pool. `tx0` is the transport's boot-allocated TX frame
/// (element 0); the remaining `depth-1` frames are driver-allocated to form a
/// real TX ring. Short pools (allocation pressure) still work — a 1-entry pool
/// degrades to the old single-buffer behavior rather than failing.
/// # C: O(depth)
fn build_tx_pool(tx0: u64, txq_size: u16) -> alloc::vec::Vec<u64> {
    let depth = (txq_size as usize).min(TX_RING_DEPTH).max(1);
    let mut bufs = alloc::vec::Vec::with_capacity(depth);
    bufs.push(tx0);
    #[cfg(not(test))]
    for _ in 1..depth {
        match pmm::setup::alloc_raw_frame() {
            Some(pa) if pa != 0 => bufs.push(pa),
            _ => break,
        }
    }
    bufs
}

#[cfg(test)]
static FAIL_NEXT_NETDEV_REGISTRATION: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static TEST_RELEASED_FRAMES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static TEST_RESETS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

fn read_device_mac(resources: virtio::VirtioResources) -> Option<[u8; NET_CFG_MAC_BYTES]> {
    let cfg = resources.device_cfg_va;
    if cfg == 0 {
        return None;
    }
    let mut mac = [0u8; NET_CFG_MAC_BYTES];
    for (i, byte) in mac.iter_mut().enumerate() {
        // SAFETY: `device_cfg_va` is the transport-owned, Device-attr mapped
        // virtio-net config window. The MAC occupies the first six bytes when
        // VIRTIO_NET_F_MAC was negotiated by the transport.
        *byte = unsafe { core::ptr::read_volatile((cfg + i as u64) as *const u8) };
    }
    Some(mac)
}

/// Stash modern virtio-net runtime state for later RX/TX drivers.
/// Returns false if this device key is already installed.
/// # C: O(1)
pub fn init_modern(
    device_key: DeviceKey,
    resources: virtio::VirtioResources,
    rx0_buf_pa: u64,
    rx0_buf_len: u16,
    tx0_buf_pa: u64,
) -> bool {
    let mut rx_bufs = alloc::vec::Vec::new();
    if rx0_buf_pa != 0 && rx0_buf_len != 0 {
        rx_bufs.push(virtio::VirtioNetRxBuffer {
            desc_id: 0,
            pa: rx0_buf_pa,
            len: rx0_buf_len,
        });
    }
    init_modern_with_rx_pool(
        device_key,
        resources,
        rx_bufs,
        tx0_buf_pa,
    )
}

/// Stash modern virtio-net runtime state with a transport-posted RX pool.
/// Returns false if this device key is already installed.
/// # C: O(N_rx_bufs^2)
pub fn init_modern_with_rx_pool(
    device_key: DeviceKey,
    resources: virtio::VirtioResources,
    rx_bufs: alloc::vec::Vec<virtio::VirtioNetRxBuffer>,
    tx0_buf_pa: u64,
) -> bool {
    let Some(rxq) = resources.require_queue(0) else {
        return false;
    };
    let Some(txq) = resources.require_queue(1) else {
        return false;
    };
    let Some(mac) = read_device_mac(resources) else {
        return false;
    };
    if !resources.common_cfg_valid()
        || rx_bufs.is_empty()
        || tx0_buf_pa == 0
    {
        return false;
    }
    if rx_bufs
        .iter()
        .any(|buf| buf.pa == 0 || buf.len == 0 || buf.desc_id >= rxq.size)
    {
        return false;
    }
    for (idx, buf) in rx_bufs.iter().enumerate() {
        if rx_bufs[idx + 1..]
            .iter()
            .any(|other| other.desc_id == buf.desc_id)
        {
            return false;
        }
    }
    let rx_next_avail = rx_bufs.len() as u16;
    let tx_bufs = build_tx_pool(tx0_buf_pa, txq.size);
    // Snapshot loggable scalars before `state` is moved into MODERN_DEVS, so the
    // debug-boot success log below does not borrow the moved value.
    #[cfg(feature = "debug-boot")]
    let log = (device_key, resources.cfg_va, rxq.size, txq.size,
               rxq.notify_va, txq.notify_va, mac);
    let state = super::ModernNetState {
        device_key,
        cfg_va: resources.cfg_va,
        hhdm: resources.hhdm,
        rxq,
        txq,
        rx_bufs,
        mac,
        tx_bufs,
        tx_last_used: 0,
        tx_next_avail: 0,
        rx_last_used: 0,
        rx_next_avail,
    };
    let mut g = MODERN_DEVS.lock();
    if g.iter().any(|installed| installed.device_key == device_key) {
        return false;
    }
    g.push(state);
    drop(g);
    if !register_netdev_after_install(device_key) {
        let _ = uninstall_modern(device_key);
        return false;
    }
    #[cfg(feature = "debug-boot")]
    {
        let (dk, cfg_va, rxq_size, txq_size, rxq_notify, txq_notify, mac) = log;
        klog::write_raw(b"[INFO]  virtio-net-modern key=");
        klog::write_hex_u64(dk.raw() as u64);
        klog::write_raw(b" cfg_va=");
        klog::write_hex_u64(cfg_va);
        klog::write_raw(b" rxq_size=");
        klog::write_dec_u64(rxq_size as u64);
        klog::write_raw(b" txq_size=");
        klog::write_dec_u64(txq_size as u64);
        klog::write_raw(b" rxq_notify_va=");
        klog::write_hex_u64(rxq_notify);
        klog::write_raw(b" txq_notify_va=");
        klog::write_hex_u64(txq_notify);
        klog::write_raw(b" mac=");
        for (i, b) in mac.iter().enumerate() {
            klog::write_hex_u64(*b as u64);
            if i < 5 { klog::write_raw(b":"); }
        }
        klog::write_raw(b"\n");
    }
    true
}

#[cfg(target_os = "oxide-kernel")]
fn register_netdev_after_install(device_key: DeviceKey) -> bool {
    super::netdev::register_netdev(device_key).is_some()
}

#[cfg(all(not(target_os = "oxide-kernel"), not(test)))]
fn register_netdev_after_install(_device_key: DeviceKey) -> bool { true }

#[cfg(test)]
fn register_netdev_after_install(device_key: DeviceKey) -> bool {
    let _ = device_key;
    if FAIL_NEXT_NETDEV_REGISTRATION.swap(false, core::sync::atomic::Ordering::AcqRel) {
        return false;
    }
    true
}

#[cfg(test)]
pub(crate) fn fail_next_netdev_registration() {
    FAIL_NEXT_NETDEV_REGISTRATION.store(true, core::sync::atomic::Ordering::Release);
}

#[cfg(test)]
pub(crate) fn clear_test_released_frames() {
    TEST_RELEASED_FRAMES.store(0, core::sync::atomic::Ordering::Release);
    TEST_RESETS.store(0, core::sync::atomic::Ordering::Release);
}

#[cfg(test)]
pub(crate) fn test_released_frames() -> u64 {
    TEST_RELEASED_FRAMES.load(core::sync::atomic::Ordering::Acquire)
}

#[cfg(test)]
pub(crate) fn test_resets() -> u64 {
    TEST_RESETS.load(core::sync::atomic::Ordering::Acquire)
}

/// Remove the installed modern virtio-net transport. This owns netdev
/// unregistration, RX bottom-half lifetime, and the queue/device state it
/// drains.
/// # C: O(NCPU)
pub fn uninstall_modern(device_key: DeviceKey) -> bool {
    let iface_published = registered_iface_for(device_key).is_some();
    if iface_published && !super::netdev::unregister_netdev(device_key) { return false; }
    let registered_removed = remove_registered_iface(device_key).is_some();
    let runtime_removed = super::netdev::remove_net_runtime(device_key).is_some();
    let rx_runtime_empty_after = super::rx::remove_rx_runtime_for(device_key);
    let rx_runtime_removed = rx_runtime_empty_after.is_some();
    let (state, last_device) = {
        let mut guard = MODERN_DEVS.lock();
        let pos = guard.iter().position(|state| state.device_key == device_key);
        match pos {
            Some(pos) => {
                let state = guard.remove(pos);
                (Some(state), guard.is_empty())
            }
            None => (None, false),
        }
    };
    let state = match state {
        Some(state) => state,
        None => {
            super::rx::release_rx_shared_runtime_if_last(rx_runtime_empty_after.unwrap_or(false));
            return registered_removed || runtime_removed || rx_runtime_removed;
        }
    };
    if last_device {
        super::rx::release_rx_shared_runtime_if_last(rx_runtime_empty_after.unwrap_or_else(super::rx::rx_runtime_empty));
    }
    reset_transport(state.cfg_va);
    for rx_buf in state.rx_bufs {
        free_frame(rx_buf.pa);
    }
    for tx_pa in state.tx_bufs {
        free_frame(tx_pa);
    }
    true
}

/// Quiesce the installed modern virtio-net transport for system shutdown.
///
/// This is terminal driver shutdown, not hot-remove: keep the netdev identity
/// published so model-visible state is not torn down underneath late callers,
/// but make TX/RX paths fail closed and stop all device/runtime activity.
/// # C: O(NCPU)
pub fn shutdown_modern(device_key: DeviceKey) -> bool {
    let rx_runtime_empty_after = super::rx::remove_rx_runtime_for(device_key);
    let (state, last_device) = {
        let mut guard = MODERN_DEVS.lock();
        let pos = guard.iter().position(|state| state.device_key == device_key);
        match pos {
            Some(pos) => {
                let state = guard.remove(pos);
                (Some(state), guard.is_empty())
            }
            None => (None, false),
        }
    };
    let state = match state {
        Some(state) => state,
        None => {
            super::rx::release_rx_shared_runtime_if_last(rx_runtime_empty_after.unwrap_or(false));
            return rx_runtime_empty_after.is_some();
        }
    };
    if last_device {
        super::rx::release_rx_shared_runtime_if_last(rx_runtime_empty_after.unwrap_or_else(super::rx::rx_runtime_empty));
    }
    reset_transport(state.cfg_va);
    for rx_buf in state.rx_bufs {
        free_frame(rx_buf.pa);
    }
    for tx_pa in state.tx_bufs {
        free_frame(tx_pa);
    }
    true
}

fn free_frame(pa: u64) {
    if pa != 0 {
        #[cfg(test)]
        {
            TEST_RELEASED_FRAMES.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            return;
        }
        #[cfg(not(test))]
        {
        // SAFETY: non-zero PAs passed here are pages allocated by the PMM for
        // this driver's payload buffers and are no longer reachable after
        // reset. Vring frames are transport-owned after successful probe and
        // are released when the transport is unpublished.
        unsafe { pmm::setup::free_one_frame(pa); }
        }
    }
}

#[cfg(test)]
fn reset_transport(_cfg_va: u64) {
    TEST_RESETS.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
}

#[cfg(not(test))]
fn reset_transport(cfg_va: u64) {
    let _ = virtio::reset_device(cfg_va);
}

/// Remember the net stack ifindex registered for this transport.
/// # C: O(1)
pub(super) fn set_registered_iface(device_key: DeviceKey, id: net::NetIfaceId) {
    let mut registered = REGISTERED_NETDEVS.lock();
    if let Some((_, iface)) = registered
        .iter_mut()
        .find(|(registered_key, _)| *registered_key == device_key)
    {
        *iface = id;
        return;
    }
    registered.push((device_key, id));
}

/// Snapshot of every registered virtio-net device and its net stack ifindex.
/// # C: O(N)
pub fn registered_ifaces() -> alloc::vec::Vec<(DeviceKey, net::NetIfaceId)> {
    REGISTERED_NETDEVS.lock().clone()
}

/// Registered ifindex for the named device key, if it owns the published netdev.
/// # C: O(1)
pub fn registered_iface_for(device_key: DeviceKey) -> Option<net::NetIfaceId> {
    REGISTERED_NETDEVS
        .lock()
        .iter()
        .find(|(registered_key, _)| *registered_key == device_key)
        .map(|(_, iface)| *iface)
}

pub(super) fn remove_registered_iface(device_key: DeviceKey) -> Option<net::NetIfaceId> {
    let mut registered = REGISTERED_NETDEVS.lock();
    let pos = registered
        .iter()
        .position(|(registered_key, _)| *registered_key == device_key)?;
    Some(registered.remove(pos).1)
}

/// Read-only accessor for the device MAC. Returns `None` until
/// `init_modern` has installed at least one device.
/// # C: O(N devices) under device-table lock
pub fn mac() -> Option<[u8; 6]> {
    MODERN_DEVS
        .lock()
        .iter()
        .next()
        .map(|state| state.mac)
}

/// Read-only accessor for one device MAC.
/// # C: O(N devices) under device-table lock
pub fn mac_for(device_key: DeviceKey) -> Option<[u8; 6]> {
    MODERN_DEVS
        .lock()
        .iter()
        .find(|state| state.device_key == device_key)
        .map(|state| state.mac)
}

/// Snapshot of the named modern device, if installed.
/// # C: O(N devices)
pub fn modern_state_for(device_key: DeviceKey) -> Option<super::ModernNetState> {
    MODERN_DEVS
        .lock()
        .iter()
        .find(|state| state.device_key == device_key)
        .cloned()
}

/// True once `init_modern` has been called with a valid state.
/// # C: O(1)
pub fn is_modern_present() -> bool { !MODERN_DEVS.lock().is_empty() }

/// True iff the named virtio-net transport owns the installed runtime state.
/// # C: O(1)
pub fn is_modern_present_for(device_key: DeviceKey) -> bool {
    modern_state_for(device_key).is_some()
}
