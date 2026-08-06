// Modern virtio-net runtime state (arch-neutral). The transport backend brings
// up cap discovery, BAR mapping, queue program, DRIVER_OK, and MSI-X bind; once
// that finishes it hands persistent kernel-side addresses here via
// `init_modern`. Runtime paths consume the stashed state to drive RX-poll, TX, and ARP through
// `crate::net::stack`.
//
// Kept arch-neutral because every operation post-bring-up is MMIO
// (notify_cap window) + HHDM (ring frames). The transport backend already
// speaks both arches, so the runtime side does too.
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

/// Virtio device ID for network cards.
pub const VIRTIO_ID_NET: u16 = 1;

type DeviceKey = virtio::VirtioChildDeviceKey;

/// Driver-model identity for virtio-net child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-net", VIRTIO_ID_NET);

/// Length of the virtio-net packet header preceding each frame in the ring
/// buffer per Virtio 1.2 §5.1.6.1.
const VIRTIO_NET_HDR_LEN: usize = 12;

const WANTED_FEATURES: u64 =
    virtio::VIRTIO_F_VERSION_1 | virtio::VIRTIO_NET_F_MAC | virtio::VIRTIO_NET_F_STATUS;

/// Feature policy for the modern virtio-net child driver. The PCI transport
/// executes the common-cfg negotiation, but the child driver owns which
/// device-specific bits it needs for its runtime model.
/// # C: O(1)
pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

/// Transport contract for the modern virtio-net child driver. The virtio bus
/// consumes this profile; the PCI transport only executes it.
/// # C: O(1)
pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    virtio::VirtioTransportProfile::net(wanted_features(), Some(config_changed))
}

/// Persistent runtime state for one modern virtio-net device. Queue resources
/// reference VAs/PAs already programmed into the device by the transport
/// probe. Identity is the transport-neutral virtio child key; backend-specific
/// coordinates stay in the transport wrapper.
#[derive(Clone)]
pub struct ModernNetState {
    /// Owning virtio child identity supplied by the transport bus.
    pub device_key: DeviceKey,
    pub cfg_va:   u64,
    pub device_cfg_va: u64,
    pub hhdm:     u64,
    /// Features the transport negotiated. `VIRTIO_NET_F_STATUS` decides
    /// whether `virtio_net_config.status` exists to read carrier from.
    pub drv_features: u64,
    pub rxq:      virtio::VirtQueueResource,
    pub txq:      virtio::VirtQueueResource,
    /// RX descriptors posted on queue 0. Each descriptor owns one packet-sized
    /// DMA buffer and is reposted after completion.
    pub rx_bufs:  alloc::vec::Vec<virtio::VirtioNetRxBuffer>,
    /// MAC read from the virtio-net device config at install time.
    pub mac:       [u8; 6],
    /// TX DMA buffer pool, one frame per usable TX descriptor. Element `i`
    /// backs descriptor `i`; `tx_bufs[0]` is the transport-allocated boot
    /// frame, the rest are driver-allocated to form a real ring (Linux
    /// `virtnet` posts across the whole TX ring, not one scratch buffer).
    pub tx_bufs: alloc::vec::Vec<u64>,
    /// TX queue cursor state owned by this device. `tx_next_avail` is the
    /// next avail index to publish; `tx_last_used` is the device `used.idx`
    /// reaped so far. In-flight count = `tx_next_avail - tx_last_used`.
    pub tx_last_used:  u16,
    pub tx_next_avail: u16,
    /// RX queue cursor state owned by this device.
    pub rx_last_used:  u16,
    pub rx_next_avail: u16,
}

mod bh_lock;
use bh_lock::DriverBhLock;

static MODERN_DEVS: DriverBhLock<alloc::vec::Vec<ModernNetState>> =
    DriverBhLock::new(alloc::vec::Vec::new());
static SOFTIRQ_INSTALLED: AtomicBool = AtomicBool::new(false);
static CONFIG_REFRESH_PENDING: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "oxide-kernel")]
static CONFIG_WORK_QUEUED: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "oxide-kernel")]
static CONFIG_RETRY_INSTALLED: AtomicBool = AtomicBool::new(false);
static REGISTERED_NETDEVS: Spinlock<alloc::vec::Vec<(DeviceKey, net::NetIfaceId)>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());

mod state;
pub use state::{
    init_modern,
    init_modern_with_rx_pool,
    read_device_carrier,
    is_modern_present,
    is_modern_present_for,
    mac,
    mac_for,
    modern_state_for,
    registered_ifaces,
    shutdown_modern,
    uninstall_modern,
    registered_iface_for,
};
use state::{remove_registered_iface, set_registered_iface};

mod tx;
pub use tx::{tx_frame_for, TxErr, TxOutcome, TX_MAX_BODY};

mod netdev;
pub use netdev::{register_netdev, unregister_netdev, VirtioNetDev};
#[cfg(test)]
use netdev::{ensure_net_runtime, net_runtime_for, remove_net_runtime, NET_RUNTIMES};

mod rx;
#[cfg(test)]
use rx::set_softirq_ip_for_iface;
pub use rx::{
    install_rx_softirq_handler,
    raise_rx,
    rx_poll_for,
    uninstall_rx_softirq_handler,
};
#[cfg(target_os = "oxide-kernel")]
pub use rx::{poll_into_stack_for, rx_drain_softirq};
use rx::{install_rx_runtime, release_rx_shared_runtime_if_last, remove_rx_runtime_for};
#[cfg(test)]
use rx::{clear_rx_runtime, first_iface_ip_for, set_softirq_iface};

mod neighbor;
use neighbor::link_address_for;

/// Process coalesced configuration changes from a kworker. Linux's
/// `virtnet_config_changed_work` uses this process-context boundary because
/// carrier publication takes RTNL and may sleep.
#[cfg(target_os = "oxide-kernel")]
fn config_refresh_work(_arg: usize) {
    loop {
        if CONFIG_REFRESH_PENDING.swap(false, Ordering::AcqRel) {
            state::refresh_carriers();
        }
        CONFIG_WORK_QUEUED.store(false, Ordering::Release);
        if !CONFIG_REFRESH_PENDING.load(Ordering::Acquire)
            || CONFIG_WORK_QUEUED.compare_exchange(false, true, Ordering::AcqRel,
                Ordering::Acquire).is_err()
        {
            return;
        }
    }
}

/// Queue the coalesced configuration work item. A full bounded workqueue leaves
/// `PENDING` set; the process-context retry timer below claims it later.
#[cfg(target_os = "oxide-kernel")]
fn queue_config_refresh() {
    if CONFIG_WORK_QUEUED.compare_exchange(false, true, Ordering::AcqRel,
        Ordering::Acquire).is_err()
    {
        return;
    }
    if !sched::live::workqueue::queue_work(config_refresh_work, 0) {
        CONFIG_WORK_QUEUED.store(false, Ordering::Release);
    }
}

/// Never-drop retry for the bounded workqueue. Timer callbacks run on
/// `ktimers`, so directly claiming and running this work is legal.
#[cfg(target_os = "oxide-kernel")]
fn config_refresh_retry(_now_ns: u64) {
    if CONFIG_REFRESH_PENDING.load(Ordering::Acquire)
        && CONFIG_WORK_QUEUED.compare_exchange(false, true, Ordering::AcqRel,
            Ordering::Acquire).is_ok()
    {
        config_refresh_work(0);
    }
}

#[cfg(target_os = "oxide-kernel")]
fn ensure_config_refresh_retry() {
    if !CONFIG_RETRY_INSTALLED.swap(true, Ordering::AcqRel) {
        timer::register_periodic(100_000_000, config_refresh_retry);
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn ensure_config_refresh_retry() {}

/// Defer a virtio-net configuration interrupt to process context. Queue zero
/// shares this MSI-X vector, so RX still needs the same bottom-half wake.
/// # C: O(1)
pub fn config_changed() {
    CONFIG_REFRESH_PENDING.store(true, Ordering::Release);
    #[cfg(target_os = "oxide-kernel")]
    queue_config_refresh();
    raise_rx();
}

#[cfg(test)]
mod tests;
