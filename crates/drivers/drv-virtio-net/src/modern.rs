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
    virtio::VirtioTransportProfile::net(wanted_features(), Some(raise_rx))
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
    pub hhdm:     u64,
    pub rxq:      virtio::VirtQueueResource,
    pub txq:      virtio::VirtQueueResource,
    /// RX descriptors posted on queue 0. Each descriptor owns one packet-sized
    /// DMA buffer and is reposted after completion.
    pub rx_bufs:  alloc::vec::Vec<virtio::VirtioNetRxBuffer>,
    /// MAC read from the virtio-net device config at install time.
    pub mac:       [u8; 6],
    /// PA of the boot-allocated TX scratch frame.
    pub tx0_buf_pa: u64,
    /// TX queue cursor state owned by this device.
    pub tx_last_used:  u16,
    pub tx_next_avail: u16,
    /// RX queue cursor state owned by this device.
    pub rx_last_used:  u16,
    pub rx_next_avail: u16,
}

static MODERN_DEVS: Spinlock<alloc::vec::Vec<ModernNetState>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());
static SOFTIRQ_INSTALLED: AtomicBool = AtomicBool::new(false);
static REGISTERED_NETDEVS: Spinlock<alloc::vec::Vec<(DeviceKey, net::NetIfaceId)>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());
static ARP_GC_TIMER_ID: AtomicU64 = AtomicU64::new(0);

mod state;
pub use state::{
    init_modern,
    init_modern_with_rx_pool,
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
use netdev::{ensure_net_runtime, net_runtime_for, remove_net_runtime, NET_RUNTIMES};

mod rx;
#[cfg(test)]
use rx::set_softirq_ip_for_iface;
pub use rx::{
    install_rx_softirq_handler,
    raise_rx,
    register_timers,
    rx_poll_for,
    uninstall_rx_softirq_handler,
    unregister_timers,
};
#[cfg(target_os = "oxide-kernel")]
pub use rx::{poll_into_stack_for, rx_drain_softirq};
use rx::{clear_rx_runtime, first_iface_ip_for, install_rx_runtime,
    release_rx_shared_runtime_if_last, remove_rx_runtime_for, set_softirq_iface};

mod neighbor;
#[cfg(test)]
use neighbor::resolve_next_hop_mac;
use neighbor::resolve_next_hop_mac_observed;
#[cfg(test)]
pub(crate) fn test_solicited_node_multicast(ip: net::Ipv6Addr) -> net::Ipv6Addr {
    neighbor::test_solicited_node_multicast(ip)
}
#[cfg(test)]
pub(crate) fn test_solicited_node_ethernet(ip: net::Ipv6Addr) -> net::MacAddr {
    neighbor::test_solicited_node_ethernet(ip)
}

#[cfg(test)]
mod tests;
