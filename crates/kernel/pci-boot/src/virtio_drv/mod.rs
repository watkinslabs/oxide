// Modern virtio-pci transport bring-up. Split from pci_boot/mod.rs.
// klog calls gated under debug_boot! per R06.

use super::virtio_transport::{
    alloc_net_tx_boot_buffer, bind_msix_vector, disable_pci_command, kick_queue_notify,
    post_net_rx_boot_buffer, program_queue_set, read_queue_used_idx, unpublish_transport_record,
    unpublish_transport_record_by_bdf, MsixBinding, NetRxBootBuffer, ProgrammedQueues, QueueRing,
    TransportMappings, VirtioProbeDevres, VIRTIO_PCI_PAGE_BASE_MASK, restore_pci_command,
    unmask_msix_bindings,
};
use alloc::sync::Arc;
use alloc::vec::Vec;

mod address;
mod driver;
mod probe;
mod probe_state;
mod runtime;

pub(super) use driver::{register_model_drivers, VirtioPciTransport};
pub(super) use probe::VirtioProbe;
#[cfg(feature = "debug-boot")]
pub(super) use probe::VirtioPciProbeTrace;
