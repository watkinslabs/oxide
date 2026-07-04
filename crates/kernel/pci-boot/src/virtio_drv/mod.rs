// Modern virtio-pci transport bring-up. Split from pci_boot/mod.rs.
// klog calls gated under debug_boot! per R06.

use super::virtio_transport::{
    alloc_net_tx_boot_buffer, bind_msix_vector, disable_pci_command, kick_queue_notify,
    post_net_rx_boot_buffer, program_queue_set, publish_transport_record, read_queue_used_idx,
    release_failed_probe, release_msix_bindings, unpublish_transport_record, MsixBinding,
    NetRxBootBuffer, ProgrammedQueues, QueueRing, TransportMappings,
};
use alloc::sync::Arc;
use alloc::vec::Vec;

mod address;
mod driver;
mod probe;
mod runtime;

pub(super) use driver::{register_model_drivers, VirtioPciTransport};
pub(super) use probe::{VirtioPciProbeTrace, VirtioProbe};
