//! Transport-owned resource descriptions handed from a virtio transport to a
//! child driver. These are plain descriptors; ownership and unmapping still
//! live with the transport until every child driver is converted to managed
//! resources.

use alloc::{format, string::String, vec::Vec};

use crate::{ProgrammedQueues, QueueRing};

mod identity;
pub use identity::{
    virtio_child_addr, virtio_child_has_parent, VirtioChildDeviceKey, VirtioChildDriverId,
    VirtioChildModelIdentity, VIRTIO_CHILD_BUS, VIRTIO_CHILD_CLASS, VIRTIO_VENDOR_ID,
};

mod profile;
pub use profile::{
    VirtioChildRequirements, VirtioEarlyPayloadPolicy, VirtioQueuePlan, VirtioTransportProfile,
    VIRTIO_MSI_NO_VECTOR, MAX_RESOURCE_QUEUES,
};

mod handoff;
pub use handoff::{
    build_queue_resources, build_runtime_handoff, resolve_planned_notify_mappings,
    VirtQueueResource, VirtioQueueNotifyMappings, VirtioRuntimeHandoff,
    VirtioRuntimeHandoffInput,
};

mod transport;
pub use transport::{
    VirtioNetBootPayloads, VirtioNetRxBuffer, VirtioResources, VirtioTransportLocation,
    VIRTIO_NET_RX_BOOT_POOL,
};

mod child;
pub use child::{
    push_unique_frame, run_child_probe, run_child_remove, run_child_shutdown,
    VirtioChildProbeFacts, VirtioChildResourceState, VirtioChildTransportSession,
    VirtioProbeLease, VirtioProbeOwnedFrames, VirtioTransportProbeResult,
};

#[cfg(test)]
mod tests;
