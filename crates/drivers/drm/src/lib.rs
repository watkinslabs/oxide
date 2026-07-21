#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod core_api;
mod ids;
mod registry;

pub use core_api::{
    mode_from_rect, ConnectorInfo, CrtcInfo, DrmDriver, EncoderInfo, Error, KResult, PlaneInfo,
    VirtgpuCaps,
};
pub use ids::{
    connector_id_for, connector_idx_of, crtc_id_for, crtc_idx_of, encoder_id_for, encoder_idx_of,
    plane_id_for, plane_idx_of, DRM_CONNECTOR_ID_BASE, DRM_CRTC_ID_BASE, DRM_ENCODER_ID_BASE,
    DRM_PLANE_ID_BASE, DRM_PLANE_ID_END,
};
pub use registry::{
    advertised_cap, alloc_handle, card, card_count, cards, default_cap, is_master_only,
    primary_card, register, register_with_parent, unregister,
};

#[cfg(test)]
pub(crate) static TEST_LOCK: sync::Spinlock<(), sync::TaskList> = sync::Spinlock::new(());

pub mod uapi;
pub use uapi::*;

#[cfg(test)]
mod tests;

pub mod crtc;
pub mod atomic;
pub mod dumb;
pub mod kms_ext;
pub mod modeset;
pub mod node;
