//! DRM module ABI manifest: state owns device records and ABI constants;
 //! device owns allocation/vblank/master lifetime; objects owns KMS graph setup;
 //! guards owns enter/exit/unplug draining.

extern crate alloc;

#[allow(unused_imports)]
pub(crate) use alloc::alloc::{alloc, alloc_zeroed, dealloc};
#[allow(unused_imports)]
pub(crate) use alloc::vec::Vec;
#[allow(unused_imports)]
pub(crate) use core::alloc::Layout;
#[allow(unused_imports)]
pub(crate) use core::ffi::c_void;
#[allow(unused_imports)]
pub(crate) use core::ptr::{read, write};
#[allow(unused_imports)]
pub(crate) use core::sync::atomic::{AtomicI32, Ordering};
#[allow(unused_imports)]
pub(crate) use sync::{Modules as ModulesLockClass, Spinlock};
#[allow(unused_imports)]
pub(crate) use crate::linux_device::devres;
#[allow(unused_imports)]
pub(crate) use crate::linux_device::types::LinuxDevice;

#[path = "linux_drm_connector.rs"] mod connector;
#[path = "linux_drm_register.rs"] mod register;
#[path = "linux_drm_format.rs"] mod format;
#[path = "linux_drm_mode.rs"] mod mode;
#[path = "linux_drm_dmt.rs"] mod dmt;
#[path = "linux_drm_probe.rs"] mod probe;
#[path = "linux_drm_file.rs"] mod file;
#[path = "linux_drm_ioctl.rs"] mod ioctl;
#[path = "linux_drm_gem.rs"] mod gem;
#[path = "linux_drm_gem_mmap.rs"] mod gem_mmap;
pub(crate) use gem::{object_get, object_put, framebuffer_get, framebuffer_put};
pub(crate) use gem_mmap::{shmem_mapping_frame, shmem_mapping_object, shmem_mapping_size};
#[path = "linux_drm_shadow.rs"] mod shadow;
#[path = "linux_drm_format_helper.rs"] mod format_helper;
#[path = "linux_drm_atomic.rs"] mod atomic;
#[path = "linux_drm_atomic_core.rs"] mod atomic_core;
#[path = "linux_drm_atomic_acquire.rs"] mod atomic_acquire;
#[path = "linux_drm_atomic_check.rs"] mod atomic_check;
#[path = "linux_drm_atomic_helper_check.rs"] mod atomic_helper_check;
#[path = "linux_drm_atomic_prepare.rs"] mod atomic_prepare;
#[path = "linux_drm_atomic_swap.rs"] mod atomic_swap;
#[path = "linux_drm_atomic_commit_setup.rs"] mod atomic_commit_setup;
#[path = "linux_drm_atomic_commit_tail.rs"] mod atomic_commit_tail;
#[path = "linux_drm_crtc_commit.rs"] mod crtc_commit;
#[path = "linux_drm_atomic_helper_commit.rs"] mod atomic_helper_commit;
#[path = "linux_drm_atomic_async.rs"] mod atomic_async;
#[path = "linux_drm_atomic_validate.rs"] mod atomic_validate;
#[path = "linux_drm_atomic_affected.rs"] mod atomic_affected;
#[path = "linux_drm_atomic_routing.rs"] mod atomic_routing;
pub(crate) use atomic_routing::update_connector_routing;
#[path = "linux_drm_atomic_clones.rs"] mod atomic_clones;
pub(crate) use atomic_clones::check_valid_clones;
#[path = "linux_drm_atomic_modeset_check.rs"] mod atomic_modeset_check;
#[path = "linux_drm_atomic_zpos.rs"] mod atomic_zpos;
#[path = "linux_drm_atomic_legacy_plane.rs"] mod atomic_legacy_plane;
#[path = "linux_drm_modeset.rs"] mod modeset;
#[path = "linux_drm_vblank.rs"] mod vblank;
#[path = "linux_drm_vblank_event.rs"] mod vblank_event;
#[path = "linux_drm_edid.rs"] mod edid;
#[path = "linux_drm_edid_owner.rs"] mod edid_owner;
#[path = "linux_drm_edid_read.rs"] mod edid_read;
#[path = "linux_drm_edid_connector.rs"] mod edid_connector;
#[path = "linux_drm_print.rs"] mod print;
#[path = "linux_drm_mode_object_refs.rs"] mod mode_object_refs;
#[path = "linux_drm_atomic_connector.rs"] mod atomic_connector;
#[path = "linux_drm_atomic_crtc.rs"] mod atomic_crtc;
#[path = "linux_drm_properties.rs"] mod properties;
#[path = "linux_drm_client.rs"] mod client;
#[path = "linux_drm_fbdev_client.rs"] mod fbdev_client;
#[path = "linux_drm_damage.rs"] mod damage;
#[path = "linux_drm_state.rs"] mod state;
#[path = "linux_drm_device.rs"] mod device;
#[path = "linux_drm_objects.rs"] mod objects;
#[path = "linux_drm_guards.rs"] mod guards;

pub(crate) use state::*;
pub(crate) use device::{
    __devm_drm_dev_alloc, drm_dev_put, drm_dev_get, drm_vblank_init, claim_primary_master,
    release_primary_master,
};
pub(crate) use device::is_live_device;
pub(crate) use objects::{
    drm_mode_object_add, drm_mode_object_unregister, drm_universal_plane_init,
    drm_plane_cleanup, drm_crtc_init_with_planes, drm_crtc_cleanup, drm_encoder_init,
    drm_encoder_cleanup, drm_mode_config_reset, drmm_mode_config_init, kms_name,
};
pub(crate) use guards::{drm_dev_enter, drm_dev_exit, drm_dev_unplug};

/// Register the DRM core object-lifetime ABI.
/// # C: O(1)
pub fn export_symbols() {
    crate::symtab::export("__devm_drm_dev_alloc", __devm_drm_dev_alloc as *const () as usize, false);
    crate::symtab::export("drm_dev_put", drm_dev_put as *const () as usize, false);
    crate::symtab::export("drm_dev_get", drm_dev_get as *const () as usize, false);
    crate::symtab::export("drm_dev_enter", drm_dev_enter as *const () as usize, false);
    crate::symtab::export("drm_dev_exit", drm_dev_exit as *const () as usize, false);
    crate::symtab::export("drm_dev_unplug", drm_dev_unplug as *const () as usize, false);
    crate::symtab::export("drmm_mode_config_init", drmm_mode_config_init as *const () as usize, false);
    crate::symtab::export("drm_mode_object_add", drm_mode_object_add as *const () as usize, false);
    crate::symtab::export("drm_mode_object_unregister", drm_mode_object_unregister as *const () as usize, false);
    crate::symtab::export("drm_universal_plane_init", drm_universal_plane_init as *const () as usize, false);
    crate::symtab::export("drm_plane_cleanup", drm_plane_cleanup as *const () as usize, false);
    crate::symtab::export("drm_crtc_init_with_planes", drm_crtc_init_with_planes as *const () as usize, false);
    crate::symtab::export("drm_crtc_cleanup", drm_crtc_cleanup as *const () as usize, false);
    crate::symtab::export("drm_encoder_init", drm_encoder_init as *const () as usize, false);
    crate::symtab::export("drm_encoder_cleanup", drm_encoder_cleanup as *const () as usize, false);
    crate::symtab::export("drm_mode_config_reset", drm_mode_config_reset as *const () as usize, false);
    crate::symtab::export("drm_vblank_init", drm_vblank_init as *const () as usize, false);
    connector::export_symbols();
    register::export_symbols();
    format::export_symbols();
    mode::export_symbols(); probe::export_symbols();
    file::export_symbols();
    ioctl::export_symbols();
    gem::export_symbols();
    gem_mmap::export_symbols();
    shadow::export_symbols();
    format_helper::export_symbols();
    atomic::export_symbols();
    atomic_core::export_symbols();
    atomic_acquire::export_symbols();
    atomic_check::export_symbols();
    atomic_helper_check::export_symbols();
    atomic_prepare::export_symbols();
    atomic_swap::export_symbols();
    crtc_commit::export_symbols();
    atomic_commit_setup::export_symbols();
    atomic_commit_tail::export_symbols();
    atomic_helper_commit::export_symbols();
    atomic_async::export_symbols();
    atomic_validate::export_symbols();
    atomic_affected::export_symbols();
    atomic_modeset_check::export_symbols();
    atomic_zpos::export_symbols();
    atomic_legacy_plane::export_symbols();
    modeset::export_symbols();
    vblank::export_symbols();
    vblank_event::export_symbols();
    edid::export_symbols();
    edid_owner::export_symbols();
    edid_read::export_symbols();
    edid_connector::export_symbols();
    print::export_symbols();
    mode_object_refs::export_symbols();
    atomic_connector::export_symbols();
    atomic_crtc::export_symbols();
    properties::export_symbols();
    client::export_symbols();
    fbdev_client::export_symbols();
    damage::export_symbols();
}

#[cfg(test)]
mod tests;
