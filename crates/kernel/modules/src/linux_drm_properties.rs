//! DRM mode-object property attachment and value tracking.

use super::*;
use alloc::vec::Vec;
use sync::{Spinlock, Modules as ModulesLockClass};

const LINUX_EINVAL: i32 = 22;
const DRM_MODE_OBJECT_PROPERTIES_OFF: usize = 8;
const DRM_OBJECT_PROPERTIES_COUNT_OFF: usize = 0;
const DRM_OBJECT_PROPERTIES_PTRS_OFF: usize = 8;
const DRM_OBJECT_PROPERTIES_VALUES_OFF: usize = 520;
const DRM_OBJECT_MAX_PROPERTY: usize = 64;
pub(super) const DRM_PLANE_PROPERTIES_OFF: usize = 192;
pub(super) const DRM_CRTC_PROPERTIES_OFF: usize = 440;
const DRM_PROPERTY_SIZE: usize = 120;
const DRM_PROPERTY_BASE_OFF: usize = 16;
const DRM_PROPERTY_FLAGS_OFF: usize = 48;
const DRM_PROPERTY_NAME_OFF: usize = 52;
const DRM_PROPERTY_DEV_OFF: usize = 96;
const DRM_PROPERTY_HEAD_OFF: usize = 0;
const DRM_PROPERTY_NAME_LEN: usize = 32;
const DRM_MODE_OBJECT_PROPERTY: u32 = 0xb0b0_b0b0;
const DRM_MODE_PROP_IMMUTABLE: u32 = 1 << 2;
const DRM_MODE_PROP_BLOB: u32 = 1 << 4;
const DRM_MODE_PROP_ATOMIC: u32 = 0x8000_0000;
const DRM_MODE_CONFIG_EDID_PROPERTY_OFF: usize = 608;
const DRM_MODE_CONFIG_FB_DAMAGE_CLIPS_OFF: usize = 752;
const DRM_MODE_CONFIG_PROPERTY_LIST_OFF: usize = 408;
const DRM_CONNECTOR_BASE_OFF: usize = 64;
const DRM_PLANE_BASE_OFF: usize = 80;

struct PropertyRecord { dev: usize, ptr: usize, layout: Layout }
static PROPERTIES: Spinlock<Vec<PropertyRecord>, ModulesLockClass> = Spinlock::new(Vec::new());

pub(super) fn export_symbols() {
    crate::symtab::export("drm_object_attach_property", drm_object_attach_property as *const () as usize, false);
    crate::symtab::export("drm_object_property_get_value", drm_object_property_get_value as *const () as usize, false);
    crate::symtab::export("drm_object_property_set_value", drm_object_property_set_value as *const () as usize, false);
    crate::symtab::export("drm_object_property_get_default_value", drm_object_property_get_default_value as *const () as usize, false);
    crate::symtab::export("drm_connector_attach_edid_property", drm_connector_attach_edid_property as *const () as usize, false);
    crate::symtab::export("drm_plane_enable_fb_damage_clips", drm_plane_enable_fb_damage_clips as *const () as usize, false);
}

/// Attach the device's immutable EDID property to one connector. # C: O(N)
pub(super) extern "C" fn drm_connector_attach_edid_property(connector: *mut c_void) {
    if connector.is_null() { return; }
    let dev = unsafe { read(connector.cast::<*mut c_void>()) }; if dev.is_null() { return; }
    let property = unsafe { read(dev.cast::<u8>().add(DRM_MODE_CONFIG_OFF + DRM_MODE_CONFIG_EDID_PROPERTY_OFF).cast::<*mut c_void>()) };
    drm_object_attach_property(unsafe { connector.cast::<u8>().add(DRM_CONNECTOR_BASE_OFF).cast() }, property, 0);
}

/// Attach the device's atomic framebuffer-damage property to one plane. # C: O(N)
pub(super) extern "C" fn drm_plane_enable_fb_damage_clips(plane: *mut c_void) {
    if plane.is_null() { return; }
    let dev = unsafe { read(plane.cast::<*mut c_void>()) }; if dev.is_null() { return; }
    let property = unsafe { read(dev.cast::<u8>().add(DRM_MODE_CONFIG_OFF + DRM_MODE_CONFIG_FB_DAMAGE_CLIPS_OFF).cast::<*mut c_void>()) };
    drm_object_attach_property(unsafe { plane.cast::<u8>().add(DRM_PLANE_BASE_OFF).cast() }, property, 0);
}

/// Create the standard blob properties every Linux KMS device exposes. # C: O(1)
pub(super) fn initialize_standard(dev: *mut c_void) -> bool {
    if dev.is_null() { return false; }
    let edid = create(dev, DRM_MODE_PROP_BLOB | DRM_MODE_PROP_IMMUTABLE, b"EDID");
    let damage = create(dev, DRM_MODE_PROP_BLOB | DRM_MODE_PROP_ATOMIC, b"FB_DAMAGE_CLIPS");
    if edid.is_null() || damage.is_null() { if !edid.is_null() { destroy(dev, edid); } if !damage.is_null() { destroy(dev, damage); } return false; }
    // SAFETY: mode_config property fields are BTF-verified, and both property objects are fully registered.
    unsafe { let config = dev.cast::<u8>().add(DRM_MODE_CONFIG_OFF); write(config.add(DRM_MODE_CONFIG_EDID_PROPERTY_OFF).cast::<*mut u8>(), edid); write(config.add(DRM_MODE_CONFIG_FB_DAMAGE_CLIPS_OFF).cast::<*mut u8>(), damage); }
    true
}

/// Release every property owned by one managed DRM device. # C: O(N_properties)
pub(super) fn release_device(dev: *mut c_void) {
    let mut properties = PROPERTIES.lock(); let mut index = 0;
    while index < properties.len() { if properties[index].dev != dev as usize { index += 1; continue; } let record = properties.remove(index); unsafe { dealloc(record.ptr as *mut u8, record.layout); } }
}

fn create(dev: *mut c_void, flags: u32, name: &[u8]) -> *mut u8 {
    let layout = Layout::from_size_align(DRM_PROPERTY_SIZE, core::mem::align_of::<u64>()).unwrap(); let property = unsafe { alloc_zeroed(layout) };
    if property.is_null() { return property; }
    let rc = super::drm_mode_object_add(dev, unsafe { property.add(DRM_PROPERTY_BASE_OFF).cast() }, DRM_MODE_OBJECT_PROPERTY);
    if rc != 0 { unsafe { dealloc(property, layout); } return core::ptr::null_mut(); }
    // SAFETY: property is a complete BTF-verified drm_property allocation and name fits the fixed field.
    unsafe { write(property.add(DRM_PROPERTY_FLAGS_OFF).cast::<u32>(), flags); write(property.add(DRM_PROPERTY_DEV_OFF).cast::<*mut c_void>(), dev); core::ptr::copy_nonoverlapping(name.as_ptr(), property.add(DRM_PROPERTY_NAME_OFF), name.len()); let config = dev.cast::<u8>().add(DRM_MODE_CONFIG_OFF); let list = config.add(DRM_MODE_CONFIG_PROPERTY_LIST_OFF).cast::<*mut c_void>(); let head = property.add(DRM_PROPERTY_HEAD_OFF).cast::<*mut c_void>(); let tail = *list.add(1); write(head, list.cast()); write(head.add(1), tail); write(tail.cast::<*mut c_void>(), head.cast()); write(list.add(1), head.cast()); }
    PROPERTIES.lock().push(PropertyRecord { dev: dev as usize, ptr: property as usize, layout }); property
}

fn destroy(dev: *mut c_void, property: *mut u8) {
    if property.is_null() { return; }
    super::drm_mode_object_unregister(dev, unsafe { property.add(DRM_PROPERTY_BASE_OFF).cast() });
    let mut properties = PROPERTIES.lock(); if let Some(index) = properties.iter().position(|entry| entry.ptr == property as usize) { let record = properties.remove(index); unsafe { dealloc(record.ptr as *mut u8, record.layout); } }
}

/// Attach one property to a KMS object exactly once, subject to Linux's 64-slot bound. # C: O(N)
pub(super) extern "C" fn drm_object_attach_property(object: *mut c_void, property: *mut c_void, value: u64) {
    if object.is_null() || property.is_null() { return; }
    let owner = unsafe { read(object.cast::<u8>().add(DRM_MODE_OBJECT_PROPERTIES_OFF).cast::<*mut u8>()) };
    if owner.is_null() { return; }
    // SAFETY: `owner` is the object's BTF-verified embedded drm_object_properties record.
    let count = unsafe { read(owner.add(DRM_OBJECT_PROPERTIES_COUNT_OFF).cast::<i32>()) };
    if !(0..DRM_OBJECT_MAX_PROPERTY as i32).contains(&count) { return; }
    let slot = count as usize;
    // SAFETY: slot is strictly within the fixed 64 property/value arrays.
    unsafe { write(owner.add(DRM_OBJECT_PROPERTIES_PTRS_OFF + slot * core::mem::size_of::<*mut c_void>()).cast::<*mut c_void>(), property); write(owner.add(DRM_OBJECT_PROPERTIES_VALUES_OFF + slot * core::mem::size_of::<u64>()).cast::<u64>(), value); write(owner.add(DRM_OBJECT_PROPERTIES_COUNT_OFF).cast::<i32>(), count + 1); }
}

/// Return the current tracked value for one attached property. # C: O(N)
pub(super) extern "C" fn drm_object_property_get_value(object: *mut c_void, property: *mut c_void, out: *mut u64) -> i32 { property_value(object, property, out, false, 0) }

/// Replace the current tracked value for one attached property. # C: O(N)
pub(super) extern "C" fn drm_object_property_set_value(object: *mut c_void, property: *mut c_void, value: u64) -> i32 { property_value(object, property, core::ptr::null_mut(), true, value) }

/// Return the initially attached property value; static properties retain this same store. # C: O(N)
pub(super) extern "C" fn drm_object_property_get_default_value(object: *mut c_void, property: *mut c_void, out: *mut u64) -> i32 { property_value(object, property, out, false, 0) }

fn property_value(object: *mut c_void, property: *mut c_void, out: *mut u64, set: bool, value: u64) -> i32 {
    if object.is_null() || property.is_null() || (!set && out.is_null()) { return -LINUX_EINVAL; }
    let owner = unsafe { read(object.cast::<u8>().add(DRM_MODE_OBJECT_PROPERTIES_OFF).cast::<*mut u8>()) };
    if owner.is_null() { return -LINUX_EINVAL; }
    let count = unsafe { read(owner.add(DRM_OBJECT_PROPERTIES_COUNT_OFF).cast::<i32>()) };
    if !(0..=DRM_OBJECT_MAX_PROPERTY as i32).contains(&count) { return -LINUX_EINVAL; }
    for slot in 0..count as usize {
        let current = unsafe { read(owner.add(DRM_OBJECT_PROPERTIES_PTRS_OFF + slot * core::mem::size_of::<*mut c_void>()).cast::<*mut c_void>()) };
        if current == property {
            let target = unsafe { owner.add(DRM_OBJECT_PROPERTIES_VALUES_OFF + slot * core::mem::size_of::<u64>()).cast::<u64>() };
            if set { unsafe { write(target, value); } } else { unsafe { write(out, read(target)); } }
            return 0;
        }
    }
    -LINUX_EINVAL
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attached_property_tracks_its_value() {
        let mut object = [0u64; 4]; let mut owner = [0u64; 130]; let mut property = 0u64; let mut value = 0;
        unsafe { write(object.as_mut_ptr().cast::<u8>().add(DRM_MODE_OBJECT_PROPERTIES_OFF).cast::<*mut u8>(), owner.as_mut_ptr().cast()); }
        drm_object_attach_property(object.as_mut_ptr().cast(), (&mut property as *mut u64).cast(), 17); assert_eq!(drm_object_property_get_value(object.as_mut_ptr().cast(), (&mut property as *mut u64).cast(), &mut value), 0); assert_eq!(value, 17);
        assert_eq!(drm_object_property_set_value(object.as_mut_ptr().cast(), (&mut property as *mut u64).cast(), 23), 0); assert_eq!(drm_object_property_get_default_value(object.as_mut_ptr().cast(), (&mut property as *mut u64).cast(), &mut value), 0); assert_eq!(value, 23);
    }
}
