//! DRM mode-object property attachment and value tracking.

use super::*;

const LINUX_EINVAL: i32 = 22;
const DRM_MODE_OBJECT_PROPERTIES_OFF: usize = 8;
const DRM_OBJECT_PROPERTIES_COUNT_OFF: usize = 0;
const DRM_OBJECT_PROPERTIES_PTRS_OFF: usize = 8;
const DRM_OBJECT_PROPERTIES_VALUES_OFF: usize = 520;
const DRM_OBJECT_MAX_PROPERTY: usize = 64;
pub(super) const DRM_PLANE_PROPERTIES_OFF: usize = 192;
pub(super) const DRM_CRTC_PROPERTIES_OFF: usize = 440;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_object_attach_property", drm_object_attach_property as *const () as usize, false);
    crate::symtab::export("drm_object_property_get_value", drm_object_property_get_value as *const () as usize, false);
    crate::symtab::export("drm_object_property_set_value", drm_object_property_set_value as *const () as usize, false);
    crate::symtab::export("drm_object_property_get_default_value", drm_object_property_get_default_value as *const () as usize, false);
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
