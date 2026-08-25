use alloc::alloc::{alloc, alloc_zeroed, dealloc};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ffi::c_void;
use core::ptr::write;
use super::{connector, modeset, properties};
use super::device::is_live_device;
use super::state::*;

/// Initialize the KMS mode-object lists embedded in a managed DRM device. # C: O(1)
pub(crate) extern "C" fn drmm_mode_config_init(dev: *mut c_void) -> i32 {
    if !is_live_device(dev) { return -LINUX_ENODEV; }
    {
        let mut devices = DEVICES.lock();
        let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return -LINUX_ENODEV; };
        if rec.mode_config || rec.dev.saturating_sub(rec.base).saturating_add(DRM_DEVICE_SIZE) > rec.layout.size() { return -LINUX_EBUSY; }
        rec.mode_config = true;
    }
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: dev is a live allocation initialized with a full embedded drm_device layout;
    // every offset names one aligned list_head within its mode_config subobject.
    unsafe {
        for off in MODE_CONFIG_LISTS {
            let head = config.add(off).cast::<*mut c_void>();
            write(head, head.cast());
            write(head.add(1), head.cast());
        }
    }
    modeset::drm_modeset_lock_init(config.wrapping_add(32).cast());
    if properties::initialize_standard(dev) { 0 } else { -LINUX_EBUSY }
}

/// Allocate and publish a KMS object identifier in one device's mode configuration. # C: O(N_objects)
pub(crate) extern "C" fn drm_mode_object_add(dev: *mut c_void, object: *mut c_void, obj_type: u32) -> i32 {
    if object.is_null() { return -LINUX_ENODEV; }
    let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) else { return -LINUX_ENODEV; };
    if rec.objects.iter().any(|entry| entry.ptr == object as usize) { return -LINUX_EBUSY; }
    let mut id = 1u32;
    while rec.objects.iter().any(|entry| entry.id == id) {
        let Some(next) = id.checked_add(1) else { return -LINUX_EBUSY; };
        id = next;
    }
    // SAFETY: caller provides a mutable drm_mode_object; its id and type are the two
    // leading u32 ABI fields and are published while the device object owner is locked.
    unsafe {
        write(object.cast::<u8>().add(DRM_MODE_OBJECT_ID_OFF).cast::<u32>(), id);
        write(object.cast::<u8>().add(DRM_MODE_OBJECT_TYPE_OFF).cast::<u32>(), obj_type);
    }
    rec.objects.push(ModeObjectRecord { ptr: object as usize, id });
    0
}

/// Withdraw a KMS object identifier; repeated withdrawal is a no-op. # C: O(N_objects)
pub(crate) extern "C" fn drm_mode_object_unregister(dev: *mut c_void, object: *mut c_void) {
    if object.is_null() { return; }
    let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return; };
    let Some(pos) = rec.objects.iter().position(|entry| entry.ptr == object as usize) else { return; };
    let entry = rec.objects.remove(pos);
    // SAFETY: object was the exact live ABI object recorded by drm_mode_object_add.
    unsafe {
        let id = object.cast::<u8>().add(DRM_MODE_OBJECT_ID_OFF).cast::<u32>();
        if *id == entry.id { write(id, 0); }
    }
}

/// Initialize a universal plane and attach it to the managed mode-config graph. # C: O(N_planes + formats)
pub(crate) unsafe extern "C" fn drm_universal_plane_init(
    dev: *mut c_void, plane: *mut c_void, possible_crtcs: u32, funcs: *const c_void,
    formats: *const u32, format_count: u32, _modifiers: *const u64, plane_type: i32,
    _name: *const core::ffi::c_char, mut _args: ...,
) -> i32 {
    if plane.is_null() || formats.is_null() || format_count == 0 || format_count > 64 { return -LINUX_ENODEV; }
    let layout = match Layout::array::<u32>(format_count as usize) { Ok(v) => v, Err(_) => return -LINUX_EBUSY };
    // SAFETY: layout describes exactly format_count u32 entries and formats is a caller-owned ABI array.
    let copied = unsafe { alloc(layout) };
    if copied.is_null() { return -LINUX_EBUSY; }
    // SAFETY: copied covers format_count u32 values and formats identifies the input array required by the ABI.
    unsafe { core::ptr::copy_nonoverlapping(formats, copied.cast::<u32>(), format_count as usize); }
    // SAFETY: plane was null-checked above and DRM_PLANE_BASE_OFF is the verified offset
    // of its embedded drm_mode_object.
    let base = unsafe { plane.cast::<u8>().add(DRM_PLANE_BASE_OFF).cast() };
    let object_result = drm_mode_object_add(dev, base, DRM_MODE_OBJECT_PLANE);
    if object_result != 0 {
        // SAFETY: copied has not been published and is released with the allocation layout above.
        unsafe { dealloc(copied, layout); }
        return object_result;
    }
    let mut devices = DEVICES.lock();
    // SAFETY: copied/layout is this call's own format-table allocation, not yet stored in
    // any PlaneRecord, freed here because no live device record matched.
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) else { unsafe { dealloc(copied, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_ENODEV; };
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: the object was accepted by drm_mode_object_add and every plane/config offset is verified ABI layout.
    let index = unsafe { *(config.add(MODE_CONFIG_NUM_TOTAL_PLANE_OFF).cast::<i32>()) };
    // SAFETY: as above, copied/layout is the unpublished format-table allocation freed here
    // because the total-plane count exceeded the object limit.
    if index >= MAX_KMS_OBJECTS { unsafe { dealloc(copied, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_EBUSY; }
    // SAFETY: rec confirms a live, mode_config-initialized device under the DEVICES lock;
    // every plane/config field written below is a verified ABI offset.
    unsafe {
        let head = plane.cast::<u8>().add(DRM_PLANE_HEAD_OFF).cast::<*mut c_void>(); let list = config.add(MODE_CONFIG_PLANE_LIST_OFF).cast::<*mut c_void>(); let tail = *list.add(1);
        write(head, list.cast()); write(head.add(1), tail); write(tail as *mut *mut c_void, head.cast()); write(list.add(1), head.cast()); write(plane.cast::<u8>().cast::<*mut c_void>(), dev);
        write(plane.cast::<u8>().add(DRM_PLANE_BASE_OFF + 8).cast::<*mut u8>(), plane.cast::<u8>().add(properties::DRM_PLANE_PROPERTIES_OFF)); write(plane.cast::<u8>().add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>(), possible_crtcs); write(plane.cast::<u8>().add(DRM_PLANE_FORMATS_OFF).cast::<*mut u32>(), copied.cast()); write(plane.cast::<u8>().add(DRM_PLANE_FORMAT_COUNT_OFF).cast::<u32>(), format_count);
        write(plane.cast::<u8>().add(DRM_PLANE_FUNCS_OFF).cast::<*const c_void>(), funcs); write(plane.cast::<u8>().add(DRM_PLANE_TYPE_OFF).cast::<i32>(), plane_type); write(plane.cast::<u8>().add(DRM_PLANE_INDEX_OFF).cast::<u32>(), index as u32); write(config.add(MODE_CONFIG_NUM_TOTAL_PLANE_OFF).cast::<i32>(), index + 1);
    }
    modeset::drm_modeset_lock_init(plane.cast::<u8>().wrapping_add(32).cast());
    rec.planes.push(PlaneRecord { ptr: plane as usize, formats: copied as usize, layout });
    0
}

/// Detach a universal plane and release its copied format table. # C: O(N_planes + N_objects)
pub(crate) extern "C" fn drm_plane_cleanup(plane: *mut c_void) {
    if plane.is_null() { return; }
    // SAFETY: plane is caller-checked non-null; offset 0 holds the device back-pointer
    // drm_universal_plane_init wrote at init time.
    let dev = unsafe { *(plane.cast::<*mut c_void>()) };
    let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return; };
    let Some(pos) = rec.planes.iter().position(|entry| entry.ptr == plane as usize) else { return; };
    let entry = rec.planes.remove(pos);
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: entry is the exact live plane record; its list links and counter share this device lock.
    unsafe {
        let head = plane.cast::<u8>().add(DRM_PLANE_HEAD_OFF).cast::<*mut c_void>();
        let next = *head; let prev = *head.add(1);
        write(prev.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), prev);
        write(head, head.cast()); write(head.add(1), head.cast());
        let count = config.add(MODE_CONFIG_NUM_TOTAL_PLANE_OFF).cast::<i32>();
        if *count > 0 { write(count, *count - 1); }
        write(plane.cast::<*mut c_void>(), core::ptr::null_mut());
        dealloc(entry.formats as *mut u8, entry.layout);
    }
    drop(devices);
    // SAFETY: plane remains a valid caller-owned allocation after cleanup; DRM_PLANE_BASE_OFF
    // is the verified embedded mode-object offset unregistered next.
    drm_mode_object_unregister(dev, unsafe { plane.cast::<u8>().add(DRM_PLANE_BASE_OFF).cast() });
}

pub(crate) fn kms_name(prefix: &[u8], index: i32) -> Option<(usize, Layout)> {
    let layout = Layout::array::<u8>(prefix.len() + 11).ok()?;
    // SAFETY: layout holds the supplied prefix, ten decimal digits and a terminator.
    let name = unsafe { alloc_zeroed(layout) };
    if name.is_null() { return None; }
    // SAFETY: name has room for the complete bounded decimal representation and terminator.
    unsafe { core::ptr::copy_nonoverlapping(prefix.as_ptr(), name, prefix.len()); let mut value = index as u32; let mut digits = [0u8; 10]; let mut len = 1; digits[0] = b'0' + (value % 10) as u8; while value >= 10 { value /= 10; digits[len] = b'0' + (value % 10) as u8; len += 1; } for pos in 0..len { *name.add(prefix.len() + pos) = digits[len - pos - 1]; } }
    Some((name as usize, layout))
}

/// Initialize one CRTC and attach its legacy planes to the managed KMS graph. # C: O(N_crtcs + N_objects)
pub(crate) unsafe extern "C" fn drm_crtc_init_with_planes(
    dev: *mut c_void, crtc: *mut c_void, primary: *mut c_void, cursor: *mut c_void,
    funcs: *const c_void, _name: *const core::ffi::c_char, mut _args: ...,
) -> i32 {
    if crtc.is_null() || funcs.is_null() { return -LINUX_EINVAL; }
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: the live-device check above confirms mode_config is initialized before this
    // read of config's verified crtc-count field.
    let index = { let devices = DEVICES.lock(); if !devices.iter().any(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) { return -LINUX_ENODEV; } unsafe { *(config.add(MODE_CONFIG_NUM_CRTC_OFF).cast::<i32>()) } };
    if index >= MAX_KMS_OBJECTS { return -LINUX_EINVAL; }
    let Some((name, layout)) = kms_name(b"crtc-", index) else { return -LINUX_EBUSY; };
    // SAFETY: crtc was null-checked above and DRM_CRTC_BASE_OFF is the verified offset
    // of its embedded drm_mode_object.
    let base = unsafe { crtc.cast::<u8>().add(DRM_CRTC_BASE_OFF).cast() };
    let object_result = drm_mode_object_add(dev, base, DRM_MODE_OBJECT_CRTC);
    // SAFETY: object registration failed so name/layout was never linked into any record;
    // this is the allocation's sole owner freeing it.
    if object_result != 0 { unsafe { dealloc(name as *mut u8, layout); } return object_result; }
    let mut devices = DEVICES.lock();
    // SAFETY: name/layout is this call's own kms_name allocation, not yet stored in any
    // CrtcRecord, freed here because no live device record matched.
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) else { unsafe { dealloc(name as *mut u8, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_ENODEV; };
    // SAFETY: config is the live device's embedded mode_config subobject and
    // MODE_CONFIG_NUM_CRTC_OFF is verified within DRM_DEVICE_SIZE, read while DEVICES is locked.
    let index = unsafe { *(config.add(MODE_CONFIG_NUM_CRTC_OFF).cast::<i32>()) };
    // SAFETY: as above, name/layout is the unpublished kms_name allocation freed here because
    // the total-crtc count exceeded the object limit.
    if index >= MAX_KMS_OBJECTS { unsafe { dealloc(name as *mut u8, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_EINVAL; }
    // SAFETY: crtc, its optional plane objects, and the mode-config graph use the verified ABI offsets; all mutations are serialized by DEVICES.
    unsafe {
        let head = crtc.cast::<u8>().add(DRM_CRTC_HEAD_OFF).cast::<*mut c_void>(); let list = config.add(MODE_CONFIG_CRTC_LIST_OFF).cast::<*mut c_void>(); let tail = *list.add(1);
        write(head, list.cast()); write(head.add(1), tail); write(tail as *mut *mut c_void, head.cast()); write(list.add(1), head.cast()); write(crtc.cast::<*mut c_void>(), dev); write(crtc.cast::<u8>().add(DRM_CRTC_BASE_OFF + 8).cast::<*mut u8>(), crtc.cast::<u8>().add(properties::DRM_CRTC_PROPERTIES_OFF)); write(crtc.cast::<u8>().add(32).cast::<*mut u8>(), name as *mut u8); write(crtc.cast::<u8>().add(DRM_CRTC_FUNCS_OFF).cast::<*const c_void>(), funcs); write(crtc.cast::<u8>().add(DRM_CRTC_PRIMARY_OFF).cast::<*mut c_void>(), primary); write(crtc.cast::<u8>().add(DRM_CRTC_CURSOR_OFF).cast::<*mut c_void>(), cursor); write(crtc.cast::<u8>().add(DRM_CRTC_INDEX_OFF).cast::<u32>(), index as u32); let commits = crtc.cast::<u8>().add(DRM_CRTC_COMMIT_LIST_OFF); write(commits.cast::<*mut u8>(), commits); write(commits.add(core::mem::size_of::<*mut u8>()).cast::<*mut u8>(), commits); write(crtc.cast::<u8>().add(DRM_CRTC_COMMIT_LOCK_OFF).cast::<u32>(), 0); write(config.add(MODE_CONFIG_NUM_CRTC_OFF).cast::<i32>(), index + 1);
        if !primary.is_null() && *(primary.cast::<u8>().add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>()) == 0 { write(primary.cast::<u8>().add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>(), 1u32 << index); }
        if !cursor.is_null() && *(cursor.cast::<u8>().add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>()) == 0 { write(cursor.cast::<u8>().add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>(), 1u32 << index); }
    }
    modeset::drm_modeset_lock_init(crtc.cast::<u8>().wrapping_add(40).cast());
    rec.crtcs.push(CrtcRecord { ptr: crtc as usize, name, layout });
    0
}

/// Detach a CRTC from its device mode graph and release its core-owned name. # C: O(N_crtcs + N_objects)
pub(crate) extern "C" fn drm_crtc_cleanup(crtc: *mut c_void) {
    if crtc.is_null() { return; }
    // SAFETY: crtc is caller-checked non-null; offset 0 holds the device back-pointer
    // drm_crtc_init_with_planes wrote at init time.
    let dev = unsafe { *(crtc.cast::<*mut c_void>()) }; let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return; };
    let Some(pos) = rec.crtcs.iter().position(|entry| entry.ptr == crtc as usize) else { return; }; let entry = rec.crtcs.remove(pos); let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: entry is the exact CRTC owned by this device, including its linked list node and allocated name.
    unsafe { let head = crtc.cast::<u8>().add(DRM_CRTC_HEAD_OFF).cast::<*mut c_void>(); let next = *head; let prev = *head.add(1); write(prev.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), prev); let count = config.add(MODE_CONFIG_NUM_CRTC_OFF).cast::<i32>(); if *count > 0 { write(count, *count - 1); } core::ptr::write_bytes(crtc.cast::<u8>(), 0, DRM_CRTC_FUNCS_OFF + core::mem::size_of::<*const c_void>()); dealloc(entry.name as *mut u8, entry.layout); }
    // SAFETY: crtc remains a valid caller-owned allocation after cleanup; DRM_CRTC_BASE_OFF
    // is the verified embedded mode-object offset unregistered next.
    drop(devices); drm_mode_object_unregister(dev, unsafe { crtc.cast::<u8>().add(DRM_CRTC_BASE_OFF).cast() });
}

/// Initialize one encoder and attach it to the managed KMS object graph. # C: O(N_encoders + N_objects)
pub(crate) unsafe extern "C" fn drm_encoder_init(dev: *mut c_void, encoder: *mut c_void, funcs: *const c_void, encoder_type: i32, _name: *const core::ffi::c_char, mut _args: ...) -> i32 {
    if encoder.is_null() || funcs.is_null() { return -LINUX_EINVAL; }
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: the live-device check above confirms mode_config is initialized before this
    // read of config's verified encoder-count field.
    let index = { let devices = DEVICES.lock(); if !devices.iter().any(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) { return -LINUX_ENODEV; } unsafe { *(config.add(MODE_CONFIG_NUM_ENCODER_OFF).cast::<i32>()) } };
    if index >= MAX_KMS_OBJECTS { return -LINUX_EINVAL; }
    // SAFETY: encoder was null-checked above and DRM_ENCODER_BASE_OFF is the verified offset
    // of its embedded drm_mode_object.
    let Some((name, layout)) = kms_name(b"encoder-", index) else { return -LINUX_EBUSY; }; let base = unsafe { encoder.cast::<u8>().add(DRM_ENCODER_BASE_OFF).cast() }; let object_result = drm_mode_object_add(dev, base, DRM_MODE_OBJECT_ENCODER);
    // SAFETY: object registration failed so name/layout was never linked into any record;
    // this is the allocation's sole owner freeing it.
    if object_result != 0 { unsafe { dealloc(name as *mut u8, layout); } return object_result; }
    let mut devices = DEVICES.lock();
    // SAFETY: as above, name/layout is the unpublished kms_name allocation freed here because
    // no live device record matched after re-acquiring DEVICES.
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) else { unsafe { dealloc(name as *mut u8, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_ENODEV; };
    // SAFETY: config is the live device's embedded mode_config subobject and
    // MODE_CONFIG_NUM_ENCODER_OFF is verified within DRM_DEVICE_SIZE, read while DEVICES is locked.
    let index = unsafe { *(config.add(MODE_CONFIG_NUM_ENCODER_OFF).cast::<i32>()) };
    // SAFETY: as above, name/layout is the unpublished kms_name allocation freed here because
    // the total-encoder count exceeded the object limit.
    if index >= MAX_KMS_OBJECTS { unsafe { dealloc(name as *mut u8, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_EINVAL; }
    // SAFETY: encoder and config offsets are verified ABI fields; list and count mutation is serialized by DEVICES.
    unsafe { let head = encoder.cast::<u8>().add(DRM_ENCODER_HEAD_OFF).cast::<*mut c_void>(); let list = config.add(MODE_CONFIG_ENCODER_LIST_OFF).cast::<*mut c_void>(); let tail = *list.add(1); write(head, list.cast()); write(head.add(1), tail); write(tail as *mut *mut c_void, head.cast()); write(list.add(1), head.cast()); write(encoder.cast::<*mut c_void>(), dev); write(encoder.cast::<u8>().add(DRM_ENCODER_NAME_OFF).cast::<*mut u8>(), name as *mut u8); write(encoder.cast::<u8>().add(DRM_ENCODER_TYPE_OFF).cast::<i32>(), encoder_type); write(encoder.cast::<u8>().add(DRM_ENCODER_INDEX_OFF).cast::<u32>(), index as u32); write(encoder.cast::<u8>().add(DRM_ENCODER_FUNCS_OFF).cast::<*const c_void>(), funcs); write(config.add(MODE_CONFIG_NUM_ENCODER_OFF).cast::<i32>(), index + 1); }
    rec.encoders.push(EncoderRecord { ptr: encoder as usize, name, layout }); 0
}

/// Detach an encoder from its device mode graph and release its core-owned name. # C: O(N_encoders + N_objects)
pub(crate) extern "C" fn drm_encoder_cleanup(encoder: *mut c_void) {
    if encoder.is_null() { return; }
    // SAFETY: encoder is caller-checked non-null; offset 0 holds the device back-pointer
    // drm_encoder_init wrote at init time.
    let dev = unsafe { *(encoder.cast::<*mut c_void>()) }; let mut devices = DEVICES.lock(); let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return; }; let Some(pos) = rec.encoders.iter().position(|entry| entry.ptr == encoder as usize) else { return; }; let entry = rec.encoders.remove(pos); let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: entry is the exact encoder owned by this device, including its linked node and name allocation.
    unsafe { let head = encoder.cast::<u8>().add(DRM_ENCODER_HEAD_OFF).cast::<*mut c_void>(); let next = *head; let prev = *head.add(1); write(prev.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), prev); let count = config.add(MODE_CONFIG_NUM_ENCODER_OFF).cast::<i32>(); if *count > 0 { write(count, *count - 1); } core::ptr::write_bytes(encoder.cast::<u8>(), 0, DRM_ENCODER_FUNCS_OFF + core::mem::size_of::<*const c_void>()); dealloc(entry.name as *mut u8, entry.layout); }
    // SAFETY: encoder remains a valid caller-owned allocation after cleanup; DRM_ENCODER_BASE_OFF
    // is the verified embedded mode-object offset unregistered next.
    drop(devices); drm_mode_object_unregister(dev, unsafe { encoder.cast::<u8>().add(DRM_ENCODER_BASE_OFF).cast() });
}

/// Reset every driver KMS object in construction order after graph setup. # C: O(N_objects)
pub(crate) extern "C" fn drm_mode_config_reset(dev: *mut c_void) {
    let calls = { let devices = DEVICES.lock(); let Some(rec) = devices.iter().find(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) else { return; }; let mut calls = Vec::new(); for plane in &rec.planes { calls.push((plane.ptr, DRM_PLANE_FUNCS_OFF, 24usize)); } for crtc in &rec.crtcs { calls.push((crtc.ptr, DRM_CRTC_FUNCS_OFF, 0)); } for encoder in &rec.encoders { calls.push((encoder.ptr, DRM_ENCODER_FUNCS_OFF, 0)); } for connector in &rec.connectors { calls.push((connector.ptr, connector::DRM_CONNECTOR_FUNCS_OFF, 8)); } calls };
    for (object, funcs_off, reset_off) in calls {
        // SAFETY: each object remains owned by the live device record; the callback offsets are verified ABI fields and reset takes that object pointer.
        unsafe { let funcs = *(object as *mut u8).add(funcs_off).cast::<*const u8>(); if !funcs.is_null() { let reset = *(funcs.add(reset_off).cast::<Option<unsafe extern "C" fn(*mut c_void)>>()); if let Some(reset) = reset { reset(object as *mut c_void); } } }
    }
}
