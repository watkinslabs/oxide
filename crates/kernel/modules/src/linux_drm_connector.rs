use super::*;

pub(super) struct ConnectorRecord { pub(super) ptr: usize, name: usize, layout: Layout }

const DRM_CONNECTOR_HEAD_OFF: usize = 32;
pub(super) const DRM_CONNECTOR_BASE_OFF: usize = 64;
const DRM_CONNECTOR_NAME_OFF: usize = 96;
const DRM_CONNECTOR_INDEX_OFF: usize = 136;
const DRM_CONNECTOR_TYPE_OFF: usize = 140;
const DRM_CONNECTOR_TYPE_ID_OFF: usize = 144;
pub(super) const DRM_CONNECTOR_FUNCS_OFF: usize = 416;
pub(super) const DRM_CONNECTOR_POSSIBLE_ENCODERS_OFF: usize = 1736;
const DRM_CONNECTOR_ENCODER_OFF: usize = 1744;
pub(super) const MODE_CONFIG_NUM_CONNECTOR_OFF: usize = 248;
pub(super) const DRM_MODE_OBJECT_CONNECTOR: u32 = 0xc0c0_c0c0;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_connector_init", drm_connector_init as *const () as usize, false);
    crate::symtab::export("drm_connector_cleanup", drm_connector_cleanup as *const () as usize, false);
    crate::symtab::export("drm_connector_attach_encoder", drm_connector_attach_encoder as *const () as usize, false);
}

/// Add an encoder to a connector's possible-encoder routing mask. # C: O(1)
pub(super) extern "C" fn drm_connector_attach_encoder(connector: *mut c_void, encoder: *mut c_void) -> i32 {
    if connector.is_null() || encoder.is_null() { return -LINUX_EINVAL; }
    let dev = unsafe { *(connector.cast::<*mut c_void>()) }; let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return -LINUX_ENODEV; };
    if !rec.connectors.iter().any(|entry| entry.ptr == connector as usize) || !rec.encoders.iter().any(|entry| entry.ptr == encoder as usize) { return -LINUX_ENODEV; }
    // SAFETY: both objects are live in the same graph; ABI fields model the routing relation.
    unsafe { if !(*(connector.cast::<u8>().add(DRM_CONNECTOR_ENCODER_OFF).cast::<*mut c_void>())).is_null() { return -LINUX_EINVAL; } let index = *(encoder.cast::<u8>().add(DRM_ENCODER_INDEX_OFF).cast::<u32>()); if index >= MAX_KMS_OBJECTS as u32 { return -LINUX_EINVAL; } let mask = connector.cast::<u8>().add(DRM_CONNECTOR_POSSIBLE_ENCODERS_OFF).cast::<u32>(); write(mask, *mask | (1u32 << index)); }
    0
}

/// Initialize a connector and publish it in the device connector list. # C: O(N_connectors + N_objects)
pub(super) extern "C" fn drm_connector_init(dev: *mut c_void, connector: *mut c_void, funcs: *const c_void, connector_type: i32) -> i32 {
    if connector.is_null() || funcs.is_null() { return -LINUX_EINVAL; }
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    let index = { let devices = DEVICES.lock(); if !devices.iter().any(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) { return -LINUX_ENODEV; } unsafe { *(config.add(MODE_CONFIG_NUM_CONNECTOR_OFF).cast::<i32>()) } };
    if index >= MAX_KMS_OBJECTS { return -LINUX_EINVAL; }
    let Some((name, layout)) = kms_name(b"connector-", index + 1) else { return -LINUX_EBUSY; }; let base = unsafe { connector.cast::<u8>().add(DRM_CONNECTOR_BASE_OFF).cast() }; let object_result = drm_mode_object_add(dev, base, DRM_MODE_OBJECT_CONNECTOR);
    if object_result != 0 { unsafe { dealloc(name as *mut u8, layout); } return object_result; }
    let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) else { unsafe { dealloc(name as *mut u8, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_ENODEV; };
    let index = unsafe { *(config.add(MODE_CONFIG_NUM_CONNECTOR_OFF).cast::<i32>()) };
    if index >= MAX_KMS_OBJECTS { unsafe { dealloc(name as *mut u8, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_EINVAL; }
    // SAFETY: connector and mode-config offsets are ABI-verified; list/count updates are serialized by DEVICES.
    unsafe { let head = connector.cast::<u8>().add(DRM_CONNECTOR_HEAD_OFF).cast::<*mut c_void>(); let list = config.add(MODE_CONFIG_CONNECTOR_LIST_OFF).cast::<*mut c_void>(); let tail = *list.add(1); write(head, list.cast()); write(head.add(1), tail); write(tail as *mut *mut c_void, head.cast()); write(list.add(1), head.cast()); write(connector.cast::<*mut c_void>(), dev); write(connector.cast::<u8>().add(DRM_CONNECTOR_NAME_OFF).cast::<*mut u8>(), name as *mut u8); write(connector.cast::<u8>().add(DRM_CONNECTOR_FUNCS_OFF).cast::<*const c_void>(), funcs); write(connector.cast::<u8>().add(DRM_CONNECTOR_INDEX_OFF).cast::<u32>(), index as u32); write(connector.cast::<u8>().add(DRM_CONNECTOR_TYPE_OFF).cast::<i32>(), connector_type); write(connector.cast::<u8>().add(DRM_CONNECTOR_TYPE_ID_OFF).cast::<i32>(), index + 1); write(config.add(MODE_CONFIG_NUM_CONNECTOR_OFF).cast::<i32>(), index + 1); }
    rec.connectors.push(ConnectorRecord { ptr: connector as usize, name, layout }); 0
}

/// Remove a connector from the device graph and free its core-owned name. # C: O(N_connectors + N_objects)
pub(super) extern "C" fn drm_connector_cleanup(connector: *mut c_void) {
    if connector.is_null() { return; } let dev = unsafe { *(connector.cast::<*mut c_void>()) }; let mut devices = DEVICES.lock(); let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return; }; let Some(pos) = rec.connectors.iter().position(|entry| entry.ptr == connector as usize) else { return; }; let entry = rec.connectors.remove(pos); let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: entry is the precise connector owned by this device, including list node and name allocation.
    unsafe { let head = connector.cast::<u8>().add(DRM_CONNECTOR_HEAD_OFF).cast::<*mut c_void>(); let next = *head; let prev = *head.add(1); write(prev.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), prev); let count = config.add(MODE_CONFIG_NUM_CONNECTOR_OFF).cast::<i32>(); if *count > 0 { write(count, *count - 1); } core::ptr::write_bytes(connector.cast::<u8>(), 0, DRM_CONNECTOR_FUNCS_OFF + core::mem::size_of::<*const c_void>()); dealloc(entry.name as *mut u8, entry.layout); }
    drop(devices); drm_mode_object_unregister(dev, unsafe { connector.cast::<u8>().add(DRM_CONNECTOR_BASE_OFF).cast() });
}
