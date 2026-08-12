use super::*;

pub(super) struct ConnectorRecord { pub(super) ptr: usize, name: usize, layout: Layout, pub(super) modes: Vec<usize>, pub(super) probed_modes: Vec<usize> }

const DRM_CONNECTOR_HEAD_OFF: usize = 32;
pub(super) const DRM_CONNECTOR_BASE_OFF: usize = 64;
const DRM_CONNECTOR_NAME_OFF: usize = 96;
const DRM_CONNECTOR_INDEX_OFF: usize = 136;
pub(super) const DRM_CONNECTOR_TYPE_OFF: usize = 140;
const DRM_CONNECTOR_TYPE_ID_OFF: usize = 144;
pub(super) const DRM_CONNECTOR_FUNCS_OFF: usize = 416;
pub(super) const DRM_CONNECTOR_HELPER_PRIVATE_OFF: usize = 1576;
const DRM_CONNECTOR_DETECT_OFF: usize = 16;
const DRM_CONNECTOR_HELPER_DETECT_CTX_OFF: usize = 8;
pub(super) const DRM_CONNECTOR_STATUS_OFF: usize = 176;
pub(super) const DRM_CONNECTOR_STATUS_CONNECTED: i32 = 1;
pub(super) const DRM_CONNECTOR_STATUS_DISCONNECTED: i32 = 2;
pub(super) const DRM_CONNECTOR_STATUS_UNKNOWN: i32 = 3;
pub(super) const DRM_CONNECTOR_POSSIBLE_ENCODERS_OFF: usize = 1736;
const DRM_CONNECTOR_ENCODER_OFF: usize = 1744;
const DRM_CONNECTOR_MODE_OBJECT_REFCOUNT_OFF: usize = 80;
const DRM_CONNECTOR_MODE_OBJECT_FREE_CB_OFF: usize = 88;
const DRM_CONNECTOR_DESTROY_OFF: usize = 64;
pub(super) const MODE_CONFIG_NUM_CONNECTOR_OFF: usize = 236;
pub(super) const DRM_MODE_OBJECT_CONNECTOR: u32 = 0xc0c0_c0c0;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_connector_init", drm_connector_init as *const () as usize, false);
    crate::symtab::export("drm_connector_cleanup", drm_connector_cleanup as *const () as usize, false);
    crate::symtab::export("drm_connector_attach_encoder", drm_connector_attach_encoder as *const () as usize, false);
    crate::symtab::export("drm_connector_helper_add", drm_connector_helper_add as *const () as usize, false);
    crate::symtab::export("drm_helper_probe_detect", drm_helper_probe_detect as *const () as usize, false);
}

extern "C" fn connector_mode_object_release(kref: *mut c_void) {
    if kref.is_null() { return; }
    // SAFETY: kref is the embedded mode-object kref at connector+80, and Linux releases through funcs->destroy.
    unsafe { let connector = kref.cast::<u8>().sub(DRM_CONNECTOR_MODE_OBJECT_REFCOUNT_OFF); let funcs = read(connector.add(DRM_CONNECTOR_FUNCS_OFF).cast::<*const u8>()); if funcs.is_null() { return; } let destroy = read(funcs.add(DRM_CONNECTOR_DESTROY_OFF).cast::<usize>()); if destroy != 0 { let callback: extern "C" fn(*mut c_void) = core::mem::transmute(destroy); callback(connector.cast()); } }
}

/// Attach a connector helper vtable. # C: O(1)
pub(super) extern "C" fn drm_connector_helper_add(connector: *mut c_void, funcs: *const c_void) {
    if connector.is_null() { return; }
    // SAFETY: helper_private is the ABI-verified connector helper-vtable pointer field.
    unsafe { write(connector.cast::<u8>().add(DRM_CONNECTOR_HELPER_PRIVATE_OFF).cast::<*const c_void>(), funcs); }
}

pub(super) unsafe fn connector_detect(connector: *mut c_void, force: bool) -> i32 {
    // SAFETY: helper and connector callback slots are ABI-verified pointers; missing callbacks imply connected.
    unsafe { let helper = *(connector.cast::<u8>().add(DRM_CONNECTOR_HELPER_PRIVATE_OFF).cast::<*const c_void>()); if !helper.is_null() { let address = helper.cast::<u8>().add(DRM_CONNECTOR_HELPER_DETECT_CTX_OFF).cast::<usize>().read(); if address != 0 { let callback: extern "C" fn(*mut c_void, *mut c_void, bool) -> i32 = core::mem::transmute(address); return normalize_status(callback(connector, core::ptr::null_mut(), force)); } } let funcs = *(connector.cast::<u8>().add(DRM_CONNECTOR_FUNCS_OFF).cast::<*const c_void>()); if funcs.is_null() { return DRM_CONNECTOR_STATUS_CONNECTED; } let address = funcs.cast::<u8>().add(DRM_CONNECTOR_DETECT_OFF).cast::<usize>().read(); if address == 0 { DRM_CONNECTOR_STATUS_CONNECTED } else { let callback: extern "C" fn(*mut c_void, bool) -> i32 = core::mem::transmute(address); normalize_status(callback(connector, force)) } }
}

/// Probe connector status through its helper callback chain. # C: O(1)
pub(super) extern "C" fn drm_helper_probe_detect(connector: *mut c_void, _ctx: *mut c_void, force: bool) -> i32 {
    if connector.is_null() { return DRM_CONNECTOR_STATUS_UNKNOWN; }
    // SAFETY: caller supplies a live connector object with ABI-verified callback tables.
    unsafe { connector_detect(connector, force) }
}

fn normalize_status(status: i32) -> i32 { if [DRM_CONNECTOR_STATUS_CONNECTED, DRM_CONNECTOR_STATUS_DISCONNECTED, DRM_CONNECTOR_STATUS_UNKNOWN].contains(&status) { status } else { DRM_CONNECTOR_STATUS_UNKNOWN } }

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
    unsafe { let head = connector.cast::<u8>().add(DRM_CONNECTOR_HEAD_OFF).cast::<*mut c_void>(); let list = config.add(MODE_CONFIG_CONNECTOR_LIST_OFF).cast::<*mut c_void>(); let tail = *list.add(1); write(head, list.cast()); write(head.add(1), tail); write(tail as *mut *mut c_void, head.cast()); write(list.add(1), head.cast()); mode::initialize_mode_lists(connector.cast()); write(connector.cast::<*mut c_void>(), dev); write(connector.cast::<u8>().add(DRM_CONNECTOR_NAME_OFF).cast::<*mut u8>(), name as *mut u8); write(connector.cast::<u8>().add(DRM_CONNECTOR_FUNCS_OFF).cast::<*const c_void>(), funcs); write(connector.cast::<u8>().add(DRM_CONNECTOR_MODE_OBJECT_REFCOUNT_OFF).cast::<i32>(), 1); write(connector.cast::<u8>().add(DRM_CONNECTOR_MODE_OBJECT_FREE_CB_OFF).cast::<usize>(), connector_mode_object_release as *const () as usize); write(connector.cast::<u8>().add(DRM_CONNECTOR_INDEX_OFF).cast::<u32>(), index as u32); write(connector.cast::<u8>().add(DRM_CONNECTOR_TYPE_OFF).cast::<i32>(), connector_type); write(connector.cast::<u8>().add(DRM_CONNECTOR_TYPE_ID_OFF).cast::<i32>(), index + 1); write(config.add(MODE_CONFIG_NUM_CONNECTOR_OFF).cast::<i32>(), index + 1); }
    rec.connectors.push(ConnectorRecord { ptr: connector as usize, name, layout, modes: Vec::new(), probed_modes: Vec::new() }); 0
}

/// Remove a connector from the device graph and free its core-owned name. # C: O(N_connectors + N_objects)
pub(super) extern "C" fn drm_connector_cleanup(connector: *mut c_void) {
    if connector.is_null() { return; } let dev = unsafe { *(connector.cast::<*mut c_void>()) }; let mut devices = DEVICES.lock(); let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return; }; let Some(pos) = rec.connectors.iter().position(|entry| entry.ptr == connector as usize) else { return; }; let entry = rec.connectors.remove(pos); let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: entry is the precise connector owned by this device, including list node and name allocation.
    edid_connector::release_connector(connector); unsafe { let head = connector.cast::<u8>().add(DRM_CONNECTOR_HEAD_OFF).cast::<*mut c_void>(); let next = *head; let prev = *head.add(1); write(prev.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), prev); let count = config.add(MODE_CONFIG_NUM_CONNECTOR_OFF).cast::<i32>(); if *count > 0 { write(count, *count - 1); } core::ptr::write_bytes(connector.cast::<u8>(), 0, DRM_CONNECTOR_FUNCS_OFF + core::mem::size_of::<*const c_void>()); dealloc(entry.name as *mut u8, entry.layout); }
    for mode in entry.modes.into_iter().chain(entry.probed_modes) { unsafe { mode::unlink_mode(mode as *mut c_void); dealloc(mode as *mut u8, mode::mode_layout()); } }
    drop(devices); drm_mode_object_unregister(dev, unsafe { connector.cast::<u8>().add(DRM_CONNECTOR_BASE_OFF).cast() });
}
