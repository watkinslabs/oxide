//! Linux DRM in-kernel client lifetime and modeset allocation.

use super::*;

const LINUX_EINVAL: i32 = 22;
const LINUX_EOPNOTSUPP: i32 = 95;
const LINUX_ENOMEM: i32 = 12;
const DRM_CLIENT_LIST_OFF: usize = 16;
const DRM_CLIENT_FUNCS_OFF: usize = 32;
const DRM_CLIENT_FILE_OFF: usize = 40;
const DRM_CLIENT_MODESETS_OFF: usize = 80;
const DRM_CLIENT_FREE_OFF: usize = 8;
const DRM_CLIENT_UNREGISTER_OFF: usize = 16;
const DRM_CLIENT_HOTPLUG_OFF: usize = 32;
const DRM_DRIVER_DUMB_CREATE_OFF: usize = 96;
const DRM_DRIVER_MODESET: u32 = 2;
const DRM_FILE_SIZE: usize = 416;
const DRM_MODESET_SIZE: usize = 48;
const DRM_MODESET_CRTC_OFF: usize = 8;
const DRM_MODESET_CONNECTORS_OFF: usize = 32;
const DRM_DEVICE_CLIENTLIST_OFF: usize = 272;
const DRM_DEVICE_FILELIST_INTERNAL_OFF: usize = 224;
const DRM_FILE_LHEAD_OFF: usize = 56;

pub(super) struct ClientRecord { pub(super) client: usize, pub(super) file: usize, modesets: usize, modesets_layout: Layout, connector_arrays: Vec<(usize, Layout)>, registered: bool }

pub(super) fn export_symbols() {
    crate::symtab::export("drm_client_init", drm_client_init as *const () as usize, false);
    crate::symtab::export("drm_client_register", drm_client_register as *const () as usize, false);
    crate::symtab::export("drm_client_release", drm_client_release as *const () as usize, false);
}

fn layout(size: usize) -> Option<Layout> { Layout::from_size_align(size.max(1), core::mem::align_of::<u64>()).ok() }

fn supported(dev: *mut c_void) -> bool {
    unsafe { let driver = read(dev.cast::<u8>().add(DRM_DEVICE_DRIVER_OFF).cast::<*const u8>()); !driver.is_null() && read(dev.cast::<u8>().add(DRM_DEVICE_FEATURES_OFF).cast::<u32>()) & DRM_DRIVER_MODESET != 0 && read(driver.add(DRM_DRIVER_DUMB_CREATE_OFF).cast::<usize>()) != 0 }
}

fn new_modesets(crtcs: &[CrtcRecord]) -> Option<(usize, Layout, Vec<(usize, Layout)>)> {
    let count = crtcs.len().checked_add(1)?; let modesets_layout = layout(DRM_MODESET_SIZE.checked_mul(count)?)?;
    let modesets = unsafe { alloc_zeroed(modesets_layout) }; if modesets.is_null() { return None; }
    let max_connectors = if crtcs.len() == 1 { 8 } else { 1 }; let mut connector_arrays = Vec::new();
    for (index, crtc) in crtcs.iter().enumerate() {
        let Some(connectors_layout) = layout(core::mem::size_of::<*mut c_void>().checked_mul(max_connectors)?) else { free_modesets(modesets as usize, modesets_layout, connector_arrays); return None; };
        let connectors = unsafe { alloc_zeroed(connectors_layout) }; if connectors.is_null() { free_modesets(modesets as usize, modesets_layout, connector_arrays); return None; }
        unsafe { write(modesets.add(index * DRM_MODESET_SIZE + DRM_MODESET_CRTC_OFF).cast::<*mut c_void>(), crtc.ptr as *mut c_void); write(modesets.add(index * DRM_MODESET_SIZE + DRM_MODESET_CONNECTORS_OFF).cast::<*mut u8>(), connectors); }
        connector_arrays.push((connectors as usize, connectors_layout));
    }
    Some((modesets as usize, modesets_layout, connector_arrays))
}

fn free_modesets(modesets: usize, modesets_layout: Layout, connector_arrays: Vec<(usize, Layout)>) {
    for (connectors, layout) in connector_arrays { unsafe { dealloc(connectors as *mut u8, layout); } }
    if modesets != 0 { unsafe { dealloc(modesets as *mut u8, modesets_layout); } }
}

fn detach(record: ClientRecord) {
    unsafe { write((record.client as *mut u8).add(DRM_CLIENT_MODESETS_OFF).cast::<*mut u8>(), core::ptr::null_mut()); write((record.client as *mut u8).add(DRM_CLIENT_FILE_OFF).cast::<*mut u8>(), core::ptr::null_mut()); }
    if record.registered { unsafe { let head = (record.client as *mut u8).add(DRM_CLIENT_LIST_OFF).cast::<*mut c_void>(); let next = read(head); let prev = read(head.add(1)); write(prev.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), prev); } }
    unsafe { let head = (record.file as *mut u8).add(DRM_FILE_LHEAD_OFF).cast::<*mut c_void>(); let next = read(head); let prev = read(head.add(1)); write(prev.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), prev); }
    free_modesets(record.modesets, record.modesets_layout, record.connector_arrays);
    gem::file_release(unsafe { read((record.client as *mut u8).cast::<*mut c_void>()) }, record.file as *mut c_void);
    unsafe { dealloc(record.file as *mut u8, layout(DRM_FILE_SIZE).unwrap()); }
}

pub(super) extern "C" fn drm_client_init(dev: *mut c_void, client: *mut c_void, name: *const u8, funcs: *const c_void) -> i32 {
    if dev.is_null() || client.is_null() || name.is_null() { return -LINUX_EINVAL; }
    if !supported(dev) { return -LINUX_EOPNOTSUPP; }
    let (modesets, modesets_layout, connector_arrays) = { let devices = DEVICES.lock(); let Some(device) = devices.iter().find(|device| device.dev == dev as usize && device.mode_config && !device.put_pending && !device.unplugged) else { return -LINUX_EINVAL; }; let crtcs: Vec<CrtcRecord> = device.crtcs.iter().copied().collect(); drop(devices); let Some(parts) = new_modesets(&crtcs) else { return -LINUX_ENOMEM; }; parts };
    let file_layout = layout(DRM_FILE_SIZE).unwrap(); let file = unsafe { alloc_zeroed(file_layout) }; if file.is_null() || !gem::file_init(file.cast()) { if !file.is_null() { unsafe { dealloc(file, file_layout); } } free_modesets(modesets, modesets_layout, connector_arrays); return -LINUX_ENOMEM; }
    unsafe { write(client.cast::<*mut c_void>(), dev); write(client.cast::<u8>().add(8).cast::<*const u8>(), name); write(client.cast::<u8>().add(DRM_CLIENT_LIST_OFF).cast::<*mut u8>(), client.cast()); write(client.cast::<u8>().add(DRM_CLIENT_LIST_OFF + 8).cast::<*mut u8>(), client.cast()); write(client.cast::<u8>().add(DRM_CLIENT_FUNCS_OFF).cast::<*const c_void>(), funcs); write(client.cast::<u8>().add(DRM_CLIENT_FILE_OFF).cast::<*mut u8>(), file); write(client.cast::<u8>().add(DRM_CLIENT_MODESETS_OFF).cast::<*mut u8>(), modesets as *mut u8); let list = dev.cast::<u8>().add(DRM_DEVICE_FILELIST_INTERNAL_OFF).cast::<*mut c_void>(); let head = file.add(DRM_FILE_LHEAD_OFF).cast::<*mut c_void>(); let tail = read(list.add(1)); write(head, list.cast()); write(head.add(1), tail); write(tail.cast::<*mut c_void>(), head.cast()); write(list.add(1), head.cast()); }
    let mut devices = DEVICES.lock(); let Some(device) = devices.iter_mut().find(|device| device.dev == dev as usize && device.mode_config && !device.put_pending && !device.unplugged) else { unsafe { gem::file_release(dev, file.cast()); dealloc(file, file_layout); } free_modesets(modesets, modesets_layout, connector_arrays); return -LINUX_EINVAL; }; device.clients.push(ClientRecord { client: client as usize, file: file as usize, modesets, modesets_layout, connector_arrays, registered: false }); drop(devices); drm_dev_get(dev); 0
}

pub(super) extern "C" fn drm_client_register(client: *mut c_void) {
    if client.is_null() { return; } let (dev, hotplug) = unsafe { (read(client.cast::<*mut c_void>()), read(client.cast::<u8>().add(DRM_CLIENT_FUNCS_OFF).cast::<*const u8>())) }; if dev.is_null() { return; }
    let mut devices = DEVICES.lock(); let Some(device) = devices.iter_mut().find(|device| device.dev == dev as usize) else { return; }; let Some(record) = device.clients.iter_mut().find(|record| record.client == client as usize) else { return; }; if record.registered { return; } unsafe { let list = dev.cast::<u8>().add(DRM_DEVICE_CLIENTLIST_OFF).cast::<*mut c_void>(); let head = client.cast::<u8>().add(DRM_CLIENT_LIST_OFF).cast::<*mut c_void>(); let tail = read(list.add(1)); write(head, list.cast()); write(head.add(1), tail); write(tail.cast::<*mut c_void>(), head.cast()); write(list.add(1), head.cast()); } record.registered = true; let hotplug = if hotplug.is_null() { 0 } else { unsafe { read(hotplug.add(DRM_CLIENT_HOTPLUG_OFF).cast::<usize>()) } }; drop(devices); if hotplug != 0 { let callback: extern "C" fn(*mut c_void) -> i32 = unsafe { core::mem::transmute(hotplug) }; let _ = callback(client); }
}

pub(super) extern "C" fn drm_client_release(client: *mut c_void) {
    if client.is_null() { return; } let dev = unsafe { read(client.cast::<*mut c_void>()) }; if dev.is_null() { return; } let record = { let mut devices = DEVICES.lock(); let Some(device) = devices.iter_mut().find(|device| device.dev == dev as usize) else { return; }; let Some(index) = device.clients.iter().position(|record| record.client == client as usize) else { return; }; device.clients.remove(index) }; let funcs = unsafe { read(client.cast::<u8>().add(DRM_CLIENT_FUNCS_OFF).cast::<*const u8>()) }; detach(record); if !funcs.is_null() { let callback = unsafe { read(funcs.add(DRM_CLIENT_FREE_OFF).cast::<usize>()) }; if callback != 0 { let callback: extern "C" fn(*mut c_void) = unsafe { core::mem::transmute(callback) }; callback(client); } } drm_dev_put(dev);
}

pub(super) fn unregister_device(dev: *mut c_void) {
    let clients = { let mut devices = DEVICES.lock(); let Some(device) = devices.iter_mut().find(|device| device.dev == dev as usize) else { return; }; let mut clients = Vec::new(); for record in device.clients.iter_mut().filter(|record| record.registered) { unsafe { let head = (record.client as *mut u8).add(DRM_CLIENT_LIST_OFF).cast::<*mut c_void>(); let next = read(head); let prev = read(head.add(1)); write(prev.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), prev); write(head, head.cast()); write(head.add(1), head.cast()); let funcs = read((record.client as *mut u8).add(DRM_CLIENT_FUNCS_OFF).cast::<*const u8>()); clients.push((record.client, if funcs.is_null() { 0 } else { read(funcs.add(DRM_CLIENT_UNREGISTER_OFF).cast::<usize>()) })); } record.registered = false; } clients };
    for (client, unregister) in clients { if unregister == 0 { drm_client_release(client as *mut c_void); } else { let callback: extern "C" fn(*mut c_void) = unsafe { core::mem::transmute(unregister) }; callback(client as *mut c_void); } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static HOTPLUGS: AtomicUsize = AtomicUsize::new(0);
    static FREES: AtomicUsize = AtomicUsize::new(0);
    static UNREGISTERS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn dumb_create(_file: *mut c_void, _dev: *mut c_void, _args: *mut c_void) -> i32 { 0 }
    extern "C" fn hotplug(_client: *mut c_void) -> i32 { HOTPLUGS.fetch_add(1, Ordering::SeqCst); 0 }
    extern "C" fn free(_client: *mut c_void) { FREES.fetch_add(1, Ordering::SeqCst); }
    extern "C" fn unregister(client: *mut c_void) { UNREGISTERS.fetch_add(1, Ordering::SeqCst); drm_client_release(client); }

    #[test]
    fn client_lifecycle_uses_the_modeset_gate_and_device_client_list() {
        let _serial = crate::test_serial::claim(); HOTPLUGS.store(0, Ordering::SeqCst); FREES.store(0, Ordering::SeqCst);
        let mut parent = LinuxDevice::new(); let mut driver = [0u8; 104]; let mut client = [0u64; 12]; let mut funcs = [0usize; 5]; let name = c"test";
        unsafe { write(driver.as_mut_ptr().add(DRM_DRIVER_FEATURES_OFF).cast::<u32>(), DRM_DRIVER_MODESET); write(driver.as_mut_ptr().add(DRM_DRIVER_DUMB_CREATE_OFF).cast::<usize>(), dumb_create as *const () as usize); }
        let dev = super::__devm_drm_dev_alloc(&mut parent, driver.as_ptr().cast(), 2048, 0); assert!(!dev.is_null()); assert_eq!(super::drmm_mode_config_init(dev), 0); funcs[1] = free as *const () as usize; funcs[4] = hotplug as *const () as usize;
        assert_eq!(drm_client_init(dev, client.as_mut_ptr().cast(), name.as_ptr().cast(), funcs.as_ptr().cast()), 0);
        unsafe { assert!(!read(client.as_ptr().cast::<u8>().add(DRM_CLIENT_FILE_OFF).cast::<*mut c_void>()).is_null()); assert!(!read(client.as_ptr().cast::<u8>().add(DRM_CLIENT_MODESETS_OFF).cast::<*mut c_void>()).is_null()); }
        drm_client_register(client.as_mut_ptr().cast()); drm_client_register(client.as_mut_ptr().cast()); assert_eq!(HOTPLUGS.load(Ordering::SeqCst), 1);
        unsafe { let list = dev.cast::<u8>().add(DRM_DEVICE_CLIENTLIST_OFF).cast::<*mut c_void>(); assert_eq!(read(list), client.as_mut_ptr().cast::<u8>().add(DRM_CLIENT_LIST_OFF).cast()); }
        drm_client_release(client.as_mut_ptr().cast()); assert_eq!(FREES.load(Ordering::SeqCst), 1); unsafe { assert!(read(client.as_ptr().cast::<u8>().add(DRM_CLIENT_FILE_OFF).cast::<*mut c_void>()).is_null()); assert!(read(client.as_ptr().cast::<u8>().add(DRM_CLIENT_MODESETS_OFF).cast::<*mut c_void>()).is_null()); }
        devres::release_device(&mut parent);
    }

    #[test]
    fn device_unregister_unlinks_then_calls_the_client_release_path() {
        let _serial = crate::test_serial::claim(); UNREGISTERS.store(0, Ordering::SeqCst); FREES.store(0, Ordering::SeqCst);
        let mut parent = LinuxDevice::new(); let mut driver = [0u8; 104]; let mut client = [0u64; 12]; let mut funcs = [0usize; 5]; let name = c"test";
        unsafe { write(driver.as_mut_ptr().add(DRM_DRIVER_FEATURES_OFF).cast::<u32>(), DRM_DRIVER_MODESET); write(driver.as_mut_ptr().add(DRM_DRIVER_DUMB_CREATE_OFF).cast::<usize>(), dumb_create as *const () as usize); }
        let dev = super::__devm_drm_dev_alloc(&mut parent, driver.as_ptr().cast(), 2048, 0); assert_eq!(super::drmm_mode_config_init(dev), 0); funcs[1] = free as *const () as usize; funcs[2] = unregister as *const () as usize;
        assert_eq!(drm_client_init(dev, client.as_mut_ptr().cast(), name.as_ptr().cast(), funcs.as_ptr().cast()), 0); drm_client_register(client.as_mut_ptr().cast()); super::register::drm_dev_unregister(dev);
        assert_eq!(UNREGISTERS.load(Ordering::SeqCst), 1); assert_eq!(FREES.load(Ordering::SeqCst), 1); unsafe { assert!(read(client.as_ptr().cast::<u8>().add(DRM_CLIENT_FILE_OFF).cast::<*mut c_void>()).is_null()); }
        devres::release_device(&mut parent);
    }
}
