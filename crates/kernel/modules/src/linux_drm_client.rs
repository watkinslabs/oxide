//! Linux DRM in-kernel client lifetime and private-file ownership.

use super::*;
use alloc::vec::Vec;
use sync::{Spinlock, Modules as ModulesLockClass};

const LINUX_EINVAL: i32 = 22;
const LINUX_EBUSY: i32 = 16;
const DRM_CLIENT_DEV_OFF: usize = 0;
const DRM_CLIENT_NAME_OFF: usize = 8;
const DRM_CLIENT_FUNCS_OFF: usize = 32;
const DRM_CLIENT_FILE_OFF: usize = 40;
const DRM_CLIENT_FREE_OFF: usize = 8;
const DRM_CLIENT_HOTPLUG_OFF: usize = 32;
const DRM_FILE_SIZE: usize = 416;

struct ClientRecord { client: usize, dev: usize, file: usize, registered: bool }
static CLIENTS: Spinlock<Vec<ClientRecord>, ModulesLockClass> = Spinlock::new(Vec::new());

pub(super) fn export_symbols() {
    crate::symtab::export("drm_client_init", drm_client_init as *const () as usize, false);
    crate::symtab::export("drm_client_register", drm_client_register as *const () as usize, false);
    crate::symtab::export("drm_client_release", drm_client_release as *const () as usize, false);
}

pub(super) extern "C" fn drm_client_init(dev: *mut c_void, client: *mut c_void, name: *const u8, funcs: *const c_void) -> i32 {
    if dev.is_null() || client.is_null() || name.is_null() { return -LINUX_EINVAL; }
    let layout = Layout::from_size_align(DRM_FILE_SIZE, core::mem::align_of::<u64>()).unwrap(); let file = unsafe { alloc_zeroed(layout) };
    if file.is_null() || !gem::file_init(file.cast()) { if !file.is_null() { unsafe { dealloc(file, layout); } } return -LINUX_EBUSY; }
    unsafe { write(client.cast::<u8>().add(DRM_CLIENT_DEV_OFF).cast::<*mut c_void>(), dev); write(client.cast::<u8>().add(DRM_CLIENT_NAME_OFF).cast::<*const u8>(), name); write(client.cast::<u8>().add(DRM_CLIENT_FUNCS_OFF).cast::<*const c_void>(), funcs); write(client.cast::<u8>().add(DRM_CLIENT_FILE_OFF).cast::<*mut u8>(), file); }
    CLIENTS.lock().push(ClientRecord { client: client as usize, dev: dev as usize, file: file as usize, registered: false }); drm_dev_get(dev); 0
}

pub(super) extern "C" fn drm_client_register(client: *mut c_void) {
    if client.is_null() { return; }
    let hotplug = { let mut clients = CLIENTS.lock(); let Some(record) = clients.iter_mut().find(|record| record.client == client as usize) else { return; }; if record.registered { return; } record.registered = true; let funcs = unsafe { read(client.cast::<u8>().add(DRM_CLIENT_FUNCS_OFF).cast::<*const u8>()) }; if funcs.is_null() { 0 } else { unsafe { read(funcs.add(DRM_CLIENT_HOTPLUG_OFF).cast::<usize>()) } } };
    if hotplug != 0 { let callback: extern "C" fn(*mut c_void) -> i32 = unsafe { core::mem::transmute(hotplug) }; let _ = callback(client); }
}

pub(super) extern "C" fn drm_client_release(client: *mut c_void) {
    if client.is_null() { return; }
    let record = { let mut clients = CLIENTS.lock(); let Some(index) = clients.iter().position(|record| record.client == client as usize) else { return; }; clients.remove(index) };
    let free = unsafe { read(client.cast::<u8>().add(DRM_CLIENT_FUNCS_OFF).cast::<*const u8>()) };
    gem::file_release(record.dev as *mut c_void, record.file as *mut c_void); unsafe { dealloc(record.file as *mut u8, Layout::from_size_align(DRM_FILE_SIZE, core::mem::align_of::<u64>()).unwrap()); write(client.cast::<u8>().add(DRM_CLIENT_FILE_OFF).cast::<*mut u8>(), core::ptr::null_mut()); }
    if !free.is_null() { let callback = unsafe { read(free.add(DRM_CLIENT_FREE_OFF).cast::<usize>()) }; if callback != 0 { let callback: extern "C" fn(*mut c_void) = unsafe { core::mem::transmute(callback) }; callback(client); } }
    drm_dev_put(record.dev as *mut c_void);
}

#[cfg(test)]
mod tests {
    use super::*;
    static CALLS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    static FREES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    extern "C" fn hotplug(_client: *mut c_void) -> i32 { CALLS.fetch_add(1, core::sync::atomic::Ordering::SeqCst); 0 }
    extern "C" fn free(_client: *mut c_void) { FREES.fetch_add(1, core::sync::atomic::Ordering::SeqCst); }
    #[test]
    fn client_owns_one_private_file_and_registers_hotplug_once() {
        let _serial = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = super::__devm_drm_dev_alloc(&mut parent, core::ptr::null(), 2048, 0); assert!(!dev.is_null()); let mut client = [0u64; 12]; let name = c"test"; let mut funcs = [0usize; 5]; funcs[1] = free as *const () as usize; funcs[4] = hotplug as *const () as usize;
        assert_eq!(drm_client_init(dev, client.as_mut_ptr().cast(), name.as_ptr().cast(), funcs.as_ptr().cast()), 0); assert!(!unsafe { read(client.as_ptr().cast::<u8>().add(DRM_CLIENT_FILE_OFF).cast::<*mut u8>()) }.is_null()); drm_client_register(client.as_mut_ptr().cast()); drm_client_register(client.as_mut_ptr().cast()); assert_eq!(CALLS.swap(0, core::sync::atomic::Ordering::SeqCst), 1); drm_client_release(client.as_mut_ptr().cast()); assert_eq!(FREES.swap(0, core::sync::atomic::Ordering::SeqCst), 1); assert!(unsafe { read(client.as_ptr().cast::<u8>().add(DRM_CLIENT_FILE_OFF).cast::<*mut u8>()) }.is_null()); devres::release_device(&mut parent);
    }
}
