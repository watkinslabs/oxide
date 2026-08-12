//! DRM module ABI object allocation and lifetime.
extern crate alloc;
use alloc::alloc::{alloc, alloc_zeroed, dealloc};
use alloc::vec::Vec;
use crate::linux_device::devres;
use crate::linux_device::types::LinuxDevice;
use core::alloc::Layout;
use core::ffi::c_void;
use core::ptr::{read, write};
use core::sync::atomic::{AtomicI32, Ordering};
use sync::{Spinlock, Modules as ModulesLockClass};

// Module manifest: connector owns connector construction, attachment and teardown.
#[path = "linux_drm_connector.rs"] mod connector;
#[path = "linux_drm_register.rs"] mod register;
#[path = "linux_drm_format.rs"] mod format;
#[path = "linux_drm_mode.rs"] mod mode;
#[path = "linux_drm_dmt.rs"] mod dmt; #[path = "linux_drm_probe.rs"] mod probe;
#[path = "linux_drm_file.rs"] mod file;
#[path = "linux_drm_ioctl.rs"] mod ioctl;
#[path = "linux_drm_gem.rs"] mod gem;
#[path = "linux_drm_shadow.rs"] mod shadow;
#[path = "linux_drm_format_helper.rs"] mod format_helper;
#[path = "linux_drm_atomic.rs"] mod atomic;
#[path = "linux_drm_vblank.rs"] mod vblank;
#[path = "linux_drm_edid.rs"] mod edid;
#[path = "linux_drm_edid_owner.rs"] mod edid_owner;
#[path = "linux_drm_edid_read.rs"] mod edid_read;

struct DeviceAllocation {
    dev: usize,
    base: usize,
    layout: Layout,
    refs: usize,
    mode_config: bool,
    objects: Vec<ModeObjectRecord>,
    planes: Vec<PlaneRecord>,
    crtcs: Vec<CrtcRecord>,
    encoders: Vec<EncoderRecord>,
    connectors: Vec<connector::ConnectorRecord>,
    vblank: Option<(usize, Layout)>,
    /// The current primary-node master file. Linux keeps this relationship in
    /// `drm_device::master`; the module ABI needs the same ownership decision
    /// before it may admit `DRM_MASTER` ioctls.
    primary_master: Option<usize>,
    put_pending: bool,
    unplugged: bool,
}

#[derive(Copy, Clone)]
struct ModeObjectRecord { ptr: usize, id: u32 }

struct PlaneRecord { ptr: usize, formats: usize, layout: Layout }

#[derive(Copy, Clone)]
struct CrtcRecord { ptr: usize, name: usize, layout: Layout }

#[derive(Copy, Clone)]
struct EncoderRecord { ptr: usize, name: usize, layout: Layout }

static DEVICES: Spinlock<Vec<DeviceAllocation>, ModulesLockClass> = Spinlock::new(Vec::new());
static GUARDS: Spinlock<Vec<(i32, usize)>, ModulesLockClass> = Spinlock::new(Vec::new());
static NEXT_GUARD: AtomicI32 = AtomicI32::new(1);
static DRAIN_WAIT: sched::live::WaitList = sched::live::WaitList::new();

const DRM_DEVICE_REF_OFF: usize = 4;
const DRM_DEVICE_DEV_OFF: usize = 8;
const DRM_DEVICE_DMA_DEV_OFF: usize = 16;
const DRM_DEVICE_FINAL_KFREE_OFF: usize = 40;
const DRM_DEVICE_DRIVER_OFF: usize = 56;
const DRM_DEVICE_FEATURES_OFF: usize = 112;
const DRM_DRIVER_FEATURES_OFF: usize = 168;
const INITIAL_REFERENCE_COUNT: i32 = 1;
const LINUX_ENODEV: i32 = 19;
const LINUX_EBUSY: i32 = 16;
const LINUX_EINVAL: i32 = 22;
const DRM_MODE_CONFIG_OFF: usize = 360;
const DRM_DEVICE_VBLANK_OFF: usize = 312;
const DRM_DEVICE_NUM_CRTCS_OFF: usize = 356;
const DRM_VBLANK_CRTC_SIZE: usize = 400;
const DRM_VBLANK_CRTC_DEV_OFF: usize = 0;
const DRM_VBLANK_CRTC_PIPE_OFF: usize = 112;
const DRM_DEVICE_SIZE: usize = 1584;
const MODE_CONFIG_FB_LIST_OFF: usize = 216;
const MODE_CONFIG_CONNECTOR_LIST_OFF: usize = 256;
const MODE_CONFIG_ENCODER_LIST_OFF: usize = 320;
const MODE_CONFIG_PLANE_LIST_OFF: usize = 344;
const MODE_CONFIG_COLOROP_LIST_OFF: usize = 368;
const MODE_CONFIG_CRTC_LIST_OFF: usize = 392;
const MODE_CONFIG_PROPERTY_LIST_OFF: usize = 408;
const MODE_CONFIG_PRIVOBJ_LIST_OFF: usize = 424;
const MODE_CONFIG_BLOB_LIST_OFF: usize = 592;
const MODE_CONFIG_LISTS: [usize; 9] = [
    MODE_CONFIG_FB_LIST_OFF, MODE_CONFIG_CONNECTOR_LIST_OFF, MODE_CONFIG_ENCODER_LIST_OFF,
    MODE_CONFIG_PLANE_LIST_OFF, MODE_CONFIG_COLOROP_LIST_OFF, MODE_CONFIG_CRTC_LIST_OFF,
    MODE_CONFIG_PROPERTY_LIST_OFF, MODE_CONFIG_PRIVOBJ_LIST_OFF, MODE_CONFIG_BLOB_LIST_OFF,
];
const DRM_MODE_OBJECT_ID_OFF: usize = 0;
const DRM_MODE_OBJECT_TYPE_OFF: usize = 4;
const MODE_CONFIG_NUM_ENCODER_OFF: usize = 312;
const MODE_CONFIG_NUM_TOTAL_PLANE_OFF: usize = 336;
const MODE_CONFIG_NUM_CRTC_OFF: usize = 384;
const DRM_PLANE_HEAD_OFF: usize = 8;
const DRM_PLANE_BASE_OFF: usize = 80;
const DRM_PLANE_POSSIBLE_CRTCS_OFF: usize = 112;
const DRM_PLANE_FORMATS_OFF: usize = 120;
const DRM_PLANE_FORMAT_COUNT_OFF: usize = 128;
const DRM_PLANE_FUNCS_OFF: usize = 176;
const DRM_PLANE_TYPE_OFF: usize = 1216;
const DRM_PLANE_INDEX_OFF: usize = 1220;
const DRM_CRTC_HEAD_OFF: usize = 16;
const DRM_CRTC_BASE_OFF: usize = 96;
const DRM_CRTC_PRIMARY_OFF: usize = 128;
const DRM_CRTC_CURSOR_OFF: usize = 136;
const DRM_CRTC_INDEX_OFF: usize = 144;
const DRM_CRTC_FUNCS_OFF: usize = 408;
const DRM_MODE_OBJECT_CRTC: u32 = 0xcccc_cccc;
const DRM_MODE_OBJECT_ENCODER: u32 = 0xe0e0_e0e0;
const DRM_MODE_OBJECT_PLANE: u32 = 0xeeee_eeee;
const DRM_ENCODER_HEAD_OFF: usize = 8;
const DRM_ENCODER_BASE_OFF: usize = 24;
const DRM_ENCODER_NAME_OFF: usize = 56;
const DRM_ENCODER_TYPE_OFF: usize = 64;
const DRM_ENCODER_INDEX_OFF: usize = 68;
const DRM_ENCODER_FUNCS_OFF: usize = 104;
const MAX_KMS_OBJECTS: i32 = 32;

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
    shadow::export_symbols();
    format_helper::export_symbols();
    atomic::export_symbols();
    vblank::export_symbols();
    edid::export_symbols();
    edid_owner::export_symbols();
    edid_read::export_symbols();
}

fn layout_for(size: usize) -> Option<Layout> {
    let size = size.max(1);
    Layout::from_size_align(size, core::mem::align_of::<u64>()).ok()
}

fn initialize_device(dev: *mut u8, parent: *mut LinuxDevice, driver: *const c_void, base: *mut u8) {
    // SAFETY: dev is the aligned embedded drm_device region inside this allocation; the
    // checked caller-provided offset leaves every written scalar within the object layout.
    unsafe {
        write(dev.add(DRM_DEVICE_REF_OFF).cast::<i32>(), INITIAL_REFERENCE_COUNT);
        write(dev.add(DRM_DEVICE_DEV_OFF).cast::<*mut LinuxDevice>(), parent);
        write(dev.add(DRM_DEVICE_DMA_DEV_OFF).cast::<*mut LinuxDevice>(), parent);
        write(dev.add(DRM_DEVICE_FINAL_KFREE_OFF).cast::<*mut u8>(), base);
        write(dev.add(DRM_DEVICE_DRIVER_OFF).cast::<*const c_void>(), driver);
        let features = if driver.is_null() { 0 } else { *(driver.cast::<u8>().add(DRM_DRIVER_FEATURES_OFF).cast::<u32>()) };
        write(dev.add(DRM_DEVICE_FEATURES_OFF).cast::<u32>(), features);
    }
}

unsafe extern "C" fn devm_drm_dev_put(data: *mut c_void) { drm_dev_put(data); }

/// Allocate one driver-private object and return its containing-object address.
/// # C: O(N_devices)
extern "C" fn __devm_drm_dev_alloc(
    parent: *mut LinuxDevice,
    driver: *const c_void,
    size: usize,
    offset: usize,
) -> *mut c_void {
    if parent.is_null() { return core::ptr::null_mut(); }
    let Some(end) = offset.checked_add(DRM_DEVICE_FEATURES_OFF + core::mem::size_of::<u32>()) else { return core::ptr::null_mut() };
    if end > size { return core::ptr::null_mut(); }
    let Some(layout) = layout_for(size) else { return core::ptr::null_mut() };
    // SAFETY: layout was validated above and the returned allocation is retained
    // in DEVICES until drm_dev_put releases exactly the same layout.
    let base = unsafe { alloc_zeroed(layout) };
    if base.is_null() { return core::ptr::null_mut(); }
    // SAFETY: end was checked against size and base is aligned for the caller's container.
    let dev = unsafe { base.add(offset) };
    initialize_device(dev, parent, driver, base);
    let dev = dev.cast::<c_void>();
    DEVICES.lock().push(DeviceAllocation { dev: dev as usize, base: base as usize, layout, refs: 1, mode_config: false, objects: Vec::new(), planes: Vec::new(), crtcs: Vec::new(), encoders: Vec::new(), connectors: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
    if devres::add_action_or_reset(parent, Some(devm_drm_dev_put), dev) != 0 { return core::ptr::null_mut(); }
    base.cast()
}

/// Drop the driver-private object allocated by `__devm_drm_dev_alloc`.
/// # C: O(N_devices)
extern "C" fn drm_dev_put(dev: *mut c_void) {
    if dev.is_null() { return; }
    let mut rec = {
        let mut devices = DEVICES.lock();
        let Some(pos) = devices.iter().position(|rec| rec.dev == dev as usize) else { return };
        if devices[pos].refs > 1 {
            devices[pos].refs -= 1;
            return;
        }
        if GUARDS.lock().iter().any(|(_, guarded)| *guarded == dev as usize) {
            devices[pos].put_pending = true;
            return;
        }
        devices.remove(pos)
    };
    register::unregister_primary(dev); release_planes(&mut rec);
    // SAFETY: rec.base was returned by alloc_zeroed with rec.layout and was
    // removed from DEVICES first, so this exact allocation is released once.
    unsafe { dealloc(rec.base as *mut u8, rec.layout); }
}

fn release_planes(rec: &mut DeviceAllocation) {
    for plane in rec.planes.drain(..) {
        // SAFETY: formats was allocated by drm_universal_plane_init with this exact layout.
        unsafe { dealloc(plane.formats as *mut u8, plane.layout); }
    }
    if let Some((storage, layout)) = rec.vblank.take() { if storage != 0 { unsafe { dealloc(storage as *mut u8, layout); } } }
}

/// Allocate per-CRTC vblank storage and publish it in the DRM device. # C: O(N_crtcs)
extern "C" fn drm_vblank_init(dev: *mut c_void, num_crtcs: u32) -> i32 {
    let Some(size) = DRM_VBLANK_CRTC_SIZE.checked_mul(num_crtcs as usize) else { return -LINUX_EINVAL; }; let Some(layout) = layout_for(size) else { return -LINUX_EBUSY; }; let storage = if size == 0 { core::ptr::null_mut() } else { unsafe { alloc_zeroed(layout) } }; if size != 0 && storage.is_null() { return -LINUX_EBUSY; }
    let mut devices = DEVICES.lock(); let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && !rec.put_pending && !rec.unplugged) else { unsafe { if !storage.is_null() { dealloc(storage, layout); } } return -LINUX_ENODEV; }; if rec.vblank.is_some() { unsafe { if !storage.is_null() { dealloc(storage, layout); } } return -LINUX_EBUSY; }
    // SAFETY: storage covers exactly num_crtcs ABI vblank records; device fields are verified offsets.
    unsafe { for pipe in 0..num_crtcs as usize { let entry = storage.add(pipe * DRM_VBLANK_CRTC_SIZE); write(entry.add(DRM_VBLANK_CRTC_DEV_OFF).cast::<*mut c_void>(), dev); write(entry.add(DRM_VBLANK_CRTC_PIPE_OFF).cast::<u32>(), pipe as u32); } write(dev.cast::<u8>().add(DRM_DEVICE_VBLANK_OFF).cast::<*mut u8>(), storage); write(dev.cast::<u8>().add(DRM_DEVICE_NUM_CRTCS_OFF).cast::<u32>(), num_crtcs); }
    rec.vblank = Some((storage as usize, layout)); 0
}

/// Take one lifetime reference held by the caller. # C: O(N_devices)
extern "C" fn drm_dev_get(dev: *mut c_void) {
    if dev.is_null() { return; }
    let mut devices = DEVICES.lock();
    if let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && !rec.put_pending) { rec.refs = rec.refs.saturating_add(1); }
}

fn is_live_device(dev: *mut c_void) -> bool {
    !dev.is_null() && DEVICES.lock().iter().any(|rec| rec.dev == dev as usize && !rec.put_pending && !rec.unplugged)
}

/// Perform Linux `drm_master_open`'s primary-node ownership decision.
///
/// Render nodes deliberately never enter this path. The first primary open
/// becomes current master and is authenticated; later opens are clients until
/// that file is released. # C: O(N_devices)
pub(super) fn claim_primary_master(dev: *mut c_void, file: *mut c_void) -> bool {
    if dev.is_null() || file.is_null() { return false; }
    let mut devices = DEVICES.lock();
    let Some(record) = devices.iter_mut().find(|record| record.dev == dev as usize && !record.put_pending && !record.unplugged) else { return false; };
    if record.primary_master.is_some() { return false; }
    record.primary_master = Some(file as usize);
    true
}

/// Release a primary node's current-master ownership at close/failure.
/// # C: O(N_devices)
pub(super) fn release_primary_master(dev: *mut c_void, file: *mut c_void) {
    if dev.is_null() || file.is_null() { return; }
    let mut devices = DEVICES.lock();
    if let Some(record) = devices.iter_mut().find(|record| record.dev == dev as usize) {
        if record.primary_master == Some(file as usize) { record.primary_master = None; }
    }
}

/// Initialize the KMS mode-object lists embedded in a managed DRM device. # C: O(1)
extern "C" fn drmm_mode_config_init(dev: *mut c_void) -> i32 {
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
    0
}

/// Allocate and publish a KMS object identifier in one device's mode configuration. # C: O(N_objects)
extern "C" fn drm_mode_object_add(dev: *mut c_void, object: *mut c_void, obj_type: u32) -> i32 {
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
extern "C" fn drm_mode_object_unregister(dev: *mut c_void, object: *mut c_void) {
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
unsafe extern "C" fn drm_universal_plane_init(
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
    let base = unsafe { plane.cast::<u8>().add(DRM_PLANE_BASE_OFF).cast() };
    let object_result = drm_mode_object_add(dev, base, DRM_MODE_OBJECT_PLANE);
    if object_result != 0 {
        // SAFETY: copied has not been published and is released with the allocation layout above.
        unsafe { dealloc(copied, layout); }
        return object_result;
    }
    let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) else { unsafe { dealloc(copied, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_ENODEV; };
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: the object was accepted by drm_mode_object_add and every plane/config offset is verified ABI layout.
    let index = unsafe { *(config.add(MODE_CONFIG_NUM_TOTAL_PLANE_OFF).cast::<i32>()) };
    if index >= MAX_KMS_OBJECTS { unsafe { dealloc(copied, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_EBUSY; }
    unsafe {
        let head = plane.cast::<u8>().add(DRM_PLANE_HEAD_OFF).cast::<*mut c_void>(); let list = config.add(MODE_CONFIG_PLANE_LIST_OFF).cast::<*mut c_void>(); let tail = *list.add(1);
        write(head, list.cast()); write(head.add(1), tail); write(tail as *mut *mut c_void, head.cast()); write(list.add(1), head.cast()); write(plane.cast::<u8>().cast::<*mut c_void>(), dev);
        write(plane.cast::<u8>().add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>(), possible_crtcs); write(plane.cast::<u8>().add(DRM_PLANE_FORMATS_OFF).cast::<*mut u32>(), copied.cast()); write(plane.cast::<u8>().add(DRM_PLANE_FORMAT_COUNT_OFF).cast::<u32>(), format_count);
        write(plane.cast::<u8>().add(DRM_PLANE_FUNCS_OFF).cast::<*const c_void>(), funcs); write(plane.cast::<u8>().add(DRM_PLANE_TYPE_OFF).cast::<i32>(), plane_type); write(plane.cast::<u8>().add(DRM_PLANE_INDEX_OFF).cast::<u32>(), index as u32); write(config.add(MODE_CONFIG_NUM_TOTAL_PLANE_OFF).cast::<i32>(), index + 1);
    }
    rec.planes.push(PlaneRecord { ptr: plane as usize, formats: copied as usize, layout });
    0
}

/// Detach a universal plane and release its copied format table. # C: O(N_planes + N_objects)
extern "C" fn drm_plane_cleanup(plane: *mut c_void) {
    if plane.is_null() { return; }
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
    drm_mode_object_unregister(dev, unsafe { plane.cast::<u8>().add(DRM_PLANE_BASE_OFF).cast() });
}

fn kms_name(prefix: &[u8], index: i32) -> Option<(usize, Layout)> {
    let layout = Layout::array::<u8>(prefix.len() + 11).ok()?;
    // SAFETY: layout holds the supplied prefix, ten decimal digits and a terminator.
    let name = unsafe { alloc_zeroed(layout) };
    if name.is_null() { return None; }
    // SAFETY: name has room for the complete bounded decimal representation and terminator.
    unsafe { core::ptr::copy_nonoverlapping(prefix.as_ptr(), name, prefix.len()); let mut value = index as u32; let mut digits = [0u8; 10]; let mut len = 1; digits[0] = b'0' + (value % 10) as u8; while value >= 10 { value /= 10; digits[len] = b'0' + (value % 10) as u8; len += 1; } for pos in 0..len { *name.add(prefix.len() + pos) = digits[len - pos - 1]; } }
    Some((name as usize, layout))
}

/// Initialize one CRTC and attach its legacy planes to the managed KMS graph. # C: O(N_crtcs + N_objects)
unsafe extern "C" fn drm_crtc_init_with_planes(
    dev: *mut c_void, crtc: *mut c_void, primary: *mut c_void, cursor: *mut c_void,
    funcs: *const c_void, _name: *const core::ffi::c_char, mut _args: ...,
) -> i32 {
    if crtc.is_null() || funcs.is_null() { return -LINUX_EINVAL; }
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    let index = { let devices = DEVICES.lock(); if !devices.iter().any(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) { return -LINUX_ENODEV; } unsafe { *(config.add(MODE_CONFIG_NUM_CRTC_OFF).cast::<i32>()) } };
    if index >= MAX_KMS_OBJECTS { return -LINUX_EINVAL; }
    let Some((name, layout)) = kms_name(b"crtc-", index) else { return -LINUX_EBUSY; };
    let base = unsafe { crtc.cast::<u8>().add(DRM_CRTC_BASE_OFF).cast() };
    let object_result = drm_mode_object_add(dev, base, DRM_MODE_OBJECT_CRTC);
    if object_result != 0 { unsafe { dealloc(name as *mut u8, layout); } return object_result; }
    let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) else { unsafe { dealloc(name as *mut u8, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_ENODEV; };
    let index = unsafe { *(config.add(MODE_CONFIG_NUM_CRTC_OFF).cast::<i32>()) };
    if index >= MAX_KMS_OBJECTS { unsafe { dealloc(name as *mut u8, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_EINVAL; }
    // SAFETY: crtc, its optional plane objects, and the mode-config graph use the verified ABI offsets; all mutations are serialized by DEVICES.
    unsafe {
        let head = crtc.cast::<u8>().add(DRM_CRTC_HEAD_OFF).cast::<*mut c_void>(); let list = config.add(MODE_CONFIG_CRTC_LIST_OFF).cast::<*mut c_void>(); let tail = *list.add(1);
        write(head, list.cast()); write(head.add(1), tail); write(tail as *mut *mut c_void, head.cast()); write(list.add(1), head.cast()); write(crtc.cast::<*mut c_void>(), dev); write(crtc.cast::<u8>().add(32).cast::<*mut u8>(), name as *mut u8); write(crtc.cast::<u8>().add(DRM_CRTC_FUNCS_OFF).cast::<*const c_void>(), funcs); write(crtc.cast::<u8>().add(DRM_CRTC_PRIMARY_OFF).cast::<*mut c_void>(), primary); write(crtc.cast::<u8>().add(DRM_CRTC_CURSOR_OFF).cast::<*mut c_void>(), cursor); write(crtc.cast::<u8>().add(DRM_CRTC_INDEX_OFF).cast::<u32>(), index as u32); write(config.add(MODE_CONFIG_NUM_CRTC_OFF).cast::<i32>(), index + 1);
        if !primary.is_null() && *(primary.cast::<u8>().add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>()) == 0 { write(primary.cast::<u8>().add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>(), 1u32 << index); }
        if !cursor.is_null() && *(cursor.cast::<u8>().add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>()) == 0 { write(cursor.cast::<u8>().add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>(), 1u32 << index); }
    }
    rec.crtcs.push(CrtcRecord { ptr: crtc as usize, name, layout });
    0
}

/// Detach a CRTC from its device mode graph and release its core-owned name. # C: O(N_crtcs + N_objects)
extern "C" fn drm_crtc_cleanup(crtc: *mut c_void) {
    if crtc.is_null() { return; }
    let dev = unsafe { *(crtc.cast::<*mut c_void>()) }; let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return; };
    let Some(pos) = rec.crtcs.iter().position(|entry| entry.ptr == crtc as usize) else { return; }; let entry = rec.crtcs.remove(pos); let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: entry is the exact CRTC owned by this device, including its linked list node and allocated name.
    unsafe { let head = crtc.cast::<u8>().add(DRM_CRTC_HEAD_OFF).cast::<*mut c_void>(); let next = *head; let prev = *head.add(1); write(prev.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), prev); let count = config.add(MODE_CONFIG_NUM_CRTC_OFF).cast::<i32>(); if *count > 0 { write(count, *count - 1); } core::ptr::write_bytes(crtc.cast::<u8>(), 0, DRM_CRTC_FUNCS_OFF + core::mem::size_of::<*const c_void>()); dealloc(entry.name as *mut u8, entry.layout); }
    drop(devices); drm_mode_object_unregister(dev, unsafe { crtc.cast::<u8>().add(DRM_CRTC_BASE_OFF).cast() });
}

/// Initialize one encoder and attach it to the managed KMS object graph. # C: O(N_encoders + N_objects)
unsafe extern "C" fn drm_encoder_init(dev: *mut c_void, encoder: *mut c_void, funcs: *const c_void, encoder_type: i32, _name: *const core::ffi::c_char, mut _args: ...) -> i32 {
    if encoder.is_null() || funcs.is_null() { return -LINUX_EINVAL; }
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    let index = { let devices = DEVICES.lock(); if !devices.iter().any(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) { return -LINUX_ENODEV; } unsafe { *(config.add(MODE_CONFIG_NUM_ENCODER_OFF).cast::<i32>()) } };
    if index >= MAX_KMS_OBJECTS { return -LINUX_EINVAL; }
    let Some((name, layout)) = kms_name(b"encoder-", index) else { return -LINUX_EBUSY; }; let base = unsafe { encoder.cast::<u8>().add(DRM_ENCODER_BASE_OFF).cast() }; let object_result = drm_mode_object_add(dev, base, DRM_MODE_OBJECT_ENCODER);
    if object_result != 0 { unsafe { dealloc(name as *mut u8, layout); } return object_result; }
    let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) else { unsafe { dealloc(name as *mut u8, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_ENODEV; };
    let index = unsafe { *(config.add(MODE_CONFIG_NUM_ENCODER_OFF).cast::<i32>()) };
    if index >= MAX_KMS_OBJECTS { unsafe { dealloc(name as *mut u8, layout); } drop(devices); drm_mode_object_unregister(dev, base); return -LINUX_EINVAL; }
    // SAFETY: encoder and config offsets are verified ABI fields; list and count mutation is serialized by DEVICES.
    unsafe { let head = encoder.cast::<u8>().add(DRM_ENCODER_HEAD_OFF).cast::<*mut c_void>(); let list = config.add(MODE_CONFIG_ENCODER_LIST_OFF).cast::<*mut c_void>(); let tail = *list.add(1); write(head, list.cast()); write(head.add(1), tail); write(tail as *mut *mut c_void, head.cast()); write(list.add(1), head.cast()); write(encoder.cast::<*mut c_void>(), dev); write(encoder.cast::<u8>().add(DRM_ENCODER_NAME_OFF).cast::<*mut u8>(), name as *mut u8); write(encoder.cast::<u8>().add(DRM_ENCODER_TYPE_OFF).cast::<i32>(), encoder_type); write(encoder.cast::<u8>().add(DRM_ENCODER_INDEX_OFF).cast::<u32>(), index as u32); write(encoder.cast::<u8>().add(DRM_ENCODER_FUNCS_OFF).cast::<*const c_void>(), funcs); write(config.add(MODE_CONFIG_NUM_ENCODER_OFF).cast::<i32>(), index + 1); }
    rec.encoders.push(EncoderRecord { ptr: encoder as usize, name, layout }); 0
}

/// Detach an encoder from its device mode graph and release its core-owned name. # C: O(N_encoders + N_objects)
extern "C" fn drm_encoder_cleanup(encoder: *mut c_void) {
    if encoder.is_null() { return; } let dev = unsafe { *(encoder.cast::<*mut c_void>()) }; let mut devices = DEVICES.lock(); let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return; }; let Some(pos) = rec.encoders.iter().position(|entry| entry.ptr == encoder as usize) else { return; }; let entry = rec.encoders.remove(pos); let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: entry is the exact encoder owned by this device, including its linked node and name allocation.
    unsafe { let head = encoder.cast::<u8>().add(DRM_ENCODER_HEAD_OFF).cast::<*mut c_void>(); let next = *head; let prev = *head.add(1); write(prev.cast::<*mut c_void>(), next); write(next.cast::<*mut c_void>().add(1), prev); let count = config.add(MODE_CONFIG_NUM_ENCODER_OFF).cast::<i32>(); if *count > 0 { write(count, *count - 1); } core::ptr::write_bytes(encoder.cast::<u8>(), 0, DRM_ENCODER_FUNCS_OFF + core::mem::size_of::<*const c_void>()); dealloc(entry.name as *mut u8, entry.layout); }
    drop(devices); drm_mode_object_unregister(dev, unsafe { encoder.cast::<u8>().add(DRM_ENCODER_BASE_OFF).cast() });
}

/// Reset every driver KMS object in construction order after graph setup. # C: O(N_objects)
extern "C" fn drm_mode_config_reset(dev: *mut c_void) {
    let calls = { let devices = DEVICES.lock(); let Some(rec) = devices.iter().find(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) else { return; }; let mut calls = Vec::new(); for plane in &rec.planes { calls.push((plane.ptr, DRM_PLANE_FUNCS_OFF, 24usize)); } for crtc in &rec.crtcs { calls.push((crtc.ptr, DRM_CRTC_FUNCS_OFF, 0)); } for encoder in &rec.encoders { calls.push((encoder.ptr, DRM_ENCODER_FUNCS_OFF, 0)); } for connector in &rec.connectors { calls.push((connector.ptr, connector::DRM_CONNECTOR_FUNCS_OFF, 8)); } calls };
    for (object, funcs_off, reset_off) in calls {
        // SAFETY: each object remains owned by the live device record; the callback offsets are verified ABI fields and reset takes that object pointer.
        unsafe { let funcs = *(object as *mut u8).add(funcs_off).cast::<*const u8>(); if !funcs.is_null() { let reset = *(funcs.add(reset_off).cast::<Option<unsafe extern "C" fn(*mut c_void)>>()); if let Some(reset) = reset { reset(object as *mut c_void); } } }
    }
}

fn next_guard() -> i32 {
    loop {
        let id = NEXT_GUARD.fetch_add(1, Ordering::Relaxed);
        if id > 0 { return id; }
    }
}

/// Enter a live DRM-device critical section and return its release token.
/// # C: O(N_devices + N_guards)
extern "C" fn drm_dev_enter(dev: *mut c_void, idx: *mut i32) -> bool {
    if dev.is_null() || idx.is_null() { return false; }
    let id = next_guard();
    let devices = DEVICES.lock();
    if !devices.iter().any(|rec| rec.dev == dev as usize && !rec.put_pending && !rec.unplugged) { return false; }
    GUARDS.lock().push((id, dev as usize));
    // SAFETY: idx was checked non-null and the caller owns this one i32 output.
    unsafe { *idx = id; }
    true
}

/// Exit the DRM-device critical section identified by `drm_dev_enter`.
/// # C: O(N_guards)
extern "C" fn drm_dev_exit(idx: i32) {
    let dev = {
        let mut guards = GUARDS.lock();
        let Some(pos) = guards.iter().position(|(id, _)| *id == idx) else { return };
        guards.remove(pos).1
    };
    DRAIN_WAIT.wake_all();
    let mut rec = {
        let mut devices = DEVICES.lock();
        let Some(pos) = devices.iter().position(|rec| rec.dev == dev && rec.put_pending) else { return };
        devices.remove(pos)
    };
    release_planes(&mut rec);
    // SAFETY: the final guard removed this pending allocation and the record
    // was atomically removed before its original allocation is released.
    unsafe { dealloc(rec.base as *mut u8, rec.layout); }
}

fn guards_drained(dev: usize) -> bool { !GUARDS.lock().iter().any(|(_, guarded)| *guarded == dev) }

/// Make a DRM device inaccessible and wait until prior critical sections exit.
/// # C: O(N_devices + N_guards)
extern "C" fn drm_dev_unplug(dev: *mut c_void) {
    if dev.is_null() { return; }
    {
        let mut devices = DEVICES.lock();
        let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return };
        rec.unplugged = true;
    }
    // SAFETY: this runs in driver teardown process context and DRAIN_WAIT is
    // woken by every matching drm_dev_exit after it removes the guard token.
    let _ = unsafe { sched::live::wait_event_uninterruptible(&DRAIN_WAIT, || guards_drained(dev as usize)) };
}

#[cfg(test)]
mod tests;
