use super::*;
use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

#[repr(C, align(8))]
struct TestDriver([u8; 200]);

#[repr(C, align(8))]
struct TestPlane([u8; 1360]);

#[repr(C, align(8))]
struct TestCrtc([u8; 1228]);

#[repr(C, align(8))]
struct TestEncoder([u8; 128]);

#[repr(C, align(8))]
struct TestConnector([u8; 2280]);

const VERIFIED_MODE_CONFIG_NUM_CONNECTOR_OFF: usize = 236;
const VERIFIED_DRM_PLANE_BASE_OFF: usize = 80;
const VERIFIED_DRM_PLANE_POSSIBLE_CRTCS_OFF: usize = 112;
const VERIFIED_DRM_PLANE_FORMATS_OFF: usize = 120;
const VERIFIED_DRM_PLANE_FORMAT_COUNT_OFF: usize = 128;
const VERIFIED_DRM_PLANE_FUNCS_OFF: usize = 176;
const VERIFIED_DRM_PLANE_TYPE_OFF: usize = 1216;
const VERIFIED_DRM_PLANE_INDEX_OFF: usize = 1220;

fn device(parent: &mut LinuxDevice, size: usize) -> *mut c_void {
    let container = __devm_drm_dev_alloc(parent, core::ptr::null(), size, 64);
    // SAFETY: each caller supplies enough container bytes for the embedded device.
    unsafe { container.cast::<u8>().add(64).cast() }
}

#[test]
fn embedded_device_keeps_the_drivers_requested_offset() {
    let _modules = crate::test_serial::claim();
    let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 256);
    assert_eq!(DEVICES.lock()[0].dev, dev as usize); devres::release_device(&mut parent); assert!(DEVICES.lock().is_empty());
}

#[test]
fn allocation_returns_the_container_and_initializes_the_embedded_device() {
    let _modules = crate::test_serial::claim();
    let mut parent = LinuxDevice::new(); let mut driver = TestDriver([0; 200]); let features = 0x1234_5678u32;
    // SAFETY: TestDriver reserves the exact driver_features field range at its ABI offset.
    unsafe { write(driver.0.as_mut_ptr().add(DRM_DRIVER_FEATURES_OFF).cast::<u32>(), features); }
    let container = __devm_drm_dev_alloc(&mut parent, (&driver as *const TestDriver).cast(), 256, 64);
    // SAFETY: the allocation is 256 bytes and the embedded object begins at 64.
    let dev = unsafe { container.cast::<u8>().add(64) };
    // SAFETY: every field below was initialized within the checked embedded device range.
    unsafe { assert_eq!(*(dev.add(DRM_DEVICE_REF_OFF).cast::<i32>()), INITIAL_REFERENCE_COUNT); assert!(*(dev.add(DRM_DEVICE_DEV_OFF).cast::<*mut LinuxDevice>()) == &mut parent); assert!(*(dev.add(DRM_DEVICE_DMA_DEV_OFF).cast::<*mut LinuxDevice>()) == &mut parent); assert_eq!(*(dev.add(DRM_DEVICE_FINAL_KFREE_OFF).cast::<*mut u8>()), container.cast()); assert_eq!(*(dev.add(DRM_DEVICE_DRIVER_OFF).cast::<*const c_void>()), (&driver as *const TestDriver).cast()); assert_eq!(*(dev.add(DRM_DEVICE_FEATURES_OFF).cast::<u32>()), features); }
    devres::release_device(&mut parent);
}

#[test]
fn registration_publishes_and_withdraws_a_primary_drm_minor() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let mut driver = TestDriver([0; 200]); let fops = [0u8; 272];
    // SAFETY: TestDriver reserves the complete fops pointer field at its verified ABI offset.
    unsafe { write(driver.0.as_mut_ptr().add(192).cast::<*const c_void>(), fops.as_ptr().cast()); }
    let container = __devm_drm_dev_alloc(&mut parent, (&driver as *const TestDriver).cast(), 2048, 64); let dev = unsafe { container.cast::<u8>().add(64).cast::<c_void>() };
    assert_eq!(register::drm_dev_register(dev, 0), 0); assert!(vfs::lookup_chrdev(vfs::Devt::from_kdev(226 << 20)).is_some());
    register::drm_dev_unregister(dev); assert!(vfs::lookup_chrdev(vfs::Devt::from_kdev(226 << 20)).is_none()); devres::release_device(&mut parent);
}

static DRIVER_OPEN: AtomicUsize = AtomicUsize::new(0);
static DRIVER_CLOSE: AtomicUsize = AtomicUsize::new(0);
extern "C" fn test_file_open(_dev: *mut c_void, _file: *mut c_void) -> i32 { DRIVER_OPEN.fetch_add(1, AtomicOrdering::SeqCst); 0 }
extern "C" fn test_file_close(_dev: *mut c_void, _file: *mut c_void) { DRIVER_CLOSE.fetch_add(1, AtomicOrdering::SeqCst); }
static IOCTL_CALLS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn test_ioctl(dev: *mut c_void, data: *mut c_void, file: *mut c_void) -> i32 {
    if dev.is_null() || data.is_null() || file.is_null() { return -LINUX_EINVAL; }
    // SAFETY: test dispatch supplies a writable u32 payload and file context.
    unsafe { *(data.cast::<u32>()) = 0xfeed_beef; }
    IOCTL_CALLS.fetch_add(1, AtomicOrdering::SeqCst); 0
}

#[test]
fn private_ioctl_dispatch_validates_command_and_preserves_file_context() {
    let _modules = crate::test_serial::claim(); IOCTL_CALLS.store(0, AtomicOrdering::SeqCst);
    let mut parent = LinuxDevice::new(); let mut driver = TestDriver([0; 200]); let mut desc = [0u8; 24]; let mut minor = [0u8; 40]; let mut file_ctx = [0u8; 416]; let mut filp = [0u8; 184]; let mut data = 0u32;
    const CMD: u32 = 0xc004_6440;
    // SAFETY: raw arrays reserve their verified DRM ABI field ranges and the test handler uses only its u32 payload.
    unsafe { write(driver.0.as_mut_ptr().add(176).cast::<*const u8>(), desc.as_ptr()); write(driver.0.as_mut_ptr().add(184).cast::<i32>(), 1); write(desc.as_mut_ptr().cast::<u32>(), CMD); write(desc.as_mut_ptr().add(8).cast::<usize>(), test_ioctl as *const () as usize); }
    let container = __devm_drm_dev_alloc(&mut parent, (&driver as *const TestDriver).cast(), 2048, 64); let dev = unsafe { container.cast::<u8>().add(64).cast::<c_void>() };
    // SAFETY: context/minor/file arrays reserve the exact fields read by the dispatcher.
    unsafe { write(minor.as_mut_ptr().add(16).cast::<*mut c_void>(), dev); write(file_ctx.as_mut_ptr().add(72).cast::<*mut c_void>(), minor.as_mut_ptr().cast()); write(filp.as_mut_ptr().add(24).cast::<*mut c_void>(), file_ctx.as_mut_ptr().cast()); }
    assert_eq!(ioctl::drm_ioctl(filp.as_mut_ptr().cast(), CMD, (&mut data as *mut u32) as usize), 0); assert_eq!(data, 0xfeed_beef); assert_eq!(IOCTL_CALLS.load(AtomicOrdering::SeqCst), 1);
    data = 0;
    assert_eq!(ioctl::drm_compat_ioctl(filp.as_mut_ptr().cast(), CMD, (&mut data as *mut u32) as usize), 0); assert_eq!(data, 0xfeed_beef); assert_eq!(IOCTL_CALLS.load(AtomicOrdering::SeqCst), 2);
    assert_eq!(ioctl::drm_ioctl(filp.as_mut_ptr().cast(), 0, (&mut data as *mut u32) as usize), -25); assert_eq!(IOCTL_CALLS.load(AtomicOrdering::SeqCst), 2); devres::release_device(&mut parent);
}

#[test]
fn core_file_context_calls_driver_open_and_postclose_once() {
    let _modules = crate::test_serial::claim(); DRIVER_OPEN.store(0, AtomicOrdering::SeqCst); DRIVER_CLOSE.store(0, AtomicOrdering::SeqCst); let mut parent = LinuxDevice::new(); let mut driver = TestDriver([0; 200]); let mut fops = [0u8; 272];
    // SAFETY: raw ABI tables reserve the verified driver and file-operation callback slots.
    unsafe { write(driver.0.as_mut_ptr().add(8).cast::<usize>(), test_file_open as *const () as usize); write(driver.0.as_mut_ptr().add(16).cast::<usize>(), test_file_close as *const () as usize); write(driver.0.as_mut_ptr().add(192).cast::<*const c_void>(), fops.as_ptr().cast()); write(fops.as_mut_ptr().add(104).cast::<usize>(), file::drm_open as *const () as usize); write(fops.as_mut_ptr().add(120).cast::<usize>(), file::drm_release as *const () as usize); }
    let container = __devm_drm_dev_alloc(&mut parent, (&driver as *const TestDriver).cast(), 2048, 64); let dev = unsafe { container.cast::<u8>().add(64).cast::<c_void>() }; assert_eq!(register::drm_dev_register(dev, 0), 0);
    let mut inode = [0u8; 616]; let mut filp = [0u8; 184]; unsafe { write(inode.as_mut_ptr().add(76).cast::<u32>(), 226 << 20); } assert_eq!(file::drm_open(inode.as_mut_ptr().cast(), filp.as_mut_ptr().cast()), 0); assert_eq!(DRIVER_OPEN.load(AtomicOrdering::SeqCst), 1); assert!(!unsafe { read(filp.as_ptr().add(24).cast::<*mut c_void>()) }.is_null()); assert_eq!(file::drm_release(inode.as_mut_ptr().cast(), filp.as_mut_ptr().cast()), 0); assert_eq!(DRIVER_CLOSE.load(AtomicOrdering::SeqCst), 1); assert!(unsafe { read(filp.as_ptr().add(24).cast::<*mut c_void>()) }.is_null()); register::drm_dev_unregister(dev); devres::release_device(&mut parent);
}

#[test]
fn primary_open_assigns_one_authenticated_master_and_handoffs_on_close() {
    let _modules = crate::test_serial::claim();
    let mut parent = LinuxDevice::new(); let mut driver = TestDriver([0; 200]); let fops = [0u8; 272]; let mut desc = [0u8; 24]; let mut data = 0u32;
    const CMD: u32 = 0xc004_6440;
    // SAFETY: TestDriver and descriptor reserve their verified DRM ABI fields.
    unsafe {
        write(driver.0.as_mut_ptr().add(176).cast::<*const u8>(), desc.as_ptr());
        write(driver.0.as_mut_ptr().add(184).cast::<i32>(), 1);
        write(driver.0.as_mut_ptr().add(192).cast::<*const c_void>(), fops.as_ptr().cast());
        write(desc.as_mut_ptr().cast::<u32>(), CMD);
        write(desc.as_mut_ptr().add(4).cast::<u32>(), 1 << 1);
        write(desc.as_mut_ptr().add(8).cast::<usize>(), test_ioctl as *const () as usize);
    }
    let container = __devm_drm_dev_alloc(&mut parent, (&driver as *const TestDriver).cast(), 2048, 64);
    let dev = unsafe { container.cast::<u8>().add(64).cast::<c_void>() };
    assert_eq!(register::drm_dev_register(dev, 0), 0);
    let mut inode = [0u8; 616]; let mut first = [0u8; 184]; let mut second = [0u8; 184]; let mut third = [0u8; 184];
    // SAFETY: inode carries the primary drm rdev that register_primary published.
    unsafe { write(inode.as_mut_ptr().add(76).cast::<u32>(), 226 << 20); }
    assert_eq!(file::drm_open(inode.as_mut_ptr().cast(), first.as_mut_ptr().cast()), 0);
    assert_eq!(file::drm_open(inode.as_mut_ptr().cast(), second.as_mut_ptr().cast()), 0);
    // SAFETY: successful opens install complete drm_file pointers in private_data.
    unsafe {
        let first_file = read(first.as_ptr().add(24).cast::<*mut u8>());
        let second_file = read(second.as_ptr().add(24).cast::<*mut u8>());
        assert!(*first_file.add(0).cast::<bool>());
        assert!(*first_file.add(8).cast::<bool>());
        assert!(!*second_file.add(0).cast::<bool>());
        assert!(!*second_file.add(8).cast::<bool>());
    }
    assert_eq!(ioctl::drm_ioctl(first.as_mut_ptr().cast(), CMD, (&mut data as *mut u32) as usize), 0);
    assert_eq!(ioctl::drm_ioctl(second.as_mut_ptr().cast(), CMD, (&mut data as *mut u32) as usize), -13);
    assert_eq!(file::drm_release(inode.as_mut_ptr().cast(), first.as_mut_ptr().cast()), 0);
    assert_eq!(file::drm_open(inode.as_mut_ptr().cast(), third.as_mut_ptr().cast()), 0);
    // SAFETY: closing the current master releases the ownership slot, so the next primary open is master.
    unsafe {
        let third_file = read(third.as_ptr().add(24).cast::<*mut u8>());
        assert!(*third_file.add(0).cast::<bool>());
        assert!(*third_file.add(8).cast::<bool>());
    }
    assert_eq!(file::drm_release(inode.as_mut_ptr().cast(), second.as_mut_ptr().cast()), 0);
    assert_eq!(file::drm_release(inode.as_mut_ptr().cast(), third.as_mut_ptr().cast()), 0);
    register::drm_dev_unregister(dev); devres::release_device(&mut parent);
}

#[test]
fn mode_config_initializes_each_object_list_once() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: the mode config was initialized above, so every tracked list head is live.
    unsafe { for off in MODE_CONFIG_LISTS { let head = config.add(off).cast::<*mut c_void>(); if off == MODE_CONFIG_PROPERTY_LIST_OFF { assert_ne!(*head, head.cast()); assert_ne!(*head.add(1), head.cast()); } else { assert_eq!(*head, head.cast()); assert_eq!(*head.add(1), head.cast()); } } }
    assert_eq!(drmm_mode_config_init(dev), -LINUX_EBUSY); devres::release_device(&mut parent);
}

#[test]
fn invalid_embedded_offset_is_rejected_before_allocation() { let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); assert!(__devm_drm_dev_alloc(&mut parent, core::ptr::null(), 8, 8).is_null()); }

#[test]
fn exports_lifetime_entry_points() { let _modules = crate::test_serial::claim(); export_symbols(); for name in ["__devm_drm_dev_alloc", "drm_dev_put", "drm_dev_get", "drm_dev_enter", "drm_dev_exit", "drm_dev_unplug", "drmm_mode_config_init", "drm_mode_object_add", "drm_mode_object_unregister", "drm_universal_plane_init", "drm_plane_cleanup", "drm_crtc_init_with_planes", "drm_crtc_cleanup", "drm_encoder_init", "drm_encoder_cleanup", "drm_connector_init", "drm_connector_cleanup", "drm_helper_probe_detect", "drm_helper_probe_single_connector_modes"] { assert!(crate::symtab::is_exported(name)); } }

#[test]
fn critical_section_token_is_released_once() { let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 256); let mut token = 0; assert!(drm_dev_enter(dev, &mut token)); drm_dev_exit(token); assert!(GUARDS.lock().is_empty()); devres::release_device(&mut parent); }

#[test]
fn put_waits_for_the_last_critical_section() { let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 256); let mut token = 0; assert!(drm_dev_enter(dev, &mut token)); drm_dev_put(dev); assert!(!drm_dev_enter(dev, &mut 0)); drm_dev_exit(token); assert!(DEVICES.lock().is_empty()); devres::release_device(&mut parent); }

#[test]
fn unplug_refuses_new_entries_after_the_drain() { let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 256); drm_dev_unplug(dev); assert!(!drm_dev_enter(dev, &mut 0)); devres::release_device(&mut parent); }

#[test]
fn mode_objects_receive_reusable_ids_and_unregister_once() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut first = [0u8; 32]; let mut second = [0u8; 32];
    assert_eq!(drm_mode_object_add(dev, first.as_mut_ptr().cast(), 0xcccc_cccc), 0); assert_eq!(drm_mode_object_add(dev, second.as_mut_ptr().cast(), 0xdddd_dddd), 0);
    // SAFETY: successful creation initialized the first two u32 ABI fields of both objects.
    unsafe { assert_eq!(*(first.as_ptr().cast::<u32>()), 3); assert_eq!(*(second.as_ptr().cast::<u32>()), 4); assert_eq!(*(first.as_ptr().add(DRM_MODE_OBJECT_TYPE_OFF).cast::<u32>()), 0xcccc_cccc); }
    drm_mode_object_unregister(dev, first.as_mut_ptr().cast()); drm_mode_object_unregister(dev, first.as_mut_ptr().cast()); let mut reused = [0u8; 32]; assert_eq!(drm_mode_object_add(dev, reused.as_mut_ptr().cast(), 0), 0);
    // SAFETY: the lowest released object identifier is assigned to the new object.
    assert_eq!(unsafe { *(reused.as_ptr().cast::<u32>()) }, 3); devres::release_device(&mut parent);
}

#[test]
fn universal_plane_owns_formats_links_the_mode_list_and_cleans_up() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut plane = TestPlane([0; 1360]); let formats = [0x3432_5258u32, 0x3432_5241]; let funcs = 1u8;
    // SAFETY: plane has the verified drm_plane layout size and formats has two valid entries.
    assert_eq!(unsafe { drm_universal_plane_init(dev, plane.0.as_mut_ptr().cast(), 1, (&funcs as *const u8).cast(), formats.as_ptr(), formats.len() as u32, core::ptr::null(), 1, c"plane".as_ptr()) }, 0);
    // SAFETY: successful initialization populated the verified plane ABI fields.
    unsafe { assert_eq!(*(plane.0.as_ptr().add(VERIFIED_DRM_PLANE_BASE_OFF).cast::<u32>()), 3); assert_eq!(*(plane.0.as_ptr().add(VERIFIED_DRM_PLANE_BASE_OFF + DRM_MODE_OBJECT_TYPE_OFF).cast::<u32>()), DRM_MODE_OBJECT_PLANE); assert_eq!(*(plane.0.as_ptr().add(VERIFIED_DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>()), 1); assert_eq!(*(plane.0.as_ptr().add(VERIFIED_DRM_PLANE_FORMAT_COUNT_OFF).cast::<u32>()), 2); assert_eq!(*(plane.0.as_ptr().add(VERIFIED_DRM_PLANE_FUNCS_OFF).cast::<*const u8>()), &funcs); assert_eq!(*(plane.0.as_ptr().add(VERIFIED_DRM_PLANE_TYPE_OFF).cast::<i32>()), 1); assert_eq!(*(plane.0.as_ptr().add(VERIFIED_DRM_PLANE_INDEX_OFF).cast::<u32>()), 0); let copied = *(plane.0.as_ptr().add(VERIFIED_DRM_PLANE_FORMATS_OFF).cast::<*const u32>()); assert_ne!(copied, formats.as_ptr()); assert_eq!(*copied, formats[0]); }
    assert_eq!(DEVICES.lock()[0].planes.len(), 1); drm_plane_cleanup(plane.0.as_mut_ptr().cast()); assert_eq!(DEVICES.lock()[0].planes.len(), 0);
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: cleanup reinitializes the removed plane link and decrements the device plane count.
    unsafe { let head = plane.0.as_ptr().add(DRM_PLANE_HEAD_OFF).cast::<*mut c_void>(); assert_eq!(*head, head.cast::<c_void>().cast_mut()); assert_eq!(*(config.add(MODE_CONFIG_NUM_TOTAL_PLANE_OFF).cast::<i32>()), 0); }
    devres::release_device(&mut parent);
}

#[test]
fn crtc_links_legacy_planes_and_reverses_all_owned_state() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut plane = TestPlane([0; 1360]); let formats = [0x3432_5258u32]; let funcs = 1u8;
    // SAFETY: plane and CRTC reserve their verified ABI layouts; the CRTC gets a live primary plane and callback table address.
    assert_eq!(unsafe { drm_universal_plane_init(dev, plane.0.as_mut_ptr().cast(), 0, core::ptr::null(), formats.as_ptr(), 1, core::ptr::null(), 1, c"plane".as_ptr()) }, 0); let mut crtc = TestCrtc([0; 1228]); assert_eq!(unsafe { drm_crtc_init_with_planes(dev, crtc.0.as_mut_ptr().cast(), plane.0.as_mut_ptr().cast(), core::ptr::null_mut(), (&funcs as *const u8).cast(), core::ptr::null()) }, 0);
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: successful initialization populated these exact ABI fields and assigned the primary-plane CRTC mask.
    unsafe { assert_eq!(*(crtc.0.as_ptr().add(DRM_CRTC_BASE_OFF).cast::<u32>()), 4); assert_eq!(*(crtc.0.as_ptr().add(DRM_CRTC_PRIMARY_OFF).cast::<*mut c_void>()), plane.0.as_mut_ptr().cast()); assert_eq!(*(plane.0.as_ptr().add(DRM_PLANE_POSSIBLE_CRTCS_OFF).cast::<u32>()), 1); assert_eq!(*(config.add(MODE_CONFIG_NUM_CRTC_OFF).cast::<i32>()), 1); }
    drm_crtc_cleanup(crtc.0.as_mut_ptr().cast()); assert_eq!(DEVICES.lock()[0].crtcs.len(), 0); unsafe { assert_eq!(*(config.add(MODE_CONFIG_NUM_CRTC_OFF).cast::<i32>()), 0); assert_eq!(*(crtc.0.as_ptr().add(DRM_CRTC_BASE_OFF).cast::<u32>()), 0); }
    drm_plane_cleanup(plane.0.as_mut_ptr().cast()); devres::release_device(&mut parent);
}

#[test]
fn encoder_links_the_mode_graph_with_a_typed_id_and_cleans_up() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut encoder = TestEncoder([0; 128]); let funcs = 1u8;
    // SAFETY: encoder reserves the verified ABI layout and receives a valid callback table address.
    assert_eq!(unsafe { drm_encoder_init(dev, encoder.0.as_mut_ptr().cast(), (&funcs as *const u8).cast(), 10, core::ptr::null()) }, 0); let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: initialization assigned the core object type, type/index fields, and mode-config count.
    unsafe { assert_eq!(*(encoder.0.as_ptr().add(DRM_ENCODER_BASE_OFF).cast::<u32>()), 3); assert_eq!(*(encoder.0.as_ptr().add(DRM_ENCODER_BASE_OFF + DRM_MODE_OBJECT_TYPE_OFF).cast::<u32>()), DRM_MODE_OBJECT_ENCODER); assert_eq!(*(encoder.0.as_ptr().add(DRM_ENCODER_TYPE_OFF).cast::<i32>()), 10); assert_eq!(*(config.add(MODE_CONFIG_NUM_ENCODER_OFF).cast::<i32>()), 1); }
    drm_encoder_cleanup(encoder.0.as_mut_ptr().cast()); assert_eq!(DEVICES.lock()[0].encoders.len(), 0); unsafe { assert_eq!(*(config.add(MODE_CONFIG_NUM_ENCODER_OFF).cast::<i32>()), 0); assert_eq!(*(encoder.0.as_ptr().add(DRM_ENCODER_BASE_OFF).cast::<u32>()), 0); } devres::release_device(&mut parent);
}

#[test]
fn connector_links_the_mode_graph_and_cleans_up() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut connector = TestConnector([0; 2280]); let funcs = 1u8;
    assert_eq!(connector::drm_connector_init(dev, connector.0.as_mut_ptr().cast(), (&funcs as *const u8).cast(), 11), 0); let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    unsafe { assert_eq!(*(connector.0.as_ptr().add(connector::DRM_CONNECTOR_BASE_OFF).cast::<u32>()), 3); assert_eq!(*(connector.0.as_ptr().add(connector::DRM_CONNECTOR_BASE_OFF + DRM_MODE_OBJECT_TYPE_OFF).cast::<u32>()), connector::DRM_MODE_OBJECT_CONNECTOR); assert_eq!(*(connector.0.as_ptr().add(80).cast::<i32>()), 1); assert_ne!(*(connector.0.as_ptr().add(88).cast::<usize>()), 0); assert_eq!(*(config.add(VERIFIED_MODE_CONFIG_NUM_CONNECTOR_OFF).cast::<i32>()), 1); }
    connector::drm_connector_cleanup(connector.0.as_mut_ptr().cast()); assert_eq!(DEVICES.lock()[0].connectors.len(), 0); devres::release_device(&mut parent);
}

#[test]
fn probed_mode_links_to_the_connector_and_destroy_unlinks_it() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut connector = TestConnector([0; 2280]); let funcs = 1u8;
    assert_eq!(connector::drm_connector_init(dev, connector.0.as_mut_ptr().cast(), (&funcs as *const u8).cast(), 11), 0); let mode = mode::drm_mode_create(dev);
    assert!(!mode.is_null()); mode::drm_mode_probed_add(connector.0.as_mut_ptr().cast(), mode);
    // SAFETY: successful publication links the display-mode node into the connector's probed list.
    unsafe { let head = connector.0.as_mut_ptr().add(mode::DRM_CONNECTOR_PROBED_MODES_OFF).cast::<*mut c_void>(); let node = mode.cast::<u8>().add(mode::DRM_DISPLAY_MODE_HEAD_OFF).cast::<*mut c_void>(); assert_eq!(*head.add(1), node.cast()); assert_eq!(*node, head.cast()); assert_eq!(*node.add(1), head.cast()); }
    mode::drm_mode_destroy(dev, mode);
    // SAFETY: destruction restores the initialized empty-list relation.
    unsafe { let head = connector.0.as_mut_ptr().add(mode::DRM_CONNECTOR_PROBED_MODES_OFF).cast::<*mut c_void>(); assert_eq!(*head, head.cast()); assert_eq!(*head.add(1), head.cast()); }
    connector::drm_connector_cleanup(connector.0.as_mut_ptr().cast()); devres::release_device(&mut parent);
}

#[test]
fn mode_helpers_name_copy_duplicate_and_measure_refresh() {
    let _modules = crate::test_serial::claim(); let mut mode = [0u8; mode::DRM_DISPLAY_MODE_SIZE];
    // SAFETY: mode reserves the complete display-mode ABI object used by the helpers.
    unsafe { write(mode.as_mut_ptr().add(0).cast::<i32>(), 25175); write(mode.as_mut_ptr().add(4).cast::<u16>(), 640); write(mode.as_mut_ptr().add(10).cast::<u16>(), 800); write(mode.as_mut_ptr().add(14).cast::<u16>(), 480); write(mode.as_mut_ptr().add(20).cast::<u16>(), 525); }
    mode::drm_mode_set_name(mode.as_mut_ptr().cast()); assert_eq!(unsafe { core::ffi::CStr::from_ptr(mode.as_ptr().add(80).cast()) }, c"640x480"); assert_eq!(mode::drm_mode_vrefresh(mode.as_ptr().cast()), 60);
    let duplicate = mode::drm_mode_duplicate(core::ptr::null_mut(), mode.as_ptr().cast()); assert!(!duplicate.is_null()); assert_eq!(mode::drm_mode_vrefresh(duplicate), 60); mode::drm_mode_destroy(core::ptr::null_mut(), duplicate);
}

#[test]
fn mode_init_copies_values_but_zeros_list_linkage() {
    let _modules = crate::test_serial::claim(); let mut src = [0u8; mode::DRM_DISPLAY_MODE_SIZE]; let mut dst = [0xffu8; mode::DRM_DISPLAY_MODE_SIZE];
    // SAFETY: both buffers reserve complete display-mode ABI objects.
    unsafe { write(src.as_mut_ptr().cast::<i32>(), 25175); write(src.as_mut_ptr().add(mode::DRM_DISPLAY_MODE_HEAD_OFF).cast::<*mut c_void>(), 1usize as *mut c_void); write(src.as_mut_ptr().add(mode::DRM_DISPLAY_MODE_HEAD_OFF + core::mem::size_of::<*mut c_void>()).cast::<*mut c_void>(), 2usize as *mut c_void); }
    mode::drm_mode_init(dst.as_mut_ptr().cast(), src.as_ptr().cast());
    // SAFETY: mode initialization copies values while retaining the cleared destination list head.
    unsafe { assert_eq!(*(dst.as_ptr().cast::<i32>()), 25175); assert!(dst.as_ptr().add(mode::DRM_DISPLAY_MODE_HEAD_OFF).cast::<*mut c_void>().read().is_null()); assert!(dst.as_ptr().add(mode::DRM_DISPLAY_MODE_HEAD_OFF + core::mem::size_of::<*mut c_void>()).cast::<*mut c_void>().read().is_null()); }
}

#[test]
fn noedid_fallback_adds_the_reference_modes_with_both_bounds() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut connector = TestConnector([0; 2280]); let funcs = 1u8;
    assert_eq!(connector::drm_connector_init(dev, connector.0.as_mut_ptr().cast(), (&funcs as *const u8).cast(), 11), 0); assert_eq!(mode::drm_add_modes_noedid(connector.0.as_mut_ptr().cast(), 1024, 768), 5); assert_eq!(DEVICES.lock()[0].connectors[0].probed_modes.len(), 5);
    connector::drm_connector_cleanup(connector.0.as_mut_ptr().cast()); devres::release_device(&mut parent);
}

#[test]
fn preferred_mode_marks_each_matching_probed_mode() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut connector = TestConnector([0; 2280]); let funcs = 1u8;
    assert_eq!(connector::drm_connector_init(dev, connector.0.as_mut_ptr().cast(), (&funcs as *const u8).cast(), 11), 0); assert_eq!(mode::drm_add_modes_noedid(connector.0.as_mut_ptr().cast(), 640, 480), 1); mode::drm_set_preferred_mode(connector.0.as_mut_ptr().cast(), 640, 480);
    let mode = DEVICES.lock()[0].connectors[0].probed_modes[0]; assert_ne!(unsafe { *((mode as *const u8).add(62)) } & (1 << 3), 0); connector::drm_connector_cleanup(connector.0.as_mut_ptr().cast()); devres::release_device(&mut parent);
}

#[test]
fn connector_list_update_moves_probed_modes_to_the_live_list() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut connector = TestConnector([0; 2280]); let funcs = 1u8;
    assert_eq!(connector::drm_connector_init(dev, connector.0.as_mut_ptr().cast(), (&funcs as *const u8).cast(), 11), 0); assert_eq!(mode::drm_add_modes_noedid(connector.0.as_mut_ptr().cast(), 640, 480), 1); mode::drm_connector_list_update(connector.0.as_mut_ptr().cast()); assert_eq!(DEVICES.lock()[0].connectors[0].probed_modes.len(), 0); assert_eq!(DEVICES.lock()[0].connectors[0].modes.len(), 1);
    connector::drm_connector_cleanup(connector.0.as_mut_ptr().cast()); devres::release_device(&mut parent);
}

#[test]
fn connector_list_update_merges_preferred_and_replaces_stale_modes() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut connector = TestConnector([0; 2280]); let funcs = 1u8;
    assert_eq!(connector::drm_connector_init(dev, connector.0.as_mut_ptr().cast(), (&funcs as *const u8).cast(), 11), 0); assert_eq!(mode::drm_add_modes_noedid(connector.0.as_mut_ptr().cast(), 640, 480), 1); mode::drm_connector_list_update(connector.0.as_mut_ptr().cast()); let old = DEVICES.lock()[0].connectors[0].modes[0] as *mut c_void; let preferred = mode::drm_mode_duplicate(dev, old); unsafe { write(preferred.cast::<u8>().add(62), mode::DRM_MODE_TYPE_PREFERRED); } mode::drm_mode_probed_add(connector.0.as_mut_ptr().cast(), preferred); mode::drm_connector_list_update(connector.0.as_mut_ptr().cast());
    assert_eq!(DEVICES.lock()[0].connectors[0].modes.len(), 1); assert_ne!(unsafe { *((old as *const u8).add(62)) } & mode::DRM_MODE_TYPE_PREFERRED, 0); unsafe { write(old.cast::<u8>().add(mode::DRM_DISPLAY_MODE_STATUS_OFF).cast::<i32>(), mode::MODE_STATUS_STALE); } let replacement = mode::drm_mode_duplicate(dev, old); unsafe { write(replacement.cast::<u8>().add(62), mode::DRM_MODE_TYPE_USERDEF); write(replacement.cast::<u8>().add(mode::DRM_DISPLAY_MODE_STATUS_OFF).cast::<i32>(), 0); } mode::drm_mode_probed_add(connector.0.as_mut_ptr().cast(), replacement); mode::drm_connector_list_update(connector.0.as_mut_ptr().cast());
    assert_eq!(unsafe { *((old as *const u8).add(62)) }, mode::DRM_MODE_TYPE_USERDEF); assert_ne!(unsafe { *((old as *const u8).add(mode::DRM_DISPLAY_MODE_STATUS_OFF).cast::<i32>()) }, mode::MODE_STATUS_STALE); connector::drm_connector_cleanup(connector.0.as_mut_ptr().cast()); devres::release_device(&mut parent);
}

#[test]
fn connector_helper_add_publishes_the_helper_vtable() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut connector = TestConnector([0; 2280]); let funcs = 1u8; let helper = 2u8;
    assert_eq!(connector::drm_connector_init(dev, connector.0.as_mut_ptr().cast(), (&funcs as *const u8).cast(), 11), 0); connector::drm_connector_helper_add(connector.0.as_mut_ptr().cast(), (&helper as *const u8).cast()); assert_eq!(unsafe { *(connector.0.as_ptr().add(connector::DRM_CONNECTOR_HELPER_PRIVATE_OFF).cast::<*const u8>()) }, &helper as *const u8);
    connector::drm_connector_cleanup(connector.0.as_mut_ptr().cast()); devres::release_device(&mut parent);
}

extern "C" fn test_get_modes(_connector: *mut c_void) -> i32 { -1 }

#[test]
fn helper_get_modes_clamps_negative_callback_returns() {
    let _modules = crate::test_serial::claim(); let mut connector = TestConnector([0; 2280]); let table: [extern "C" fn(*mut c_void) -> i32; 1] = [test_get_modes];
    connector::drm_connector_helper_add(connector.0.as_mut_ptr().cast(), table.as_ptr().cast()); assert_eq!(unsafe { mode::connector_get_modes(connector.0.as_mut_ptr().cast()) }, 0);
}

extern "C" fn test_detect(_connector: *mut c_void, _force: bool) -> i32 { 99 }

#[test]
fn connector_detect_normalizes_invalid_callback_status() {
    let _modules = crate::test_serial::claim(); let mut connector = TestConnector([0; 2280]); let funcs: [usize; 3] = [0, 0, test_detect as *const () as usize];
    unsafe { write(connector.0.as_mut_ptr().add(connector::DRM_CONNECTOR_FUNCS_OFF).cast::<*const c_void>(), funcs.as_ptr().cast()); } assert_eq!(unsafe { connector::connector_detect(connector.0.as_mut_ptr().cast(), true) }, 3);
}

extern "C" fn helper_detect(_connector: *mut c_void, ctx: *mut c_void, force: bool) -> i32 { if ctx.is_null() && force { 2 } else { 3 } }

#[test]
fn helper_detect_precedes_connector_detect_callback() {
    let _modules = crate::test_serial::claim(); let mut connector = TestConnector([0; 2280]); let helper: [usize; 2] = [0, helper_detect as *const () as usize]; let funcs: [usize; 3] = [0, 0, test_detect as *const () as usize];
    unsafe { write(connector.0.as_mut_ptr().add(connector::DRM_CONNECTOR_FUNCS_OFF).cast::<*const c_void>(), funcs.as_ptr().cast()); } connector::drm_connector_helper_add(connector.0.as_mut_ptr().cast(), helper.as_ptr().cast()); assert_eq!(unsafe { connector::connector_detect(connector.0.as_mut_ptr().cast(), true) }, 2);
}

extern "C" fn add_one_mode(connector: *mut c_void) -> i32 { mode::drm_add_modes_noedid(connector, 640, 480) }

#[test]
fn helper_probe_publishes_driver_modes() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); let funcs: [usize; 3] = [0; 3]; let helper: [usize; 2] = [add_one_mode as *const () as usize, 0]; let mut connector = TestConnector([0; 2280]); assert_eq!(drmm_mode_config_init(dev), 0); assert_eq!(connector::drm_connector_init(dev, connector.0.as_mut_ptr().cast(), funcs.as_ptr().cast(), 11), 0); connector::drm_connector_helper_add(connector.0.as_mut_ptr().cast(), helper.as_ptr().cast());
    assert_eq!(probe::drm_helper_probe_single_connector_modes(connector.0.as_mut_ptr().cast(), 640, 480), 1); assert_eq!(DEVICES.lock()[0].connectors[0].modes.len(), 1); assert_eq!(unsafe { connector.0.as_ptr().add(connector::DRM_CONNECTOR_STATUS_OFF).cast::<i32>().read() }, connector::DRM_CONNECTOR_STATUS_CONNECTED); connector::drm_connector_cleanup(connector.0.as_mut_ptr().cast()); devres::release_device(&mut parent);
}

#[test]
fn connector_attachment_sets_only_its_live_encoder_bit() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let funcs = 1u8; let mut encoder = TestEncoder([0; 128]); let mut connector = TestConnector([0; 2280]);
    assert_eq!(unsafe { drm_encoder_init(dev, encoder.0.as_mut_ptr().cast(), (&funcs as *const u8).cast(), 10, core::ptr::null()) }, 0); assert_eq!(connector::drm_connector_init(dev, connector.0.as_mut_ptr().cast(), (&funcs as *const u8).cast(), 11), 0); assert_eq!(connector::drm_connector_attach_encoder(connector.0.as_mut_ptr().cast(), encoder.0.as_mut_ptr().cast()), 0);
    unsafe { assert_eq!(*(connector.0.as_ptr().add(connector::DRM_CONNECTOR_POSSIBLE_ENCODERS_OFF).cast::<u32>()), 1); }
    connector::drm_connector_cleanup(connector.0.as_mut_ptr().cast()); drm_encoder_cleanup(encoder.0.as_mut_ptr().cast()); devres::release_device(&mut parent);
}
