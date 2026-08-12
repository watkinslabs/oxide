use super::*;

#[repr(C, align(8))]
struct TestDriver([u8; DRM_DRIVER_FEATURES_OFF + core::mem::size_of::<u32>()]);

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
    let mut parent = LinuxDevice::new(); let mut driver = TestDriver([0; DRM_DRIVER_FEATURES_OFF + core::mem::size_of::<u32>()]); let features = 0x1234_5678u32;
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
fn mode_config_initializes_each_object_list_once() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: the mode config was initialized above, so every tracked list head is live.
    unsafe { for off in MODE_CONFIG_LISTS { let head = config.add(off).cast::<*mut c_void>(); assert_eq!(*head, head.cast()); assert_eq!(*head.add(1), head.cast()); } }
    assert_eq!(drmm_mode_config_init(dev), -LINUX_EBUSY); devres::release_device(&mut parent);
}

#[test]
fn invalid_embedded_offset_is_rejected_before_allocation() { let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); assert!(__devm_drm_dev_alloc(&mut parent, core::ptr::null(), 8, 8).is_null()); }

#[test]
fn exports_lifetime_entry_points() { let _modules = crate::test_serial::claim(); export_symbols(); for name in ["__devm_drm_dev_alloc", "drm_dev_put", "drm_dev_get", "drm_dev_enter", "drm_dev_exit", "drm_dev_unplug", "drmm_mode_config_init", "drm_mode_object_add", "drm_mode_object_unregister"] { assert!(crate::symtab::is_exported(name)); } }

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
    unsafe { assert_eq!(*(first.as_ptr().cast::<u32>()), 1); assert_eq!(*(second.as_ptr().cast::<u32>()), 2); assert_eq!(*(first.as_ptr().add(DRM_MODE_OBJECT_TYPE_OFF).cast::<u32>()), 0xcccc_cccc); }
    drm_mode_object_unregister(dev, first.as_mut_ptr().cast()); drm_mode_object_unregister(dev, first.as_mut_ptr().cast()); let mut reused = [0u8; 32]; assert_eq!(drm_mode_object_add(dev, reused.as_mut_ptr().cast(), 0), 0);
    // SAFETY: the lowest released object identifier is assigned to the new object.
    assert_eq!(unsafe { *(reused.as_ptr().cast::<u32>()) }, 1); devres::release_device(&mut parent);
}

#[test]
fn universal_plane_owns_formats_links_the_mode_list_and_cleans_up() {
    let _modules = crate::test_serial::claim(); let mut parent = LinuxDevice::new(); let dev = device(&mut parent, 2048); assert_eq!(drmm_mode_config_init(dev), 0); let mut plane = [0u8; 1360]; let formats = [0x3432_5258u32, 0x3432_5241];
    // SAFETY: plane has the verified drm_plane layout size and formats has two valid entries.
    assert_eq!(unsafe { drm_universal_plane_init(dev, plane.as_mut_ptr().cast(), 1, core::ptr::null(), formats.as_ptr(), formats.len() as u32, core::ptr::null(), 1, c"plane".as_ptr()) }, 0);
    // SAFETY: successful initialization populated the verified plane ABI fields.
    unsafe { assert_eq!(*(plane.as_ptr().add(DRM_PLANE_BASE_OFF).cast::<u32>()), 1); assert_eq!(*(plane.as_ptr().add(DRM_PLANE_FORMAT_COUNT_OFF).cast::<u32>()), 2); let copied = *(plane.as_ptr().add(DRM_PLANE_FORMATS_OFF).cast::<*const u32>()); assert_ne!(copied, formats.as_ptr()); assert_eq!(*copied, formats[0]); }
    assert_eq!(DEVICES.lock()[0].planes.len(), 1); drm_plane_cleanup(plane.as_mut_ptr().cast()); assert_eq!(DEVICES.lock()[0].planes.len(), 0);
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: cleanup reinitializes the removed plane link and decrements the device plane count.
    unsafe { let head = plane.as_ptr().add(DRM_PLANE_HEAD_OFF).cast::<*mut c_void>(); assert_eq!(*head, head.cast::<c_void>().cast_mut()); assert_eq!(*(config.add(MODE_CONFIG_NUM_TOTAL_PLANE_OFF).cast::<i32>()), 0); }
    devres::release_device(&mut parent);
}
