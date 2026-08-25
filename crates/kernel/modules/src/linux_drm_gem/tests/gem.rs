//! Focused tests for the DRM GEM handle, dumb-buffer, mmap, and framebuffer contracts.

use super::*;

#[test]
fn handles_are_file_owned_and_close_once() {
    let mut file = [0u8; 416]; let mut object = [0u8; 384]; let mut dev = [0u8; 64]; let mut handle = 0;
    assert!(file_init(file.as_mut_ptr().cast())); drm_gem_private_object_init(dev.as_mut_ptr().cast(), object.as_mut_ptr().cast(), 4096);
    // SAFETY: the test object reserves the complete ABI object and was initialized above.
    unsafe { assert_eq!(read(object.as_ptr().add(DRM_GEM_DEVICE_OFF).cast::<*mut c_void>()), dev.as_mut_ptr().cast()); assert_eq!(read(object.as_ptr().add(DRM_GEM_SIZE_OFF).cast::<usize>()), 4096); }
    assert_eq!(drm_gem_handle_create(file.as_mut_ptr().cast(), object.as_mut_ptr().cast(), &mut handle), 0); assert_eq!(handle, 1);
    assert_eq!(drm_gem_object_lookup(file.as_mut_ptr().cast(), handle), object.as_mut_ptr().cast()); assert_eq!(drm_gem_handle_delete(file.as_mut_ptr().cast(), handle), 0);
    assert!(drm_gem_object_lookup(file.as_mut_ptr().cast(), handle).is_null()); assert_eq!(drm_gem_handle_delete(file.as_mut_ptr().cast(), handle), -LINUX_EINVAL); file_release(dev.as_mut_ptr().cast(), file.as_mut_ptr().cast());
}

#[test]
fn generic_gem_entry_points_are_module_exports() {
    let _modules = crate::test_serial::claim();
    export_symbols();
    for name in ["drm_gem_private_object_init", "drm_gem_object_release", "drm_gem_handle_create", "drm_gem_handle_delete", "drm_gem_object_lookup", "drm_gem_release", "drm_gem_dumb_map_offset", "drm_mode_size_dumb", "drm_gem_shmem_dumb_create", "drm_gem_shmem_prime_import_no_map"] { assert!(crate::symtab::is_exported(name)); }
}

#[test]
fn dumb_size_rounds_pitch_and_size_and_rejects_overflow() {
    let mut args = [0u8; 32];
    // SAFETY: args reserves the complete dumb-buffer ABI record.
    unsafe { write(args.as_mut_ptr().add(DRM_DUMB_HEIGHT_OFF).cast::<u32>(), 768); write(args.as_mut_ptr().add(DRM_DUMB_WIDTH_OFF).cast::<u32>(), 1024); write(args.as_mut_ptr().add(DRM_DUMB_BPP_OFF).cast::<u32>(), 32); }
    assert_eq!(drm_mode_size_dumb(core::ptr::null_mut(), args.as_mut_ptr().cast(), 64, 0), 0);
    // SAFETY: successful sizing populated the checked output fields.
    unsafe { assert_eq!(read(args.as_ptr().add(DRM_DUMB_PITCH_OFF).cast::<u32>()), 4096); assert_eq!(read(args.as_ptr().add(DRM_DUMB_SIZE_OFF).cast::<u64>()), 3_145_728); write(args.as_mut_ptr().add(DRM_DUMB_WIDTH_OFF).cast::<u32>(), u32::MAX); }
    assert_eq!(drm_mode_size_dumb(core::ptr::null_mut(), args.as_mut_ptr().cast(), 0, 0), -LINUX_EINVAL);
}

#[test]
fn shmem_dumb_create_publishes_a_page_backed_handle_and_reclaims_it() {
    let mut file = [0u8; 416]; let mut dev = [0u8; 64]; let mut args = [0u8; 32];
    assert!(file_init(file.as_mut_ptr().cast()));
    // SAFETY: args reserves the complete dumb-buffer ABI record.
    unsafe { write(args.as_mut_ptr().add(DRM_DUMB_HEIGHT_OFF).cast::<u32>(), 4); write(args.as_mut_ptr().add(DRM_DUMB_WIDTH_OFF).cast::<u32>(), 8); write(args.as_mut_ptr().add(DRM_DUMB_BPP_OFF).cast::<u32>(), 32); }
    assert_eq!(drm_gem_shmem_dumb_create(file.as_mut_ptr().cast(), dev.as_mut_ptr().cast(), args.as_mut_ptr().cast()), 0);
    // SAFETY: successful creation populated handle and page-rounded size.
    let handle = unsafe { read(args.as_ptr().add(DRM_DUMB_HANDLE_OFF).cast::<u32>()) }; assert_ne!(handle, 0);
    let object = drm_gem_object_lookup(file.as_mut_ptr().cast(), handle); assert!(!object.is_null());
    // SAFETY: object is live through its file handle and contains the shmem backing pointer.
    unsafe { assert_eq!(read(object.cast::<u8>().add(DRM_GEM_SIZE_OFF).cast::<usize>()), PAGE_SIZE as usize); assert!(!read(object.cast::<u8>().add(DRM_GEM_SHMEM_VADDR_OFF).cast::<*mut u8>()).is_null()); }
    object_put(object);
    assert_eq!(drm_gem_handle_delete(file.as_mut_ptr().cast(), handle), 0); assert!(drm_gem_object_lookup(file.as_mut_ptr().cast(), handle).is_null()); file_release(dev.as_mut_ptr().cast(), file.as_mut_ptr().cast());
}

#[test]
fn dumb_map_offset_is_file_authorized_stable_and_page_aligned() {
    let mut file = [0u8; 416]; let mut dev = [0u8; 64]; let mut args = [0u8; 32]; let mut first = 0u64; let mut second = 0u64;
    assert!(file_init(file.as_mut_ptr().cast()));
    // SAFETY: args reserves drm_mode_create_dumb and receives one shmem object handle.
    unsafe { write(args.as_mut_ptr().add(DRM_DUMB_HEIGHT_OFF).cast::<u32>(), 4); write(args.as_mut_ptr().add(DRM_DUMB_WIDTH_OFF).cast::<u32>(), 8); write(args.as_mut_ptr().add(DRM_DUMB_BPP_OFF).cast::<u32>(), 32); }
    assert_eq!(drm_gem_shmem_dumb_create(file.as_mut_ptr().cast(), dev.as_mut_ptr().cast(), args.as_mut_ptr().cast()), 0);
    // SAFETY: the successful create call above populated args' handle field.
    let handle = unsafe { read(args.as_ptr().add(DRM_DUMB_HANDLE_OFF).cast::<u32>()) };
    assert_eq!(drm_gem_dumb_map_offset(file.as_mut_ptr().cast(), dev.as_mut_ptr().cast(), handle, &mut first), 0); assert_ne!(first, 0); assert_eq!(first % PAGE_SIZE, 0);
    assert_eq!(drm_gem_dumb_map_offset(file.as_mut_ptr().cast(), dev.as_mut_ptr().cast(), handle, &mut second), 0); assert_eq!(first, second);
    let object = mmap_object_lookup(file.as_mut_ptr().cast(), first / PAGE_SIZE, 1); assert!(!object.is_null()); object_put(object);
    assert!(mmap_object_lookup(file.as_mut_ptr().cast(), first / PAGE_SIZE + 1, 1).is_null()); assert_eq!(drm_gem_dumb_map_offset(file.as_mut_ptr().cast(), dev.as_mut_ptr().cast(), handle.wrapping_add(1), &mut second), -LINUX_EINVAL); file_release(dev.as_mut_ptr().cast(), file.as_mut_ptr().cast());
}

#[test]
fn gem_framebuffer_keeps_the_backing_object_after_handle_close() {
    let mut file = [0u8; 416]; let mut dev = [0u8; 64]; let mut dumb = [0u8; 32]; let mut cmd = [0u8; 104];
    assert!(file_init(file.as_mut_ptr().cast()));
    // SAFETY: dumb reserves drm_mode_create_dumb and receives one shmem handle.
    unsafe { write(dumb.as_mut_ptr().add(DRM_DUMB_HEIGHT_OFF).cast::<u32>(), 4); write(dumb.as_mut_ptr().add(DRM_DUMB_WIDTH_OFF).cast::<u32>(), 8); write(dumb.as_mut_ptr().add(DRM_DUMB_BPP_OFF).cast::<u32>(), 32); }
    assert_eq!(drm_gem_shmem_dumb_create(file.as_mut_ptr().cast(), dev.as_mut_ptr().cast(), dumb.as_mut_ptr().cast()), 0);
    // SAFETY: cmd reserves drm_mode_fb_cmd2 and is populated with matching dimensions/handle/pitch.
    unsafe { let handle = read(dumb.as_ptr().add(DRM_DUMB_HANDLE_OFF).cast::<u32>()); write(cmd.as_mut_ptr().add(DRM_FB_CMD_WIDTH_OFF).cast::<u32>(), 8); write(cmd.as_mut_ptr().add(DRM_FB_CMD_HEIGHT_OFF).cast::<u32>(), 4); write(cmd.as_mut_ptr().add(DRM_FB_CMD_HANDLES_OFF).cast::<u32>(), handle); write(cmd.as_mut_ptr().add(DRM_FB_CMD_PITCHES_OFF).cast::<u32>(), 32); }
    let info = format::drm_format_info(0x3432_5258).cast::<u8>(); let fb = drm_gem_fb_create_with_dirty(dev.as_mut_ptr().cast(), file.as_mut_ptr().cast(), info, cmd.as_ptr()); assert!(!fb.is_null());
    // SAFETY: successful creation retained the source GEM object in fb->obj[0].
    let object = unsafe { read(fb.cast::<u8>().add(DRM_FB_OBJECTS_OFF).cast::<*mut c_void>()) }; let handle = unsafe { read(dumb.as_ptr().add(DRM_DUMB_HANDLE_OFF).cast::<u32>()) };
    // SAFETY: fb is the live framebuffer just created above; refcount is read
    // after framebuffer_get's balanced increment, before framebuffer_put's decrement.
    framebuffer_get(fb); assert_eq!(unsafe { read(fb.cast::<u8>().add(DRM_FB_REFCOUNT_OFF).cast::<i32>()) }, 2); framebuffer_put(fb);
    // SAFETY: one reference remains after the balanced temporary get/put pair.
    assert_eq!(unsafe { read(fb.cast::<u8>().add(DRM_FB_REFCOUNT_OFF).cast::<i32>()) }, 1);
    assert_eq!(drm_gem_handle_delete(file.as_mut_ptr().cast(), handle), 0); assert!(!object.is_null());
    framebuffer_put(fb); file_release(dev.as_mut_ptr().cast(), file.as_mut_ptr().cast());
}
