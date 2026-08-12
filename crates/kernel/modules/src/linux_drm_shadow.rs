//! DRM shadow-plane CPU mappings for shmem GEM framebuffers.

use super::*;

const LINUX_EINVAL: i32 = 22;
const DRM_PLANE_STATE_FB_OFF: usize = 16;
const DRM_SHADOW_MAPS_OFF: usize = 208;
const DRM_SHADOW_DATA_OFF: usize = 272;
const DRM_IOSYS_MAP_SIZE: usize = 16;
const DRM_FB_FORMAT_OFF: usize = 72;
const DRM_FB_OFFSETS_OFF: usize = 104;
const DRM_FB_OBJECTS_OFF: usize = 160;
const DRM_FORMAT_PLANES_OFF: usize = 5;
const DRM_GEM_SHMEM_VADDR_OFF: usize = 432;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_gem_begin_shadow_fb_access", drm_gem_begin_shadow_fb_access as *const () as usize, false);
    crate::symtab::export("drm_gem_end_shadow_fb_access", drm_gem_end_shadow_fb_access as *const () as usize, false);
}

/// Map every shmem GEM backing object used by a shadow-plane framebuffer. # C: O(N_planes)
pub(super) extern "C" fn drm_gem_begin_shadow_fb_access(_plane: *mut c_void, state: *mut c_void) -> i32 {
    if state.is_null() { return -LINUX_EINVAL; }
    // SAFETY: state is a complete drm_shadow_plane_state whose base framebuffer field is at this verified offset.
    let fb = unsafe { read(state.cast::<u8>().add(DRM_PLANE_STATE_FB_OFF).cast::<*mut u8>()) };
    if fb.is_null() { return 0; }
    // SAFETY: fb is a complete DRM framebuffer and format is initialized during framebuffer creation.
    let format = unsafe { read(fb.add(DRM_FB_FORMAT_OFF).cast::<*const u8>()) };
    if format.is_null() { return -LINUX_EINVAL; }
    // SAFETY: num_planes is a verified byte in the immutable format descriptor.
    let planes = unsafe { *format.add(DRM_FORMAT_PLANES_OFF) as usize };
    if planes == 0 || planes > 4 { return -LINUX_EINVAL; }
    for plane in 0..planes {
        // SAFETY: plane is bounded by DRM_FORMAT_MAX_PLANES and object/offset arrays have four fixed slots.
        let (object, offset) = unsafe { (read(fb.add(DRM_FB_OBJECTS_OFF + plane * core::mem::size_of::<*mut c_void>()).cast::<*mut u8>()), read(fb.add(DRM_FB_OFFSETS_OFF + plane * 4).cast::<u32>())) };
        if object.is_null() { drm_gem_end_shadow_fb_access(core::ptr::null_mut(), state); return -LINUX_EINVAL; }
        // SAFETY: shmem dumb GEM creation publishes the backing vaddr at this verified shmem-object offset.
        let vaddr = unsafe { read(object.add(DRM_GEM_SHMEM_VADDR_OFF).cast::<*mut u8>()) };
        let Some(data) = (!vaddr.is_null()).then(|| unsafe { vaddr.add(offset as usize) }) else { drm_gem_end_shadow_fb_access(core::ptr::null_mut(), state); return -LINUX_EINVAL; };
        // SAFETY: map/data slots are exact iosys_map records; a shmem mapping is normal memory, so is_iomem remains false.
        unsafe { write(state.cast::<u8>().add(DRM_SHADOW_MAPS_OFF + plane * DRM_IOSYS_MAP_SIZE).cast::<*mut u8>(), vaddr); write(state.cast::<u8>().add(DRM_SHADOW_DATA_OFF + plane * DRM_IOSYS_MAP_SIZE).cast::<*mut u8>(), data); }
    }
    0
}

/// Drop the transient CPU mapping records published for a shadow-plane framebuffer. # C: O(N_planes)
pub(super) extern "C" fn drm_gem_end_shadow_fb_access(_plane: *mut c_void, state: *mut c_void) {
    if state.is_null() { return; }
    // SAFETY: state owns four fixed iosys_map pairs; clearing their address field ends CPU access without freeing the GEM backing.
    unsafe { for plane in 0..4 { write(state.cast::<u8>().add(DRM_SHADOW_MAPS_OFF + plane * DRM_IOSYS_MAP_SIZE).cast::<*mut u8>(), core::ptr::null_mut()); write(state.cast::<u8>().add(DRM_SHADOW_DATA_OFF + plane * DRM_IOSYS_MAP_SIZE).cast::<*mut u8>(), core::ptr::null_mut()); } }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_access_maps_the_framebuffer_gem_data_at_its_offset() {
        let mut state = [0u8; 336]; let mut fb = [0u8; 192]; let mut object = [0u8; 448]; let mut format = [0u8; 24]; let mut backing = [0u8; 64];
        format[DRM_FORMAT_PLANES_OFF] = 1;
        // SAFETY: each test array reserves the complete ABI record used at the written offsets.
        unsafe { write(state.as_mut_ptr().add(DRM_PLANE_STATE_FB_OFF).cast::<*mut u8>(), fb.as_mut_ptr()); write(fb.as_mut_ptr().add(DRM_FB_FORMAT_OFF).cast::<*const u8>(), format.as_ptr()); write(fb.as_mut_ptr().add(DRM_FB_OBJECTS_OFF).cast::<*mut u8>(), object.as_mut_ptr()); write(fb.as_mut_ptr().add(DRM_FB_OFFSETS_OFF).cast::<u32>(), 8); write(object.as_mut_ptr().add(DRM_GEM_SHMEM_VADDR_OFF).cast::<*mut u8>(), backing.as_mut_ptr()); }
        assert_eq!(drm_gem_begin_shadow_fb_access(core::ptr::null_mut(), state.as_mut_ptr().cast()), 0);
        // SAFETY: successful begin fills the first map/data iosys_map address fields.
        unsafe { assert_eq!(read(state.as_ptr().add(DRM_SHADOW_MAPS_OFF).cast::<*mut u8>()), backing.as_mut_ptr()); assert_eq!(read(state.as_ptr().add(DRM_SHADOW_DATA_OFF).cast::<*mut u8>()), backing.as_mut_ptr().add(8)); }
        drm_gem_end_shadow_fb_access(core::ptr::null_mut(), state.as_mut_ptr().cast());
        // SAFETY: end clears each published address slot.
        assert!(unsafe { read(state.as_ptr().add(DRM_SHADOW_MAPS_OFF).cast::<*mut u8>()) }.is_null());
    }

    #[test]
    fn shadow_access_entry_points_are_module_exports() {
        export_symbols();
        assert!(crate::symtab::is_exported("drm_gem_begin_shadow_fb_access"));
        assert!(crate::symtab::is_exported("drm_gem_end_shadow_fb_access"));
    }
}
