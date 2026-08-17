//! Reference-counted DRM mode-object ownership.

use super::*;

const DRM_MODE_OBJECT_REFCOUNT_OFF: usize = 16;
const DRM_MODE_OBJECT_FREE_CB_OFF: usize = 24;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_mode_object_get", drm_mode_object_get as *const () as usize, false);
    crate::symtab::export("drm_mode_object_put", drm_mode_object_put as *const () as usize, false);
}

pub(super) fn get(object: *mut c_void) {
    if object.is_null() { return; }
    // SAFETY: mode-object callers provide the embedded reference and callback fields at their ABI offsets.
    let (refs, free) = unsafe { (object.cast::<u8>().add(DRM_MODE_OBJECT_REFCOUNT_OFF).cast::<AtomicI32>(), read(object.cast::<u8>().add(DRM_MODE_OBJECT_FREE_CB_OFF).cast::<usize>())) };
    if free == 0 { return; }
    // SAFETY: a non-null callback means refs was initialized before the object was published.
    let refs = unsafe { &*refs };
    let mut current = refs.load(Ordering::Acquire);
    while current > 0 {
        match refs.compare_exchange_weak(current, current.saturating_add(1), Ordering::AcqRel, Ordering::Acquire) { Ok(_) => return, Err(next) => current = next }
    }
}

pub(super) fn put(object: *mut c_void) {
    if object.is_null() { return; }
    // SAFETY: mode-object callers provide the embedded reference and callback fields at their ABI offsets.
    let (refs, free) = unsafe { (object.cast::<u8>().add(DRM_MODE_OBJECT_REFCOUNT_OFF).cast::<AtomicI32>(), read(object.cast::<u8>().add(DRM_MODE_OBJECT_FREE_CB_OFF).cast::<usize>())) };
    if free == 0 { return; }
    // SAFETY: the callback-owning object initialized this atomic before it could be referenced.
    let refs = unsafe { &*refs };
    if refs.fetch_sub(1, Ordering::AcqRel) != 1 { return; }
    // SAFETY: the transition from the sole reference invokes Linux's kref release callback exactly once.
    unsafe { let release: extern "C" fn(*mut c_void) = core::mem::transmute(free); release(object.cast::<u8>().add(DRM_MODE_OBJECT_REFCOUNT_OFF).cast()); }
}

pub(super) extern "C" fn drm_mode_object_get(object: *mut c_void) { get(object); }
pub(super) extern "C" fn drm_mode_object_put(object: *mut c_void) { put(object); }

#[cfg(test)]
mod tests {
    use super::*;
    static RELEASES: AtomicI32 = AtomicI32::new(0);
    extern "C" fn release(_kref: *mut c_void) { RELEASES.fetch_add(1, Ordering::SeqCst); }
    #[test]
    fn reference_owner_releases_once_after_its_last_put() {
        let mut object = [0u8; 32]; RELEASES.store(0, Ordering::SeqCst);
        // SAFETY: object is a 32-byte stack array, sized past both fixed offsets
        // used below, owned exclusively by this test with no concurrent access.
        unsafe { write(object.as_mut_ptr().add(DRM_MODE_OBJECT_REFCOUNT_OFF).cast::<i32>(), 1); write(object.as_mut_ptr().add(DRM_MODE_OBJECT_FREE_CB_OFF).cast::<usize>(), release as *const () as usize); }
        get(object.as_mut_ptr().cast()); put(object.as_mut_ptr().cast()); assert_eq!(RELEASES.load(Ordering::SeqCst), 0); put(object.as_mut_ptr().cast()); assert_eq!(RELEASES.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn reference_entry_points_are_module_exports() { export_symbols(); assert!(crate::symtab::is_exported("drm_mode_object_get")); assert!(crate::symtab::is_exported("drm_mode_object_put")); }
}
