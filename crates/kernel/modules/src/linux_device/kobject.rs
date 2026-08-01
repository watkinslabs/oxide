use super::format::format_into;
use super::registry;
use super::types::{LinuxAttribute, LinuxKobjType, LinuxKobject, DEVICE_NAME_LEN, LINUX_EINVAL, LINUX_OK};
use core::ffi::c_char;

const KOBJ_ADD: u32 = 0;
const KOBJ_REMOVE: u32 = 1;
const KOBJ_CHANGE: u32 = 2;

/// Register Linux kobject/sysfs KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("kobject_init",      kobject_init      as *const () as usize),
        ("kobject_get",       kobject_get       as *const () as usize),
        ("kobject_put",       kobject_put       as *const () as usize),
        ("kobject_name",      kobject_name      as *const () as usize),
        ("kobject_set_name",  kobject_set_name  as *const () as usize),
        ("kobject_uevent",    kobject_uevent    as *const () as usize),
        ("sysfs_create_file", sysfs_create_file as *const () as usize),
        ("sysfs_remove_file", sysfs_remove_file as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn kobject_init(kobj: *mut LinuxKobject, ktype: *const LinuxKobjType) {
    if kobj.is_null() { return; }
    // SAFETY: kobj points at caller-owned Linux kobject storage.
    unsafe {
        (*kobj).name = core::ptr::null();
        (*kobj).parent = core::ptr::null_mut();
        (*kobj).kset = core::ptr::null_mut();
        (*kobj).ktype = ktype;
        (*kobj).private = core::ptr::null_mut();
        (*kobj).refcount = 1;
        (*kobj).name_buf = [0; DEVICE_NAME_LEN];
    }
    registry::initialize_kobject(kobj as usize);
}

extern "C" fn kobject_get(kobj: *mut LinuxKobject) -> *mut LinuxKobject {
    if kobj.is_null() { return core::ptr::null_mut(); }
    // SAFETY: kobj points at initialized Linux kobject storage.
    unsafe { (*kobj).refcount = (*kobj).refcount.saturating_add(1); }
    registry::get_kobject(kobj as usize);
    kobj
}

extern "C" fn kobject_put(kobj: *mut LinuxKobject) {
    if kobj.is_null() { return; }
    // SAFETY: kobj points at initialized Linux kobject storage.
    let final_put = unsafe {
        (*kobj).refcount = (*kobj).refcount.saturating_sub(1);
        (*kobj).refcount == 0
    };
    if !final_put { return; }
    registry::remove_kobject(kobj as usize);
    // SAFETY: release is the Linux kobject type callback installed by caller.
    unsafe {
        let ktype = (*kobj).ktype;
        if !ktype.is_null() {
            if let Some(release) = (*ktype).release { release(kobj); }
        }
    }
}

extern "C" fn kobject_name(kobj: *const LinuxKobject) -> *const c_char {
    if kobj.is_null() { return core::ptr::null(); }
    // SAFETY: kobj points at Linux kobject storage.
    unsafe { (*kobj).name }
}

unsafe extern "C" fn kobject_set_name(kobj: *mut LinuxKobject, fmt: *const c_char, mut ap: ...) -> i32 {
    if kobj.is_null() || fmt.is_null() { return -LINUX_EINVAL; }
    // SAFETY: fmt and ap follow Linux printf-style varargs contract.
    unsafe {
        format_into((*kobj).name_buf.as_mut_ptr(), DEVICE_NAME_LEN, fmt, &mut ap);
        (*kobj).name = (*kobj).name_buf.as_ptr();
    }
    LINUX_OK
}

extern "C" fn kobject_uevent(kobj: *mut LinuxKobject, action: u32) -> i32 {
    if kobj.is_null() { return -LINUX_EINVAL; }
    match action {
        KOBJ_ADD | KOBJ_REMOVE | KOBJ_CHANGE => {
            registry::record_kobject_uevent(kobj as usize);
            LINUX_OK
        }
        _ => -LINUX_EINVAL,
    }
}

extern "C" fn sysfs_create_file(kobj: *mut LinuxKobject, attr: *const LinuxAttribute) -> i32 {
    if kobj.is_null() || attr.is_null() { -LINUX_EINVAL } else { registry::add_kobject_attr(kobj as usize, attr as usize) }
}

extern "C" fn sysfs_remove_file(kobj: *mut LinuxKobject, attr: *const LinuxAttribute) {
    if kobj.is_null() || attr.is_null() { return; }
    registry::remove_kobject_attr(kobj as usize, attr as usize);
}

#[cfg(test)]
pub(super) fn attr_count(kobj: *mut LinuxKobject) -> usize {
    registry::kobject_attr_count(kobj as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn release(_kobj: *mut LinuxKobject) {
        RELEASES.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn kobject_refs_names_attrs_and_uevents() {
        RELEASES.store(0, Ordering::Relaxed);
        let ktype = LinuxKobjType { release: Some(release) };
        let mut kobj = LinuxKobject::new();
        let attr = LinuxAttribute { name: c"state".as_ptr(), mode: 0o444 };
        kobject_init(&mut kobj, &ktype);
        // SAFETY: kobject_set_name's varargs contract is satisfied here — the literal format string carries exactly one integer conversion and exactly one int-sized argument is passed for it.
        assert_eq!(unsafe { kobject_set_name(&mut kobj, c"kobj%d".as_ptr(), 7u32) }, LINUX_OK);
        // SAFETY: the set_name above returned LINUX_OK, so name points into kobj.name_buf (64 bytes) holding "kobj7\0"; offset 4 is the last digit, well inside that buffer.
        assert_eq!(unsafe { *kobject_name(&kobj).add(4) as u8 }, b'7');
        assert_eq!(sysfs_create_file(&mut kobj, &attr), LINUX_OK);
        assert_eq!(attr_count(&mut kobj), 1);
        sysfs_remove_file(&mut kobj, &attr);
        assert_eq!(attr_count(&mut kobj), 0);
        assert_eq!(kobject_uevent(&mut kobj, KOBJ_CHANGE), LINUX_OK);
        assert_eq!(kobject_get(&mut kobj), &mut kobj as *mut _);
        kobject_put(&mut kobj);
        assert_eq!(RELEASES.load(Ordering::Relaxed), 0);
        kobject_put(&mut kobj);
        assert_eq!(RELEASES.load(Ordering::Relaxed), 1);
    }
}
