use super::format::format_into;
use super::registry;
use super::types::{LinuxAttribute, LinuxKobjType, LinuxKobjUeventEnv, LinuxKobject, DEVICE_NAME_LEN, LINUX_EINVAL, LINUX_ENOMEM, LINUX_OK};
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_char, CStr};

const KOBJ_REMOVE: u32 = 1;
const KOBJ_ADD: u32 = 0;
pub(super) const KOBJ_CHANGE: u32 = 2;
const KOBJ_UNBIND: u32 = 7;
const KOBJ_ACTIONS: [&str; 8] = ["add", "remove", "change", "move", "online", "offline", "bind", "unbind"];
const STATE_INITIALIZED: u32 = 1;
const STATE_ADD_UEVENT_SENT: u32 = 1 << 2;
const STATE_REMOVE_UEVENT_SENT: u32 = 1 << 3;
const UEVENT_SUPPRESS: u32 = 1 << 4;

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
        ("kobject_uevent_env", kobject_uevent_env as *const () as usize),
        ("add_uevent_var",    add_uevent_var    as *const () as usize),
        ("sysfs_create_file", sysfs_create_file as *const () as usize),
        ("sysfs_remove_file", sysfs_remove_file as *const () as usize),
        ("sysfs_create_link", sysfs_create_link as *const () as usize),
        ("sysfs_remove_link", sysfs_remove_link as *const () as usize),
        ("sysfs_add_link_to_group", sysfs_add_link_to_group as *const () as usize),
        ("sysfs_remove_link_from_group", sysfs_remove_link_from_group as *const () as usize),
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
        (*kobj).entry = [core::ptr::null_mut(); 2];
        (*kobj).sd = core::ptr::null_mut();
        (*kobj).kref = 1;
        (*kobj).state = STATE_INITIALIZED;
    }
    registry::initialize_kobject(kobj as usize);
}

extern "C" fn kobject_get(kobj: *mut LinuxKobject) -> *mut LinuxKobject {
    if kobj.is_null() { return core::ptr::null_mut(); }
    registry::get_kobject(kobj as usize);
    kobj
}

extern "C" fn kobject_put(kobj: *mut LinuxKobject) {
    if kobj.is_null() { return; }
    let final_put = registry::put_kobject(kobj as usize);
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
        let mut name = [0; DEVICE_NAME_LEN];
        format_into(name.as_mut_ptr(), DEVICE_NAME_LEN, fmt, &mut ap);
        (*kobj).name = registry::replace_kobject_name(kobj as usize, name);
    }
    LINUX_OK
}

pub(super) extern "C" fn kobject_uevent(kobj: *mut LinuxKobject, action: u32) -> i32 {
    kobject_uevent_env(kobj, action, core::ptr::null_mut())
}

pub(super) extern "C" fn kobject_uevent_env(kobj: *mut LinuxKobject, action: u32, envp_ext: *mut *mut c_char) -> i32 {
    if kobj.is_null() || action as usize >= KOBJ_ACTIONS.len() { return -LINUX_EINVAL; }
    // SAFETY: kobj was null-checked and is caller-owned live kobject storage for this event call.
    unsafe {
        if action == KOBJ_REMOVE { (*kobj).state |= STATE_REMOVE_UEVENT_SENT; }
        let mut top = kobj;
        while (*top).kset.is_null() && !(*top).parent.is_null() { top = (*top).parent; }
        if (*top).kset.is_null() { return -LINUX_EINVAL; }
        if (*kobj).state & UEVENT_SUPPRESS != 0 { return LINUX_OK; }
        let ops = (*(*top).kset).uevent_ops;
        if !ops.is_null() {
            if let Some(filter) = (*ops).filter {
                if filter(kobj) == 0 { return LINUX_OK; }
            }
        }
        let subsystem = if !ops.is_null() {
            match (*ops).name { Some(name) => name(kobj), None => (*(*top).kset).kobj.name }
        } else { (*(*top).kset).kobj.name };
        if subsystem.is_null() { return LINUX_OK; }
        let Ok(subsystem) = cstr_string(subsystem) else { return -LINUX_EINVAL; };
        let Ok(devpath) = kobject_path(kobj) else { return -LINUX_EINVAL; };
        let mut env = LinuxKobjUeventEnv::new();
        if let Some(rc) = add_default_env(&mut env, KOBJ_ACTIONS[action as usize], &devpath, &subsystem, envp_ext) { return rc; }
        if !ops.is_null() {
            if let Some(uevent) = (*ops).uevent {
                let rc = uevent(kobj, &mut env);
                if rc != LINUX_OK { return rc; }
            }
        }
        if action == KOBJ_ADD { (*kobj).state |= STATE_ADD_UEVENT_SENT; }
        if action == KOBJ_UNBIND { zap_modalias(&mut env); }
        let extras = env_entries(&env);
        let refs: Vec<&[u8]> = extras.iter().skip(3).map(Vec::as_slice).collect();
        netlink::emit_uevent_with_env_bytes(KOBJ_ACTIONS[action as usize], &devpath, &subsystem, &refs);
        registry::record_kobject_uevent(kobj as usize);
    }
    LINUX_OK
}

unsafe extern "C" fn add_uevent_var(env: *mut LinuxKobjUeventEnv, fmt: *const c_char, mut ap: ...) -> i32 {
    if env.is_null() || fmt.is_null() { return -LINUX_EINVAL; }
    let mut entry = [0 as c_char; 2048];
    // SAFETY: env/fmt were null-checked and `ap` matches the caller's printf format contract.
    unsafe { super::format::format_into_uevent(entry.as_mut_ptr(), entry.len(), fmt, &mut ap); }
    let len = entry.iter().position(|c| *c == 0).unwrap_or(entry.len());
    // SAFETY: `entry[..len]` is the formatter's bounded NUL-terminated output, and env is a live caller-provided environment.
    unsafe { add_env_bytes(&mut *env, &entry[..len].iter().map(|c| *c as u8).collect::<Vec<_>>()) }
}

unsafe fn cstr_string(ptr: *const c_char) -> Result<String, ()> {
    if ptr.is_null() { return Err(()); }
    // SAFETY: KPI callers provide a NUL-terminated C string for each kobject name and subsystem result.
    let bytes = unsafe { CStr::from_ptr(ptr).to_bytes() };
    core::str::from_utf8(bytes).map(String::from).map_err(|_| ())
}

unsafe fn kobject_path(kobj: *const LinuxKobject) -> Result<String, ()> {
    let mut names = Vec::new();
    let mut cur = kobj;
    while !cur.is_null() {
        // SAFETY: each link is from the caller-owned live kobject ancestry used during uevent construction.
        let name = unsafe { (*cur).name };
        if !name.is_null() { names.push(unsafe { cstr_string(name) }?); }
        // SAFETY: same live ancestry; the link is only read to continue toward the root.
        cur = unsafe { (*cur).parent };
    }
    if names.is_empty() { return Err(()); }
    let mut path = String::new();
    for name in names.iter().rev() { path.push('/'); path.push_str(name); }
    Ok(path)
}

unsafe fn add_default_env(env: &mut LinuxKobjUeventEnv, action: &str, devpath: &str, subsystem: &str, envp_ext: *mut *mut c_char) -> Option<i32> {
    for entry in [alloc::format!("ACTION={action}"), alloc::format!("DEVPATH={devpath}"), alloc::format!("SUBSYSTEM={subsystem}")] {
        let rc = unsafe { add_env_bytes(env, entry.as_bytes()) };
        if rc != LINUX_OK { return Some(rc); }
    }
    let mut ext = envp_ext;
    while !ext.is_null() {
        // SAFETY: envp_ext follows the KPI NULL-terminated vector contract.
        let entry = unsafe { *ext };
        if entry.is_null() { break; }
        // SAFETY: each vector element is a NUL-terminated environment string by the KPI contract.
        let bytes = unsafe { CStr::from_ptr(entry).to_bytes() };
        let rc = unsafe { add_env_bytes(env, bytes) };
        if rc != LINUX_OK { return Some(rc); }
        // SAFETY: the element above was valid, so increment remains within the caller's NULL-terminated vector.
        ext = unsafe { ext.add(1) };
    }
    None
}

unsafe fn add_env_bytes(env: &mut LinuxKobjUeventEnv, bytes: &[u8]) -> i32 {
    let idx = env.envp_idx.max(0) as usize;
    let used = env.buflen.max(0) as usize;
    if idx >= env.envp.len() || bytes.len().saturating_add(1) > env.buf.len().saturating_sub(used) { return -LINUX_ENOMEM; }
    // SAFETY: the capacity test above proves the output range is within env.buf, and the pointer remains valid while env lives.
    unsafe {
        let dst = env.buf.as_mut_ptr().add(used);
        for (offset, byte) in bytes.iter().enumerate() { *dst.add(offset) = *byte as c_char; }
        *dst.add(bytes.len()) = 0;
        env.envp[idx] = dst;
    }
    env.envp_idx += 1;
    env.buflen += bytes.len() as i32 + 1;
    LINUX_OK
}

fn env_entries(env: &LinuxKobjUeventEnv) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for ptr in env.envp.iter().take(env.envp_idx.max(0) as usize) {
        if ptr.is_null() { continue; }
        // SAFETY: add_uevent_var stores NUL-terminated entries in env.buf, and kset callbacks share the same C environment contract.
        out.push(unsafe { CStr::from_ptr(*ptr).to_bytes().to_vec() });
    }
    out
}

fn zap_modalias(env: &mut LinuxKobjUeventEnv) {
    let kept: Vec<Vec<u8>> = env_entries(env).into_iter().filter(|entry| !entry.starts_with(b"MODALIAS=")).collect();
    *env = LinuxKobjUeventEnv::new();
    for entry in kept { let _ = unsafe { add_env_bytes(env, &entry) }; }
}

extern "C" fn sysfs_create_file(kobj: *mut LinuxKobject, attr: *const LinuxAttribute) -> i32 {
    if kobj.is_null() || attr.is_null() { -LINUX_EINVAL } else { registry::add_kobject_attr(kobj as usize, attr as usize) }
}

extern "C" fn sysfs_remove_file(kobj: *mut LinuxKobject, attr: *const LinuxAttribute) {
    if kobj.is_null() || attr.is_null() { return; }
    registry::remove_kobject_attr(kobj as usize, attr as usize);
}

extern "C" fn sysfs_create_link(kobj: *mut LinuxKobject, target: *mut LinuxKobject, name: *const c_char) -> i32 {
    if kobj.is_null() || target.is_null() { return -LINUX_EINVAL; }
    registry::add_kobject_link(kobj as usize, target as usize, core::ptr::null(), name)
}

extern "C" fn sysfs_remove_link(kobj: *mut LinuxKobject, name: *const c_char) {
    if kobj.is_null() { return; }
    registry::remove_kobject_link(kobj as usize, core::ptr::null(), name);
}

extern "C" fn sysfs_add_link_to_group(kobj: *mut LinuxKobject, group: *const c_char, target: *mut LinuxKobject, name: *const c_char) -> i32 {
    if kobj.is_null() || target.is_null() || group.is_null() { return -LINUX_EINVAL; }
    registry::add_kobject_link(kobj as usize, target as usize, group, name)
}

extern "C" fn sysfs_remove_link_from_group(kobj: *mut LinuxKobject, group: *const c_char, name: *const c_char) {
    if kobj.is_null() || group.is_null() { return; }
    registry::remove_kobject_link(kobj as usize, group, name);
}

#[cfg(test)]
pub(super) fn attr_count(kobj: *mut LinuxKobject) -> usize {
    registry::kobject_attr_count(kobj as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASES: AtomicUsize = AtomicUsize::new(0);
    static CALLBACK_ENV_ENTRIES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn release(_kobj: *mut LinuxKobject) {
        RELEASES.fetch_add(1, Ordering::Relaxed);
    }

    unsafe extern "C" fn callback(_kobj: *const LinuxKobject, env: *mut LinuxKobjUeventEnv) -> i32 {
        // SAFETY: the uevent core passes its live environment to this synchronous kset callback.
        unsafe { CALLBACK_ENV_ENTRIES.store((*env).envp_idx as usize, Ordering::Relaxed); }
        LINUX_OK
    }

    #[test]
    fn kobject_refs_names_attrs_and_uevents() {
        let _modules = crate::test_serial::claim();
        RELEASES.store(0, Ordering::Relaxed);
        let ktype = LinuxKobjType {
            release: Some(release), sysfs_ops: core::ptr::null(), default_groups: core::ptr::null(),
            child_ns_type: core::ptr::null(), namespace: core::ptr::null(), get_ownership: core::ptr::null(),
        };
        let mut kset = super::super::types::LinuxKset {
            list: [core::ptr::null_mut(); 2], list_lock: 0, _pad: 0,
            kobj: LinuxKobject::new(), uevent_ops: core::ptr::null(),
        };
        let ops = super::super::types::LinuxKsetUeventOps { filter: None, name: None, uevent: Some(callback) };
        let mut kobj = LinuxKobject::new();
        let attr = LinuxAttribute { name: c"state".as_ptr(), mode: 0o444 };
        kobject_init(&mut kset.kobj, &ktype);
        // SAFETY: the literal needs no varargs and kset.kobj remains live through the child event.
        assert_eq!(unsafe { kobject_set_name(&mut kset.kobj, c"devices".as_ptr()) }, LINUX_OK);
        kobject_init(&mut kobj, &ktype);
        kset.uevent_ops = &ops;
        kobj.kset = &mut kset;
        // SAFETY: kobject_set_name's varargs contract is satisfied here — the literal format string carries exactly one integer conversion and exactly one int-sized argument is passed for it.
        assert_eq!(unsafe { kobject_set_name(&mut kobj, c"kobj%d".as_ptr(), 7u32) }, LINUX_OK);
        // SAFETY: the set_name above installed a live registry-owned NUL-terminated name buffer.
        assert_eq!(unsafe { *kobject_name(&kobj).add(4) as u8 }, b'7');
        assert_eq!(sysfs_create_file(&mut kobj, &attr), LINUX_OK);
        assert_eq!(attr_count(&mut kobj), 1);
        sysfs_remove_file(&mut kobj, &attr);
        assert_eq!(attr_count(&mut kobj), 0);
        let mut target = LinuxKobject::new();
        kobject_init(&mut target, &ktype);
        assert_eq!(sysfs_create_link(&mut kobj, &mut target, c"device".as_ptr()), LINUX_OK);
        assert_eq!(registry::kobject_link_count(&mut kobj as *mut _ as usize), 1);
        assert_eq!(registry::kobject_link_target(&mut kobj as *mut _ as usize), &mut target as *mut _ as usize);
        sysfs_remove_link(&mut kobj, c"device".as_ptr());
        assert_eq!(registry::kobject_link_count(&mut kobj as *mut _ as usize), 0);
        let group_create = [b'h' as c_char, b'o' as c_char, b'l' as c_char, b'd' as c_char, b'e' as c_char, b'r' as c_char, b's' as c_char, 0];
        let group_remove = [b'h' as c_char, b'o' as c_char, b'l' as c_char, b'd' as c_char, b'e' as c_char, b'r' as c_char, b's' as c_char, 0];
        assert_eq!(sysfs_add_link_to_group(&mut kobj, group_create.as_ptr(), &mut target, c"nvme0n1".as_ptr()), LINUX_OK);
        sysfs_remove_link_from_group(&mut kobj, group_remove.as_ptr(), c"nvme0n1".as_ptr());
        assert_eq!(registry::kobject_link_count(&mut kobj as *mut _ as usize), 0);
        CALLBACK_ENV_ENTRIES.store(0, Ordering::Relaxed);
        let mut extra = [c"RESIZE=1".as_ptr() as *mut c_char, core::ptr::null_mut()];
        assert_eq!(kobject_uevent_env(&mut kobj, KOBJ_CHANGE, extra.as_mut_ptr()), LINUX_OK);
        assert_eq!(CALLBACK_ENV_ENTRIES.load(Ordering::Relaxed), 4);
        assert_eq!(kobject_get(&mut kobj), &mut kobj as *mut _);
        kobject_put(&mut kobj);
        assert_eq!(RELEASES.load(Ordering::Relaxed), 0);
        kobject_put(&mut kobj);
        assert_eq!(RELEASES.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn kobject_uevent_abi_carries_complete_kset_environment() {
        assert_eq!((size_of::<LinuxKobject>(), align_of::<LinuxKobject>()), (64, 8));
        assert_eq!((size_of::<LinuxKobjType>(), align_of::<LinuxKobjType>()), (48, 8));
        assert_eq!((size_of::<LinuxKobjUeventEnv>(), align_of::<LinuxKobjUeventEnv>()), (2592, 8));
        assert_eq!((size_of::<super::super::types::LinuxKset>(), align_of::<super::super::types::LinuxKset>()), (96, 8));
    }
}
