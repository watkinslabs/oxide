extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, Spinlock};
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError};

const LINUX_OK: i32 = 0;
const LINUX_EINVAL: i32 = 22;
const LINUX_EEXIST: i32 = 17;
const NAME_MAX: usize = 255;
const DEFAULT_ATTR_MODE: u16 = 0o644;
const CONFIG_PATH_MAGIC: u32 = 0x4346_5350;

static NEXT_INO: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0x6c00_0000);
static LOCK: Spinlock<(), ModulesLockClass> = Spinlock::new(());

type ShowFn = unsafe extern "C" fn(*mut ConfigItem, *mut c_char) -> isize;
type StoreFn = unsafe extern "C" fn(*mut ConfigItem, *const c_char, usize) -> isize;
type ReleaseFn = unsafe extern "C" fn(*mut ConfigItem);

#[repr(C)]
pub struct ConfigfsAttribute {
    name: *const c_char,
    mode: u16,
    show: Option<ShowFn>,
    store: Option<StoreFn>,
}

#[repr(C)]
pub struct ConfigItemType {
    release: Option<ReleaseFn>,
    attrs: *mut *mut ConfigfsAttribute,
}

#[repr(C)]
pub struct ConfigItem {
    name: *const c_char,
    ty: *mut ConfigItemType,
    private: *mut c_void,
}

#[repr(C)]
pub struct ConfigGroup {
    item: ConfigItem,
}

#[repr(C)]
pub struct ConfigfsSubsystem {
    group: ConfigGroup,
}

struct PathState {
    magic: u32,
    path: String,
}

struct AttrData {
    item: usize,
    attr: usize,
}

struct AttrOps;
impl FileOps for AttrOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<AttrData>().ok_or(VfsError::Einval)?;
        let attr = attr_ref(d.attr).ok_or(VfsError::Einval)?;
        let show = attr.show.ok_or(VfsError::Einval)?;
        let mut body = [0u8; 4096];
        // SAFETY: configfs attribute callback receives the live item and page-sized kernel buffer.
        let n = unsafe { show(d.item as *mut ConfigItem, body.as_mut_ptr() as *mut c_char) };
        checked_size(n).map(|len| read_at(&body[..len.min(body.len())], off, buf))
    }

    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<AttrData>().ok_or(VfsError::Einval)?;
        let attr = attr_ref(d.attr).ok_or(VfsError::Einval)?;
        let store = attr.store.ok_or(VfsError::Einval)?;
        // SAFETY: configfs attribute callback receives the live item and caller-provided kernel slice.
        checked_size(unsafe {
            store(d.item as *mut ConfigItem, buf.as_ptr() as *const c_char, buf.len())
        })
    }
}

/// Register Linux configfs KPI symbols. # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("config_item_init",              config_item_init              as *const () as usize),
        ("config_item_init_type_name",    config_item_init_type_name    as *const () as usize),
        ("config_group_init",             config_group_init             as *const () as usize),
        ("config_group_init_type_name",   config_group_init_type_name   as *const () as usize),
        ("configfs_register_subsystem",   configfs_register_subsystem   as *const () as usize),
        ("configfs_unregister_subsystem", configfs_unregister_subsystem as *const () as usize),
        ("configfs_register_group",       configfs_register_group       as *const () as usize),
        ("configfs_unregister_group",     configfs_unregister_group     as *const () as usize),
        ("config_item_get",               config_item_get               as *const () as usize),
        ("config_item_put",               config_item_put               as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn config_item_init(item: *mut ConfigItem) {
    if item.is_null() { return; }
    // SAFETY: item is caller-owned configfs storage.
    unsafe { (*item).private = null_mut(); }
}

extern "C" fn config_item_init_type_name(item: *mut ConfigItem, name: *const c_char, ty: *mut ConfigItemType) {
    if item.is_null() { return; }
    // SAFETY: item is caller-owned configfs storage.
    unsafe {
        (*item).name = name;
        (*item).ty = ty;
        (*item).private = null_mut();
    }
}

extern "C" fn config_group_init(group: *mut ConfigGroup) {
    if group.is_null() { return; }
    // SAFETY: group is caller-owned configfs storage.
    unsafe { config_item_init(&mut (*group).item); }
}

extern "C" fn config_group_init_type_name(group: *mut ConfigGroup, name: *const c_char, ty: *mut ConfigItemType) {
    if group.is_null() { return; }
    // SAFETY: group is caller-owned configfs storage.
    unsafe { config_item_init_type_name(&mut (*group).item, name, ty); }
}

extern "C" fn configfs_register_subsystem(subsys: *mut ConfigfsSubsystem) -> i32 {
    if subsys.is_null() { return -LINUX_EINVAL; }
    // SAFETY: subsys is caller-owned configfs storage.
    unsafe { register_group(null_mut(), &mut (*subsys).group) }
}

extern "C" fn configfs_unregister_subsystem(subsys: *mut ConfigfsSubsystem) {
    if subsys.is_null() { return; }
    // SAFETY: subsys is caller-owned configfs storage.
    unsafe { unregister_group(&mut (*subsys).group); }
}

extern "C" fn configfs_register_group(parent: *mut ConfigGroup, group: *mut ConfigGroup) -> i32 {
    // SAFETY: group and parent are caller-owned configfs storage when non-null.
    unsafe { register_group(parent, group) }
}

extern "C" fn configfs_unregister_group(group: *mut ConfigGroup) {
    // SAFETY: group is caller-owned configfs storage when non-null.
    unsafe { unregister_group(group); }
}

extern "C" fn config_item_get(item: *mut ConfigItem) -> *mut ConfigItem { item }
extern "C" fn config_item_put(_item: *mut ConfigItem) {}

unsafe fn register_group(parent: *mut ConfigGroup, group: *mut ConfigGroup) -> i32 {
    if group.is_null() { return -LINUX_EINVAL; }
    // SAFETY: group is checked non-null and owned by module code for registration.
    let group_item = unsafe { &mut (*group).item };
    let name = match read_cstr(group_item.name, NAME_MAX) { Some(n) => n, None => return -LINUX_EINVAL };
    if !valid_name(&name) { return -LINUX_EINVAL; }
    let parent_path = if parent.is_null() {
        String::new()
    } else {
        // SAFETY: non-null parent is caller-owned configfs group storage.
        let parent_item = unsafe { &mut (*parent).item };
        match item_path(parent_item) { Some(p) => p, None => return -LINUX_EINVAL }
    };
    let path = join_path(&parent_path, &name);
    let _g = LOCK.lock();
    if tracefs::config_root().lookup_path(&path).is_some() { return -LINUX_EEXIST; }
    tracefs::config_root().ensure_dir_path(&path);
    install_attrs(&path, group_item);
    set_item_path(group_item, path);
    LINUX_OK
}

unsafe fn unregister_group(group: *mut ConfigGroup) {
    if group.is_null() { return; }
    // SAFETY: group is checked non-null and owned by module code for unregister.
    let item = unsafe { &mut (*group).item };
    if let Some(path) = item_path(item) {
        let _g = LOCK.lock();
        tracefs::config_root().remove_subtree(&path);
    }
    clear_item_path(item);
}

fn install_attrs(path: &str, item: *mut ConfigItem) {
    let ty = item_type(item);
    let attrs = match ty.and_then(|t| attrs_ptr(t)) { Some(a) => a, None => return };
    let mut i = 0usize;
    loop {
        // SAFETY: configfs attr array is NULL-terminated by module code.
        let attr = unsafe { *attrs.add(i) };
        if attr.is_null() { break; }
        if let Some(name) = unsafe { read_cstr((*attr).name, NAME_MAX) } {
            if valid_name(&name) {
                let ap = join_path(path, &name);
                let mode = unsafe { (*attr).mode };
                let data = AttrData { item: item as usize, attr: attr as usize };
                tracefs::config_root().insert_path(&ap, attr_inode(mode, data));
            }
        }
        i += 1;
    }
}

fn attr_inode(mode: u16, data: AttrData) -> InodeRef {
    let perm = if mode == 0 { DEFAULT_ATTR_MODE } else { mode & 0o777 };
    InodeBuilder::new(
        NEXT_INO.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        mk_mode(FileType::Regular, perm),
        default_inode_ops(),
        Arc::new(AttrOps),
    ).private(Arc::new(data)).build()
}

fn item_type(item: *mut ConfigItem) -> Option<*mut ConfigItemType> {
    if item.is_null() { None } else {
        // SAFETY: item is checked non-null and owned by module code.
        let ty = unsafe { (*item).ty };
        if ty.is_null() { None } else { Some(ty) }
    }
}

fn attrs_ptr(ty: *mut ConfigItemType) -> Option<*mut *mut ConfigfsAttribute> {
    // SAFETY: ty is checked non-null by caller.
    let attrs = unsafe { (*ty).attrs };
    if attrs.is_null() { None } else { Some(attrs) }
}

fn attr_ref(ptr: usize) -> Option<&'static ConfigfsAttribute> {
    if ptr == 0 { None } else {
        // SAFETY: pointer comes from a module-owned static configfs attribute.
        Some(unsafe { &*(ptr as *const ConfigfsAttribute) })
    }
}

fn set_item_path(item: *mut ConfigItem, path: String) {
    let state = Box::new(PathState { magic: CONFIG_PATH_MAGIC, path });
    // SAFETY: item is caller-owned configfs storage.
    unsafe { (*item).private = Box::into_raw(state) as *mut c_void; }
}

fn clear_item_path(item: *mut ConfigItem) {
    // SAFETY: item is caller-owned configfs storage.
    let p = unsafe { (*item).private };
    if p.is_null() { return; }
    // SAFETY: private was set by set_item_path for registered items.
    let state = unsafe { Box::from_raw(p as *mut PathState) };
    if state.magic != CONFIG_PATH_MAGIC { core::mem::forget(state); return; }
    // SAFETY: item is caller-owned configfs storage.
    unsafe { (*item).private = null_mut(); }
}

fn item_path(item: *mut ConfigItem) -> Option<String> {
    if item.is_null() { return None; }
    // SAFETY: item is checked non-null and owned by module code.
    let p = unsafe { (*item).private };
    if p.is_null() { return None; }
    // SAFETY: private points to PathState for registered items.
    let state = unsafe { &*(p as *const PathState) };
    if state.magic == CONFIG_PATH_MAGIC { Some(state.path.clone()) } else { None }
}

fn checked_size(v: isize) -> KResult<usize> {
    if v < 0 { Err(errno_to_vfs((-v) as i32)) } else { Ok(v as usize) }
}

fn errno_to_vfs(e: i32) -> VfsError {
    match e {
        2 => VfsError::Enoent,
        12 => VfsError::Enomem,
        13 => VfsError::Eacces,
        16 => VfsError::Ebusy,
        22 => VfsError::Einval,
        _ => VfsError::Eio,
    }
}

fn read_at(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let off = off as usize;
    if off >= body.len() { return 0; }
    let n = (body.len() - off).min(buf.len());
    buf[..n].copy_from_slice(&body[off..off + n]);
    n
}

fn read_cstr(ptr: *const c_char, max: usize) -> Option<String> {
    if ptr.is_null() { return None; }
    let mut bytes = alloc::vec::Vec::new();
    for i in 0..=max {
        // SAFETY: caller passes a NUL-terminated C string; bounded scan avoids unbounded reads.
        let b = unsafe { *ptr.add(i) } as u8;
        if b == 0 { return String::from_utf8(bytes).ok(); }
        bytes.push(b);
    }
    None
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.as_bytes().iter().any(|b| *b == b'/')
}

fn join_path(parent: &str, name: &str) -> String {
    let mut p = String::from(parent);
    if !p.is_empty() { p.push('/'); }
    p.push_str(name);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    static ATTR_NAME: &[u8] = b"value\0";
    static GROUP_NAME: &[u8] = b"sample\0";

    unsafe extern "C" fn show(_item: *mut ConfigItem, buf: *mut c_char) -> isize {
        let body = b"ok\n";
        // SAFETY: configfs passes a page-sized writable kernel buffer.
        unsafe { core::ptr::copy_nonoverlapping(body.as_ptr(), buf as *mut u8, body.len()); }
        body.len() as isize
    }

    #[test]
    fn export_symbols_registers_configfs_surface() {
        export_symbols();
        assert!(crate::is_exported("configfs_register_subsystem"));
        assert!(crate::is_exported("configfs_unregister_group"));
    }

    #[test]
    fn subsystem_registers_attrs_in_config_root() {
        let mut attr = ConfigfsAttribute {
            name: ATTR_NAME.as_ptr() as *const c_char,
            mode: 0o444,
            show: Some(show),
            store: None,
        };
        let mut attrs = [&mut attr as *mut ConfigfsAttribute, core::ptr::null_mut()];
        let mut ty = ConfigItemType { release: None, attrs: attrs.as_mut_ptr() };
        let mut s = ConfigfsSubsystem {
            group: ConfigGroup {
                item: ConfigItem {
                    name: GROUP_NAME.as_ptr() as *const c_char,
                    ty: &mut ty,
                    private: null_mut(),
                },
            },
        };
        assert_eq!(configfs_register_subsystem(&mut s), 0);
        let inode = tracefs::config_root().lookup_path("sample/value").expect("configfs attr");
        let mut buf = [0u8; 8];
        let n = inode.read(0, &mut buf).expect("read configfs attr");
        assert_eq!(&buf[..n], b"ok\n");
        configfs_unregister_subsystem(&mut s);
        assert!(tracefs::config_root().lookup_path("sample/value").is_none());
    }
}
