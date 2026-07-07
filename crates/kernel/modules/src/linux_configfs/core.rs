extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Modules as ModulesLockClass, Spinlock};
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError};

use super::util::{checked_size, join_path, read_at, read_cstr, valid_name};

#[path = "dynamic.rs"]
mod dynamic;

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
type BinReadFn = unsafe extern "C" fn(*mut ConfigItem, *mut c_void, *mut c_void, *mut c_char, i64, usize) -> isize;
type BinWriteFn = unsafe extern "C" fn(*mut ConfigItem, *mut c_void, *mut c_void, *const c_char, i64, usize) -> isize;
type LinkFn = unsafe extern "C" fn(*mut ConfigItem, *mut ConfigItem) -> i32;
pub(super) type MakeItemFn = unsafe extern "C" fn(*mut ConfigGroup, *const c_char) -> *mut ConfigItem;
pub(super) type MakeGroupFn = unsafe extern "C" fn(*mut ConfigGroup, *const c_char) -> *mut ConfigGroup;
pub(super) type DropItemFn = unsafe extern "C" fn(*mut ConfigGroup, *mut ConfigItem);

#[repr(C)]
pub struct ConfigfsAttribute {
    name: *const c_char,
    mode: u16,
    show: Option<ShowFn>,
    store: Option<StoreFn>,
}

#[repr(C)]
pub struct ConfigfsBinAttribute {
    attr: ConfigfsAttribute,
    private: *mut c_void,
    size: usize,
    read: Option<BinReadFn>,
    write: Option<BinWriteFn>,
}

#[repr(C)]
pub struct ConfigItemType {
    release: Option<ReleaseFn>,
    attrs: *mut *mut ConfigfsAttribute,
    default_groups: *mut *mut ConfigGroup,
    bin_attrs: *mut *mut ConfigfsBinAttribute,
    allow_link: Option<LinkFn>,
    drop_link: Option<LinkFn>,
    make_item: Option<MakeItemFn>,
    make_group: Option<MakeGroupFn>,
    drop_item: Option<DropItemFn>,
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
    refs: AtomicU32,
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

struct BinAttrData {
    item: usize,
    attr: usize,
}

struct BinAttrOps;
impl FileOps for BinAttrOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<BinAttrData>().ok_or(VfsError::Einval)?;
        let attr = bin_attr_ref(d.attr).ok_or(VfsError::Einval)?;
        let read = attr.read.ok_or(VfsError::Einval)?;
        // SAFETY: configfs bin attr callback receives live item/private storage and VFS buffer.
        checked_size(unsafe {
            read(d.item as *mut ConfigItem, attr.private, null_mut(), buf.as_mut_ptr() as *mut c_char, off as i64, buf.len())
        })
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<BinAttrData>().ok_or(VfsError::Einval)?;
        let attr = bin_attr_ref(d.attr).ok_or(VfsError::Einval)?;
        let write = attr.write.ok_or(VfsError::Einval)?;
        // SAFETY: configfs bin attr callback receives live item/private storage and VFS buffer.
        checked_size(unsafe { write(d.item as *mut ConfigItem, attr.private, null_mut(), buf.as_ptr() as *const c_char, off as i64, buf.len()) })
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
        ("configfs_create_link",          configfs_create_link          as *const () as usize),
        ("configfs_drop_link",            configfs_drop_link            as *const () as usize),
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

extern "C" fn config_item_get(item: *mut ConfigItem) -> *mut ConfigItem {
    if let Some(state) = item_state(item) { state.refs.fetch_add(1, Ordering::AcqRel); }
    item
}

extern "C" fn config_item_put(item: *mut ConfigItem) {
    let Some(state) = item_state(item) else { return; };
    if state.refs.fetch_sub(1, Ordering::AcqRel) == 1 { release_item(item); }
}

extern "C" fn configfs_create_link(parent: *mut ConfigItem, target: *mut ConfigItem, name: *const c_char) -> i32 {
    if parent.is_null() || target.is_null() { return -LINUX_EINVAL; }
    let name = match read_cstr(name, NAME_MAX) { Some(n) => n, None => return -LINUX_EINVAL };
    if !valid_name(&name) { return -LINUX_EINVAL; }
    let parent_path = match item_path(parent) { Some(p) => p, None => return -LINUX_EINVAL };
    let target_path = match item_path(target) { Some(p) => p, None => return -LINUX_EINVAL };
    if let Some(ty) = item_type(parent) {
        // SAFETY: item type and callback are module-owned configfs operation storage.
        let rc = unsafe { (*ty).allow_link.map(|f| f(parent, target)).unwrap_or(LINUX_OK) };
        if rc < 0 { return rc; }
    }
    let link_path = join_path(&parent_path, &name);
    let _g = LOCK.lock();
    tracefs::config_root().insert_path(&link_path, symlink_inode(target_path.as_bytes()));
    LINUX_OK
}

extern "C" fn configfs_drop_link(parent: *mut ConfigItem, target: *mut ConfigItem, name: *const c_char) {
    if parent.is_null() || target.is_null() { return; }
    let Some(name) = read_cstr(name, NAME_MAX) else { return; };
    if !valid_name(&name) { return; }
    if let Some(ty) = item_type(parent) {
        // SAFETY: item type and callback are module-owned configfs operation storage.
        unsafe { if let Some(f) = (*ty).drop_link { let _ = f(parent, target); } }
    }
    if let Some(parent_path) = item_path(parent) {
        let _g = LOCK.lock();
        tracefs::config_root().remove_subtree(&join_path(&parent_path, &name));
    }
}

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
    {
        let _g = LOCK.lock();
        if tracefs::config_root().lookup_path(&path).is_some() { return -LINUX_EEXIST; }
        tracefs::config_root().ensure_dir_path_with_hooks(&path, Arc::new(dynamic::ConfigDirHooks::new(group as usize)));
        install_attrs(&path, group_item);
        install_bin_attrs(&path, group_item);
        set_item_path(group_item, path);
    }
    install_default_groups(group_item, group);
    LINUX_OK
}

unsafe fn unregister_group(group: *mut ConfigGroup) {
    if group.is_null() { return; }
    // SAFETY: group is checked non-null and owned by module code for unregister.
    let item = unsafe { &mut (*group).item };
    unregister_default_groups(item);
    if let Some(path) = item_path(item) {
        let _g = LOCK.lock();
        tracefs::config_root().remove_subtree(&path);
    }
    clear_item_path(item);
    release_item(item);
}

pub(super) fn install_attrs(path: &str, item: *mut ConfigItem) {
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

pub(super) fn install_bin_attrs(path: &str, item: *mut ConfigItem) {
    let ty = item_type(item);
    let attrs = match ty.and_then(|t| bin_attrs_ptr(t)) { Some(a) => a, None => return };
    let mut i = 0usize;
    loop {
        // SAFETY: configfs bin attr array is NULL-terminated by module code.
        let attr = unsafe { *attrs.add(i) };
        if attr.is_null() { break; }
        // SAFETY: bin attr pointer comes from module-owned static configfs storage.
        if let Some(name) = unsafe { read_cstr((*attr).attr.name, NAME_MAX) } {
            if valid_name(&name) {
                let ap = join_path(path, &name);
                // SAFETY: bin attr pointer comes from module-owned static configfs storage.
                let mode = unsafe { (*attr).attr.mode };
                let data = BinAttrData { item: item as usize, attr: attr as usize };
                tracefs::config_root().insert_path(&ap, bin_attr_inode(mode, data));
            }
        }
        i += 1;
    }
}

pub(super) fn install_default_groups(parent_item: *mut ConfigItem, parent_group: *mut ConfigGroup) {
    let ty = item_type(parent_item);
    let groups = match ty.and_then(|t| default_groups_ptr(t)) { Some(g) => g, None => return };
    let mut i = 0usize;
    loop {
        // SAFETY: configfs default group array is NULL-terminated by module code.
        let group = unsafe { *groups.add(i) };
        if group.is_null() { break; }
        // SAFETY: default group pointer comes from module-owned configfs storage.
        let _ = unsafe { register_group(parent_group, group) };
        i += 1;
    }
}

fn unregister_default_groups(parent_item: *mut ConfigItem) {
    let ty = item_type(parent_item);
    let groups = match ty.and_then(|t| default_groups_ptr(t)) { Some(g) => g, None => return };
    let mut i = 0usize;
    loop {
        // SAFETY: configfs default group array is NULL-terminated by module code.
        let group = unsafe { *groups.add(i) };
        if group.is_null() { break; }
        // SAFETY: default group pointer comes from module-owned configfs storage.
        unsafe { unregister_group(group); }
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

fn bin_attr_inode(mode: u16, data: BinAttrData) -> InodeRef {
    let perm = if mode == 0 { DEFAULT_ATTR_MODE } else { mode & 0o777 };
    InodeBuilder::new(
        NEXT_INO.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        mk_mode(FileType::Regular, perm),
        default_inode_ops(),
        Arc::new(BinAttrOps),
    ).private(Arc::new(data)).build()
}

fn symlink_inode(target: &[u8]) -> InodeRef {
    InodeBuilder::new(
        NEXT_INO.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        mk_mode(FileType::Symlink, 0o777),
        default_inode_ops(),
        vfs::default_file_ops(),
    ).size(target.len() as u64).link(target.to_vec().into_boxed_slice()).build()
}

pub(super) fn item_type(item: *mut ConfigItem) -> Option<*mut ConfigItemType> {
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

fn default_groups_ptr(ty: *mut ConfigItemType) -> Option<*mut *mut ConfigGroup> {
    // SAFETY: ty is checked non-null by caller.
    let groups = unsafe { (*ty).default_groups };
    if groups.is_null() { None } else { Some(groups) }
}

fn bin_attrs_ptr(ty: *mut ConfigItemType) -> Option<*mut *mut ConfigfsBinAttribute> {
    // SAFETY: ty is checked non-null by caller.
    let attrs = unsafe { (*ty).bin_attrs };
    if attrs.is_null() { None } else { Some(attrs) }
}

fn attr_ref(ptr: usize) -> Option<&'static ConfigfsAttribute> {
    if ptr == 0 { None } else {
        // SAFETY: pointer comes from a module-owned static configfs attribute.
        Some(unsafe { &*(ptr as *const ConfigfsAttribute) })
    }
}

fn bin_attr_ref(ptr: usize) -> Option<&'static ConfigfsBinAttribute> {
    if ptr == 0 { None } else {
        // SAFETY: pointer comes from a module-owned static configfs bin attribute.
        Some(unsafe { &*(ptr as *const ConfigfsBinAttribute) })
    }
}

pub(super) fn set_item_path(item: *mut ConfigItem, path: String) {
    let state = Box::new(PathState { magic: CONFIG_PATH_MAGIC, path, refs: AtomicU32::new(1) });
    // SAFETY: item is caller-owned configfs storage.
    unsafe { (*item).private = Box::into_raw(state) as *mut c_void; }
}

fn item_state(item: *mut ConfigItem) -> Option<&'static PathState> {
    if item.is_null() { return None; }
    // SAFETY: item is checked non-null and owned by module code.
    let p = unsafe { (*item).private };
    if p.is_null() { return None; }
    // SAFETY: private points to PathState for registered items.
    let state = unsafe { &*(p as *const PathState) };
    if state.magic == CONFIG_PATH_MAGIC { Some(state) } else { None }
}

pub(super) fn clear_item_path(item: *mut ConfigItem) {
    // SAFETY: item is caller-owned configfs storage.
    let p = unsafe { (*item).private };
    if p.is_null() { return; }
    // SAFETY: private was set by set_item_path for registered items.
    let state = unsafe { Box::from_raw(p as *mut PathState) };
    if state.magic != CONFIG_PATH_MAGIC { core::mem::forget(state); return; }
    // SAFETY: item is caller-owned configfs storage.
    unsafe { (*item).private = null_mut(); }
}

pub(super) fn item_path(item: *mut ConfigItem) -> Option<String> {
    item_state(item).map(|state| state.path.clone())
}

pub(super) fn release_item(item: *mut ConfigItem) {
    if let Some(ty) = item_type(item) {
        // SAFETY: item type and release callback are module-owned configfs operation storage.
        unsafe { if let Some(release) = (*ty).release { release(item); } }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
