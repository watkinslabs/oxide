use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_char;

use kernfs::{PseudoDir, PseudoDirHooks};
use sync::{Modules as ModulesLockClass, Spinlock};
use vfs::{CreateCtx, InodeRef, KResult, VfsError};

use super::{
    clear_item_path, install_attrs, install_bin_attrs, install_default_groups, item_path, item_type,
    item_dependent_count, release_item, set_item_path, ConfigGroup, ConfigItem,
};
use crate::linux_configfs::util::{join_path, valid_name};

const MAX_ERRNO: usize = 4095;
static CREATED: Spinlock<BTreeMap<String, usize>, ModulesLockClass> = Spinlock::new(BTreeMap::new());

pub(super) struct ConfigDirHooks { group: usize }

impl ConfigDirHooks {
    pub(super) fn new(group: usize) -> Self { Self { group } }
}

impl PseudoDirHooks for ConfigDirHooks {
    fn mkdir(&self, _dir: &PseudoDir, name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<Option<InodeRef>> {
        if !valid_name(name) { return Err(VfsError::Einval); }
        let group = self.group as *mut ConfigGroup;
        if group.is_null() { return Err(VfsError::Einval); }
        let parent_path = parent_path(group)?;
        let path = join_path(&parent_path, name);
        if tracefs::config_root().lookup_path(&path).is_some() { return Err(VfsError::Eexist); }
        let ty = item_type(parent_item(group)).ok_or(VfsError::Eperm)?;
        let cname = c_name(name);
        // SAFETY: configfs group operation pointers are module-owned and receive a NUL-terminated name valid for this call.
        let made_group = unsafe { (*ty).make_group.map(|f| f(group, cname.as_ptr() as *const c_char)) };
        if let Some(raw) = made_group {
            let child = ptr_result_group(raw)?;
            install_group_path(group, child, path);
            return tracefs::config_root().lookup_path(&join_path(&parent_path, name)).map(Some).ok_or(VfsError::Eio);
        }
        // SAFETY: configfs group operation pointers are module-owned and receive a NUL-terminated name valid for this call.
        let made_item = unsafe { (*ty).make_item.map(|f| f(group, cname.as_ptr() as *const c_char)) };
        if let Some(raw) = made_item {
            let item = ptr_result_item(raw)?;
            install_item_path(item, path, false, group);
            return tracefs::config_root().lookup_path(&join_path(&parent_path, name)).map(Some).ok_or(VfsError::Eio);
        }
        Err(VfsError::Eperm)
    }

    fn rmdir(&self, _dir: &PseudoDir, name: &str) -> KResult<bool> {
        if !valid_name(name) { return Err(VfsError::Einval); }
        let group = self.group as *mut ConfigGroup;
        if group.is_null() { return Err(VfsError::Einval); }
        let path = join_path(&parent_path(group)?, name);
        let item = *CREATED.lock().get(&path).ok_or(VfsError::Enoent)? as *mut ConfigItem;
        if item.is_null() { return Err(VfsError::Einval); }
        if item_dependent_count(item) != 0 { return Err(VfsError::Ebusy); }
        if child_has_children(&path) { CREATED.lock().insert(path, item as usize); return Err(VfsError::Enotempty); }
        CREATED.lock().remove(&path);
        let ty = item_type(parent_item(group));
        tracefs::config_root().remove_subtree(&path);
        clear_item_path(item);
        // SAFETY: drop_item belongs to the parent group's configfs type and receives the child being removed.
        unsafe {
            if let Some(t) = ty {
                if let Some(drop) = (*t).drop_item {
                    drop(group, item);
                    return Ok(true);
                }
            }
        }
        release_item(item);
        Ok(true)
    }
}

fn install_group_path(parent: *mut ConfigGroup, group: *mut ConfigGroup, path: String) {
    // SAFETY: group pointer was returned by the module's make_group callback.
    let item = unsafe { &mut (*group).item as *mut ConfigItem };
    let p = path.clone();
    install_item_path(item, path, true, parent);
    install_default_groups(item, group);
    CREATED.lock().insert(p, item as usize);
}

fn install_item_path(item: *mut ConfigItem, path: String, is_group: bool, parent: *mut ConfigGroup) {
    if is_group {
        let group = item as *mut ConfigGroup;
        tracefs::config_root().ensure_dir_path_with_hooks(&path, Arc::new(ConfigDirHooks::new(group as usize)));
    } else {
        tracefs::config_root().ensure_dir_path(&path);
    }
    set_item_path(item, path.clone());
    install_attrs(&path, item);
    install_bin_attrs(&path, item);
    CREATED.lock().insert(path, item as usize);
    let _ = parent;
}

fn parent_item(group: *mut ConfigGroup) -> *mut ConfigItem {
    // SAFETY: group is checked non-null by callers.
    unsafe { &mut (*group).item }
}

fn parent_path(group: *mut ConfigGroup) -> KResult<String> {
    item_path(parent_item(group)).ok_or(VfsError::Einval)
}

fn c_name(name: &str) -> Vec<u8> {
    let mut v = Vec::from(name.as_bytes());
    v.push(0);
    v
}

fn ptr_result_item(ptr: *mut ConfigItem) -> KResult<*mut ConfigItem> {
    if ptr.is_null() { return Err(VfsError::Einval); }
    let raw = ptr as usize;
    if raw >= usize::MAX - MAX_ERRNO { return Err(crate::linux_configfs::util::errno_to_vfs((usize::MAX - raw + 1) as i32)); }
    Ok(ptr)
}

fn ptr_result_group(ptr: *mut ConfigGroup) -> KResult<*mut ConfigGroup> {
    if ptr.is_null() { return Err(VfsError::Einval); }
    let raw = ptr as usize;
    if raw >= usize::MAX - MAX_ERRNO { return Err(crate::linux_configfs::util::errno_to_vfs((usize::MAX - raw + 1) as i32)); }
    Ok(ptr)
}

fn child_has_children(path: &str) -> bool {
    let prefix = {
        let mut s = String::from(path);
        s.push('/');
        s
    };
    CREATED.lock().keys().any(|p| p.starts_with(&prefix))
}
