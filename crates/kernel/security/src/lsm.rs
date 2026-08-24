//! Linux-shaped LSM hook dispatch.
//!
//! Providers register their hooks here and callers invoke one dispatcher. The
//! registry owns no policy: it snapshots the installed providers before
//! calling them, so one security module cannot silently replace another.

extern crate alloc;

use alloc::vec::Vec;

use sync::{SecurityPolicy as LockClass, Spinlock};
use vfs::{Dentry, FileType, InodeRef, KResult, VfsPath};

/// Context passed to the common open hook. `access` is the current access
/// mask; a provider may return a reduced/recorded mask, or refuse the open.
pub struct OpenContext<'a> {
    pub path: &'a VfsPath,
    pub inode: &'a InodeRef,
    pub access: u64,
    pub flags: u64,
    pub is_device: bool,
}

/// One provider in the open hook chain.
pub type OpenHook = for<'a> fn(&OpenContext<'a>) -> Result<u64, i64>;

/// One provider in the inode-permission hook chain.
pub type InodePermissionHook = fn(&InodeRef, u32) -> KResult<()>;
pub type InodeCreateHook = fn(&InodeRef, &InodeRef, &str);
pub type InodeInstantiateHook = fn(&Dentry, &InodeRef);
pub type InodeInitSecurityAnonHook = fn(&InodeRef, &str, Option<&InodeRef>) -> KResult<()>;
pub type DevicePermissionHook = fn(FileType, u32, u32) -> KResult<()>;
pub type FileIoctlHook = fn(&InodeRef, u32) -> KResult<()>;

static OPEN_HOOKS: Spinlock<Vec<OpenHook>, LockClass> = Spinlock::new(Vec::new());
static INODE_PERMISSION_HOOKS: Spinlock<Vec<InodePermissionHook>, LockClass> =
    Spinlock::new(Vec::new());
static INODE_CREATE_HOOKS: Spinlock<Vec<InodeCreateHook>, LockClass> = Spinlock::new(Vec::new());
static INODE_INSTANTIATE_HOOKS: Spinlock<Vec<InodeInstantiateHook>, LockClass> =
    Spinlock::new(Vec::new());
static INODE_INIT_SECURITY_ANON_HOOKS: Spinlock<Vec<InodeInitSecurityAnonHook>, LockClass> =
    Spinlock::new(Vec::new());
static DEVICE_PERMISSION_HOOKS: Spinlock<Vec<DevicePermissionHook>, LockClass> =
    Spinlock::new(Vec::new());
static FILE_IOCTL_HOOKS: Spinlock<Vec<FileIoctlHook>, LockClass> = Spinlock::new(Vec::new());

/// Register one open provider. Registration is idempotent by function address,
/// matching the one-time LSM init window and preventing duplicate decisions.
pub fn register_open(hook: OpenHook) {
    let mut hooks = OPEN_HOOKS.lock();
    if hooks.iter().any(|installed| *installed as usize == hook as usize) { return; }
    hooks.push(hook);
}

/// Register one inode-permission provider. # C: O(providers)
pub fn register_inode_permission(hook: InodePermissionHook) {
    let mut hooks = INODE_PERMISSION_HOOKS.lock();
    if hooks.iter().any(|installed| *installed as usize == hook as usize) { return; }
    hooks.push(hook);
}

fn register_once<T>(hooks: &mut Vec<T>, hook: T, same: fn(&T, &T) -> bool) {
    if hooks.iter().any(|installed| same(installed, &hook)) { return; }
    hooks.push(hook);
}

/// Register an inode-create provider. # C: O(providers)
pub fn register_inode_create(hook: InodeCreateHook) {
    register_once(&mut INODE_CREATE_HOOKS.lock(), hook,
                  |a, b| *a as usize == *b as usize);
}

/// Register an inode-instantiation provider. # C: O(providers)
pub fn register_inode_instantiate(hook: InodeInstantiateHook) {
    register_once(&mut INODE_INSTANTIATE_HOOKS.lock(), hook,
                  |a, b| *a as usize == *b as usize);
}

/// Register a secure-anonymous-inode provider. # C: O(providers)
pub fn register_inode_init_security_anon(hook: InodeInitSecurityAnonHook) {
    register_once(&mut INODE_INIT_SECURITY_ANON_HOOKS.lock(), hook,
                  |a, b| *a as usize == *b as usize);
}

/// Register a device-permission provider. # C: O(providers)
pub fn register_device_permission(hook: DevicePermissionHook) {
    register_once(&mut DEVICE_PERMISSION_HOOKS.lock(), hook,
                  |a, b| *a as usize == *b as usize);
}

pub fn register_file_ioctl(hook: FileIoctlHook) {
    register_once(&mut FILE_IOCTL_HOOKS.lock(), hook,
                  |a, b| *a as usize == *b as usize);
}

/// Run every open provider in registration order. # C: O(providers)
pub fn open(path: &VfsPath, inode: &InodeRef, access: u64, flags: u64,
            is_device: bool) -> Result<u64, i64>
{
    let hooks = OPEN_HOOKS.lock().clone();
    let mut access = access;
    for hook in hooks {
        access = hook(&OpenContext { path, inode, access, flags, is_device })?;
    }
    Ok(access)
}

/// VFS adapter for the common inode-permission hook. # C: O(providers)
pub fn inode_permission(inode: &InodeRef, mask: u32) -> KResult<()> {
    let hooks = INODE_PERMISSION_HOOKS.lock().clone();
    for hook in hooks { hook(inode, mask)?; }
    Ok(())
}

/// VFS adapter for inode creation notifications. # C: O(providers)
pub fn inode_created(dir: &InodeRef, inode: &InodeRef, name: &str) {
    let hooks = INODE_CREATE_HOOKS.lock().clone();
    for hook in hooks { hook(dir, inode, name); }
}

/// VFS adapter for inode instantiation notifications. # C: O(providers)
pub fn inode_instantiated(dentry: &Dentry, inode: &InodeRef) {
    let hooks = INODE_INSTANTIATE_HOOKS.lock().clone();
    for hook in hooks { hook(dentry, inode); }
}

/// VFS adapter for secure anonymous inode initialization. # C: O(providers)
pub fn inode_init_security_anon(inode: &InodeRef, name: &str,
                                context: Option<&InodeRef>) -> KResult<()> {
    let hooks = INODE_INIT_SECURITY_ANON_HOOKS.lock().clone();
    for hook in hooks { hook(inode, name, context)?; }
    Ok(())
}

/// VFS adapter for device permission. # C: O(providers)
pub fn device_permission(file_type: FileType, rdev: u32, mask: u32) -> KResult<()> {
    if rdev == 0 || !matches!(file_type, FileType::CharDev | FileType::BlockDev) {
        return Ok(());
    }
    let hooks = DEVICE_PERMISSION_HOOKS.lock().clone();
    for hook in hooks { hook(file_type, rdev, mask)?; }
    Ok(())
}

pub fn file_ioctl(inode: &InodeRef, cmd: u32) -> KResult<()> {
    let hooks = FILE_IOCTL_HOOKS.lock().clone();
    for hook in hooks { hook(inode, cmd)?; }
    Ok(())
}
