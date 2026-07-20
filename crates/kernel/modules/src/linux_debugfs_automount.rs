extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;

use vfs::{Dentry, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

use crate::linux_debugfs::LinuxDentry;

const VFSMOUNT_MAGIC: u32 = 0x5646_534d;
#[cfg(test)]
const DEBUGFS_MAGIC: u64 = tracefs::fs_impl::DEBUGFS_SUPER_MAGIC;

static NEXT_INO: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(crate::linux_debugfs_ids::AUTOMOUNT_INO_BASE);

type DebugfsAutomount = unsafe extern "C" fn(*mut LinuxDentry, *mut c_void) -> *mut LinuxVfsmount;

pub struct LinuxVfsmount {
    magic: u32,
    fs:    Arc<dyn vfs::fs::FileSystem>,
    root:  InodeRef,
}

#[cfg(test)]
struct AutomountFs {
    root: InodeRef,
}

#[cfg(test)]
impl vfs::fs::FileSystem for AutomountFs {
    fn name(&self) -> &str { "debugfs-automount" }
    fn magic(&self) -> u64 { DEBUGFS_MAGIC }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}

struct AutomountData {
    path: String,
    cb:   DebugfsAutomount,
    data: usize,
}

struct AutomountOps;
impl InodeOps for AutomountOps {
    fn is_automount(&self, _inode: &Inode) -> bool { true }

    fn automount(&self, inode: &Inode, dentry: &Arc<Dentry>, parent_mnt: u64) -> KResult<bool> {
        if dentry.is_mounted() { return Ok(false); }
        let data = inode.private::<AutomountData>().ok_or(VfsError::Einval)?;
        let handle = crate::linux_debugfs::dentry_handle(data.path.clone());
        // SAFETY: callback and opaque data were supplied by debugfs_create_automount for this inode.
        let mnt = unsafe { (data.cb)(handle, data.data as *mut c_void) };
        // SAFETY: handle was allocated only to present a Linux-shaped dentry during this callback.
        unsafe { drop(Box::from_raw(handle)); }
        if mnt.is_null() { return Ok(false); }
        // SAFETY: returned pointer is an opaque Oxide LinuxVfsmount created for KPI callbacks.
        let mnt = unsafe { &*mnt };
        if mnt.magic != VFSMOUNT_MAGIC { return Err(VfsError::Einval); }
        vfs::mount::register_bind_at(Some(dentry.clone()), mnt.fs.clone(), mnt.root.clone(), Some(parent_mnt))?;
        Ok(true)
    }
}

/// Linux `debugfs_create_automount`. # C: O(path)
pub extern "C" fn debugfs_create_automount(
    name: *const c_char,
    parent: *mut LinuxDentry,
    cb: Option<DebugfsAutomount>,
    data: *mut c_void,
) -> *mut LinuxDentry {
    let Some(cb) = cb else { return null_mut(); };
    let path = match crate::linux_debugfs::entry_path(parent, name) { Some(p) => p, None => return null_mut() };
    let private = Arc::new(AutomountData { path: path.clone(), cb, data: data as usize });
    let inode = InodeBuilder::new(
        NEXT_INO.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        mk_mode(FileType::Directory, 0o755),
        Arc::new(AutomountOps),
        default_file_ops(),
    ).private(private).build();
    crate::linux_debugfs::create_path_entry(path, inode)
}

#[cfg(test)]
pub(crate) fn test_vfsmount(root: InodeRef) -> *mut LinuxVfsmount {
    let fs = Arc::new(AutomountFs { root: root.clone() });
    Box::into_raw(Box::new(LinuxVfsmount { magic: VFSMOUNT_MAGIC, fs, root }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;
    use core::ptr::null_mut;
    use core::sync::atomic::{AtomicU32, Ordering};

    static NEXT_NAME: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn mount_cb(_dentry: *mut LinuxDentry, data: *mut c_void) -> *mut LinuxVfsmount {
        // SAFETY: test passes a valid InodeRef pointer as callback data.
        let root = unsafe { (*(data as *const InodeRef)).clone() };
        test_vfsmount(root)
    }

    #[test]
    fn debugfs_automount_resolves_through_vfs_walk() {
        let n = NEXT_NAME.fetch_add(1, Ordering::Relaxed);
        let mut name = [0u8; 32];
        let prefix = b"auto";
        name[..prefix.len()].copy_from_slice(prefix);
        let digit = b'0' + (n % 10) as u8;
        name[prefix.len()] = digit;

        let mounted = kernfs::PseudoDir::new_root(0x6d20_0000 + n as u64, 0x6d21_0000 + n as u64);
        mounted.insert_path("leaf", vfs::make_static_file_inode(b"mounted\n"));
        let root_inode = mounted.as_inode();

        let d = debugfs_create_automount(
            name.as_ptr() as *const c_char,
            null_mut(),
            Some(mount_cb),
            &root_inode as *const InodeRef as *mut c_void,
        );
        assert!(!d.is_null());

        let debug_root = vfs::Dentry::new_root(tracefs::debug_root().as_inode());
        let path = alloc::format!("{}/leaf", core::str::from_utf8(&name[..prefix.len() + 1]).unwrap());
        let (inode, _) = vfs::path_lookup(debug_root.clone(), debug_root, &path, vfs::LookupFlags::default())
            .expect("automount path resolves");
        let mut buf = [0u8; 16];
        let len = inode.read(0, &mut buf).expect("mounted leaf read");
        assert_eq!(&buf[..len], b"mounted\n");

        crate::linux_debugfs::debugfs_remove(d);
    }
}
