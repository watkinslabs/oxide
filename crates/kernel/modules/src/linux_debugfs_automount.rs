extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;

use vfs::{Dentry, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, FileSystemType, default_file_ops, mk_mode};

use crate::linux_debugfs::LinuxDentry;

const VFSMOUNT_MAGIC: u32 = 0x5646_534d;

static NEXT_INO: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(crate::linux_debugfs_ids::AUTOMOUNT_INO_BASE);

type DebugfsAutomount = unsafe extern "C" fn(*mut LinuxDentry, *mut c_void) -> *mut LinuxVfsmount;

/// Opaque `struct vfsmount` handed back by a `d_automount` callback. Carries the
/// `file_system_type` its superblock was built from (`mnt->mnt_sb->s_type`), so
/// the graft never re-derives a type from `fs.name()` through the global
/// registry — Linux binds the type at mount-construction time and
/// `finish_automount` performs no name lookup.
pub struct LinuxVfsmount {
    magic:  u32,
    s_type: Arc<dyn FileSystemType>,
    fs:     Arc<dyn vfs::fs::FileSystem>,
    root:   InodeRef,
}

/// Linux `vfs_kern_mount`: build an unattached mount from an EXPLICIT
/// `file_system_type` plus the realized fs and its root inode. Ownership of the
/// returned box passes to whoever consumes it (`finish_automount` semantics).
/// # C: O(1)
pub fn vfs_kern_mount(s_type: Arc<dyn FileSystemType>, fs: Arc<dyn vfs::fs::FileSystem>,
    root: InodeRef) -> *mut LinuxVfsmount {
    Box::into_raw(Box::new(LinuxVfsmount { magic: VFSMOUNT_MAGIC, s_type, fs, root }))
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
        // A NULL vfsmount means "nothing to mount here" (Linux finish_automount: !m ⇒ 0).
        if mnt.is_null() { return Ok(false); }
        // SAFETY: returned pointer is an opaque Oxide LinuxVfsmount minted by vfs_kern_mount;
        // finish_automount consumes the reference, so take ownership of the box here.
        let mnt = unsafe { Box::from_raw(mnt) };
        if mnt.magic != VFSMOUNT_MAGIC { return Err(VfsError::Einval); }
        // Linux finish_automount: a mount whose root IS the trigger dentry would
        // mount onto itself ⇒ ELOOP.
        if dentry.inode().is_some_and(|d| Arc::ptr_eq(&mnt.root, &d)) { return Err(VfsError::Eloop); }
        vfs::mount::register_bind_typed_at(mnt.s_type.clone(), Some(dentry.clone()),
            mnt.fs.clone(), mnt.root.clone(), Some(parent_mnt))?;
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
mod tests {
    use super::*;
    use core::ffi::c_void;
    use core::ptr::null_mut;
    use core::sync::atomic::{AtomicU32, Ordering};

    const DEBUGFS_MAGIC: u64 = tracefs::fs_impl::DEBUGFS_SUPER_MAGIC;
    /// Deliberately NEVER passed to `register_filesystem`: the automount graft
    /// must bind the type the producer handed it, exactly as Linux's
    /// `finish_automount` does, without consulting the name registry.
    const UNREGISTERED_FS_NAME: &str = "debugfs-automount";

    static NEXT_NAME: AtomicU32 = AtomicU32::new(0);

    struct AutomountFs { root: InodeRef }
    impl vfs::fs::FileSystem for AutomountFs {
        fn name(&self) -> &str { UNREGISTERED_FS_NAME }
        fn magic(&self) -> u64 { DEBUGFS_MAGIC }
        fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
    }

    struct AutomountType;
    impl FileSystemType for AutomountType {
        fn name(&self) -> &str { UNREGISTERED_FS_NAME }
        fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<vfs::SuperBlock>> {
            Err(VfsError::Einval)
        }
    }

    fn submount(root: InodeRef) -> *mut LinuxVfsmount {
        let fs = Arc::new(AutomountFs { root: root.clone() });
        vfs_kern_mount(Arc::new(AutomountType), fs, root)
    }

    unsafe extern "C" fn mount_cb(_dentry: *mut LinuxDentry, data: *mut c_void) -> *mut LinuxVfsmount {
        // SAFETY: test passes a valid InodeRef pointer as callback data.
        let root = unsafe { (*(data as *const InodeRef)).clone() };
        submount(root)
    }

    unsafe extern "C" fn loop_cb(_dentry: *mut LinuxDentry, data: *mut c_void) -> *mut LinuxVfsmount {
        // SAFETY: test passes a live `Option<InodeRef>` slot, populated before the walk.
        let root = unsafe { (*(data as *const Option<InodeRef>)).clone() };
        match root { Some(r) => submount(r), None => null_mut() }
    }

    fn entry_name(buf: &mut [u8; 32], prefix: &[u8], n: u32) -> String {
        buf[..prefix.len()].copy_from_slice(prefix);
        buf[prefix.len()] = b'0' + (n % 10) as u8;
        String::from(core::str::from_utf8(&buf[..prefix.len() + 1]).unwrap())
    }

    /// Linux `finish_automount`: a returned mount whose root IS the trigger
    /// dentry mounts onto itself ⇒ `ELOOP`. The same walk with `AT_NO_AUTOMOUNT`
    /// never fires the trigger, so it resolves to the empty trigger directory.
    #[test]
    fn automount_onto_own_root_is_eloop_and_no_automount_skips_trigger() {
        let n = NEXT_NAME.fetch_add(1, Ordering::Relaxed);
        let mut buf = [0u8; 32];
        let name = entry_name(&mut buf, b"loop", n);
        let mut cname = [0u8; 32];
        cname[..name.len()].copy_from_slice(name.as_bytes());

        let mut loop_root: Option<InodeRef> = None;
        let d = debugfs_create_automount(
            cname.as_ptr() as *const c_char,
            null_mut(),
            Some(loop_cb),
            &mut loop_root as *mut Option<InodeRef> as *mut c_void,
        );
        assert!(!d.is_null());

        // AT_NO_AUTOMOUNT: trigger is traversed as the plain directory it is.
        let root = || vfs::Dentry::new_root(tracefs::debug_root().as_inode());
        let no_auto = vfs::LookupFlags { no_automount: true, ..Default::default() };
        let (trigger, _) = vfs::path_lookup(root(), root(), &name, no_auto)
            .expect("AT_NO_AUTOMOUNT resolves the trigger itself");

        // Control: with the slot still empty the callback returns a NULL vfsmount,
        // which is "nothing to mount here" (Linux finish_automount: !m ⇒ 0), not an error.
        assert!(vfs::path_lookup(root(), root(), &name, vfs::LookupFlags::default()).is_ok(),
            "NULL vfsmount leaves the trigger resolvable");

        // Now make the callback return a mount rooted AT the trigger inode.
        loop_root = Some(trigger);
        assert_eq!(vfs::path_lookup(root(), root(), &name, vfs::LookupFlags::default()).err(),
            Some(VfsError::Eloop), "mount onto its own root ⇒ ELOOP");
        assert!(loop_root.is_some(), "callback slot stayed live across the walk");

        crate::linux_debugfs::debugfs_remove(d);
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

        // The graft must not depend on a registry entry for the submount's type.
        assert!(vfs::fs::get_fs_type(UNREGISTERED_FS_NAME).is_none(),
            "automount fs type is deliberately unregistered");

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
