// Projection of a name-keyed virtual device class into sysfs.
//
//   /sys/class/<class>/<name>              -> ../../devices/virtual/<class>/<name>
//   /sys/devices/virtual/<class>/<name>/   attributes, uevent, subsystem
//
// The class registries this projects are keyed by device name and resolved on
// every operation, so a retained inode for a departed device reports ENOENT
// instead of answering from a stale copy. One implementation serves every
// such class: a second copy per class is how two class trees end up
// disagreeing about which devices exist.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef,
          KResult, VfsError};

use crate::kobject::{make_attr_inode, Attribute, SysfsOps};
use crate::{DIR_PERM, RW_PERM};

/// The class-specific half of the projection: how to enumerate devices, what
/// attributes each publishes, and how to read/write them. Every callback is
/// keyed by device name and must report `None`/`ENOENT` for a name that is no
/// longer registered.
pub(crate) struct VirtualClass {
    /// `/sys/class/<name>` directory name and the uevent SUBSYSTEM.
    pub(crate) name: &'static str,
    /// Names of the currently registered devices.
    pub(crate) devices: fn() -> Vec<String>,
    /// Attribute files and modes for one device, or `None` when it is gone.
    pub(crate) attrs: fn(&str) -> Option<Vec<(&'static str, u16)>>,
    /// Render one attribute.
    pub(crate) show: fn(&str, &str) -> KResult<Vec<u8>>,
    /// Consume a write to one attribute.
    pub(crate) store: fn(&str, &str, &[u8]) -> KResult<usize>,
    /// `uevent` body lines for one device.
    pub(crate) uevent_env: fn(&str) -> Option<Vec<String>>,
    pub(crate) ino_class: Ino,
    pub(crate) ino_virtual: Ino,
    pub(crate) ino_device: Ino,
    pub(crate) ino_attr: Ino,
    pub(crate) ino_link: Ino,
}

impl VirtualClass {
    /// Whether `name` is currently registered. # C: O(N_devices)
    fn present(&self, name: &str) -> bool { (self.devices)().iter().any(|dev| dev == name) }

    /// Canonical device path used as the uevent DEVPATH. # C: O(1)
    fn devpath(&self, name: &str) -> String {
        alloc::format!("/devices/virtual/{}/{}", self.name, name)
    }
}

/// Emit a hotplug event for one device of `class`. # C: O(N_env)
pub(crate) fn emit_uevent(class: &'static VirtualClass, action: &str, name: &str) {
    let Some(env) = (class.uevent_env)(name) else { return; };
    let refs: Vec<&str> = env.iter().map(String::as_str).collect();
    ::netlink::emit_uevent_with_env(action, &class.devpath(name), class.name, &refs);
}

// ---- per-attribute leaf --------------------------------------------------

struct AttrOps { class: &'static VirtualClass, device: String }

impl SysfsOps for AttrOps {
    fn show(&self, attr: &str) -> KResult<Vec<u8>> { (self.class.show)(&self.device, attr) }
    fn store(&self, attr: &str, buf: &[u8]) -> KResult<usize> {
        (self.class.store)(&self.device, attr, buf)
    }
}

// ---- uevent leaf ---------------------------------------------------------

struct UeventData { class: &'static VirtualClass, device: String }
struct UeventOps;

impl FileOps for UeventOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<UeventData>().ok_or(VfsError::Einval)?;
        let env = (data.class.uevent_env)(&data.device).ok_or(VfsError::Enoent)?;
        let mut body = Vec::new();
        for line in env { body.extend_from_slice(line.as_bytes()); body.push(b'\n'); }
        Ok(crate::read_window(&body, off, buf))
    }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let data = inode.private::<UeventData>().ok_or(VfsError::Einval)?;
        if !data.class.present(&data.device) { return Err(VfsError::Enoent); }
        emit_uevent(data.class, crate::uevent_action(buf), &data.device);
        Ok(buf.len())
    }
}

fn make_uevent_inode(class: &'static VirtualClass, device: String) -> InodeRef {
    InodeBuilder::new(
        class.ino_attr,
        mk_mode(FileType::Regular, RW_PERM),
        crate::kobject::attr_inode_ops(),
        Arc::new(UeventOps),
    )
    .private(Arc::new(UeventData { class, device }))
    .build()
}

// ---- /sys/devices/virtual/<class>/<name> ---------------------------------

struct DeviceDirData { class: &'static VirtualClass, device: String }
struct DeviceDirOps;

/// Entries every class device carries beyond its own attributes.
const UEVENT_ENTRY: &str = "uevent";
const SUBSYSTEM_ENTRY: &str = "subsystem";
/// `/sys/devices/virtual/<class>/<name>` is four levels below `/sys`.
const SUBSYSTEM_LINK_PREFIX: &str = "../../../../class/";

impl InodeOps for DeviceDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<DeviceDirData>().ok_or(VfsError::Einval)?;
        let attrs = (data.class.attrs)(&data.device).ok_or(VfsError::Enoent)?;
        if name == UEVENT_ENTRY {
            return Ok(make_uevent_inode(data.class, data.device.clone()));
        }
        if name == SUBSYSTEM_ENTRY {
            return Ok(crate::make_symlink_inode_ino(
                alloc::format!("{SUBSYSTEM_LINK_PREFIX}{}", data.class.name).into_bytes(),
                data.class.ino_link,
            ));
        }
        let (attr, mode) = attrs.into_iter().find(|(attr, _)| *attr == name)
            .ok_or(VfsError::Enoent)?;
        Ok(make_attr_inode(
            &Attribute { name: attr, mode },
            Arc::new(AttrOps { class: data.class, device: data.device.clone() }),
            data.class.ino_attr,
        ))
    }
}

impl FileOps for DeviceDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = inode.private::<DeviceDirData>().ok_or(VfsError::Einval)?;
        let attrs = (data.class.attrs)(&data.device).ok_or(VfsError::Enoent)?;
        let mut entries: Vec<(&str, FileType)> = Vec::with_capacity(attrs.len() + 2);
        entries.push((UEVENT_ENTRY, FileType::Regular));
        entries.push((SUBSYSTEM_ENTRY, FileType::Symlink));
        for (attr, _) in attrs.iter() { entries.push((attr, FileType::Regular)); }
        crate::readdir::emit_table(inode, ctx, &entries)
    }
}

/// Build the `/sys/devices/virtual/<class>/<name>` directory. # C: O(1)
pub(crate) fn make_device_dir(class: &'static VirtualClass, device: String) -> InodeRef {
    InodeBuilder::new(
        class.ino_device,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DeviceDirOps),
        Arc::new(DeviceDirOps),
    )
    .private(Arc::new(DeviceDirData { class, device }))
    .build()
}

// ---- /sys/devices/virtual/<class> ----------------------------------------

struct ClassRootData { class: &'static VirtualClass }
struct VirtualRootOps;

impl InodeOps for VirtualRootOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<ClassRootData>().ok_or(VfsError::Einval)?;
        if !data.class.present(name) { return Err(VfsError::Enoent); }
        Ok(make_device_dir(data.class, String::from(name)))
    }
}

impl FileOps for VirtualRootOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = inode.private::<ClassRootData>().ok_or(VfsError::Einval)?;
        let names = (data.class.devices)();
        crate::readdir::emit_names(inode, ctx, names.iter().map(String::as_str),
            FileType::Directory)
    }
}

// ---- /sys/class/<class> --------------------------------------------------

struct ClassDirOps;

/// `/sys/class/<class>/<name>` is two levels below `/sys`.
const CLASS_LINK_PREFIX: &str = "../../devices/virtual/";

impl InodeOps for ClassDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<ClassRootData>().ok_or(VfsError::Einval)?;
        if !data.class.present(name) { return Err(VfsError::Enoent); }
        Ok(crate::make_symlink_inode_ino(
            alloc::format!("{CLASS_LINK_PREFIX}{}/{name}", data.class.name).into_bytes(),
            data.class.ino_link,
        ))
    }
}

impl FileOps for ClassDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = inode.private::<ClassRootData>().ok_or(VfsError::Einval)?;
        let names = (data.class.devices)();
        crate::readdir::emit_names(inode, ctx, names.iter().map(String::as_str),
            FileType::Symlink)
    }
}

/// Build the `/sys/class/<class>` directory. # C: O(1)
pub(crate) fn make_class_dir(class: &'static VirtualClass) -> InodeRef {
    InodeBuilder::new(
        class.ino_class,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(ClassDirOps),
        Arc::new(ClassDirOps),
    )
    .private(Arc::new(ClassRootData { class }))
    .build()
}

/// Build the `/sys/devices/virtual/<class>` directory. # C: O(1)
pub(crate) fn make_virtual_dir(class: &'static VirtualClass) -> InodeRef {
    InodeBuilder::new(
        class.ino_virtual,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(VirtualRootOps),
        Arc::new(VirtualRootOps),
    )
    .private(Arc::new(ClassRootData { class }))
    .build()
}

/// Register both halves of a virtual class's sysfs tree. # C: O(1)
pub(crate) fn register(class: &'static VirtualClass) {
    crate::register(
        &alloc::format!("/sys/devices/virtual/{}", class.name),
        make_virtual_dir(class),
    );
    crate::register(&alloc::format!("/sys/class/{}", class.name), make_class_dir(class));
}
