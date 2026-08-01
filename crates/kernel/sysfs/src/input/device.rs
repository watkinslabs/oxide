use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{
    mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult,
    VfsError,
};

use super::attrs;
use super::model::{
    input_by_addr, input_by_identity, parent_device_target, InputDevInfo, InputIdentity,
    INO_INPUT_ATTR, INO_INPUT_DIR,
};
use crate::{DIR_PERM, RW_PERM};

fn input_uevent_body(info: &InputDevInfo) -> Vec<u8> {
    alloc::format!(
        "MAJOR={}\nMINOR={}\nDEVNAME={}\n",
        info.dev_t.0, info.dev_t.1, info.devname,
    ).into_bytes()
}

fn input_parent_uevent_body(info: &InputDevInfo) -> Vec<u8> {
    let mut body = Vec::new();
    for entry in input::uevent_env_for(&info.model) {
        body.extend_from_slice(&entry);
        body.push(b'\n');
    }
    body
}

struct InputUeventData { identity: InputIdentity }
struct InputUeventOps;

impl FileOps for InputUeventOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<InputUeventData>().ok_or(VfsError::Einval)?;
        let info = input_by_identity(&data.identity).ok_or(VfsError::Enoent)?;
        Ok(crate::read_window(&input_uevent_body(&info), off, buf))
    }

    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let data = inode.private::<InputUeventData>().ok_or(VfsError::Einval)?;
        let info = input_by_identity(&data.identity).ok_or(VfsError::Enoent)?;
        let devpath = alloc::format!(
            "/{}",
            info.sysfs_event_canon().ok_or(VfsError::Enoent)?,
        );
        let devname = alloc::format!("DEVNAME={}", info.devname);
        let major = alloc::format!("MAJOR={}", info.dev_t.0);
        let minor = alloc::format!("MINOR={}", info.dev_t.1);
        let env: [&[u8]; 3] = [devname.as_bytes(), major.as_bytes(), minor.as_bytes()];
        ::netlink::emit_uevent_with_env_bytes(
            crate::uevent_action(buf),
            &devpath,
            "input",
            &env,
        );
        Ok(buf.len())
    }
}

fn make_input_uevent_inode(info: &InputDevInfo) -> InodeRef {
    InodeBuilder::new(
        INO_INPUT_ATTR,
        mk_mode(FileType::Regular, RW_PERM),
        crate::kobject::attr_inode_ops(),
        Arc::new(InputUeventOps),
    )
    .private(Arc::new(InputUeventData { identity: info.identity() }))
    .build()
}

struct InputParentUeventData { identity: InputIdentity }
struct InputParentUeventOps;

impl FileOps for InputParentUeventOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<InputParentUeventData>().ok_or(VfsError::Einval)?;
        let info = input_by_identity(&data.identity).ok_or(VfsError::Enoent)?;
        Ok(crate::read_window(&input_parent_uevent_body(&info), off, buf))
    }

    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let data = inode.private::<InputParentUeventData>().ok_or(VfsError::Einval)?;
        let info = input_by_identity(&data.identity).ok_or(VfsError::Enoent)?;
        let devpath = alloc::format!(
            "/{}",
            info.sysfs_parent_canon().ok_or(VfsError::Enoent)?,
        );
        let env = input::uevent_env_for(&info.model);
        let refs: Vec<&[u8]> = env.iter().map(Vec::as_slice).collect();
        ::netlink::emit_uevent_with_env_bytes(
            crate::uevent_action(buf),
            &devpath,
            "input",
            &refs,
        );
        Ok(buf.len())
    }
}

fn make_input_parent_uevent_inode(info: &InputDevInfo) -> InodeRef {
    InodeBuilder::new(
        INO_INPUT_ATTR,
        mk_mode(FileType::Regular, RW_PERM),
        crate::kobject::attr_inode_ops(),
        Arc::new(InputParentUeventOps),
    )
    .private(Arc::new(InputParentUeventData { identity: info.identity() }))
    .build()
}

struct InputDevDirData { identity: InputIdentity }
struct InputDevDirOps;

impl InodeOps for InputDevDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<InputDevDirData>().ok_or(VfsError::Einval)?;
        let info = input_by_identity(&data.identity).ok_or(VfsError::Enoent)?;
        match name {
            "uevent" => Ok(make_input_uevent_inode(&info)),
            "dev" => Ok(crate::make_body_inode(
                alloc::format!("{}:{}\n", info.dev_t.0, info.dev_t.1).into_bytes(),
                INO_INPUT_ATTR,
            )),
            "subsystem" => Ok(crate::make_symlink_inode(
                alloc::format!(
                    "{}class/input",
                    crate::bus::ups_prefix(
                        &info.sysfs_event_canon().ok_or(VfsError::Enoent)?,
                    ),
                ).into_bytes(),
            )),
            "device" => Ok(crate::make_symlink_inode(
                alloc::format!("../../input{}", info.model.input_id).into_bytes(),
            )),
            _ => Err(VfsError::Enoent),
        }
    }
}

impl FileOps for InputDevDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const ENTRIES: &[(&str, FileType)] = &[
            ("uevent", FileType::Regular),
            ("dev", FileType::Regular),
            ("subsystem", FileType::Symlink),
            ("device", FileType::Symlink),
        ];
        let data = inode.private::<InputDevDirData>().ok_or(VfsError::Einval)?;
        let _info = input_by_identity(&data.identity).ok_or(VfsError::Enoent)?;
        emit_entries(inode, ctx, ENTRIES)
    }
}

fn make_input_event_dir(info: &InputDevInfo) -> InodeRef {
    InodeBuilder::new(
        INO_INPUT_DIR,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(InputDevDirOps),
        Arc::new(InputDevDirOps),
    )
    .private(Arc::new(InputDevDirData { identity: info.identity() }))
    .build()
}

struct InputParentDirData { identity: Option<InputIdentity> }
struct InputParentDirOps;

impl InodeOps for InputParentDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<InputParentDirData>().ok_or(VfsError::Einval)?;
        let identity = data.identity.as_ref().ok_or(VfsError::Enoent)?;
        let info = input_by_identity(identity).ok_or(VfsError::Enoent)?;
        if let Some(attr) = attrs::lookup(&info, name) {
            return attr;
        }
        match name {
            "uevent" => Ok(make_input_parent_uevent_inode(&info)),
            "subsystem" => Ok(crate::make_symlink_inode(
                alloc::format!(
                    "{}class/input",
                    crate::bus::ups_prefix(
                        &info.sysfs_parent_canon().ok_or(VfsError::Enoent)?,
                    ),
                ).into_bytes(),
            )),
            "device" => Ok(crate::make_symlink_inode(
                parent_device_target(&info).ok_or(VfsError::Enoent)?,
            )),
            child if child == info.addr => Ok(make_input_event_dir(&info)),
            _ => Err(VfsError::Enoent),
        }
    }
}

impl FileOps for InputParentDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const BASE_ENTRIES: &[(&str, FileType)] = &[
            ("uevent", FileType::Regular),
            ("subsystem", FileType::Symlink),
        ];
        let data = inode.private::<InputParentDirData>().ok_or(VfsError::Einval)?;
        let identity = data.identity.as_ref().ok_or(VfsError::Enoent)?;
        let info = input_by_identity(identity).ok_or(VfsError::Enoent)?;
        let mut entries: Vec<(&str, FileType)> = BASE_ENTRIES.to_vec();
        entries.extend_from_slice(attrs::PARENT_ENTRIES);
        if parent_device_target(&info).is_some() {
            entries.push(("device", FileType::Symlink));
        }
        entries.push((info.addr.as_str(), FileType::Directory));
        emit_entries(inode, ctx, &entries)
    }
}

fn emit_entries(
    inode: &Inode,
    ctx: &mut DirContext,
    entries: &[(&str, FileType)],
) -> KResult<()> {
    crate::readdir::emit_table(inode, ctx, entries)
}

pub(super) fn make_input_parent_dir(addr: String) -> InodeRef {
    let identity = input_by_addr(&addr).map(|info| info.identity());
    InodeBuilder::new(
        INO_INPUT_DIR,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(InputParentDirOps),
        Arc::new(InputParentDirOps),
    )
    .private(Arc::new(InputParentDirData { identity }))
    .build()
}
