//! Linux `/sys/class/zram-control` ABI.

use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::kobject::{make_attr_inode, Attribute, AttrGroup, SysfsOps};
use crate::{DIR_PERM, WO_PERM};

const ROOT: Ino = crate::ids::ZRAM_CONTROL_ROOT;
const HOT_ADD_PERM: u16 = 0o400;
const ATTRS: &[Attribute] = &[
    Attribute { name: "hot_add", mode: HOT_ADD_PERM },
    Attribute { name: "hot_remove", mode: WO_PERM },
];
static GROUP: AttrGroup = AttrGroup { attrs: ATTRS };

/// `/sys/class/zram-control` leaves have separate VFS inode identities.
/// # C: O(1)
fn attr_ino(name: &str) -> KResult<Ino> {
    match name {
        "hot_add" => Ok(crate::ids::ZRAM_CONTROL_HOT_ADD),
        "hot_remove" => Ok(crate::ids::ZRAM_CONTROL_HOT_REMOVE),
        _ => Err(VfsError::Enoent),
    }
}

struct Control;
impl SysfsOps for Control {
    fn show(&self, attr: &str) -> KResult<Vec<u8>> {
        match attr {
            "hot_add" => Ok(alloc::format!("{}\n", drv_zram::hot_add().map_err(|_| VfsError::Enomem)?).into_bytes()),
            _ => Err(VfsError::Erofs),
        }
    }

    fn store(&self, attr: &str, buf: &[u8]) -> KResult<usize> {
        if attr != "hot_remove" { return Err(VfsError::Erofs); }
        let index = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?.trim().parse()
            .map_err(|_| VfsError::Einval)?;
        drv_zram::hot_remove(index).map_err(|error| match error {
            block::BlockError::Ebusy => VfsError::Ebusy,
            block::BlockError::Einval => VfsError::Enodev,
            _ => VfsError::Einval,
        })?;
        Ok(buf.len())
    }
}

struct RootOps;
impl InodeOps for RootOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let attr = GROUP.find(name).ok_or(VfsError::Enoent)?;
        Ok(make_attr_inode(attr, Arc::new(Control), attr_ino(name)?))
    }
}
impl FileOps for RootOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        while (ctx.pos as usize) < GROUP.attrs.len() {
            let name = GROUP.attrs[ctx.pos as usize].name;
            let next = ctx.pos + 1;
            if !ctx.emit(name, inode.lookup(name).map(|child| child.ino()).unwrap_or(0), FileType::Regular, next) { break; }
            ctx.pos = next;
        }
        Ok(())
    }
}

fn root() -> InodeRef {
    InodeBuilder::new(ROOT, mk_mode(FileType::Directory, DIR_PERM), Arc::new(RootOps), Arc::new(RootOps)).build()
}

/// Linux built-in `zram.num_devices=` parameter name.
const NUM_DEVICES_PARAMETER: &[u8] = b"zram.num_devices";

fn parse_num_devices(value: &[u8]) -> Option<u32> {
    core::str::from_utf8(value).ok()?.parse::<u32>().ok()
}

fn configured_num_devices() -> u32 {
    let Some(value) = cmdline::parameter_value(NUM_DEVICES_PARAMETER) else {
        return drv_zram::DEFAULT_NUM_DEVICES;
    };
    parse_num_devices(value).unwrap_or(drv_zram::DEFAULT_NUM_DEVICES)
}

pub fn init() {
    drv_zram::init_with_num_devices(configured_num_devices())
        .expect("zram default-device initialization");
    crate::register("/sys/class/zram-control", root());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num_devices_parser_accepts_linux_unsigned_range_and_rejects_invalid_text() {
        const ZERO_DEVICES: u32 = 0;
        const THREE_DEVICES: u32 = 3;
        assert_eq!(parse_num_devices(b"0"), Some(ZERO_DEVICES));
        assert_eq!(parse_num_devices(b"3"), Some(THREE_DEVICES));
        assert_eq!(parse_num_devices(b"invalid"), None);
        assert_eq!(parse_num_devices(b"-1"), None);
    }

    #[test]
    fn hot_add_read_publishes_exact_block_disk() {
        let root = root();
        let add = root.lookup("hot_add").unwrap();
        let mut out = [0u8; 16];
        let size = add.read(0, &mut out).unwrap();
        let index = core::str::from_utf8(&out[..size]).unwrap().trim().parse::<u32>().unwrap();
        let name = alloc::format!("zram{}", index);
        assert!(block::registry::by_name(&name).is_some());
        let remove = root.lookup("hot_remove").unwrap();
        let text = alloc::format!("{}\n", index);
        assert_eq!(remove.write(0, text.as_bytes()), Ok(text.len()));
        assert!(block::registry::by_name(&name).is_none());
    }

    #[test]
    fn hot_add_partial_file_reads_publish_one_disk_per_open() {
        let root = root();
        let add = root.lookup("hot_add").unwrap();
        let dentry = vfs::Dentry::new_root(add);
        let fdt = vfs::FdTable::new();
        let fd = vfs::file::install_open_at(&fdt, dentry.inode().expect("hot_add dentry inode"), dentry,
            vfs::OpenFlags::O_RDONLY, 0, vfs::FileCred::root(), usize::MAX, None).unwrap();
        let file = fdt.get(fd).unwrap();
        let mut byte = [0u8; 1];
        let mut text = Vec::new();
        while file.read(&mut byte).unwrap() != 0 { text.push(byte[0]); }
        let index = core::str::from_utf8(&text).unwrap().trim().parse::<u32>().unwrap();
        let name = alloc::format!("zram{}", index);
        assert!(block::registry::by_name(&name).is_some());
        assert_eq!(fdt.close(fd), Ok(()));
        assert!(drv_zram::hot_remove(index).is_ok());
        assert!(block::registry::by_name(&name).is_none());
    }

    #[test]
    fn control_leaves_have_distinct_inode_identities() {
        let root = root();
        let hot_add = root.lookup("hot_add").unwrap();
        let hot_remove = root.lookup("hot_remove").unwrap();
        assert_ne!(hot_add.ino(), hot_remove.ino());
    }
}
