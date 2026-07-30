// Linux input parent identity and capability attributes. The canonical input
// registry owns every value; sysfs only renders its live snapshot.

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use super::model::{
    input_by_identity, InputDevInfo, InputIdentity, INO_INPUT_ATTR, INO_INPUT_DIR,
};
use crate::DIR_PERM;

pub(super) const PARENT_ENTRIES: &[(&str, FileType)] = &[
    ("name", FileType::Regular),
    ("phys", FileType::Regular),
    ("uniq", FileType::Regular),
    ("modalias", FileType::Regular),
    ("properties", FileType::Regular),
    ("inhibited", FileType::Regular),
    ("id", FileType::Directory),
    ("capabilities", FileType::Directory),
];

const ID_ENTRIES: &[(&str, FileType)] = &[
    ("bustype", FileType::Regular),
    ("vendor", FileType::Regular),
    ("product", FileType::Regular),
    ("version", FileType::Regular),
];

const CAP_ENTRIES: &[(&str, FileType)] = &[
    ("ev", FileType::Regular),
    ("key", FileType::Regular),
    ("rel", FileType::Regular),
    ("abs", FileType::Regular),
    ("msc", FileType::Regular),
    ("led", FileType::Regular),
    ("snd", FileType::Regular),
    ("ff", FileType::Regular),
    ("sw", FileType::Regular),
];

fn text_body(bytes: &[u8], declared: usize) -> Vec<u8> {
    let declared = declared.min(bytes.len());
    let end = bytes[..declared].iter().position(|byte| *byte == 0).unwrap_or(declared);
    let mut body = bytes[..end].to_vec();
    body.push(b'\n');
    body
}

fn bitmap_body(bits: &[u8]) -> Vec<u8> {
    let mut body = input::format_bitmap(bits).into_bytes();
    body.push(b'\n');
    body
}

fn id_body(id: u16) -> Vec<u8> {
    alloc::format!("{id:04x}\n").into_bytes()
}

fn make_attr(body: Vec<u8>) -> InodeRef {
    crate::make_body_inode(body, INO_INPUT_ATTR)
}

struct IdDirData { identity: InputIdentity }
struct IdDirOps;

impl InodeOps for IdDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<IdDirData>().ok_or(VfsError::Einval)?;
        let ids = input_by_identity(&data.identity)
            .ok_or(VfsError::Enoent)?.model.ids;
        let value = match name {
            "bustype" => ids.bustype,
            "vendor" => ids.vendor,
            "product" => ids.product,
            "version" => ids.version,
            _ => return Err(VfsError::Enoent),
        };
        Ok(make_attr(id_body(value)))
    }
}

impl FileOps for IdDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = inode.private::<IdDirData>().ok_or(VfsError::Einval)?;
        let _info = input_by_identity(&data.identity).ok_or(VfsError::Enoent)?;
        emit(inode, ctx, ID_ENTRIES)
    }
}

fn make_id_dir(info: &InputDevInfo) -> InodeRef {
    InodeBuilder::new(
        INO_INPUT_DIR,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(IdDirOps),
        Arc::new(IdDirOps),
    )
    .private(Arc::new(IdDirData { identity: info.identity() }))
    .build()
}

struct CapDirData { identity: InputIdentity }
struct CapDirOps;

impl InodeOps for CapDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<CapDirData>().ok_or(VfsError::Einval)?;
        let dev = input_by_identity(&data.identity)
            .ok_or(VfsError::Enoent)?.model;
        let bits: &[u8] = match name {
            "ev" => &dev.ev_bits,
            "key" => &dev.key_bits.bits,
            "rel" => &dev.rel_bits.bits,
            "abs" => &dev.abs_bits.bits,
            "msc" => &dev.msc_bits.bits,
            "led" => &dev.led_bits.bits,
            "snd" => &dev.snd_bits.bits,
            "ff" => &dev.ff_bits.bits,
            "sw" => &dev.sw_bits.bits,
            _ => return Err(VfsError::Enoent),
        };
        Ok(make_attr(bitmap_body(bits)))
    }
}

impl FileOps for CapDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = inode.private::<CapDirData>().ok_or(VfsError::Einval)?;
        let _info = input_by_identity(&data.identity).ok_or(VfsError::Enoent)?;
        emit(inode, ctx, CAP_ENTRIES)
    }
}

fn make_cap_dir(info: &InputDevInfo) -> InodeRef {
    InodeBuilder::new(
        INO_INPUT_DIR,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(CapDirOps),
        Arc::new(CapDirOps),
    )
    .private(Arc::new(CapDirData { identity: info.identity() }))
    .build()
}

fn emit(inode: &Inode, ctx: &mut DirContext, entries: &[(&str, FileType)]) -> KResult<()> {
    let mut idx = ctx.pos as usize;
    while idx < entries.len() {
        let (name, ty) = entries[idx];
        let next = idx as u64 + 1;
        let ino = inode.lookup(name).map(|child| child.ino()).unwrap_or(0);
        if !ctx.emit(name, ino, ty, next) { return Ok(()); }
        idx += 1;
    }
    Ok(())
}

pub(super) fn lookup(info: &InputDevInfo, name: &str) -> Option<KResult<InodeRef>> {
    let dev = &info.model;
    let result = match name {
        "name" => Ok(make_attr(text_body(&dev.name, dev.name_len))),
        "phys" => Ok(make_attr(text_body(&dev.phys, dev.phys_len))),
        "uniq" => Ok(make_attr(text_body(&dev.serial, dev.serial_len))),
        "modalias" => Ok(make_attr(
            alloc::format!("{}\n", input::modalias(dev)).into_bytes(),
        )),
        "properties" => Ok(make_attr(bitmap_body(&dev.prop_bits))),
        "inhibited" => Ok(super::inhibited::make_attr(info)),
        "id" => Ok(make_id_dir(info)),
        "capabilities" => Ok(make_cap_dir(info)),
        _ => return None,
    };
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTR_READ_BUFFER_BYTES: usize = 256;
    const TEST_DEVICE_KEY_RAW: u32 = 0x7a00_0000;
    const TEST_BUS_TYPE: u16 = 0x0006;
    const TEST_VENDOR_ID: u16 = 0x1af4;
    const TEST_PRODUCT_ID: u16 = 0x1052;
    const TEST_VERSION_ID: u16 = 0x0001;
    const TEST_DEVICE_CLASS: u32 = 6;
    const PROP_DIRECT_MASK: u8 = 0x02;
    const EV_BASE_MASK: u8 = 0x3e;
    const EV_REP_BYTE: usize = 2;
    const EV_REP_BASE_MASK: u8 = 0x06;
    const EV_FF_MASK: u8 = 0x20;
    const KEY_LOW_BYTE: usize = 3;
    const KEY_HIGH_BYTE: usize = 8;
    const KEY_MASK: u8 = 0x40;
    const REL_MASK: u8 = 0x03;
    const ABS_MASK: u8 = 0x01;
    const MSC_MASK: u8 = 0x10;
    const LED_MASK: u8 = 0x04;
    const SND_MASK: u8 = 0x08;
    const SW_MASK: u8 = 0x40;

    fn read_body(inode: &InodeRef) -> Vec<u8> {
        let mut buf = [0u8; ATTR_READ_BUFFER_BYTES];
        let n = inode.read(0, &mut buf).expect("read sysfs attribute");
        buf[..n].to_vec()
    }

    #[test]
    fn input_parent_projects_canonical_identity_and_capabilities() {
        let _serial = super::super::tests::INPUT_TEST_MUTEX.lock()
            .unwrap_or_else(|err| err.into_inner());
        input::clear_devices_for_tests();
        let key = input::VirtioChildDeviceKey::from_raw(TEST_DEVICE_KEY_RAW);
        let mut model = input::VirtioInputDev::empty(key);
        let name = b"oxide keyboard";
        model.name[..name.len()].copy_from_slice(name);
        model.name_len = name.len();
        model.name_present = true;
        let phys = b"virtio6/input0";
        model.phys[..phys.len()].copy_from_slice(phys);
        model.phys_len = phys.len();
        model.phys_present = true;
        let uniq = b"seat-input-6";
        model.serial[..uniq.len()].copy_from_slice(uniq);
        model.serial_len = uniq.len();
        model.serial_present = true;
        model.ids = input::VirtioInputDevIds {
            bustype: TEST_BUS_TYPE,
            vendor: TEST_VENDOR_ID,
            product: TEST_PRODUCT_ID,
            version: TEST_VERSION_ID,
        };
        model.prop_bits[0] = PROP_DIRECT_MASK;
        model.ev_bits[0] = EV_BASE_MASK;
        model.ev_bits[EV_REP_BYTE] = EV_REP_BASE_MASK;
        model.ev_bits[EV_REP_BYTE] |= EV_FF_MASK;
        model.key_bits.bits[KEY_LOW_BYTE] = KEY_MASK;
        model.key_bits.bits[KEY_HIGH_BYTE] = KEY_MASK;
        model.rel_bits.bits[0] = REL_MASK;
        model.abs_bits.bits[0] = ABS_MASK;
        model.msc_bits.bits[0] = MSC_MASK;
        model.led_bits.bits[0] = LED_MASK;
        model.snd_bits.bits[0] = SND_MASK;
        model.ff_bits.bits[0] = EV_FF_MASK;
        model.sw_bits.bits[0] = SW_MASK;
        let (input_id, evdev_id) = input::install(model).expect("test input model");

        let input_dev = Arc::new(
            drv::Device::new(
                "input",
                alloc::format!("event{evdev_id}"),
                0,
                0,
                TEST_DEVICE_CLASS,
            )
                .with_sysfs_relpath(alloc::format!(
                    "input{input_id}/event{evdev_id}",
                ))
                .with_devnode(
                    "input",
                    alloc::format!("input/event{evdev_id}"),
                    Some((input::INPUT_MAJOR, input::EVENT_MINOR_BASE + evdev_id)),
                ),
        );
        drv::try_device_add(Arc::clone(&input_dev)).expect("test input registration");
        let parent = super::super::device::make_input_parent_dir(
            alloc::format!("event{evdev_id}"),
        );

        assert_eq!(read_body(&parent.lookup("name").expect("name")), b"oxide keyboard\n");
        assert_eq!(read_body(&parent.lookup("phys").expect("phys")), b"virtio6/input0\n");
        assert_eq!(read_body(&parent.lookup("uniq").expect("uniq")), b"seat-input-6\n");
        assert!(read_body(&parent.lookup("modalias").expect("modalias"))
            .starts_with(b"input:b0006v1AF4p1052e0001-"));
        assert_eq!(read_body(&parent.lookup("properties").expect("properties")), b"2\n");
        let ids = parent.lookup("id").expect("id directory");
        assert_eq!(read_body(&ids.lookup("bustype").expect("bustype")), b"0006\n");
        assert_eq!(read_body(&ids.lookup("vendor").expect("vendor")), b"1af4\n");
        assert_eq!(read_body(&ids.lookup("product").expect("product")), b"1052\n");
        assert_eq!(read_body(&ids.lookup("version").expect("version")), b"0001\n");
        let caps = parent.lookup("capabilities").expect("capabilities directory");
        assert_eq!(read_body(&caps.lookup("ev").expect("ev")), b"26003f\n");
        assert_eq!(read_body(&caps.lookup("key").expect("key")), b"40 40000000\n");
        assert_eq!(read_body(&caps.lookup("rel").expect("rel")), b"3\n");
        assert_eq!(read_body(&caps.lookup("abs").expect("abs")), b"1\n");
        assert_eq!(read_body(&caps.lookup("msc").expect("msc")), b"10\n");
        assert_eq!(read_body(&caps.lookup("led").expect("led")), b"4\n");
        assert_eq!(read_body(&caps.lookup("snd").expect("snd")), b"8\n");
        assert_eq!(read_body(&caps.lookup("ff").expect("ff")), b"20\n");
        assert_eq!(read_body(&caps.lookup("sw").expect("sw")), b"40\n");

        assert_eq!(input_id, 0);
        drv::device_del(&input_dev);
        assert_eq!(input::remove_device(key), Some(evdev_id));
        input::clear_devices_for_tests();
    }
}
