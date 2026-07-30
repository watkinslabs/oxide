use alloc::sync::Arc;

use vfs::{Dentry, File, OpenFlags};

use crate::devfs::make_evdev_inode;

const TEST_DEVICE_KEY_BASE: u32 = 0x7000_0000;

pub(super) fn test_file(id: u32) -> Arc<File> {
    test_file_with_flags(id, OpenFlags::O_RDONLY | OpenFlags::O_NONBLOCK)
}

pub(super) fn test_file_with_flags(id: u32, flags: OpenFlags) -> Arc<File> {
    let inode = make_evdev_inode(id);
    let file = File::new(
        inode.clone(),
        Dentry::new_anon(inode),
        flags,
    );
    file.open_hook().expect("open evdev client");
    file
}

pub(super) fn test_dev(id: u32) -> crate::VirtioInputDev {
    crate::VirtioInputDev::empty(
        virtio::VirtioChildDeviceKey::from_raw(TEST_DEVICE_KEY_BASE + id),
    )
}

pub(super) fn evio_read(nr: u32, size: usize) -> u64 {
    ((crate::IOC_READ as u64) << crate::IOC_DIR_SHIFT)
        | ((size as u64) << crate::IOC_SIZE_SHIFT)
        | ((crate::EVIOC_GROUP as u64) << crate::IOC_TYPE_SHIFT)
        | u64::from(nr)
}

pub(super) fn output_record(
    ev_type: u16,
    code: u16,
    value: i32,
) -> [u8; crate::evdev_queue::INPUT_EVENT_BYTES] {
    const EVENT_TYPE_OFF: usize = core::mem::size_of::<u64>() * 2;
    const EVENT_CODE_OFF: usize = EVENT_TYPE_OFF + core::mem::size_of::<u16>();
    const EVENT_VALUE_OFF: usize = EVENT_CODE_OFF + core::mem::size_of::<u16>();

    let mut record = [0; crate::evdev_queue::INPUT_EVENT_BYTES];
    record[EVENT_TYPE_OFF..EVENT_CODE_OFF].copy_from_slice(&ev_type.to_le_bytes());
    record[EVENT_CODE_OFF..EVENT_VALUE_OFF].copy_from_slice(&code.to_le_bytes());
    record[EVENT_VALUE_OFF..].copy_from_slice(&value.to_le_bytes());
    record
}
