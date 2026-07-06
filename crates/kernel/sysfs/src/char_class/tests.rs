use super::*;
use alloc::sync::Arc;
use netlink::{proto, NetlinkSocket};

const GRAPHICS_MAJOR: u32 = 29;
const FBDEV_TEST_MINOR: u32 = 9;
const MEM_MAJOR: u32 = 1;
const MISC_MAJOR: u32 = 10;
const MEM_TEST_MINOR: u32 = 8;
const MISC_TEST_MINOR: u32 = 235;

fn add_char(class: &'static str, addr: &str, devname: &str, dt: (u32, u32)) -> Arc<drv::Device> {
    let dev = Arc::new(
        drv::Device::new(class, String::from(addr), 0, 0, 0)
            .with_devnode(class, String::from(devname), Some(dt)),
    );
    drv::try_device_add(Arc::clone(&dev)).expect("test device registration");
    dev
}

fn add_char_env(class: &'static str, addr: &str, devname: &str, dt: (u32, u32), env: &str)
    -> Arc<drv::Device>
{
    let dev = Arc::new(
        drv::Device::new(class, String::from(addr), 0, 0, 0)
            .with_devnode(class, String::from(devname), Some(dt))
            .with_uevent_env(alloc::vec![String::from(env)]),
    );
    drv::try_device_add(Arc::clone(&dev)).expect("test device registration");
    dev
}

#[test]
fn mem_class_resolves_model_backed_char_device() {
    let dev = add_char("mem", "sysfs-null-test", "null-test", (1, 3));

    let class = make_sys_class_inode("mem", INO_CLASS_MEM);
    let link = class.lookup("sysfs-null-test").expect("class link");
    assert_eq!(
        link.readlink().expect("readlink"),
        b"../../devices/virtual/mem/sysfs-null-test".to_vec()
    );

    let root = make_virtual_class_inode("mem", INO_VIRT_MEM);
    let dir = root.lookup("sysfs-null-test").expect("device dir");
    let dev_attr = dir.lookup("dev").expect("dev attr");
    let mut buf = [0u8; 32];
    let n = dev_attr.read(0, &mut buf).expect("read dev attr");
    assert_eq!(&buf[..n], b"1:3\n");

    let subsystem = dir.lookup("subsystem").expect("subsystem link");
    assert_eq!(
        subsystem.readlink().expect("readlink"),
        b"../../../../class/mem".to_vec()
    );

    drv::device_del(&dev);
    assert_eq!(root.lookup("sysfs-null-test").err(), Some(VfsError::Enoent));
    assert_eq!(class.lookup("sysfs-null-test").err(), Some(VfsError::Enoent));
}

#[test]
fn misc_class_uevent_uses_model_devname() {
    let dev = add_char("misc", "sysfs-hwrng-test", "hwrng-test", (10, 183));

    let root = make_virtual_class_inode("misc", INO_VIRT_MISC);
    let dir = root.lookup("sysfs-hwrng-test").expect("device dir");
    let uevent = dir.lookup("uevent").expect("uevent attr");
    let mut buf = [0u8; 64];
    let n = uevent.read(0, &mut buf).expect("read uevent");
    assert_eq!(
        &buf[..n],
        b"MAJOR=10\nMINOR=183\nDEVNAME=hwrng-test\n"
    );

    drv::device_del(&dev);
    assert_eq!(root.lookup("sysfs-hwrng-test").err(), Some(VfsError::Enoent));
}

#[test]
fn class_uevent_write_reemits_model_event() {
    let dev = add_char("sound", "controlC12", "snd/controlC12", (116, 322));
    let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
    listener.set_group_mask(1);
    netlink::register_uevent_listener(&listener);

    let root = make_virtual_class_inode("sound", INO_VIRT_SOUND);
    let dir = root.lookup("controlC12").expect("sound device dir");
    let uevent = dir.lookup("uevent").expect("uevent attr");
    assert_eq!(uevent.write(0, b"change\n"), Ok("change\n".len()));
    let msg = (0..64)
        .filter_map(|_| listener.dequeue().map(|(msg, _src)| msg))
        .find(|msg| msg.windows(b"DEVPATH=/devices/virtual/sound/controlC12".len())
            .any(|w| w == b"DEVPATH=/devices/virtual/sound/controlC12"))
        .expect("matching uevent message");
    assert!(msg.windows(b"ACTION=change".len()).any(|w| w == b"ACTION=change"));
    assert!(msg.windows(b"DEVPATH=/devices/virtual/sound/controlC12".len()).any(|w| w == b"DEVPATH=/devices/virtual/sound/controlC12"));
    assert!(msg.windows(b"SUBSYSTEM=sound".len()).any(|w| w == b"SUBSYSTEM=sound"));
    assert!(msg.windows(b"DEVNAME=snd/controlC12".len()).any(|w| w == b"DEVNAME=snd/controlC12"));

    drv::device_del(&dev);
}

#[test]
fn misc_class_autofs_is_model_backed_with_linux_dev_t() {
    let dev = add_char("misc", "autofs", "autofs", (10, 235));

    let class = make_sys_class_inode("misc", INO_CLASS_MISC);
    let link = class.lookup("autofs").expect("autofs class link");
    assert_eq!(
        link.readlink().expect("readlink"),
        b"../../devices/virtual/misc/autofs".to_vec()
    );

    let root = make_virtual_class_inode("misc", INO_VIRT_MISC);
    let dir = root.lookup("autofs").expect("autofs device dir");
    let dev_attr = dir.lookup("dev").expect("dev attr");
    let mut buf = [0u8; 32];
    let n = dev_attr.read(0, &mut buf).expect("read dev attr");
    assert_eq!(&buf[..n], b"10:235\n");

    drv::device_del(&dev);
    assert_eq!(class.lookup("autofs").err(), Some(VfsError::Enoent));
}

#[test]
fn misc_and_mem_uevent_writes_reemit_model_events() {
    let mem = add_char("mem", "random-test", "random-test", (MEM_MAJOR, MEM_TEST_MINOR));
    let misc = add_char("misc", "autofs-trigger", "autofs-trigger", (MISC_MAJOR, MISC_TEST_MINOR));
    let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
    listener.set_group_mask(1);
    netlink::register_uevent_listener(&listener);

    let mem_root = make_virtual_class_inode("mem", INO_VIRT_MEM);
    let mem_dir = mem_root.lookup("random-test").expect("mem device dir");
    let mem_uevent = mem_dir.lookup("uevent").expect("mem uevent attr");
    assert_eq!(mem_uevent.write(0, b"change\n"), Ok("change\n".len()));

    let misc_root = make_virtual_class_inode("misc", INO_VIRT_MISC);
    let misc_dir = misc_root.lookup("autofs-trigger").expect("misc device dir");
    let misc_uevent = misc_dir.lookup("uevent").expect("misc uevent attr");
    assert_eq!(misc_uevent.write(0, b"add\n"), Ok("add\n".len()));

    let mem_major = alloc::format!("MAJOR={}", MEM_MAJOR);
    let mem_minor = alloc::format!("MINOR={}", MEM_TEST_MINOR);
    let misc_major = alloc::format!("MAJOR={}", MISC_MAJOR);
    let misc_minor = alloc::format!("MINOR={}", MISC_TEST_MINOR);
    let mem_msg = (0..64)
        .filter_map(|_| listener.dequeue().map(|(msg, _src)| msg))
        .find(|msg| msg.windows(b"DEVPATH=/devices/virtual/mem/random-test".len())
            .any(|w| w == b"DEVPATH=/devices/virtual/mem/random-test"))
        .expect("matching mem uevent");
    assert!(mem_msg.windows(b"ACTION=change".len()).any(|w| w == b"ACTION=change"));
    assert!(mem_msg.windows(b"SUBSYSTEM=mem".len()).any(|w| w == b"SUBSYSTEM=mem"));
    assert!(mem_msg.windows(b"DEVNAME=random-test".len()).any(|w| w == b"DEVNAME=random-test"));
    assert!(mem_msg.windows(mem_major.len()).any(|w| w == mem_major.as_bytes()));
    assert!(mem_msg.windows(mem_minor.len()).any(|w| w == mem_minor.as_bytes()));

    let misc_msg = (0..64)
        .filter_map(|_| listener.dequeue().map(|(msg, _src)| msg))
        .find(|msg| msg.windows(b"DEVPATH=/devices/virtual/misc/autofs-trigger".len())
            .any(|w| w == b"DEVPATH=/devices/virtual/misc/autofs-trigger"))
        .expect("matching misc uevent");
    assert!(misc_msg.windows(b"ACTION=add".len()).any(|w| w == b"ACTION=add"));
    assert!(misc_msg.windows(b"SUBSYSTEM=misc".len()).any(|w| w == b"SUBSYSTEM=misc"));
    assert!(misc_msg.windows(b"DEVNAME=autofs-trigger".len()).any(|w| w == b"DEVNAME=autofs-trigger"));
    assert!(misc_msg.windows(misc_major.len()).any(|w| w == misc_major.as_bytes()));
    assert!(misc_msg.windows(misc_minor.len()).any(|w| w == misc_minor.as_bytes()));

    drv::device_del(&mem);
    drv::device_del(&misc);
}

#[test]
fn sound_class_separates_sysfs_leaf_from_devtmpfs_path() {
    let dev = add_char("sound", "controlC9", "snd/controlC9", (116, 288));

    let class = make_sys_class_inode("sound", INO_CLASS_SOUND);
    let link = class.lookup("controlC9").expect("sound class link");
    assert_eq!(
        link.readlink().expect("readlink"),
        b"../../devices/virtual/sound/controlC9".to_vec()
    );
    assert_eq!(class.lookup("snd").err(), Some(VfsError::Enoent));

    let root = make_virtual_class_inode("sound", INO_VIRT_SOUND);
    let dir = root.lookup("controlC9").expect("sound device dir");
    let uevent = dir.lookup("uevent").expect("uevent attr");
    let mut buf = [0u8; 64];
    let n = uevent.read(0, &mut buf).expect("read uevent");
    assert_eq!(
        &buf[..n],
        b"MAJOR=116\nMINOR=288\nDEVNAME=snd/controlC9\n"
    );

    drv::device_del(&dev);
    assert_eq!(root.lookup("controlC9").err(), Some(VfsError::Enoent));
}

#[test]
fn graphics_class_resolves_fbdev_nodes() {
    let dev = add_char("graphics", "fb7", "fb7", (29, 7));

    let class = make_sys_class_inode("graphics", INO_CLASS_GRAPHICS);
    let link = class.lookup("fb7").expect("graphics class link");
    assert_eq!(
        link.readlink().expect("readlink"),
        b"../../devices/virtual/graphics/fb7".to_vec()
    );

    let root = make_virtual_class_inode("graphics", INO_VIRT_GRAPHICS);
    let dir = root.lookup("fb7").expect("graphics device dir");
    let subsystem = dir.lookup("subsystem").expect("subsystem link");
    assert_eq!(
        subsystem.readlink().expect("readlink"),
        b"../../../../class/graphics".to_vec()
    );

    drv::device_del(&dev);
    assert_eq!(class.lookup("fb7").err(), Some(VfsError::Enoent));
}

#[test]
fn graphics_uevent_write_reemits_fbdev_model_event() {
    let dev = add_char_env(
        "graphics", "fb9", "fb9", (GRAPHICS_MAJOR, FBDEV_TEST_MINOR), "DEVTYPE=fb");
    let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
    listener.set_group_mask(1);
    netlink::register_uevent_listener(&listener);

    let root = make_virtual_class_inode("graphics", INO_VIRT_GRAPHICS);
    let dir = root.lookup("fb9").expect("graphics device dir");
    let uevent = dir.lookup("uevent").expect("uevent attr");
    let mut buf = [0u8; 80];
    let n = uevent.read(0, &mut buf).expect("read graphics uevent");
    assert!(buf[..n].windows(b"DEVTYPE=fb".len()).any(|w| w == b"DEVTYPE=fb"));
    assert_eq!(uevent.write(0, b"change\n"), Ok("change\n".len()));

    let msg = (0..64)
        .filter_map(|_| listener.dequeue().map(|(msg, _src)| msg))
        .find(|msg| msg.windows(b"DEVPATH=/devices/virtual/graphics/fb9".len())
            .any(|w| w == b"DEVPATH=/devices/virtual/graphics/fb9"))
        .expect("matching graphics uevent");
    let major = alloc::format!("MAJOR={}", GRAPHICS_MAJOR);
    let minor = alloc::format!("MINOR={}", FBDEV_TEST_MINOR);
    assert!(msg.windows(b"ACTION=change".len()).any(|w| w == b"ACTION=change"));
    assert!(msg.windows(b"SUBSYSTEM=graphics".len()).any(|w| w == b"SUBSYSTEM=graphics"));
    assert!(msg.windows(b"DEVNAME=fb9".len()).any(|w| w == b"DEVNAME=fb9"));
    assert!(msg.windows(b"DEVTYPE=fb".len()).any(|w| w == b"DEVTYPE=fb"));
    assert!(msg.windows(major.len()).any(|w| w == major.as_bytes()));
    assert!(msg.windows(minor.len()).any(|w| w == minor.as_bytes()));

    drv::device_del(&dev);
}

#[test]
fn class_device_links_to_model_parent_when_present() {
    let parent = Arc::new(drv::Device::new(
        "virtio",
        String::from("virtio-snd-parent0"),
        0x1af4,
        25,
        0,
    ));
    drv::try_device_add(Arc::clone(&parent)).expect("test parent registration");
    let dev = Arc::new(
        drv::Device::new("sound", String::from("controlC10"), 0, 0, 0)
            .with_parent("virtio", String::from("virtio-snd-parent0"))
            .with_devnode("sound", String::from("snd/controlC10"), Some((116, 320))),
    );
    drv::try_device_add(Arc::clone(&dev)).expect("test sound registration");

    let root = make_virtual_class_inode("sound", INO_VIRT_SOUND);
    let dir = root.lookup("controlC10").expect("sound device dir");
    let device = dir.lookup("device").expect("parent device link");
    assert_eq!(
        device.readlink().expect("readlink"),
        b"../../../virtio/virtio-snd-parent0".to_vec()
    );

    drv::device_del(&dev);
    drv::device_del(&parent);
    assert_eq!(root.lookup("controlC10").err(), Some(VfsError::Enoent));
}

#[test]
fn class_device_parent_link_tracks_remove_readd_model_state() {
    let parent = Arc::new(drv::Device::new(
        "virtio",
        String::from("virtio-snd-readd-parent0"),
        0x1af4,
        25,
        0,
    ));
    drv::try_device_add(Arc::clone(&parent)).expect("test parent registration");

    let root = make_virtual_class_inode("sound", INO_VIRT_SOUND);
    let class = make_sys_class_inode("sound", INO_CLASS_SOUND);
    let first = Arc::new(
        drv::Device::new("sound", String::from("controlC11"), 0, 0, 0)
            .with_parent("virtio", String::from("virtio-snd-readd-parent0"))
            .with_devnode("sound", String::from("snd/controlC11"), Some((116, 321))),
    );
    drv::try_device_add(Arc::clone(&first)).expect("first sound registration");

    let dir = root.lookup("controlC11").expect("first sound device dir");
    let device = dir.lookup("device").expect("first parent device link");
    assert_eq!(
        device.readlink().expect("readlink"),
        b"../../../virtio/virtio-snd-readd-parent0".to_vec()
    );
    assert!(class.lookup("controlC11").is_ok());

    drv::device_del(&first);
    assert_eq!(root.lookup("controlC11").err(), Some(VfsError::Enoent));
    assert_eq!(class.lookup("controlC11").err(), Some(VfsError::Enoent));

    let second = Arc::new(
        drv::Device::new("sound", String::from("controlC11"), 0, 0, 0)
            .with_parent("virtio", String::from("virtio-snd-readd-parent0"))
            .with_devnode("sound", String::from("snd/controlC11"), Some((116, 321))),
    );
    drv::try_device_add(Arc::clone(&second)).expect("second sound registration");

    let dir = root.lookup("controlC11").expect("readded sound device dir");
    let device = dir.lookup("device").expect("readded parent device link");
    assert_eq!(
        device.readlink().expect("readlink"),
        b"../../../virtio/virtio-snd-readd-parent0".to_vec()
    );
    let link = class.lookup("controlC11").expect("readded class link");
    assert_eq!(
        link.readlink().expect("readlink"),
        b"../../devices/virtual/sound/controlC11".to_vec()
    );

    drv::device_del(&second);
    drv::device_del(&parent);
    assert_eq!(root.lookup("controlC11").err(), Some(VfsError::Enoent));
}
