use alloc::string::String;
use alloc::sync::Arc;

use netlink::{proto, NetlinkSocket};
use vfs::VfsError;

use super::{class, topology};

const TEST_BUS_TYPE: u16 = 3;
const TEST_EV_KEY_MASK: u8 = 0x02;
const TEST_KEY_CAP_MASK: u8 = 0x40;
const TEST_VENDOR_ID: u16 = 0x1234;
const TEST_PRODUCT_ID: u16 = 0x5678;
const TEST_VERSION_ID: u16 = 0x9abc;
const TEST_VIRTIO_VENDOR_ID: u16 = 0x1af4;
const TEST_VIRTIO_INPUT_DEVICE_ID: u16 = 18;
const OLD_DEVICE_KEY_RAW: u32 = 0x7b00_0010;
const REPLACEMENT_DEVICE_KEY_RAW: u32 = 0x7b00_0011;
const PARENTED_DEVICE_KEY_RAW: u32 = 0x7b00_0000;
const PARENTLESS_DEVICE_KEY_RAW: u32 = 0x7b00_0001;
const UEVENT_DEVICE_KEY_RAW: u32 = 0x7b00_0002;
const ATTRIBUTE_READ_BUFFER_BYTES: usize = 64;
const UEVENT_READ_BUFFER_BYTES: usize = 160;

pub(crate) static INPUT_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn install_model(
    key_raw: u32,
) -> (input::VirtioChildDeviceKey, u32, u32) {
    install_named_model(key_raw, b"oxide keyboard")
}

fn install_named_model(
    key_raw: u32,
    name: &[u8],
) -> (input::VirtioChildDeviceKey, u32, u32) {
    let key = input::VirtioChildDeviceKey::from_raw(key_raw);
    let mut model = input::VirtioInputDev::empty(key);
    model.name[..name.len()].copy_from_slice(name);
    model.name_len = name.len();
    model.name_present = true;
    let serial = b"input-serial";
    model.serial[..serial.len()].copy_from_slice(serial);
    model.serial_len = serial.len();
    model.serial_present = true;
    model.ids = input::VirtioInputDevIds {
        bustype: TEST_BUS_TYPE,
        vendor: TEST_VENDOR_ID,
        product: TEST_PRODUCT_ID,
        version: TEST_VERSION_ID,
    };
    model.ev_bits[0] = TEST_EV_KEY_MASK;
    model.key_bits.bits[3] = TEST_KEY_CAP_MASK;
    let (input_id, evdev_id) = input::install(model).expect("test input model");
    (key, input_id, evdev_id)
}

#[test]
fn retained_input_inodes_reject_reused_event_identity() {
    let _serial = INPUT_TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    let _hook_serial = crate::bus::device_hook_serial();
    input::clear_devices_for_tests();

    let (old_key, old_input_id, old_evdev_id) =
        install_named_model(OLD_DEVICE_KEY_RAW, b"old keyboard");
    let old_event_name = alloc::format!("event{old_evdev_id}");
    let old_device = Arc::new(
        drv::Device::new("input", old_event_name.clone(), 0, 0, 0)
            .with_sysfs_relpath(alloc::format!(
                "input{old_input_id}/{old_event_name}",
            ))
            .with_devnode(
                "input",
                alloc::format!("input/{old_event_name}"),
                Some((input::INPUT_MAJOR, input::EVENT_MINOR_BASE + old_evdev_id)),
            ),
    );
    drv::try_device_add(Arc::clone(&old_device)).expect("old input registration");

    let root = topology::make_virtual_input_dir();
    let old_parent = root.lookup(&alloc::format!("input{old_input_id}"))
        .expect("old input parent");
    let old_event = old_parent.lookup(&old_event_name).expect("old event child");
    let old_ids = old_parent.lookup("id").expect("old id directory");
    let old_caps = old_parent.lookup("capabilities").expect("old capability directory");
    let old_name = old_parent.lookup("name").expect("old name attribute");
    let old_inhibited = old_parent.lookup("inhibited").expect("old inhibited attribute");
    let old_parent_uevent = old_parent.lookup("uevent").expect("old parent uevent");
    let old_event_uevent = old_event.lookup("uevent").expect("old event uevent");

    drv::device_del(&old_device);
    assert_eq!(input::remove_device(old_key), Some(old_evdev_id));

    let (new_key, new_input_id, new_evdev_id) =
        install_named_model(REPLACEMENT_DEVICE_KEY_RAW, b"replacement keyboard");
    assert_ne!(new_input_id, old_input_id, "inputN identity must not recycle");
    assert_eq!(new_evdev_id, old_evdev_id, "fixture requires eventN reuse");
    let new_event_name = alloc::format!("event{new_evdev_id}");
    let new_device = Arc::new(
        drv::Device::new("input", new_event_name.clone(), 0, 0, 0)
            .with_sysfs_relpath(alloc::format!(
                "input{new_input_id}/{new_event_name}",
            ))
            .with_devnode(
                "input",
                alloc::format!("input/{new_event_name}"),
                Some((input::INPUT_MAJOR, input::EVENT_MINOR_BASE + new_evdev_id)),
            ),
    );
    drv::try_device_add(Arc::clone(&new_device)).expect("replacement input registration");

    assert_eq!(
        root.lookup(&alloc::format!("input{old_input_id}")).err(),
        Some(VfsError::Enoent),
        "removed inputN must not alias the replacement",
    );
    let new_parent = root.lookup(&alloc::format!("input{new_input_id}"))
        .expect("replacement input parent");
    assert!(new_parent.lookup(&new_event_name).is_ok());
    let mut buf = [0u8; ATTRIBUTE_READ_BUFFER_BYTES];
    let new_name = new_parent.lookup("name").expect("replacement name");
    let new_len = new_name.read(0, &mut buf).expect("read replacement name");
    assert_eq!(&buf[..new_len], b"replacement keyboard\n");

    for (inode, child) in [
        (&old_parent, "name"),
        (&old_parent, old_event_name.as_str()),
        (&old_event, "dev"),
        (&old_event, "device"),
        (&old_ids, "vendor"),
        (&old_caps, "ev"),
    ] {
        assert_eq!(inode.lookup(child).err(), Some(VfsError::Enoent), "{child}");
    }
    assert_eq!(old_parent_uevent.read(0, &mut buf), Err(VfsError::Enoent));
    assert_eq!(old_parent_uevent.write(0, b"change\n"), Err(VfsError::Enoent));
    assert_eq!(old_inhibited.read(0, &mut buf), Err(VfsError::Enoent));
    assert_eq!(old_inhibited.write(0, b"1\n"), Err(VfsError::Enoent));
    assert_eq!(old_event_uevent.read(0, &mut buf), Err(VfsError::Enoent));
    assert_eq!(old_event_uevent.write(0, b"change\n"), Err(VfsError::Enoent));

    let old_len = old_name.read(0, &mut buf).expect("retained old attribute body");
    assert_eq!(&buf[..old_len], b"old keyboard\n");

    drv::device_del(&new_device);
    assert_eq!(input::remove_device(new_key), Some(new_evdev_id));
    input::clear_devices_for_tests();
}

#[test]
fn input_class_device_links_to_model_parent_when_present() {
    let _serial = INPUT_TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    input::clear_devices_for_tests();
    let parent = Arc::new(drv::Device::new(
        "virtio",
        String::from("virtio-input-parent0"),
        TEST_VIRTIO_VENDOR_ID,
        TEST_VIRTIO_INPUT_DEVICE_ID,
        0,
    ));
    drv::try_device_add(Arc::clone(&parent)).expect("test parent registration");
    let (key, input_id, evdev_id) = install_model(PARENTED_DEVICE_KEY_RAW);
    let input = Arc::new(
        drv::Device::new("input", alloc::format!("event{evdev_id}"), 0, 0, 0)
            .with_parent("virtio", String::from("virtio-input-parent0"))
            .with_sysfs_relpath(alloc::format!(
                "input/input{input_id}/event{evdev_id}",
            ))
            .with_devnode(
                "input",
                alloc::format!("input/event{evdev_id}"),
                Some((input::INPUT_MAJOR, input::EVENT_MINOR_BASE + evdev_id)),
            ),
    );
    drv::try_device_add(Arc::clone(&input)).expect("test input registration");

    let root = topology::make_transport_input_dir("virtio", "virtio-input-parent0");
    let parent_dir = root.lookup(&alloc::format!("input{input_id}")).expect("input parent dir");
    let event_name = alloc::format!("event{evdev_id}");
    let dir = parent_dir.lookup(&event_name).expect("evdev child dir");
    assert_eq!(
        dir.lookup("device").expect("evdev parent link").readlink().expect("readlink"),
        alloc::format!("../../input{input_id}").into_bytes(),
    );
    let physical = parent_dir.lookup("device").expect("physical parent link");
    assert_eq!(
        physical.readlink().expect("readlink"),
        b"../../../../../devices/virtio/virtio-input-parent0".to_vec(),
    );
    let class_dir = class::make_class_input_dir();
    assert_eq!(
        class_dir.lookup(&alloc::format!("input{input_id}"))
            .expect("input class link").readlink().expect("readlink"),
        alloc::format!(
            "../../devices/virtio/virtio-input-parent0/input/input{input_id}",
        ).into_bytes(),
    );
    assert_eq!(
        class_dir.lookup(&event_name)
            .expect("event class link").readlink().expect("readlink"),
        alloc::format!(
            "../../devices/virtio/virtio-input-parent0/input/input{input_id}/{event_name}",
        ).into_bytes(),
    );

    drv::device_del(&input);
    assert_eq!(input::remove_device(key), Some(evdev_id));
    drv::device_del(&parent);
    assert_eq!(root.lookup(&alloc::format!("input{input_id}")).err(), Some(VfsError::Enoent));
    assert_eq!(dir.lookup("device").err(), Some(VfsError::Enoent));
    input::clear_devices_for_tests();
}

#[test]
fn input_class_device_without_parent_has_no_device_link() {
    let _serial = INPUT_TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    input::clear_devices_for_tests();
    let (key, input_id, evdev_id) = install_model(PARENTLESS_DEVICE_KEY_RAW);
    let input = Arc::new(
        drv::Device::new("input", alloc::format!("event{evdev_id}"), 0, 0, 0)
            .with_sysfs_relpath(alloc::format!(
                "input{input_id}/event{evdev_id}",
            ))
            .with_devnode(
                "input",
                alloc::format!("input/event{evdev_id}"),
                Some((input::INPUT_MAJOR, input::EVENT_MINOR_BASE + evdev_id)),
            ),
    );
    drv::try_device_add(Arc::clone(&input)).expect("test input registration");

    let root = topology::make_virtual_input_dir();
    let parent = root.lookup(&alloc::format!("input{input_id}")).expect("input parent dir");
    assert_eq!(parent.lookup("device").err(), Some(VfsError::Enoent));
    assert!(parent.lookup(&alloc::format!("event{evdev_id}")).is_ok());

    drv::device_del(&input);
    assert_eq!(input::remove_device(key), Some(evdev_id));
    input::clear_devices_for_tests();
}

#[test]
fn input_uevent_write_reemits_model_event() {
    let _serial = INPUT_TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    let _hook_serial = crate::bus::device_hook_serial();
    drv::set_sysfs_hook(crate::bus::publish_device_cb);
    input::clear_devices_for_tests();
    let raw_name = b"oxide \xff keyboard";
    let raw_name_env = b"NAME=\"oxide \xff keyboard\"";
    let (key, input_id, evdev_id) =
        install_named_model(UEVENT_DEVICE_KEY_RAW, raw_name);
    let input = Arc::new(
        drv::Device::new("input", alloc::format!("event{evdev_id}"), 0, 0, 0)
            .with_sysfs_relpath(alloc::format!(
                "input{input_id}/event{evdev_id}",
            ))
            .with_devnode(
                "input",
                alloc::format!("input/event{evdev_id}"),
                Some((input::INPUT_MAJOR, input::EVENT_MINOR_BASE + evdev_id)),
            ),
    );
    let listener = Arc::new(NetlinkSocket::new(
        proto::NETLINK_KOBJECT_UEVENT,
        &network_namespace::initial(),
    ));
    listener.set_group_mask(netlink::KOBJECT_UEVENT_KERNEL_GROUP_MASK);
    netlink::register_uevent_listener(&listener);
    drv::try_device_add(Arc::clone(&input)).expect("test input registration");
    let parent_path = alloc::format!("DEVPATH=/devices/virtual/input/input{input_id}");
    let event_path = alloc::format!("{parent_path}/event{evdev_id}");

    let parent_add = core::iter::from_fn(|| listener.dequeue().map(|(msg, _src)| msg))
        .find(|msg| {
            msg.split(|byte| *byte == 0).any(|entry| entry == b"ACTION=add")
                && msg.split(|byte| *byte == 0)
                    .any(|entry| entry == parent_path.as_bytes())
        })
        .expect("input parent add event");
    assert!(parent_add.windows(b"PRODUCT=3/1234/5678/9abc".len())
        .any(|window| window == b"PRODUCT=3/1234/5678/9abc"));
    assert!(parent_add.windows(raw_name_env.len()).any(|window| window == raw_name_env));
    assert!(!parent_add.windows(b"DEVNAME=".len()).any(|window| window == b"DEVNAME="));
    let event_add = core::iter::from_fn(|| listener.dequeue().map(|(msg, _src)| msg))
        .find(|msg| {
            msg.split(|byte| *byte == 0).any(|entry| entry == b"ACTION=add")
                && msg.split(|byte| *byte == 0)
                    .any(|entry| entry == event_path.as_bytes())
        })
        .expect("evdev child add event");
    let devname = alloc::format!("DEVNAME=input/event{evdev_id}");
    assert!(event_add.windows(devname.len()).any(|window| window == devname.as_bytes()));
    assert!(!event_add.windows(b"PRODUCT=".len()).any(|window| window == b"PRODUCT="));

    let root = topology::make_virtual_input_dir();
    let parent = root.lookup(&alloc::format!("input{input_id}")).expect("input parent dir");
    let dir = parent.lookup(&alloc::format!("event{evdev_id}")).expect("evdev child dir");
    let parent_uevent = parent.lookup("uevent").expect("parent uevent attr");
    let mut parent_buf = [0u8; UEVENT_READ_BUFFER_BYTES];
    let parent_n = parent_uevent.read(0, &mut parent_buf).expect("read parent uevent");
    assert!(!parent_buf[..parent_n].windows(b"DEVNAME=".len()).any(|w| w == b"DEVNAME="));
    assert!(parent_buf[..parent_n].windows(b"PRODUCT=3/1234/5678/9abc".len())
        .any(|window| window == b"PRODUCT=3/1234/5678/9abc"));
    assert!(parent_buf[..parent_n].windows(raw_name_env.len())
        .any(|window| window == raw_name_env));
    assert_eq!(parent_uevent.write(0, b"change\n"), Ok("change\n".len()));
    let parent_msg = core::iter::from_fn(|| listener.dequeue().map(|(msg, _src)| msg))
        .find(|msg| {
            msg.split(|byte| *byte == 0).any(|entry| entry == b"ACTION=change")
                && msg.split(|byte| *byte == 0)
                    .any(|entry| entry == parent_path.as_bytes())
                && msg.split(|byte| *byte == 0)
                    .any(|entry| entry == b"SUBSYSTEM=input")
        })
        .expect("matching input parent uevent message");
    assert!(parent_msg.windows(raw_name_env.len()).any(|window| window == raw_name_env));
    let uevent = dir.lookup("uevent").expect("uevent attr");
    let mut buf = [0u8; UEVENT_READ_BUFFER_BYTES];
    let n = uevent.read(0, &mut buf).expect("read uevent");
    assert!(buf[..n].windows(devname.len()).any(|window| window == devname.as_bytes()));
    assert!(!buf[..n].windows(b"PRODUCT=".len()).any(|window| window == b"PRODUCT="));
    assert_eq!(uevent.write(0, b"change\n"), Ok("change\n".len()));
    let msg = core::iter::from_fn(|| listener.dequeue().map(|(msg, _src)| msg))
        .find(|msg| {
            msg.split(|byte| *byte == 0).any(|entry| entry == b"ACTION=change")
                && msg.split(|byte| *byte == 0)
                    .any(|entry| entry == event_path.as_bytes())
                && msg.split(|byte| *byte == 0)
                    .any(|entry| entry == b"SUBSYSTEM=input")
        })
        .expect("matching input uevent message");
    assert!(msg.windows(event_path.len()).any(|window| window == event_path.as_bytes()));
    assert!(msg.windows(devname.len()).any(|window| window == devname.as_bytes()));
    assert!(!msg.windows(b"PRODUCT=".len()).any(|window| window == b"PRODUCT="));

    drv::device_del(&input);
    assert_eq!(input::remove_device(key), Some(evdev_id));
    input::clear_devices_for_tests();
}
