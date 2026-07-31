use alloc::string::String;
use alloc::sync::Arc;

use vfs::{Dentry, LookupFlags, VfsError};

const PCI_ADDR: &str = "0000:00:1e.7";
const VIRTIO_ADDR: &str = "virtio157";
const DUMMY_KEY_RAW: u32 = 0x7d00_0000;
const DEVICE_KEY_RAW: u32 = 0x7d00_0001;
const TEST_EV_KEY_MASK: u8 = 0x02;
const TEST_KEY_CAP_MASK: u8 = 0x40;
const TEST_VIRTIO_VENDOR_ID: u16 = 0x1af4;
const TEST_VIRTIO_INPUT_DEVICE_ID: u16 = 18;
const TEST_PCI_DEVICE_ID: u16 = 0x1052;
const TEST_PCI_CLASS: u32 = 0x030000;

fn hosted_sysfs_root() -> Arc<Dentry> {
    use vfs::fs::FileSystem;

    Dentry::new_root(crate::SysfsFs.root().expect("hosted sysfs root inode"))
}

fn resolve(root: &Arc<Dentry>, full_path: &str) -> Result<Arc<Dentry>, VfsError> {
    let relative = full_path.strip_prefix("/sys")
        .expect("test path must name the sysfs mount");
    vfs::path_lookup(
        Arc::clone(root),
        Arc::clone(root),
        relative,
        LookupFlags::default(),
    ).map(|(_, dentry)| dentry)
}

fn resolved_full_path(dentry: &Dentry) -> String {
    let path = dentry.absolute_path();
    let relative = core::str::from_utf8(&path).expect("sysfs path is UTF-8");
    alloc::format!("/sys{relative}")
}

fn assert_converges(root: &Arc<Dentry>, aliases: &[String], canonical: &str) {
    let target = resolve(root, canonical).expect("resolve canonical sysfs device");
    assert_eq!(resolved_full_path(&target), canonical);
    for alias in aliases {
        let resolved = resolve(root, alias).expect("resolve sysfs projection");
        assert_eq!(resolved_full_path(&resolved), canonical, "{alias}");
        assert!(
            Arc::ptr_eq(&resolved, &target),
            "{alias} did not converge on the canonical dentry",
        );
    }
}

fn assert_missing(root: &Arc<Dentry>, path: &str) {
    assert_eq!(resolve(root, path).err(), Some(VfsError::Enoent), "{path}");
}

#[test]
fn real_vfs_resolves_physical_input_projections_and_invalidates_remove() {
    let _input_serial = super::tests::INPUT_TEST_MUTEX.lock()
        .unwrap_or_else(|error| error.into_inner());
    let _hook_serial = crate::bus::device_hook_serial();
    input::clear_devices_for_tests();
    crate::bus::init();
    super::class::init();
    drv::set_sysfs_hook(crate::bus::publish_device_cb);
    drv::set_sysfs_remove_hook(crate::bus::remove_device_cb);

    let pci = Arc::new(drv::Device::new(
        "pci",
        String::from(PCI_ADDR),
        TEST_VIRTIO_VENDOR_ID,
        TEST_PCI_DEVICE_ID,
        TEST_PCI_CLASS,
    ));
    drv::try_device_add(Arc::clone(&pci)).expect("register PCI transport");
    let virtio = Arc::new(
        drv::Device::new(
            "virtio",
            String::from(VIRTIO_ADDR),
            TEST_VIRTIO_VENDOR_ID,
            TEST_VIRTIO_INPUT_DEVICE_ID,
            0,
        ).with_parent("pci", String::from(PCI_ADDR)),
    );
    drv::try_device_add(Arc::clone(&virtio)).expect("register nested virtio device");

    let dummy_key = input::VirtioChildDeviceKey::from_raw(DUMMY_KEY_RAW);
    let (dummy_input_id, dummy_evdev_id) = input::install(
        input::VirtioInputDev::empty_boxed(dummy_key),
    ).expect("reserve first input identities");
    assert_eq!((dummy_input_id, dummy_evdev_id), (0, 0));
    assert_eq!(input::remove_device(dummy_key), Some(dummy_evdev_id));

    let device_key = input::VirtioChildDeviceKey::from_raw(DEVICE_KEY_RAW);
    let mut model = input::VirtioInputDev::empty_boxed(device_key);
    let name = b"hosted physical keyboard";
    model.name[..name.len()].copy_from_slice(name);
    model.name_len = name.len();
    model.name_present = true;
    model.ev_bits[0] = TEST_EV_KEY_MASK;
    model.key_bits.bits[3] = TEST_KEY_CAP_MASK;
    let (input_id, evdev_id) = input::install(model).expect("publish input model");
    assert_eq!(input_id, dummy_input_id + 1, "inputN must remain monotonic");
    assert_eq!(evdev_id, dummy_evdev_id, "eventN minor must be reusable");
    assert_ne!(input_id, evdev_id, "fixture requires divergent inputN/eventN");

    let event_name = alloc::format!("event{evdev_id}");
    let minor = input::EVENT_MINOR_BASE + evdev_id;
    let input_device = Arc::new(
        drv::Device::new("input", event_name.clone(), 0, 0, evdev_id)
            .with_parent("virtio", String::from(VIRTIO_ADDR))
            .with_sysfs_relpath(alloc::format!(
                "input/input{input_id}/{event_name}",
            ))
            .with_devnode(
                "input",
                alloc::format!("input/{event_name}"),
                Some((input::INPUT_MAJOR, minor)),
            ),
    );
    drv::try_device_add(Arc::clone(&input_device)).expect("register evdev child");

    let event_canon = alloc::format!(
        "/sys/{}",
        drv::device_canon_exact(&input_device)
            .expect("canonical physical event child"),
    );
    let parent_canon = String::from(
        event_canon
            .rsplit_once('/')
            .expect("event path has input parent")
            .0,
    );
    let transport_canon = alloc::format!(
        "/sys/{}",
        drv::device_canon("virtio", VIRTIO_ADDR)
            .expect("canonical live transport"),
    );
    let class_parent = alloc::format!("/sys/class/input/input{input_id}");
    let class_event = alloc::format!("/sys/class/input/{event_name}");
    let dev_index = alloc::format!("/sys/dev/char/{}:{minor}", input::INPUT_MAJOR);
    let event_device = alloc::format!("{event_canon}/device");
    let class_event_device = alloc::format!("{class_event}/device");
    let parent_device = alloc::format!("{parent_canon}/device");
    let class_parent_device = alloc::format!("{class_parent}/device");

    let root = hosted_sysfs_root();
    assert_converges(
        &root,
        &[class_parent.clone(), event_device.clone(), class_event_device.clone()],
        &parent_canon,
    );
    assert_converges(
        &root,
        &[class_event.clone(), dev_index.clone()],
        &event_canon,
    );
    assert_converges(
        &root,
        &[parent_device.clone(), class_parent_device.clone()],
        &transport_canon,
    );

    drv::device_del(&input_device);
    let post_remove_root = hosted_sysfs_root();
    for path in [
        class_parent.as_str(),
        class_event.as_str(),
        dev_index.as_str(),
        event_device.as_str(),
        parent_device.as_str(),
        parent_canon.as_str(),
        event_canon.as_str(),
    ] {
        assert_missing(&post_remove_root, path);
    }
    assert_eq!(input::remove_device(device_key), Some(evdev_id));
    drv::device_del(&virtio);
    drv::device_del(&pci);
    input::clear_devices_for_tests();
}
