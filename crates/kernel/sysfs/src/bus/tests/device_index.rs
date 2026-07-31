use super::*;

const ATTRIBUTE_READ_BUFFER_BYTES: usize = 16;
const RESOURCE_READ_BUFFER_BYTES: usize = 160;
const TEST_VIRTIO_DEVICE_ID: u16 = 2;
const TEST_BLOCK_DEVT: (u32, u32) = (254, 42);
const TEST_PCI_VENDOR_ID: u16 = 0x1234;
const TEST_PCI_DEVICE_ID: u16 = 0x5678;
const TEST_PCI_STORAGE_CLASS: u32 = 0x010601;
const TEST_INPUT_KEY_RAW: u32 = 0x7c00_0007;
const TEST_DRM_MINOR: u32 = 88;
const PARENTED_DRM_MINOR: u32 = 89;
const PATH_DRM_MINOR: u32 = 7;
const TEST_VIRTIO_VENDOR_ID: u16 = 0x1af4;
const TEST_VIRTIO_GPU_DEVICE_ID: u16 = 16;
const TEST_GPU_PCI_DEVICE_ID: u16 = 0x1050;
const TEST_GPU_PCI_CLASS: u32 = 0x030000;
const TEST_MEM_DEVT: (u32, u32) = (1, 8);
const TEST_MISC_DEVT: (u32, u32) = (10, 235);
const TEST_SOUND_DEVT: (u32, u32) = (116, 256);
const TEST_GRAPHICS_DEVT: (u32, u32) = (29, 8);
const REUSED_SOUND_DEVT: (u32, u32) = (116, 322);

fn devt_name(dev_t: (u32, u32)) -> String {
    alloc::format!("{}:{}", dev_t.0, dev_t.1)
}

#[test]
fn model_device_with_dev_t_exposes_dev_attr_and_sys_dev_index() {
    let dev = Arc::new(
        drv::Device::new(
            "virtio",
            String::from("sysfs-dev-index0"),
            0,
            TEST_VIRTIO_DEVICE_ID,
            0,
        )
            .with_devnode("block", String::from("vdt"), Some(TEST_BLOCK_DEVT)));
    drv::try_device_add(Arc::clone(&dev)).expect("test device registration");

    let devices = make_devices_root_inode("virtio");
    let dir = devices.lookup("sysfs-dev-index0").expect("device dir");
    let dev_attr = dir.lookup("dev").expect("dev attr");
    let mut buf = [0u8; ATTRIBUTE_READ_BUFFER_BYTES];
    let n = dev_attr.read(0, &mut buf).expect("read dev attr");
    let block_index = alloc::format!("{}:{}", TEST_BLOCK_DEVT.0, TEST_BLOCK_DEVT.1);
    let block_attr = alloc::format!("{block_index}\n");
    assert_eq!(&buf[..n], block_attr.as_bytes());

    let index = make_sys_dev_index_inode(DevIndexKind::Block);
    let link = index.lookup(&block_index).expect("block dev index link");
    assert_eq!(
        link.readlink().expect("readlink"),
        b"../../devices/virtio/sysfs-dev-index0".to_vec());

    drv::device_del(&dev);
    assert_eq!(devices.lookup("sysfs-dev-index0").err(), Some(VfsError::Enoent));
    assert_eq!(index.lookup(&block_index).err(), Some(VfsError::Enoent));
}

#[test]
fn pci_device_exposes_indexed_bar_resource_attrs() {
    let dev = Arc::new(
        drv::Device::new(
            "pci",
            String::from("0000:00:1f.0"),
            TEST_PCI_VENDOR_ID,
            TEST_PCI_DEVICE_ID,
            TEST_PCI_STORAGE_CLASS,
        )
            .with_resources(Vec::from([
                drv::Resource { bar: 2, start: 0x1000, end: 0x1fff, flags: 0x200 },
                drv::Resource { bar: 5, start: 0xfebc_0000, end: 0xfebc_0fff, flags: 0x2200 },
            ])));
    drv::try_device_add(Arc::clone(&dev)).expect("test pci registration");

    let devices = make_devices_root_inode("pci");
    let dir = devices.lookup("0000:00:1f.0").expect("pci device dir");
    assert_eq!(dir.lookup("resource0").err(), Some(VfsError::Enoent));

    let resource = dir.lookup("resource").expect("aggregate resource attr");
    let mut buf = [0u8; RESOURCE_READ_BUFFER_BYTES];
    let n = resource.read(0, &mut buf).expect("read aggregate resource");
    assert_eq!(
        &buf[..n],
        b"0x0000000000001000 0x0000000000001fff 0x0000000000000200\n0x00000000febc0000 0x00000000febc0fff 0x0000000000002200\n");

    let res2 = dir.lookup("resource2").expect("resource2 attr");
    let n = res2.read(0, &mut buf).expect("read resource2");
    assert_eq!(
        &buf[..n],
        b"0x0000000000001000 0x0000000000001fff 0x0000000000000200\n");

    let res5 = dir.lookup("resource5").expect("resource5 attr");
    let n = res5.read(0, &mut buf).expect("read resource5");
    assert_eq!(
        &buf[..n],
        b"0x00000000febc0000 0x00000000febc0fff 0x0000000000002200\n");

    let modalias = dir.lookup("modalias").expect("modalias still works");
    let n = modalias.read(0, &mut buf).expect("read modalias");
    assert_eq!(&buf[..n], b"pci:v00001234d00005678sv*sd*bc01sc06i01\n");

    drv::device_del(&dev);
}

#[test]
fn sys_dev_char_indexes_virtual_char_class_devices() {
    let _input_serial = crate::input::INPUT_TEST_MUTEX.lock()
        .unwrap_or_else(|err| err.into_inner());
    let mem = Arc::new(
        drv::Device::new("mem", String::from("sysfs-random-test"), 0, 0, 0)
            .with_devnode("mem", String::from("random-test"), Some(TEST_MEM_DEVT)));
    let misc = Arc::new(
        drv::Device::new("misc", String::from("sysfs-autofs-test"), 0, 0, 0)
            .with_devnode("misc", String::from("autofs-test"), Some(TEST_MISC_DEVT)));
    let sound = Arc::new(
        drv::Device::new("sound", String::from("controlC8"), 0, 0, 0)
            .with_devnode("sound", String::from("snd/controlC8"), Some(TEST_SOUND_DEVT)));
    let graphics = Arc::new(
        drv::Device::new("graphics", String::from("fb8"), 0, 0, 0)
            .with_devnode("graphics", String::from("fb8"), Some(TEST_GRAPHICS_DEVT)));
    let input_key = input::VirtioChildDeviceKey::from_raw(TEST_INPUT_KEY_RAW);
    let (input_id, evdev_id) = input::install(input::VirtioInputDev::empty_boxed(input_key))
        .expect("test input model");
    let input_minor = input::EVENT_MINOR_BASE + evdev_id;
    let input = Arc::new(
        drv::Device::new("input", alloc::format!("event{evdev_id}"), 0, 0, 0)
            .with_sysfs_relpath(alloc::format!("input{input_id}/event{evdev_id}"))
            .with_devnode(
                "input",
                alloc::format!("input/event{evdev_id}"),
                Some((input::INPUT_MAJOR, input_minor)),
            ));
    let drm = Arc::new(
        drv::Device::new("drm", String::from("card88"), 0, 0, 0)
            .with_devnode(
                "drm",
                String::from("dri/card88"),
                Some((::drm::DRM_MAJOR, TEST_DRM_MINOR)),
            ));
    drv::try_device_add(Arc::clone(&mem)).expect("test mem registration");
    drv::try_device_add(Arc::clone(&misc)).expect("test misc registration");
    drv::try_device_add(Arc::clone(&sound)).expect("test sound registration");
    drv::try_device_add(Arc::clone(&graphics)).expect("test graphics registration");
    drv::try_device_add(Arc::clone(&input)).expect("test input registration");
    drv::try_device_add(Arc::clone(&drm)).expect("test drm registration");

    let index = make_sys_dev_index_inode(DevIndexKind::Char);
    let mem_index = devt_name(TEST_MEM_DEVT);
    let misc_index = devt_name(TEST_MISC_DEVT);
    let sound_index = devt_name(TEST_SOUND_DEVT);
    let graphics_index = devt_name(TEST_GRAPHICS_DEVT);
    let drm_index = devt_name((::drm::DRM_MAJOR, TEST_DRM_MINOR));
    let mem_link = index.lookup(&mem_index).expect("mem char index link");
    assert_eq!(
        mem_link.readlink().expect("readlink"),
        b"../../devices/virtual/mem/sysfs-random-test".to_vec());
    let misc_link = index.lookup(&misc_index).expect("misc char index link");
    assert_eq!(
        misc_link.readlink().expect("readlink"),
        b"../../devices/virtual/misc/sysfs-autofs-test".to_vec());
    let sound_link = index.lookup(&sound_index).expect("sound char index link");
    assert_eq!(
        sound_link.readlink().expect("readlink"),
        b"../../devices/virtual/sound/controlC8".to_vec());
    let graphics_link = index.lookup(&graphics_index).expect("graphics char index link");
    assert_eq!(
        graphics_link.readlink().expect("readlink"),
        b"../../devices/virtual/graphics/fb8".to_vec());
    let input_index = alloc::format!("{}:{input_minor}", input::INPUT_MAJOR);
    let input_link = index.lookup(&input_index).expect("input char index link");
    assert_eq!(
        input_link.readlink().expect("readlink"),
        alloc::format!(
            "../../devices/virtual/input/input{input_id}/event{evdev_id}",
        ).into_bytes());
    let drm_link = index.lookup(&drm_index).expect("drm char index link");
    assert_eq!(
        drm_link.readlink().expect("readlink"),
        b"../../devices/virtual/drm/card88".to_vec());

    drv::device_del(&mem);
    drv::device_del(&misc);
    drv::device_del(&sound);
    drv::device_del(&graphics);
    drv::device_del(&input);
    assert_eq!(input::remove_device(input_key), Some(evdev_id));
    drv::device_del(&drm);
    assert_eq!(index.lookup(&mem_index).err(), Some(VfsError::Enoent));
    assert_eq!(index.lookup(&misc_index).err(), Some(VfsError::Enoent));
    assert_eq!(index.lookup(&sound_index).err(), Some(VfsError::Enoent));
    assert_eq!(index.lookup(&graphics_index).err(), Some(VfsError::Enoent));
    assert_eq!(index.lookup(&input_index).err(), Some(VfsError::Enoent));
    assert_eq!(index.lookup(&drm_index).err(), Some(VfsError::Enoent));
}

#[test]
fn sys_dev_char_indexes_parented_drm_under_parent_device() {
    let parent = Arc::new(drv::Device::new(
        "virtio",
        String::from("sysfs-gpu-parent0"),
        TEST_VIRTIO_VENDOR_ID,
        TEST_VIRTIO_GPU_DEVICE_ID,
        0,
    ));
    let drm = Arc::new(
        drv::Device::new("drm", String::from("card89"), 0, 0, 0)
            .with_parent("virtio", String::from("sysfs-gpu-parent0"))
            .with_sysfs_relpath(String::from("drm/card89"))
            .with_devnode(
                "drm",
                String::from("dri/card89"),
                Some((::drm::DRM_MAJOR, PARENTED_DRM_MINOR)),
            ),
    );
    drv::try_device_add(Arc::clone(&parent)).expect("test parent registration");
    drv::try_device_add(Arc::clone(&drm)).expect("test drm registration");

    let parent_dir = make_devices_root_inode("virtio")
        .lookup("sysfs-gpu-parent0")
        .expect("parent device dir");
    let drm_dir = parent_dir.lookup("drm").expect("parent drm child dir");
    assert!(drm_dir.lookup("card89").is_ok());

    let index = make_sys_dev_index_inode(DevIndexKind::Char);
    let drm_index = devt_name((::drm::DRM_MAJOR, PARENTED_DRM_MINOR));
    let drm_link = index.lookup(&drm_index).expect("drm char index link");
    assert_eq!(
        drm_link.readlink().expect("readlink"),
        b"../../devices/virtio/sysfs-gpu-parent0/drm/card89".to_vec());

    drv::device_del(&drm);
    drv::device_del(&parent);
    assert_eq!(index.lookup(&drm_index).err(), Some(VfsError::Enoent));
}

/// A PCI-backed virtio-gpu DRM card must nest under the PCI transport so
/// The installed `path_id` classifier reaches a PCI ancestor and
/// resolves ID_PATH instead of failing ENOENT. Reproduces the seat card0
/// topology and walks it exactly as `path_id`'s parent walk does.
#[test]
fn drm_card_nests_under_pci_transport_for_path_id() {
    let pci = Arc::new(
        drv::Device::new(
            "pci",
            String::from("0000:00:04.0"),
            TEST_VIRTIO_VENDOR_ID,
            TEST_GPU_PCI_DEVICE_ID,
            TEST_GPU_PCI_CLASS,
        ));
    let virtio = Arc::new(
        drv::Device::new(
            "virtio",
            String::from("virtio7"),
            TEST_VIRTIO_VENDOR_ID,
            TEST_VIRTIO_GPU_DEVICE_ID,
            0,
        )
            .with_parent("pci", String::from("0000:00:04.0")));
    let card = Arc::new(
        drv::Device::new("drm", String::from("card7"), 0, 0, 0)
            .with_parent("virtio", String::from("virtio7"))
            .with_sysfs_relpath(String::from("drm/card7"))
            .with_devnode(
                "drm",
                String::from("dri/card7"),
                Some((::drm::DRM_MAJOR, PATH_DRM_MINOR)),
            ));
    drv::try_device_add(Arc::clone(&pci)).expect("pci registration");
    drv::try_device_add(Arc::clone(&virtio)).expect("virtio registration");
    drv::try_device_add(Arc::clone(&card)).expect("drm registration");

    // /sys/class/drm/card7 -> nested path under the PCI function.
    let class = crate::drm::make_sys_class_drm_inode_for_test();
    assert_eq!(
        class.lookup("card7").expect("class link").readlink().expect("readlink"),
        b"../../devices/pci0000:00/0000:00:04.0/virtio7/drm/card7".to_vec());

    // Walk the physical directory chain the way udev/path_id does, from the
    // PCI root down to card7, and verify each device dir's `subsystem`
    // basename (path_id classifies parents by that basename only).
    let pci_root = make_devices_root_inode("pci");
    let pci_dir = pci_root.lookup("0000:00:04.0").expect("pci device dir");
    assert!(subsystem_basename(&pci_dir) == b"pci");

    let virtio_dir = pci_dir.lookup("virtio7").expect("virtio nested under pci");
    assert!(subsystem_basename(&virtio_dir) == b"virtio");
    let vendor = virtio_dir.lookup("vendor").expect("virtio vendor attribute");
    let mut vendor_bytes = [0u8; ATTRIBUTE_READ_BUFFER_BYTES];
    let n = vendor.read(0, &mut vendor_bytes).expect("read virtio vendor");
    let expected_vendor = alloc::format!("0x{TEST_VIRTIO_VENDOR_ID:04x}\n");
    assert_eq!(&vendor_bytes[..n], expected_vendor.as_bytes());
    // The virtio function is NO LONGER at the flat /sys/devices/virtio root.
    assert_eq!(
        make_devices_root_inode("virtio").lookup("virtio7").err(),
        Some(VfsError::Enoent));

    let drm_dir = virtio_dir.lookup("drm").expect("drm container under virtio");
    assert!(drm_dir.lookup("card7").is_ok());

    // path_id parent walk: card7 -> drm(container) -> virtio7(virtio,skip)
    // -> 0000:00:04.0(pci) => supported_parent, ID_PATH=pci-0000:00:04.0.
    // The chain reaching a "pci" subsystem is what the walk above proves.

    drv::device_del(&card);
    drv::device_del(&virtio);
    drv::device_del(&pci);
}

fn subsystem_basename(dir: &vfs::InodeRef) -> Vec<u8> {
    let link = dir.lookup("subsystem").expect("subsystem symlink");
    let target = link.readlink().expect("readlink");
    target.rsplit(|b| *b == b'/').next().unwrap_or(&target).to_vec()
}

#[test]
fn sys_dev_char_index_tracks_remove_readd_same_devt() {
    let index = make_sys_dev_index_inode(DevIndexKind::Char);
    let first = Arc::new(
        drv::Device::new("sound", String::from("controlC12"), 0, 0, 0)
            .with_devnode("sound", String::from("snd/controlC12"), Some(REUSED_SOUND_DEVT)));
    drv::try_device_add(Arc::clone(&first)).expect("first sound registration");

    let sound_index = devt_name(REUSED_SOUND_DEVT);
    let link = index.lookup(&sound_index).expect("first sound char index");
    assert_eq!(
        link.readlink().expect("readlink"),
        b"../../devices/virtual/sound/controlC12".to_vec());

    drv::device_del(&first);
    assert_eq!(index.lookup(&sound_index).err(), Some(VfsError::Enoent));

    let second = Arc::new(
        drv::Device::new("sound", String::from("controlC12"), 0, 0, 0)
            .with_devnode("sound", String::from("snd/controlC12"), Some(REUSED_SOUND_DEVT)));
    drv::try_device_add(Arc::clone(&second)).expect("second sound registration");

    let link = index.lookup(&sound_index).expect("readded sound char index");
    assert_eq!(
        link.readlink().expect("readlink"),
        b"../../devices/virtual/sound/controlC12".to_vec());

    drv::device_del(&second);
    assert_eq!(index.lookup(&sound_index).err(), Some(VfsError::Enoent));
}
