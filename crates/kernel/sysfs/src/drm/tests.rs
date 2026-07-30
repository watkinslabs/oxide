use super::*;
use alloc::sync::Arc;

const ATTRIBUTE_READ_BUFFER_BYTES: usize = 16;
const ENUM_CARD_MINOR: u32 = 42;
const ENUM_RENDER_MINOR: u32 = ::drm::DRM_RENDER_MINOR_BASE + ENUM_CARD_MINOR;
const PARENTED_CARD_MINOR: u32 = 43;
const PARENTED_RENDER_MINOR: u32 =
    ::drm::DRM_RENDER_MINOR_BASE + PARENTED_CARD_MINOR;
const ORPHAN_CARD_MINOR: u32 = 45;
const UEVENT_CARD_MINOR: u32 = 44;
const TEST_VIRTIO_VENDOR_ID: u16 = 0x1af4;
const TEST_VIRTIO_GPU_DEVICE_ID: u16 = 16;
const TEST_PCI_DEVICE_ID: u16 = 0x1050;

fn drm_dev(name: &str, minor: u32) -> Arc<drv::Device> {
    let addr = name.rsplit('/').next().expect("DRM devname leaf");
    drv::try_device_add(Arc::new(
        drv::Device::new("drm", String::from(addr), 0, 0, 0)
            .with_devnode("drm", String::from(name), Some((::drm::DRM_MAJOR, minor))),
    ))
    .expect("test device registration")
}

// The model registry is process-global, so enumeration tests must serialize.
static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn drm_class_enumerates_live_model_devices() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let card = drm_dev("dri/card42", ENUM_CARD_MINOR);
    let render = drm_dev("dri/renderD170", ENUM_RENDER_MINOR);

    let minors = drm_minors();
    assert!(minors
        .iter()
        .any(|m| m.name == "card42" && m.minor == ENUM_CARD_MINOR));
    assert!(minors
        .iter()
        .any(|m| m.name == "renderD170" && m.minor == ENUM_RENDER_MINOR));

    let class = make_sys_class_drm_inode();
    assert!(class.lookup("card42").is_ok());
    assert!(class.lookup("renderD170").is_ok());
    assert_eq!(class.lookup("card43").err(), Some(VfsError::Enoent));

    let devices = make_sys_devices_virtual_drm_inode();
    let card_dir = devices.lookup("card42").expect("card42 sysfs dir");
    let dev_attr = card_dir.lookup("dev").expect("card42 dev attr");
    let mut buf = [0u8; ATTRIBUTE_READ_BUFFER_BYTES];
    let n = dev_attr.read(0, &mut buf).expect("read dev attr");
    let expected = alloc::format!("{}:{ENUM_CARD_MINOR}\n", ::drm::DRM_MAJOR);
    assert_eq!(&buf[..n], expected.as_bytes());

    drv::device_del(&render);
    drv::device_del(&card);
}

#[test]
fn drm_class_device_links_to_model_parent_when_present() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let parent = Arc::new(drv::Device::new(
        "virtio",
        String::from("virtio-gpu-parent0"),
        TEST_VIRTIO_VENDOR_ID,
        TEST_VIRTIO_GPU_DEVICE_ID,
        0,
    ));
    drv::try_device_add(Arc::clone(&parent)).expect("test parent registration");
    let card = drv::try_device_add(Arc::new(
        drv::Device::new("drm", String::from("card43"), 0, 0, 0)
            .with_parent("virtio", String::from("virtio-gpu-parent0"))
            .with_sysfs_relpath(String::from("drm/card43"))
            .with_devnode(
                "drm",
                String::from("dri/card43"),
                Some((::drm::DRM_MAJOR, PARENTED_CARD_MINOR)),
            ),
    ))
    .expect("test drm registration");
    let render = drv::try_device_add(Arc::new(
        drv::Device::new("drm", String::from("renderD171"), 0, 0, 0)
            .with_parent("virtio", String::from("virtio-gpu-parent0"))
            .with_sysfs_relpath(String::from("drm/renderD171"))
            .with_devnode(
                "drm",
                String::from("dri/renderD171"),
                Some((::drm::DRM_MAJOR, PARENTED_RENDER_MINOR)),
            ),
    ))
    .expect("test render registration");

    let class = make_sys_class_drm_inode();
    assert_eq!(
        class.lookup("card43").expect("card43 class link").readlink().expect("readlink"),
        b"../../devices/virtio/virtio-gpu-parent0/drm/card43".to_vec(),
    );
    assert_eq!(
        class.lookup("renderD171").expect("render class link").readlink().expect("readlink"),
        b"../../devices/virtio/virtio-gpu-parent0/drm/renderD171".to_vec(),
    );
    assert_eq!(
        make_sys_devices_virtual_drm_inode().lookup("card43").err(),
        Some(VfsError::Enoent),
    );

    let parent_drm = make_parent_drm_inode(Arc::clone(&parent));
    let card_dir = parent_drm.lookup("card43").expect("card43 parented sysfs dir");
    assert!(parent_drm.lookup("renderD171").is_ok());
    assert_eq!(
        card_dir.lookup("device").expect("parent link").readlink().expect("readlink"),
        b"../..".to_vec(),
    );
    assert_eq!(
        card_dir.lookup("subsystem").expect("subsystem").readlink().expect("readlink"),
        b"../../../../../class/drm".to_vec(),
    );

    drv::device_del(&render);
    drv::device_del(&card);
    drv::device_del(&parent);
    assert_eq!(parent_drm.lookup("card43").err(), Some(VfsError::Enoent));
}

#[test]
fn drm_projection_rejects_removed_transitive_ancestor_and_reuse() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let pci_addr = "0000:00:2b.0";
    let virtio_addr = "virtio-gpu-orphan";
    let pci = drv::try_device_add(Arc::new(drv::Device::new(
        "pci",
        String::from(pci_addr),
        TEST_VIRTIO_VENDOR_ID,
        TEST_PCI_DEVICE_ID,
        0,
    ))).expect("PCI ancestor");
    let virtio = drv::try_device_add(Arc::new(
        drv::Device::new(
            "virtio",
            String::from(virtio_addr),
            TEST_VIRTIO_VENDOR_ID,
            TEST_VIRTIO_GPU_DEVICE_ID,
            0,
        )
            .with_parent("pci", String::from(pci_addr)),
    )).expect("virtio parent");
    let card = drv::try_device_add(Arc::new(
        drv::Device::new("drm", String::from("card45"), 0, 0, 0)
            .with_parent("virtio", String::from(virtio_addr))
            .with_sysfs_relpath(String::from("drm/card45"))
            .with_devnode(
                "drm",
                String::from("dri/card45"),
                Some((::drm::DRM_MAJOR, ORPHAN_CARD_MINOR)),
            ),
    )).expect("DRM child");
    let class = make_sys_class_drm_inode();
    assert!(class.lookup("card45").is_ok());
    let parent_drm = make_parent_drm_inode(Arc::clone(&virtio));
    let card_dir = parent_drm.lookup("card45").expect("parented card directory");
    let retained_uevent = card_dir.lookup("uevent").expect("retained uevent");

    drv::device_del(&pci);
    assert_eq!(class.lookup("card45").err(), Some(VfsError::Enoent));
    assert_eq!(parent_drm.lookup("card45").err(), Some(VfsError::Enoent));
    assert_eq!(card_dir.lookup("subsystem").err(), Some(VfsError::Enoent));
    assert_eq!(
        retained_uevent.write(0, b"change\n").err(),
        Some(VfsError::Enoent),
    );
    let replacement = drv::try_device_add(Arc::new(drv::Device::new(
        "pci",
        String::from(pci_addr),
        TEST_VIRTIO_VENDOR_ID,
        TEST_PCI_DEVICE_ID,
        0,
    ))).expect("same-name replacement ancestor");
    assert_eq!(class.lookup("card45").err(), Some(VfsError::Enoent));

    drv::device_del(&card);
    drv::device_del(&virtio);
    drv::device_del(&replacement);
}

#[test]
fn drm_uevent_attr_accepts_o_trunc_open() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let card = drm_dev("dri/card44", UEVENT_CARD_MINOR);
    let devices = make_sys_devices_virtual_drm_inode();
    let card_dir = devices.lookup("card44").expect("card44 sysfs dir");
    let uevent = card_dir.lookup("uevent").expect("card44 uevent attr");
    assert_eq!(uevent.truncate(0), Ok(()));
    let dentry = vfs::Dentry::new_root(Arc::clone(&uevent));
    let fdt = vfs::FdTable::new();
    let fd = vfs::file::install_open_at(
        &fdt,
        uevent,
        dentry,
        vfs::OpenFlags::O_WRONLY | vfs::OpenFlags::O_TRUNC,
        0,
        vfs::FileCred::root(),
        usize::MAX,
        None,
    ).expect("O_TRUNC open of uevent attr");
    assert_eq!(fdt.get(fd).unwrap().write(b"add\n"), Ok(4));
    drv::device_del(&card);
}
