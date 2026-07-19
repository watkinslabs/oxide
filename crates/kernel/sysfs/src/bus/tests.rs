extern crate alloc;
    mod block_index;
    mod uevent_replay;
    use super::hooks::*;
    use super::dirs::{make_bus_drivers_inode, make_devices_root_inode};
    use super::index::{make_sys_dev_index_inode, DevIndexKind};
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};
    use vfs::VfsError;

    struct SysfsBindDriver;
    impl drv::Driver for SysfsBindDriver {
        fn bus(&self) -> &'static str { "platform" }
        fn name(&self) -> &'static str { "sysfs-bind-test" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.addr == "sysfs-bind-dev0" }
        fn probe(&self, _dev: &Arc<drv::Device>) -> drv::KResult<()> {
            BIND_PROBES.fetch_add(1, Ordering::Release);
            Ok(())
        }
        fn remove(&self, _dev: &drv::Device) {
            BIND_REMOVES.fetch_add(1, Ordering::Release);
        }
    }

    static SYSFS_BIND_DRIVER: SysfsBindDriver = SysfsBindDriver;
    static BIND_PROBES: AtomicU32 = AtomicU32::new(0);
    static BIND_REMOVES: AtomicU32 = AtomicU32::new(0);

    struct SysfsNestedVirtioDriver;
    impl drv::Driver for SysfsNestedVirtioDriver {
        fn bus(&self) -> &'static str { "virtio" }
        fn name(&self) -> &'static str { "sysfs-nested-virtio-test" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.addr == "sysfs-virtio-child0" }
    }
    static SYSFS_NESTED_VIRTIO_DRIVER: SysfsNestedVirtioDriver = SysfsNestedVirtioDriver;

    struct SysfsBindUeventDriver;
    impl drv::Driver for SysfsBindUeventDriver {
        fn bus(&self) -> &'static str { "platform" }
        fn name(&self) -> &'static str { "sysfs-bind-uevent-test" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.addr == "sysfs-bind-uevent0" }
    }
    static SYSFS_BIND_UEVENT_DRIVER: SysfsBindUeventDriver = SysfsBindUeventDriver;

    struct SysfsAddUeventDriver;
    impl drv::Driver for SysfsAddUeventDriver {
        fn bus(&self) -> &'static str { "platform" }
        fn name(&self) -> &'static str { "sysfs-add-uevent-test" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.addr == "sysfs-add-uevent0" }
    }
    static SYSFS_ADD_UEVENT_DRIVER: SysfsAddUeventDriver = SysfsAddUeventDriver;

    struct RejectDriver;
    impl drv::Driver for RejectDriver {
        fn bus(&self) -> &'static str { "platform" }
        fn name(&self) -> &'static str { "sysfs-bind-reject" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.addr == "sysfs-bind-reject0" }
        fn probe(&self, _dev: &Arc<drv::Device>) -> drv::KResult<()> {
            Err(drv::Error::ProbeFailed)
        }
    }
    static REJECT_DRIVER: RejectDriver = RejectDriver;

    struct SysfsUnregisterDriver;
    impl drv::Driver for SysfsUnregisterDriver {
        fn bus(&self) -> &'static str { "platform" }
        fn name(&self) -> &'static str { "sysfs-unregister-test" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.addr == "sysfs-unregister0" }
        fn remove(&self, _dev: &drv::Device) {
            UNREGISTER_REMOVES.fetch_add(1, Ordering::Release);
        }
    }
    static SYSFS_UNREGISTER_DRIVER: SysfsUnregisterDriver = SysfsUnregisterDriver;
    static UNREGISTER_REMOVES: AtomicU32 = AtomicU32::new(0);

    fn platform_device(addr: &str) -> Arc<drv::Device> {
        let d = Arc::new(drv::Device::new("platform", String::from(addr), 0, 0, 0));
        drv::try_device_add(Arc::clone(&d)).expect("test device registration");
        d
    }

    fn uevent_has_entry(msg: &[u8], needle: &[u8]) -> bool {
        msg.split(|b| *b == 0).any(|entry| entry == needle)
    }

    fn next_uevent_matching(listener: &netlink::NetlinkSocket, needles: &[&[u8]]) -> Vec<u8> {
        for _ in 0..64 {
            let Some((msg, _src)) = listener.dequeue() else { break; };
            if needles.iter().all(|needle| uevent_has_entry(&msg, needle)) {
                return msg;
            }
        }
        panic!("matching uevent not delivered");
    }

    #[test]
    fn driver_bind_unbind_attrs_drive_drv_model() {
        BIND_PROBES.store(0, Ordering::Release);
        BIND_REMOVES.store(0, Ordering::Release);
        drv::register_driver(&SYSFS_BIND_DRIVER);
        let dev = platform_device("sysfs-bind-dev0");

        let root = make_bus_drivers_inode("platform");
        let dir = root.lookup("sysfs-bind-test").expect("driver dir");
        let bind = dir.lookup("bind").expect("bind attr");
        assert_eq!(dev.bound(), Some("sysfs-bind-test"));
        assert_eq!(BIND_PROBES.load(Ordering::Acquire), 1);
        assert_eq!(bind.write(0, b"sysfs-bind-dev0\n").err(), Some(VfsError::Ebusy));
        let bound_link = dir.lookup("sysfs-bind-dev0").expect("driver dir bound device symlink");
        assert_eq!(
            bound_link.readlink().expect("readlink"),
            b"../../../../devices/platform/sysfs-bind-dev0".to_vec());
        let devices = make_devices_root_inode("platform");
        let device_dir = devices.lookup("sysfs-bind-dev0").expect("device dir");
        let driver_link = device_dir.lookup("driver").expect("device driver symlink");
        assert_eq!(
            driver_link.readlink().expect("readlink"),
            b"../../../bus/platform/drivers/sysfs-bind-test".to_vec());

        let unbind = dir.lookup("unbind").expect("unbind attr");
        assert_eq!(unbind.write(0, b"sysfs-bind-dev0\n"), Ok("sysfs-bind-dev0\n".len()));
        assert_eq!(dev.bound(), None);
        assert_eq!(BIND_REMOVES.load(Ordering::Acquire), 1);
        assert_eq!(dir.lookup("sysfs-bind-dev0").err(), Some(VfsError::Enoent));
        assert_eq!(device_dir.lookup("driver").err(), Some(VfsError::Enoent));

        assert_eq!(bind.write(0, b"sysfs-bind-dev0\n"), Ok("sysfs-bind-dev0\n".len()));
        assert_eq!(dev.bound(), Some("sysfs-bind-test"));
        assert_eq!(BIND_PROBES.load(Ordering::Acquire), 2);
        let rebound_link = dir.lookup("sysfs-bind-dev0").expect("driver dir rebound device symlink");
        assert_eq!(
            rebound_link.readlink().expect("readlink"),
            b"../../../../devices/platform/sysfs-bind-dev0".to_vec());
        let rebound_driver_link = device_dir.lookup("driver").expect("device rebound driver symlink");
        assert_eq!(
            rebound_driver_link.readlink().expect("readlink"),
            b"../../../bus/platform/drivers/sysfs-bind-test".to_vec());
    }

    #[test]
    fn driver_device_symlink_uses_canonical_nested_path() {
        drv::register_driver(&SYSFS_NESTED_VIRTIO_DRIVER);
        let parent = Arc::new(drv::Device::new(
            "pci", String::from("0000:00:2f.0"), 0x1af4, 0x1000, 0x010000));
        drv::try_device_add(Arc::clone(&parent)).expect("parent registered");
        let child = Arc::new(drv::Device::new(
            "virtio", String::from("sysfs-virtio-child0"), 0, 2, 0)
            .with_parent("pci", String::from("0000:00:2f.0")));
        drv::try_device_add(Arc::clone(&child)).expect("child registered");
        assert_eq!(child.bound(), Some("sysfs-nested-virtio-test"));

        let root = make_bus_drivers_inode("virtio");
        let dir = root.lookup("sysfs-nested-virtio-test").expect("driver dir");
        let link = dir.lookup("sysfs-virtio-child0").expect("driver device link");
        assert_eq!(
            link.readlink().expect("driver link target"),
            b"../../../../devices/pci0000:00/0000:00:2f.0/sysfs-virtio-child0".to_vec());
    }

    #[test]
    fn driver_override_attr_tracks_model_state() {
        let dev = platform_device("sysfs-override-dev0");
        let devices = make_devices_root_inode("platform");
        let device_dir = devices.lookup("sysfs-override-dev0").expect("device dir");
        let attr = device_dir.lookup("driver_override").expect("driver_override attr");

        let mut buf = [0u8; 64];
        let n = attr.read(0, &mut buf).expect("read default override");
        assert_eq!(&buf[..n], b"(null)\n");
        assert_eq!(dev.driver_override(), None);

        assert_eq!(attr.write(0, b"sysfs-override-driver\n"), Ok("sysfs-override-driver\n".len()));
        assert_eq!(dev.driver_override().as_deref(), Some("sysfs-override-driver"));
        let n = attr.read(0, &mut buf).expect("read written override");
        assert_eq!(&buf[..n], b"sysfs-override-driver\n");

        assert_eq!(attr.write(0, b"(null)\n"), Ok("(null)\n".len()));
        assert_eq!(dev.driver_override(), None);
        let n = attr.read(0, &mut buf).expect("read cleared override");
        assert_eq!(&buf[..n], b"(null)\n");
    }

    #[test]
    fn bind_unbind_emit_change_uevents_from_current_model_state() {
        use netlink::{proto, NetlinkSocket};

        let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
        listener.set_group_mask(1);
        netlink::register_uevent_listener(&listener);
        drv::set_bind_hook(bind_device_cb);

        let dev = platform_device("sysfs-bind-uevent0");
        drv::register_driver(&SYSFS_BIND_UEVENT_DRIVER);

        let bound = next_uevent_matching(&listener, &[
            b"ACTION=change",
            b"DEVPATH=/devices/platform/sysfs-bind-uevent0",
            b"SUBSYSTEM=platform",
            b"DRIVER=sysfs-bind-uevent-test",
        ]);
        assert!(uevent_has_entry(&bound, b"ACTION=change"));
        assert!(uevent_has_entry(&bound, b"DEVPATH=/devices/platform/sysfs-bind-uevent0"));
        assert!(uevent_has_entry(&bound, b"SUBSYSTEM=platform"));
        assert!(uevent_has_entry(&bound, b"DRIVER=sysfs-bind-uevent-test"));
        assert_eq!(dev.bound(), Some("sysfs-bind-uevent-test"));

        let root = make_bus_drivers_inode("platform");
        let dir = root.lookup("sysfs-bind-uevent-test").expect("driver dir");
        let unbind = dir.lookup("unbind").expect("unbind attr");
        assert_eq!(unbind.write(0, b"sysfs-bind-uevent0\n"), Ok("sysfs-bind-uevent0\n".len()));

        let unbound = next_uevent_matching(&listener, &[
            b"ACTION=change",
            b"DEVPATH=/devices/platform/sysfs-bind-uevent0",
            b"SUBSYSTEM=platform",
        ]);
        assert!(uevent_has_entry(&unbound, b"ACTION=change"));
        assert!(uevent_has_entry(&unbound, b"DEVPATH=/devices/platform/sysfs-bind-uevent0"));
        assert!(uevent_has_entry(&unbound, b"SUBSYSTEM=platform"));
        assert!(!uevent_has_entry(&unbound, b"DRIVER=sysfs-bind-uevent-test"));
        assert_eq!(dev.bound(), None);

        drv::device_del(&dev);
    }

    #[test]
    fn device_add_uevent_includes_initial_bound_driver_state() {
        use netlink::{proto, NetlinkSocket};

        drv::set_sysfs_hook(publish_device_cb);
        drv::register_driver(&SYSFS_ADD_UEVENT_DRIVER);
        let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
        listener.set_group_mask(1);
        netlink::register_uevent_listener(&listener);

        let dev = platform_device("sysfs-add-uevent0");

        let added = next_uevent_matching(&listener, &[
            b"ACTION=add",
            b"DEVPATH=/devices/platform/sysfs-add-uevent0",
            b"SUBSYSTEM=platform",
            b"DRIVER=sysfs-add-uevent-test",
        ]);
        assert!(uevent_has_entry(&added, b"ACTION=add"));
        assert!(uevent_has_entry(&added, b"DEVPATH=/devices/platform/sysfs-add-uevent0"));
        assert!(uevent_has_entry(&added, b"SUBSYSTEM=platform"));
        assert!(uevent_has_entry(&added, b"DRIVER=sysfs-add-uevent-test"));
        assert_eq!(dev.bound(), Some("sysfs-add-uevent-test"));

        drv::device_del(&dev);
    }

    #[test]
    fn device_del_emits_remove_uevent_before_model_disappears() {
        use netlink::{proto, NetlinkSocket};

        fn no_add_uevent(_dev: &drv::Device) {}

        let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
        listener.set_group_mask(1);
        netlink::register_uevent_listener(&listener);
        drv::set_sysfs_hook(no_add_uevent);
        drv::set_sysfs_remove_hook(remove_device_cb);

        let dev = Arc::new(drv::Device::new(
            "platform",
            String::from("sysfs-remove-uevent0"),
            0,
            0,
            0,
        ));
        drv::try_device_add(Arc::clone(&dev)).expect("test device registration");

        drv::device_del(&dev);

        let removed = next_uevent_matching(&listener, &[
            b"ACTION=remove",
            b"DEVPATH=/devices/platform/sysfs-remove-uevent0",
            b"SUBSYSTEM=platform",
        ]);
        assert!(uevent_has_entry(&removed, b"ACTION=remove"));
        assert!(uevent_has_entry(
            &removed,
            b"DEVPATH=/devices/platform/sysfs-remove-uevent0"
        ));
        assert!(uevent_has_entry(&removed, b"SUBSYSTEM=platform"));
        assert!(!drv::devices()
            .iter()
            .any(|registered| Arc::ptr_eq(registered, &dev)));
    }

    #[test]
    fn driver_unregister_removes_sysfs_driver_dir_and_unbinds_devices() {
        UNREGISTER_REMOVES.store(0, Ordering::Release);
        drv::register_driver(&SYSFS_UNREGISTER_DRIVER);
        let dev = platform_device("sysfs-unregister0");

        let root = make_bus_drivers_inode("platform");
        assert!(root.lookup("sysfs-unregister-test").is_ok());
        assert_eq!(dev.bound(), Some("sysfs-unregister-test"));

        assert_eq!(drv::unregister_driver(&SYSFS_UNREGISTER_DRIVER), Ok(()));
        assert_eq!(dev.bound(), None);
        assert_eq!(UNREGISTER_REMOVES.load(Ordering::Acquire), 1);
        assert_eq!(root.lookup("sysfs-unregister-test").err(), Some(VfsError::Enoent));

        drv::device_del(&dev);
    }

    #[test]
    fn driver_bind_attr_preserves_unbound_state_on_probe_failure() {
        drv::register_driver(&REJECT_DRIVER);
        let dev = platform_device("sysfs-bind-reject0");

        let root = make_bus_drivers_inode("platform");
        let dir = root.lookup("sysfs-bind-reject").expect("driver dir");
        let bind = dir.lookup("bind").expect("bind attr");
        assert_eq!(bind.write(0, b"sysfs-bind-reject0\n").err(), Some(VfsError::Eio));
        assert_eq!(dev.bound(), None);
        assert_eq!(dir.lookup("sysfs-bind-reject0").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn model_device_with_dev_t_exposes_dev_attr_and_sys_dev_index() {
        let dev = Arc::new(
            drv::Device::new("virtio", String::from("sysfs-dev-index0"), 0, 2, 0)
                .with_devnode("block", String::from("vdt"), Some((254, 42))));
        drv::try_device_add(Arc::clone(&dev)).expect("test device registration");

        let devices = make_devices_root_inode("virtio");
        let dir = devices.lookup("sysfs-dev-index0").expect("device dir");
        let dev_attr = dir.lookup("dev").expect("dev attr");
        let mut buf = [0u8; 16];
        let n = dev_attr.read(0, &mut buf).expect("read dev attr");
        assert_eq!(&buf[..n], b"254:42\n");

        let index = make_sys_dev_index_inode(DevIndexKind::Block);
        let link = index.lookup("254:42").expect("block dev index link");
        assert_eq!(
            link.readlink().expect("readlink"),
            b"../../devices/virtio/sysfs-dev-index0".to_vec());

        drv::device_del(&dev);
        assert_eq!(devices.lookup("sysfs-dev-index0").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("254:42").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn pci_device_exposes_indexed_bar_resource_attrs() {
        let dev = Arc::new(
            drv::Device::new("pci", String::from("0000:00:1f.0"), 0x1234, 0x5678, 0x010601)
                .with_resources(Vec::from([
                    drv::Resource { bar: 2, start: 0x1000, end: 0x1fff, flags: 0x200 },
                    drv::Resource { bar: 5, start: 0xfebc_0000, end: 0xfebc_0fff, flags: 0x2200 },
                ])));
        drv::try_device_add(Arc::clone(&dev)).expect("test pci registration");

        let devices = make_devices_root_inode("pci");
        let dir = devices.lookup("0000:00:1f.0").expect("pci device dir");
        assert_eq!(dir.lookup("resource0").err(), Some(VfsError::Enoent));

        let resource = dir.lookup("resource").expect("aggregate resource attr");
        let mut buf = [0u8; 160];
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
        let mem = Arc::new(
            drv::Device::new("mem", String::from("sysfs-random-test"), 0, 0, 0)
                .with_devnode("mem", String::from("random-test"), Some((1, 8))));
        let misc = Arc::new(
            drv::Device::new("misc", String::from("sysfs-autofs-test"), 0, 0, 0)
                .with_devnode("misc", String::from("autofs-test"), Some((10, 235))));
        let sound = Arc::new(
            drv::Device::new("sound", String::from("controlC8"), 0, 0, 0)
                .with_devnode("sound", String::from("snd/controlC8"), Some((116, 256))));
        let graphics = Arc::new(
            drv::Device::new("graphics", String::from("fb8"), 0, 0, 0)
                .with_devnode("graphics", String::from("fb8"), Some((29, 8))));
        let input = Arc::new(
            drv::Device::new("input", String::from("event-sysdev8"), 0, 0, 0)
                .with_devnode("input", String::from("input/event-sysdev8"), Some((13, 88))));
        let drm = Arc::new(
            drv::Device::new("drm", String::from("card88"), 0, 0, 0)
                .with_devnode("drm", String::from("dri/card88"), Some((226, 88))));
        drv::try_device_add(Arc::clone(&mem)).expect("test mem registration");
        drv::try_device_add(Arc::clone(&misc)).expect("test misc registration");
        drv::try_device_add(Arc::clone(&sound)).expect("test sound registration");
        drv::try_device_add(Arc::clone(&graphics)).expect("test graphics registration");
        drv::try_device_add(Arc::clone(&input)).expect("test input registration");
        drv::try_device_add(Arc::clone(&drm)).expect("test drm registration");

        let index = make_sys_dev_index_inode(DevIndexKind::Char);
        let mem_link = index.lookup("1:8").expect("mem char index link");
        assert_eq!(
            mem_link.readlink().expect("readlink"),
            b"../../devices/virtual/mem/sysfs-random-test".to_vec());
        let misc_link = index.lookup("10:235").expect("misc char index link");
        assert_eq!(
            misc_link.readlink().expect("readlink"),
            b"../../devices/virtual/misc/sysfs-autofs-test".to_vec());
        let sound_link = index.lookup("116:256").expect("sound char index link");
        assert_eq!(
            sound_link.readlink().expect("readlink"),
            b"../../devices/virtual/sound/controlC8".to_vec());
        let graphics_link = index.lookup("29:8").expect("graphics char index link");
        assert_eq!(
            graphics_link.readlink().expect("readlink"),
            b"../../devices/virtual/graphics/fb8".to_vec());
        let input_link = index.lookup("13:88").expect("input char index link");
        assert_eq!(
            input_link.readlink().expect("readlink"),
            b"../../devices/virtual/input/input-sysdev8/event-sysdev8".to_vec());
        let drm_link = index.lookup("226:88").expect("drm char index link");
        assert_eq!(
            drm_link.readlink().expect("readlink"),
            b"../../devices/virtual/drm/card88".to_vec());

        drv::device_del(&mem);
        drv::device_del(&misc);
        drv::device_del(&sound);
        drv::device_del(&graphics);
        drv::device_del(&input);
        drv::device_del(&drm);
        assert_eq!(index.lookup("1:8").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("10:235").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("116:256").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("29:8").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("13:88").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("226:88").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn sys_dev_char_indexes_parented_drm_under_parent_device() {
        let parent = Arc::new(drv::Device::new(
            "virtio",
            String::from("sysfs-gpu-parent0"),
            0x1af4,
            16,
            0,
        ));
        let drm = Arc::new(
            drv::Device::new("drm", String::from("card89"), 0, 0, 0)
                .with_parent("virtio", String::from("sysfs-gpu-parent0"))
                .with_devnode("drm", String::from("dri/card89"), Some((226, 89))),
        );
        drv::try_device_add(Arc::clone(&parent)).expect("test parent registration");
        drv::try_device_add(Arc::clone(&drm)).expect("test drm registration");

        let parent_dir = make_devices_root_inode("virtio")
            .lookup("sysfs-gpu-parent0")
            .expect("parent device dir");
        let drm_dir = parent_dir.lookup("drm").expect("parent drm child dir");
        assert!(drm_dir.lookup("card89").is_ok());

        let index = make_sys_dev_index_inode(DevIndexKind::Char);
        let drm_link = index.lookup("226:89").expect("drm char index link");
        assert_eq!(
            drm_link.readlink().expect("readlink"),
            b"../../devices/virtio/sysfs-gpu-parent0/drm/card89".to_vec());

        drv::device_del(&drm);
        drv::device_del(&parent);
        assert_eq!(index.lookup("226:89").err(), Some(VfsError::Enoent));
    }

    /// A PCI-backed virtio-gpu DRM card must nest under the PCI transport so
    /// udev's `path_id` builtin (71-seat.rules) reaches a PCI ancestor and
    /// resolves ID_PATH instead of failing ENOENT. Reproduces the seat card0
    /// topology and walks it exactly as `path_id`'s parent walk does.
    #[test]
    fn drm_card_nests_under_pci_transport_for_path_id() {
        let pci = Arc::new(
            drv::Device::new("pci", String::from("0000:00:04.0"), 0x1af4, 0x1050, 0x030000));
        let virtio = Arc::new(
            drv::Device::new("virtio", String::from("virtio7"), 0x1af4, 16, 0)
                .with_parent("pci", String::from("0000:00:04.0")));
        let card = Arc::new(
            drv::Device::new("drm", String::from("card7"), 0, 0, 0)
                .with_parent("virtio", String::from("virtio7"))
                .with_devnode("drm", String::from("dri/card7"), Some((226, 7))));
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
        let mut vendor_bytes = [0u8; 16];
        let n = vendor.read(0, &mut vendor_bytes).expect("read virtio vendor");
        assert_eq!(&vendor_bytes[..n], b"0x1af4\n");
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
                .with_devnode("sound", String::from("snd/controlC12"), Some((116, 322))));
        drv::try_device_add(Arc::clone(&first)).expect("first sound registration");

        let link = index.lookup("116:322").expect("first sound char index");
        assert_eq!(
            link.readlink().expect("readlink"),
            b"../../devices/virtual/sound/controlC12".to_vec());

        drv::device_del(&first);
        assert_eq!(index.lookup("116:322").err(), Some(VfsError::Enoent));

        let second = Arc::new(
            drv::Device::new("sound", String::from("controlC12"), 0, 0, 0)
                .with_devnode("sound", String::from("snd/controlC12"), Some((116, 322))));
        drv::try_device_add(Arc::clone(&second)).expect("second sound registration");

        let link = index.lookup("116:322").expect("readded sound char index");
        assert_eq!(
            link.readlink().expect("readlink"),
            b"../../devices/virtual/sound/controlC12".to_vec());

        drv::device_del(&second);
        assert_eq!(index.lookup("116:322").err(), Some(VfsError::Enoent));
    }
