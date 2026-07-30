use super::*;

const TEST_PCI_VENDOR_ID: u16 = 0x1af4;
const TEST_PCI_DEVICE_ID: u16 = 0x1000;
const TEST_PCI_CLASS: u32 = 0x010000;
const TEST_VIRTIO_DEVICE_ID: u16 = 2;
const ATTRIBUTE_READ_BUFFER_BYTES: usize = 64;

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

    pub(super) fn uevent_has_entry(msg: &[u8], needle: &[u8]) -> bool {
        msg.split(|b| *b == 0).any(|entry| entry == needle)
    }

    pub(super) fn next_uevent_matching(
        listener: &netlink::NetlinkSocket,
        needles: &[&[u8]],
    ) -> Vec<u8> {
        // KOBJECT_UEVENT is process-global broadcast state in hosted tests.
        // Discard unrelated broadcasts until this listener's queue is empty;
        // a fixed scan bound could hide the event this test just generated.
        while let Some((msg, _src)) = listener.dequeue() {
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
            "pci",
            String::from("0000:00:2f.0"),
            TEST_PCI_VENDOR_ID,
            TEST_PCI_DEVICE_ID,
            TEST_PCI_CLASS,
        ));
        drv::try_device_add(Arc::clone(&parent)).expect("parent registered");
        let child = Arc::new(drv::Device::new(
            "virtio",
            String::from("sysfs-virtio-child0"),
            0,
            TEST_VIRTIO_DEVICE_ID,
            0,
        )
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

        let mut buf = [0u8; ATTRIBUTE_READ_BUFFER_BYTES];
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
        listener.set_group_mask(netlink::KOBJECT_UEVENT_KERNEL_GROUP_MASK);
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

        let _hook_serial = super::device_hook_serial();
        drv::set_sysfs_hook(publish_device_cb);
        drv::register_driver(&SYSFS_ADD_UEVENT_DRIVER);
        let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
        listener.set_group_mask(netlink::KOBJECT_UEVENT_KERNEL_GROUP_MASK);
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

        let _hook_serial = super::device_hook_serial();
        fn no_add_uevent(_dev: &drv::Device) {}

        let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
        listener.set_group_mask(netlink::KOBJECT_UEVENT_KERNEL_GROUP_MASK);
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
