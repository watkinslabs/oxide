use super::*;

#[test]
fn bind_hook_reports_bound_and_unbound_after_state_change() {
    use sync::Spinlock as TestLock;
    static EVENTS: TestLock<Vec<BindEvent>, DriverListClass> = TestLock::new(Vec::new());
    fn hook(_bus: &str, _addr: &str, _driver: &'static str, event: BindEvent) {
        EVENTS.lock().push(event);
    }

    EVENTS.lock().clear();
    set_bind_hook(hook);
    register_driver(&REMOVE_DRV);
    let d = device_add(Arc::new(Device::new(
        "pci", String::from("0000:00:12.0"), 0x1234, 0x7777, 0)));

    assert_eq!(d.bound(), Some("remove-test"));
    assert_eq!(unbind(&d), Ok(()));
    assert_eq!(d.bound(), None);
    assert_eq!(&*EVENTS.lock(), &[BindEvent::Unbound]);
    assert_eq!(bind(&d, "remove-test"), Ok(()));
    assert_eq!(&*EVENTS.lock(), &[BindEvent::Unbound, BindEvent::Bound]);
}

#[test]
fn device_add_fires_devtmpfs_hook_and_registers() {
    use sync::Spinlock as TestLock;
    static SEEN: TestLock<Option<(&'static str, String, Option<(u32, u32)>)>, DriverListClass>
        = TestLock::new(None);
    static ORDER: AtomicU32 = AtomicU32::new(0);
    static SYSFS_AFTER_DEV: AtomicU32 = AtomicU32::new(0);
    fn cb(class: &str, name: &str, dev_t: Option<(u32, u32)>, _f: Option<NodeFactory>) {
        let c: &'static str = if class == "block" { "block" } else { "other" };
        *SEEN.lock() = Some((c, String::from(name), dev_t));
        ORDER.store(1, Ordering::Release);
    }
    fn sysfs_cb(_d: &Device) {
        if ORDER.load(Ordering::Acquire) == 1 {
            SYSFS_AFTER_DEV.store(1, Ordering::Release);
        }
    }
    ORDER.store(0, Ordering::Release);
    SYSFS_AFTER_DEV.store(0, Ordering::Release);
    set_devtmpfs_hook(cb);
    set_sysfs_hook(sysfs_cb);
    let dev = device_add(Arc::new(
        Device::new("virtio", String::from("virtio9"), 0x1AF4, 0x1042, 0)
            .with_devnode("block", String::from("vdz"), Some((254, 9)))));
    let seen = SEEN.lock().clone();
    assert_eq!(seen, Some(("block", String::from("vdz"), Some((254, 9)))));
    assert!(devices().iter().any(|x| x.addr == "virtio9"));
    assert_eq!(dev.dev_class, "block");
    assert_eq!(SYSFS_AFTER_DEV.load(Ordering::Acquire), 1);
}

#[test]
fn device_add_initial_probe_precedes_add_uevent_without_bind_change() {
    fn devtmpfs_cb(_class: &str, name: &str, _dev_t: Option<(u32, u32)>, _f: Option<NodeFactory>) {
        if name == "device-add-order-node" {
            ADD_ORDER.lock().push("devtmpfs");
        }
    }
    fn sysfs_cb(d: &Device) {
        if d.addr == "device-add-order0" {
            if d.bound() == Some("device-add-order-test") {
                ADD_SYSFS_SAW_BOUND.store(1, Ordering::Release);
            }
            ADD_ORDER.lock().push("sysfs-add");
        }
    }
    fn bind_cb(_bus: &str, addr: &str, _driver: &'static str, event: BindEvent) {
        if addr == "device-add-order0" && event == BindEvent::Bound {
            ADD_BIND_EVENTS.fetch_add(1, Ordering::Release);
        }
    }

    ADD_ORDER.lock().clear();
    ADD_PROBES.store(0, Ordering::Release);
    ADD_SYSFS_SAW_BOUND.store(0, Ordering::Release);
    ADD_BIND_EVENTS.store(0, Ordering::Release);
    set_devtmpfs_hook(devtmpfs_cb);
    set_sysfs_hook(sysfs_cb);
    set_bind_hook(bind_cb);
    register_driver(&ADD_ORDER_DRV);

    let dev = device_add(Arc::new(
        Device::new("platform", String::from("device-add-order0"), 0, 0x6300, 0)
            .with_devnode("misc", String::from("device-add-order-node"), Some((10, 252)))));

    assert_eq!(dev.bound(), Some("device-add-order-test"));
    assert_eq!(ADD_PROBES.load(Ordering::Acquire), 1);
    assert_eq!(ADD_SYSFS_SAW_BOUND.load(Ordering::Acquire), 1);
    assert_eq!(ADD_BIND_EVENTS.load(Ordering::Acquire), 0);
    assert_eq!(&*ADD_ORDER.lock(), &["devtmpfs", "probe", "sysfs-add"]);
    device_del(&dev);
}

#[test]
fn sysfs_hook_fires_on_device_add() {
    static HITS: AtomicU32 = AtomicU32::new(0);
    fn cb(_d: &Device) { HITS.fetch_add(1, Ordering::Release); }
    set_sysfs_hook(cb);
    let before = HITS.load(Ordering::Acquire);
    device_add(Arc::new(Device::new(
        "pci", alloc::string::String::from("0000:00:0c.0"), 0x1234, 0x5678, 0)));
    assert!(HITS.load(Ordering::Acquire) > before);
}
