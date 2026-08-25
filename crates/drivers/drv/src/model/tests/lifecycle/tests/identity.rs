use super::*;

#[test]
fn find_matching_device_identity_reuses_only_exact_platform_identity() {
    let _model = crate::model::test_claim::claim_model();
    let existing = try_device_add(Arc::new(Device::new(
        "platform", String::from(PLATFORM_REUSE_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )))
    .unwrap();
    let same = Device::new(
        "platform", String::from(PLATFORM_REUSE_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    );
    let with_parent = Device::new(
        "platform", String::from(PLATFORM_REUSE_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )
        .with_parent("platform", String::from(PLATFORM_REUSE_PARENT_ADDR));
    let with_devnode = Device::new(
        "platform", String::from(PLATFORM_REUSE_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )
        .with_devnode(
            PLATFORM_REUSE_DEVNODE_CLASS,
            String::from(PLATFORM_REUSE_DEVNODE_NAME),
            Some((PLATFORM_REUSE_DEV_MAJOR, PLATFORM_REUSE_DEV_MINOR)),
        );
    let with_resource = Device::new(
        "platform", String::from(PLATFORM_REUSE_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )
        .with_resources(Vec::from([
            Resource {
                bar: PLATFORM_REUSE_RESOURCE_BAR,
                start: PLATFORM_REUSE_RESOURCE_START,
                end: PLATFORM_REUSE_RESOURCE_END,
                flags: IORESOURCE_MEM,
            },
        ]));

    assert!(Arc::ptr_eq(&find_matching_device_identity(&same).unwrap(), &existing));
    assert!(!existing.identity_eq(&with_parent));
    assert!(!existing.identity_eq(&with_devnode));
    assert!(!existing.identity_eq(&with_resource));
    assert!(find_matching_device_identity(&with_parent).is_none());
    assert!(find_matching_device_identity(&with_devnode).is_none());
    assert!(find_matching_device_identity(&with_resource).is_none());

    device_del(&existing);
}

#[test]
fn platform_identity_conflict_is_busy_but_not_reusable() {
    let _model = crate::model::test_claim::claim_model();
    let existing = try_device_add(Arc::new(Device::new(
        "platform", String::from(PLATFORM_CONFLICT_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )))
    .unwrap();
    let conflict = Arc::new(Device::new(
        "platform", String::from(PLATFORM_CONFLICT_ADDR),
        PLATFORM_REUSE_VENDOR_ID, PLATFORM_REUSE_DEVICE_ID, PLATFORM_REUSE_CLASS,
    )
    .with_devnode(
        PLATFORM_CONFLICT_DEVNODE_CLASS,
        String::from(PLATFORM_CONFLICT_DEVNODE_NAME),
        Some((PLATFORM_CONFLICT_DEV_MAJOR, PLATFORM_CONFLICT_DEV_MINOR)),
    ));

    assert!(matches!(
        try_device_add(Arc::clone(&conflict)),
        Err(crate::Error::Busy)
    ));
    assert!(find_matching_device_identity(&conflict).is_none());
    assert!(devices().iter().any(|d| Arc::ptr_eq(d, &existing)));
    assert_eq!(
        devices().iter()
            .filter(|d| d.bus == "platform" && d.addr == PLATFORM_CONFLICT_ADDR)
            .count(),
        1
    );

    device_del(&existing);
}

#[test]
fn try_device_add_preserves_pci_bar_resources_and_rejects_republish() {
    let _model = crate::model::test_claim::claim_model();
    let first = try_device_add(Arc::new(
        Device::new("pci", String::from("0000:00:18.0"), 0x1234, 0x5678, 0x010601)
            .with_resources(Vec::from([
                Resource { bar: 0, start: 0x8000_0000, end: 0x8000_0fff, flags: IORESOURCE_MEM },
                Resource { bar: 5, start: 0x0000_c000, end: 0x0000_c0ff, flags: IORESOURCE_IO },
            ]))))
        .unwrap();

    assert_eq!(first.resources.len(), 2);
    assert_eq!(
        first.resources[0],
        Resource { bar: 0, start: 0x8000_0000, end: 0x8000_0fff, flags: IORESOURCE_MEM });
    assert_eq!(
        first.resources[1],
        Resource { bar: 5, start: 0x0000_c000, end: 0x0000_c0ff, flags: IORESOURCE_IO });

    let duplicate = try_device_add(Arc::new(
        Device::new("pci", String::from("0000:00:18.0"), 0x1234, 0x5678, 0x010601)
            .with_resources(Vec::from([
                Resource { bar: 0, start: 0x9000_0000, end: 0x9000_0fff, flags: IORESOURCE_MEM },
            ]))));

    assert!(matches!(duplicate, Err(crate::Error::Busy)));
    let dev = devices().into_iter()
        .find(|d| d.bus == "pci" && d.addr == "0000:00:18.0")
        .unwrap();
    assert_eq!(dev.resources, first.resources);

    device_del(&first);
}

#[test]
fn pci_identity_mismatch_does_not_replace_or_rebind() {
    let _model = crate::model::test_claim::claim_model();
    PCI_IDENTITY_PROBES.store(0, Ordering::Release);
    PCI_MISMATCH_PROBES.store(0, Ordering::Release);
    register_driver(&PCI_IDENTITY_DRV);
    register_driver(&PCI_MISMATCH_DRV);
    for (idx, addr) in ["0000:00:17.0", "0000:01:17.0"].iter().enumerate() {
        let first = try_device_add(Arc::new(Device::new(
            "pci", String::from(*addr), 0x1af4, 0x1041, 0x010000)))
            .unwrap();

        assert_eq!(first.bound(), Some("pci-identity-test"));
        assert_eq!(PCI_IDENTITY_PROBES.load(Ordering::Acquire), (idx + 1) as u32);
        assert_eq!(PCI_MISMATCH_PROBES.load(Ordering::Acquire), 0);

        let mismatch = try_device_add(Arc::new(Device::new(
            "pci", String::from(*addr), 0x1af4, 0x1042, 0x020000)));

        assert!(matches!(mismatch, Err(crate::Error::Busy)));
        assert_eq!(first.bound(), Some("pci-identity-test"));
        assert_eq!(PCI_IDENTITY_PROBES.load(Ordering::Acquire), (idx + 1) as u32);
        assert_eq!(PCI_MISMATCH_PROBES.load(Ordering::Acquire), 0);
        assert_eq!(
            devices().iter()
                .filter(|d| d.bus == "pci" && d.addr == *addr)
                .count(),
            1
        );
        let dev = devices().into_iter()
            .find(|d| d.bus == "pci" && d.addr == *addr)
            .unwrap();
        assert_eq!(dev.vendor_id, 0x1af4);
        assert_eq!(dev.device_id, 0x1041);
        assert_eq!(dev.class, 0x010000);

        device_del(&first);
    }
}
