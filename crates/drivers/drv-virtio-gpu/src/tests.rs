use super::*;
use alloc::{format, string::String};
use core::sync::atomic::{AtomicU32, AtomicU64};
use sync::{Spinlock, TaskList as DriverLockClass};

static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());

    const fn key(raw: u32) -> DeviceKey {
        DeviceKey::from_raw(raw)
    }

    fn test_ctrlq() -> virtio::VirtQueueResource {
        virtio::VirtQueueResource {
            index:      0,
            size:       1,
            desc_pa:    0,
            driver_pa:  0,
            device_pa:  0,
            notify_va:  0,
            notify_off: 0,
        }
    }

    #[test]
    fn ctrl_hdr_layout() {
        // virtio 1.2 §5.7.6.7: 24 bytes.
        assert_eq!(core::mem::size_of::<VirtioGpuCtrlHdr>(), 24);
    }

    #[test]
    fn rect_layout() {
        assert_eq!(core::mem::size_of::<VirtioGpuRect>(), 16);
    }

    #[test]
    fn display_one_layout() {
        assert_eq!(core::mem::size_of::<VirtioGpuDisplayOne>(), 24);
    }

    #[test]
    fn resp_display_info_layout() {
        // 24 hdr + 16 modes × 24 = 24 + 384 = 408
        assert_eq!(core::mem::size_of::<VirtioGpuRespDisplayInfo>(), 24 + 16 * 24);
    }

    #[test]
    fn resp_edid_size() {
        // 24 hdr + 4 size + 4 padding + 1024 edid = 1056
        assert_eq!(core::mem::size_of::<VirtioGpuRespEdid>(), 1056);
    }

    #[test]
    fn negotiate_intersects() {
        let host    = 0b1111u64;
        let driver  = 0b0110u64;
        assert_eq!(negotiate_features(host, driver), 0b0110u64);
    }

    #[test]
    fn driver_features_include_virgl_and_edid() {
        let bits = default_driver_features();
        assert!(bits & (1u64 << VIRTIO_GPU_F_VIRGL) != 0);
        assert!(bits & (1u64 << VIRTIO_GPU_F_EDID) != 0);
        assert!(bits & (1u64 << VIRTIO_F_VERSION_1) != 0);
    }

    #[test]
    fn bpp_for_known_formats() {
        assert_eq!(VirtioGpuDev::bytes_per_pixel(VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM), 4);
        assert_eq!(VirtioGpuDev::bytes_per_pixel(VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM), 4);
        assert_eq!(VirtioGpuDev::bytes_per_pixel(0xdead), 0);
    }

    #[test]
    fn encode_get_display_info_writes_24() {
        let mut buf = [0xAAu8; 64];
        let n = encode_get_display_info(&mut buf);
        assert_eq!(n, 24);
        assert_eq!(read_u32_le(&buf, 0), VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
        assert_eq!(read_u32_le(&buf, 4), 0);
        for i in 8..24 { assert_eq!(buf[i], 0); }
    }

    #[test]
    fn encode_get_edid_writes_32_with_scanout() {
        let mut buf = [0u8; 64];
        let n = encode_get_edid(&mut buf, 7);
        assert_eq!(n, 32);
        assert_eq!(read_u32_le(&buf, 0), VIRTIO_GPU_CMD_GET_EDID);
        assert_eq!(read_u32_le(&buf, 24), 7);
    }

    #[test]
    fn encode_resource_create_2d_layout() {
        let mut buf = [0u8; 64];
        let n = encode_resource_create_2d(&mut buf, 5, VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM, 800, 600);
        assert_eq!(n, 40);
        assert_eq!(read_u32_le(&buf, 0),  VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
        assert_eq!(read_u32_le(&buf, 24), 5);
        assert_eq!(read_u32_le(&buf, 28), VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM);
        assert_eq!(read_u32_le(&buf, 32), 800);
        assert_eq!(read_u32_le(&buf, 36), 600);
    }

    #[test]
    fn encode_resource_lifetime_layouts() {
        let mut detach = [0u8; 64];
        let n = encode_resource_detach_backing(&mut detach, 9);
        assert_eq!(n, 32);
        assert_eq!(read_u32_le(&detach, 0), VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING);
        assert_eq!(read_u32_le(&detach, 24), 9);
        assert_eq!(read_u32_le(&detach, 28), 0);

        let mut unref = [0u8; 64];
        let n = encode_resource_unref(&mut unref, 9);
        assert_eq!(n, 32);
        assert_eq!(read_u32_le(&unref, 0), VIRTIO_GPU_CMD_RESOURCE_UNREF);
        assert_eq!(read_u32_le(&unref, 24), 9);
        assert_eq!(read_u32_le(&unref, 28), 0);
    }

    #[test]
    fn encode_set_scanout_layout() {
        let mut buf = [0u8; 64];
        let n = encode_set_scanout(&mut buf, 0, 5, 0, 0, 800, 600);
        assert_eq!(n, 48);
        assert_eq!(read_u32_le(&buf, 0),  VIRTIO_GPU_CMD_SET_SCANOUT);
        assert_eq!(read_u32_le(&buf, 32), 800);   // rect width
        assert_eq!(read_u32_le(&buf, 36), 600);   // rect height
        assert_eq!(read_u32_le(&buf, 40), 0);     // scanout
        assert_eq!(read_u32_le(&buf, 44), 5);     // res_id
    }

    #[test]
    fn cursor_wire_layouts_and_encodings() {
        assert_eq!(core::mem::size_of::<VirtioGpuCursorPos>(), 16);
        assert_eq!(core::mem::size_of::<VirtioGpuUpdateCursor>(), 56);
        let mut update = [0u8; 64];
        assert_eq!(encode_update_cursor(&mut update, 9, 64, 64, 17, 23, 2, 3), 56);
        assert_eq!(read_u32_le(&update, 0), VIRTIO_GPU_CMD_UPDATE_CURSOR);
        assert_eq!(read_u32_le(&update, 24), 0);
        assert_eq!(read_u32_le(&update, 28), 17);
        assert_eq!(read_u32_le(&update, 32), 23);
        assert_eq!(read_u32_le(&update, 40), 9);
        assert_eq!(read_u32_le(&update, 44), 2);
        assert_eq!(read_u32_le(&update, 48), 3);
        let mut mov = [0u8; 64];
        assert_eq!(encode_move_cursor(&mut mov, 10, 20), 40);
        assert_eq!(read_u32_le(&mov, 0), VIRTIO_GPU_CMD_MOVE_CURSOR);
        assert_eq!(read_u32_le(&mov, 28), 10);
        assert_eq!(read_u32_le(&mov, 32), 20);
    }

    #[test]
    fn parse_display_info_decodes_one_enabled() {
        let mut resp = [0u8; 24 + 16 * 24];
        // type = RESP_OK_DISPLAY_INFO
        write_u32_le(&mut resp, 0, VIRTIO_GPU_RESP_OK_DISPLAY_INFO);
        // pmode[0] = enabled at 800x600
        write_u32_le(&mut resp, 24 + 0,  0);   // x
        write_u32_le(&mut resp, 24 + 4,  0);   // y
        write_u32_le(&mut resp, 24 + 8,  800); // w
        write_u32_le(&mut resp, 24 + 12, 600); // h
        write_u32_le(&mut resp, 24 + 16, 1);   // enabled
        let info = parse_display_info(&resp).unwrap();
        assert_eq!(info.count_enabled, 1);
        assert_eq!(info.modes[0].r.width,  800);
        assert_eq!(info.modes[0].r.height, 600);
        assert_eq!(info.modes[0].enabled, 1);
    }

    #[test]
    fn parse_display_info_rejects_wrong_type() {
        let mut resp = [0u8; 24 + 16 * 24];
        write_u32_le(&mut resp, 0, VIRTIO_GPU_RESP_ERR_UNSPEC);
        let r = parse_display_info(&resp);
        assert!(matches!(r, Err(Error::BadResp(VIRTIO_GPU_RESP_ERR_UNSPEC))));
    }

    #[test]
    fn parse_edid_decodes_block() {
        let mut resp = [0u8; 24 + 8 + 1024];
        write_u32_le(&mut resp, 0, VIRTIO_GPU_RESP_OK_EDID);
        // canonical EDID magic at offset 32
        let magic = [0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00];
        for i in 0..8 { resp[32 + i] = magic[i]; }
        let edid = parse_edid(&resp).unwrap();
        assert_eq!(&edid[..8], &magic);
    }

    #[test]
    fn parse_nodata_accepts_any_ok() {
        let mut resp = [0u8; 24];
        write_u32_le(&mut resp, 0, VIRTIO_GPU_RESP_OK_NODATA);
        assert!(parse_nodata_resp(&resp).is_ok());
        write_u32_le(&mut resp, 0, VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY);
        assert!(parse_nodata_resp(&resp).is_err());
    }

    #[test]
    fn install_and_lookup_roundtrip() {
        let _guard = TEST_LOCK.lock();
        // Reset the global table first to keep tests order-independent.
        DEVICES.lock().clear();
        assert!(!is_present());
        install(VirtioGpuDev {
            device_key: key(0x0010_0000),
            bdf: 0x0010_0000,
            card_id: 0,
            cfg_va: 0,
            ctrlq: test_ctrlq(), cursorq: test_ctrlq(),
            features_negotiated: (1u64 << VIRTIO_GPU_F_EDID),
            display: DisplayInfo {
                modes: [VirtioGpuDisplayOne::default(); VIRTIO_GPU_MAX_SCANOUTS],
                count_enabled: 1,
            },
            resource_id_alloc: AtomicU32::new(1),
            blob_uuid_alloc: AtomicU64::new(1),
            capset_count: 0,
        }).unwrap();
        install(VirtioGpuDev {
            device_key: key(0x0020_0000),
            bdf: 0x0020_0000,
            card_id: 1,
            cfg_va: 0,
            ctrlq: test_ctrlq(), cursorq: test_ctrlq(),
            features_negotiated: 0,
            display: DisplayInfo {
                modes: [VirtioGpuDisplayOne::default(); VIRTIO_GPU_MAX_SCANOUTS],
                count_enabled: 2,
            },
            resource_id_alloc: AtomicU32::new(1),
            blob_uuid_alloc: AtomicU64::new(1),
            capset_count: 0,
        }).unwrap();
        assert!(is_present());
        let first = display_info_for_bdf(0x0010_0000).unwrap();
        let second = display_info_for_bdf(0x0020_0000).unwrap();
        assert_eq!(first.count_enabled, 1);
        assert_eq!(second.count_enabled, 2);
        assert!(negotiated_features_for_bdf(0x0010_0000).unwrap() & (1u64 << VIRTIO_GPU_F_EDID) != 0);
        assert_eq!(negotiated_features_for_bdf(0x0020_0000), Some(0));
        assert!(display_info_for_bdf(0x0030_0000).is_none());
        assert!(negotiated_features_for_bdf(0x0030_0000).is_none());
        // Cleanup.
        DEVICES.lock().clear();
    }

    #[test]
    fn install_accepts_multiple_keys_and_rejects_duplicate_key() {
        let _guard = TEST_LOCK.lock();
        fn dev(device_key: DeviceKey, bdf: u32) -> VirtioGpuDev {
            VirtioGpuDev {
                device_key,
                bdf,
                card_id: 0,
                cfg_va: 0,
                ctrlq: test_ctrlq(), cursorq: test_ctrlq(),
                features_negotiated: 0,
                display: DisplayInfo::default(),
                resource_id_alloc: AtomicU32::new(1),
                blob_uuid_alloc: AtomicU64::new(1),
                capset_count: 0,
            }
        }

        DEVICES.lock().clear();
        install(dev(key(1), 0x0010_0000)).unwrap();
        install(dev(key(2), 0x0020_0000)).unwrap();
        assert_eq!(install(dev(key(2), 0x0020_0001)), Err(Error::Busy));
        assert_eq!(DEVICES.lock().len(), 2);
        assert_eq!(uninstall(key(1)).unwrap().bdf, 0x0010_0000);
        assert!(is_present());
        assert_eq!(uninstall(key(2)).unwrap().bdf, 0x0020_0000);
        assert!(!is_present());
    }

    #[test]
    fn uninstall_selects_owner_by_child_key_not_raw_bdf() {
        let _guard = TEST_LOCK.lock();
        fn dev(device_key: DeviceKey, bdf: u32) -> VirtioGpuDev {
            VirtioGpuDev {
                device_key,
                bdf,
                card_id: 0,
                cfg_va: 0,
                ctrlq: test_ctrlq(), cursorq: test_ctrlq(),
                features_negotiated: 0,
                display: DisplayInfo::default(),
                resource_id_alloc: AtomicU32::new(1),
                blob_uuid_alloc: AtomicU64::new(1),
                capset_count: 0,
            }
        }

        DEVICES.lock().clear();
        install(dev(key(0x00aa_0000), 0x0010_0000)).unwrap();
        install(dev(key(0x0010_0000), 0x0020_0000)).unwrap();

        let removed = uninstall(key(0x00aa_0000)).unwrap();
        assert_eq!(removed.bdf, 0x0010_0000);
        assert_eq!(DEVICES.lock().len(), 1);
        assert_eq!(uninstall(key(0x0010_0000)).unwrap().bdf, 0x0020_0000);
        assert!(!is_present());
    }

    #[test]
    fn install_with_drm_tracks_each_bdf_card_id() {
        let _guard = TEST_LOCK.lock();
        fn dev(device_key: DeviceKey, bdf: u32) -> VirtioGpuDev {
            VirtioGpuDev {
                device_key,
                bdf,
                card_id: 0,
                cfg_va: 0,
                ctrlq: test_ctrlq(), cursorq: test_ctrlq(),
                features_negotiated: 0,
                display: DisplayInfo::default(),
                resource_id_alloc: AtomicU32::new(1),
                blob_uuid_alloc: AtomicU64::new(1),
                capset_count: 0,
            }
        }

        DEVICES.lock().clear();
        let card_id_1 = install_with_drm(dev(key(1), 0x0010_0000)).unwrap();
        let card_id_2 = install_with_drm(dev(key(2), 0x0020_0000)).unwrap();
        {
            let devices = DEVICES.lock();
            assert_eq!(
                devices
                    .iter()
                    .find(|dev| dev.device_key == key(1))
                    .unwrap()
                    .card_id,
                card_id_1
            );
            assert_eq!(
                devices
                    .iter()
                    .find(|dev| dev.device_key == key(2))
                    .unwrap()
                    .card_id,
                card_id_2
            );
        }
        let cards_before_dup = drm::card_count();
        let drm_devices_before_dup = drv::devices().into_iter().filter(|dev| dev.bus == "drm").count();
        assert_eq!(install_with_drm(dev(key(2), 0x0020_0001)), Err(Error::Busy));
        assert_eq!(drm::card_count(), cards_before_dup);
        assert_eq!(drv::devices().into_iter().filter(|dev| dev.bus == "drm").count(), drm_devices_before_dup);
        assert_eq!(uninstall(key(1)).unwrap().card_id, card_id_1);
        assert!(is_present());
        assert_eq!(uninstall(key(2)).unwrap().card_id, card_id_2);
        assert!(!is_present());
    }

    #[test]
    fn install_with_drm_records_model_parent() {
        let _guard = TEST_LOCK.lock();
        fn dev(device_key: DeviceKey, bdf: u32) -> VirtioGpuDev {
            VirtioGpuDev {
                device_key,
                bdf,
                card_id: 0,
                cfg_va: 0,
                ctrlq: test_ctrlq(), cursorq: test_ctrlq(),
                features_negotiated: 0,
                display: DisplayInfo::default(),
                resource_id_alloc: AtomicU32::new(1),
                blob_uuid_alloc: AtomicU64::new(1),
                capset_count: 0,
            }
        }

        DEVICES.lock().clear();
        let parent_addr = String::from("virtio-gpu-parent-test0");
        let card_id = install_with_drm_parent(
            dev(key(3), 0x0030_0000),
            Some(("virtio", parent_addr.clone())),
        ).unwrap();
        let card_name = format!("dri/card{card_id}");
        let drm_dev = drv::devices()
            .into_iter()
            .find(|dev| dev.bus == "drm" && dev.addr.as_str() == card_name.as_str())
            .expect("DRM card model device");
        assert_eq!(drm_dev.parent(), Some(("virtio", parent_addr.as_str())));

        assert_eq!(uninstall(key(3)).unwrap().card_id, card_id);
        assert!(!is_present());
    }

    #[test]
    fn shutdown_keeps_device_installed() {
        let _guard = TEST_LOCK.lock();
        DEVICES.lock().clear();
        install(VirtioGpuDev {
            device_key: key(1),
            bdf: 1,
            card_id: 0,
            cfg_va: 0,
            ctrlq: test_ctrlq(), cursorq: test_ctrlq(),
            features_negotiated: 0,
            display: DisplayInfo::default(),
            resource_id_alloc: AtomicU32::new(1),
            blob_uuid_alloc: AtomicU64::new(1),
            capset_count: 0,
        }).unwrap();

        assert!(!shutdown(key(2)));
        assert!(shutdown(key(1)));
        assert!(is_present());

        DEVICES.lock().clear();
    }

    #[test]
    fn drm_accessors_skip_disabled_scanouts() {
        use drm::DrmDriver;
        let mut modes = [VirtioGpuDisplayOne::default(); VIRTIO_GPU_MAX_SCANOUTS];
        // scanout 0 disabled; scanout 1 enabled 800x600; scanout 3 enabled 1024x768.
        modes[1] = VirtioGpuDisplayOne {
            r: VirtioGpuRect { x: 0, y: 0, width: 800, height: 600 }, enabled: 1, flags: 0 };
        modes[3] = VirtioGpuDisplayOne {
            r: VirtioGpuRect { x: 0, y: 0, width: 1024, height: 768 }, enabled: 1, flags: 0 };
        let d = VirtioGpuDrm {
            display: DisplayInfo { modes, count_enabled: 2 },
            features_negotiated: 0, bdf: 0,
            unique: drm_unique_from_bdf(0),
        };
        // Two CRTC/connector/encoder objects and primary+cursor planes.
        assert_eq!(d.crtc_ids(), alloc::vec![1, 2]);
        assert_eq!(d.connector_ids(), alloc::vec![0x100, 0x101]);
        assert_eq!(d.encoder_ids(), alloc::vec![0x200, 0x201]);
        assert_eq!(d.plane_ids(), alloc::vec![0x300, 0x301, 0x302, 0x303]);
        // enabled index 0 → first enabled (800x600), index 1 → 1024x768.
        let m0 = d.mode_for(0);
        assert_eq!(m0.hdisplay, 800);
        assert_eq!(m0.vdisplay, 600);
        let m1 = d.mode_for(1);
        assert_eq!(m1.hdisplay, 1024);
        assert_eq!(m1.vdisplay, 768);
        // connector / crtc / encoder facts for index 1.
        let c = d.connector_info(1).unwrap();
        assert_eq!(c.connection, drm::DRM_MODE_CONNECTED);
        assert_eq!(c.encoder_id, 0x201);
        assert_eq!(c.mode_count, 1);
        let cr = d.crtc_info(1).unwrap();
        assert_eq!(cr.mode_valid, 1);
        assert_eq!(cr.fb_id, 0);
        assert_eq!(d.virtgpu_get_caps(0), Some(drm::VirtgpuCaps::NoCapsets));
        assert_eq!(cr.mode.hdisplay, 1024);
        let e = d.encoder_info(1).unwrap();
        assert_eq!(e.crtc_id, 2);
        assert_eq!(e.possible_crtcs, 1 << 1);
        let p = d.plane_info(0).unwrap();
        assert_eq!(p.crtc_id, 1);
        assert_eq!(d.plane_info(1).unwrap().crtc_id, 1);
        assert_eq!(d.plane_info(2).unwrap().crtc_id, 2);
        // out of range
        assert!(d.connector_info(2).is_none());
        assert!(d.crtc_info(2).is_none());
    }

    #[test]
    fn drm_fourcc_mapping() {
        // XRGB8888 'XR24' → BGRX (no alpha); ARGB8888 'AR24' → BGRA.
        assert_eq!(drm_fourcc_to_virtio(0x3432_5258), Some(VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM));
        assert_eq!(drm_fourcc_to_virtio(0x3432_5241), Some(VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM));
        // Match the drm crate's published fourcc constants exactly.
        assert_eq!(drm_fourcc_to_virtio(drm::DRM_FORMAT_XRGB8888), Some(VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM));
        assert_eq!(drm_fourcc_to_virtio(drm::DRM_FORMAT_ARGB8888), Some(VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM));
        assert_eq!(drm_fourcc_to_virtio(0xdead_beef), None);
    }

    #[test]
    fn drm_unique_uses_pci_bdf_bus_id() {
        assert_eq!(drm_unique_from_bdf(0x0010_0000), "pci:0000:10:00.0");
        assert_eq!(drm_unique_from_bdf(0x0001_0203), "pci:0000:01:02.3");
    }

    #[test]
    fn resource_id_increments() {
        let dev = VirtioGpuDev {
            device_key: key(0),
            bdf: 0,
            card_id: 0,
            cfg_va: 0,
            ctrlq: test_ctrlq(), cursorq: test_ctrlq(),
            features_negotiated: 0,
            display: DisplayInfo::default(),
            resource_id_alloc: AtomicU32::new(1),
            blob_uuid_alloc: AtomicU64::new(1),
            capset_count: 0,
        };
        let a = dev.next_resource_id();
        let b = dev.next_resource_id();
        assert_ne!(a, b);
        assert_eq!(b, a + 1);
    }
