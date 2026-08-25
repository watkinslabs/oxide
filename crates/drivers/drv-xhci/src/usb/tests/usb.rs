    use super::*;
    #[test]
    fn device_descriptor_keeps_the_wire_ep0_encoding() {
        let mut bytes = [0u8; DEVICE_DESC_BYTES]; bytes[0] = 18; bytes[1] = DESC_DEVICE; bytes[7] = 64; bytes[8] = 0x34; bytes[9] = 0x12; bytes[10] = 0x78; bytes[11] = 0x56; bytes[17] = 1;
        assert_eq!(device_descriptor(&bytes), Some(DeviceDescriptor { vendor: 0x1234, product: 0x5678, device_class: 0, device_protocol: 0, max_packet0: 64, serial_index: 0, configurations: 1 }));
        bytes[7] = 7; assert!(device_descriptor(&bytes).is_none());
        bytes[7] = 9; assert_eq!(device_descriptor(&bytes).unwrap().max_packet0, 9);
    }
    #[test]
    fn string_descriptor_is_exact_utf16le_and_carries_its_wire_index() {
        assert_eq!(string_descriptor(&[12, DESC_STRING, b'o', 0, b'x', 0, b'i', 0, b'd', 0, b'e', 0]).as_deref(), Some("oxide"));
        assert_eq!(string_descriptor(&[6, DESC_STRING, 0x3d, 0xd8, 0x80, 0xde]).as_deref(), Some("🚀"));
        assert!(string_descriptor(&[5, DESC_STRING, b'x', 0, 0]).is_none());
        let td = get_string_descriptor_trbs(0x90_000, 7).unwrap();
        assert_eq!(td[0].dword[0], 0x0307_0680);
        assert_eq!(td[0].dword[1], 0x00ff_0409);
    }
    #[test]
    fn ep0_packet_size_follows_speed_specific_usb_encoding() {
        assert_eq!(ep0_packet_size(1, 8), Some(8));
        assert_eq!(ep0_packet_size(1, 64), Some(64));
        assert_eq!(ep0_packet_size(2, 8), Some(8));
        assert_eq!(ep0_packet_size(3, 64), Some(64));
        assert_eq!(ep0_packet_size(4, 9), Some(512));
        assert_eq!(ep0_packet_size(5, 9), Some(512));
        assert_eq!(ep0_packet_size(3, 9), None);
        assert_eq!(ep0_packet_size(4, 64), None);
    }
    #[test]
    fn device_descriptor_request_is_standard_in_control_td() {
        let td = get_device_descriptor_trbs(0x90_000).unwrap();
        assert_eq!(td[0].dword[0], 0x0100_0680);
        assert_eq!(td[1].dword[2], DEVICE_DESC_BYTES as u32);
        assert_eq!(td[2].dword[3], (crate::ring::TRB_TYPE_STATUS << crate::ring::TRB_TYPE_SHIFT) | (1 << 5));
    }
    #[test]
    fn configuration_header_and_two_stage_request_are_strict() {
        let bytes = [9, DESC_CONFIGURATION, 34, 0, 1, 2, 0, 0x80, 50];
        assert_eq!(configuration_header(&bytes), Some(ConfigurationHeader { total_length: 34, value: 2, interfaces: 1 }));
        assert!(configuration_header(&[9, DESC_CONFIGURATION, 8, 0, 1, 2, 0, 0, 0]).is_none());
        let td = get_configuration_descriptor_trbs(0x90_000, 2, 34).unwrap();
        assert_eq!(td[0].dword[0], 0x0202_0680);
        assert_eq!(td[1].dword[2], 34);
        assert!(get_configuration_descriptor_trbs(0x90_000, 0, 8).is_none());
    }
    #[test]
    fn hid_boot_parser_selects_only_interrupt_in_keyboard_or_mouse() {
        let bytes = [9, DESC_CONFIGURATION, 34, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 1, 1, 0, 9, 0x21, 0x11, 1, 0, 1, 0x22, 63, 0, 7, 5, 0x81, 3, 8, 0, 10];
        assert_eq!(hid_boot_interface(&bytes), Some(HidBootInterface { configuration: 1, interface: 0, protocol: 1, endpoint: 0x81, max_packet: 8, interval: 10 }));
        let mut non_boot = bytes; non_boot[15] = 2;
        assert!(hid_boot_interface(&non_boot).is_none());
    }
    #[test]
    fn generic_hid_interface_and_report_request_are_exact() {
        let bytes = [9, DESC_CONFIGURATION, 34, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 3, 0, 0, 0, 9, 0x21, 0x11, 1, 0, 1, 0x22, 52, 0, 7, 5, 0x81, 3, 8, 0, 10];
        assert_eq!(hid_interface(&bytes), Some(HidInterface { configuration: 1, interface: 0, endpoint: 0x81, max_packet: 8, interval: 10, report_bytes: 52 }));
        let td = get_hid_report_descriptor_trbs(0x90_000, 0, 52).unwrap();
        assert_eq!(td[0].dword[0], 0x2200_0681);
        assert_eq!(td[1].dword[2], 52);
        let idle = set_hid_idle_trbs(3);
        assert_eq!(idle[0].dword[0], 0x0000_0a21);
        assert_eq!(idle[0].dword[1], 3);
        assert_eq!(idle[1].dword[3], (crate::ring::TRB_TYPE_STATUS << crate::ring::TRB_TYPE_SHIFT) | (1 << 5) | (1 << 16));
    }
    #[test]
    fn storage_parser_requires_transparent_scsi_bulk_in_and_out() {
        let bytes = [9, DESC_CONFIGURATION, 32, 0, 1, 1, 0, 0x80, 50, 9, 4, 2, 0, 2, 8, 6, 0x50, 0, 7, 5, 0x02, 2, 0, 2, 0, 7, 5, 0x81, 2, 0, 2, 0];
        assert_eq!(mass_storage_interface(&bytes), Some(crate::storage::MassStorageInterface { configuration: 1, interface: 2, bulk_in: 0x81, bulk_in_packet: 512, bulk_out: 2, bulk_out_packet: 512 }));
        let mut wrong_protocol = bytes; wrong_protocol[16] = 0x62;
        assert!(mass_storage_interface(&wrong_protocol).is_none());
        let max_lun = get_mass_storage_max_lun_trbs(0x90_000, 2).unwrap();
        assert_eq!(max_lun[0].dword, [0x0000_fea1, 2 | ((MASS_STORAGE_MAX_LUN_BYTES as u32) << 16), 8,
            (crate::ring::TRB_TYPE_SETUP << crate::ring::TRB_TYPE_SHIFT) | (1 << 6) | (3 << 16)]);
        assert_eq!(max_lun[1].dword[2], MASS_STORAGE_MAX_LUN_BYTES as u32);
    }
    #[test]
    fn set_configuration_is_a_no_data_out_control_td() {
        let td = set_configuration_trbs(1).unwrap();
        assert_eq!(td[0].dword, [0x0001_0900, 0, 8, (crate::ring::TRB_TYPE_SETUP << crate::ring::TRB_TYPE_SHIFT) | (1 << 6)]);
        assert_eq!(td[1].dword[3], (crate::ring::TRB_TYPE_STATUS << crate::ring::TRB_TYPE_SHIFT) | (1 << 16) | (1 << 5));
        assert!(set_configuration_trbs(0).is_none());
    }
    #[test]
    fn hid_boot_protocol_is_a_class_interface_no_data_request() {
        let td = set_hid_boot_protocol_trbs(3);
        assert_eq!(td[0].dword, [0x0000_0b21, 3, 8, (crate::ring::TRB_TYPE_SETUP << crate::ring::TRB_TYPE_SHIFT) | (1 << 6)]);
        assert_eq!(td[1].dword[3], (crate::ring::TRB_TYPE_STATUS << crate::ring::TRB_TYPE_SHIFT) | (1 << 16) | (1 << 5));
    }
    #[test]
    fn hub_descriptor_and_class_request_keep_port_geometry_strict() {
        let descriptor = [9, DESC_HUB, 4, 0x20, 0, 10, 0, 0, 0];
        assert_eq!(hub_descriptor(&descriptor), Some(HubDescriptor { ports: 4, power_good_ms: 20, tt_think_time: 1 }));
        assert!(hub_descriptor(&[7, DESC_HUB, 4, 0, 0, 10, 0]).is_none());
        let td = get_hub_descriptor_trbs(0x90_000, 9).unwrap();
        assert_eq!(td[0].dword, [0x2900_06a0, 9 << 16, 8, (crate::ring::TRB_TYPE_SETUP << crate::ring::TRB_TYPE_SHIFT) | (1 << 6) | (3 << 16)]);
        assert_eq!(td[1].dword[2], 9);
    }
    #[test]
    fn hub_port_control_uses_class_port_recipients_and_exact_status_bytes() {
        assert_eq!(hub_port_status(&[1, 0, 1, 0]), Some(HubPortStatus { status: 1, change: 1 }));
        assert!(hub_port_status(&[0; 3]).is_none());
        let status = get_hub_port_status_trbs(0x90_000, 2).unwrap();
        assert_eq!(status[0].dword[0], 0x0000_00a3);
        assert_eq!(status[0].dword[1], 2 | ((HUB_PORT_STATUS_BYTES as u32) << 16));
        let power = hub_port_feature_trbs(2, HUB_PORT_FEATURE_POWER, true).unwrap();
        assert_eq!(power[0].dword[0], 0x0008_0323);
        assert_eq!(hub_port_changed(&[0b0000_0010], 1), Some(true));
        assert_eq!(hub_port_changed(&[0b0000_0010], 2), Some(false));
        assert_eq!(hub_port_changed(&[0], 8), None);
        let reset = hub_port_status(&[0x13, 4, 16, 0]).unwrap();
        assert!(reset.connected() && reset.enabled() && reset.resetting() && reset.reset_changed());
        assert_eq!(reset.xhci_portsc(), 3 << 10);
    }
    #[test]
    fn hub_interrupt_bitmap_is_exact_and_covers_bit_zero_through_last_port() {
        let bitmap = hub_status_bitmap(&[0b0000_0001, 0b0000_0010], 9).unwrap();
        assert_eq!(bitmap.bytes(), &[0b0000_0001, 0b0000_0010]);
        assert_eq!(hub_port_changed(bitmap.bytes(), 9), Some(true));
        assert!(hub_status_bitmap(&[0], 9).is_none());
        assert!(hub_status_bitmap(&[0; HUB_STATUS_MAX_BYTES + 1], u8::MAX).is_none());
    }
    #[test]
    fn hub_interface_requires_class_interrupt_in_status_endpoint() {
        let bytes = [9, DESC_CONFIGURATION, 25, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, USB_CLASS_HUB, 0, 0, 0, 7, 5, 0x81, 3, 2, 0, 12];
        assert_eq!(hub_interface(&bytes), Some(HubInterface { configuration: 1, interface: 0, endpoint: 0x81, max_packet: 2, interval: 12 }));
    }

