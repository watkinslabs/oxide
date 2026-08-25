    use super::*;

    #[test]
    fn port_offset_math() {
        // Port 0 regs at ABAR+0x100; port 1 at +0x180.
        assert_eq!(port_off(0), 0x100);
        assert_eq!(port_off(1), 0x180);
        assert_eq!(port_off(2), 0x200);
        // PxCI of port 0 / port 3.
        assert_eq!(port_reg(0, P_CI), 0x138);
        assert_eq!(port_reg(3, P_CI), 0x100 + 3 * 0x80 + 0x38);
        // PxSSTS of port 1.
        assert_eq!(port_reg(1, P_SSTS), 0x180 + 0x28);
    }

    #[test]
    fn usable_port_map_rejects_bits_outside_capability_or_aperture() {
        let cap_three_ports = 2;
        let three_port_aperture = PORT_BASE + PORT_STRIDE * 3;
        assert_eq!(usable_port_map(cap_three_ports, 0b1111, three_port_aperture), 0b111);
        assert_eq!(usable_port_map(7, 0b1111, PORT_BASE + PORT_STRIDE * 2), 0b11);
    }

    #[test]
    fn dma_range_obeys_s64a() {
        assert!(dma_range_fits(CAP_S64A, 1 << 40, 4096));
        assert!(!dma_range_fits(CAP_S64A, u64::MAX, 4096));
        assert!(dma_range_fits(0, 0xFFFF_F000, 4096));
        assert!(!dma_range_fits(0, 0xFFFF_F001, 4096));
        assert!(!dma_range_fits(0, 1 << 32, 1));
        assert!(!dma_range_fits(0, 0, 0));
    }

    #[test]
    fn dma_mask_obeys_s64a() {
        assert_eq!(dma_mask(CAP_S64A), u64::MAX);
        assert_eq!(dma_mask(0), u32::MAX as u64);
    }

    #[test]
    fn one_prdt_entry_covers_the_contiguous_two_mib_data_run() {
        assert!(prdt_entry_fits(2 * 1024 * 1024));
        assert!(prdt_entry_fits(PRDT_MAX_BYTES));
        assert!(!prdt_entry_fits(0));
        assert!(!prdt_entry_fits(PRDT_MAX_BYTES + 1));
    }

    #[test]
    fn irq_completion_requires_slot_done_or_error() {
        assert!(!irq_finishes_slot(PIS_DPS, 1, 0));
        assert!(irq_finishes_slot(PIS_DHRS, 0, 0));
        assert!(irq_finishes_slot(PIS_TFES, 1, 0));
        assert!(irq_finishes_slot(PIS_DHRS, 1, TFD_ERR));
        assert!(!irq_status_failed(PIS_DHRS, 0));
        assert!(irq_status_failed(PIS_HBFS, 0));
    }

    #[test]
    fn stale_port_irq_cannot_complete_an_unissued_command() {
        assert!(!irq_finishes_issued_slot(false, PIS_DHRS, 0, 0));
        assert!(irq_finishes_issued_slot(true, PIS_DHRS, 0, 0));
    }

    #[test]
    fn link_change_is_limited_to_ahci_connect_and_phy_ready_causes() {
        assert!(irq_reports_link_change(PIS_PCS));
        assert!(irq_reports_link_change(PIS_PRCS));
        assert!(irq_reports_link_change(PIS_PCS | PIS_DHRS));
        assert!(!irq_reports_link_change(PIS_IPMS));
        assert!(!irq_reports_link_change(PIS_TFES));
        assert!(link_is_online(SSTS_DET_READY));
        assert!(!link_is_online(1));
        assert!(!link_is_online(0));
    }

    #[test]
    fn cmd_header_packing() {
        // 5-dword H2D FIS, read, PRDTL=1.
        let dw0 = cmd_header_dw0(5, false, 1);
        assert_eq!(dw0 & 0x1F, 5);          // CFL
        assert_eq!((dw0 >> 6) & 1, 0);      // W=0
        assert_eq!((dw0 >> 16) & 0xFFFF, 1); // PRDTL
        // write variant sets W.
        let dw0w = cmd_header_dw0(5, true, 1);
        assert_eq!((dw0w >> 6) & 1, 1);
        // PRDTL field is the upper 16 bits.
        assert_eq!(cmd_header_dw0(5, false, 8) >> 16, 8);
    }

    #[test]
    fn h2d_fis_identify() {
        // IDENTIFY: no LBA/count, device 0.
        let f = h2d_fis(ATA_IDENTIFY, 0, 0, 0);
        assert_eq!(f[0], 0x27);
        assert_eq!(f[1], 0x80);            // C bit
        assert_eq!(f[2], 0xEC);
        assert_eq!(&f[4..7], &[0, 0, 0]);
        assert_eq!(f[12], 0);
    }

    #[test]
    fn h2d_fis_read_lba48() {
        // READ DMA EXT, LBA = 0x0001_0203_0405, count 8, LBA mode device.
        let f = h2d_fis(ATA_READ_DMA_EXT, 0x0001_0203_0405, 8, ATA_DEV_LBA);
        assert_eq!(f[2], 0x25);
        assert_eq!(f[7], 0x40);            // device LBA bit
        // LBA[23:0] in b4..b6, LBA[47:24] in b8..b10.
        assert_eq!(f[4], 0x05);
        assert_eq!(f[5], 0x04);
        assert_eq!(f[6], 0x03);
        assert_eq!(f[8], 0x02);
        assert_eq!(f[9], 0x01);
        assert_eq!(f[10], 0x00);
        // count[7:0]=8, count[15:8]=0.
        assert_eq!(f[12], 8);
        assert_eq!(f[13], 0);
    }

    #[test]
    fn taskfile_fis_includes_the_32_byte_pass_through_auxiliary_register() {
        let mut taskfile = ata::Taskfile::non_data(ATA_IDENTIFY);
        taskfile.auxiliary = 0x1234_5678;
        let fis = h2d_taskfile(&taskfile);
        assert_eq!(&fis[16..20], &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn identify_count_lba48_preferred() {
        let mut w = [0u16; 256];
        // LBA48 supported (word 83 bit 10) + a 48-bit count.
        w[83] = 1 << 10;
        w[100] = 0x4000; w[101] = 0x0001; // 0x1_4000 = 81920 sectors
        // a stale/smaller LBA28 value that must be ignored.
        w[60] = 0x2000; w[61] = 0;
        assert_eq!(identify_sector_count(&w), 0x1_4000);
    }

    #[test]
    fn identify_count_lba28_fallback() {
        let mut w = [0u16; 256];
        // LBA48 NOT supported → use words 60-61.
        w[60] = 0x8000; w[61] = 0x0000; // 32768 sectors
        w[100] = 0xFFFF; w[101] = 0xFFFF; // present but must be ignored
        assert_eq!(identify_sector_count(&w), 0x8000);
        // LBA48 supported but zero → fall back to LBA28 too.
        w[83] = 1 << 10;
        w[100] = 0; w[101] = 0; w[102] = 0; w[103] = 0;
        assert_eq!(identify_sector_count(&w), 0x8000);
    }

    #[test]
    fn identify_size_default_512() {
        let w = [0u16; 256];
        assert_eq!(identify_sector_size(&w), 512);
    }

    #[test]
    fn identify_size_4k() {
        let mut w = [0u16; 256];
        // word 106: bit 14 set (word valid), bit 13 clear (not multiple
        // logical per physical relevant here), bit 12 set (logical > 512).
        w[106] = (1 << 14) | (1 << 12);
        w[117] = 2048; w[118] = 0; // 2048 words = 4096 bytes
        assert_eq!(identify_sector_size(&w), 4096);
    }

    #[test]
    fn identify_write_cache_follows_wce() {
        let mut w = [0u16; 256];
        assert!(!identify_write_cache_word(w[85]));
        w[85] = 1 << 5;
        assert!(identify_write_cache_word(w[85]));
    }

    #[test]
    fn identify_serial_decodes_ata_word_swapped_ascii() {
        let mut w = [0u16; 256];
        let serial = *b"  OXIDE-AHCI-0001   ";
        for i in 0..10 {
            w[10 + i] = ((serial[i * 2] as u16) << 8) | serial[i * 2 + 1] as u16;
        }
        let (decoded, len) = identify_serial(&w);
        assert_eq!(&decoded[..len], b"OXIDE-AHCI-0001");
    }

    #[test]
    fn identify_serial_all_padding_is_absent() {
        let w = [0x2020u16; 256];
        let (_decoded, len) = identify_serial(&w);
        assert_eq!(len, 0);
    }
