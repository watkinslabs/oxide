use super::*;

    #[test]
    fn setup_error_distinct() {
        assert_ne!(SetupError::NoMemmap,        SetupError::NoHhdm);
        assert_ne!(SetupError::NoUsableRegion,  SetupError::NoSpaceForBitmaps);
    }

    #[test]
    fn empty_memmap_returns_nomemmap() {
        let info = BootInfo {
            memmap_count: 0,
            memmap_ptr: core::ptr::null(),
            seed: [0; 32],
            boot_ns: 0,
            rsdp_pa: 0,
            hhdm_offset: 0xFFFF_8000_0000_0000,
            smp_info_array: 0,
            smp_count: 0,
            bsp_lapic_id: 0,
            _pad: 0,
        };
        // SAFETY: hosted test; memmap_count is 0 so memmap_ptr is
        // never dereferenced.
        assert_eq!(unsafe { init_from_boot_info(&info).err() }, Some(SetupError::NoMemmap));
    }

    #[test]
    fn missing_hhdm_returns_nohhdm() {
        let r = [BootMemRegion { base_pa: 0, len: 4096, kind: BootMemKind::Usable }];
        let info = BootInfo {
            memmap_count: 1,
            memmap_ptr: r.as_ptr(),
            seed: [0; 32],
            boot_ns: 0,
            rsdp_pa: 0,
            hhdm_offset: 0,
            smp_info_array: 0,
            smp_count: 0,
            bsp_lapic_id: 0,
            _pad: 0,
        };
        // SAFETY: hosted test; r outlives the call.
        assert_eq!(unsafe { init_from_boot_info(&info).err() }, Some(SetupError::NoHhdm));
    }
