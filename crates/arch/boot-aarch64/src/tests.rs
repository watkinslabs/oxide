use super::*;


    #[test]
    fn stub_boot_info_is_empty() {
        // SAFETY: stub_boot_info returns owned BootInfo; static empty slice.
        let info = unsafe { stub_boot_info() };
        assert_eq!(info.memmap_count, 0);
    }
