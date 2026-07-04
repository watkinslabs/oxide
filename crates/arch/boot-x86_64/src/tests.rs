use super::*;

    use boot_info::BootMemKind;

    #[test]
    fn stub_boot_info_is_empty() {
        // SAFETY: stub_boot_info returns a value owned by the caller;
        // pointed-to slice is &'static empty.
        let info = unsafe { stub_boot_info() };
        assert_eq!(info.memmap_count, 0);
        let _ = BootMemKind::Usable;
    }
