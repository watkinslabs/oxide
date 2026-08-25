    use super::*;

    #[test]
    fn unpack_flags_roundtrip_writable_nonexec() {
        // Pack via the walker's `pack_4k_leaf`, unpack here, expect
        // identical bits — confirms the two halves agree on the bit
        // layout.
        use hal::pt_walker::PtWalker;
        let pa = 0xdead_b000_u64;
        let want = PageFlags::READ | PageFlags::WRITE; // EXEC clear → NX set
        let leaf = PtWalkerX86::pack_4k_leaf(pa, want);
        let got = unpack_flags(leaf, false);
        assert_eq!(got, want);
}
    #[test]
    fn unpack_flags_roundtrip_exec_user() {
        use hal::pt_walker::PtWalker;
        let pa = 0xcafe_b000_u64;
        let want = PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC | PageFlags::USER;
        let leaf = PtWalkerX86::pack_4k_leaf(pa, want);
        let got = unpack_flags(leaf, false);
        assert_eq!(got, want);
    }

    #[test]
    fn unpack_flags_roundtrip_pkey() {
        use hal::pt_walker::PtWalker;
        let want = (PageFlags::READ | PageFlags::USER).with_pkey(13);
        assert_eq!(unpack_flags(PtWalkerX86::pack_4k_leaf(0xcafe_b000, want), false), want);
    }
