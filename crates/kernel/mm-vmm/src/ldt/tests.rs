use super::*;

#[test]
fn a_fresh_state_has_no_table_and_no_view() {
    let s = LdtState::new();
    assert_eq!(s.nr_entries(), 0);
    assert_eq!(s.view(), LdtView::NONE);
    assert!(!s.view().is_loaded());
}

#[test]
fn installing_an_entry_publishes_a_loadable_view() {
    let s = LdtState::new();
    s.install(0, 0x00CF_F300_0000_FFFF).expect("install");
    let v = s.view();
    assert!(v.is_loaded());
    assert_ne!(v.base, 0);
    assert_eq!(v.nr_entries, 1);
    assert!(any_ldt_in_use());
}

#[test]
fn the_claimed_entry_count_tracks_the_highest_slot_written() {
    let s = LdtState::new();
    s.install(5, 1).expect("install");
    assert_eq!(s.nr_entries(), 6);
    // Writing a LOWER slot must not shrink the table: the higher entry is
    // still installed and must stay inside the limit.
    s.install(1, 2).expect("install");
    assert_eq!(s.nr_entries(), 6);
    s.install(LDT_ENTRIES - 1, 3).expect("install");
    assert_eq!(s.nr_entries(), LDT_ENTRIES);
}

#[test]
fn the_base_address_never_moves_once_published() {
    let s = LdtState::new();
    s.install(0, 1).expect("install");
    let base = s.view().base;
    for e in [1u32, 100, 4095, LDT_ENTRIES - 1] {
        s.install(e, e as u64 + 1).expect("install");
        assert_eq!(s.view().base, base, "the table must never be reallocated");
    }
}

#[test]
fn an_out_of_range_entry_is_refused_without_allocating() {
    let s = LdtState::new();
    assert_eq!(s.install(LDT_ENTRIES, 1), Err(LdtError::Range));
    assert_eq!(s.install(u32::MAX, 1), Err(LdtError::Range));
    assert_eq!(s.view(), LdtView::NONE);
}

#[test]
fn installed_descriptors_read_back_byte_for_byte() {
    let s = LdtState::new();
    s.install(0, 0x0011_2233_4455_6677).expect("install");
    s.install(2, 0x8899_AABB_CCDD_EEFF).expect("install");
    let mut buf = [0u8; 24];
    s.read_bytes(&mut buf);
    assert_eq!(&buf[0..8], &0x0011_2233_4455_6677u64.to_le_bytes());
    assert_eq!(&buf[8..16], &[0u8; 8], "an unwritten slot reads back as zeroes");
    assert_eq!(&buf[16..24], &0x8899_AABB_CCDD_EEFFu64.to_le_bytes());
}

#[test]
fn read_bytes_on_a_process_with_no_table_touches_nothing() {
    let s = LdtState::new();
    let mut buf = [0xAAu8; 16];
    s.read_bytes(&mut buf);
    assert_eq!(buf, [0xAAu8; 16]);
}

#[test]
fn the_generation_advances_on_every_install() {
    let s = LdtState::new();
    s.install(0, 1).expect("install");
    let g0 = s.view().generation;
    s.install(0, 2).expect("install");
    assert!(s.view().generation > g0, "a rewritten entry must still trigger a reload");
    let g1 = s.view().generation;
    s.install(9, 3).expect("install");
    assert!(s.view().generation > g1);
}

#[test]
fn fork_gives_the_child_a_copy_not_a_share() {
    let parent = LdtState::new();
    parent.install(3, 0xDEAD_BEEF_0000_0001).expect("install");
    let child = parent.dup().expect("dup");
    assert_eq!(child.nr_entries(), parent.nr_entries());
    assert_ne!(child.view().base, parent.view().base, "two mms never share a table");

    let mut before = [0u8; 32];
    child.read_bytes(&mut before);
    let mut want = [0u8; 32];
    parent.read_bytes(&mut want);
    assert_eq!(before, want, "the child starts from the parent's descriptors");

    // Mutating either side must leave the other alone.
    child.install(3, 0).expect("install");
    let mut p = [0u8; 32];
    parent.read_bytes(&mut p);
    assert_eq!(p, want, "the child's write must not reach the parent");
    parent.install(3, 0x1111_2222_3333_4444).expect("install");
    let mut c = [0u8; 32];
    child.read_bytes(&mut c);
    assert_eq!(&c[24..32], &[0u8; 8], "the parent's write must not reach the child");
}

#[test]
fn forking_a_process_with_no_ldt_allocates_nothing() {
    let parent = LdtState::new();
    let child = parent.dup().expect("dup");
    assert_eq!(child.view(), LdtView::NONE);
    assert_eq!(child.nr_entries(), 0);
}

#[test]
fn the_table_covers_the_whole_architectural_index_space() {
    assert_eq!(LDT_ENTRIES, 8192);
    assert_eq!(LDT_ENTRY_SIZE, 8);
    assert_eq!(LDT_TABLE_BYTES, 65536);
    // The selector index field is 13 bits, so 8192 is the ceiling the
    // hardware imposes, not a policy number.
    assert_eq!(LDT_ENTRIES, 1 << 13);
}
