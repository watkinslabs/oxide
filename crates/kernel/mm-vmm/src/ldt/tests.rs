use super::*;

/// Test shorthand: install, then immediately release the displaced table.
///
/// The REAL caller must converge every CPU between those two steps; that
/// ordering is pinned in `sched::ldt::converge`, which owns it. Here the
/// concern is only what the state itself publishes.
trait InstallOk {
    fn install_ok(&self, entry: u32, desc: u64) -> Result<LdtView, LdtError>;
}

impl InstallOk for LdtState {
    fn install_ok(&self, entry: u32, desc: u64) -> Result<LdtView, LdtError> {
        let swap = self.install(entry, desc)?;
        let v = swap.view();
        swap.release_after_converge();
        Ok(v)
    }
}

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
    s.install_ok(0, 0x00CF_F300_0000_FFFF).expect("install");
    let v = s.view();
    assert!(v.is_loaded());
    assert_ne!(v.base, 0);
    assert_eq!(v.nr_entries, 1);
    assert!(any_ldt_in_use());
}

#[test]
fn the_claimed_entry_count_tracks_the_highest_slot_written() {
    let s = LdtState::new();
    s.install_ok(5, 1).expect("install");
    assert_eq!(s.nr_entries(), 6);
    // Writing a LOWER slot must not shrink the table: the higher entry is
    // still installed and must stay inside the limit.
    s.install_ok(1, 2).expect("install");
    assert_eq!(s.nr_entries(), 6);
    s.install_ok(LDT_ENTRIES - 1, 3).expect("install");
    assert_eq!(s.nr_entries(), LDT_ENTRIES);
}

#[test]
fn the_table_is_sized_to_the_highest_entry_not_to_the_architectural_maximum() {
    // The reference allocates `nr_entries * 8` bytes, not the full 64 KiB.
    let s = LdtState::new();
    s.install_ok(0, 1).expect("install");
    assert_eq!(s.table_bytes(), 8, "a one-entry table must not cost 64 KiB");
    s.install_ok(511, 1).expect("install");
    assert_eq!(s.table_bytes(), 512 * 8);
    assert!(s.table_bytes() < LDT_TABLE_BYTES as u64);
}

#[test]
fn growing_the_table_moves_the_base_and_hands_back_the_old_one() {
    let s = LdtState::new();
    let first = s.install(0, 1).expect("install");
    assert!(!first.displaced_a_table(), "the first install displaces nothing");
    let base0 = first.view().base;
    first.release_after_converge();

    let grow = s.install(100, 2).expect("install");
    assert!(grow.displaced_a_table(), "a grow must hand the old table back to be freed");
    assert_ne!(grow.view().base, base0, "a grow reallocates, as the reference does");
    assert_eq!(grow.view().nr_entries, 101);
    // The old table is still ALIVE here: nothing freed it, which is what
    // lets the caller converge every CPU first.
    grow.release_after_converge();
}

#[test]
fn a_grow_carries_every_previously_installed_descriptor_forward() {
    let s = LdtState::new();
    s.install_ok(0, 0x1111_1111_1111_1111).expect("install");
    s.install_ok(1, 0x2222_2222_2222_2222).expect("install");
    s.install_ok(300, 0x3333_3333_3333_3333).expect("install");
    let mut buf = alloc::vec![0u8; s.table_bytes() as usize];
    s.read_bytes(&mut buf);
    assert_eq!(&buf[0..8], &0x1111_1111_1111_1111u64.to_le_bytes());
    assert_eq!(&buf[8..16], &0x2222_2222_2222_2222u64.to_le_bytes());
    assert_eq!(&buf[2400..2408], &0x3333_3333_3333_3333u64.to_le_bytes());
}

#[test]
fn rewriting_an_existing_entry_does_not_shrink_or_grow_the_table() {
    let s = LdtState::new();
    s.install_ok(10, 1).expect("install");
    let bytes = s.table_bytes();
    let swap = s.install(3, 2).expect("install");
    assert_eq!(s.table_bytes(), bytes, "writing a lower slot must not shrink the limit");
    assert!(swap.displaced_a_table());
    swap.release_after_converge();
}

#[test]
fn the_published_base_and_entry_count_are_always_one_installs_pair() {
    // A view that paired a new base with an old count would program a limit
    // shorter or longer than the table it names.
    let s = LdtState::new();
    for e in [0u32, 7, 63, 511, LDT_ENTRIES - 1] {
        s.install_ok(e, e as u64 + 1).expect("install");
        let v = s.view();
        assert_eq!(v.nr_entries, s.nr_entries());
        assert_ne!(v.base, 0);
        assert_eq!(v.nr_entries as u64 * LDT_ENTRY_SIZE as u64, s.table_bytes());
    }
}

#[test]
fn an_out_of_range_entry_is_refused_without_allocating() {
    let s = LdtState::new();
    assert!(matches!(s.install(LDT_ENTRIES, 1), Err(LdtError::Range)));
    assert!(matches!(s.install(u32::MAX, 1), Err(LdtError::Range)));
    assert_eq!(s.view(), LdtView::NONE);
}

#[test]
fn installed_descriptors_read_back_byte_for_byte() {
    let s = LdtState::new();
    s.install_ok(0, 0x0011_2233_4455_6677).expect("install");
    s.install_ok(2, 0x8899_AABB_CCDD_EEFF).expect("install");
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
    s.install_ok(0, 1).expect("install");
    let g0 = s.view().generation;
    s.install_ok(0, 2).expect("install");
    assert!(s.view().generation > g0, "a rewritten entry must still trigger a reload");
    let g1 = s.view().generation;
    s.install_ok(9, 3).expect("install");
    assert!(s.view().generation > g1);
}

#[test]
fn fork_gives_the_child_a_copy_not_a_share() {
    let parent = LdtState::new();
    parent.install_ok(3, 0xDEAD_BEEF_0000_0001).expect("install");
    let child = parent.dup().expect("dup");
    assert_eq!(child.nr_entries(), parent.nr_entries());
    assert_ne!(child.view().base, parent.view().base, "two mms never share a table");

    let mut before = [0u8; 32];
    child.read_bytes(&mut before);
    let mut want = [0u8; 32];
    parent.read_bytes(&mut want);
    assert_eq!(before, want, "the child starts from the parent's descriptors");

    // Mutating either side must leave the other alone.
    child.install_ok(3, 0).expect("install");
    let mut p = [0u8; 32];
    parent.read_bytes(&mut p);
    assert_eq!(p, want, "the child's write must not reach the parent");
    parent.install_ok(3, 0x1111_2222_3333_4444).expect("install");
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
