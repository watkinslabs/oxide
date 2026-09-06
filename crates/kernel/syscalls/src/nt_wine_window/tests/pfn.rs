use super::*;

#[test]
fn initialize_ignores_upper_ulong_bits_and_preserves_pointers() {
    let clean = [0x7f65_1234_0000, 0x88, 0x7f65_1235_0000, 0x88, 0x7f65_1236_0000, 0x58];
    let mut dirty = clean;
    dirty[1] |= 0xffff_ffff_0000_0000;
    dirty[3] |= 0x1234_5678_0000_0000;
    dirty[5] = 0x7f65_0000_0058;
    assert_eq!(initialize_args(dirty), Some(clean));
}

#[test]
fn initialize_checks_each_normalized_size_boundary_and_alignment() {
    for (index, limit) in [(1, 0x88), (3, 0x88), (5, 0x58)] {
        for size in 0..=limit + 8 {
            let mut args = [0; 6];
            args[index] = 0x7f65_0000_0000 | size;
            assert_eq!(initialize_args(args).is_some(), size <= limit && size % 8 == 0);
        }
    }
}

#[test]
fn zero_ulong_sizes_do_not_probe_null_tables() {
    let args = initialize_args([0, 1 << 32, 0, 2 << 32, 0, 3 << 32]).unwrap();
    assert_eq!(args, [0; 6]);
    assert!(validate_table(args[0], args[1], |_| { assert!(false, "zero size probed memory"); false }));
}

#[test]
fn exact_procedure_table_does_not_read_eighteenth_entry() {
    let mut reads = 0;
    assert!(validate_table(0x1000, CLIENT_PROCS_BYTES, |address| {
        reads += 1;
        address < 0x1088
    }));
    assert_eq!(reads, 17);
    let mut workers = 0;
    assert!(validate_table(0x2000, WORKERS_BYTES, |_| { workers += 1; true }));
    assert_eq!(workers, 11);
}

#[test]
fn table_probe_stops_at_fault_and_address_wrap() {
    let mut reads = 0;
    assert!(!validate_table(0x1000, CLIENT_PROCS_BYTES, |address| { reads += 1; address != 0x1010 }));
    assert_eq!(reads, 3);
    assert!(!validate_table(u64::MAX - 7, 16, |_| true));
}
