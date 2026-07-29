// Hosted tests for `prctl(PR_SET_MM)` field storage, ordering
// validation, and the whole-map apply path (B430). The syscall wrapper
// (cap check + user-memory reads) is kernel-only; these exercise the
// hosted-drivable validation/apply core on a root_pa==0 stub AS.

use super::*;
use address_space::{
    prctl_mm_map_size, validate_mm_map, PrctlMmMap,
    PR_SET_MM_ARG_END, PR_SET_MM_ARG_START, PR_SET_MM_END_CODE, PR_SET_MM_START_CODE,
};

fn valid_map() -> PrctlMmMap {
    PrctlMmMap {
        start_code: 0x1000, end_code: 0x2000,
        start_data: 0x2000, end_data: 0x3000,
        start_brk:  0x3000, brk:      0x4000,
        start_stack: 0x7fff_0000,
        arg_start:  0x5000, arg_end:  0x5100,
        env_start:  0x5100, env_end:  0x5200,
        auxv: 0, auxv_size: 0, exe_fd: -1,
    }
}

#[test]
fn map_size_matches_linux_struct() {
    // struct prctl_mm_map = 11×u64 + u64 ptr + u32 + i32 = 104 bytes.
    assert_eq!(prctl_mm_map_size(), 104);
    assert_eq!(PrctlMmMap::SIZE, 104);
}

#[test]
fn from_bytes_roundtrips() {
    let m = valid_map();
    let mut raw = [0u8; 104];
    let put = |raw: &mut [u8], o: usize, v: u64| raw[o..o + 8].copy_from_slice(&v.to_le_bytes());
    put(&mut raw, 0, m.start_code);  put(&mut raw, 8, m.end_code);
    put(&mut raw, 16, m.start_data); put(&mut raw, 24, m.end_data);
    put(&mut raw, 32, m.start_brk);  put(&mut raw, 40, m.brk);
    put(&mut raw, 48, m.start_stack);
    put(&mut raw, 56, m.arg_start);  put(&mut raw, 64, m.arg_end);
    put(&mut raw, 72, m.env_start);  put(&mut raw, 80, m.env_end);
    put(&mut raw, 88, m.auxv);
    raw[96..100].copy_from_slice(&m.auxv_size.to_le_bytes());
    raw[100..104].copy_from_slice(&m.exe_fd.to_le_bytes());
    assert_eq!(PrctlMmMap::from_bytes(&raw), Some(m));
    // Wrong length rejected.
    assert_eq!(PrctlMmMap::from_bytes(&raw[..103]), None);
}

#[test]
fn apply_map_stores_all_fields() {
    let as_ = AddressSpace::new(0).unwrap();
    let m = valid_map();
    assert!(as_.apply_prctl_mm_map(&m).is_ok());
    assert_eq!(as_.start_code(), 0x1000);
    assert_eq!(as_.end_code(),   0x2000);
    assert_eq!(as_.start_data(), 0x2000);
    assert_eq!(as_.end_data(),   0x3000);
    assert_eq!(as_.start_brk(),  0x3000);
    assert_eq!(as_.brk(),        0x4000);
    assert_eq!(as_.start_stack(), 0x7fff_0000);
    assert_eq!(as_.arg_start(),  0x5000);
    assert_eq!(as_.arg_end(),    0x5100);
    assert_eq!(as_.env_start(),  0x5100);
    assert_eq!(as_.env_end(),    0x5200);
    // A successful apply flips the user-set flag (gates /proc region read).
    assert!(as_.mm_user_set());
}

#[test]
fn single_field_setter_stores_value() {
    let as_ = AddressSpace::new(0).unwrap();
    // Seed code/data so ordering invariants hold for later single sets.
    as_.apply_prctl_mm_map(&valid_map()).unwrap();
    // Widen arg_end first (arg_start=0x5000 <= 0x6200), then move arg_start
    // up within the new bound — each single set re-validates the whole map.
    assert!(as_.prctl_set_field(PR_SET_MM_ARG_END, 0x6200).is_ok());
    assert_eq!(as_.arg_end(), 0x6200);
    assert!(as_.prctl_set_field(PR_SET_MM_ARG_START, 0x6000).is_ok());
    assert_eq!(as_.arg_start(), 0x6000);
}

#[test]
fn empty_data_interval_does_not_block_argv_rewrite() {
    // Linux `validate_prctl_map_addr()` requires `start_data <= end_data`,
    // unlike the strict `start_code < end_code` rule. An executable with an
    // empty data interval must therefore still be able to relabel argv.
    let as_ = AddressSpace::new(0).unwrap();
    let mut m = valid_map();
    m.end_data = m.start_data;
    assert!(as_.apply_prctl_mm_map(&m).is_ok());
    assert!(as_.prctl_set_field(PR_SET_MM_ARG_START, 0x5080).is_ok());
    assert_eq!(as_.arg_start(), 0x5080);
}

#[test]
fn ordering_violation_is_einval() {
    let as_ = AddressSpace::new(0).unwrap();
    let mut m = valid_map();
    m.start_code = 0x9000; // start_code > end_code (0x2000)
    assert!(!validate_mm_map(&m));
    assert!(as_.apply_prctl_mm_map(&m).is_err());
    // arg_start > arg_end likewise rejected.
    let mut m2 = valid_map();
    m2.arg_start = 0x5200; m2.arg_end = 0x5000;
    assert!(as_.apply_prctl_mm_map(&m2).is_err());
}

#[test]
fn user_address_above_split_is_einval() {
    let as_ = AddressSpace::new(0).unwrap();
    as_.apply_prctl_mm_map(&valid_map()).unwrap();
    // >= USER_VA_END (0x0000_8000_0000_0000) must be refused.
    assert!(as_.prctl_set_field(PR_SET_MM_ARG_START, 0x0000_8000_0000_0000).is_err());
    // start_code stays as seeded (nothing committed on the failed set).
    assert_eq!(as_.start_code(), 0x1000);
}

#[test]
fn single_setter_bad_ordering_rejected() {
    let as_ = AddressSpace::new(0).unwrap();
    as_.apply_prctl_mm_map(&valid_map()).unwrap();
    // Set START_CODE above END_CODE (0x2000) → EINVAL, value unchanged.
    assert!(as_.prctl_set_field(PR_SET_MM_START_CODE, 0x2500).is_err());
    assert_eq!(as_.start_code(), 0x1000);
    // Set END_CODE above START_CODE → OK.
    assert!(as_.prctl_set_field(PR_SET_MM_END_CODE, 0x2800).is_ok());
    assert_eq!(as_.end_code(), 0x2800);
}

#[test]
fn fork_copies_mm_layout() {
    let parent = AddressSpace::new(0).unwrap();
    parent.apply_prctl_mm_map(&valid_map()).unwrap();
    parent.set_auxv(alloc::vec![1u8, 2, 3, 4]);
    let child = parent.fork(0).unwrap();
    assert_eq!(child.arg_start(), 0x5000);
    assert_eq!(child.env_end(),   0x5200);
    assert_eq!(child.start_code(), 0x1000);
    assert!(child.mm_user_set());
    assert_eq!(child.auxv(), Some(alloc::vec![1u8, 2, 3, 4]));
}

#[test]
fn auxv_store_roundtrips() {
    let as_ = AddressSpace::new(0).unwrap();
    assert_eq!(as_.auxv(), None);
    as_.set_auxv(alloc::vec![9u8; 32]);
    assert_eq!(as_.auxv(), Some(alloc::vec![9u8; 32]));
}
