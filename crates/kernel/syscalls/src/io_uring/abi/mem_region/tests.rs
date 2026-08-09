// `IORING_REGISTER_MEM_REGION` admission ladder + the registered-wait offset
// check. The ORDER of the descriptor's refusals is contract, not taste, so
// each rung is pinned by a case that also violates a later rung.

use super::*;
use crate::io_uring_abi::enter::REG_WAIT_BYTES as ENTER_REG_WAIT_BYTES;

const PAGE: u64 = 4096;

fn ok_desc() -> RegionDesc {
    RegionDesc { user_addr: 0, size: PAGE, flags: 0, id: 0, mmap_offset: 0, resv: [0; 4] }
}

fn ok_user_desc() -> RegionDesc {
    RegionDesc {
        user_addr: 0x1000_0000, size: 2 * PAGE, flags: IORING_MEM_REGION_TYPE_USER,
        id: 0, mmap_offset: 0, resv: [0; 4],
    }
}

#[test]
fn wire_sizes_match_the_abi_structs() {
    assert_eq!(MEM_REGION_REG_BYTES, 32);
    assert_eq!(REGION_DESC_BYTES, 64);
    // The wait record's size is stated in two modules; a drift between them
    // would move the bound of the offset check away from what enter reads.
    assert_eq!(REG_WAIT_BYTES, ENTER_REG_WAIT_BYTES);
}

#[test]
fn param_region_offset_is_distinct_under_the_mmap_mask() {
    use crate::io_uring_abi::uapi::*;
    let m = IORING_OFF_MMAP_MASK;
    assert_eq!(IORING_MAP_OFF_PARAM_REGION & m, IORING_MAP_OFF_PARAM_REGION);
    for other in [IORING_OFF_SQ_RING, IORING_OFF_CQ_RING, IORING_OFF_SQES, IORING_OFF_PBUF_RING] {
        assert_ne!(IORING_MAP_OFF_PARAM_REGION & m, other & m);
    }
}

#[test]
fn reg_round_trips_its_wire_form() {
    let mut b = [0u8; MEM_REGION_REG_BYTES as usize];
    b[0..8].copy_from_slice(&0xdead_beef_u64.to_le_bytes());
    b[8..16].copy_from_slice(&1u64.to_le_bytes());
    let r = MemRegionReg::from_bytes(&b);
    assert_eq!(r.region_uptr, 0xdead_beef);
    assert_eq!(r.flags, IORING_MEM_REGION_REG_WAIT_ARG);
    assert_eq!(r.resv, [0, 0]);
}

#[test]
fn desc_round_trips_its_wire_form() {
    let d = RegionDesc {
        user_addr: 0x4000, size: 0x2000, flags: IORING_MEM_REGION_TYPE_USER,
        id: 0, mmap_offset: IORING_MAP_OFF_PARAM_REGION, resv: [0; 4],
    };
    assert_eq!(RegionDesc::from_bytes(&d.to_bytes()), d);
}

// --- registration record -------------------------------------------------

#[test]
fn reg_reserved_words_must_be_zero() {
    let r = MemRegionReg { region_uptr: 1, flags: 0, resv: [0, 9] };
    assert_eq!(admit_mem_region_reg(&r, true), Err(Errno::Einval));
}

#[test]
fn reg_rejects_unknown_flags() {
    let r = MemRegionReg { region_uptr: 1, flags: 1 << 4, resv: [0, 0] };
    assert_eq!(admit_mem_region_reg(&r, true), Err(Errno::Einval));
}

#[test]
fn wait_arg_form_is_refused_once_the_ring_is_enabled() {
    let r = MemRegionReg { region_uptr: 1, flags: IORING_MEM_REGION_REG_WAIT_ARG, resv: [0, 0] };
    assert_eq!(admit_mem_region_reg(&r, false), Err(Errno::Einval));
    assert_eq!(admit_mem_region_reg(&r, true), Ok(()));
}

#[test]
fn plain_region_registration_needs_no_disabled_ring() {
    let r = MemRegionReg { region_uptr: 1, flags: 0, resv: [0, 0] };
    assert_eq!(admit_mem_region_reg(&r, false), Ok(()));
}

// --- descriptor ladder ---------------------------------------------------

#[test]
fn kernel_and_user_descriptors_are_admitted() {
    assert_eq!(admit_region_desc(&ok_desc(), PAGE), Ok(()));
    assert_eq!(admit_region_desc(&ok_user_desc(), PAGE), Ok(()));
}

#[test]
fn desc_reserved_words_are_checked_before_everything_else() {
    // Also mistyped, misaligned and zero-sized: the reserved check still wins.
    let d = RegionDesc { user_addr: 1, size: 0, flags: 0xff, id: 7, mmap_offset: 9, resv: [1, 0, 0, 0] };
    assert_eq!(admit_region_desc(&d, PAGE), Err(Errno::Einval));
}

#[test]
fn desc_rejects_unknown_flags() {
    let mut d = ok_desc();
    d.flags = 1 << 3;
    assert_eq!(admit_region_desc(&d, PAGE), Err(Errno::Einval));
}

#[test]
fn type_and_user_addr_must_agree_and_that_is_efault() {
    // User type with no address.
    let mut d = ok_desc();
    d.flags = IORING_MEM_REGION_TYPE_USER;
    assert_eq!(admit_region_desc(&d, PAGE), Err(Errno::Efault));
    // Address with no user type.
    let mut d = ok_desc();
    d.user_addr = 0x2000;
    assert_eq!(admit_region_desc(&d, PAGE), Err(Errno::Efault));
}

#[test]
fn type_mismatch_outranks_the_size_and_id_rules() {
    let mut d = ok_desc();
    d.flags = IORING_MEM_REGION_TYPE_USER; // no user_addr
    d.size = 0;
    d.id = 3;
    d.mmap_offset = PAGE;
    assert_eq!(admit_region_desc(&d, PAGE), Err(Errno::Efault));
}

#[test]
fn zero_size_preset_id_and_preset_mmap_offset_are_einval() {
    for mutate in [
        (|d: &mut RegionDesc| d.size = 0) as fn(&mut RegionDesc),
        |d: &mut RegionDesc| d.id = 1,
        |d: &mut RegionDesc| d.mmap_offset = IORING_MAP_OFF_PARAM_REGION,
    ] {
        let mut d = ok_desc();
        mutate(&mut d);
        assert_eq!(admit_region_desc(&d, PAGE), Err(Errno::Einval));
    }
}

#[test]
fn an_absurd_size_is_e2big_before_its_alignment_is_examined() {
    let mut d = ok_desc();
    // Past the page ceiling AND misaligned: E2BIG is the rung that fires.
    d.size = (MAX_REGION_PAGES + 1) * PAGE + 1;
    assert_eq!(admit_region_desc(&d, PAGE), Err(Errno::E2big));
}

#[test]
fn misaligned_size_or_address_is_einval() {
    let mut d = ok_desc();
    d.size = PAGE + 1;
    assert_eq!(admit_region_desc(&d, PAGE), Err(Errno::Einval));
    let mut d = ok_user_desc();
    d.user_addr += 1;
    assert_eq!(admit_region_desc(&d, PAGE), Err(Errno::Einval));
}

#[test]
fn a_user_range_that_wraps_the_address_space_is_eoverflow() {
    let d = RegionDesc {
        user_addr: u64::MAX - PAGE + 1, size: PAGE, flags: IORING_MEM_REGION_TYPE_USER,
        id: 0, mmap_offset: 0, resv: [0; 4],
    };
    // Aligned, in-range size, correct type — only the wrap is wrong.
    assert_eq!(admit_region_desc(&d, PAGE), Err(Errno::Eoverflow));
}

// --- registered wait offset ----------------------------------------------

#[test]
fn a_ring_with_no_wait_area_faults_every_offset() {
    assert_eq!(ext_arg_reg_offset(0, 0), Err(Errno::Efault));
    assert_eq!(ext_arg_reg_offset(64, 0), Err(Errno::Efault));
}

#[test]
fn wait_offset_must_be_word_aligned() {
    assert_eq!(ext_arg_reg_offset(4, PAGE), Err(Errno::Efault));
    assert_eq!(ext_arg_reg_offset(8, PAGE), Ok(8));
}

#[test]
fn the_whole_record_must_fit_inside_the_area() {
    // Last record that fits in one page.
    assert_eq!(ext_arg_reg_offset(PAGE - REG_WAIT_BYTES, PAGE), Ok(PAGE - REG_WAIT_BYTES));
    // One word further and the record's tail is outside.
    assert_eq!(ext_arg_reg_offset(PAGE - REG_WAIT_BYTES + 8, PAGE), Err(Errno::Efault));
    assert_eq!(ext_arg_reg_offset(PAGE, PAGE), Err(Errno::Efault));
}

#[test]
fn an_offset_that_wraps_when_the_record_is_added_is_efault() {
    assert_eq!(ext_arg_reg_offset(u64::MAX - 7, u64::MAX), Err(Errno::Efault));
}

#[test]
fn the_param_offset_classifies_as_its_own_mmap_region() {
    use crate::io_uring_abi::layout::{mmap_region, MmapRegion};
    assert_eq!(mmap_region(IORING_MAP_OFF_PARAM_REGION), MmapRegion::Param);
    // The low bits below the selector mask name a record inside the region,
    // not a different region.
    assert_eq!(mmap_region(IORING_MAP_OFF_PARAM_REGION + 0x40), MmapRegion::Param);
    assert_ne!(mmap_region(0), MmapRegion::Param);
}

#[test]
fn the_register_ladder_admits_mem_region_and_bounds_its_arguments() {
    use crate::io_uring_abi::register_op::*;
    // One record, non-null pointer.
    assert_eq!(decode(IORING_REGISTER_MEM_REGION, 3, 0x1000, 1).map(|r| r.op),
               Ok(RegisterOp::MemRegion { arg: 0x1000 }));
    assert_eq!(decode(IORING_REGISTER_MEM_REGION, 3, 0, 1).err(), Some(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_MEM_REGION, 3, 0x1000, 0).err(), Some(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_MEM_REGION, 3, 0x1000, 2).err(), Some(Errno::Einval));
    // Not a blind form: without a ring it is an argument error.
    assert_eq!(decode(IORING_REGISTER_MEM_REGION, -1, 0x1000, 1).err(), Some(Errno::Einval));
}
