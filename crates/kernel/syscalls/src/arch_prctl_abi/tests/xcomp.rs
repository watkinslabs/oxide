use crate::arch_prctl_abi::xcomp::*;
use syscall::errno::Errno;

const EINVAL: i64 = -(Errno::Einval.as_i32() as i64);
const ENOTSUP: i64 = -(Errno::Eopnotsupp.as_i32() as i64);

#[test]
fn xfeature_max_is_one_past_the_highest_named_component() {
    // XTILE_CFG(17), XTILE_DATA(18), APX(19) — so XFEATURE_MAX is 20. An
    // off-by-one here reclassifies APX's index from EOPNOTSUPP to EINVAL,
    // which is the difference between "known feature, not available" and
    // "no such feature number".
    assert_eq!(XFEATURE_MAX, 20);
    assert_eq!(XFEATURE_XTILE_CFG, 17);
    assert_eq!(XFEATURE_XTILE_DATA, 18);
    assert_eq!(xcomp_request(19, u64::MAX, 0), Err(ENOTSUP), "APX index is in range");
    assert_eq!(xcomp_request(20, u64::MAX, 0), Err(EINVAL));
}

#[test]
fn xcomp_supported_falls_back_to_x87_sse_without_xsave() {
    assert_eq!(xcomp_supported(false, 0), XFEATURE_MASK_FPSSE);
    assert_eq!(xcomp_supported(false, 0b1110_0111), XFEATURE_MASK_FPSSE,
               "a stale XCR0 must not be reported by an FXSAVE-only kernel");
    // With XSAVE on, the live XCR0 is the answer, always including x87+SSE.
    assert_eq!(xcomp_supported(true, 0b1110_0111), 0b1110_0111);
    assert_eq!(xcomp_supported(true, 0b1110_0100), 0b1110_0111);
}

#[test]
fn xcomp_supported_drops_components_outside_the_user_set() {
    // A supervisor or unimplemented bit that somehow appeared in XCR0 must
    // not be advertised: nothing saves or restores it for user state.
    let pt = 1u64 << 8;      // XFEATURE_PT — supervisor
    let cet_user = 1u64 << 11;
    let lbr = 1u64 << 15;
    assert_eq!(xcomp_supported(true, 0b111 | pt | cet_user | lbr), 0b111);
    // ...while every genuinely user-visible component survives.
    assert_eq!(xcomp_supported(true, XFEATURE_MASK_USER_SUPPORTED),
               XFEATURE_MASK_USER_SUPPORTED);
}

#[test]
fn user_supported_mask_names_exactly_the_documented_components() {
    // FP,SSE,YMM,BNDREGS,BNDCSR,OPMASK,ZMM_Hi256,Hi16_ZMM,PKRU,XTILE*,APX.
    let expect = 0xFFu64 | (1 << 9) | (1 << 17) | (1 << 18) | (1 << 19);
    assert_eq!(XFEATURE_MASK_USER_SUPPORTED, expect);
    // The supervisor components must be absent.
    for sup in [8u32, 10, 11, 12, 13, 14, 15, 16] {
        assert_eq!(XFEATURE_MASK_USER_SUPPORTED & (1 << sup), 0, "component {sup}");
    }
}

#[test]
fn permission_is_support_minus_the_dynamic_components() {
    // The distinction that makes these two sub-codes different questions: on
    // a CPU with AMX, SUPP advertises XTILE_DATA but PERM withholds it until
    // ARCH_REQ_XCOMP_PERM grants it.
    let amx = (1u64 << 17) | (1 << 18);
    let supported = 0b111 | amx;
    assert_eq!(xcomp_permitted(supported, 0), 0b111 | (1 << 17),
               "XTILE_CFG is in the default set; XTILE_DATA is not");
    assert_eq!(xcomp_permitted(supported, XFEATURE_MASK_XTILE_DATA), supported,
               "after a granted request the two masks agree");
}

#[test]
fn permission_equals_support_when_the_cpu_has_no_dynamic_state() {
    // The oxide case: no AMX in XCR0, so PERM and SUPP coincide — but by the
    // rule, not by construction.
    let supported = xcomp_supported(true, 0b1110_0111);
    assert_eq!(xcomp_permitted(supported, 0), supported);
}

#[test]
fn request_out_of_range_is_the_only_einval() {
    for idx in [XFEATURE_MAX, XFEATURE_MAX + 1, u64::MAX] {
        assert_eq!(xcomp_request(idx, u64::MAX, 0), Err(EINVAL));
    }
    // Every in-range index that names no dynamic facility is EOPNOTSUPP,
    // NOT EINVAL and NOT success.
    for idx in 0..XFEATURE_MAX {
        if idx == XFEATURE_XTILE_DATA { continue; }
        assert_eq!(xcomp_request(idx, u64::MAX, 0), Err(ENOTSUP), "idx {idx}");
    }
}

#[test]
fn tiledata_is_the_only_grantable_index_and_asks_for_the_data_bit_alone() {
    // `xstate_prctl_req[XTILE_DATA] = XFEATURE_MASK_XTILE_DATA` — the DATA
    // bit only. Requiring XTILE_CFG in the requested mask would make the
    // grant fail on a CPU that has AMX, since CFG is already permitted by
    // default and is never part of the request.
    assert_eq!(XFEATURE_MASK_XTILE_DATA, 1 << 18);
    let amx = (1u64 << 17) | (1 << 18);
    assert_eq!(xcomp_request(18, amx, 0), Ok(XFEATURE_MASK_XTILE_DATA));
    // Support test is against the REQUESTED mask.
    assert_eq!(xcomp_request(18, 1 << 18, 0), Ok(XFEATURE_MASK_XTILE_DATA));
    assert_eq!(xcomp_request(18, 1 << 17, 0), Err(ENOTSUP), "no XTILE_DATA -> unsupported");
    assert_eq!(xcomp_request(18, 0b1110_0111, 0), Err(ENOTSUP), "no AMX at all");
}

#[test]
fn a_repeated_request_succeeds_without_re_granting() {
    // Linux's lockless quick check returns 0 when the permission already
    // holds, so a second ARCH_REQ_XCOMP_PERM is not an error.
    assert_eq!(xcomp_request(18, 1 << 18, XFEATURE_MASK_XTILE_DATA), Ok(0));
}

#[test]
fn a_granted_request_is_visible_to_the_matching_get() {
    // The grant is CONSUMED: request → the permitted mask grows → the same
    // request now short-circuits.
    let supported = 0b111u64 | (1 << 17) | (1 << 18);
    let mut permitted_extra = 0u64;
    match xcomp_request(18, supported, xcomp_permitted(supported, permitted_extra)) {
        Ok(m) => permitted_extra |= m,
        Err(e) => panic!("expected a grant, got {e}"),
    }
    assert_eq!(permitted_extra, XFEATURE_MASK_XTILE_DATA);
    let perm = xcomp_permitted(supported, permitted_extra);
    assert_eq!(perm & XFEATURE_MASK_XTILE_DATA, XFEATURE_MASK_XTILE_DATA);
    assert_eq!(xcomp_request(18, supported, perm), Ok(0));
}
