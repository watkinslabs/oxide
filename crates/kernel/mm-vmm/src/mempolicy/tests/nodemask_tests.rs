// `get_nodes` / `copy_nodes_to_user` (`mm/mempolicy.c:1634..1716`).
//
// The pre-F763 slots never read or wrote a nodemask at all, so every
// assertion here fails against the old shims by construction: they returned 0
// for any nodemask argument.

use crate::mempolicy::nodemask::*;
use crate::mempolicy::uapi::*;
use crate::Error;

/// A reader over a fixed word array; out-of-range words are unreadable
/// (`copy_from_user` failure ⇒ EFAULT).
fn words(v: &[u64]) -> impl FnMut(u64) -> Result<u64, Error> + '_ {
    move |i| v.get(i as usize).copied().ok_or(Error::Fault)
}

#[test]
fn maxnode_is_a_bit_count_plus_one() {
    // maxnode = 1 ⇒ zero bits ⇒ empty mask, and nmask is never touched.
    assert_eq!(get_nodes(true, 1, |_| panic!("must not read")), Ok(NodeMask::EMPTY));
    // maxnode = 2 ⇒ one bit ⇒ node 0 only.
    assert_eq!(get_nodes(true, 2, words(&[0b11])), Ok(NodeMask(0b1)));
    // maxnode = 3 ⇒ two bits.
    assert_eq!(get_nodes(true, 3, words(&[0b111])), Ok(NodeMask(0b11)));
}

#[test]
fn maxnode_zero_underflows_into_the_page_size_ceiling() {
    // `--maxnode` on 0 gives ULONG_MAX, which exceeds PAGE_SIZE*8 ⇒ EINVAL.
    // Only a NULL nmask escapes, because that test comes first.
    assert_eq!(get_nodes(true, 0, words(&[0])), Err(Error::Inval));
    assert_eq!(get_nodes(false, 0, |_| panic!("must not read")), Ok(NodeMask::EMPTY));
}

#[test]
fn a_null_nodemask_is_an_empty_mask_at_any_maxnode() {
    assert_eq!(get_nodes(false, 1024, |_| panic!("must not read")), Ok(NodeMask::EMPTY));
}

#[test]
fn maxnode_above_the_page_ceiling_is_einval() {
    // The ceiling is on `maxnode - 1`, so exactly PAGE_SIZE*8 bits is legal
    // and one more is not.
    let zeros = |_| Ok(0u64);
    assert_eq!(get_nodes(true, MAX_NODEMASK_BITS + 1, zeros), Ok(NodeMask::EMPTY));
    assert_eq!(get_nodes(true, MAX_NODEMASK_BITS + 2, zeros), Err(Error::Inval));
}

#[test]
fn bits_above_maxnode_in_the_last_word_are_masked_off_not_rejected() {
    // maxnode = 5 ⇒ 4 bits kept; the caller's stray bit 7 is discarded, which
    // is why `mbind(MPOL_BIND, mask=0x80|0x1, maxnode=5)` is NOT EINVAL.
    assert_eq!(get_nodes(true, 5, words(&[0b1000_0001])), Ok(NodeMask(0b1)));
}

#[test]
fn a_full_word_request_keeps_every_bit() {
    // maxnode = 65 ⇒ 64 bits ⇒ no masking (`maxnode % BITS_PER_LONG == 0`).
    assert_eq!(get_nodes(true, MAX_NUMNODES + 1, words(&[u64::MAX])), Ok(NodeMask(u64::MAX)));
}

#[test]
fn set_bits_above_max_numnodes_are_einval_and_zero_ones_are_fine() {
    // libnuma routinely passes maxnode = 1024. The overflow words must be
    // all-zero; a set bit up there is EINVAL, not a silent truncation.
    let mut w = [0u64; 16];
    w[0] = 0b1;
    assert_eq!(get_nodes(true, 1024 + 1, words(&w)), Ok(NodeMask(0b1)));
    w[8] = 1 << 3;
    assert_eq!(get_nodes(true, 1024 + 1, words(&w)), Err(Error::Inval));
}

#[test]
fn an_unreadable_overflow_word_is_efault_not_einval() {
    // Only 2 words readable but maxnode names 1024 bits.
    assert_eq!(get_nodes(true, 1024 + 1, words(&[1, 0])), Err(Error::Fault));
}

#[test]
fn an_unreadable_first_word_is_efault() {
    assert_eq!(get_nodes(true, 2, words(&[])), Err(Error::Fault));
}

#[test]
fn copy_out_rounds_the_bit_count_up_to_a_whole_word() {
    // maxnode = 1 ⇒ ALIGN(0, 64)/8 = 0 bytes written.
    assert_eq!(copy_nodes_to_user_plan(1),
               Ok(NodemaskOut { copy_bytes: 0, clear_off: 0, clear_bytes: 0 }));
    // maxnode = 64 ⇒ ALIGN(63, 64)/8 = 8 bytes, exactly nr_node_ids' word.
    assert_eq!(copy_nodes_to_user_plan(MAX_NUMNODES),
               Ok(NodemaskOut { copy_bytes: 8, clear_off: 0, clear_bytes: 0 }));
}

#[test]
fn an_oversized_request_is_zero_filled_past_nr_node_ids() {
    // libnuma's maxnode = 1024 ⇒ 128 bytes expected: 8 real, 120 zeroed.
    assert_eq!(copy_nodes_to_user_plan(1024),
               Ok(NodemaskOut { copy_bytes: 8, clear_off: 8, clear_bytes: 120 }));
}

#[test]
fn a_request_wider_than_a_page_is_einval() {
    // ALIGN(maxnode-1,64)/8 > PAGE_SIZE ⇒ EINVAL (`mm/mempolicy.c:1705`).
    assert_eq!(copy_nodes_to_user_plan(NODEMASK_COPY_MAX_BYTES * 8 + 1),
               Ok(NodemaskOut { copy_bytes: 8, clear_off: 8,
                                clear_bytes: NODEMASK_COPY_MAX_BYTES - 8 }));
    assert_eq!(copy_nodes_to_user_plan(NODEMASK_COPY_MAX_BYTES * 8 + 2), Err(Error::Inval));
}

#[test]
fn relative_nodemask_folds_onto_the_allowed_set() {
    let allowed = NodeMask::single(0);
    // Any non-empty request folds onto the single allowed node.
    assert_eq!(relative_nodemask(NodeMask(0b1010), allowed), allowed);
    assert_eq!(relative_nodemask(NodeMask::EMPTY, allowed), NodeMask::EMPTY);
    // Multi-node shape survives: {0,1} relative to {2,3} is {2,3}.
    assert_eq!(relative_nodemask(NodeMask(0b11), NodeMask(0b1100)), NodeMask(0b1100));
}

#[test]
fn nodes_with_memory_is_exactly_node_zero() {
    assert_eq!(nodes_with_memory(), NodeMask::single(NODE_ID_LOCAL));
    assert_eq!(NR_NODE_IDS, 1);
}
