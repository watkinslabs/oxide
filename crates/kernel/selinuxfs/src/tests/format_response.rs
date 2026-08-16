// What the read side of each node renders.

use selinux::avc::{AvDecision, CacheStats};
use selinux::sidtab::HashStats;

use crate::format::response::{access_response, avc_hash_stats_response, bool_response,
                              cache_stats_response, policyvers_response,
                              sidtab_hash_stats_response, AV_LEGACY_ALL_ONES};

/// A decision whose four masks are all different, so a field rendered in the
/// wrong slot cannot look right by coincidence.
fn distinct_decision() -> AvDecision {
    AvDecision { allowed: 0x1, auditallow: 0x2, auditdeny: 0x4, seqno: 7, flags: 0x8 }
}

#[test]
fn a_decision_renders_its_six_fields_in_order() {
    assert_eq!(access_response(&distinct_decision()), "1 ffffffff 2 4 7 8");
}

#[test]
fn the_audit_masks_are_not_interchangeable() {
    // Swapping them reports the allow-audit mask as the deny-audit mask, so a
    // caller silently audits the wrong accesses. Each must land in its own
    // slot, which only differing values can show.
    let r = access_response(&distinct_decision());
    let f: alloc::vec::Vec<&str> = r.split(' ').collect();
    assert_eq!(f[2], "2", "auditallow is the third field");
    assert_eq!(f[3], "4", "auditdeny is the fourth field");
}

#[test]
fn the_legacy_field_is_emitted_literally() {
    // The response is positional: dropping the fixed word shifts every later
    // field left and the audit masks are read as the grant.
    let r = access_response(&distinct_decision());
    assert_eq!(r.split(' ').nth(1), Some(AV_LEGACY_ALL_ONES));
    assert_eq!(r.split(' ').count(), 6);
}

#[test]
fn a_decision_renders_its_masks_in_hexadecimal_and_the_sequence_in_decimal() {
    let avd = AvDecision { allowed: 0xff, auditallow: 0x10, auditdeny: 0xabcd,
                           seqno: 16, flags: 0x1 };
    assert_eq!(access_response(&avd), "ff ffffffff 10 abcd 16 1");
}

#[test]
fn a_boolean_reads_as_committed_then_pending() {
    assert_eq!(bool_response(true, false), "1 0");
    assert_eq!(bool_response(false, true), "0 1");
    assert_eq!(bool_response(true, true), "1 1");
}

#[test]
fn the_version_carries_its_terminator() {
    assert_eq!(policyvers_response(35), "35\n");
}

#[test]
fn statistics_name_their_columns_before_their_values() {
    let st = HashStats { entries: 3, buckets: 512, used_buckets: 2, longest_chain: 2 };
    assert_eq!(avc_hash_stats_response(&st),
               "entries buckets used_buckets longest_chain\n3 512 2 2\n");
    assert_eq!(sidtab_hash_stats_response(&st),
               "entries buckets used_buckets longest_chain\n3 512 2 2\n");
    let cs = CacheStats { lookups: 9, misses: 4, allocations: 4, reclaims: 1, frees: 2 };
    assert_eq!(cache_stats_response(&cs),
               "lookups misses allocations reclaims frees\n9 4 4 1 2\n");
}
