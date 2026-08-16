// The read-only reports, the compatibility controls, the policy-load node,
// and the relabel-validation node.

use vfs::VfsError;

use crate::fake::FakeOps;
use crate::nodes::caps::read_cap;
use crate::nodes::classes::{class_nodes, value_response, CLASS_DIR};
use crate::nodes::initcon::read_initial_context;
use crate::nodes::load::{read_policy, write_load, PERM_LOAD_POLICY, PERM_READ_POLICY};
use crate::nodes::misc::{read_compat, read_deny_unknown, read_mls, read_policyvers,
                         read_reject_unknown, write_compat, write_validatetrans,
                         PERM_VALIDATE_TRANS};
use crate::nodes::stats::{read_avc_hash_stats, read_cache_stats, read_cache_threshold,
                          read_sidtab_hash_stats, read_status, write_cache_threshold,
                          PERM_SETSECPARAM};
use crate::ops::{PolicyFacts, PolicyOps};

#[test]
fn the_version_is_the_highest_the_engine_reads() {
    let expected = alloc::format!("{}\n", selinux::uapi::version::POLICYDB_VERSION_MAX);
    assert_eq!(read_policyvers(), expected);
}

#[test]
fn the_policy_disposition_reports_read_as_flags() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(read_mls(&ops), "0");
    assert_eq!(read_reject_unknown(&ops), "0");
    assert_eq!(read_deny_unknown(&ops), "0");
    ops.facts = PolicyFacts { loaded: true, mls: true, reject_unknown: true,
                              deny_unknown: true, seqno: 3, policyload: 1, status_seq: 6 };
    assert_eq!(read_mls(&ops), "1");
    assert_eq!(read_reject_unknown(&ops), "1");
    assert_eq!(read_deny_unknown(&ops), "1");
}

#[test]
fn a_capability_reads_as_the_policys_bit() {
    let mut ops = FakeOps::allow_all();
    ops.caps = 1 << 2;
    assert_eq!(read_cap(&ops, 2), "1");
    assert_eq!(read_cap(&ops, 3), "0");
}

#[test]
fn an_initial_context_reads_as_that_sids_context() {
    let ops = FakeOps::allow_all();
    assert_eq!(read_initial_context(&ops, 2), "initial:2");
}

#[test]
fn a_class_publishes_its_value_and_each_permissions_value() {
    let ops = FakeOps::allow_all();
    let class = &ops.classes()[0];
    let nodes = class_nodes(class);
    let paths: alloc::vec::Vec<&str> = nodes.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(paths, alloc::vec![
        alloc::format!("{CLASS_DIR}/file/index").as_str(),
        alloc::format!("{CLASS_DIR}/file/perms/read").as_str(),
        alloc::format!("{CLASS_DIR}/file/perms/write").as_str()]);
    assert_eq!(value_response(class.value), "6");
    assert_eq!(value_response(class.perms[0].value), "2");
}

#[test]
fn the_compatibility_controls_report_one_state_and_accept_a_number() {
    assert_eq!(read_compat(), "0");
    assert_eq!(write_compat(b"1\n").unwrap(), 2);
    assert_eq!(write_compat(b"0").unwrap(), 1);
    assert_eq!(write_compat(b"maybe").err(), Some(VfsError::Einval));
}

#[test]
fn a_policy_arrives_in_one_write_at_offset_zero() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(write_load(&mut ops, 0, b"Policy").unwrap(), 6);
    assert_eq!(ops.image.as_deref(), Some(b"Policy".as_slice()));
    // A caller streaming the image would have each piece parsed as a whole
    // policy, so a write past the start is refused rather than parsed.
    assert_eq!(write_load(&mut ops, 6, b"more").err(), Some(VfsError::Einval));
    assert_eq!(write_load(&mut ops, 0, b"").err(), Some(VfsError::Einval));
}

#[test]
fn a_malformed_image_leaves_the_previous_policy_in_force() {
    let mut ops = FakeOps::allow_all();
    write_load(&mut ops, 0, b"Policy").unwrap();
    assert_eq!(write_load(&mut ops, 0, b"rubbish").err(), Some(VfsError::Einval));
    assert_eq!(ops.image.as_deref(), Some(b"Policy".as_slice()));
}

#[test]
fn a_denied_load_stores_nothing() {
    let mut ops = FakeOps::denying(PERM_LOAD_POLICY);
    assert_eq!(write_load(&mut ops, 0, b"Policy").err(), Some(VfsError::Eacces));
    assert_eq!(ops.image, None);
}

#[test]
fn the_image_reads_back_verbatim_and_only_with_permission() {
    let mut ops = FakeOps::allow_all();
    write_load(&mut ops, 0, b"Policy").unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(read_policy(&mut ops, 0, &mut buf).unwrap(), 4);
    assert_eq!(&buf, b"Poli");
    assert_eq!(read_policy(&mut ops, 4, &mut buf).unwrap(), 2);
    assert_eq!(read_policy(&mut ops, 6, &mut buf).unwrap(), 0);
    let mut denied = FakeOps::denying(PERM_READ_POLICY);
    assert_eq!(read_policy(&mut denied, 0, &mut buf).err(), Some(VfsError::Eacces));
}

#[test]
fn the_statistics_render_from_the_live_counters() {
    let ops = FakeOps::allow_all();
    assert_eq!(read_avc_hash_stats(&ops),
               "entries buckets used_buckets longest_chain\n3 512 2 2\n");
    assert_eq!(read_sidtab_hash_stats(&ops),
               "entries buckets used_buckets longest_chain\n5 128 4 2\n");
    assert_eq!(read_cache_stats(&ops), "lookups misses allocations reclaims frees\n9 4 4 1 2\n");
}

#[test]
fn the_cache_threshold_round_trips_and_is_gated() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(read_cache_threshold(&ops), "0");
    write_cache_threshold(&mut ops, b"512\n").unwrap();
    assert_eq!(read_cache_threshold(&ops), "512");
    assert_eq!(write_cache_threshold(&mut ops, b"lots").err(), Some(VfsError::Einval));
    let mut denied = FakeOps::denying(PERM_SETSECPARAM);
    assert_eq!(write_cache_threshold(&mut denied, b"8").err(), Some(VfsError::Eacces));
    assert_eq!(denied.threshold, 0);
}

#[test]
fn a_relabel_validation_takes_four_fields_and_is_gated() {
    let mut ops = FakeOps::allow_all();
    assert_eq!(write_validatetrans(&mut ops, b"old new 6 task").unwrap(), 14);
    assert_eq!(write_validatetrans(&mut ops, b"old new 6").err(), Some(VfsError::Einval));
    assert_eq!(write_validatetrans(&mut ops, b"bad new 6 task").err(), Some(VfsError::Einval));
    let mut denied = FakeOps::denying(PERM_VALIDATE_TRANS);
    assert_eq!(write_validatetrans(&mut denied, b"old new 6 task").err(),
               Some(VfsError::Eacces));
}

#[test]
fn the_status_page_carries_one_consistent_sample_of_the_state() {
    let mut ops = FakeOps::allow_all();
    ops.enforcing = true;
    // seqno and status_seq are deliberately different values here: the page
    // must carry each in the word the reference puts it in, and this test
    // previously asserted the POLICY sequence in the seqlock word — which is
    // the defect it was meant to catch, encoded as the expectation.
    ops.facts = PolicyFacts { loaded: true, mls: false, reject_unknown: false,
                              deny_unknown: true, seqno: 5, policyload: 2, status_seq: 4 };
    let page = read_status(&ops);
    let field = crate::format::response::STATUS_FIELD_BYTES;
    let word = |i: usize| u32::from_le_bytes(
        page[i * field..(i + 1) * field].try_into().unwrap());
    assert_eq!(word(0), crate::format::response::STATUS_VERSION, "layout version");
    assert_eq!(word(1), 4, "seqlock, not the policy sequence number");
    assert_eq!(word(2), 1, "enforcing");
    assert_eq!(word(3), 5, "policy sequence number, as the reference writes here");
    assert_eq!(word(4), 1, "deny unknown");
}

/// The word userspace spins on must be even for any state the page can be
/// read in. A reader that sees odd concludes the kernel is mid-update and
/// waits — forever, if nothing is going to finish the update.
#[test]
fn the_status_page_never_publishes_an_odd_seqlock() {
    let mut ops = FakeOps::allow_all();
    let field = crate::format::response::STATUS_FIELD_BYTES;
    for updates in 0..8u32 {
        ops.facts = PolicyFacts { loaded: true, mls: false, reject_unknown: false,
                                  deny_unknown: false, seqno: updates, policyload: updates,
                                  status_seq: updates * selinux::status::STATUS_SEQ_PER_UPDATE };
        let page = read_status(&ops);
        let seq = u32::from_le_bytes(page[field..field * 2].try_into().unwrap());
        assert_eq!(seq % 2, 0, "page readable after {updates} update(s) must publish an even seqlock");
    }
}
