use alloc::vec;
use alloc::vec::Vec;

use crate::flags::*;
use crate::fsmagic;
use crate::policy::matcher::{match_policy, match_rule, LsmProps, Request};
use crate::policy::parse::parse_rule;
use crate::policy::rule::Rule;
use crate::uapi::Hook;

fn rules(lines: &[&str]) -> Vec<Rule> {
    lines.iter().map(|l| parse_rule(l).unwrap_or_else(|e| panic!("{l}: {e:?}"))).collect()
}

fn exec_req() -> Request<'static> {
    let mut r = Request::new(Hook::BprmCheck, MAY_EXEC);
    r.fsmagic = fsmagic::EXT4;
    r.fsname = "ext4";
    r
}

// A rule that parses but cannot match is the defect this file exists to catch:
// every condition below is asserted to MATCH a request it must match, not
// merely to have parsed.

#[test]
fn a_hook_and_mask_rule_matches_the_hook_it_names() {
    let r = &rules(&["measure func=BPRM_CHECK mask=MAY_EXEC"])[0];
    assert!(match_rule(r, &exec_req()));
    // ...and only that hook and that exact mask.
    let mut other = exec_req();
    other.func = Hook::FileCheck;
    assert!(!match_rule(r, &other));
    let mut wider = exec_req();
    wider.mask = MAY_EXEC | MAY_READ;
    assert!(!match_rule(r, &wider));
}

#[test]
fn an_any_of_mask_rule_matches_a_request_carrying_that_bit() {
    let r = &rules(&["measure func=FILE_CHECK mask=^MAY_READ"])[0];
    let mut req = Request::new(Hook::FileCheck, MAY_READ | MAY_WRITE);
    assert!(match_rule(r, &req));
    req.mask = MAY_WRITE;
    assert!(!match_rule(r, &req));
}

#[test]
fn fsmagic_fsname_subtype_and_uuid_match_their_values() {
    let req = {
        let mut q = Request::new(Hook::FileCheck, MAY_READ);
        q.fsmagic = fsmagic::TMPFS;
        q.fsname = "tmpfs";
        q.fs_subtype = Some("overlay");
        q.fsuuid = [0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78,
                    0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78];
        q
    };
    assert!(match_rule(&rules(&["dont_measure fsmagic=0x1021994"])[0], &req));
    assert!(!match_rule(&rules(&["dont_measure fsmagic=0x9fa0"])[0], &req));
    assert!(match_rule(&rules(&["dont_measure fsname=tmpfs"])[0], &req));
    assert!(!match_rule(&rules(&["dont_measure fsname=ext4"])[0], &req));
    assert!(match_rule(&rules(&["dont_measure fs_subtype=overlay"])[0], &req));
    assert!(!match_rule(&rules(&["dont_measure fs_subtype=fuse"])[0], &req));
    assert!(match_rule(
        &rules(&["dont_measure fsuuid=12345678-1234-5678-9abc-def012345678"])[0], &req));
    assert!(!match_rule(
        &rules(&["dont_measure fsuuid=00000000-1234-5678-9abc-def012345678"])[0], &req));
}

#[test]
fn id_conditions_match_the_right_credential() {
    let mut req = Request::new(Hook::FileCheck, MAY_READ);
    req.uid = 1000; req.euid = 0; req.suid = 0;
    req.gid = 100; req.egid = 0; req.sgid = 0;
    req.inode_uid = 0; req.inode_gid = 42;

    assert!(match_rule(&rules(&["measure func=FILE_CHECK uid=1000"])[0], &req));
    assert!(!match_rule(&rules(&["measure func=FILE_CHECK uid=0"])[0], &req));
    assert!(match_rule(&rules(&["measure func=FILE_CHECK uid>999"])[0], &req));
    assert!(match_rule(&rules(&["measure func=FILE_CHECK uid<1001"])[0], &req));
    assert!(match_rule(&rules(&["measure func=FILE_CHECK euid=0"])[0], &req));
    assert!(match_rule(&rules(&["measure func=FILE_CHECK gid=100"])[0], &req));
    assert!(match_rule(&rules(&["measure func=FILE_CHECK egid=0"])[0], &req));
    assert!(match_rule(&rules(&["measure func=FILE_CHECK fowner=0"])[0], &req));
    assert!(!match_rule(&rules(&["measure func=FILE_CHECK fowner=1"])[0], &req));
    assert!(match_rule(&rules(&["measure func=FILE_CHECK fgroup=42"])[0], &req));
    assert!(match_rule(&rules(&["measure func=FILE_CHECK fgroup<43"])[0], &req));
}

#[test]
fn an_effective_uid_condition_widens_for_a_task_that_may_change_uid() {
    let r = &rules(&["measure func=FILE_CHECK euid=0"])[0];
    let mut req = Request::new(Hook::FileCheck, MAY_READ);
    req.uid = 0; req.euid = 1000; req.suid = 1000;
    // Without the capability only the effective id is considered.
    assert!(!match_rule(r, &req));
    // With it, holding the id in any of the three slots is enough.
    req.cap_setuid = true;
    assert!(match_rule(r, &req));
}

#[test]
fn an_lsm_condition_that_cannot_resolve_does_not_match() {
    let r = &rules(&["dont_measure obj_type=var_log_t"])[0];
    let mut req = Request::new(Hook::FileCheck, MAY_READ);
    // The label resolves and equals the rule's: match.
    req.lsm = LsmProps { obj_type: Some("var_log_t"), ..LsmProps::default() };
    assert!(match_rule(r, &req));
    // A different label: no match.
    req.lsm = LsmProps { obj_type: Some("etc_t"), ..LsmProps::default() };
    assert!(!match_rule(r, &req));
    // No label at all — the rule must NOT match, or it would exclude from
    // measurement a file it was never meant to name.
    req.lsm = LsmProps::default();
    assert!(!match_rule(r, &req));
}

#[test]
fn the_key_hook_matches_on_its_keyring_list_only() {
    let r = &rules(&["measure func=KEY_CHECK keyrings=.ima|.evm"])[0];
    let mut req = Request::new(Hook::KeyCheck, 0);
    req.func_data = Some(".ima");
    assert!(match_rule(r, &req));
    req.func_data = Some(".builtin_trusted_keys");
    assert!(!match_rule(r, &req));
    // A rule with no list matches every keyring.
    let any = &rules(&["measure func=KEY_CHECK"])[0];
    assert!(match_rule(any, &req));
    // And a keyring rule never matches another hook.
    let mut file = Request::new(Hook::FileCheck, MAY_READ);
    file.func_data = Some(".ima");
    assert!(!match_rule(r, &file));
}

#[test]
fn the_critical_data_hook_matches_on_its_label_list() {
    let r = &rules(&["measure func=CRITICAL_DATA label=selinux|kernel"])[0];
    let mut req = Request::new(Hook::CriticalData, 0);
    req.func_data = Some("kernel");
    assert!(match_rule(r, &req));
    req.func_data = Some("other");
    assert!(!match_rule(r, &req));
    req.func_data = None;
    assert!(!match_rule(r, &req));
}

// --- the walk ------------------------------------------------------------

#[test]
fn the_first_matching_rule_decides_an_action() {
    // The exclusion comes first, so nothing on this filesystem is measured
    // even though a later rule would measure it.
    let rs = rules(&["dont_measure fsmagic=0x1021994", "measure func=FILE_CHECK mask=^MAY_READ"]);
    let mut req = Request::new(Hook::FileCheck, MAY_READ);
    req.fsmagic = fsmagic::TMPFS;
    let d = match_policy(&rs, &req, IMA_MEASURE, false);
    assert_eq!(d.action & IMA_MEASURE, 0, "an earlier dont_measure must win");

    // Reversing the order reverses the outcome, which is what makes the
    // ordering load-bearing rather than incidental.
    let rs = rules(&["measure func=FILE_CHECK mask=^MAY_READ", "dont_measure fsmagic=0x1021994"]);
    let d = match_policy(&rs, &req, IMA_MEASURE, false);
    assert_eq!(d.action & IMA_MEASURE, IMA_MEASURE);
}

#[test]
fn actions_are_decided_independently() {
    let rs = rules(&["dont_measure func=FILE_CHECK", "appraise func=FILE_CHECK"]);
    let req = Request::new(Hook::FileCheck, MAY_READ);
    let d = match_policy(&rs, &req, IMA_MEASURE | IMA_APPRAISE, false);
    assert_eq!(d.action & IMA_MEASURE, 0);
    assert_eq!(d.action & IMA_APPRAISE, IMA_APPRAISE);
    assert_eq!(d.action & IMA_FILE_APPRAISE, IMA_FILE_APPRAISE);
}

#[test]
fn a_rule_pcr_selects_the_register_and_the_default_is_used_otherwise() {
    let rs = rules(&["measure func=BPRM_CHECK mask=MAY_EXEC pcr=11"]);
    let d = match_policy(&rs, &exec_req(), IMA_MEASURE, false);
    assert_eq!(d.pcr, Some(11));
    assert_eq!(crate::list::pcr_for(d.pcr), 11);

    let rs = rules(&["measure func=BPRM_CHECK mask=MAY_EXEC"]);
    let d = match_policy(&rs, &exec_req(), IMA_MEASURE, false);
    assert_eq!(d.pcr, None);
    assert_eq!(crate::list::pcr_for(d.pcr), crate::limits::DEFAULT_MEASURE_PCR);
}

#[test]
fn a_rule_template_selects_the_record_format() {
    let rs = rules(&["measure func=BPRM_CHECK mask=MAY_EXEC template=ima-sig"]);
    let d = match_policy(&rs, &exec_req(), IMA_MEASURE, false);
    assert_eq!(d.template.as_deref(), Some("ima-sig"));
}

#[test]
fn appraisal_subaction_follows_the_hook() {
    for (hook, want) in [
        (Hook::MmapCheck, IMA_MMAP_APPRAISE), (Hook::MmapCheckReqprot, IMA_MMAP_APPRAISE),
        (Hook::BprmCheck, IMA_BPRM_APPRAISE), (Hook::CredsCheck, IMA_CREDS_APPRAISE),
        (Hook::FileCheck, IMA_FILE_APPRAISE), (Hook::ModuleCheck, IMA_READ_APPRAISE),
    ] {
        let line = alloc::format!("appraise func={}", hook.token());
        let rs = rules(&[&line]);
        let req = Request::new(hook, 0);
        let d = match_policy(&rs, &req, IMA_APPRAISE, false);
        assert_eq!(d.action & IMA_APPRAISE_SUBMASK, want, "{}", hook.token());
    }
}

#[test]
fn an_appraisal_rule_carries_its_signature_requirement_into_the_decision() {
    let rs = rules(&["appraise func=MODULE_CHECK appraise_type=imasig"]);
    let req = Request::new(Hook::ModuleCheck, 0);
    let d = match_policy(&rs, &req, IMA_APPRAISE, false);
    assert!(d.action & IMA_DIGSIG_REQUIRED != 0);
    assert!(d.action & IMA_CHECK_BLACKLIST != 0);
    // Failing securely is a boot-time choice, not a per-rule one.
    assert_eq!(d.action & IMA_FAIL_UNVERIFIABLE_SIGS, 0);
    let d = match_policy(&rs, &req, IMA_APPRAISE, true);
    assert!(d.action & IMA_FAIL_UNVERIFIABLE_SIGS != 0);
}

#[test]
fn an_appraisal_allowlist_reaches_the_decision() {
    let rs = rules(&["appraise func=FILE_CHECK appraise_algos=sha256"]);
    let req = Request::new(Hook::FileCheck, MAY_READ);
    let d = match_policy(&rs, &req, IMA_APPRAISE, false);
    let bits = d.allowed_algos.expect("allowlist must reach the decision");
    assert!(crate::appraise::algo_allowed(Some(bits), crate::hash::HashAlgo::Sha256));
    assert!(!crate::appraise::algo_allowed(Some(bits), crate::hash::HashAlgo::Sha1));
}

#[test]
fn an_appraisal_supersedes_a_hash_already_decided() {
    // Appraisal computes and checks the digest itself, so a hash action an
    // earlier rule asked for is dropped once an appraisal is decided.
    let rs = rules(&["hash func=FILE_CHECK", "appraise func=FILE_CHECK"]);
    let req = Request::new(Hook::FileCheck, MAY_READ);
    let d = match_policy(&rs, &req, IMA_APPRAISE | IMA_HASH, false);
    assert_eq!(d.action & IMA_HASH, 0);
    assert_eq!(d.action & IMA_APPRAISE, IMA_APPRAISE);
}

#[test]
fn an_empty_policy_decides_nothing() {
    let d = match_policy(&[], &exec_req(), IMA_MEASURE | IMA_APPRAISE, false);
    assert_eq!(d.action, 0);
    assert_eq!(d.pcr, None);
}

#[test]
fn only_the_requested_actions_are_walked() {
    let rs = rules(&["measure func=BPRM_CHECK mask=MAY_EXEC"]);
    let d = match_policy(&rs, &exec_req(), IMA_APPRAISE, false);
    assert_eq!(d.action, 0, "a measure rule must not answer an appraisal question");
}

#[test]
fn measured_pcr_tracking_suppresses_a_repeat_but_not_a_new_register() {
    let m = crate::list::note_measured(0, 10);
    assert!(!crate::list::should_store(m, 10, false));
    assert!(crate::list::should_store(m, 11, false));
    // An appended signature is only available at appraisal time, so its record
    // is stored even when the file was already measured.
    assert!(crate::list::should_store(m, 10, true));
    assert_eq!(vec![m], vec![1u64 << 10]);
}
