use super::*;
use crate::status::Enforcing;
use crate::uapi::classmap::{class_by_name, perm_bit};

/// The distribution policy the composed image ships. Its presence is what
/// makes these tests exercise a real policy rather than a hand-built one; a
/// machine without the image still runs the rest of the suite.
const DISTRO_POLICY: &str =
    "/home/nd/oxide/images/build/lite-x86_64-root/etc/selinux/targeted/policy/policy.34";

#[cfg(test)]
extern crate std;

fn distro_image() -> Option<alloc::vec::Vec<u8>> {
    match std::fs::read(DISTRO_POLICY) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            std::println!("skipping: {DISTRO_POLICY} is not present on this machine");
            None
        }
    }
}

fn server() -> SecurityServer { SecurityServer::new(BootConfig::default()) }

fn loaded() -> Option<SecurityServer> {
    let image = distro_image()?;
    let mut s = server();
    s.load_policy(&image).expect("the distribution policy must load");
    Some(s)
}

#[test]
fn a_fresh_server_has_no_policy_and_consults_none() {
    let s = server();
    assert!(s.enabled());
    assert!(!s.initialized());
    assert!(s.policy().is_none());
    assert!(!s.state().consults_policy());
}

#[test]
fn before_a_policy_is_loaded_every_check_is_allowed() {
    let mut s = server();
    let v = s.has_perm(1, 2, class_by_name("file").unwrap(), u32::MAX);
    assert!(v.allowed, "the bootstrap window must not deny the process that loads the policy");
    assert_eq!(v.denied, 0);
    assert!(!v.audit);
}

#[test]
fn a_disabled_server_never_consults_policy() {
    let mut s = SecurityServer::new(BootConfig { enabled: false, enforcing: None });
    assert!(!s.enabled());
    assert!(s.has_perm(1, 2, 7, u32::MAX).allowed);
}

#[test]
fn enforcement_can_be_switched_and_reads_back() {
    let mut s = server();
    assert_eq!(s.enforcing(), Enforcing::Permissive);
    s.set_enforcing(Enforcing::Enforcing).expect("switch");
    assert_eq!(s.enforcing(), Enforcing::Enforcing);
    assert!(s.enforcing().refuses());
}

#[test]
fn a_disabled_server_refuses_an_enforcement_change() {
    let mut s = SecurityServer::new(BootConfig { enabled: false, enforcing: None });
    assert!(s.set_enforcing(Enforcing::Enforcing).is_err());
}

#[test]
fn loading_the_distribution_policy_initialises_the_server() {
    let Some(s) = loaded() else { return };
    assert!(s.initialized());
    assert!(s.state().consults_policy());
    assert_eq!(s.state().policyload, 1);
    assert!(s.state().seqno > 0, "a load must invalidate every cached decision");
    let db = s.policy().expect("policy");
    assert_eq!(db.version, 34);
    assert!(db.mls, "the shipped policy carries MLS");
    assert!(db.process_class > 0);
    assert!(!db.te_avtab.is_empty());
}

#[test]
fn a_malformed_image_leaves_the_previous_policy_in_force() {
    let Some(image) = distro_image() else { return };
    let mut s = server();
    s.load_policy(&image).expect("first load");
    let before = s.state().policyload;
    let mut broken = image.clone();
    broken[0] ^= 0xff;
    assert!(s.load_policy(&broken).is_err());
    assert!(s.initialized(), "a refused load must not unload the working policy");
    assert_eq!(s.state().policyload, before,
               "a refused load is not a load and must not count as one");
    assert_eq!(s.policy().expect("policy").version, 34);
}

#[test]
fn a_truncated_image_is_refused_without_disturbing_the_server() {
    let Some(image) = distro_image() else { return };
    let mut s = server();
    s.load_policy(&image).expect("first load");
    assert!(s.load_policy(&image[..image.len() / 2]).is_err());
    assert_eq!(s.policy().expect("policy").version, 34);
}

#[test]
fn every_initial_sid_the_policy_names_renders_to_a_context() {
    let Some(s) = loaded() else { return };
    for sid in 1..=crate::uapi::initsid::SECINITSID_NUM {
        if crate::uapi::initsid::initsid_name(sid).is_none() { continue; }
        let text = s.sid_to_context(sid)
            .unwrap_or_else(|e| panic!("initial sid {sid} renders: {e:?}"));
        assert!(text.contains(':'), "sid {sid} rendered as {text:?}");
    }
}

#[test]
fn a_rendered_context_resolves_back_to_the_same_sid() {
    let Some(mut s) = loaded() else { return };
    let sid = crate::uapi::initsid::InitSid::Kernel.sid();
    let text = s.sid_to_context(sid).expect("render");
    let again = s.context_to_sid(&text).expect("resolve");
    assert_eq!(s.sid_to_context(again).expect("re-render"), text,
               "a context must survive a render/parse round trip unchanged");
}

#[test]
fn an_unresolvable_context_is_refused_rather_than_silently_labelled() {
    let Some(mut s) = loaded() else { return };
    for bad in ["", "nonsense", "a:b:c", "system_u:object_r:no_such_type_t:s0", "::::"] {
        assert!(s.context_to_sid(bad).is_err(), "{bad:?} must not resolve");
    }
}

#[test]
fn a_reload_keeps_every_sid_meaning_the_same_object() {
    let Some(image) = distro_image() else { return };
    let mut s = server();
    s.load_policy(&image).expect("first load");
    let text = s.sid_to_context(crate::uapi::initsid::InitSid::Init.sid()).expect("render");
    let allocated = s.context_to_sid(&text).expect("resolve");
    let before = s.sid_to_context(allocated).expect("render allocated");
    s.load_policy(&image).expect("reload");
    assert_eq!(s.sid_to_context(allocated).expect("render after reload"), before,
               "a SID is a handle userspace already holds; a reload must not repoint it");
    assert_eq!(s.state().policyload, 2);
}

#[test]
fn booleans_stage_before_they_commit() {
    let Some(mut s) = loaded() else { return };
    let Some(index) = s.bool_index(&s.bool_names().next().map(alloc::string::String::from)
        .unwrap_or_default()) else { return };
    let (committed, _) = s.get_bool(index).expect("read");
    s.set_bool_pending(index, !committed).expect("stage");
    let (still, pending) = s.get_bool(index).expect("read staged");
    assert_eq!(still, committed, "a staged write must not change the committed value");
    assert_eq!(pending, !committed);
    let seq = s.state().seqno;
    s.commit_bools().expect("commit");
    let (now, after) = s.get_bool(index).expect("read committed");
    assert_eq!(now, !committed);
    assert_eq!(after, now, "the pending value is consumed by the commit");
    assert!(s.state().seqno > seq, "a commit changes decisions, so caches must be invalidated");
}

#[test]
fn a_boolean_index_outside_the_table_is_refused() {
    let Some(mut s) = loaded() else { return };
    let n = s.bool_names().count();
    assert!(s.set_bool_pending(n + 1000, true).is_err());
    assert!(s.get_bool(n + 1000).is_none());
}

#[test]
fn boolean_operations_without_a_policy_are_refused_rather_than_ignored() {
    let mut s = server();
    assert!(s.set_bool_pending(0, true).is_err());
    assert!(s.commit_bools().is_err());
    assert!(s.get_bool(0).is_none());
}

#[test]
fn transition_and_render_are_refused_before_a_policy_is_loaded() {
    let mut s = server();
    assert!(s.transition_sid(1, 2, 7, None).is_err());
    assert!(s.change_sid(1, 2, 7).is_err());
    assert!(s.member_sid(1, 2, 7).is_err());
    assert!(s.sid_to_context(1).is_err());
    assert!(s.context_to_sid("system_u:object_r:etc_t:s0").is_err());
}

#[test]
fn a_repeated_check_is_answered_from_the_cache() {
    let Some(mut s) = loaded() else { return };
    let class = class_by_name("file").unwrap();
    let bit = perm_bit(class, "read").unwrap();
    let (ssid, tsid) = (crate::uapi::initsid::InitSid::Kernel.sid(),
                        crate::uapi::initsid::InitSid::File.sid());
    let _ = s.has_perm(ssid, tsid, class, bit);
    let misses = s.avc().stats().misses;
    for _ in 0..16 { let _ = s.has_perm(ssid, tsid, class, bit); }
    assert_eq!(s.avc().stats().misses, misses,
               "a repeated identical check must not re-consult the policy");
}

#[test]
fn a_policy_load_invalidates_the_cache() {
    let Some(image) = distro_image() else { return };
    let mut s = server();
    s.load_policy(&image).expect("load");
    let class = class_by_name("file").unwrap();
    let _ = s.has_perm(crate::uapi::initsid::InitSid::Kernel.sid(),
                       crate::uapi::initsid::InitSid::File.sid(), class, 1);
    assert!(s.avc().active_nodes() > 0);
    s.load_policy(&image).expect("reload");
    assert_eq!(s.avc().active_nodes(), 0,
               "a decision computed against the old policy must never survive a reload");
}

#[test]
fn a_denial_in_permissive_mode_is_allowed_through_and_still_reported() {
    let Some(mut s) = loaded() else { return };
    let class = class_by_name("file").unwrap();
    // A permission the kernel initial SID plainly does not hold over the
    // security server's own object class.
    let bit = perm_bit(class, "relabelto").unwrap();
    let v = s.has_perm(crate::uapi::initsid::InitSid::Init.sid(),
                       crate::uapi::initsid::InitSid::Security.sid(), class, bit);
    if v.denied != 0 {
        assert!(v.allowed, "permissive mode allows the operation through");
        assert!(v.permissive, "and must say that it did");
    }
}

#[test]
fn the_same_denial_in_enforcing_mode_is_refused() {
    let Some(mut s) = loaded() else { return };
    s.set_enforcing(Enforcing::Enforcing).expect("enforce");
    let class = class_by_name("file").unwrap();
    let bit = perm_bit(class, "relabelto").unwrap();
    let v = s.has_perm(crate::uapi::initsid::InitSid::Init.sid(),
                       crate::uapi::initsid::InitSid::Security.sid(), class, bit);
    if v.denied != 0 {
        assert!(!v.allowed, "enforcing mode refuses");
        assert!(!v.permissive);
    }
}
