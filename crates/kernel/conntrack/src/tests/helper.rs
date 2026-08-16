// Helper registration and the attach decision.

extern crate alloc;
use alloc::string::String;
use alloc::vec;

use crate::helper::*;
use crate::limits::EXPECT_MAX_CNT;
use crate::uapi::{IPPROTO_TCP, IPS_HELPER, NFPROTO_IPV4};
use super::tuple::{v4_tcp, v4_udp};

fn ftp() -> Helper {
    Helper { name: String::from("ftp"), l3num: NFPROTO_IPV4, protonum: IPPROTO_TCP,
             port: 21, policies: vec![ExpectPolicy { max_expected: 1, timeout: 300 }] }
}

#[test]
fn registration_rejects_a_duplicate_name() {
    let r = HelperRegistry::new();
    assert!(r.register(ftp()).is_ok());
    assert_eq!(r.register(ftp()), Err(HelperError::Exists));
}

#[test]
fn a_class_budget_above_the_ceiling_is_refused() {
    let r = HelperRegistry::new();
    let bad = Helper { policies: vec![ExpectPolicy { max_expected: EXPECT_MAX_CNT + 1,
                                                     timeout: 300 }], ..ftp() };
    assert_eq!(r.register(bad), Err(HelperError::BadPolicy));
}

#[test]
fn a_helper_claims_its_service_port_not_the_clients() {
    let r = HelperRegistry::new();
    r.register(ftp()).unwrap();
    // Destination 21 is the service.
    assert!(r.find_for(&v4_tcp([10, 0, 0, 1], 49152, [10, 0, 0, 2], 21)).is_some());
    // Source 21 is not: matching it would attach a payload parser to any flow
    // that happens to originate from port 21.
    assert!(r.find_for(&v4_tcp([10, 0, 0, 1], 21, [10, 0, 0, 2], 49152)).is_none());
    assert!(r.find_for(&v4_udp([10, 0, 0, 1], 49152, [10, 0, 0, 2], 21)).is_none());
}

#[test]
fn a_port_of_zero_matches_any_port() {
    let r = HelperRegistry::new();
    r.register(Helper { name: String::from("any"), port: 0, ..ftp() }).unwrap();
    assert!(r.find_for(&v4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 9999)).is_some());
}

#[test]
fn unregister_removes_it() {
    let r = HelperRegistry::new();
    r.register(ftp()).unwrap();
    assert!(r.unregister("ftp"));
    assert!(!r.unregister("ftp"));
    assert!(r.find("ftp").is_none());
}

#[test]
fn a_missing_class_falls_back_to_the_default_budget() {
    let h = ftp();
    assert_eq!(h.policy(0).max_expected, 1);
    assert_eq!(h.policy(2).max_expected, EXPECT_MAX_CNT);
}

#[test]
fn an_explicit_helper_choice_is_never_overridden() {
    // IPS_HELPER means a rule set it deliberately. Automatic port matching
    // must not silently swap it for something else.
    assert_eq!(assign(IPS_HELPER, Some("ftp"), Some("sip")), HelperAssign::Keep);
    assert_eq!(assign(IPS_HELPER, None, Some("sip")), HelperAssign::Keep);
}

#[test]
fn a_template_naming_no_helper_detaches_one() {
    assert_eq!(assign(0, Some("ftp"), None), HelperAssign::Detach);
    assert_eq!(assign(0, None, None), HelperAssign::Keep);
}

#[test]
fn a_template_helper_attaches_when_nothing_is_set() {
    assert_eq!(assign(0, None, Some("ftp")), HelperAssign::Attach(String::from("ftp")));
    // Already holding one: leave it, rather than swapping parsers mid-flow.
    assert_eq!(assign(0, Some("ftp"), Some("sip")), HelperAssign::Keep);
}
