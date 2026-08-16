// Context parsing: what userspace may hand back, and what must be refused.

use crate::services::fixture::*;

use crate::context::Context;
use crate::error::Error;
use crate::services::{context_from_string, string_to_sid};
use crate::sidtab::Sidtab;

#[test]
fn a_plain_context_resolves_every_component() {
    let db = policy();
    let c = context_from_string(&db, "system_u:system_r:init_t:s0").expect("parse");
    assert_eq!((c.user, c.role, c.ty), (U_SYSTEM, R_SYSTEM, T_INIT));
    assert_eq!(c.range, one(S0, &[]));
}

#[test]
fn a_category_run_expands_inclusively() {
    let db = policy();
    let c = context_from_string(&db, "system_u:system_r:init_t:s0:c1.c3").expect("parse");
    assert_eq!(c.range, one(S0, &[1, 2, 3]));
}

#[test]
fn a_category_list_mixes_singles_and_runs() {
    let db = policy();
    let c = context_from_string(&db, "system_u:system_r:init_t:s0:c0,c2.c4").expect("parse");
    assert_eq!(c.range, one(S0, &[0, 2, 3, 4]));
}

#[test]
fn a_dash_separates_the_two_levels() {
    let db = policy();
    let c = context_from_string(&db, "system_u:system_r:init_t:s0:c0-s2:c0,c1").expect("parse");
    assert_eq!(c.range.low, level(S0, &[0]));
    assert_eq!(c.range.high, level(S2, &[0, 1]));
}

#[test]
fn an_unknown_name_is_refused_rather_than_ignored() {
    let db = policy();
    for s in ["nobody_u:system_r:init_t:s0",
              "system_u:nobody_r:init_t:s0",
              "system_u:system_r:nobody_t:s0",
              "system_u:system_r:init_t:s9",
              "system_u:system_r:init_t:s0:c9"] {
        assert_eq!(context_from_string(&db, s), Err(Error::UnknownSymbol), "{s}");
    }
}

#[test]
fn a_malformed_shape_is_refused() {
    let db = policy();
    for s in ["system_u",
              "system_u:system_r",
              "system_u:system_r:init_t",
              "system_u:system_r:init_t:",
              "system_u:system_r:init_t:s0:",
              "system_u:system_r:init_t:s0:,",
              "system_u:system_r:init_t:s0:c3.c1"] {
        assert_eq!(context_from_string(&db, s), Err(Error::Malformed), "{s}");
    }
}

#[test]
fn a_non_mls_policy_refuses_a_level() {
    let mut db = policy();
    db.mls = false;
    assert_eq!(context_from_string(&db, "system_u:system_r:init_t:s0"), Err(Error::Malformed));
    let c = context_from_string(&db, "system_u:system_r:init_t").expect("parse");
    assert_eq!(c.ty, T_INIT);
}

#[test]
fn a_string_becomes_a_stable_sid() {
    let db = policy();
    let mut sidtab = Sidtab::new();
    let a = string_to_sid(&db, &mut sidtab, "system_u:system_r:init_t:s0").expect("sid");
    // The same set spelled as a run and as a pair must not become two SIDs.
    let b = string_to_sid(&db, &mut sidtab, "system_u:system_r:init_t:s0").expect("sid");
    assert_eq!(a, b);
    let c = string_to_sid(&db, &mut sidtab, "system_u:system_r:init_t:s0:c0.c2").expect("sid");
    let d = string_to_sid(&db, &mut sidtab, "system_u:system_r:init_t:s0:c0,c1,c2").expect("sid");
    assert_eq!(c, d);
    assert_ne!(a, c);
    assert!(matches!(sidtab.lookup(a), Some(Context::Valid(_))));
}

#[test]
fn a_context_the_policy_forbids_gets_no_sid() {
    let db = policy();
    let mut sidtab = Sidtab::new();
    // The unprivileged user may not assume the system role.
    let out = string_to_sid(&db, &mut sidtab, "user_u:system_r:init_t:s0");
    assert_eq!(out, Err(Error::InvalidContext));
    // A range outside the user's clearance is refused the same way.
    let out = string_to_sid(&db, &mut sidtab, "user_u:user_r:init_t:s0-s2:c0.c5");
    assert_eq!(out, Err(Error::InvalidContext));
    // An attribute is not a type a context may carry.
    let out = string_to_sid(&db, &mut sidtab, "system_u:system_r:attr_domain:s0");
    assert_eq!(out, Err(Error::InvalidContext));
}

#[test]
fn an_inverted_range_is_refused_by_validation() {
    let db = policy();
    let mut sidtab = Sidtab::new();
    let out = string_to_sid(&db, &mut sidtab, "system_u:system_r:init_t:s2-s0");
    assert_eq!(out, Err(Error::InvalidContext));
}
