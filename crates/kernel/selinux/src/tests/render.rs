// Context rendering, and the round trip back through the parser.

use alloc::string::{String, ToString};

use crate::services::fixture::*;

use crate::context::{Context, ValidContext};
use crate::error::Error;
use crate::policydb::Policydb;
use crate::services::{context_from_string, context_to_string, sid_to_context};
use crate::sidtab::Sidtab;

fn render(db: &Policydb, c: &ValidContext) -> String {
    context_to_string(db, &Context::Valid(c.clone())).expect("render")
}

/// Render, parse back, and assert both halves agree.
fn round_trip(db: &Policydb, c: &ValidContext, want: &str) {
    let s = render(db, c);
    assert_eq!(s, want);
    assert_eq!(&context_from_string(db, &s).expect("parse"), c);
}

#[test]
fn a_context_with_no_categories_renders_its_level_alone() {
    let db = policy();
    round_trip(&db, &ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]), "system_u:system_r:init_t:s0");
}

#[test]
fn one_category_renders_as_itself() {
    let db = policy();
    round_trip(&db, &ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[0]),
               "system_u:system_r:init_t:s0:c0");
}

#[test]
fn two_adjacent_categories_render_as_a_pair_not_a_range() {
    let db = policy();
    // A dotted range here would widen nothing today but parses back to the
    // same two members only by luck; the pair form is the ABI.
    round_trip(&db, &ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[0, 1]),
               "system_u:system_r:init_t:s0:c0,c1");
}

#[test]
fn three_adjacent_categories_render_as_a_range() {
    let db = policy();
    round_trip(&db, &ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[0, 1, 2]),
               "system_u:system_r:init_t:s0:c0.c2");
}

#[test]
fn a_mixed_set_renders_run_by_run() {
    let db = policy();
    round_trip(&db, &ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[0, 2, 3, 4]),
               "system_u:system_r:init_t:s0:c0,c2.c4");
}

#[test]
fn unequal_levels_render_both_ends() {
    let db = policy();
    let c = ctx_range(U_SYSTEM, R_SYSTEM, T_INIT, level(S0, &[]), level(S2, &[0, 1, 2, 3, 4, 5]));
    round_trip(&db, &c, "system_u:system_r:init_t:s0-s2:c0.c5");
}

#[test]
fn equal_levels_render_once() {
    let db = policy();
    let c = ctx_range(U_SYSTEM, R_SYSTEM, T_INIT, level(S1, &[1]), level(S1, &[1]));
    round_trip(&db, &c, "system_u:system_r:init_t:s1:c1");
}

#[test]
fn a_non_mls_policy_renders_three_fields() {
    let mut db = policy();
    db.mls = false;
    let c = ValidContext { user: U_SYSTEM, role: R_SYSTEM, ty: T_INIT, ..Default::default() };
    round_trip(&db, &c, "system_u:system_r:init_t");
}

#[test]
fn an_unmapped_context_renders_verbatim() {
    let db = policy();
    let raw = "some_u:some_r:some_t:s9";
    let out = context_to_string(&db, &Context::Unmapped(raw.to_string())).expect("render");
    assert_eq!(out, raw);
}

#[test]
fn a_category_the_policy_does_not_name_renders_by_number() {
    let mut db = policy();
    db.symbols.cats.clear();
    let out = render(&db, &ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[3]));
    assert_eq!(out, "system_u:system_r:init_t:s0:c3");
}

#[test]
fn an_unresolvable_component_is_refused() {
    let db = policy();
    let c = ValidContext { user: 99, ..ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]) };
    assert_eq!(context_to_string(&db, &Context::Valid(c)), Err(Error::UnknownSymbol));
}

#[test]
fn a_sid_renders_the_context_it_names() {
    let db = policy();
    let mut sidtab = Sidtab::new();
    crate::services::load_initial_sids(&db, &mut sidtab).expect("initial sids");
    let out = sid_to_context(&db, &sidtab, crate::uapi::initsid::InitSid::Kernel.sid())
        .expect("render");
    assert_eq!(out, "system_u:system_r:init_t:s0");
}

#[test]
fn every_initial_context_survives_a_round_trip() {
    let db = policy();
    for isid in &db.ocontexts.isids {
        let s = render(&db, &isid.context);
        assert_eq!(context_from_string(&db, &s).expect("parse"), isid.context, "{s}");
    }
}
