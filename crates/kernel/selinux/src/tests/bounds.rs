use crate::context::Context;
use crate::services::bounded_transition;
use crate::services::fixture::*;
use crate::sidtab::Sidtab;

fn sid(tab: &mut Sidtab, ty: u32) -> u32 {
    tab.context_to_sid(Context::Valid(ctx(U_SYSTEM, R_SYSTEM, ty, S0, &[])))
        .expect("fixture sid")
}

#[test]
fn a_child_type_is_bounded_by_its_declared_parent() {
    let db = policy();
    let mut tab = Sidtab::new();
    let parent = sid(&mut tab, T_INIT);
    let child = sid(&mut tab, T_CHILD);
    assert_eq!(bounded_transition(&db, &tab, parent, child), Ok(true));
}

#[test]
fn an_unrelated_type_is_not_a_bounded_transition() {
    let db = policy();
    let mut tab = Sidtab::new();
    let parent = sid(&mut tab, T_INIT);
    let unrelated = sid(&mut tab, T_LONE);
    assert_eq!(bounded_transition(&db, &tab, parent, unrelated), Ok(false));
}

#[test]
fn an_unchanged_type_is_always_bounded() {
    let db = policy();
    let mut tab = Sidtab::new();
    let old = sid(&mut tab, T_INIT);
    let same_type = tab.context_to_sid(Context::Valid(ctx(U_SYSTEM, R_SYSTEM, T_INIT, S1, &[])))
        .expect("same-type sid");
    assert_eq!(bounded_transition(&db, &tab, old, same_type), Ok(true));
}

#[test]
fn a_malformed_bounds_cycle_terminates_as_unbounded() {
    let db = policy();
    let mut tab = Sidtab::new();
    let parent = sid(&mut tab, T_INIT);
    let cycle = sid(&mut tab, T_CYCLE_A);
    assert_eq!(bounded_transition(&db, &tab, parent, cycle), Ok(false));
}
