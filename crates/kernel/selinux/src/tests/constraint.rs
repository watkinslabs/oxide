// Constraint evaluation, with every MLS operator checked in both directions.
//
// Each operator has an inverted twin that grants precisely what MLS exists to
// refuse, so every case below is paired: one input that must evaluate true and
// one that must evaluate false. A single-direction test passes just as happily
// against a swapped comparison.

use alloc::vec;
use alloc::vec::Vec;

use crate::services::fixture::*;

use crate::context::ValidContext;
use crate::ebitmap::Ebitmap;
use crate::policydb::constraints::{Expr, TypeSet, CEXPR_AND, CEXPR_ATTR, CEXPR_DOM, CEXPR_DOMBY,
                                   CEXPR_EQ, CEXPR_H1H2, CEXPR_H1L2, CEXPR_INCOMP, CEXPR_L1H1,
                                   CEXPR_L1H2, CEXPR_L1L2, CEXPR_L2H2, CEXPR_NAMES, CEXPR_NEQ,
                                   CEXPR_NOT, CEXPR_OR, CEXPR_ROLE, CEXPR_TARGET, CEXPR_TYPE,
                                   CEXPR_USER, CEXPR_XTARGET};
use crate::policydb::Policydb;
use crate::services::constraint_eval;

/// An expression kind the format does not define.
const CEXPR_BOGUS: u32 = 99;

fn node(expr_type: u32, attr: u32, op: u32) -> Expr {
    Expr { expr_type, attr, op, names: Ebitmap::new(), type_names: None }
}

fn names_node(attr: u32, op: u32, values: &[u32]) -> Expr {
    let mut names = Ebitmap::new();
    for v in values { names.set(v - 1, true); }
    Expr { expr_type: CEXPR_NAMES, attr, op, names, type_names: None }
}

fn attr_node(attr: u32, op: u32) -> Vec<Expr> { vec![node(CEXPR_ATTR, attr, op)] }

fn eval(db: &Policydb, expr: &[Expr], s: &ValidContext, t: &ValidContext) -> bool {
    constraint_eval(db, expr, s, t, None)
}

/// Source and target contexts at the given levels.
fn pair(slow: (u32, &[u32]), tlow: (u32, &[u32])) -> (ValidContext, ValidContext) {
    (ctx(U_SYSTEM, R_SYSTEM, T_INIT, slow.0, slow.1),
     ctx(U_SYSTEM, R_OBJECT, T_FILE, tlow.0, tlow.1))
}

#[test]
fn mls_eq_holds_only_for_identical_levels() {
    let db = policy();
    let expr = attr_node(CEXPR_L1L2, CEXPR_EQ);
    let (s, t) = pair((S0, &[0, 1]), (S0, &[0, 1]));
    assert!(eval(&db, &expr, &s, &t));
    let (s, t) = pair((S0, &[0, 1]), (S0, &[0]));
    assert!(!eval(&db, &expr, &s, &t));
}

#[test]
fn mls_neq_is_the_exact_complement_of_eq() {
    let db = policy();
    let expr = attr_node(CEXPR_L1L2, CEXPR_NEQ);
    let (s, t) = pair((S0, &[0]), (S1, &[0]));
    assert!(eval(&db, &expr, &s, &t));
    let (s, t) = pair((S1, &[0]), (S1, &[0]));
    assert!(!eval(&db, &expr, &s, &t));
}

#[test]
fn mls_dom_is_the_source_dominating_the_target() {
    let db = policy();
    let expr = attr_node(CEXPR_L1L2, CEXPR_DOM);
    // Higher sensitivity and a superset of categories dominates.
    let (s, t) = pair((S2, &[0, 1]), (S0, &[0]));
    assert!(eval(&db, &expr, &s, &t));
    // The reverse pair must NOT satisfy the same node.
    let (s, t) = pair((S0, &[0]), (S2, &[0, 1]));
    assert!(!eval(&db, &expr, &s, &t));
}

#[test]
fn mls_dom_needs_the_categories_and_not_only_the_sensitivity() {
    let db = policy();
    let expr = attr_node(CEXPR_L1L2, CEXPR_DOM);
    // Equal sensitivities, strict subset of categories: no dominance.
    let (s, t) = pair((S1, &[0]), (S1, &[0, 1]));
    assert!(!eval(&db, &expr, &s, &t));
    // Same sensitivities the other way round: the superset dominates.
    let (s, t) = pair((S1, &[0, 1]), (S1, &[0]));
    assert!(eval(&db, &expr, &s, &t));
    // A higher sensitivity does not rescue a missing category.
    let (s, t) = pair((S2, &[0]), (S0, &[0, 1]));
    assert!(!eval(&db, &expr, &s, &t));
}

#[test]
fn mls_domby_is_the_target_dominating_the_source() {
    let db = policy();
    let expr = attr_node(CEXPR_L1L2, CEXPR_DOMBY);
    let (s, t) = pair((S0, &[0]), (S2, &[0, 1]));
    assert!(eval(&db, &expr, &s, &t));
    let (s, t) = pair((S2, &[0, 1]), (S0, &[0]));
    assert!(!eval(&db, &expr, &s, &t));
}

#[test]
fn mls_domby_needs_the_categories_too() {
    let db = policy();
    let expr = attr_node(CEXPR_L1L2, CEXPR_DOMBY);
    let (s, t) = pair((S1, &[0]), (S1, &[0, 1]));
    assert!(eval(&db, &expr, &s, &t));
    let (s, t) = pair((S1, &[0, 1]), (S1, &[0]));
    assert!(!eval(&db, &expr, &s, &t));
}

#[test]
fn mls_incomp_holds_when_neither_side_dominates() {
    let db = policy();
    let expr = attr_node(CEXPR_L1L2, CEXPR_INCOMP);
    // Disjoint category sets: incomparable in both directions.
    let (s, t) = pair((S1, &[0]), (S1, &[1]));
    assert!(eval(&db, &expr, &s, &t));
    // Nested category sets: comparable, so the node is false.
    let (s, t) = pair((S1, &[0, 1]), (S1, &[0]));
    assert!(!eval(&db, &expr, &s, &t));
}

#[test]
fn mls_pair_flags_select_the_levels_they_name() {
    let db = policy();
    let s = ctx_range(U_SYSTEM, R_SYSTEM, T_INIT, level(S0, &[]), level(S2, &[0, 1]));
    let t = ctx_range(U_SYSTEM, R_OBJECT, T_FILE, level(S1, &[0]), level(S1, &[0]));

    // source low vs target low: s0 does not dominate s1.
    assert!(!eval(&db, &attr_node(CEXPR_L1L2, CEXPR_DOM), &s, &t));
    // source high vs target low: s2:c0,c1 does.
    assert!(eval(&db, &attr_node(CEXPR_H1L2, CEXPR_DOM), &s, &t));
    // source low vs target high: still not.
    assert!(!eval(&db, &attr_node(CEXPR_L1H2, CEXPR_DOM), &s, &t));
    // source high vs target high.
    assert!(eval(&db, &attr_node(CEXPR_H1H2, CEXPR_DOM), &s, &t));
    // source high vs source low, within one context.
    assert!(eval(&db, &attr_node(CEXPR_L1H1, CEXPR_DOMBY), &s, &t));
    assert!(!eval(&db, &attr_node(CEXPR_L1H1, CEXPR_DOM), &s, &t));
    // target low vs target high, within the other context.
    assert!(eval(&db, &attr_node(CEXPR_L2H2, CEXPR_EQ), &s, &t));
}

#[test]
fn user_and_type_compare_by_equality_only() {
    let db = policy();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let same = ctx(U_SYSTEM, R_OBJECT, T_INIT, S0, &[]);
    let other = ctx(U_USER, R_OBJECT, T_FILE, S0, &[]);

    assert!(eval(&db, &attr_node(CEXPR_USER, CEXPR_EQ), &s, &same));
    assert!(!eval(&db, &attr_node(CEXPR_USER, CEXPR_EQ), &s, &other));
    assert!(eval(&db, &attr_node(CEXPR_TYPE, CEXPR_EQ), &s, &same));
    assert!(eval(&db, &attr_node(CEXPR_TYPE, CEXPR_NEQ), &s, &other));
    // Dominance is meaningless over users and types.
    assert!(!eval(&db, &attr_node(CEXPR_USER, CEXPR_DOM), &s, &same));
}

#[test]
fn role_dominance_follows_the_role_bitmap() {
    let db = policy();
    let admin = ctx(U_SYSTEM, R_ADMIN, T_INIT, S0, &[]);
    let system = ctx(U_SYSTEM, R_SYSTEM, T_FILE, S0, &[]);
    let user = ctx(U_SYSTEM, R_USER, T_FILE, S0, &[]);

    assert!(eval(&db, &attr_node(CEXPR_ROLE, CEXPR_DOM), &admin, &system));
    assert!(!eval(&db, &attr_node(CEXPR_ROLE, CEXPR_DOM), &system, &admin));
    assert!(eval(&db, &attr_node(CEXPR_ROLE, CEXPR_DOMBY), &system, &admin));
    assert!(!eval(&db, &attr_node(CEXPR_ROLE, CEXPR_DOMBY), &admin, &system));
    // Neither role reaches the other.
    assert!(eval(&db, &attr_node(CEXPR_ROLE, CEXPR_INCOMP), &user, &system));
    assert!(!eval(&db, &attr_node(CEXPR_ROLE, CEXPR_INCOMP), &admin, &system));
}

#[test]
fn names_membership_reads_the_named_side() {
    let db = policy();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_USER, R_OBJECT, T_FILE, S0, &[]);

    let source_users = vec![names_node(CEXPR_USER, CEXPR_EQ, &[U_SYSTEM])];
    assert!(eval(&db, &source_users, &s, &t));
    let target_users = vec![names_node(CEXPR_USER | CEXPR_TARGET, CEXPR_EQ, &[U_SYSTEM])];
    assert!(!eval(&db, &target_users, &s, &t));
    let target_users = vec![names_node(CEXPR_USER | CEXPR_TARGET, CEXPR_EQ, &[U_USER])];
    assert!(eval(&db, &target_users, &s, &t));
    // Non-membership is the operator's complement, not a separate set.
    let not_member = vec![names_node(CEXPR_USER, CEXPR_NEQ, &[U_USER])];
    assert!(eval(&db, &not_member, &s, &t));
}

#[test]
fn names_type_set_subtracts_its_negative_side() {
    let db = policy();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]);

    let mut types = Ebitmap::new();
    types.set(T_INIT - 1, true);
    let mut negset = Ebitmap::new();
    let mut e = names_node(CEXPR_TYPE, CEXPR_EQ, &[]);
    e.type_names = Some(TypeSet { types: types.clone(), negset: negset.clone(), flags: 0 });
    assert!(eval(&db, &[e], &s, &t));

    // The same type named on the negative side is excluded.
    negset.set(T_INIT - 1, true);
    let mut e = names_node(CEXPR_TYPE, CEXPR_EQ, &[]);
    e.type_names = Some(TypeSet { types, negset, flags: 0 });
    assert!(!eval(&db, &[e], &s, &t));
}

#[test]
fn xtarget_names_need_a_third_context() {
    let db = policy();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]);
    let x = ctx(U_USER, R_OBJECT, T_ETC, S0, &[]);
    let expr = vec![names_node(CEXPR_USER | CEXPR_XTARGET, CEXPR_EQ, &[U_USER])];

    assert!(constraint_eval(&db, &expr, &s, &t, Some(&x)));
    // Absent third context: the node is false, never silently the source's.
    assert!(!constraint_eval(&db, &expr, &s, &t, None));
}

#[test]
fn boolean_operators_combine_the_stack() {
    let db = policy();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]);

    let t_node = node(CEXPR_ATTR, CEXPR_USER, CEXPR_EQ);
    let f_node = node(CEXPR_ATTR, CEXPR_TYPE, CEXPR_EQ);

    assert!(!eval(&db, &[t_node.clone(), node(CEXPR_NOT, 0, 0)], &s, &t));
    assert!(eval(&db, &[f_node.clone(), node(CEXPR_NOT, 0, 0)], &s, &t));
    assert!(!eval(&db, &[t_node.clone(), f_node.clone(), node(CEXPR_AND, 0, 0)], &s, &t));
    assert!(eval(&db, &[t_node.clone(), f_node.clone(), node(CEXPR_OR, 0, 0)], &s, &t));
    assert!(!eval(&db, &[f_node.clone(), f_node, node(CEXPR_OR, 0, 0)], &s, &t));
    assert!(eval(&db, &[t_node.clone(), t_node, node(CEXPR_AND, 0, 0)], &s, &t));
}

#[test]
fn malformed_expressions_evaluate_false() {
    let db = policy();
    let s = ctx(U_SYSTEM, R_SYSTEM, T_INIT, S0, &[]);
    let t = ctx(U_SYSTEM, R_OBJECT, T_FILE, S0, &[]);
    let true_node = node(CEXPR_ATTR, CEXPR_USER, CEXPR_EQ);

    // Empty expression: no value on the stack.
    assert!(!eval(&db, &[], &s, &t));
    // Two values left: the expression never combined them.
    assert!(!eval(&db, &[true_node.clone(), true_node.clone()], &s, &t));
    // An operator with nothing under it.
    assert!(!eval(&db, &[node(CEXPR_AND, 0, 0)], &s, &t));
    assert!(!eval(&db, &[node(CEXPR_NOT, 0, 0)], &s, &t));
    // An unknown node kind.
    assert!(!eval(&db, &[node(CEXPR_BOGUS, 0, 0)], &s, &t));
    // An operand pushed past the bounded stack.
    let deep: Vec<Expr> = core::iter::repeat_with(|| true_node.clone()).take(16).collect();
    assert!(!eval(&db, &deep, &s, &t));
    // An unknown operator on a well-formed node.
    assert!(!eval(&db, &attr_node(CEXPR_USER, 0), &s, &t));
}
