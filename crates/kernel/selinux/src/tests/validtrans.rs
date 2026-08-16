// Validate-transition, which reads the class's SECOND constraint list.
//
// The list is unreachable from anywhere else in the engine, so if this entry
// point does not evaluate it, nothing does — and the interface that asks the
// question answers "permitted" to every relabel the policy forbids.

use crate::services::fixture::*;

use crate::context::{Context, ValidContext};
use crate::mapping::Mapping;
use crate::policydb::Policydb;
use crate::policydb::constraints::{Constraint, Expr, CEXPR_ATTR, CEXPR_EQ, CEXPR_TYPE};
use crate::services::validtrans::validate_transition;
use crate::sidtab::{Sid, Sidtab};
use crate::uapi::classmap::class_by_name;
use crate::Error;
use alloc::vec;
use alloc::vec::Vec;

fn kcls(name: &str) -> u16 { class_by_name(name).expect("kernel class") }

fn sid(sidtab: &mut Sidtab, c: ValidContext) -> Sid {
    sidtab.context_to_sid(Context::Valid(c)).expect("sid")
}

/// A constraint over the source and target USER components, which the fixture
/// gives distinct values so a comparison cannot pass by coincidence.
fn user_equality_constraint() -> Constraint {
    Constraint {
        permissions: u32::MAX,
        expr: vec![Expr { expr_type: CEXPR_ATTR, attr: crate::policydb::constraints::CEXPR_USER,
                          op: CEXPR_EQ, names: Default::default(), type_names: None }],
    }
}

/// A constraint that does not hold for the pairs these tests use: it demands
/// the two labels share a type, and every pair here deliberately differs.
fn type_equality_constraint() -> Constraint {
    Constraint {
        permissions: u32::MAX,
        expr: vec![Expr { expr_type: CEXPR_ATTR, attr: CEXPR_TYPE, op: CEXPR_EQ,
                          names: Default::default(), type_names: None }],
    }
}

struct Env { db: Policydb, map: Mapping, sidtab: Sidtab }

fn env(validtrans: Vec<Constraint>) -> Env {
    let mut db = policy();
    let class = db.symbols.classes.get_mut(CLS_FILE as usize - 1).expect("file class");
    class.validatetrans = validtrans;
    let map = Mapping::build(&db).expect("mapping");
    let mut sidtab = Sidtab::new();
    crate::services::load_initial_sids(&db, &mut sidtab).expect("initial sids");
    Env { db, map, sidtab }
}

/// Old label, new label, and the task requesting the move.
fn three(e: &mut Env, old: ValidContext, new: ValidContext, task: ValidContext)
    -> (Sid, Sid, Sid)
{
    (sid(&mut e.sidtab, old), sid(&mut e.sidtab, new), sid(&mut e.sidtab, task))
}

fn file(user: u32, ty: u32) -> ValidContext { ctx(user, R_OBJECT, ty, S0, &[]) }
fn task(user: u32) -> ValidContext { ctx(user, R_SYSTEM, T_INIT, S0, &[]) }

#[test]
fn a_class_with_no_validate_constraints_permits_every_move() {
    let mut e = env(Vec::new());
    let (old, new, t) = three(&mut e, file(U_SYSTEM, T_FILE), file(U_USER, T_ETC),
                              task(U_SYSTEM));
    assert_eq!(validate_transition(&e.db, &e.map, &e.sidtab, old, new, t, kcls("file")),
               Ok(()));
}

#[test]
fn a_constraint_that_holds_permits_the_move() {
    let mut e = env(vec![user_equality_constraint()]);
    let (old, new, t) = three(&mut e, file(U_SYSTEM, T_FILE), file(U_SYSTEM, T_ETC),
                              task(U_SYSTEM));
    assert_eq!(validate_transition(&e.db, &e.map, &e.sidtab, old, new, t, kcls("file")),
               Ok(()));
}

#[test]
fn a_constraint_that_fails_refuses_the_move() {
    let mut e = env(vec![user_equality_constraint()]);
    let (old, new, t) = three(&mut e, file(U_SYSTEM, T_FILE), file(U_USER, T_ETC),
                              task(U_SYSTEM));
    assert_eq!(validate_transition(&e.db, &e.map, &e.sidtab, old, new, t, kcls("file")),
               Err(Error::InvalidContext),
               "the second constraint list is the only thing guarding a relabel");
}

#[test]
fn every_constraint_must_hold_not_merely_one() {
    let mut e = env(vec![user_equality_constraint(), type_equality_constraint()]);
    let (old, new, t) = three(&mut e, file(U_SYSTEM, T_FILE), file(U_SYSTEM, T_ETC),
                              task(U_SYSTEM));
    assert!(validate_transition(&e.db, &e.map, &e.sidtab, old, new, t, kcls("file")).is_err(),
            "a satisfied constraint must not excuse an unsatisfied one");
}

#[test]
fn the_permission_guard_of_a_validate_constraint_is_not_consulted() {
    // A validate-transition constraint guards the MOVE, not a permission, so
    // its permission mask is irrelevant here; a zero mask must not make it
    // silently inapplicable.
    let mut c = user_equality_constraint();
    c.permissions = 0;
    let mut e = env(vec![c]);
    let (old, new, t) = three(&mut e, file(U_SYSTEM, T_FILE), file(U_USER, T_ETC),
                              task(U_SYSTEM));
    assert!(validate_transition(&e.db, &e.map, &e.sidtab, old, new, t, kcls("file")).is_err());
}

#[test]
fn an_unknown_sid_is_refused_rather_than_treated_as_permitted() {
    let mut e = env(vec![user_equality_constraint()]);
    let (old, new, t) = three(&mut e, file(U_SYSTEM, T_FILE), file(U_SYSTEM, T_ETC),
                              task(U_SYSTEM));
    let absent: Sid = 100_000;
    for triple in [(absent, new, t), (old, absent, t), (old, new, absent)] {
        assert_eq!(validate_transition(&e.db, &e.map, &e.sidtab,
                                       triple.0, triple.1, triple.2, kcls("file")),
                   Err(Error::UnknownSid));
    }
}

#[test]
fn an_unmapped_label_is_refused_rather_than_compared_as_absent() {
    let mut e = env(vec![user_equality_constraint()]);
    let (old, _, t) = three(&mut e, file(U_SYSTEM, T_FILE), file(U_SYSTEM, T_ETC),
                            task(U_SYSTEM));
    let unmapped = e.sidtab
        .context_to_sid(Context::Unmapped(alloc::string::String::from("who:knows:what:s0")))
        .expect("unmapped sid");
    assert_eq!(validate_transition(&e.db, &e.map, &e.sidtab, old, unmapped, t, kcls("file")),
               Err(Error::InvalidContext),
               "a label with no components cannot satisfy a constraint about them");
}

#[test]
fn a_class_the_policy_does_not_define_is_refused() {
    let mut e = env(vec![user_equality_constraint()]);
    let (old, new, t) = three(&mut e, file(U_SYSTEM, T_FILE), file(U_SYSTEM, T_ETC),
                              task(U_SYSTEM));
    // The fixture defines process, file and dir only.
    let absent_class = kcls("io_uring");
    assert!(validate_transition(&e.db, &e.map, &e.sidtab, old, new, t, absent_class).is_err());
}

#[test]
fn the_task_context_is_the_third_operand_and_reaches_the_expression() {
    // A constraint naming the third context must see the TASK, not the target.
    let mut c = user_equality_constraint();
    c.expr[0].attr = crate::policydb::constraints::CEXPR_USER
        | crate::policydb::constraints::CEXPR_XTARGET;
    c.expr[0].expr_type = crate::policydb::constraints::CEXPR_NAMES;
    let mut names = crate::ebitmap::Ebitmap::new();
    names.set(U_SYSTEM - 1, true);
    c.expr[0].names = names;
    let mut e = env(vec![c]);

    let (old, new, sys_task) = three(&mut e, file(U_SYSTEM, T_FILE), file(U_USER, T_ETC),
                                     task(U_SYSTEM));
    assert_eq!(validate_transition(&e.db, &e.map, &e.sidtab, old, new, sys_task, kcls("file")),
               Ok(()), "the system task is named by the set");

    let user_task = sid(&mut e.sidtab, task(U_USER));
    assert!(validate_transition(&e.db, &e.map, &e.sidtab, old, new, user_task,
                                kcls("file")).is_err(),
            "a different task must reach a different answer, or the operand is ignored");
}
