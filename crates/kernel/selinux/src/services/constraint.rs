// Constraint evaluation: the postfix boolean expressions that remove granted
// permissions, and with them the whole of MLS enforcement.
//
// Two invariants keep this honest. A malformed expression evaluates FALSE, so
// a policy that fails to parse into a well-formed stack machine removes the
// permissions it guards rather than granting them. And every comparison is
// written with the SOURCE operand on the left: `dominates` is not symmetric,
// so a swapped pair grants exactly the reads MLS exists to refuse.

use crate::context::ValidContext;
use crate::mls::Level;
use crate::policydb::Policydb;
use crate::policydb::constraints::{
    Expr, CEXPR_AND, CEXPR_ATTR, CEXPR_DOM, CEXPR_DOMBY, CEXPR_EQ, CEXPR_H1H2, CEXPR_H1L2,
    CEXPR_INCOMP, CEXPR_L1H1, CEXPR_L1H2, CEXPR_L1L2, CEXPR_L2H2, CEXPR_MAXDEPTH, CEXPR_NAMES,
    CEXPR_NEQ, CEXPR_NOT, CEXPR_OR, CEXPR_ROLE, CEXPR_TARGET, CEXPR_TYPE, CEXPR_USER,
    CEXPR_XTARGET,
};

/// Every MLS level-pair selector; a node carrying one of these compares
/// levels rather than symbol values.
const MLS_PAIR_MASK: u32 =
    CEXPR_L1L2 | CEXPR_L1H2 | CEXPR_H1L2 | CEXPR_H1H2 | CEXPR_L1H1 | CEXPR_L2H2;

/// Evaluate one constraint expression. # C: O(nodes)
pub fn constraint_eval(db: &Policydb, expr: &[Expr],
                       scontext: &ValidContext, tcontext: &ValidContext,
                       xcontext: Option<&ValidContext>) -> bool {
    let mut stack = [false; CEXPR_MAXDEPTH];
    let mut sp: usize = 0;

    for e in expr {
        match e.expr_type {
            CEXPR_NOT => {
                if sp < 1 { return false; }
                stack[sp - 1] = !stack[sp - 1];
            }
            CEXPR_AND => {
                if sp < 2 { return false; }
                sp -= 1;
                stack[sp - 1] = stack[sp - 1] && stack[sp];
            }
            CEXPR_OR => {
                if sp < 2 { return false; }
                sp -= 1;
                stack[sp - 1] = stack[sp - 1] || stack[sp];
            }
            CEXPR_ATTR => {
                if sp >= CEXPR_MAXDEPTH { return false; }
                stack[sp] = eval_attr(db, e, scontext, tcontext);
                sp += 1;
            }
            CEXPR_NAMES => {
                if sp >= CEXPR_MAXDEPTH { return false; }
                stack[sp] = eval_names(e, scontext, tcontext, xcontext);
                sp += 1;
            }
            _ => return false,
        }
    }
    sp == 1 && stack[0]
}

/// Compare one component of the source with the same component of the target.
fn eval_attr(db: &Policydb, e: &Expr, s: &ValidContext, t: &ValidContext) -> bool {
    if e.attr & MLS_PAIR_MASK != 0 { return eval_mls(e, s, t); }
    match e.attr {
        CEXPR_USER => eval_value(e.op, s.user, t.user),
        CEXPR_TYPE => eval_value(e.op, s.ty, t.ty),
        CEXPR_ROLE => eval_role(db, e.op, s.role, t.role),
        _ => false,
    }
}

/// Compare the two levels the node's pair flag selects.
fn eval_mls(e: &Expr, s: &ValidContext, t: &ValidContext) -> bool {
    let (l1, l2): (&Level, &Level) = match e.attr & MLS_PAIR_MASK {
        CEXPR_L1L2 => (&s.range.low, &t.range.low),
        CEXPR_L1H2 => (&s.range.low, &t.range.high),
        CEXPR_H1L2 => (&s.range.high, &t.range.low),
        CEXPR_H1H2 => (&s.range.high, &t.range.high),
        CEXPR_L1H1 => (&s.range.low, &s.range.high),
        CEXPR_L2H2 => (&t.range.low, &t.range.high),
        _ => return false,
    };
    match e.op {
        CEXPR_EQ => l1.eq_level(l2),
        CEXPR_NEQ => !l1.eq_level(l2),
        CEXPR_DOM => l1.dominates(l2),
        CEXPR_DOMBY => l2.dominates(l1),
        CEXPR_INCOMP => l1.incomparable(l2),
        _ => false,
    }
}

/// Users and types admit equality only; there is no ordering over them.
fn eval_value(op: u32, v1: u32, v2: u32) -> bool {
    match op {
        CEXPR_EQ => v1 == v2,
        CEXPR_NEQ => v1 != v2,
        _ => false,
    }
}

/// Roles additionally carry a dominance relation of their own.
fn eval_role(db: &Policydb, op: u32, r1: u32, r2: u32) -> bool {
    match op {
        CEXPR_EQ => r1 == r2,
        CEXPR_NEQ => r1 != r2,
        CEXPR_DOM => role_dominates(db, r1, r2),
        CEXPR_DOMBY => role_dominates(db, r2, r1),
        CEXPR_INCOMP => !role_dominates(db, r1, r2) && !role_dominates(db, r2, r1),
        _ => false,
    }
}

fn role_dominates(db: &Policydb, r1: u32, r2: u32) -> bool {
    let Some(bit) = r2.checked_sub(1) else { return false };
    db.symbols.role(r1).is_some_and(|r| r.dominates.get(bit))
}

/// Membership of one context's component in the node's named set.
fn eval_names(e: &Expr, s: &ValidContext, t: &ValidContext,
              x: Option<&ValidContext>) -> bool {
    let c = if e.attr & CEXPR_XTARGET != 0 {
        let Some(x) = x else { return false };
        x
    } else if e.attr & CEXPR_TARGET != 0 { t } else { s };

    let value = if e.attr & CEXPR_USER != 0 { c.user }
        else if e.attr & CEXPR_ROLE != 0 { c.role }
        else if e.attr & CEXPR_TYPE != 0 { c.ty }
        else { return false };
    let Some(bit) = value.checked_sub(1) else { return false };

    let member = match (&e.type_names, e.attr & CEXPR_TYPE != 0) {
        (Some(set), true) => set.types.get(bit) && !set.negset.get(bit),
        _ => e.names.get(bit),
    };
    match e.op {
        CEXPR_EQ => member,
        CEXPR_NEQ => !member,
        _ => false,
    }
}

#[cfg(test)]
#[path = "../tests/constraint.rs"]
mod tests;
