// Conditional policy: boolean expressions and the rule lists they gate.
//
// A conditional rule lives in the conditional access-vector table with an
// enabled bit that is recomputed whenever a boolean commits. The decision path
// then consults conditional rules exactly like unconditional ones, honouring
// only the enabled ones. Nothing is added or removed from the table when a
// boolean flips — only the bit — so a stale bit is indistinguishable from a
// policy that really grants the access.

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// Operand is the named boolean's current state.
pub const COND_BOOL: u32 = 1;
/// Logical negation.
pub const COND_NOT: u32 = 2;
/// Disjunction.
pub const COND_OR: u32 = 3;
/// Conjunction.
pub const COND_AND: u32 = 4;
/// Exclusive disjunction.
pub const COND_XOR: u32 = 5;
/// Equality.
pub const COND_EQ: u32 = 6;
/// Inequality.
pub const COND_NEQ: u32 = 7;

/// Maximum operand-stack depth a conditional expression may reach.
pub const COND_EXPR_MAXDEPTH: usize = 10;

/// One node of a postfix boolean expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CondExpr {
    /// Node kind.
    pub expr_type: u32,
    /// 1-based boolean value, for an operand node.
    pub boolean: u32,
}

/// One conditional block: an expression and the rules each outcome enables.
#[derive(Clone, Debug)]
pub struct CondNode {
    /// Current truth value of the expression.
    pub cur_state: bool,
    /// Expression in postfix order.
    pub expr: Vec<CondExpr>,
    /// Conditional-table rule indices enabled when the expression is true.
    pub true_list: Vec<usize>,
    /// Conditional-table rule indices enabled when the expression is false.
    pub false_list: Vec<usize>,
}

/// Evaluate one postfix boolean expression. # C: O(nodes)
///
/// An expression that under- or over-flows its operand stack is not a policy
/// this engine will guess at: it returns `None`, and the caller disables every
/// rule the block gates rather than enabling them on a malformed expression.
pub fn evaluate(expr: &[CondExpr], bool_state: &impl Fn(u32) -> Option<bool>) -> Option<bool> {
    let mut stack: Vec<bool> = Vec::new();
    for node in expr {
        match node.expr_type {
            COND_BOOL => {
                if stack.len() >= COND_EXPR_MAXDEPTH { return None; }
                stack.push(bool_state(node.boolean)?);
            }
            COND_NOT => { let a = stack.pop()?; stack.push(!a); }
            COND_OR => { let (b, a) = (stack.pop()?, stack.pop()?); stack.push(a || b); }
            COND_AND => { let (b, a) = (stack.pop()?, stack.pop()?); stack.push(a && b); }
            COND_XOR => { let (b, a) = (stack.pop()?, stack.pop()?); stack.push(a ^ b); }
            COND_EQ => { let (b, a) = (stack.pop()?, stack.pop()?); stack.push(a == b); }
            COND_NEQ => { let (b, a) = (stack.pop()?, stack.pop()?); stack.push(a != b); }
            _ => return None,
        }
    }
    if stack.len() != 1 { return None; }
    stack.pop()
}

/// Reject an expression whose node kind is not defined. # C: O(1)
pub fn check_expr_type(expr_type: u32) -> Result<()> {
    if (COND_BOOL..=COND_NEQ).contains(&expr_type) { Ok(()) } else { Err(Error::Malformed) }
}
