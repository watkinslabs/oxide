// Validate-transition: may an object move from one label to another?
//
// A class carries a SECOND constraint list beside the one that guards its
// permissions, and this is the only thing that reads it. Accepting a
// transition without evaluating that list grants exactly the relabels the list
// exists to refuse — and does so silently, because nothing else in the engine
// ever consults it.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::mapping::Mapping;
use crate::policydb::Policydb;
use crate::services::constraint::constraint_eval;
use crate::sidtab::{Sid, Sidtab};

/// Whether an object of `kernel_class` may move from `old_sid` to `new_sid`
/// at the request of a task labelled `task_sid`. # C: O(constraints)
///
/// The task's context is the THIRD operand: a validate-transition constraint
/// is written about the mover as well as the two labels, so evaluating it with
/// only the two would answer a different question.
pub fn validate_transition(db: &Policydb, map: &Mapping, sidtab: &Sidtab,
                           old_sid: Sid, new_sid: Sid, task_sid: Sid, kernel_class: u16)
    -> Result<()>
{
    let policy_class = map.policy_class(kernel_class).ok_or(Error::Malformed)?;
    validate_transition_user(db, sidtab, old_sid, new_sid, task_sid, policy_class)
}

/// Same question for a class named in the POLICY's numbering — what userspace
/// writes to the `validatetrans` node. # C: O(constraints)
pub fn validate_transition_user(db: &Policydb, sidtab: &Sidtab,
                                old_sid: Sid, new_sid: Sid, task_sid: Sid, policy_class: u32)
    -> Result<()>
{
    let class = db.symbols.class(policy_class).ok_or(Error::UnknownSymbol)?;
    if class.validatetrans.is_empty() { return Ok(()); }

    let old = valid_context(sidtab, old_sid)?;
    let new = valid_context(sidtab, new_sid)?;
    let task = valid_context(sidtab, task_sid)?;

    for constraint in &class.validatetrans {
        if !constraint_eval(db, &constraint.expr, old, new, Some(task)) {
            return Err(Error::InvalidContext);
        }
    }
    Ok(())
}

/// Resolve a SID to an interpreted context, refusing an unmapped one.
///
/// A retained-unmapped context has no components to compare, so a constraint
/// cannot be evaluated against it; answering "permitted" there would let a
/// relabel through precisely when the label is one the policy does not know.
fn valid_context(sidtab: &Sidtab, sid: Sid) -> Result<&crate::context::ValidContext> {
    // `lookup` and not the searching form: the searching form substitutes the
    // unlabeled context for an absent SID, which would turn "this handle names
    // nothing" into "this handle names an object with no label" and let a
    // constraint be evaluated against a label nobody set.
    match sidtab.lookup(sid) {
        Some(Context::Valid(c)) => Ok(c),
        Some(Context::Unmapped(_)) => Err(Error::InvalidContext),
        None => Err(Error::UnknownSid),
    }
}

#[cfg(test)]
#[path = "../tests/validtrans.rs"]
mod tests;
