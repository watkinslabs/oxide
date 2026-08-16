// Constraints: postfix boolean expressions over the source and target
// contexts that REMOVE permissions the type-enforcement rules granted.
//
// MLS enforcement lives here. There is no separate MLS phase in the decision
// path: a policy expresses "the subject's clearance must dominate the object's
// level" as an ordinary constraint whose operands are the two contexts' MLS
// levels. An expression evaluated the wrong way round therefore grants exactly
// the accesses MLS exists to refuse.

use alloc::vec::Vec;

use crate::ebitmap::Ebitmap;
use crate::error::{Error, Result};
use crate::reader::Reader;
use crate::uapi::version::POLICYDB_VERSION_CONSTRAINT_NAMES;

/// Maximum operand-stack depth an expression may reach.
pub const CEXPR_MAXDEPTH: usize = 5;

/// Logical negation of the top operand.
pub const CEXPR_NOT: u32 = 1;
/// Conjunction of the top two operands.
pub const CEXPR_AND: u32 = 2;
/// Disjunction of the top two operands.
pub const CEXPR_OR: u32 = 3;
/// Comparison between two context attributes.
pub const CEXPR_ATTR: u32 = 4;
/// Membership of a context attribute in a named set.
pub const CEXPR_NAMES: u32 = 5;

/// Operand names the user component.
pub const CEXPR_USER: u32 = 1;
/// Operand names the role component.
pub const CEXPR_ROLE: u32 = 2;
/// Operand names the type component.
pub const CEXPR_TYPE: u32 = 4;
/// Operand names the target context rather than the source.
pub const CEXPR_TARGET: u32 = 8;
/// Operand names the third context of a transition check.
pub const CEXPR_XTARGET: u32 = 16;
/// Compare the source low level with the target low level.
pub const CEXPR_L1L2: u32 = 32;
/// Compare the source low level with the target high level.
pub const CEXPR_L1H2: u32 = 64;
/// Compare the source high level with the target low level.
pub const CEXPR_H1L2: u32 = 128;
/// Compare the source high level with the target high level.
pub const CEXPR_H1H2: u32 = 256;
/// Compare the source low level with the source high level.
pub const CEXPR_L1H1: u32 = 512;
/// Compare the target low level with the target high level.
pub const CEXPR_L2H2: u32 = 1024;

/// Operands are equal.
pub const CEXPR_EQ: u32 = 1;
/// Operands are unequal.
pub const CEXPR_NEQ: u32 = 2;
/// Left operand dominates the right.
pub const CEXPR_DOM: u32 = 3;
/// Left operand is dominated by the right.
pub const CEXPR_DOMBY: u32 = 4;
/// Neither operand dominates the other.
pub const CEXPR_INCOMP: u32 = 5;

/// A named type set, with its complement flag.
#[derive(Clone, Debug, Default)]
pub struct TypeSet {
    /// Types named positively.
    pub types: Ebitmap,
    /// Types named as exclusions.
    pub negset: Ebitmap,
    /// Set-composition flags supplied by the policy compiler.
    pub flags: u32,
}

/// One node of a postfix constraint expression.
#[derive(Clone, Debug)]
pub struct Expr {
    /// Node kind.
    pub expr_type: u32,
    /// Which context component the node names.
    pub attr: u32,
    /// Comparison operator.
    pub op: u32,
    /// Named value set, for a membership node.
    pub names: Ebitmap,
    /// Named type set, present from the version that introduced it.
    pub type_names: Option<TypeSet>,
}

/// One constraint: the permissions it guards and the expression guarding them.
#[derive(Clone, Debug)]
pub struct Constraint {
    /// Permissions removed when the expression evaluates false.
    pub permissions: u32,
    /// Expression in postfix order.
    pub expr: Vec<Expr>,
}

/// Read a constraint list. # C: O(nodes)
///
/// `allow_xtarget` distinguishes the two lists a class carries: ordinary
/// constraints may not name a third context, validatetrans constraints may.
pub fn read_list(r: &mut Reader<'_>, version: u32, ncons: u32, allow_xtarget: bool)
    -> Result<Vec<Constraint>>
{
    let mut out = Vec::new();
    out.try_reserve(ncons as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..ncons {
        let permissions = r.u32()?;
        let nexpr = r.u32()?;
        let mut expr = Vec::new();
        expr.try_reserve(nexpr as usize).map_err(|_| Error::NoMemory)?;
        let mut depth: isize = -1;
        for _ in 0..nexpr {
            let [expr_type, attr, op] = r.u32_array::<3>()?;
            match expr_type {
                CEXPR_NOT => if depth < 0 { return Err(Error::Malformed); },
                CEXPR_AND | CEXPR_OR => {
                    if depth < 1 { return Err(Error::Malformed); }
                    depth -= 1;
                }
                CEXPR_ATTR | CEXPR_NAMES => {
                    if depth == CEXPR_MAXDEPTH as isize - 1 { return Err(Error::Malformed); }
                    depth += 1;
                }
                _ => return Err(Error::Malformed),
            }
            if !allow_xtarget && attr & CEXPR_XTARGET != 0 { return Err(Error::Malformed); }
            let (names, type_names) = if expr_type == CEXPR_NAMES {
                let names = Ebitmap::read(r)?;
                let set = if version >= POLICYDB_VERSION_CONSTRAINT_NAMES {
                    Some(TypeSet {
                        types: Ebitmap::read(r)?,
                        negset: Ebitmap::read(r)?,
                        flags: r.u32()?,
                    })
                } else { None };
                (names, set)
            } else { (Ebitmap::new(), None) };
            expr.push(Expr { expr_type, attr, op, names, type_names });
        }
        if depth != 0 { return Err(Error::Malformed); }
        out.push(Constraint { permissions, expr });
    }
    Ok(out)
}
