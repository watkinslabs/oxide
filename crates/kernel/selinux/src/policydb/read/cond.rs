// Conditional blocks: the boolean expressions and the two rule lists each
// block gates.
//
// The rules themselves live in one table alongside every other conditional
// rule; a block owns only the indices. Enablement is a bit on the stored rule,
// recomputed from the booleans, so the decision path never has to know a rule
// was conditional at all.

use alloc::vec::Vec;

use crate::avtab::{read_item, Avtab, AVTAB_ENABLED};
use crate::error::{Error, Result};
use crate::policydb::cond::{check_expr_type, evaluate, CondExpr, CondNode, COND_BOOL};
use crate::policydb::Policydb;
use crate::reader::Reader;

use super::ctx::check_value;

/// Read the conditional block list and the rules it gates. # C: O(rules)
pub fn read_list(r: &mut Reader<'_>, version: u32, nbool: u32, te_len: usize)
    -> Result<(Avtab, Vec<CondNode>)>
{
    let ncond = r.u32()?;
    let mut tab = Avtab::with_capacity(te_len as u32);
    let mut nodes: Vec<CondNode> = Vec::new();
    nodes.try_reserve(ncond as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..ncond {
        let [_cur_state, nexpr] = r.u32_array::<2>()?;
        let mut expr: Vec<CondExpr> = Vec::new();
        expr.try_reserve(nexpr as usize).map_err(|_| Error::NoMemory)?;
        for _ in 0..nexpr {
            let [expr_type, boolean] = r.u32_array::<2>()?;
            check_expr_type(expr_type)?;
            if expr_type == COND_BOOL { check_value(boolean, nbool)?; }
            expr.push(CondExpr { expr_type, boolean });
        }
        let true_list = read_rule_list(r, version, &mut tab)?;
        let false_list = read_rule_list(r, version, &mut tab)?;
        // The stored state is recomputed from the booleans below; trusting the
        // image's copy would let a doctored policy enable a block its own
        // expression evaluates false.
        nodes.push(CondNode { cur_state: false, expr, true_list, false_list });
    }
    Ok((tab, nodes))
}

/// Read one gated rule list, inserting its rules and keeping their indices.
fn read_rule_list(r: &mut Reader<'_>, version: u32, tab: &mut Avtab) -> Result<Vec<usize>> {
    let len = r.u32()?;
    let mut out: Vec<usize> = Vec::new();
    if len == 0 { return Ok(out); }
    out.try_reserve(len as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..len {
        read_item(r, version, true, &mut |rule| {
            out.push(tab.len());
            tab.insert(rule);
            Ok(())
        })?;
    }
    Ok(out)
}

/// Recompute every conditional rule's enabled bit from boolean state. # C: O(rules)
///
/// Run after a load and after every boolean commit. The decision path reads the
/// bit and nothing else, so a stale bit is indistinguishable from a policy that
/// really grants the access.
pub fn evaluate_cond_nodes(db: &mut Policydb) {
    for i in 0..db.cond_list.len() {
        let state = {
            let bools = &db.symbols.bools;
            evaluate(&db.cond_list[i].expr, &|value: u32| {
                bools.get(value.checked_sub(1)? as usize).map(|b| b.state)
            })
        };
        // A malformed expression disables both arms rather than guessing.
        let (cur_state, enable_true, enable_false) = match state {
            Some(s) => (s, s, !s),
            None => (false, false, false),
        };
        db.cond_list[i].cur_state = cur_state;
        let (t, f) = (db.cond_list[i].true_list.clone(), db.cond_list[i].false_list.clone());
        set_enabled(&mut db.te_cond_avtab, &t, enable_true);
        set_enabled(&mut db.te_cond_avtab, &f, enable_false);
    }
}

fn set_enabled(tab: &mut Avtab, list: &[usize], enabled: bool) {
    for &i in list {
        if let Some(rule) = tab.rule_mut(i) {
            if enabled { rule.key.specified |= AVTAB_ENABLED; }
            else { rule.key.specified &= !AVTAB_ENABLED; }
        }
    }
}
