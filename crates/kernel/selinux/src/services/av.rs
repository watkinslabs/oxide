// Access-vector computation: what a subject may do to an object.
//
// The order of the steps below IS the semantics. Everything starts denied and
// fully audited; rules add grants; constraints, the role-transition gate and
// type bounds only ever take grants away. A step moved earlier or later
// changes which accesses survive, so the sequence is fixed:
//
//   deny-all -> resolve -> permissive -> class -> rules -> constraints
//            -> role gate -> bounds -> translate to kernel numbering

use crate::avc::{AvDecision, AVD_FLAGS_NEVERAUDIT, AVD_FLAGS_PERMISSIVE};
use crate::avtab::{Avtab, Key, AVTAB_ALLOWED, AVTAB_AUDITALLOW, AVTAB_AUDITDENY, AVTAB_AV,
                   AVTAB_ENABLED, AVTAB_XPERMS, AVTAB_XPERMS_ALLOWED,
                   AVTAB_XPERMS_AUDITALLOW, AVTAB_XPERMS_DONTAUDIT,
                   AVTAB_XPERMS_IOCTLFUNCTION};
use crate::context::{Context, ValidContext};
use crate::mapping::Mapping;
use crate::policydb::Policydb;
use crate::sidtab::{Sid, Sidtab};

use super::constraint::constraint_eval;

/// Bounding chains longer than this are treated as a cycle and cut.
///
/// A policy is not trusted to be acyclic: a bound that eventually names its
/// own subject would otherwise recurse until the kernel stack ran out.
pub const MAX_BOUNDS_DEPTH: u32 = 4;

/// Every permission granted; the value a permissive domain answers with.
const ALL_PERMS: u32 = u32::MAX;

/// One extended-permission result. `None` means this policy has no xperm rule
/// for the requested driver, so the caller must use the ordinary permission.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct XpermDecision {
    pub selected: bool,
    pub allowed: bool,
    pub auditallow: bool,
    pub auditdeny: bool,
}

/// Accumulated verdict in POLICY bit numbering.
struct Vector {
    allowed: u32,
    auditallow: u32,
    auditdeny: u32,
}

/// Decide what `ssid` may do to `tsid` in one class. # C: O(attrs^2 * bucket)
pub fn compute_av(db: &Policydb, map: &Mapping, sidtab: &Sidtab,
                  ssid: Sid, tsid: Sid, kernel_class: u16, seqno: u32) -> AvDecision {
    let mut avd = AvDecision::init(seqno);
    let Some((scontext, tcontext)) = admit(db, sidtab, ssid, tsid, &mut avd) else { return avd };

    // An unknown class has no rules to consult, so the policy's own stance on
    // classes it does not describe is the whole answer.
    let Some(policy_class) = map.policy_class(kernel_class) else {
        if db.allow_unknown { avd.allowed = ALL_PERMS; }
        return finish_audit(avd);
    };

    let v = compute_vector(db, policy_class, scontext, tcontext, 0);
    avd.allowed = map.to_kernel_av(kernel_class, v.allowed);
    avd.auditallow = map.to_kernel_av(kernel_class, v.auditallow);
    avd.auditdeny = map.to_kernel_av(kernel_class, v.auditdeny);
    finish_audit(avd)
}

/// Same decision for a class named in the POLICY's numbering — what userspace
/// writes to the `access` node. # C: O(attrs^2 * bucket)
///
/// The vectors are answered in POLICY bit numbering too, unmapped: the caller
/// read the permission bit values out of `class/<name>/perms/` and compares
/// against those, so translating into the kernel's numbering would answer a
/// different question. No decision-cache lookup or insert happens here either
/// — that cache is keyed by the kernel's class numbering and a policy value
/// stored under it would be handed back to a kernel caller as its own.
pub fn compute_av_user(db: &Policydb, sidtab: &Sidtab,
                       ssid: Sid, tsid: Sid, policy_class: u32, seqno: u32) -> AvDecision {
    let mut avd = AvDecision::init(seqno);
    let Some((scontext, tcontext)) = admit(db, sidtab, ssid, tsid, &mut avd) else { return avd };

    if db.symbols.class(policy_class).is_none() {
        if db.allow_unknown { avd.allowed = ALL_PERMS; }
        return finish_audit(avd);
    }

    let v = compute_vector(db, policy_class, scontext, tcontext, 0);
    avd.allowed = v.allowed;
    avd.auditallow = v.auditallow;
    avd.auditdeny = v.auditdeny;
    finish_audit(avd)
}

/// Resolve one ioctl/netlink extended permission from the policy's xperm
/// bitmaps. The base permission is deliberately checked by the caller through
/// the normal AVC path; xperms refine that grant, exactly as in Linux.
pub fn compute_xperm(db: &Policydb, map: &Mapping, sidtab: &Sidtab,
                     ssid: Sid, tsid: Sid, kernel_class: u16,
                     driver: u8, xperm: u8, seqno: u32) -> Option<XpermDecision> {
    let (scontext, tcontext) = {
        let mut ignored = AvDecision::init(seqno);
        admit(db, sidtab, ssid, tsid, &mut ignored)?
    };
    let policy_class = map.policy_class(kernel_class)?;
    let (sattrs, tattrs) = (db.type_attrs(scontext.ty)?, db.type_attrs(tcontext.ty)?);
    let mut result = XpermDecision {
        selected: false, allowed: false, auditallow: false, auditdeny: true,
    };
    for source in sattrs.iter() {
        for target in tattrs.iter() {
            let key = Key {
                source_type: (source + 1) as u16,
                target_type: (target + 1) as u16,
                target_class: policy_class as u16,
                specified: AVTAB_XPERMS,
            };
            accumulate_xperm(&db.te_avtab, &key, false, driver, xperm, &mut result);
            accumulate_xperm(&db.te_cond_avtab, &key, true, driver, xperm, &mut result);
        }
    }
    result.selected.then_some(result)
}

/// Resolve both operands and settle the source domain's blanket flags.
///
/// `None` means the answer is already complete: either a SID names nothing, or
/// the domain is both permissive and never-audited, which grants everything
/// without consulting a single rule.
fn admit<'a>(db: &Policydb, sidtab: &'a Sidtab, ssid: Sid, tsid: Sid, avd: &mut AvDecision)
    -> Option<(&'a ValidContext, &'a ValidContext)>
{
    let (Some(scontext), Some(tcontext)) = (valid(sidtab, ssid), valid(sidtab, tsid))
        else { return None };

    if db.type_is_permissive(scontext.ty) { avd.flags |= AVD_FLAGS_PERMISSIVE; }
    if db.type_is_neveraudit(scontext.ty) { avd.flags |= AVD_FLAGS_NEVERAUDIT; }
    if avd.flags & AVD_FLAGS_PERMISSIVE != 0 && avd.flags & AVD_FLAGS_NEVERAUDIT != 0 {
        avd.allowed = ALL_PERMS;
        return None;
    }
    Some((scontext, tcontext))
}

/// A neveraudit domain records nothing, whichever way the decision went.
fn finish_audit(mut avd: AvDecision) -> AvDecision {
    if avd.flags & AVD_FLAGS_NEVERAUDIT != 0 {
        avd.auditallow = 0;
        avd.auditdeny = 0;
    }
    avd
}

fn valid(sidtab: &Sidtab, sid: Sid) -> Option<&ValidContext> {
    sidtab.search(sid).and_then(Context::valid)
}

/// Rule walk, constraints, role gate and bounds, in policy bit numbering.
fn compute_vector(db: &Policydb, policy_class: u32,
                  scontext: &ValidContext, tcontext: &ValidContext, depth: u32) -> Vector {
    let mut v = Vector { allowed: 0, auditallow: 0, auditdeny: ALL_PERMS };

    walk_rules(db, policy_class, scontext.ty, tcontext.ty, &mut v);
    apply_constraints(db, policy_class, scontext, tcontext, &mut v);
    apply_role_gate(db, policy_class, scontext, tcontext, &mut v);
    apply_bounds(db, policy_class, scontext, tcontext, depth, &mut v);
    v
}

/// Walk every rule reachable from the two types' attribute sets.
///
/// A rule is stored against a type OR an attribute, indistinguishably, so the
/// lookup must be over the CROSS PRODUCT of both attribute sets rather than
/// the two concrete types. Iterating only the concrete pair makes every
/// attribute rule invisible and answers "denied" for access the policy grants.
fn walk_rules(db: &Policydb, policy_class: u32, sty: u32, tty: u32, v: &mut Vector) {
    let (Some(sattrs), Some(tattrs)) = (db.type_attrs(sty), db.type_attrs(tty)) else { return };
    for i in sattrs.iter() {
        for j in tattrs.iter() {
            let key = Key {
                source_type: (i + 1) as u16,
                target_type: (j + 1) as u16,
                target_class: policy_class as u16,
                specified: AVTAB_AV | AVTAB_XPERMS,
            };
            accumulate(&db.te_avtab, &key, false, v);
            accumulate(&db.te_cond_avtab, &key, true, v);
        }
    }
}

/// Fold one table's matching rules into the vector.
///
/// `auditdeny` is intersected, never unioned: a rule of that kind names the
/// denials still worth recording, so it can only ever narrow the set. A union
/// here would let one suppression rule silence the whole policy's denials.
fn accumulate(table: &Avtab, key: &Key, conditional: bool, v: &mut Vector) {
    for rule in table.search(key) {
        if conditional && rule.key.specified & AVTAB_ENABLED == 0 { continue; }
        let word = rule.datum.word();
        match rule.key.kind() {
            AVTAB_ALLOWED => v.allowed |= word,
            AVTAB_AUDITALLOW => v.auditallow |= word,
            AVTAB_AUDITDENY => v.auditdeny &= word,
            _ => {}
        }
    }
}

fn accumulate_xperm(table: &Avtab, key: &Key, conditional: bool,
                    driver: u8, xperm: u8, result: &mut XpermDecision) {
    for rule in table.search(key) {
        if conditional && rule.key.specified & AVTAB_ENABLED == 0 { continue; }
        let Some(xperms) = rule.datum.xperms() else { continue };
        let applies = match xperms.specified {
            AVTAB_XPERMS_IOCTLFUNCTION => xperms.driver == driver,
            // A driver rule grants the complete 256-function range when its
            // driver bit is selected.
            crate::avtab::AVTAB_XPERMS_IOCTLDRIVER => xperms.get(driver),
            _ => false,
        };
        if !applies { continue; }
        result.selected = true;
        match rule.key.kind() {
            AVTAB_XPERMS_ALLOWED => {
                result.allowed |= xperms.specified == crate::avtab::AVTAB_XPERMS_IOCTLDRIVER
                    || xperms.get(xperm);
            }
            AVTAB_XPERMS_AUDITALLOW => result.auditallow = true,
            AVTAB_XPERMS_DONTAUDIT => result.auditdeny = false,
            _ => {}
        }
    }
}

/// Remove permissions whose guarding constraint does not hold.
fn apply_constraints(db: &Policydb, policy_class: u32,
                     scontext: &ValidContext, tcontext: &ValidContext, v: &mut Vector) {
    let Some(class) = db.symbols.class(policy_class) else { return };
    for c in &class.constraints {
        if c.permissions & v.allowed == 0 { continue; }
        if !constraint_eval(db, &c.expr, scontext, tcontext, None) {
            v.allowed &= !c.permissions;
        }
    }
}

/// Remove process transitions between roles the policy does not pair.
fn apply_role_gate(db: &Policydb, policy_class: u32,
                   scontext: &ValidContext, tcontext: &ValidContext, v: &mut Vector) {
    if policy_class != db.process_class { return; }
    if v.allowed & db.process_trans_perms == 0 { return; }
    if scontext.role == tcontext.role { return; }
    let pair = (scontext.role, tcontext.role);
    if !db.role_allow.contains(&pair) {
        v.allowed &= !db.process_trans_perms;
    }
}

/// Remove anything the source type's bound does not also allow.
fn apply_bounds(db: &Policydb, policy_class: u32,
                scontext: &ValidContext, tcontext: &ValidContext, depth: u32, v: &mut Vector) {
    if depth >= MAX_BOUNDS_DEPTH { return; }
    let Some(ty) = db.symbols.ty(scontext.ty) else { return };
    if ty.bounds == 0 || ty.bounds == scontext.ty { return; }
    let mut bounded = scontext.clone();
    bounded.ty = ty.bounds;
    let outer = compute_vector(db, policy_class, &bounded, tcontext, depth + 1);
    v.allowed &= outer.allowed;
}

#[cfg(test)]
#[path = "../tests/services.rs"]
mod tests;
