// The label of a newly created, polyinstantiated or relabelled object.
//
// The four components are decided independently and in a fixed order, because
// the later sources OVERRIDE the earlier ones: an ordinary type transition is
// computed first and a matching filename transition replaces its answer; a
// role comes from the class default and a role transition replaces it; the MLS
// range is decided last of all. Computing an override before the value it
// overrides inverts the precedence and labels the object with the weaker rule.

use alloc::string::String;

use crate::avtab::{Key, Rule, AVTAB_CHANGE, AVTAB_ENABLED, AVTAB_MEMBER, AVTAB_TRANSITION};
use crate::context::{Context, ValidContext};
use crate::error::{Error, Result};
use crate::mapping::Mapping;
use crate::mls::{Level, Range};
use crate::policydb::Policydb;
use crate::policydb::symbols::{Class, Default1, DefaultRange, OBJECT_R_VAL};
use crate::sidtab::{Sid, Sidtab};

/// Suffix every socket-like class name carries.
const SOCKET_SUFFIX: &str = "socket";

/// Which label a request is asking for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TransitionKind {
    /// Label of an object the source creates.
    Transition,
    /// Label of a polyinstantiated member.
    Member,
    /// Label the source relabels the object to.
    Change,
}

impl TransitionKind {
    /// Rule kind this request consults in the access-vector table. # C: O(1)
    pub const fn rule_kind(self) -> u16 {
        match self {
            Self::Transition => AVTAB_TRANSITION,
            Self::Member => AVTAB_MEMBER,
            Self::Change => AVTAB_CHANGE,
        }
    }
}

/// Which numbering a request names its class in.
///
/// A kernel caller knows the class by the kernel's own value and needs the
/// mapping to reach the loaded policy's. Userspace asking through the
/// filesystem does not: it read the value out of `class/<name>/index`, which
/// publishes the POLICY value, and writes that same number back. Treating the
/// one as the other silently answers about a different class whenever the two
/// numberings differ.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ClassValue {
    /// Value in the kernel's class numbering; resolved through the mapping.
    Kernel(u16),
    /// Value in the loaded policy's numbering; used as it stands.
    Policy(u32),
}

impl ClassValue {
    /// Policy class value this names. # C: O(1)
    pub fn resolve(self, map: &Mapping) -> Result<u32> {
        match self {
            Self::Kernel(k) => map.policy_class(k).ok_or(Error::UnknownSymbol),
            Self::Policy(p) => Ok(p),
        }
    }
}

/// One label-computation request.
pub struct TransitionRequest<'a> {
    /// Subject performing the operation.
    pub ssid: Sid,
    /// Object or parent directory the operation is against.
    pub tsid: Sid,
    /// Class of the object being labelled, in its caller's numbering.
    pub class: ClassValue,
    /// Name the object is created under, when the caller knows it.
    pub objname: Option<&'a str>,
    /// Which label is being asked for.
    pub kind: TransitionKind,
}

/// Label of an object created by `ssid` in `tsid`. # C: O(rules + transitions)
pub fn transition_sid(db: &Policydb, map: &Mapping, sidtab: &mut Sidtab,
                      ssid: Sid, tsid: Sid, kernel_class: u16,
                      objname: Option<&str>) -> Result<Sid> {
    compute_sid(db, map, sidtab, &TransitionRequest {
        ssid, tsid, class: ClassValue::Kernel(kernel_class), objname,
        kind: TransitionKind::Transition,
    })
}

/// Same label, for a class named in the POLICY's numbering — what userspace
/// writes to the `create` node. # C: O(rules + transitions)
pub fn transition_sid_user(db: &Policydb, map: &Mapping, sidtab: &mut Sidtab,
                           ssid: Sid, tsid: Sid, policy_class: u32,
                           objname: Option<&str>) -> Result<Sid> {
    compute_sid(db, map, sidtab, &TransitionRequest {
        ssid, tsid, class: ClassValue::Policy(policy_class), objname,
        kind: TransitionKind::Transition,
    })
}

/// Label `ssid` relabels `tsid` to. # C: O(rules + transitions)
pub fn change_sid(db: &Policydb, map: &Mapping, sidtab: &mut Sidtab,
                  ssid: Sid, tsid: Sid, kernel_class: u16) -> Result<Sid> {
    compute_sid(db, map, sidtab, &TransitionRequest {
        ssid, tsid, class: ClassValue::Kernel(kernel_class), objname: None,
        kind: TransitionKind::Change,
    })
}

/// Same relabel, for a class named in the POLICY's numbering. # C: O(rules + transitions)
pub fn change_sid_user(db: &Policydb, map: &Mapping, sidtab: &mut Sidtab,
                       ssid: Sid, tsid: Sid, policy_class: u32) -> Result<Sid> {
    compute_sid(db, map, sidtab, &TransitionRequest {
        ssid, tsid, class: ClassValue::Policy(policy_class), objname: None,
        kind: TransitionKind::Change,
    })
}

/// Label of a polyinstantiated member of `tsid`. # C: O(rules + transitions)
pub fn member_sid(db: &Policydb, map: &Mapping, sidtab: &mut Sidtab,
                  ssid: Sid, tsid: Sid, kernel_class: u16) -> Result<Sid> {
    compute_sid(db, map, sidtab, &TransitionRequest {
        ssid, tsid, class: ClassValue::Kernel(kernel_class), objname: None,
        kind: TransitionKind::Member,
    })
}

/// Same member label, for a class named in the POLICY's numbering.
/// # C: O(rules + transitions)
pub fn member_sid_user(db: &Policydb, map: &Mapping, sidtab: &mut Sidtab,
                       ssid: Sid, tsid: Sid, policy_class: u32) -> Result<Sid> {
    compute_sid(db, map, sidtab, &TransitionRequest {
        ssid, tsid, class: ClassValue::Policy(policy_class), objname: None,
        kind: TransitionKind::Member,
    })
}

/// Compute one label, allocating a SID for it. # C: O(rules + transitions)
pub fn compute_sid(db: &Policydb, map: &Mapping, sidtab: &mut Sidtab,
                   req: &TransitionRequest<'_>) -> Result<Sid> {
    let scontext = resolve(sidtab, req.ssid)?;
    let tcontext = resolve(sidtab, req.tsid)?;
    let policy_class = req.class.resolve(map)?;
    let class = db.symbols.class(policy_class).ok_or(Error::UnknownSymbol)?;
    let source_like = policy_class == db.process_class || is_socket_class(db, policy_class);

    let user = new_user(class, req.kind, &scontext, &tcontext);
    let mut role = new_role(class, source_like, &scontext, &tcontext);
    let mut ty = new_type(db, class, policy_class, req.kind, source_like, &scontext, &tcontext);

    if let Some(name) = req.objname {
        if req.kind == TransitionKind::Transition {
            if let Some(otype) = filename_otype(db, policy_class, &scontext, &tcontext, name) {
                ty = otype;
            }
        }
    }

    if req.kind == TransitionKind::Transition {
        if let Some(rt) = db.role_tr.iter()
            .find(|r| r.role == scontext.role && r.ty == tcontext.ty && r.tclass == policy_class)
        { role = rt.new_role; }
    }

    let range = new_range(db, class, policy_class, req.kind, source_like, &scontext, &tcontext);

    let out = ValidContext { user, role, ty, range };
    if !db.context_is_valid(&out) { return Err(Error::InvalidContext); }
    if out == scontext { return Ok(req.ssid); }
    if out == tcontext { return Ok(req.tsid); }
    sidtab.context_to_sid(Context::Valid(out))
}

/// Whether a class names a socket. # C: O(1)
///
/// Socket-like classes inherit the creating task's role, type and range in the
/// absence of a rule, the same way a process does.
pub fn is_socket_class(db: &Policydb, policy_class: u32) -> bool {
    db.symbols.class(policy_class).is_some_and(|c| c.name.ends_with(SOCKET_SUFFIX))
}

fn resolve(sidtab: &Sidtab, sid: Sid) -> Result<ValidContext> {
    sidtab.search(sid).and_then(Context::valid).cloned().ok_or(Error::UnknownSid)
}

fn new_user(class: &Class, kind: TransitionKind,
            scontext: &ValidContext, tcontext: &ValidContext) -> u32 {
    match kind {
        // A member is an instance OF the object, so it keeps the object's owner.
        TransitionKind::Member => tcontext.user,
        _ => match class.default_user {
            Default1::Target => tcontext.user,
            _ => scontext.user,
        },
    }
}

fn new_role(class: &Class, source_like: bool,
            scontext: &ValidContext, tcontext: &ValidContext) -> u32 {
    match class.default_role {
        Default1::Source => scontext.role,
        Default1::Target => tcontext.role,
        Default1::Unset => if source_like { scontext.role } else { OBJECT_R_VAL },
    }
}

fn new_type(db: &Policydb, class: &Class, policy_class: u32, kind: TransitionKind,
            source_like: bool, scontext: &ValidContext, tcontext: &ValidContext) -> u32 {
    let key = Key {
        source_type: scontext.ty as u16,
        target_type: tcontext.ty as u16,
        target_class: policy_class as u16,
        specified: kind.rule_kind(),
    };
    let hit = db.te_avtab.search(&key).next()
        .or_else(|| db.te_cond_avtab.search(&key).find(|r: &&Rule| {
            r.key.specified & AVTAB_ENABLED != 0
        }));
    if let Some(rule) = hit { return rule.datum.word(); }

    match class.default_type {
        Default1::Source => scontext.ty,
        Default1::Target => tcontext.ty,
        Default1::Unset => if source_like { scontext.ty } else { tcontext.ty },
    }
}

/// Type a filename transition names for this parent, class and name.
///
/// The bitmap of target types carrying any filename transition is consulted
/// first: it is what keeps the common case — a directory named by no rule —
/// from scanning the whole table on every file creation.
fn filename_otype(db: &Policydb, policy_class: u32, scontext: &ValidContext,
                  tcontext: &ValidContext, name: &str) -> Option<u32> {
    // Keyed by the raw type value; see where the bitmap is built for why this
    // is not value-minus-one like the type-attribute map.
    if !db.filename_trans_ttypes.get(tcontext.ty) { return None; }
    db.filename_trans.iter()
        .find(|f| f.ttype == tcontext.ty && f.tclass == policy_class && f.name == name)
        .and_then(|f| f.otype_for(scontext.ty))
}

fn new_range(db: &Policydb, class: &Class, policy_class: u32, kind: TransitionKind,
             source_like: bool, scontext: &ValidContext, tcontext: &ValidContext) -> Range {
    if kind == TransitionKind::Transition {
        if let Some(rt) = db.range_tr.iter().find(|r| {
            r.source_type == scontext.ty && r.target_type == tcontext.ty
                && r.target_class == policy_class
        }) { return rt.range.clone(); }
    }
    match class.default_range {
        DefaultRange::SourceLow => single(&scontext.range.low),
        DefaultRange::SourceHigh => single(&scontext.range.high),
        DefaultRange::SourceLowHigh => scontext.range.clone(),
        DefaultRange::TargetLow => single(&tcontext.range.low),
        DefaultRange::TargetHigh => single(&tcontext.range.high),
        DefaultRange::TargetLowHigh => tcontext.range.clone(),
        DefaultRange::Glblub => Range::glblub(&scontext.range, &tcontext.range),
        DefaultRange::Unset => match kind {
            // A member never widens the range it was instantiated from.
            TransitionKind::Member => single(&scontext.range.low),
            _ => if source_like { scontext.range.clone() } else { single(&scontext.range.low) },
        },
    }
}

fn single(level: &Level) -> Range { Range::single(level.clone()) }

/// Name of a class, for diagnostics that must not re-derive it. # C: O(1)
pub fn class_name(db: &Policydb, policy_class: u32) -> Option<&String> {
    db.symbols.class(policy_class).map(|c| &c.name)
}

#[cfg(test)]
#[path = "../tests/transition.rs"]
mod tests;
