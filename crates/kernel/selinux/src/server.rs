// The security server: the loaded policy, the SID table, the decision cache
// and the enforcement state, held together so a check is one call.
//
// This is the ONE owner of that state. Nothing else keeps a copy of the
// policy, a second SID table, or a private notion of whether enforcement is
// on — a second copy is a source of truth that can disagree with this one, and
// a disagreement here is an access granted that the policy refuses.
//
// It is still pure: no locking, no globals, no logging, no task state. The
// caller owns the lock and the audit record.

use alloc::string::String;
use alloc::vec::Vec;

use crate::avc::{Avc, AvDecision, AVD_FLAGS_PERMISSIVE};
use crate::context::Context;
use crate::error::{Error, Result};
use crate::mapping::Mapping;
use crate::policydb::Policydb;
use crate::services;
use crate::sidtab::{Sid, Sidtab};
use crate::status::{BootConfig, Enforcing, SecurityState};
use crate::uapi::initsid::InitSid;

/// Base-two logarithm of the decision cache's bucket count.
pub const AVC_SLOTS_LOG2: u32 = 9;

/// Pre-policy rendering of one SID. # C: O(1)
fn initial_sid_context(sid: Sid) -> Result<String> {
    crate::uapi::initsid::initial_sid_context(sid)
        .map(alloc::string::ToString::to_string)
        .ok_or(Error::InvalidContext)
}

/// Outcome of one access check.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Verdict {
    /// Whether the operation proceeds.
    pub allowed: bool,
    /// Permissions the request asked for that the policy does not grant.
    pub denied: u32,
    /// Whether the denial was allowed through because the domain is permissive
    /// or the server is not enforcing.
    pub permissive: bool,
    /// Whether the caller should emit an audit record.
    pub audit: bool,
}

impl Verdict {
    /// An allow with nothing to report. # C: O(1)
    pub const fn allow() -> Self {
        Self { allowed: true, denied: 0, permissive: false, audit: false }
    }
}

/// A policy staged for loading, with the tables it needs.
struct Loaded {
    db: Policydb,
    map: Mapping,
    sidtab: Sidtab,
    /// Boolean values written but not yet committed.
    pending_bools: Vec<Option<bool>>,
}

/// The security server.
pub struct SecurityServer {
    state: SecurityState,
    avc: Avc,
    loaded: Option<Loaded>,
}

/// A policy image parsed into tables, not yet live.
///
/// Parsing an image is the single most expensive thing this module does: a
/// distribution policy is megabytes and expands into hundreds of thousands of
/// rules. Doing it while the live server is locked disables preemption for the
/// whole parse, and an allocation that large can reach the block layer — which
/// is a sleep, under a spinlock, on every policy load.
///
/// Splitting the load in two removes that entirely: build the new policy with
/// no lock held and nothing live to disturb, then take the lock only long
/// enough to swap it in. A failed parse never reaches the live server at all.
pub struct StagedPolicy {
    db: Policydb,
    map: Mapping,
}

impl StagedPolicy {
    /// Parse and index a policy image. # C: O(image)
    ///
    /// Deliberately takes no server and borrows nothing from one, so it cannot
    /// be called with the server's lock held by construction.
    pub fn parse(image: &[u8]) -> Result<Self> {
        let db = crate::policydb::load(image)?;
        let map = Mapping::build(&db)?;
        Ok(Self { db, map })
    }

    /// Version of the parsed policy. # C: O(1)
    pub fn version(&self) -> u32 { self.db.version }
}

impl SecurityServer {
    /// A server that has not yet loaded a policy. # C: O(cache slots)
    pub fn new(boot: BootConfig) -> Self {
        Self { state: SecurityState::new(boot), avc: Avc::new(AVC_SLOTS_LOG2), loaded: None }
    }

    /// Current enforcement and initialisation state. # C: O(1)
    pub const fn state(&self) -> &SecurityState { &self.state }

    /// Whether the module runs at all this boot. # C: O(1)
    pub const fn enabled(&self) -> bool { self.state.enabled }

    /// Whether a policy has been loaded. # C: O(1)
    pub const fn initialized(&self) -> bool { self.state.initialized }

    /// Current enforcement mode. # C: O(1)
    pub const fn enforcing(&self) -> Enforcing { self.state.enforcing }

    /// Change the enforcement mode. # C: O(1)
    ///
    /// The cache is NOT flushed: enforcement changes what a denial does, not
    /// what the policy decides, and flushing here would cost every cached
    /// decision for no gain.
    pub fn set_enforcing(&mut self, e: Enforcing) -> Result<()> { self.state.set_enforcing(e) }

    /// The loaded policy, if any. # C: O(1)
    pub fn policy(&self) -> Option<&Policydb> { self.loaded.as_ref().map(|l| &l.db) }

    /// The SID table, if a policy is loaded. # C: O(1)
    pub fn sidtab(&self) -> Option<&Sidtab> { self.loaded.as_ref().map(|l| &l.sidtab) }

    /// The decision cache. # C: O(1)
    pub const fn avc(&self) -> &Avc { &self.avc }

    /// Mutable decision cache, for the statistics and threshold controls. # C: O(1)
    pub fn avc_mut(&mut self) -> &mut Avc { &mut self.avc }

    /// Load a policy image, replacing any policy already loaded. # C: O(image)
    ///
    /// Convenience for a caller that holds no lock. A caller that DOES hold
    /// the server's lock must use `StagedPolicy::parse` outside it and
    /// `install_policy` inside; see `StagedPolicy` for why.
    pub fn load_policy(&mut self, image: &[u8]) -> Result<()> {
        self.install_policy(StagedPolicy::parse(image)?)
    }

    /// Replace the loaded policy with one already parsed. # C: O(existing SIDs)
    ///
    /// A malformed image leaves the previous policy in force rather than the
    /// system with half a policy, which would be neither the old rules nor the
    /// new ones — which is why parsing happens before this is called, not
    /// inside it. Contexts already resolved are carried across and
    /// re-validated; one that no longer resolves is retained verbatim.
    pub fn install_policy(&mut self, staged: StagedPolicy) -> Result<()> {
        let StagedPolicy { db, map } = staged;
        let mut sidtab = Sidtab::new();
        services::load_initial_sids(&db, &mut sidtab)?;
        self.carry_over_contexts(&db, &mut sidtab)?;
        let pending = alloc::vec![None; db.symbols.bools.len()];
        self.loaded = Some(Loaded { db, map, sidtab, pending_bools: pending });
        self.state.note_policy_load();
        self.avc.reset(self.state.seqno);
        Ok(())
    }

    /// Re-resolve every SID the old policy issued against the new one.
    ///
    /// A SID is a handle userspace and the kernel already hold; it must keep
    /// meaning the same object across a reload. A context the new policy
    /// cannot interpret is retained as its written form so a later reload that
    /// restores the type recovers it.
    fn carry_over_contexts(&mut self, db: &Policydb, next: &mut Sidtab) -> Result<()> {
        let Some(old) = self.loaded.as_ref() else { return Ok(()) };
        let carried: Vec<(Sid, Context)> = old.sidtab.entries()
            .map(|(sid, c)| (sid, c.clone())).collect();
        for (_, context) in carried {
            let converted = match &context {
                Context::Valid(v) if db.context_is_valid(v) => context.clone(),
                Context::Valid(v) => Context::Unmapped(
                    services::context_to_string(&old.db, &Context::Valid(v.clone()))
                        .unwrap_or_else(|_| String::new())),
                Context::Unmapped(s) => match services::context_from_string(db, s) {
                    Ok(v) => Context::Valid(v),
                    Err(_) => context.clone(),
                },
            };
            next.context_to_sid(converted)?;
        }
        Ok(())
    }

    /// Decide whether a subject may exercise permissions on an object. # C: O(1) cached
    ///
    /// Before the first policy load there is no policy and everything is
    /// allowed; that is the bootstrap window, not a decision.
    pub fn has_perm(&mut self, ssid: Sid, tsid: Sid, kernel_class: u16, requested: u32)
        -> Verdict
    {
        if !self.state.consults_policy() { return Verdict::allow(); }
        let avd = self.compute(ssid, tsid, kernel_class);
        let denied = requested & !avd.allowed;
        if denied == 0 {
            let audit = requested & avd.auditallow != 0;
            return Verdict { allowed: true, denied: 0, permissive: false, audit };
        }
        let permissive = !self.state.enforcing.refuses()
            || avd.flags & AVD_FLAGS_PERMISSIVE != 0;
        // A permissive domain repeats the same denied access constantly. Widen
        // the cached decision so the next repeat is a cache hit rather than a
        // full policy consultation; the verdict itself is unchanged.
        if permissive { self.avc.grant(ssid, tsid, kernel_class, denied); }
        let audit = denied & avd.auditdeny != 0;
        Verdict { allowed: permissive, denied, permissive, audit }
    }

    /// Full decision for a subject/object/class triple. # C: O(1) cached
    pub fn compute(&mut self, ssid: Sid, tsid: Sid, kernel_class: u16) -> AvDecision {
        if let Some(avd) = self.avc.lookup(ssid, tsid, kernel_class) { return avd; }
        let seqno = self.state.seqno;
        let Some(l) = self.loaded.as_ref() else { return AvDecision::init(seqno) };
        let avd = services::compute_av(&l.db, &l.map, &l.sidtab, ssid, tsid, kernel_class, seqno);
        self.avc.insert(ssid, tsid, kernel_class, avd);
        avd
    }

    /// Full decision for a class named in the POLICY's numbering, uncached and
    /// answered in policy bit numbering. # C: O(attrs^2 * bucket)
    ///
    /// The question userspace asks through `access`, which names its class and
    /// reads its permission bits out of the `class/` tree — both in the
    /// policy's own numbering.
    pub fn compute_av_user(&self, ssid: Sid, tsid: Sid, policy_class: u32) -> AvDecision {
        let seqno = self.state.seqno;
        // Before the first policy load there are no rules to consult and
        // everything is permitted; answering the zero vector instead would
        // report every access as denied to a caller that has no way to tell
        // "denied" from "nothing loaded yet".
        let Some(l) = self.loaded.as_ref() else {
            return AvDecision { allowed: u32::MAX, ..AvDecision::init(seqno) };
        };
        services::compute_av_user(&l.db, &l.sidtab, ssid, tsid, policy_class, seqno)
    }

    /// SID of a newly created object, for a class named in the POLICY's
    /// numbering. # C: O(rules)
    pub fn transition_sid_user(&mut self, ssid: Sid, tsid: Sid, policy_class: u32,
                               objname: Option<&str>) -> Result<Sid> {
        if let Some(sid) = self.bootstrap_sid(ssid, tsid, policy_class) { return Ok(sid) }
        let l = self.loaded.as_mut().ok_or(Error::UnknownSid)?;
        services::transition_sid_user(&l.db, &l.map, &mut l.sidtab, ssid, tsid, policy_class,
                                      objname)
    }

    /// SID an object takes when relabelled, for a class named in the POLICY's
    /// numbering. # C: O(rules)
    pub fn change_sid_user(&mut self, ssid: Sid, tsid: Sid, policy_class: u32) -> Result<Sid> {
        if let Some(sid) = self.bootstrap_sid(ssid, tsid, policy_class) { return Ok(sid) }
        let l = self.loaded.as_mut().ok_or(Error::UnknownSid)?;
        services::change_sid_user(&l.db, &l.map, &mut l.sidtab, ssid, tsid, policy_class)
    }

    /// SID of a polyinstantiated member, for a class named in the POLICY's
    /// numbering. # C: O(rules)
    pub fn member_sid_user(&mut self, ssid: Sid, tsid: Sid, policy_class: u32) -> Result<Sid> {
        if let Some(sid) = self.bootstrap_sid(ssid, tsid, policy_class) { return Ok(sid) }
        let l = self.loaded.as_mut().ok_or(Error::UnknownSid)?;
        services::member_sid_user(&l.db, &l.map, &mut l.sidtab, ssid, tsid, policy_class)
    }

    /// Whether an object may move between two written labels, for a class
    /// named in the POLICY's numbering. # C: O(constraints)
    pub fn validate_transition_user(&mut self, old: &str, new: &str, policy_class: u32,
                                    task: &str) -> Result<()>
    {
        // No policy, no constraint list, nothing to refuse.
        if !self.initialized() { return Ok(()) }
        let l = self.loaded.as_mut().ok_or(Error::InvalidContext)?;
        let old_sid = services::string_to_sid(&l.db, &mut l.sidtab, old)?;
        let new_sid = services::string_to_sid(&l.db, &mut l.sidtab, new)?;
        let task_sid = services::string_to_sid(&l.db, &mut l.sidtab, task)?;
        services::validate_transition_user(&l.db, &l.sidtab, old_sid, new_sid, task_sid,
                                           policy_class)
    }

    /// Label a computation answers with before any policy is loaded. # C: O(1)
    ///
    /// `None` once a policy is loaded, so the caller computes. Before then a
    /// new process keeps its creator's label and any other object keeps the
    /// one it is created against — there is no policy to say otherwise, and
    /// refusing would make the interface unusable for the whole bootstrap
    /// window. The class is compared against the KERNEL's `process` value
    /// because with no policy loaded there is no other numbering in existence.
    fn bootstrap_sid(&self, ssid: Sid, tsid: Sid, class: u32) -> Option<Sid> {
        if self.initialized() { return None }
        let process = crate::uapi::classmap::class_by_name("process")? as u32;
        Some(if class == process { ssid } else { tsid })
    }

    /// SID of a newly created object. # C: O(rules)
    pub fn transition_sid(&mut self, ssid: Sid, tsid: Sid, kernel_class: u16,
                          objname: Option<&str>) -> Result<Sid> {
        let l = self.loaded.as_mut().ok_or(Error::UnknownSid)?;
        services::transition_sid(&l.db, &l.map, &mut l.sidtab, ssid, tsid, kernel_class, objname)
    }

    /// SID an object takes when relabelled. # C: O(rules)
    pub fn change_sid(&mut self, ssid: Sid, tsid: Sid, kernel_class: u16) -> Result<Sid> {
        let l = self.loaded.as_mut().ok_or(Error::UnknownSid)?;
        services::change_sid(&l.db, &l.map, &mut l.sidtab, ssid, tsid, kernel_class)
    }

    /// SID of a polyinstantiated member. # C: O(rules)
    pub fn member_sid(&mut self, ssid: Sid, tsid: Sid, kernel_class: u16) -> Result<Sid> {
        let l = self.loaded.as_mut().ok_or(Error::UnknownSid)?;
        services::member_sid(&l.db, &l.map, &mut l.sidtab, ssid, tsid, kernel_class)
    }

    /// Whether an object may move from one written label to another at the
    /// request of a task. # C: O(constraints)
    ///
    /// The class's validate-transition constraints are the only thing guarding
    /// a relabel, and nothing else in the engine reads them; resolving the
    /// three contexts and stopping there would accept every move the policy
    /// forbids.
    pub fn validate_transition(&mut self, old: &str, new: &str, kernel_class: u16, task: &str)
        -> Result<()>
    {
        let l = self.loaded.as_mut().ok_or(Error::InvalidContext)?;
        let old_sid = services::string_to_sid(&l.db, &mut l.sidtab, old)?;
        let new_sid = services::string_to_sid(&l.db, &mut l.sidtab, new)?;
        let task_sid = services::string_to_sid(&l.db, &mut l.sidtab, task)?;
        services::validate_transition(&l.db, &l.map, &l.sidtab,
                                      old_sid, new_sid, task_sid, kernel_class)
    }

    /// Rendered context of a SID. # C: O(categories)
    ///
    /// Before a policy is loaded there is no table to render from, and the
    /// answer is the initial SID's own policy name — a reader asking for a
    /// label this early gets the name the policy will bind, not a failure.
    /// Refusing instead would make every label read fail for the whole of
    /// early boot, which userspace reads as a kernel without the module.
    pub fn sid_to_context(&self, sid: Sid) -> Result<String> {
        let Some(l) = self.loaded.as_ref() else { return initial_sid_context(sid) };
        services::sid_to_context(&l.db, &l.sidtab, sid)
    }

    /// Rendered context of a SID without substituting the unlabeled context. # C: O(categories)
    pub fn sid_to_context_force(&self, sid: Sid) -> Result<String> {
        let Some(l) = self.loaded.as_ref() else { return initial_sid_context(sid) };
        services::sid_to_context_force(&l.db, &l.sidtab, sid)
    }

    /// One SID's user, role and type carrying another's MLS range.
    /// # C: O(categories)
    ///
    /// The range travels from the second SID while the identity comes from the
    /// first, which is how a connection's server end takes the server's type at
    /// the client's sensitivity. With no policy, no MLS, or an opaque context on
    /// either side there is no range to move and the first SID stands.
    pub fn sid_mls_copy(&mut self, sid: Sid, mls_sid: Sid) -> Result<Sid> {
        let Some(l) = self.loaded.as_mut() else { return Ok(sid) };
        if !l.db.mls { return Ok(sid); }
        let Some(base) = l.sidtab.search(sid).ok_or(Error::UnknownSid)?.valid().cloned()
            else { return Ok(sid) };
        let Some(range) = l.sidtab.search(mls_sid).ok_or(Error::UnknownSid)?
            .valid().map(|c| c.range.clone()) else { return Ok(sid) };
        let new = crate::context::ValidContext { range, ..base };
        if !l.db.context_is_valid(&new) { return Err(Error::InvalidContext); }
        l.sidtab.context_to_sid(Context::Valid(new))
    }

    /// SID for a written context, allocating one if it is new. # C: O(categories)
    pub fn context_to_sid(&mut self, s: &str) -> Result<Sid> {
        let l = self.loaded.as_mut().ok_or(Error::InvalidContext)?;
        services::string_to_sid(&l.db, &mut l.sidtab, s)
    }

    /// SID of one initial SID number. # C: O(1)
    pub fn initial_sid(&self, sid: InitSid) -> Sid { sid.sid() }

    /// Committed and pending value of one boolean. # C: O(1)
    pub fn get_bool(&self, index: usize) -> Option<(bool, bool)> {
        let l = self.loaded.as_ref()?;
        let committed = l.db.symbols.bools.get(index)?.state;
        Some((committed, l.pending_bools.get(index).copied().flatten().unwrap_or(committed)))
    }

    /// Stage a boolean value without committing it. # C: O(1)
    ///
    /// Nothing changes until `commit_bools`. Applying a write immediately
    /// would let a caller setting several related booleans be observed in a
    /// state no policy author ever wrote.
    pub fn set_bool_pending(&mut self, index: usize, value: bool) -> Result<()> {
        let l = self.loaded.as_mut().ok_or(Error::UnknownSymbol)?;
        let slot = l.pending_bools.get_mut(index).ok_or(Error::UnknownSymbol)?;
        *slot = Some(value);
        Ok(())
    }

    /// Apply every staged boolean value at once. # C: O(conditional rules)
    pub fn commit_bools(&mut self) -> Result<()> {
        let l = self.loaded.as_mut().ok_or(Error::UnknownSymbol)?;
        for (i, pending) in l.pending_bools.iter_mut().enumerate() {
            if let Some(v) = pending.take() {
                if let Some(b) = l.db.symbols.bools.get_mut(i) { b.state = v; }
            }
        }
        crate::policydb::read::evaluate_cond_nodes(&mut l.db);
        self.state.note_bool_commit();
        // Conditional rules changed, so every cached decision may be wrong.
        self.avc.reset(self.state.seqno);
        Ok(())
    }

    /// Boolean names in value order. # C: O(booleans)
    pub fn bool_names(&self) -> impl Iterator<Item = &str> {
        self.loaded.iter().flat_map(|l| l.db.symbols.bools.iter().map(|b| b.name.as_str()))
    }

    /// Index of a boolean by name. # C: O(booleans)
    pub fn bool_index(&self, name: &str) -> Option<usize> {
        self.loaded.as_ref()?.db.symbols.bools.iter().position(|b| b.name == name)
    }
}

#[cfg(test)]
#[path = "tests/server.rs"]
mod tests;
