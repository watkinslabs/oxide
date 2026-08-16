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
    /// The image is parsed WHOLE before anything is replaced. A malformed
    /// image leaves the previous policy in force rather than leaving the
    /// system with half a policy, which would be neither the old rules nor the
    /// new ones. Contexts already resolved are carried across and re-validated;
    /// one that no longer resolves is retained verbatim, not dropped.
    pub fn load_policy(&mut self, image: &[u8]) -> Result<()> {
        let db = crate::policydb::load(image)?;
        let map = Mapping::build(&db)?;
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

    /// Rendered context of a SID. # C: O(categories)
    pub fn sid_to_context(&self, sid: Sid) -> Result<String> {
        let l = self.loaded.as_ref().ok_or(Error::UnknownSid)?;
        services::sid_to_context(&l.db, &l.sidtab, sid)
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
