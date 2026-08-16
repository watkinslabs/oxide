// The node handlers' operations over the live security server.
//
// The one server lives in `selinux-runtime`; this is a view of it, not a
// second copy. Each operation takes and releases the server lock on its own
// rather than holding it across a handler, because the permission check that
// gates a write takes the same lock.
//
// The policy IMAGE is the one thing kept here: the engine consumes an image
// and retains only what it parsed, while the `policy` node must hand back the
// bytes verbatim. Those bytes are not policy state and nothing decides
// anything from them.

use alloc::string::String;
use alloc::vec::Vec;

use selinux::avc::{AvDecision, CacheStats};
use selinux::sidtab::HashStats;
use sync::{SecurityPolicy as LockClass, Spinlock};
use vfs::{KResult, VfsError};

use crate::nodes::plumb::{copy_out, slice_at};
use crate::ops::{ClassEntry, NewContext, PermEntry, PolicyFacts, PolicyOps};

/// The image the loaded policy was read from.
static IMAGE: Spinlock<Option<Vec<u8>>, LockClass> = Spinlock::new(None);

/// Run a handler against the live server. # C: O(handler)
pub fn with_ops<R>(f: impl FnOnce(&mut dyn PolicyOps) -> R) -> R {
    let mut ops = KernelOps;
    f(&mut ops)
}

/// Refusal reported for a policy-engine error. # C: O(1)
///
/// Every engine refusal reaching this interface is a request userspace got
/// wrong — an uninterpretable context, an unknown class, a malformed image —
/// except exhaustion, which must not be reported as a bad request.
fn engine_error(e: selinux::Error) -> VfsError {
    match e { selinux::Error::NoMemory => VfsError::Enomem, _ => VfsError::Einval }
}

/// The live security server, as the node handlers see it.
pub struct KernelOps;

impl PolicyOps for KernelOps {
    /// # C: O(1) cached
    fn check(&mut self, permission: &str) -> KResult<()> {
        let subject = crate::subject::current_sid();
        selinux_runtime::check::security_perm(subject, permission)
            .map_err(|_| VfsError::Eacces)
    }

    /// # C: O(1)
    fn enforcing(&self) -> bool {
        selinux_runtime::with(|s| s.enforcing().refuses()).unwrap_or(false)
    }

    /// # C: O(1)
    fn set_enforcing(&mut self, on: bool) -> KResult<()> {
        let mode = if on { selinux::Enforcing::Enforcing } else { selinux::Enforcing::Permissive };
        match selinux_runtime::with(|s| s.set_enforcing(mode)) {
            Some(Ok(())) => Ok(()),
            // No server installed: the state userspace asked for is the state
            // a server-less kernel already reports, so the write is inert
            // rather than an error the caller cannot act on.
            None => Ok(()),
            Some(Err(e)) => Err(engine_error(e)),
        }
    }

    /// # C: O(image)
    fn load_policy(&mut self, image: &[u8]) -> KResult<()> {
        // Parse BEFORE taking the server lock. A distribution policy is
        // megabytes and expands into hundreds of thousands of rules; doing
        // that with the lock held disables preemption for the whole parse, and
        // an allocation that large can reach the block layer. The result is a
        // sleep under a spinlock on every policy load, which the scheduler
        // reports as a violation and which no hosted test can see.
        let staged = selinux::StagedPolicy::parse(image).map_err(engine_error)?;
        // Same reason: copy the image before taking ITS lock, not under it.
        let retained = image.to_vec();
        match selinux_runtime::with(|s| s.install_policy(staged)) {
            Some(Ok(())) => {}
            Some(Err(e)) => return Err(engine_error(e)),
            None => return Err(VfsError::Einval),
        }
        *IMAGE.lock() = Some(retained);
        Ok(())
    }

    /// # C: O(buf)
    ///
    /// The slice handed out is caller memory, and touching caller memory can
    /// take a demand fault that sleeps. So the bytes are copied into a kernel
    /// buffer under the lock and written out after it is dropped: holding a
    /// spinlock across the write would sleep with preemption disabled.
    fn read_policy_image(&self, off: usize, buf: &mut [u8]) -> KResult<usize> {
        let staged: Option<alloc::vec::Vec<u8>> = {
            let image = IMAGE.lock();
            image.as_ref().map(|bytes| slice_at(bytes, off as u64, buf.len()))
        };
        match staged {
            Some(bytes) => Ok(copy_out(&bytes, 0, buf)),
            None => Err(VfsError::Einval),
        }
    }

    /// # C: O(booleans)
    fn bool_value(&self, name: &str) -> Option<(bool, bool)> {
        selinux_runtime::with(|s| {
            let index = s.bool_index(name)?;
            s.get_bool(index)
        }).flatten()
    }

    /// # C: O(booleans)
    fn set_bool_pending(&mut self, name: &str, value: bool) -> KResult<()> {
        let done = selinux_runtime::with(|s| {
            let Some(index) = s.bool_index(name) else { return Err(VfsError::Einval) };
            s.set_bool_pending(index, value).map_err(engine_error)
        });
        done.unwrap_or(Err(VfsError::Einval))
    }

    /// # C: O(conditional rules)
    fn commit_bools(&mut self) -> KResult<()> {
        selinux_runtime::with(|s| s.commit_bools().map_err(engine_error))
            .unwrap_or(Err(VfsError::Einval))
    }

    /// # C: O(booleans)
    fn bool_names(&self) -> Vec<String> {
        selinux_runtime::with(|s| s.bool_names().map(String::from).collect())
            .unwrap_or_default()
    }

    /// # C: O(1) cached
    fn compute_av(&mut self, scon: &str, tcon: &str, class: u16) -> KResult<AvDecision> {
        selinux_runtime::with(|s| {
            let ssid = s.context_to_sid(scon).map_err(engine_error)?;
            let tsid = s.context_to_sid(tcon).map_err(engine_error)?;
            Ok(s.compute(ssid, tsid, class))
        }).unwrap_or(Err(VfsError::Einval))
    }

    /// # C: O(categories)
    fn canonical_context(&mut self, context: &str) -> KResult<String> {
        selinux_runtime::with(|s| {
            let sid = s.context_to_sid(context).map_err(engine_error)?;
            s.sid_to_context(sid).map_err(engine_error)
        }).unwrap_or(Err(VfsError::Einval))
    }

    /// # C: O(rules)
    fn new_context(&mut self, kind: NewContext, scon: &str, tcon: &str, class: u16,
                   name: Option<&str>) -> KResult<String> {
        selinux_runtime::with(|s| {
            let ssid = s.context_to_sid(scon).map_err(engine_error)?;
            let tsid = s.context_to_sid(tcon).map_err(engine_error)?;
            let new = match kind {
                NewContext::Create => s.transition_sid(ssid, tsid, class, name),
                NewContext::Relabel => s.change_sid(ssid, tsid, class),
                NewContext::Member => s.member_sid(ssid, tsid, class),
            }.map_err(engine_error)?;
            s.sid_to_context(new).map_err(engine_error)
        }).unwrap_or(Err(VfsError::Einval))
    }

    /// # C: O(constraints)
    ///
    /// The class's validate-transition constraints decide this and nothing
    /// else does: resolving the three contexts and stopping would accept every
    /// relabel the policy forbids, silently.
    fn validate_trans(&mut self, old: &str, new: &str, class: u16, task: &str) -> KResult<()> {
        if selinux::uapi::classmap::class_def(class).is_none() { return Err(VfsError::Einval); }
        selinux_runtime::with(|s| {
            s.validate_transition(old, new, class, task).map_err(engine_error)
        }).unwrap_or(Err(VfsError::Einval))
    }

    /// # C: O(1)
    fn cache_threshold(&self) -> u32 {
        selinux_runtime::with(|s| s.avc().threshold()).unwrap_or(0)
    }

    /// # C: O(1)
    fn set_cache_threshold(&mut self, n: u32) {
        selinux_runtime::with(|s| s.avc_mut().set_threshold(n));
    }

    /// # C: O(slots)
    fn avc_hash_stats(&self) -> HashStats {
        selinux_runtime::with(|s| s.avc().hash_stats()).unwrap_or(HashStats {
            entries: 0, buckets: 0, used_buckets: 0, longest_chain: 0 })
    }

    /// # C: O(1)
    fn avc_cache_stats(&self) -> CacheStats {
        selinux_runtime::with(|s| s.avc().stats()).unwrap_or_default()
    }

    /// # C: O(buckets)
    fn sidtab_hash_stats(&self) -> HashStats {
        let empty = HashStats { entries: 0, buckets: 0, used_buckets: 0, longest_chain: 0 };
        selinux_runtime::with(|s| s.sidtab().map(|t| t.hash_stats()).unwrap_or(empty))
            .unwrap_or(empty)
    }

    /// # C: O(1)
    fn facts(&self) -> PolicyFacts {
        selinux_runtime::with(|s| {
            let state = *s.state();
            let (mls, reject_unknown, deny_unknown) = match s.policy() {
                Some(db) => (db.mls, db.reject_unknown, !db.allow_unknown),
                None => (false, false, false),
            };
            PolicyFacts { loaded: state.initialized, mls, reject_unknown, deny_unknown,
                          seqno: state.seqno, policyload: state.policyload }
        }).unwrap_or_default()
    }

    /// # C: O(log chunks)
    fn policycap(&self, bit: u32) -> bool {
        selinux_runtime::with(|s| s.policy().is_some_and(|db| db.policycap(bit)))
            .unwrap_or(false)
    }

    /// # C: O(categories)
    fn initial_context(&self, sid: u32) -> Option<String> {
        selinux_runtime::with(|s| s.sid_to_context(sid).ok()).flatten()
    }

    /// # C: O(classes × perms)
    fn classes(&self) -> Vec<ClassEntry> {
        selinux_runtime::with(|s| {
            let Some(db) = s.policy() else { return Vec::new() };
            db.symbols.classes.iter().map(|c| {
                let mut perms = Vec::new();
                if let Some(value) = c.common {
                    if let Some(common) = db.symbols.commons.iter().find(|x| x.value == value) {
                        for p in &common.perms {
                            perms.push(PermEntry { name: p.name.clone(), value: p.value });
                        }
                    }
                }
                for p in &c.perms { perms.push(PermEntry { name: p.name.clone(), value: p.value }); }
                ClassEntry { name: c.name.clone(), value: c.value, perms }
            }).collect()
        }).unwrap_or_default()
    }
}
