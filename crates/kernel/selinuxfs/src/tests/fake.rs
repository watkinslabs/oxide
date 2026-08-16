// A policy the handler tests drive, standing in for the live server.
//
// It records what was CHECKED as well as what was asked, so a test can assert
// that a handler gated a write at all — a handler that skips its permission
// check answers exactly like one that passed it, and only the record of the
// check tells them apart.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use selinux::avc::{AvDecision, CacheStats};
use selinux::sidtab::HashStats;
use vfs::{KResult, VfsError};

use crate::ops::{ClassEntry, NewContext, PermEntry, PolicyFacts, PolicyOps};

/// Context string the fake policy cannot interpret.
pub const BAD_CONTEXT: &str = "bad";

/// A policy whose every answer a test states up front.
pub struct FakeOps {
    /// Permissions the policy refuses.
    pub denied: Vec<String>,
    /// Permissions a handler checked, in order.
    pub checked: Vec<String>,
    /// Whether denials are refused.
    pub enforcing: bool,
    /// Committed and pending value of each boolean.
    pub bools: BTreeMap<String, (bool, bool)>,
    /// Commits applied.
    pub commits: u32,
    /// Decision every query answers with.
    pub avd: AvDecision,
    /// What the read-only nodes report.
    pub facts: PolicyFacts,
    /// Capability bits the policy enables.
    pub caps: u32,
    /// Image the last load accepted.
    pub image: Option<Vec<u8>>,
    /// Reclaim threshold.
    pub threshold: u32,
    /// Name the last create request carried.
    pub last_name: Option<String>,
}

impl Default for FakeOps {
    fn default() -> Self {
        Self { denied: Vec::new(), checked: Vec::new(), enforcing: false,
               bools: BTreeMap::new(), commits: 0, avd: AvDecision::init(0),
               facts: PolicyFacts::default(), caps: 0, image: None, threshold: 0,
               last_name: None }
    }
}

impl FakeOps {
    /// A policy that answers everything and refuses nothing. # C: O(1)
    pub fn allow_all() -> Self { Self::default() }

    /// A policy that refuses one permission. # C: O(1)
    pub fn denying(permission: &str) -> Self {
        Self { denied: alloc::vec![permission.to_string()], ..Self::default() }
    }

    /// Add a boolean with a committed value and no pending one. # C: O(log n)
    pub fn with_bool(mut self, name: &str, committed: bool) -> Self {
        self.bools.insert(name.to_string(), (committed, committed));
        self
    }

    /// Whether a permission was checked. # C: O(checks)
    pub fn was_checked(&self, permission: &str) -> bool {
        self.checked.iter().any(|p| p == permission)
    }
}

impl PolicyOps for FakeOps {
    fn check(&mut self, permission: &str) -> KResult<()> {
        self.checked.push(permission.to_string());
        if self.denied.iter().any(|p| p == permission) { return Err(VfsError::Eacces); }
        Ok(())
    }
    fn enforcing(&self) -> bool { self.enforcing }
    fn set_enforcing(&mut self, on: bool) -> KResult<()> { self.enforcing = on; Ok(()) }
    fn load_policy(&mut self, image: &[u8]) -> KResult<()> {
        if image.first() != Some(&b'P') { return Err(VfsError::Einval); }
        self.image = Some(image.to_vec());
        Ok(())
    }
    fn read_policy_image(&self, off: usize, buf: &mut [u8]) -> KResult<usize> {
        let image = self.image.as_ref().ok_or(VfsError::Einval)?;
        Ok(crate::nodes::plumb::copy_out(image, off as u64, buf))
    }
    fn bool_value(&self, name: &str) -> Option<(bool, bool)> { self.bools.get(name).copied() }
    fn set_bool_pending(&mut self, name: &str, value: bool) -> KResult<()> {
        let slot = self.bools.get_mut(name).ok_or(VfsError::Einval)?;
        slot.1 = value;
        Ok(())
    }
    fn commit_bools(&mut self) -> KResult<()> {
        for slot in self.bools.values_mut() { slot.0 = slot.1; }
        self.commits += 1;
        Ok(())
    }
    fn bool_names(&self) -> Vec<String> { self.bools.keys().cloned().collect() }
    fn compute_av(&mut self, scon: &str, tcon: &str, _class: u16) -> KResult<AvDecision> {
        if scon == BAD_CONTEXT || tcon == BAD_CONTEXT { return Err(VfsError::Einval); }
        Ok(self.avd)
    }
    fn canonical_context(&mut self, context: &str) -> KResult<String> {
        if context == BAD_CONTEXT { return Err(VfsError::Einval); }
        Ok(format!("canon:{context}"))
    }
    fn new_context(&mut self, kind: NewContext, scon: &str, tcon: &str, class: u16,
                   name: Option<&str>) -> KResult<String> {
        if scon == BAD_CONTEXT || tcon == BAD_CONTEXT { return Err(VfsError::Einval); }
        self.last_name = name.map(ToString::to_string);
        let which = match kind {
            NewContext::Create => "create", NewContext::Relabel => "relabel",
            NewContext::Member => "member",
        };
        Ok(format!("{which}:{scon}:{tcon}:{class}"))
    }
    fn validate_trans(&mut self, old: &str, new: &str, _class: u16, task: &str) -> KResult<()> {
        for c in [old, new, task] { if c == BAD_CONTEXT { return Err(VfsError::Einval); } }
        Ok(())
    }
    fn cache_threshold(&self) -> u32 { self.threshold }
    fn set_cache_threshold(&mut self, n: u32) { self.threshold = n; }
    fn avc_hash_stats(&self) -> HashStats {
        HashStats { entries: 3, buckets: 512, used_buckets: 2, longest_chain: 2 }
    }
    fn avc_cache_stats(&self) -> CacheStats {
        CacheStats { lookups: 9, misses: 4, allocations: 4, reclaims: 1, frees: 2 }
    }
    fn sidtab_hash_stats(&self) -> HashStats {
        HashStats { entries: 5, buckets: 128, used_buckets: 4, longest_chain: 2 }
    }
    fn facts(&self) -> PolicyFacts { self.facts }
    fn policycap(&self, bit: u32) -> bool { self.caps & (1 << bit) != 0 }
    fn initial_context(&self, sid: u32) -> Option<String> { Some(format!("initial:{sid}")) }
    fn classes(&self) -> Vec<ClassEntry> {
        alloc::vec![ClassEntry { name: "file".to_string(), value: 6,
            perms: alloc::vec![PermEntry { name: "read".to_string(), value: 2 },
                               PermEntry { name: "write".to_string(), value: 3 }] }]
    }
}
