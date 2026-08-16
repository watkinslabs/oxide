// The policy operations a node handler acts through.
//
// Every handler in `nodes` takes `&mut dyn PolicyOps` rather than reaching
// for the live server, so the decision each node makes — which permission
// gates it, what it refuses, what it renders — is a function over values and
// is exercised hosted. A handler that reached for the global directly could
// only be tested by booting, which is how a missing permission check ships.

use alloc::string::String;
use alloc::vec::Vec;

use selinux::avc::{AvDecision, CacheStats};
use selinux::sidtab::HashStats;
use vfs::{KResult, VfsError};

/// Which new-context question a transaction node asks.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NewContext {
    /// Context of an object the subject creates.
    Create,
    /// Context an object takes when relabelled.
    Relabel,
    /// Context of a polyinstantiated member.
    Member,
}

/// Facts about the loaded policy that the read-only nodes publish.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyFacts {
    /// Whether a policy has been loaded at all.
    pub loaded: bool,
    /// Whether the loaded policy carries MLS levels and categories.
    pub mls: bool,
    /// Whether the policy refuses to load against an unknown class.
    pub reject_unknown: bool,
    /// Whether the policy denies permissions on classes it does not know.
    pub deny_unknown: bool,
    /// Sequence number the last policy load or boolean commit produced.
    pub seqno: u32,
    /// Policy loads since boot.
    pub policyload: u32,
}

/// One permission of one class, as the `class/` tree publishes it.
pub struct PermEntry {
    /// Permission name.
    pub name: String,
    /// 1-based value within the class's access vector.
    pub value: u32,
}

/// One class of the loaded policy, as the `class/` tree publishes it.
pub struct ClassEntry {
    /// Class name.
    pub name: String,
    /// 1-based class value.
    pub value: u32,
    /// Permissions of the class, inherited ones included.
    pub perms: Vec<PermEntry>,
}

/// What a node handler may ask of the policy.
pub trait PolicyOps {
    /// Whether the caller may act on the security server this way. # C: O(1) cached
    fn check(&mut self, permission: &str) -> KResult<()>;

    /// Whether denials are refused rather than only reported. # C: O(1)
    fn enforcing(&self) -> bool;

    /// Change the enforcement mode. # C: O(1)
    fn set_enforcing(&mut self, on: bool) -> KResult<()>;

    /// Replace the loaded policy with this image. # C: O(image)
    fn load_policy(&mut self, image: &[u8]) -> KResult<()>;

    /// Copy out part of the loaded image; `0` at or past its end. # C: O(buf)
    fn read_policy_image(&self, off: usize, buf: &mut [u8]) -> KResult<usize>;

    /// Committed and pending value of one boolean. # C: O(booleans)
    fn bool_value(&self, name: &str) -> Option<(bool, bool)>;

    /// Stage a boolean value without committing it. # C: O(booleans)
    fn set_bool_pending(&mut self, name: &str, value: bool) -> KResult<()>;

    /// Apply every staged boolean value at once. # C: O(conditional rules)
    fn commit_bools(&mut self) -> KResult<()>;

    /// Boolean names in policy order. # C: O(booleans)
    fn bool_names(&self) -> Vec<String>;

    /// Full decision for a written subject, object and class. # C: O(1) cached
    fn compute_av(&mut self, scon: &str, tcon: &str, class: u16) -> KResult<AvDecision>;

    /// Canonical rendering of a written context. # C: O(categories)
    fn canonical_context(&mut self, context: &str) -> KResult<String>;

    /// Context of a created, relabelled or member object. # C: O(rules)
    fn new_context(&mut self, kind: NewContext, scon: &str, tcon: &str, class: u16,
                   name: Option<&str>) -> KResult<String>;

    /// Whether a relabel from one context to another is permitted. # C: O(constraints)
    fn validate_trans(&mut self, old: &str, new: &str, class: u16, task: &str) -> KResult<()>;

    /// Entry count above which the decision cache reclaims. # C: O(1)
    fn cache_threshold(&self) -> u32;

    /// Set the reclaim threshold. # C: O(1)
    fn set_cache_threshold(&mut self, n: u32);

    /// Bucket shape of the decision cache. # C: O(slots)
    fn avc_hash_stats(&self) -> HashStats;

    /// Activity counters of the decision cache. # C: O(1)
    fn avc_cache_stats(&self) -> CacheStats;

    /// Bucket shape of the SID table. # C: O(buckets)
    fn sidtab_hash_stats(&self) -> HashStats;

    /// What the read-only nodes report about the loaded policy. # C: O(1)
    fn facts(&self) -> PolicyFacts;

    /// Whether the loaded policy enables one capability bit. # C: O(log chunks)
    fn policycap(&self, bit: u32) -> bool;

    /// Rendered context of one initial SID. # C: O(categories)
    fn initial_context(&self, sid: u32) -> Option<String>;

    /// Classes and permissions of the loaded policy. # C: O(classes × perms)
    fn classes(&self) -> Vec<ClassEntry>;
}

/// Refusal a denied permission produces at this interface. # C: O(1)
///
/// A denial is `EACCES`, never a silent success: userspace reads the write's
/// return value to decide whether the state it asked for is the state that
/// now holds.
pub const fn denied() -> VfsError { VfsError::Eacces }

/// Refusal a malformed request produces. # C: O(1)
pub const fn malformed() -> VfsError { VfsError::Einval }
