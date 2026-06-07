// landlock_create_ruleset / landlock_add_rule / landlock_restrict_self
// per Linux landlock(7). Per-task chain stored on Task; namei
// check hook (`security::landlock::chain_permits`) walks the chain
// on every path-based syscall.
//
// `landlock_create_ruleset` allocates a registry entry and returns
// an anonymous fd backed by a `LandlockRulesetInode` carrying the
// ruleset id. `landlock_add_rule` resolves the fd → inode → id,
// then appends a (path, allowed_access) rule. `landlock_restrict
// _self` pushes the id onto the calling task's landlock_chain.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::errno::Errno;

use ::security::landlock::{self as ll};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// /sys/landlock anonymous-fd inode carrying a ruleset id.
pub struct LandlockRulesetInode {
    pub ruleset_id: u64,
}

impl Inode for LandlockRulesetInode {
    fn ino(&self) -> Ino { 0x4C4E_4400_0000_0000 | self.ruleset_id }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Check `(path, op)` against the calling task's landlock chain.
/// Returns Ok(()) when every entry in the chain allows the op;
/// Err(-EACCES-as-i64) on first denial. Empty chain = unrestricted.
/// Called from path-based syscalls (openat, unlinkat, …) before
/// the actual VFS work.
/// # C: O(N_chain × N_rules)
pub fn check(path: &str, op: u64) -> Result<(), i64> {
    let cur = match sched::live::current() { Some(c) => c, None => return Ok(()) };
    let chain_ids = cur.landlock_chain.lock().clone();
    if chain_ids.is_empty() { return Ok(()); }
    let chain: alloc::vec::Vec<Arc<ll::Ruleset>> =
        chain_ids.into_iter().filter_map(ll::lookup).collect();
    if ll::chain_permits(&chain, path, op) { Ok(()) }
    else { Err(-(Errno::Eacces.as_i32() as i64)) }
}
