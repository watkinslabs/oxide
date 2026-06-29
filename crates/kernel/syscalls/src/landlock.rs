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
use vfs::{FileType, Inode, InodeRef, KResult, VfsError};
use vfs::{InodeBuilder, default_inode_ops, mk_mode};
use vfs::FileOps;

/// `/sys/landlock` anonymous-fd backend state (`i_private`) carrying a ruleset
/// id. Post-KEYSTONE: the inode is a concrete `vfs::Inode` whose `i_private`
/// is this struct; the data path lives in [`LandlockFileOps`].
pub struct LandlockRulesetInode {
    pub ruleset_id: u64,
}

/// `file_operations` for a landlock ruleset fd: not a data stream — `read`/
/// `write` are `Eio` (Linux landlock fds are config handles, not readable).
/// # C: O(1)
struct LandlockFileOps;
impl FileOps for LandlockFileOps {
    fn read(&self, _inode: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _inode: &Inode, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Construct a landlock ruleset anon inode carrying `ruleset_id`. The ino keeps
/// the old `"LND"`-tagged marker (`0x4C4E_4400…`). # C: O(1)
pub fn make_landlock_inode(ruleset_id: u64) -> InodeRef {
    let ino = 0x4C4E_4400_0000_0000 | ruleset_id;
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), Arc::new(LandlockFileOps))
        .private(Arc::new(LandlockRulesetInode { ruleset_id }))
        .build()
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
