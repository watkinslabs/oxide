// Delegation breaking on MUTATION — the second half of the lease contract.
//
// A conflicting OPEN breaks leases and delegations alike (`open.rs`). A
// mutation — create, unlink, rmdir, rename, link, setattr — breaks
// DELEGATIONS ONLY, on the directory it changes and on the file it changes,
// and it must complete the break before the change lands. Without this a
// delegation holder is never told its cached copy went stale.
//
// Two-phase, so a caller may release whatever it holds before it sleeps:
// [`try_break_deleg`] never sleeps and answers `EAGAIN` with the inode
// recorded, [`break_deleg_wait`] sleeps on the recorded inode. [`break_deleg`]
// is the loop over the pair, for a caller holding nothing across the break.

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::inode::InodeRef;
use crate::types::{KResult, VfsError};

use super::lease_policy::FL_DELEG;
use super::{lease_break_signal, lease_conflict, lease_force_break};

/// A mutation always demands the delegation back in full: there is no
/// "downgrade" answer to a change that already happened.
const DELEG_BREAK_WRITES: bool = true;

/// Scheduler boundary for the blocking half of a delegation break, matching the
/// file-lock / quota / rwsem wait hooks: the VFS owns the lease contract, the
/// scheduler owns sleeping and the break-time deadline. `true` = the conflict
/// is gone (released or force-broken), `false` = a deliverable signal arrived.
pub type DelegBreakWaitHook = fn(&InodeRef) -> bool;

static DELEG_WAIT_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the sleeping half of the delegation break. # C: O(1)
pub fn set_deleg_wait_hook(h: DelegBreakWaitHook) {
    DELEG_WAIT_HOOK.store(h as usize, Ordering::Release);
}

/// The inode a non-blocking break asked the caller to wait on, held across the
/// caller's lock release. Empty until a break actually blocks, so the common
/// no-delegation mutation refcounts nothing.
pub struct DelegatedInode(Option<InodeRef>);

impl DelegatedInode {
    /// A fresh, empty slot. # C: O(1)
    pub fn new() -> Self { Self(None) }

    /// True once a break has parked an inode here for the caller to wait on.
    /// # C: O(1)
    pub fn is_delegated(&self) -> bool { self.0.is_some() }
}

impl Default for DelegatedInode {
    /// # C: O(1)
    fn default() -> Self { Self::new() }
}

/// Non-blocking delegation break. Signals every conflicting delegation holder
/// on `inode` once, then answers:
///
///   * `Ok(())` — no delegation stands in the way; the mutation may proceed;
///   * `Err(Eagain)` — a holder must answer first. `di` now names the inode, and
///     the caller must release its locks, call [`break_deleg_wait`], and retry
///     the operation from the top.
///
/// A plain lease is NOT disturbed: only a conflicting open breaks those.
/// Zero-cost when nothing on the system holds a lease: one relaxed load.
/// # C: O(1) common, O(N_leases) when a lease exists
pub fn try_break_deleg(inode: &InodeRef, di: &mut DelegatedInode) -> KResult<()> {
    if !lease_conflict(inode, FL_DELEG, DELEG_BREAK_WRITES) { return Ok(()); }
    lease_break_signal(inode, FL_DELEG, DELEG_BREAK_WRITES);
    // The holder may have released while being signalled — re-test rather than
    // blocking a caller whose way is already clear.
    if !lease_conflict(inode, FL_DELEG, DELEG_BREAK_WRITES) { return Ok(()); }
    di.0 = Some(inode.clone());
    Err(VfsError::Eagain)
}

/// Block until the delegation recorded by [`try_break_deleg`] is gone, then
/// clear the slot. The holder either releases within the break time or the
/// delegation is force-broken and the mutation proceeds; a deliverable signal
/// aborts the wait with `EINTR`. With no scheduler installed (hosted callers,
/// early boot) there is nobody to wait for the holder to be scheduled, so the
/// break completes immediately — the same outcome the break time reaches.
/// # C: sleeps up to the break time
pub fn break_deleg_wait(di: &mut DelegatedInode) -> KResult<()> {
    let Some(inode) = di.0.take() else { return Ok(()); };
    let h = DELEG_WAIT_HOOK.load(Ordering::Acquire);
    if h == 0 {
        lease_force_break(&inode, FL_DELEG, DELEG_BREAK_WRITES);
        return Ok(());
    }
    // SAFETY: h was stored by `set_deleg_wait_hook` from a DelegBreakWaitHook
    // fn pointer; the cast restores that exact signature and nothing else is
    // ever stored in this slot.
    let f: DelegBreakWaitHook = unsafe { core::mem::transmute(h) };
    if f(&inode) { Ok(()) } else { Err(VfsError::Eintr) }
}

/// [`try_break_deleg`] + [`break_deleg_wait`] for a caller that holds nothing
/// across the break and can wait in place. Returns once no delegation conflicts
/// with the pending mutation. # C: O(1) common; sleeps when a delegation exists
pub fn break_deleg(inode: &InodeRef) -> KResult<()> {
    let mut di = DelegatedInode::new();
    loop {
        match try_break_deleg(inode, &mut di) {
            Ok(())                => return Ok(()),
            Err(VfsError::Eagain) => break_deleg_wait(&mut di)?,
            Err(e)                => return Err(e),
        }
    }
}
