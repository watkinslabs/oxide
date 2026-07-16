use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::PollSubscribers;
use vmm::AddressSpace;

use super::Task;
use crate::signum::{self, DefaultAction, Signum};

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SIGACTION_COUNT: usize = 64;
const SA_NOCLDSTOP: u64 = 0x00000001;
const SA_NOCLDWAIT: u64 = 0x00000002;
const SA_SIGINFO:   u64 = 0x00000004;
const SA_RESTORER:  u64 = 0x04000000;
const SA_ONSTACK:   u64 = 0x08000000;
const SA_RESTART:   u64 = 0x10000000;
const SA_NODEFER:   u64 = 0x40000000;
const SA_RESETHAND: u64 = 0x80000000;
const UAPI_SA_FLAGS: u64 = SA_NOCLDSTOP | SA_NOCLDWAIT | SA_SIGINFO | SA_RESTORER
    | SA_ONSTACK | SA_RESTART | SA_NODEFER | SA_RESETHAND;
const UNBLOCKABLE_MASK: u64 = Signum::Sigkill.bit() | Signum::Sigstop.bit();
pub const SIG_BLOCK:   u64 = 0;
pub const SIG_UNBLOCK: u64 = 1;
pub const SIG_SETMASK: u64 = 2;

/// Pending-signal bitmap plus the wait source shared with signalfd inodes.
pub struct SignalPending {
    bits: AtomicU64,
    poll: Arc<PollSubscribers>,
}

impl SignalPending {
    /// Empty pending set with a fresh signal wait source. # C: O(1)
    pub fn new() -> Self {
        Self { bits: AtomicU64::new(0), poll: Arc::new(PollSubscribers::new()) }
    }

    /// Atomic pending-set snapshot. # C: O(1)
    pub fn load(&self, order: Ordering) -> u64 { self.bits.load(order) }

    /// Post pending bits and notify signalfd pollers on a real 0-to-1 transition. # C: O(N_subscribers)
    pub fn fetch_or(&self, bits: u64, order: Ordering) -> u64 {
        let prior = self.bits.fetch_or(bits, order);
        if bits & !prior != 0 { self.poll.notify_mask(vfs::POLL_IN); }
        prior
    }

    /// Clear pending bits without producing a readiness event. # C: O(1)
    pub fn fetch_and(&self, bits: u64, order: Ordering) -> u64 { self.bits.fetch_and(bits, order) }

    /// Clone the source signalfd inodes expose to epoll. # C: O(1)
    pub fn poll_subscribers(&self) -> Arc<PollSubscribers> { Arc::clone(&self.poll) }
}

impl Default for SignalPending {
    fn default() -> Self { Self::new() }
}

/// Linux `struct sigaction` core fields per `27§3`.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SaHandler {
    /// Handler entry. `0` = SIG_DFL (default disposition); `1` =
    /// SIG_IGN (ignore). Anything else = user fn pointer.
    pub handler:   u64,
    /// `SA_*` flags (Linux: SA_SIGINFO=0x4, SA_RESTART=0x10000000,
    /// SA_NOCLDSTOP, SA_NODEFER, etc.).
    pub flags:     u64,
    /// Optional return-trampoline (sa_restorer). musl + glibc set
    /// this to a libc-private stub that issues `rt_sigreturn`.
    pub restorer:  u64,
    /// Per-handler additional mask applied during dispatch.
    pub mask:      u64,
}

pub struct SigActions {
    table: Spinlock<[SaHandler; SIGACTION_COUNT], TaskListClass>,
}

impl SigActions {
    /// Fresh Linux sighand action table. # C: O(1)
    pub fn new() -> Self { Self { table: Spinlock::new([SaHandler::default(); SIGACTION_COUNT]) } }

    /// Deep-copy action table for fork/clone without CLONE_SIGHAND. # C: O(64)
    pub fn fork_clone(&self) -> Self { Self { table: Spinlock::new(*self.table.lock()) } }

    /// Read one action slot for signal delivery. # C: O(1)
    pub fn get(&self, sig: u32) -> SaHandler { self.table.lock()[(sig - 1) as usize] }

    /// Reset caught handlers at execve. # C: O(64)
    pub fn reset_caught(&self) {
        let mut t = self.table.lock();
        for slot in t.iter_mut() {
            if slot.handler != SIG_DFL && slot.handler != SIG_IGN {
                *slot = SaHandler::default();
            }
        }
    }

    /// Linux do_sigaction core: validate, snapshot old, sanitize, install.
    /// # C: O(1) plus ignored-signal flush below.
    pub fn set_action(&self, sig: usize, act: Option<SaHandler>) -> Result<SaHandler, ()> {
        if sig == 0 || sig > SIGACTION_COUNT || act.is_some() && signum::is_unblockable(sig as u32) {
            return Err(());
        }
        let idx = sig - 1;
        let mut t = self.table.lock();
        let old = sanitize_action(t[idx]);
        if let Some(mut new) = act {
            new.flags = sanitize_flags(new.flags);
            new.mask  = sanitize_mask(new.mask);
            t[idx] = new;
        }
        Ok(old)
    }
}

impl Default for SigActions {
    fn default() -> Self { Self::new() }
}

fn sanitize_flags(flags: u64) -> u64 { flags & UAPI_SA_FLAGS }
fn sanitize_mask(mask: u64) -> u64 { mask & !UNBLOCKABLE_MASK }
fn sanitize_action(mut act: SaHandler) -> SaHandler {
    act.flags = sanitize_flags(act.flags);
    act.mask = sanitize_mask(act.mask);
    act
}

fn apply_sigprocmask(prior: u64, how: u64, set: u64) -> Result<u64, ()> {
    let new = match how {
        SIG_BLOCK   => prior | set,
        SIG_UNBLOCK => prior & !set,
        SIG_SETMASK => set,
        _           => return Err(()),
    };
    Ok(sanitize_mask(new))
}

fn ignores_signal(sig: usize, act: SaHandler) -> bool {
    act.handler == SIG_IGN
        || act.handler == SIG_DFL && signum::default_action(sig as u32) == DefaultAction::Ign
}

impl Task {
    /// Borrow the shared sighand table. # C: O(1)
    pub fn sigactions_ref(&self) -> &SigActions {
        // SAFETY: the Arc slot is replaced only before a child is scheduled; the shared table behind it is internally locked.
        unsafe { &*self.sigactions.get() }
    }

    /// Clone the shared sighand pointer for CLONE_SIGHAND. # C: O(1)
    pub fn sigactions_arc(&self) -> Arc<SigActions> {
        // SAFETY: the Arc slot is stable for scheduled tasks; cloning only bumps the Arc refcount.
        unsafe { Arc::clone(&*self.sigactions.get()) }
    }

    /// Replace a not-yet-scheduled child's sighand pointer. # C: O(1)
    /// # SAFETY: caller must be the sole owner/mutator before runqueue publication.
    pub unsafe fn replace_sigactions(&self, new: Arc<SigActions>) {
        // SAFETY: caller guarantees child publication has not happened, so no concurrent readers can observe the slot replacement.
        unsafe { *self.sigactions.get() = new; }
    }

    /// Linux rt_sigaction work function after syscall copy-in. # C: O(N_threads)
    pub fn rt_sigaction(&self, sig: usize, act: Option<SaHandler>) -> Result<SaHandler, ()> {
        let old = self.sigactions_ref().set_action(sig, act)?;
        if act.map(|a| ignores_signal(sig, a)).unwrap_or(false) {
            self.flush_pending_signal_group(sig);
        }
        Ok(old)
    }

    /// Linux rt_sigprocmask work function after syscall copy-in. # C: O(1)
    pub fn rt_sigprocmask(&self, how: u64, set: Option<u64>) -> Result<u64, ()> {
        let prior = self.sigmask.load(Ordering::Acquire);
        if let Some(mask) = set {
            let new = apply_sigprocmask(prior, how, mask)?;
            self.set_current_blocked(new);
        }
        Ok(prior)
    }

    /// Linux set_current_blocked for user-originated masks. # C: O(1)
    pub fn set_current_blocked(&self, mask: u64) {
        self.sigmask.store(sanitize_mask(mask), Ordering::Release);
    }

    /// Clear a newly ignored signal from this thread group. # C: O(N_threads)
    pub fn flush_pending_signal_group(&self, sig: usize) {
        #[cfg(target_os = "oxide-kernel")]
        {
            let tgid = self.tgid.load(Ordering::Acquire);
            for (_vtid, tid) in crate::registry::thread_entries(tgid) {
                if let Some(t) = crate::registry::lookup(tid) { t.flush_pending_signal(sig); }
            }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        self.flush_pending_signal(sig);
    }

    /// Clear one pending signal and its queued payloads. # C: O(1)
    pub fn flush_pending_signal(&self, sig: usize) {
        if sig == 0 || sig > SIGACTION_COUNT { return; }
        self.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
        if sig == Signum::Sigchld as usize { self.child_sigq.lock().clear(); }
        if let Some(idx) = crate::signum::rt_index(sig as u32) { self.rt_sigqueue.lock()[idx].clear(); }
    }

    /// Borrow `mm` (the `Arc<AddressSpace>` if set). Read-only;
    /// callers must observe the single-mutator invariant per the
    /// `mm` field doc.
    /// # SAFETY: caller is in IRQ-off / preempt-off context, OR
    /// holds a guarantee that no concurrent execve runs against
    /// this task on another CPU.
    /// # C: O(1)
    pub unsafe fn mm_ref(&self) -> Option<&Arc<AddressSpace>> {
        self.debug_check_canary("mm_ref");
        // SAFETY: caller asserts no concurrent writer; UnsafeCell::get is the supported deref pattern for shared interior mutability under documented external synchronization.
        unsafe { (&*self.mm.get()).as_ref() }
    }

    /// Soft `RLIMIT_NOFILE` — the per-task fd ceiling the fd-alloc path
    /// enforces (Linux `rlimit(RLIMIT_NOFILE)`); fd installs beyond it
    /// → EMFILE. Source for every `FdTable::alloc_limit` call site.
    /// # C: O(1)
    pub fn nofile_soft(&self) -> usize {
        // SAFETY: rlimits is single-mutator per the running task on this CPU (same invariant as `mm`); reads one (cur,max) slot only.
        unsafe { (*self.rlimits.get())[crate::rlimit::rlim::NOFILE].0 as usize }
    }

    /// Atomically replace `mm` with `new`. The displaced Arc is NOT dropped
    /// here — it is parked in this CPU's `active_mm` slot (Linux `exit_mm`
    /// keeps `active_mm`+`mm_count`; `mmdrop` runs after the next switch):
    /// on exit/signal-death the caller clears `mm` BEFORE the final
    /// `schedule()`, so an in-place drop of the last Arc would free the
    /// page-table root while it is still live in CR3/TTBR0 (GAP-2
    /// use-after-free → random exec/ld.so corruption). `execve` is safe by
    /// ordering (it `activate`s the new root BEFORE calling this) but parks
    /// through the same choke-point.
    /// # SAFETY: caller is the running task on its CPU OR holds
    /// the runqueue invariant for this task; preempt-off. Not safe
    /// to call on an actively-scheduled task from another CPU.
    /// # C: O(1)
    pub unsafe fn replace_mm(&self, new: Option<Arc<AddressSpace>>) {
        self.debug_check_canary("replace_mm");
        // SAFETY: see fn-level contract; single-mutator on this CPU.
        let old = unsafe { core::mem::replace(&mut *self.mm.get(), new) };
        #[cfg(target_os = "oxide-kernel")]
        if let Some(m) = old { crate::live::schedule::park_active_mm(m); }
        #[cfg(not(target_os = "oxide-kernel"))]
        drop(old); // hosted: no live CR3 to protect
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rt_sigaction_sanitizes_flags_and_mask() {
        let sa = SigActions::new();
        let input = SaHandler { handler: 0x1234, flags: u64::MAX, restorer: 0x5678, mask: u64::MAX };
        assert_eq!(sa.set_action(Signum::Sigusr1 as usize, Some(input)), Ok(SaHandler::default()));
        let got = sa.get(Signum::Sigusr1 as u32);
        assert_eq!(got.flags, UAPI_SA_FLAGS);
        assert_eq!(got.mask & UNBLOCKABLE_MASK, 0);
    }

    #[test]
    fn rt_sigaction_rejects_catching_unblockable_signals() {
        let sa = SigActions::new();
        let input = SaHandler { handler: 0x1234, flags: 0, restorer: 0, mask: 0 };
        assert_eq!(sa.set_action(Signum::Sigkill as usize, Some(input)), Err(()));
        assert_eq!(sa.set_action(Signum::Sigstop as usize, Some(input)), Err(()));
        assert_eq!(sa.set_action(Signum::Sigkill as usize, None), Ok(SaHandler::default()));
    }

    #[test]
    fn rt_sigprocmask_ignores_how_when_set_is_null() {
        let prior = Signum::Sigusr1.bit();
        assert_eq!(Ok(prior), sigprocmask_snapshot(prior, 999, None));
    }

    #[test]
    fn rt_sigprocmask_rejects_bad_how_when_set_exists() {
        let prior = Signum::Sigusr1.bit();
        assert_eq!(Err(()), sigprocmask_snapshot(prior, 999, Some(Signum::Sigusr2.bit())));
    }

    #[test]
    fn rt_sigprocmask_applies_block_unblock_and_setmask() {
        let usr1 = Signum::Sigusr1.bit();
        let usr2 = Signum::Sigusr2.bit();
        assert_eq!(Ok(usr1 | usr2), sigprocmask_snapshot(usr1, SIG_BLOCK, Some(usr2)));
        assert_eq!(Ok(usr1), sigprocmask_snapshot(usr1 | usr2, SIG_UNBLOCK, Some(usr2)));
        assert_eq!(Ok(usr2), sigprocmask_snapshot(usr1, SIG_SETMASK, Some(usr2)));
    }

    #[test]
    fn rt_sigprocmask_strips_unblockable_signals() {
        let set = Signum::Sigusr1.bit() | Signum::Sigkill.bit() | Signum::Sigstop.bit();
        assert_eq!(Ok(Signum::Sigusr1.bit()), sigprocmask_snapshot(0, SIG_SETMASK, Some(set)));
    }

    #[test]
    fn set_current_blocked_strips_unblockable_signals() {
        assert_eq!(Signum::Sigusr2.bit(), sanitize_mask(Signum::Sigusr2.bit() | UNBLOCKABLE_MASK));
    }

    fn sigprocmask_snapshot(prior: u64, how: u64, set: Option<u64>) -> Result<u64, ()> {
        match set {
            Some(mask) => apply_sigprocmask(prior, how, mask),
            None => Ok(prior),
        }
    }
}
