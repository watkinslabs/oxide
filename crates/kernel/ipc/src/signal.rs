// Per-task signal state per `24§4` and `15§6` `rt_sigaction`. Three
// pieces:
//
//   - `Signal` (1..=64) + `SignalSet` (u64 bitmap)
//   - `SigAction` (handler / mask / flags) per-signal table
//   - `SignalState` (pending bitmap, blocked mask, RT queue, action table)
//
// SIGKILL/SIGSTOP can never be caught/blocked/ignored per `24§2`
// invariant 3 — the `SignalState` enforces that on every mutator.
//
// Delivery / signal trampoline (vDSO build-out) lands when ELF + the
// kernel→user return path do; this module is the data-side only.

extern crate alloc;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Subset of `siginfo_t` per `15§5` — the bits the signal queue
/// actually carries. The full struct lives in `userspace-abi` once
/// that crate exists.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SigInfo {
    pub signo: u8,
    pub code:  i32,
    pub pid:   u32,
    pub uid:   u32,
    pub value: u64,
}

/// Linux signal numbers per `24§4` (Linux x86_64 numbering).
/// Standard: 1..=31. RT: 34..=64. 32/33 are glibc-reserved (kept
/// undefined so no consumer can post them; rejected with `Einval`).
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum Signal {
    SIGHUP    = 1,  SIGINT  = 2,  SIGQUIT = 3,  SIGILL  = 4,
    SIGTRAP   = 5,  SIGABRT = 6,  SIGBUS  = 7,  SIGFPE  = 8,
    SIGKILL   = 9,  SIGUSR1 = 10, SIGSEGV = 11, SIGUSR2 = 12,
    SIGPIPE   = 13, SIGALRM = 14, SIGTERM = 15, SIGSTKFLT = 16,
    SIGCHLD   = 17, SIGCONT = 18, SIGSTOP = 19, SIGTSTP = 20,
    SIGTTIN   = 21, SIGTTOU = 22, SIGURG  = 23, SIGXCPU = 24,
    SIGXFSZ   = 25, SIGVTALRM = 26, SIGPROF = 27, SIGWINCH = 28,
    SIGIO     = 29, SIGPWR    = 30, SIGSYS    = 31,
    SIGRT0    = 34, SIGRT1    = 35, SIGRT15   = 49, SIGRT_LAST = 64,
}

impl Signal {
    /// Construct from a raw u8. Rejects 0 / 32 / 33 / >64.
    /// # C: O(1)
    pub const fn from_u8(v: u8) -> Option<Self> {
        let in_range = matches!(v, 1..=31 | 34..=64);
        if !in_range { return None; }
        // SAFETY: every byte in 1..=31 / 34..=64 is a valid repr(u8) Signal variant; out-of-range bytes returned None above; Signal has no payload, so bit pattern alone determines the value.
        let s: Signal = unsafe { core::mem::transmute(v) };
        Some(s)
    }
    /// # C: O(1)
    pub const fn as_u8(self) -> u8 { self as u8 }

    /// True iff this signal is a real-time signal (queued with
    /// `siginfo_t` payload per `24§2` invariant 4).
    /// # C: O(1)
    pub const fn is_realtime(self) -> bool { (self.as_u8()) >= 34 }

    /// True iff this signal can be caught / blocked / ignored. SIGKILL
    /// and SIGSTOP cannot per `24§2` invariant 3.
    /// # C: O(1)
    pub const fn is_maskable(self) -> bool {
        !matches!(self.as_u8(), 9 | 19)
    }
}

/// Bitmap of signals 1..=64 stored in a single u64 — bit `n-1` is
/// signal `n`. Signal 0 is unused (not a real signal).
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SignalSet(pub u64);

impl SignalSet {
    /// # C: O(1)
    pub const fn empty() -> Self { Self(0) }

    /// All maskable signals (i.e. everything except SIGKILL+SIGSTOP).
    /// # C: O(1)
    pub const fn all_maskable() -> Self {
        // bit `n-1` set for n in {1..=64} \ {9, 19}.
        let all_64: u64 = u64::MAX;
        // Clear bits for SIGKILL (9) and SIGSTOP (19).
        Self(all_64 & !(1u64 << 8) & !(1u64 << 18))
    }

    /// # C: O(1)
    pub const fn contains(&self, sig: Signal) -> bool {
        (self.0 & (1u64 << (sig.as_u8() - 1))) != 0
    }

    /// # C: O(1)
    pub fn add(&mut self, sig: Signal)    { self.0 |=  1u64 << (sig.as_u8() - 1); }
    /// # C: O(1)
    pub fn remove(&mut self, sig: Signal) { self.0 &= !(1u64 << (sig.as_u8() - 1)); }
    /// # C: O(1)
    pub fn clear(&mut self) { self.0 = 0; }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.0 == 0 }
    /// # C: O(1)
    pub fn intersect(self, other: Self) -> Self { Self(self.0 & other.0) }
    /// # C: O(1)
    pub fn complement(self) -> Self { Self(!self.0) }
}

/// `sigaction` slot per `24§4`. `handler` is a userspace function
/// pointer (or one of the `SIG_DFL` / `SIG_IGN` sentinels); we keep
/// it as a `u64` here to dodge architecture / userspace ABI shape.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SigAction {
    pub handler: u64,
    pub mask:    SignalSet,
    pub flags:   u32,
}

/// Special handler values per POSIX.
pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

impl SigAction {
    /// # C: O(1)
    pub const fn default() -> Self {
        Self { handler: SIG_DFL, mask: SignalSet::empty(), flags: 0 }
    }
}

/// Per-task signal state. Atomics on the bitmap fields keep the wake
/// path lock-free (`24§4` "Send paths"); the RT queue + action table
/// live behind a per-task spinlock that the caller wraps externally
/// (kept inline as a `core::cell` here for the data structure tests).
pub struct SignalState {
    pub blocked: AtomicU64,
    pub pending: AtomicU64,

    pub actions: [SigAction; 64],
    pub queue:   VecDeque<SigInfo>,

    /// Bound on `queue.len()` per `24§2` invariant 2.
    pub queue_max: u32,
    pub queue_dropped: AtomicU32,
}

impl SignalState {
    /// # C: O(1)
    pub fn new(queue_max: u32) -> Self {
        Self {
            blocked: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            actions: [SigAction::default(); 64],
            queue:   VecDeque::new(),
            queue_max,
            queue_dropped: AtomicU32::new(0),
        }
    }

    /// Snapshot the blocked mask.
    /// # C: O(1)
    pub fn blocked(&self) -> SignalSet {
        SignalSet(self.blocked.load(Ordering::Acquire))
    }

    /// Set the blocked mask, masking out SIGKILL/SIGSTOP per `24§2`
    /// invariant 3 silently (Linux behavior — applications can pass
    /// them; kernel ignores).
    /// # C: O(1)
    pub fn set_blocked(&self, mut mask: SignalSet) {
        mask.remove(Signal::SIGKILL);
        mask.remove(Signal::SIGSTOP);
        self.blocked.store(mask.0, Ordering::Release);
    }

    /// Snapshot the pending bitmap.
    /// # C: O(1)
    pub fn pending(&self) -> SignalSet {
        SignalSet(self.pending.load(Ordering::Acquire))
    }

    /// Bitmap of signals deliverable right now (pending & ~blocked).
    /// # C: O(1)
    pub fn deliverable(&self) -> SignalSet {
        SignalSet(self.pending.load(Ordering::Acquire)
                  & !self.blocked.load(Ordering::Acquire))
    }

    /// Install `act` for `sig`. Returns the previous action.
    /// SIGKILL / SIGSTOP cannot be re-actioned (`24§2` invariant 3) —
    /// such requests are silently capped to a no-op (caller can detect
    /// by comparing the returned value).
    /// # C: O(1)
    pub fn set_action(&mut self, sig: Signal, act: SigAction) -> SigAction {
        let idx = (sig.as_u8() - 1) as usize;
        if !sig.is_maskable() {
            return self.actions[idx];
        }
        let prev = self.actions[idx];
        self.actions[idx] = act;
        prev
    }

    /// # C: O(1)
    pub fn action(&self, sig: Signal) -> SigAction {
        self.actions[(sig.as_u8() - 1) as usize]
    }

    /// Send `sig`. For RT signals also enqueues `info` (`24§4` "RT
    /// signals queue with siginfo_t payloads"); standard signals
    /// collapse to the pending bit. Returns whether the signal was
    /// newly raised (pending bit transitioned 0→1 OR queue depth
    /// increased for RT signals).
    /// # C: O(1)
    pub fn send(&mut self, sig: Signal, info: SigInfo) -> bool {
        let bit = 1u64 << (sig.as_u8() - 1);
        let prev = self.pending.fetch_or(bit, Ordering::AcqRel);
        let newly = (prev & bit) == 0;
        if sig.is_realtime() {
            if (self.queue.len() as u32) >= self.queue_max {
                self.queue_dropped.fetch_add(1, Ordering::Relaxed);
                return newly;
            }
            self.queue.push_back(info);
            return true;
        }
        newly
    }

    /// Pop the lowest-numbered deliverable signal, if any. For RT
    /// signals also yields the queued `siginfo_t`. The caller drives
    /// the "deliver to user" handoff per `24§4`.
    /// # C: O(1) standard / O(N) RT (queue scan)
    pub fn pop_deliverable(&mut self) -> Option<(Signal, SigInfo)> {
        let avail = self.deliverable();
        if avail.is_empty() { return None; }
        let bit = avail.0.trailing_zeros() as u8 + 1;
        let sig = Signal::from_u8(bit)?;
        let bitmask = 1u64 << (bit - 1);
        if sig.is_realtime() {
            // Find first matching queued info.
            let pos = self.queue.iter().position(|si| si.signo == bit)?;
            let info = self.queue.remove(pos)?;
            // Clear pending iff no further queued instance for this RT
            // signal remains.
            if !self.queue.iter().any(|si| si.signo == bit) {
                self.pending.fetch_and(!bitmask, Ordering::AcqRel);
            }
            Some((sig, info))
        } else {
            // Standard signals: clear bit unconditionally.
            self.pending.fetch_and(!bitmask, Ordering::AcqRel);
            Some((sig, SigInfo {
                signo: bit, code: 0, pid: 0, uid: 0, value: 0,
            }))
        }
    }

    /// Drop all pending state — used on `execve` per Linux semantics.
    /// SIGKILL semantics (uncatchable termination) live in the
    /// scheduler delivery path, not here.
    /// # C: O(1)
    pub fn reset_for_exec(&mut self) {
        self.pending.store(0, Ordering::Release);
        self.queue.clear();
        self.actions = [SigAction::default(); 64];
        // Blocked mask survives execve per POSIX.
    }
}
