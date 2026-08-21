// Generic cross-CPU function call (`smp_call_function_many` equivalent).
//
// ONE cross-CPU call mechanism exists in this kernel and this is its
// boundary. The reference has no private TLB-shootdown vector: its
// `flush_tlb_multi` goes through `on_each_cpu_mask` onto the same
// call-function queue every other cross-CPU request uses, and a second
// vector with its own protocol would be a parallel mechanism that could
// disagree with the first about who has acknowledged what. `tlb.rs` is
// therefore a caller of this module, not a peer of it.
//
// WHAT A CALL KIND MAY DO. The drain runs from IRQ context AND from the
// spin-relax hook, i.e. from inside an arbitrary lock's spin loop with
// this CPU's interrupts possibly masked. A handler therefore must take no
// lock, never sleep, be idempotent, and be reentrant against itself. That
// contract is why the kinds are a closed enum rather than a raw function
// pointer: every handler is auditable in one place, and a caller cannot
// smuggle a lock-taking closure into a context that would deadlock on it.
// Adding a kind is a one-line change plus a handler that meets the
// contract above.
//
// The hook is unset only before arch bring-up and in the hosted harness.
// Arm64 still bypasses queued TLB invalidations because its broadcast TLBI
// reaches every CPU in hardware, but other call kinds use its SGI transport.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// What a queued cross-CPU call asks the target to do.
///
/// `repr(u32)` because the queue that carries these is kind-agnostic — it
/// moves an opaque `(u32, u64)` pair and never interprets it, which keeps
/// the queue protocol testable without any arch or subsystem in scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CallKind {
    /// Invalidate `arg` in the local TLB, or the whole local TLB when
    /// `arg == ALL`. The reference's `flush_tlb_func`.
    TlbFlush = 1,
    /// Reload LDTR from the address space whose page-table root is `arg`,
    /// but only if this CPU currently has that address space loaded. The
    /// reference's `flush_ldt`.
    LdtReload = 2,
    /// Record this CPU as stopped and park it forever — the reference's
    /// reboot IPI, used to take every other CPU off the machine before a
    /// kexec relocation overwrites the pages they are executing out of.
    ///
    /// The one handler that never returns, and the only one for which that is
    /// correct: its caller must not wait on the queue slot (`wait: false`) and
    /// waits on [`stopped_words`] instead, which the handler publishes BEFORE
    /// it parks.
    Stop = 3,
    /// Full memory barrier for a globally registered membarrier target.
    MembarrierGlobalMb = 4,
    /// Full memory barrier for a target still running the address space named
    /// by `arg`.
    MembarrierPrivateMb = 5,
    /// Private membarrier barrier plus core serialization for `arg`'s current
    /// address space.
    MembarrierPrivateSyncCore = 6,
    /// Private membarrier barrier plus restartable-sequence fixup for `arg`'s
    /// current address space.
    MembarrierPrivateRseq = 7,
    /// Program a self-contained CPU-frequency command. The target handler
    /// takes no lock and performs only the admitted register write.
    CpuFreq = 8,
    /// Enter the architecture CPU-hotplug play-dead state after publishing
    /// the canonical online-set transition. `arg` identifies the sender whose
    /// queue slot must be released before the target stops executing.
    CpuOffline = 9,
}

impl CallKind {
    /// Wire value stored in a queue slot.
    /// # C: O(1)
    pub const fn as_u32(self) -> u32 { self as u32 }

    /// Recover a kind from a slot. `None` for a value no kind uses, which
    /// the drain treats as a corrupt slot rather than guessing.
    /// # C: O(1)
    pub const fn from_u32(v: u32) -> Option<CallKind> {
        match v {
            1 => Some(CallKind::TlbFlush),
            2 => Some(CallKind::LdtReload),
            3 => Some(CallKind::Stop),
            4 => Some(CallKind::MembarrierGlobalMb),
            5 => Some(CallKind::MembarrierPrivateMb),
            6 => Some(CallKind::MembarrierPrivateSyncCore),
            7 => Some(CallKind::MembarrierPrivateRseq),
            8 => Some(CallKind::CpuFreq),
            9 => Some(CallKind::CpuOffline),
            _ => None,
        }
    }
}

/// Sentinel VA meaning "flush everything", not a single page. `u64::MAX` is
/// never a valid user VA.
pub const ALL: u64 = u64::MAX;

/// CPUs that have run [`CallKind::Stop`] and parked.
///
/// Lives beside the kind rather than in the subsystem that asks for the stop:
/// the handler is here, and a counter kept elsewhere would be a second record
/// of the same fact that only one of the two updates.
/// Fixed word capacity of the architecture stop transport.
pub const STOPPED_WORDS: usize = crate::MAX_SMP_CPUS.div_ceil(u64::BITS as usize);

static STOPPED: [AtomicU64; STOPPED_WORDS] = [const { AtomicU64::new(0) }; STOPPED_WORDS];

/// Record `cpu` as stopped. Called by the handler immediately before it parks,
/// so a waiter that observes the bit knows the CPU is no longer executing
/// anything that could be relocated out from under it.
/// # C: O(1)
pub fn mark_stopped(cpu: u32) {
    let word = cpu as usize / u64::BITS as usize;
    if word < STOPPED_WORDS { STOPPED[word].fetch_or(1u64 << (cpu % u64::BITS), Ordering::Release); }
}

/// The set of parked CPUs.
/// # C: O(words)
pub fn stopped_words() -> [u64; STOPPED_WORDS] {
    let mut words = [0; STOPPED_WORDS];
    let mut i = 0;
    while i < STOPPED_WORDS {
        words[i] = STOPPED[i].load(Ordering::Acquire);
        i += 1;
    }
    words
}

/// `fn(mask, kind, arg, wait)`. Stored as `usize` because `AtomicPtr` over a
/// function pointer is not a stable atomic form; only `set_call_hook` writes
/// it and only with a value of this exact type, so the cast back is sound.
static HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the arch implementation. Called once at boot, after AP bring-up
/// and after the call-function IDT vector is live.
/// # SAFETY: caller is the boot path; `f` lives for the kernel lifetime and
/// no other CPU can be issuing a cross-CPU call at install time.
/// # C: O(1)
pub unsafe fn set_call_hook(f: fn(&[u64], u32, u64, bool)) {
    HOOK.store(f as usize, Ordering::Release);
}

/// True once an arch implementation is installed. Callers that must not
/// silently skip convergence check this rather than assuming.
/// # C: O(1)
#[inline]
pub fn available() -> bool { HOOK.load(Ordering::Acquire) != 0 }

/// Run `kind`/`arg` on every online CPU in `mask` except this one, and when
/// `wait` is set do not return until each has finished running it.
///
/// `wait` is what makes a free-after-converge safe: the handler having RUN
/// on every target happens-before this returns, so a caller may release the
/// resource the handler was told to stop using. Without it the call is only
/// a request.
///
/// No-op before `set_call_hook` (UP boot or hosted harness).
/// # C: O(popcount(mask)) + IPI round-trip
#[inline]
pub fn call_function_many(mask: &[u64], kind: CallKind, arg: u64, wait: bool) {
    let p = HOOK.load(Ordering::Acquire);
    if p == 0 { return; }
    // SAFETY: only `set_call_hook` writes HOOK, and only with a
    // `fn(&[u64], u32, u64, bool)`; casting back to that same type is sound.
    let f: fn(&[u64], u32, u64, bool) = unsafe { core::mem::transmute(p) };
    f(mask, kind.as_u32(), arg, wait);
}

#[cfg(test)]
mod tests;
