// `ARCH_SHSTK_{ENABLE,DISABLE,LOCK,UNLOCK,STATUS}` rules — Linux
// `shstk_prctl`.
//
// A current Linux ships user-shadow-stack support compiled IN, so these five
// codes are NOT uniformly EINVAL on a CPU that lacks the hardware: STATUS and
// LOCK succeed unconditionally (they only touch per-thread bookkeeping), and
// only the paths that must actually program `MSR_IA32_U_CET` fall to
// EOPNOTSUPP. Answering EINVAL everywhere tells a runtime "this kernel has
// never heard of shadow stacks", which is a different fact from "this CPU
// cannot provide them" and steers glibc's CET probe down the wrong branch.

use syscall::errno::Errno;
use syscall::nrs;

/// Per-thread `thread.features` / `thread.features_locked`. Both are bit sets
/// over `ARCH_SHSTK_SHSTK` | `ARCH_SHSTK_WRSS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShstkState {
    /// `thread.features` — which facilities are ENABLED for this thread.
    pub features: u64,
    /// `thread.features_locked` — which may no longer be changed.
    pub locked: u64,
}

impl ShstkState {
    /// Linux `reset_thread_features()`, run from `start_thread_common` on
    /// every successful exec: a new image inherits neither the enabled set
    /// nor the lock.
    /// # C: O(1)
    pub fn after_exec() -> Self { Self { features: 0, locked: 0 } }
}

/// What `shstk_prctl` asks the caller to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShstkOutcome {
    /// `put_user(task->thread.features, arg2)` — the STATUS answer. The
    /// pointer is unvalidated here, exactly as Linux leaves it to `put_user`.
    PutUser { ptr: u64, val: u64 },
    /// Store the new state, then return 0.
    Store(ShstkState),
    /// Return this value (0 or a negated errno).
    Ret(i64),
}

fn err(e: Errno) -> ShstkOutcome { ShstkOutcome::Ret(-(e.as_i32() as i64)) }

/// Linux `shstk_prctl(task, option, arg2)` for `task == current`.
///
/// `user_shstk` is `cpu_feature_enabled(X86_FEATURE_USER_SHSTK)` — the
/// KERNEL-side enablement, not raw CPUID: a kernel that does not allocate
/// shadow-stack VMAs and does not program `MSR_IA32_PL3_SSP` must report the
/// feature as absent even on hardware that has it, or an `ARCH_SHSTK_ENABLE`
/// returning 0 promises a shadow stack no `call` will ever push to.
///
/// Order matters and is not obvious: STATUS and LOCK are answered BEFORE the
/// lock check and before the "one feature at a time" check, so
/// `ARCH_SHSTK_LOCK` can lock a bit that is already locked and
/// `ARCH_SHSTK_STATUS` ignores `arg2`'s bit pattern entirely (it is a
/// pointer there, not a feature mask). `ARCH_SHSTK_UNLOCK` on the CALLING
/// thread falls through to the enable ladder — Linux only gives it its
/// unlock meaning for a ptraced target — so on self it answers exactly as
/// `ARCH_SHSTK_ENABLE` does.
/// # C: O(1)
pub fn shstk_prctl(option: u64, arg2: u64, st: ShstkState, user_shstk: bool) -> ShstkOutcome {
    if option == nrs::ARCH_SHSTK_STATUS {
        return ShstkOutcome::PutUser { ptr: arg2, val: st.features };
    }
    if option == nrs::ARCH_SHSTK_LOCK {
        return ShstkOutcome::Store(ShstkState { features: st.features, locked: st.locked | arg2 });
    }
    let features = arg2;
    // `if (features & task->thread.features_locked) return -EPERM;`
    if features & st.locked != 0 { return err(Errno::Eperm); }
    // `if (hweight_long(features) > 1) return -EINVAL;`
    if features.count_ones() > 1 { return err(Errno::Einval); }

    if option == nrs::ARCH_SHSTK_DISABLE {
        if features & nrs::ARCH_SHSTK_WRSS != 0 { return wrss_control(st, false, user_shstk); }
        if features & nrs::ARCH_SHSTK_SHSTK != 0 { return shstk_disable(st, user_shstk); }
        return err(Errno::Einval);
    }
    // ARCH_SHSTK_ENABLE — and ARCH_SHSTK_UNLOCK on the calling thread.
    if features & nrs::ARCH_SHSTK_SHSTK != 0 { return shstk_setup(st, user_shstk); }
    if features & nrs::ARCH_SHSTK_WRSS != 0 { return wrss_control(st, true, user_shstk); }
    err(Errno::Einval)
}

/// Linux `shstk_setup()`. Already-enabled short-circuits to 0 BEFORE the
/// capability test, so a redundant enable never turns into EOPNOTSUPP.
/// # C: O(1)
fn shstk_setup(st: ShstkState, user_shstk: bool) -> ShstkOutcome {
    if st.features & nrs::ARCH_SHSTK_SHSTK != 0 { return ShstkOutcome::Ret(0); }
    if !user_shstk { return err(Errno::Eopnotsupp); }
    ShstkOutcome::Store(ShstkState { features: st.features | nrs::ARCH_SHSTK_SHSTK, locked: st.locked })
}

/// Linux `shstk_disable()`. Disabling shadow stack also drops WRSS.
/// # C: O(1)
fn shstk_disable(st: ShstkState, user_shstk: bool) -> ShstkOutcome {
    if !user_shstk { return err(Errno::Eopnotsupp); }
    if st.features & nrs::ARCH_SHSTK_SHSTK == 0 { return ShstkOutcome::Ret(0); }
    let clear = nrs::ARCH_SHSTK_SHSTK | nrs::ARCH_SHSTK_WRSS;
    ShstkOutcome::Store(ShstkState { features: st.features & !clear, locked: st.locked })
}

/// Linux `wrss_control(enable)`. WRSS is meaningless without a shadow stack,
/// so it is EPERM — not EOPNOTSUPP — when shadow stack is off but the CPU
/// does have the feature.
/// # C: O(1)
fn wrss_control(st: ShstkState, enable: bool, user_shstk: bool) -> ShstkOutcome {
    if !user_shstk { return err(Errno::Eopnotsupp); }
    if st.features & nrs::ARCH_SHSTK_SHSTK == 0 { return err(Errno::Eperm); }
    if (st.features & nrs::ARCH_SHSTK_WRSS != 0) == enable { return ShstkOutcome::Ret(0); }
    let features = if enable { st.features | nrs::ARCH_SHSTK_WRSS }
                   else { st.features & !nrs::ARCH_SHSTK_WRSS };
    ShstkOutcome::Store(ShstkState { features, locked: st.locked })
}
