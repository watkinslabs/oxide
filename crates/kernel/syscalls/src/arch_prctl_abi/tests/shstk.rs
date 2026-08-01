use crate::arch_prctl_abi::shstk::*;
use syscall::errno::Errno;
use syscall::nrs;

const SHSTK: u64 = nrs::ARCH_SHSTK_SHSTK;
const WRSS:  u64 = nrs::ARCH_SHSTK_WRSS;

fn e(err: Errno) -> ShstkOutcome { ShstkOutcome::Ret(-(err.as_i32() as i64)) }

#[test]
fn status_always_answers_and_reports_the_enabled_set() {
    // The single most important correction over a blanket EINVAL: a current
    // Linux answers ARCH_SHSTK_STATUS on EVERY CPU, because it only reads
    // per-thread bookkeeping. glibc's CET probe reads this.
    for cpu in [false, true] {
        assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_STATUS, 0x7fff_0000, ShstkState::default(), cpu),
                   ShstkOutcome::PutUser { ptr: 0x7fff_0000, val: 0 });
        let st = ShstkState { features: SHSTK | WRSS, locked: SHSTK };
        assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_STATUS, 0x1000, st, cpu),
                   ShstkOutcome::PutUser { ptr: 0x1000, val: SHSTK | WRSS },
                   "STATUS reports thread.features, not features_locked");
    }
}

#[test]
fn lock_always_succeeds_and_accumulates() {
    // ARCH_SHSTK_LOCK is answered BEFORE the capability test and before the
    // "one feature at a time" test, so it succeeds on a CPU with no CET and
    // accepts several bits at once.
    let out = shstk_prctl(nrs::ARCH_SHSTK_LOCK, SHSTK | WRSS, ShstkState::default(), false);
    assert_eq!(out, ShstkOutcome::Store(ShstkState { features: 0, locked: SHSTK | WRSS }));
    // Locking again is idempotent, and locking a second bit ORs in.
    let st = ShstkState { features: 0, locked: SHSTK };
    assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_LOCK, WRSS, st, false),
               ShstkOutcome::Store(ShstkState { features: 0, locked: SHSTK | WRSS }));
}

#[test]
fn lock_then_change_is_eperm() {
    // `if (features & task->thread.features_locked) return -EPERM;` — and it
    // runs before the hweight check, so it wins over EINVAL.
    let st = ShstkState { features: 0, locked: SHSTK };
    for option in [nrs::ARCH_SHSTK_ENABLE, nrs::ARCH_SHSTK_DISABLE, nrs::ARCH_SHSTK_UNLOCK] {
        assert_eq!(shstk_prctl(option, SHSTK, st, true), e(Errno::Eperm));
        assert_eq!(shstk_prctl(option, SHSTK | WRSS, st, true), e(Errno::Eperm),
                   "the locked-bit test precedes the hweight test");
    }
}

#[test]
fn more_than_one_feature_at_a_time_is_einval() {
    for option in [nrs::ARCH_SHSTK_ENABLE, nrs::ARCH_SHSTK_DISABLE, nrs::ARCH_SHSTK_UNLOCK] {
        assert_eq!(shstk_prctl(option, SHSTK | WRSS, ShstkState::default(), true),
                   e(Errno::Einval));
    }
}

#[test]
fn zero_features_is_einval_not_success() {
    for option in [nrs::ARCH_SHSTK_ENABLE, nrs::ARCH_SHSTK_DISABLE, nrs::ARCH_SHSTK_UNLOCK] {
        assert_eq!(shstk_prctl(option, 0, ShstkState::default(), true), e(Errno::Einval));
        assert_eq!(shstk_prctl(option, 0, ShstkState::default(), false), e(Errno::Einval),
                   "hweight(0) == 0 passes the count test, then no bit matches");
    }
}

#[test]
fn enable_without_kernel_support_is_eopnotsupp_not_einval() {
    // The distinction that matters: EINVAL means "unknown request", and a
    // runtime retries elsewhere; EOPNOTSUPP means "understood, unavailable".
    assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_ENABLE, SHSTK, ShstkState::default(), false),
               e(Errno::Eopnotsupp));
    assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_DISABLE, SHSTK, ShstkState::default(), false),
               e(Errno::Eopnotsupp));
    assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_ENABLE, WRSS, ShstkState::default(), false),
               e(Errno::Eopnotsupp));
}

#[test]
fn enable_is_idempotent_before_the_capability_test() {
    // `shstk_setup()` short-circuits on "already enabled" FIRST, so a thread
    // that somehow holds the bit gets 0 rather than EOPNOTSUPP.
    let st = ShstkState { features: SHSTK, locked: 0 };
    assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_ENABLE, SHSTK, st, false), ShstkOutcome::Ret(0));
}

#[test]
fn unlock_on_the_calling_thread_behaves_as_enable() {
    // Linux gives ARCH_SHSTK_UNLOCK its unlock meaning only for a PTRACED
    // target; on self it falls through into the enable ladder. Encoding this
    // keeps a future ptrace path from being written against the wrong rule.
    for cpu in [false, true] {
        assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_UNLOCK, SHSTK, ShstkState::default(), cpu),
                   shstk_prctl(nrs::ARCH_SHSTK_ENABLE, SHSTK, ShstkState::default(), cpu));
    }
}

#[test]
fn wrss_requires_shadow_stack_first() {
    // `wrss_control` answers EPERM — not EOPNOTSUPP and not EINVAL — when
    // shadow stack is off on a capable CPU.
    assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_ENABLE, WRSS, ShstkState::default(), true),
               e(Errno::Eperm));
    assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_DISABLE, WRSS, ShstkState::default(), true),
               e(Errno::Eperm));
}

#[test]
fn a_capable_kernel_stores_and_reports_the_enabled_set() {
    // The state is CONSUMED, not merely written: enable → STATUS sees it →
    // disable clears both bits.
    let mut st = ShstkState::default();
    match shstk_prctl(nrs::ARCH_SHSTK_ENABLE, SHSTK, st, true) {
        ShstkOutcome::Store(n) => st = n,
        other => panic!("expected Store, got {other:?}"),
    }
    assert_eq!(st.features, SHSTK);
    assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_STATUS, 0x40, st, true),
               ShstkOutcome::PutUser { ptr: 0x40, val: SHSTK });
    match shstk_prctl(nrs::ARCH_SHSTK_ENABLE, WRSS, st, true) {
        ShstkOutcome::Store(n) => st = n,
        other => panic!("expected Store, got {other:?}"),
    }
    assert_eq!(st.features, SHSTK | WRSS);
    // Disabling shadow stack drops WRSS with it.
    match shstk_prctl(nrs::ARCH_SHSTK_DISABLE, SHSTK, st, true) {
        ShstkOutcome::Store(n) => st = n,
        other => panic!("expected Store, got {other:?}"),
    }
    assert_eq!(st.features, 0, "disabling shadow stack must clear WRSS too");
}

#[test]
fn wrss_disable_is_a_no_op_when_already_off() {
    let st = ShstkState { features: SHSTK, locked: 0 };
    assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_DISABLE, WRSS, st, true), ShstkOutcome::Ret(0));
}

#[test]
fn shstk_disable_is_a_no_op_when_already_off_on_a_capable_cpu() {
    assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_DISABLE, SHSTK, ShstkState::default(), true),
               ShstkOutcome::Ret(0));
}

#[test]
fn exec_resets_both_the_enabled_and_the_locked_set() {
    // Linux `reset_thread_features()` from `start_thread_common`. Without the
    // lock reset, a locked bit would outlive the image that locked it and
    // make the new program's first ARCH_SHSTK_ENABLE a permanent EPERM.
    assert_eq!(ShstkState::after_exec(), ShstkState { features: 0, locked: 0 });
    let st = ShstkState::after_exec();
    assert_eq!(shstk_prctl(nrs::ARCH_SHSTK_ENABLE, SHSTK, st, true),
               ShstkOutcome::Store(ShstkState { features: SHSTK, locked: 0 }));
}
