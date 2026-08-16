use super::*;
use core::sync::atomic::{AtomicU32, Ordering};

// Each hook sets its own bit, so one run reports the exact set called.
static CALLED: AtomicU32 = AtomicU32::new(0);
fn reset() { CALLED.store(0, Ordering::SeqCst); }
fn called() -> u32 { CALLED.load(Ordering::SeqCst) }
fn mark(bit: u32) { CALLED.fetch_or(1 << bit, Ordering::SeqCst); }

const D_BEGIN: u32 = 0; const D_PREPARE: u32 = 1; const D_PREPARE_LATE: u32 = 2;
const D_ENTER: u32 = 3; const D_WAKE: u32 = 4; const D_FINISH: u32 = 5;
const D_END: u32 = 6; const D_RECOVER: u32 = 7;
const I_BEGIN: u32 = 8; const I_PREPARE: u32 = 9; const I_PREPARE_LATE: u32 = 10;
const I_RESTORE_EARLY: u32 = 11; const I_RESTORE: u32 = 12; const I_END: u32 = 13;

fn d_begin(_s: SuspendState) -> KResult<()> { mark(D_BEGIN); Ok(()) }
fn d_prepare() -> KResult<()> { mark(D_PREPARE); Ok(()) }
fn d_prepare_late() -> KResult<()> { mark(D_PREPARE_LATE); Ok(()) }
fn d_enter(_s: SuspendState) -> KResult<()> { mark(D_ENTER); Ok(()) }
fn d_wake() { mark(D_WAKE); }
fn d_finish() { mark(D_FINISH); }
fn d_end() { mark(D_END); }
fn d_recover() { mark(D_RECOVER); }
fn i_begin() -> KResult<()> { mark(I_BEGIN); Ok(()) }
fn i_prepare() -> KResult<()> { mark(I_PREPARE); Ok(()) }
fn i_prepare_late() -> KResult<()> { mark(I_PREPARE_LATE); Ok(()) }
fn i_restore_early() { mark(I_RESTORE_EARLY); }
fn i_restore() { mark(I_RESTORE); }
fn i_end() { mark(I_END); }

static DEEP: PlatformSuspendOps = PlatformSuspendOps {
    valid: None, begin: Some(d_begin), prepare: Some(d_prepare),
    prepare_late: Some(d_prepare_late), enter: Some(d_enter), wake: Some(d_wake),
    finish: Some(d_finish), suspend_again: None, end: Some(d_end), recover: Some(d_recover),
};
static IDLE: PlatformS2idleOps = PlatformS2idleOps {
    begin: Some(i_begin), prepare: Some(i_prepare), prepare_late: Some(i_prepare_late),
    wake: None, check: None, restore_early: Some(i_restore_early),
    restore: Some(i_restore), end: Some(i_end),
};

fn both() -> Tables<'static> { Tables { suspend: Some(&DEEP), s2idle: Some(&IDLE) } }

fn full_cycle(state: SuspendState) -> u32 {
    let _g = crate::suspend::test_lock();
    reset();
    let t = both();
    begin(t, state).unwrap();
    prepare(t, state).unwrap();
    prepare_late(t, state).unwrap();
    prepare_noirq(t, state).unwrap();
    enter(t, state).unwrap();
    resume_noirq(t, state);
    resume_early(t, state);
    resume_finish(t, state);
    resume_end(t, state);
    called()
}

#[test]
fn a_deep_cycle_calls_only_the_deep_table() {
    let got = full_cycle(SuspendState::Mem);
    let want = (1 << D_BEGIN) | (1 << D_PREPARE) | (1 << D_PREPARE_LATE) | (1 << D_ENTER)
        | (1 << D_WAKE) | (1 << D_FINISH) | (1 << D_END);
    assert_eq!(got, want, "deep cycle called the wrong hooks");
}

#[test]
fn an_idle_cycle_calls_only_the_s2idle_table() {
    let got = full_cycle(SuspendState::ToIdle);
    let want = (1 << I_BEGIN) | (1 << I_PREPARE) | (1 << I_PREPARE_LATE)
        | (1 << I_RESTORE_EARLY) | (1 << I_RESTORE) | (1 << I_END);
    assert_eq!(got, want, "idle cycle reached the deep table");
}

#[test]
fn standby_routes_the_same_as_mem() {
    assert_eq!(full_cycle(SuspendState::Standby), full_cycle(SuspendState::Mem));
}

#[test]
fn the_prepare_positions_cross_tables_as_the_reference_does() {
    let _g = crate::suspend::test_lock();
    let t = both();
    // Step 9 is the s2idle table's `prepare`, not the deep table's anything.
    reset(); prepare_late(t, SuspendState::ToIdle).unwrap();
    assert_eq!(called(), 1 << I_PREPARE);
    // Step 11 is the s2idle table's `prepare_late` for freeze...
    reset(); prepare_noirq(t, SuspendState::ToIdle).unwrap();
    assert_eq!(called(), 1 << I_PREPARE_LATE);
    // ...and the deep table's `prepare_late` otherwise.
    reset(); prepare_noirq(t, SuspendState::Mem).unwrap();
    assert_eq!(called(), 1 << D_PREPARE_LATE);
}

#[test]
fn suspend_to_idle_never_enters_the_platform() {
    let _g = crate::suspend::test_lock();
    reset();
    enter(both(), SuspendState::ToIdle).unwrap();
    assert_eq!(called(), 0, "freeze handed the machine to firmware");
}

#[test]
fn recover_is_deep_only() {
    let _g = crate::suspend::test_lock();
    reset(); recover(both(), SuspendState::ToIdle);
    assert_eq!(called(), 0);
    reset(); recover(both(), SuspendState::Mem);
    assert_eq!(called(), 1 << D_RECOVER);
}

#[test]
fn empty_tables_succeed_at_every_position() {
    let t = Tables::none();
    for state in [SuspendState::ToIdle, SuspendState::Standby, SuspendState::Mem] {
        assert!(begin(t, state).is_ok());
        assert!(prepare(t, state).is_ok());
        assert!(prepare_late(t, state).is_ok());
        assert!(prepare_noirq(t, state).is_ok());
        assert!(enter(t, state).is_ok());
        resume_noirq(t, state); resume_early(t, state);
        resume_finish(t, state); resume_end(t, state); recover(t, state);
        assert!(!suspend_again(t, state));
    }
}

#[test]
fn suspend_again_is_deep_only_and_defaults_false() {
    let t = both();
    assert!(!suspend_again(t, SuspendState::ToIdle));
    assert!(!suspend_again(t, SuspendState::Mem), "absent hook did not default to false");
}
