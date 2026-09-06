//! IRQ exclusion at production TaskPi acquisition sites, without a real IRQ.
use std::cell::Cell;

std::thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(true) };
    static TASK: Cell<*const crate::Task> = const { Cell::new(core::ptr::null()) };
    static EVENTS: Cell<usize> = const { Cell::new(0) };
}

pub struct TestIrq;

fn assert_unlocked() {
    TASK.with(|slot| {
        let ptr = slot.get();
        if ptr.is_null() { return; }
        // SAFETY: check() retains the borrowed task until its probe is reset.
        let task = unsafe { &*ptr };
        assert!(task.pi_lock.try_lock().is_some(), "IRQ transition while TaskPi is held");
    });
}

impl sync::IrqGate for TestIrq {
    unsafe fn save_disable() -> u64 {
        assert_unlocked();
        EVENTS.with(|n| n.set(n.get() + 1));
        ENABLED.with(|state| state.replace(false) as u64)
    }
    unsafe fn save_enable() -> u64 { ENABLED.with(|state| state.replace(true) as u64) }
    unsafe fn restore(flags: u64) {
        assert_unlocked();
        assert!(!ENABLED.with(Cell::get), "IRQs enabled inside TaskPi guard");
        EVENTS.with(|n| n.set(n.get() + 1));
        ENABLED.with(|state| state.set(flags != 0));
    }
}

pub fn check(task: &crate::Task, enabled: bool, f: impl FnOnce()) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TASK.with(|slot| slot.set(core::ptr::null()));
            ENABLED.with(|state| state.set(true));
        }
    }
    assert!(TASK.with(|slot| slot.replace(task)).is_null());
    let _reset = Reset;
    ENABLED.with(|state| state.set(enabled));
    EVENTS.with(|n| n.set(0));
    f();
    assert_eq!(EVENTS.with(Cell::get), 2, "production site must save and restore IRQs once");
    assert_eq!(ENABLED.with(Cell::get), enabled, "entry IRQ state changed");
    assert!(task.pi_lock.try_lock().is_some(), "TaskPi leaked after operation");
}
