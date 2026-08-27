use core::sync::atomic::{AtomicU64, Ordering};

use super::{program, ARMED_NS};

static FAILED_CALLS: AtomicU64 = AtomicU64::new(0);

fn failed_arm(_: u64) -> bool {
    FAILED_CALLS.fetch_add(1, Ordering::Relaxed);
    false
}

fn successful_arm(_: u64) -> bool { true }

#[test]
fn failed_arm_is_retried_instead_of_cached_as_hardware_state() {
    let cpu = crate::cpustat::this_cpu();
    let slot = &ARMED_NS[cpu];
    let deadline = super::clock::monotonic_now_ns().saturating_add(1_000_000_000);
    FAILED_CALLS.store(0, Ordering::Relaxed);
    slot.store(0, Ordering::Relaxed);
    super::install_deadline_programmer(failed_arm);

    program(deadline);
    program(deadline);

    assert_eq!(FAILED_CALLS.load(Ordering::Relaxed), 2);
    assert_eq!(slot.load(Ordering::Relaxed), 0);

    super::install_deadline_programmer(successful_arm);
    program(deadline);
    assert_eq!(slot.load(Ordering::Relaxed), deadline);
}
