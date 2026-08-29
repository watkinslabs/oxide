use core::sync::atomic::{AtomicU64, Ordering};

use super::program;

static FAILED_CALLS: AtomicU64 = AtomicU64::new(0);

fn failed_arm(_: u64) -> bool {
    FAILED_CALLS.fetch_add(1, Ordering::Relaxed);
    false
}

fn successful_arm(_: u64) -> bool { true }

#[test]
fn failed_arm_is_retried_instead_of_cached_as_hardware_state() {
    let deadline = super::clock::monotonic_now_ns().saturating_add(1_000_000_000);
    FAILED_CALLS.store(0, Ordering::Relaxed);
    super::install_deadline_programmer(failed_arm);

    program(deadline);
    program(deadline);

    assert_eq!(FAILED_CALLS.load(Ordering::Relaxed), 2);

    super::install_deadline_programmer(successful_arm);
    program(deadline);
}
