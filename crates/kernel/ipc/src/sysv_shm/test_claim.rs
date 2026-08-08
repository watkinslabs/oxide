// One claim, and one reset body, for the ONE System V shared-memory subsystem.
//
// `REG` — the segment table and its id counter — and the per-namespace
// `kernel.shm_rmid_forced` flag are process-global exactly as they are in the
// kernel, so no test can own a private copy, and the reset each test starts
// with is the most destructive operation in the crate.
//
// The lock has one owner. What did not was the RESET: four test files each
// carried their own copy of it — `tests.rs`, `shmctl.rs`, `creator/tests.rs`,
// and a raw `REG.segs.lock().clear()` in `shmdt/tests.rs` — and they did not
// agree on what "reset" means. Only two of the four returned `next_id` to 1;
// only `creator`'s cleared `shm_rmid_forced`. A test's starting state therefore
// depended on which file it lived in, and a flag one file cleared stayed set
// for the others. `reset_shm` below is the single definition: empty registry,
// id counter at 1, `shm_rmid_forced` off.
//
// Poison is recovered rather than propagated: a genuine assertion failure must
// report as ONE failure instead of cascading into every sibling.

use core::sync::atomic::Ordering;
use std::sync::{Mutex, MutexGuard};

// `pub(crate)`: the sem-undo tests alias this SAME mutex as their
// `TEST_LOCK` (`sysv::sem::tests::common`) because both files install the
// process-global `sched::current` hook / read `current_tgid()` — one
// resource, one claim, crate-wide.
pub(crate) static SHM: Mutex<()> = Mutex::new(());

/// Live claim on the shared-memory subsystem. Held for the body of a test.
pub(crate) struct ShmClaim(#[allow(dead_code)] MutexGuard<'static, ()>);

/// Take the claim, with the subsystem returned to its boot state.
pub(crate) fn claim_shm() -> ShmClaim {
    let g = SHM.lock().unwrap_or_else(|e| e.into_inner());
    reset_shm();
    ShmClaim(g)
}

/// Return the subsystem to its boot state. Callers must hold the claim.
pub(crate) fn reset_shm() {
    super::REG.next_id.store(1, Ordering::Release);
    super::REG.segs.lock().clear();
    super::set_shm_rmid_forced(0);
    super::huge::set_hugetlb_shm_group(0);
}
