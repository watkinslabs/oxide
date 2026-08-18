use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::{FreqEntry, FreqTable};

static TARGET: AtomicUsize = AtomicUsize::new(usize::MAX);
static RESUMES: AtomicUsize = AtomicUsize::new(0);

struct SuspendDriver;
impl CpufreqOps for SuspendDriver {
    fn target_index(&self, _policy: &Policy, index: usize) -> KResult<()> {
        TARGET.store(index, Ordering::Release);
        Ok(())
    }

    fn suspend(&self, policy: &Policy) -> KResult<Option<usize>> {
        let index = policy.suspend_index().ok_or(VfsError::Einval)?;
        self.target_index(policy, index)?;
        Ok(Some(index))
    }

    fn resume(&self, _policy: &Policy) -> KResult<()> {
        RESUMES.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn system_suspend_uses_the_platform_suspend_opp_and_stops_governing_until_resume() {
    let _guard = test_guard();
    TARGET.store(usize::MAX, Ordering::Relaxed);
    RESUMES.store(0, Ordering::Relaxed);
    register_driver("suspend", Arc::new(SuspendDriver)).expect("driver");
    let table = FreqTable::new(alloc::vec![FreqEntry::new(1_000, 0), FreqEntry::new(2_000, 1)]).expect("table");
    let policy = Policy::new_with_suspend(alloc::vec![0], table, 1, 2_000, Some(0), "schedutil").expect("policy");
    register_policy(policy.clone()).expect("policy");
    suspend();
    assert!(suspended());
    assert_eq!(TARGET.load(Ordering::Acquire), 0);
    assert_eq!(policy.cur(), 1_000);
    assert_eq!(govern(&policy, &Demand::default(), 1), Ok(None));
    resume();
    assert!(!suspended());
    assert_eq!(RESUMES.load(Ordering::Relaxed), 1);
}
