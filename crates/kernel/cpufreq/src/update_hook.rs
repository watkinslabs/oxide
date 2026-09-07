// The scheduler's per-CPU entry into cpufreq.
//
// The utilisation hook runs in hard-interrupt context, on the wakeup path,
// with interrupts masked. It therefore may not walk the policy registry: that
// registry is a lock process context holds with interrupts ENABLED, so a
// wakeup interrupt landing on a holder spins for ever on a single CPU — the
// console goes silent mid-line and the machine never runs another instruction.
// Measured: an interrupt-context policy-registry acquisition wedged an x86
// guest permanently, with the transmit queue empty and no producer left.
//
// The reference answers this by publishing ONE pointer per CPU when a policy
// is registered and dereferencing it, lock-free, from the hook. The registry
// keeps every published policy alive, so the pointer a CPU reads is valid for
// as long as the slot holds it.

use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::policy::Policy;

/// Policy governing each CPU, published for the scheduler's hook. Null means
/// no policy governs that CPU and the hook has nothing to do.
static HOOK: [AtomicPtr<Policy>; cpu::MAX_CPUS] =
    [const { AtomicPtr::new(ptr::null_mut()) }; cpu::MAX_CPUS];

/// Publish `policy` as the one governing `cpu`.
///
/// The caller must keep `policy` alive for as long as the slot names it; the
/// policy registry is what does so, and it is the only caller.
/// # C: O(1)
pub(crate) fn add_update_util_hook(cpu: usize, policy: &Arc<Policy>) {
    if cpu >= cpu::MAX_CPUS { return; }
    HOOK[cpu].store(Arc::as_ptr(policy) as *mut Policy, Ordering::Release);
}

/// The policy governing `cpu`, read without taking any lock.
///
/// This is the whole of what the scheduler's hook needs from the registry, and
/// the reason it needs nothing that an interrupt could be made to wait for.
/// # C: O(1)
pub fn hook_policy(cpu: usize) -> Option<&'static Policy> {
    if cpu >= cpu::MAX_CPUS { return None; }
    let raw = HOOK[cpu].load(Ordering::Acquire);
    if raw.is_null() { return None; }
    // SAFETY: add_update_util_hook publishes only a pointer into an Arc the
    // policy registry holds for the life of the kernel (nothing withdraws a
    // registered policy), and clear_hooks nulls every slot before the test
    // registry is emptied, so the target outlives this read.
    Some(unsafe { &*raw })
}

/// Withdraw every published policy between tests. # C: O(MAX_CPUS)
#[cfg(test)]
pub(crate) fn clear_hooks() {
    for slot in HOOK.iter() { slot.store(ptr::null_mut(), Ordering::Release); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FreqEntry, FreqTable};

    fn policy(cpus: alloc::vec::Vec<usize>) -> Arc<Policy> {
        let table = FreqTable::new(alloc::vec![FreqEntry::new(1_000, 0), FreqEntry::new(2_000, 1)])
            .expect("table");
        Policy::new(cpus, table, 1, 1_000, "schedutil").expect("policy")
    }

    #[test]
    fn a_published_policy_is_readable_without_the_registry_lock() {
        let _guard = crate::driver::test_guard();
        let p = policy(alloc::vec![0]);
        add_update_util_hook(0, &p);
        // The registry lock is held for the whole of this read: the hook path
        // must not need it, which is exactly what an interrupt cannot wait for.
        let held = crate::driver::lock_registry_for_tests();
        let seen = hook_policy(0).expect("published policy");
        assert!(core::ptr::eq(seen, Arc::as_ptr(&p)));
        drop(held);
        clear_hooks();
        assert!(hook_policy(0).is_none());
    }

    #[test]
    fn an_out_of_range_cpu_publishes_and_reads_nothing() {
        let _guard = crate::driver::test_guard();
        let p = policy(alloc::vec![cpu::MAX_CPUS]);
        add_update_util_hook(cpu::MAX_CPUS, &p);
        assert!(hook_policy(cpu::MAX_CPUS).is_none());
    }
}
