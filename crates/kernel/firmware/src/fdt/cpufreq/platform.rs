//! Aarch64 DT OPP policy publication and dependency retry.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

use super::{Candidate, domains};
use super::assemble::{Domain, build};

struct Driver { domains: Spinlock<Vec<Domain>, Devices> }

static DT_DRIVER: Spinlock<Option<Arc<Driver>>, Devices> = Spinlock::new(None);
static WORK_READY: AtomicBool = AtomicBool::new(false);
static PENDING: AtomicBool = AtomicBool::new(false);
static QUEUED: AtomicBool = AtomicBool::new(false);

impl Driver {
    fn domain_for(&self, policy: &cpufreq::Policy) -> Option<Arc<opp::Domain>> {
        self.domains.lock().iter().find(|domain| core::ptr::eq(Arc::as_ptr(&domain.policy), policy))
            .map(|domain| Arc::clone(&domain.opp))
    }

    fn domain_on(&self, cpu: usize) -> Option<Arc<opp::Domain>> {
        self.domains.lock().iter().find(|domain| domain.policy.related_cpus.contains(&cpu))
            .map(|domain| Arc::clone(&domain.opp))
    }

    fn publish(&self, domain: Domain) -> bool {
        if cpufreq::register_policy(Arc::clone(&domain.policy)).is_err() { return false; }
        self.domains.lock().push(domain);
        true
    }
}

impl cpufreq::CpufreqOps for Driver {
    fn target_index(&self, policy: &cpufreq::Policy, index: usize) -> KResult<()> {
        self.domain_for(policy).ok_or(VfsError::Enodev)?.transition(index)
    }

    fn get(&self, cpu: usize) -> Option<u32> {
        let rate = self.domain_on(cpu)?.current_rate_hz()?;
        if rate % cpufreq::limits::HZ_PER_KHZ != 0 { return None; }
        u32::try_from(rate / cpufreq::limits::HZ_PER_KHZ).ok()
    }
}

/// Register owner notifications and publish every currently complete policy. # C: O(FDT²)
pub(super) fn init() -> usize {
    clk::subscribe_availability(owner_available);
    regulator::subscribe_availability(owner_available);
    probe()
}

/// Permit owner notifications to use the scheduler workqueue. # C: O(1)
pub(super) fn start_deferred() {
    WORK_READY.store(true, Ordering::Release);
    if PENDING.load(Ordering::Acquire) { schedule_retry(); }
}

fn owner_available() {
    PENDING.store(true, Ordering::Release);
    if WORK_READY.load(Ordering::Acquire) { schedule_retry(); }
}

fn schedule_retry() {
    if QUEUED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    if !sched::live::workqueue::queue_work(retry, 0) {
        QUEUED.store(false, Ordering::Release);
    }
}

fn retry(_: usize) {
    loop {
        PENDING.store(false, Ordering::Release);
        let _ = probe();
        if PENDING.load(Ordering::Acquire) { continue; }
        QUEUED.store(false, Ordering::Release);
        if !PENDING.swap(false, Ordering::AcqRel) { return; }
        if QUEUED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
    }
}

fn probe() -> usize {
    let Some(tree) = super::super::blob() else { return 0; };
    let candidates = ::fdt::cpu_opp_tables(tree).into_iter().filter_map(|table| {
        let cpu = usize::try_from(cpu::logical_id_for_hardware(table.cpu_mpidr)?).ok()?;
        Some(Candidate { cpu, table })
    }).collect();
    let plans = domains(candidates);
    if let Some(driver) = current_driver() {
        return plans.into_iter().filter(|plan| plan.cpus.iter().all(|cpu| cpufreq::policy_for(*cpu).is_none()))
            .filter_map(build).map(|domain| driver.publish(domain)).filter(|published| *published).count();
    }
    if cpufreq::driver::driver().is_some() { return 0; }
    let domains: Vec<Domain> = plans.into_iter().filter_map(build).collect();
    if domains.is_empty() { return 0; }
    let driver = Arc::new(Driver { domains: Spinlock::new(Vec::new()) });
    if cpufreq::register_driver("cpufreq-dt", driver.clone()).is_err() { return 0; }
    *DT_DRIVER.lock() = Some(Arc::clone(&driver));
    domains.into_iter().map(|domain| driver.publish(domain)).filter(|published| *published).count()
}

fn current_driver() -> Option<Arc<Driver>> { DT_DRIVER.lock().clone() }
