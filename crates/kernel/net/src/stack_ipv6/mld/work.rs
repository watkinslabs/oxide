use super::*;

#[cfg(target_os = "oxide-kernel")]
use alloc::vec::Vec;
#[cfg(target_os = "oxide-kernel")]
use sync::{Spinlock, Socket as StackLockClass};

#[cfg(target_os = "oxide-kernel")]
static PENDING_MLD_WORK: Spinlock<Vec<V6ReportWork>, StackLockClass> = Spinlock::new(Vec::new());

#[cfg(target_os = "oxide-kernel")]
fn run_deferred_mld_report(arg: usize) {
    // SAFETY: the work item is allocated immediately before queueing and is
    // consumed exactly once by this callback.
    let work = unsafe { alloc::boxed::Box::from_raw(arg as *mut V6ReportWork) };
    crate::global_stack().finish_v6_multicast(Some(*work));
}

impl NetStack {
    /// Run report emission away from NET_RX. Linux's `igmp6_event_query`
    /// records the query and schedules multicast work; it does not transmit a
    /// reply while the receive stack is still active.
    pub(super) fn finish_v6_multicast_from_rx(&self, work: V6ReportWork) {
        #[cfg(target_os = "oxide-kernel")]
        {
            let raw = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(work)) as usize;
            if sched::live::workqueue::queue_work(run_deferred_mld_report, raw) { return; }
            // A full workqueue is a transient resource failure. Retain the
            // report and retry from NET_RX rather than re-entering transmit.
            let work = unsafe { alloc::boxed::Box::from_raw(raw as *mut V6ReportWork) };
            PENDING_MLD_WORK.lock().push(*work);
            softirq::raise(softirq::Slot::NetRx);
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        self.finish_v6_multicast(Some(work));
    }
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn drain_deferred_mld_reports() -> bool {
    loop {
        let Some(work) = PENDING_MLD_WORK.lock().pop() else { return false };
        let raw = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(work)) as usize;
        if sched::live::workqueue::queue_work(run_deferred_mld_report, raw) { continue; }
        let work = unsafe { alloc::boxed::Box::from_raw(raw as *mut V6ReportWork) };
        PENDING_MLD_WORK.lock().push(*work);
        return true;
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) fn drain_deferred_mld_reports() -> bool { false }
