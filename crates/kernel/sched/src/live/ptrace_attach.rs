//! Trace relationship publication and initial attach signal.
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use crate::{Task, Signum};
use crate::sigsend::{SigSource, SigTarget};

/// Publish an authorized attachment; SEIZE does not generate a signal.
/// Caller validates credentials, target eligibility and request options.
/// # C: O(N_threads) for pending job-control signal cancellation
pub fn attach(tracer: &Task, target: &Arc<Task>, seize: bool, options: u32) {
    target.traced_by.store(tracer.tid, Ordering::Release);
    target.security.ptrace_seized.store(seize, Ordering::Release);
    target.ptrace_options.store(options, Ordering::Release);
    if !seize {
        let _ = super::send::send_signal(target, Signum::Sigstop as u32,
            SigSource::Kernel, SigTarget::Thread);
    }
}
