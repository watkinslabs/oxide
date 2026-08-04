use super::*;
use std::sync::{Arc, Barrier};
use std::vec::Vec;

/// Hosted workers must not borrow an interrupt context from another OS thread.
#[test]
fn hosted_threads_do_not_alias_preempt_context_after_cpu_capacity() {
    const WORKERS: usize = cpu::MAX_CPUS * 2;
    let entered = Arc::new(Barrier::new(WORKERS + 1));
    let release = Arc::new(Barrier::new(WORKERS + 1));
    let mut workers = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let entered = entered.clone();
        let release = release.clone();
        workers.push(std::thread::spawn(move || {
            preempt_count_add(SOFTIRQ_OFFSET);
            entered.wait();
            release.wait();
            preempt_count_sub(SOFTIRQ_OFFSET);
        }));
    }
    entered.wait();
    let observer = std::thread::spawn(in_interrupt).join().unwrap();
    assert!(!observer, "a fresh hosted worker must start in process context");
    release.wait();
    for worker in workers { worker.join().unwrap(); }
}
