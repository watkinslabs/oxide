// Scheduler-owned process-context receiver for non-fast cpufreq transitions.
//
// Each CPU has one current target and one worker state. Producers replace the
// target while a worker is pending or running; the worker observes the newest
// sequence before it returns, so clock and regulator calls stay in kworker
// context without growing the workqueue for every scheduler sample.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use cpufreq::{Relation, Target};

const IDLE: u8 = 0;
const QUEUING: u8 = 1;
const QUEUED: u8 = 2;
const RUNNING: u8 = 3;
const RELATION_SHIFT: u32 = 32;
const RELATION_MASK: u64 = 0b11 << RELATION_SHIFT;
const LOWEST: u64 = 0;
const HIGHEST: u64 = 1;
const CLOSEST: u64 = 2;

static TARGET: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];
static WHEN_NS: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];
static SEQUENCE: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];
static STATE: [AtomicU8; cpu::MAX_CPUS] = [const { AtomicU8::new(IDLE) }; cpu::MAX_CPUS];

fn encode(target: Target) -> u64 {
    let relation = match target.relation {
        Relation::Lowest => LOWEST, Relation::Highest => HIGHEST, Relation::Closest => CLOSEST,
    };
    u64::from(target.freq_khz) | (relation << RELATION_SHIFT)
}

fn decode(raw: u64) -> Target {
    let relation = match (raw & RELATION_MASK) >> RELATION_SHIFT {
        LOWEST => Relation::Lowest, HIGHEST => Relation::Highest, CLOSEST => Relation::Closest,
        _ => Relation::Lowest,
    };
    Target { freq_khz: raw as u32, relation }
}

/// Queue the CPU's coalesced target for process-context execution. # C: O(1)
pub fn defer(cpu: usize, target: Target, now_ns: u64) -> bool {
    if cpu >= cpu::MAX_CPUS { return false; }
    TARGET[cpu].store(encode(target), Ordering::Release);
    WHEN_NS[cpu].store(now_ns, Ordering::Release);
    SEQUENCE[cpu].fetch_add(1, Ordering::Release);
    queue(cpu)
}

fn queue(cpu: usize) -> bool {
    loop {
        match STATE[cpu].load(Ordering::Acquire) {
            QUEUED | RUNNING => return true,
            IDLE => {
                if STATE[cpu].compare_exchange(IDLE, QUEUING, Ordering::AcqRel, Ordering::Acquire).is_err() {
                    continue;
                }
                if crate::live::workqueue::queue_work_on(cpu, work, cpu) {
                    let _ = STATE[cpu].compare_exchange(QUEUING, QUEUED, Ordering::AcqRel, Ordering::Acquire);
                    return true;
                }
                let _ = STATE[cpu].compare_exchange(QUEUING, IDLE, Ordering::AcqRel, Ordering::Acquire);
                return false;
            }
            QUEUING => {
                if !crate::live::workqueue::queue_work_on(cpu, work, cpu) { return false; }
                let _ = STATE[cpu].compare_exchange(QUEUING, QUEUED, Ordering::AcqRel, Ordering::Acquire);
                return true;
            }
            _ => return false,
        }
    }
}

fn work(cpu: usize) {
    if STATE[cpu].compare_exchange(QUEUED, RUNNING, Ordering::AcqRel, Ordering::Acquire).is_err() {
        if STATE[cpu].compare_exchange(QUEUING, RUNNING, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
    }
    loop {
        let sequence = SEQUENCE[cpu].load(Ordering::Acquire);
        let target = decode(TARGET[cpu].load(Ordering::Acquire));
        let now_ns = WHEN_NS[cpu].load(Ordering::Acquire);
        if let Some(policy) = cpufreq::policy_for(cpu) {
            let _ = cpufreq::drive(&policy, target, now_ns);
        }
        if SEQUENCE[cpu].load(Ordering::Acquire) != sequence { continue; }
        if STATE[cpu].compare_exchange(RUNNING, IDLE, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
        if SEQUENCE[cpu].load(Ordering::Acquire) == sequence { return; }
        if STATE[cpu].compare_exchange(IDLE, RUNNING, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
    }
}
