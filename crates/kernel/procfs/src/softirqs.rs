//! Live `/proc/softirqs` renderer backed by the dispatcher counters.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use core::fmt::Write as _;

use vfs::{Ino, InodeRef};

const CLASSES: [(softirq::StatClass, &str); softirq::N_STAT_CLASSES] = [
    (softirq::StatClass::Hi, "HI"), (softirq::StatClass::Timer, "TIMER"),
    (softirq::StatClass::NetTx, "NET_TX"), (softirq::StatClass::NetRx, "NET_RX"),
    (softirq::StatClass::Block, "BLOCK"), (softirq::StatClass::IrqPoll, "IRQ_POLL"),
    (softirq::StatClass::Tasklet, "TASKLET"), (softirq::StatClass::Sched, "SCHED"),
    (softirq::StatClass::Hrtimer, "HRTIMER"), (softirq::StatClass::Rcu, "RCU"),
];

fn body() -> Vec<u8> {
    let ncpu = (cpu::smp::online_count() as usize).clamp(1, cpu::MAX_CPUS);
    let mut out = Vec::with_capacity(20 + ncpu * (11 + CLASSES.len() * 12));
    for cpu in 0..ncpu { let _ = write!(VecFmt(&mut out), "{:>10}", alloc::format!("CPU{cpu}")); }
    out.push(b'\n');
    for (class, name) in CLASSES {
        let _ = write!(VecFmt(&mut out), "{:>10}:", name);
        for cpu in 0..ncpu { let _ = write!(VecFmt(&mut out), " {:>10}", softirq::stat_count(class, cpu)); }
        out.push(b'\n');
    }
    out
}

/// `/proc/softirqs` inode. # C: O(N_cpu * N_softirq_classes)
pub fn make_proc_softirqs() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::SOFTIRQS as Ino, body) }

struct VecFmt<'a>(&'a mut Vec<u8>);
impl core::fmt::Write for VecFmt<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result { self.0.extend_from_slice(s.as_bytes()); Ok(()) }
}
