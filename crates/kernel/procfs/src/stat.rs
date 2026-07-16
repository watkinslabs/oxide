// /proc/stat — system-wide kernel counters per `19§4`.
//
// Body shape (per-CPU rows then aggregates):
//   cpu  <user> <nice> <sys> <idle> <iowait> <irq> <softirq> <steal> <guest> <gnice>
//   cpu0 <same>
//   intr 0
//   ctxt 0
//   btime <unix-seconds at boot>
//   processes <total spawned>
//   procs_running <runnable count>
//   procs_blocked 0
//   softirq 0 0 0 0 0 0 0 0 0 0
//
// v1: jiffies counters report 0 (no per-CPU tick accounting yet).
// btime and processes/procs_running come from live kernel state.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;

use vfs::{Ino, InodeRef};

fn body() -> Vec<u8> {
        let (total, running) = sched::live::registry::live_counts();
        let btime = crate::proc_clock::ReaderClock::current()
            .btime_seconds(crate::hooks::boot_unix_seconds());
        let ctxt  = sched::diag::switches();
        // Per-CPU time in raw timer ticks (user nice system idle iowait irq
        // softirq steal guest guest_nice). htop computes %CPU from deltas so
        // the unit cancels. `cpu` = aggregate; `cpuN` = each online CPU
        // (Linux per-CPU kcpustat).
        let ncpu = (cpu::smp::online_count() as usize).clamp(1, cpu::MAX_CPUS);
        let (au, as_, ai) = sched::cpustat::snapshot();
        let mut out: Vec<u8> = Vec::with_capacity(96 + ncpu * 80);
        let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut out), format_args!(
            "cpu  {au} 0 {as_} {ai} 0 0 0 0 0 0\n"));
        for c in 0..ncpu {
            let (u, s, i) = sched::cpustat::snapshot_cpu(c);
            let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut out), format_args!(
                "cpu{c} {u} 0 {s} {i} 0 0 0 0 0 0\n"));
        }
        let _ = core::fmt::Write::write_fmt(&mut VecFmt(&mut out), format_args!(
            "intr 0\n\
             ctxt {ctxt}\n\
             btime {btime}\n\
             processes {total}\n\
             procs_running {running}\n\
             procs_blocked 0\n\
             softirq 0 0 0 0 0 0 0 0 0 0\n",
        ));
        out
}

/// `/proc/stat` inode (KEYSTONE struct-`Inode`). # C: O(1)
pub fn make_proc_stat() -> InodeRef { crate::dyn_file::make_gen_file(crate::ids::STAT as Ino, body) }

struct VecFmt<'a>(&'a mut Vec<u8>);
impl<'a> core::fmt::Write for VecFmt<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}
