// `/proc/pressure/{cpu,memory,io}` — Linux PSI files (`kernel/sched/psi.c`
// `psi_*_proc_ops`). Each is O_RDWR: `read` renders the two-line snapshot from
// the `sched::psi` accounting core, `write` registers a poll trigger
// (`<some|full> <threshold_us> <window_us>`), and `poll` reports `POLL_PRI`
// once that resource's trigger crosses. Systemd's memory-pressure watch opens
// `/proc/pressure/memory` O_RDWR + epoll — creating these files (write must
// succeed) is what clears its `Operation not supported`.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use sched::psi::{self, PsiRes};
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, PollSubscribers, VfsError};

use crate::dyn_file::read_at;

/// Inode numbers for the three pressure files (procfs `0x3000_1Axx` band). # C: O(1)
const INO_CPU: Ino = crate::ids::PRESSURE_CPU;
const INO_MEMORY: Ino = crate::ids::PRESSURE_MEMORY;
const INO_IO: Ino = crate::ids::PRESSURE_IO;

/// `i_private` for a pressure file: which resource it reports. # C: O(1)
struct PressureData { res: PsiRes }

/// Live monotonic clock in ns (PSI settles totals to this on every read/poll).
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
#[cfg(target_arch = "aarch64")]
fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }

struct PressureFileOps;
impl FileOps for PressureFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<PressureData>().ok_or(VfsError::Einval)?;
        Ok(read_at(&psi::format(d.res, now_ns()), off, buf))
    }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<PressureData>().ok_or(VfsError::Einval)?;
        // `psi_trigger_parse` rejects a bad spec / out-of-range window with EINVAL.
        psi::add_trigger(d.res, buf).map_err(|_| VfsError::Einval)?;
        Ok(buf.len())
    }
    /// PSI files signal readiness ONLY via `POLL_PRI` when a trigger crosses
    /// (Linux `psi_fop_poll`) — never `POLL_IN`/`POLL_OUT`. # C: O(N_trig)
    fn poll(&self, inode: &Inode) -> u32 {
        match inode.private::<PressureData>() { Some(d) => psi::poll_mask(d.res, now_ns()), None => 0 }
    }
}

/// Build one `/proc/pressure/<res>` inode (`0o644`, O_RDWR) and bind its poll
/// subscribers into the live PSI singleton so the timer tick can wake waiters.
/// # C: O(1)
fn make_pressure_file(res: PsiRes, ino: Ino) -> InodeRef {
    let subs = Arc::new(PollSubscribers::new());
    psi::attach_poll(res, Arc::clone(&subs));
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(PressureFileOps))
        .private(Arc::new(PressureData { res }))
        .poll_subs_arc(subs)
        .build()
}

/// Register the `/proc/pressure/` directory + cpu/memory/io files. # C: O(1)
pub fn register() {
    crate::reg::register("/proc/pressure/cpu", make_pressure_file(PsiRes::Cpu, INO_CPU));
    crate::reg::register("/proc/pressure/memory", make_pressure_file(PsiRes::Memory, INO_MEMORY));
    crate::reg::register("/proc/pressure/io", make_pressure_file(PsiRes::Io, INO_IO));
}
