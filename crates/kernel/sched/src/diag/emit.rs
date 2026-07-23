use core::sync::atomic::{AtomicBool, Ordering};

use crate::Task;

use super::current_task;
use super::format::{col_dec, col_str, col_syscall, emit_syscall};
use super::ring::{dump_exit_recent, switches};

const SYSRQ_ARM: u8 = 0x00;
static SYSRQ_ARMED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "debug-watchdog")]
pub fn report_lockup(secs: u64, tid: u32, cur: Option<&Task>) {
    klog::write_raw(b"\n[WATCHDOG] soft lockup: no reschedule for ");
    klog::write_dec_u64(secs);
    klog::write_raw(b"s on tid=");
    klog::write_dec_u64(tid as u64);
    if let Some(t) = cur {
        klog::write_raw(b" (");
        klog::write_raw(t.name.as_bytes());
        klog::write_raw(b") last_syscall=");
        emit_syscall(t.last_syscall_nr.load(Ordering::Relaxed));
        #[cfg(feature = "debug-getdents")]
        super::getdents::emit_getdents(t);
        #[cfg(feature = "debug-syscall-return")]
        super::syscall_return::emit_syscall_return(t);
    }
    klog::write_raw(b"\n");
    dump_tasks();
}

pub fn dump_tasks() {
    #[cfg(feature = "debug-watchdog")]
    dump_tasks_emit();
}

#[cfg(feature = "debug-watchdog")]
fn dump_tasks_emit() {
    klog::write_raw(b"[sysrq] task dump  switches=");
    klog::write_dec_u64(switches());
    if let Some(t) = current_task() {
        klog::write_raw(b" current=tid:");
        klog::write_dec_u64(t.tid as u64);
    }
    klog::write_raw(b"\n  PID   TID name             ST onrq cpu  last-sysc  nsysc      cputime_ms\n");

    let tasks = match crate::registry::try_snapshot() {
        Some(v) => v,
        None => {
            klog::write_raw(b"  <registry busy - lock held; cannot snapshot>\n");
            return;
        }
    };
    for t in tasks.iter() {
        let vpid = t.vtgid.load(Ordering::Relaxed);
        col_dec(if vpid != 0 { vpid as u64 } else { t.tid as u64 }, 5);
        klog::write_raw(b" ");
        col_dec(t.tid as u64, 6);
        klog::write_raw(b" ");
        let comm = t.comm();
        col_str(&comm, 16);
        klog::write_raw(b" ");
        klog::write_raw(&[t.state().linux_char()]);
        // Mark reaped-but-pidfd-pinned tasks (release_task done; gone from /proc)
        // so the dump distinguishes them from genuinely-unreaped zombies.
        if t.reaped.load(Ordering::Relaxed) { klog::write_raw(b"* "); } else { klog::write_raw(b"  "); }
        klog::write_raw(if t.on_rq.load(Ordering::Relaxed) { b"y  " } else { b"n  " });
        let cpu = t.cpu.load(Ordering::Relaxed);
        if cpu == u16::MAX { klog::write_raw(b"  -"); } else { col_dec(cpu as u64, 3); }
        klog::write_raw(b"  ");
        col_syscall(t.last_syscall_nr.load(Ordering::Relaxed));
        klog::write_raw(b" ");
        col_dec(t.nsyscalls.load(Ordering::Relaxed), 10);
        klog::write_raw(b" ");
        col_dec(t.sum_exec_runtime_ns.load(Ordering::Relaxed) / 1_000_000, 10);
        klog::write_raw(b" tgid="); col_dec(t.tgid.load(Ordering::Relaxed) as u64, 6);
        klog::write_raw(b" vtid="); col_dec(t.vtid.load(Ordering::Relaxed) as u64, 6);
        klog::write_raw(b" ptid="); col_dec(t.parent_tid.load(Ordering::Relaxed) as u64, 6);
        let fux = t.futex_uaddr.load(Ordering::Relaxed);
        if fux != 0 { klog::write_raw(b" fux="); klog::write_hex_u64(fux); }
        let wake_dl = t.wakeup_deadline_ns.load(Ordering::Relaxed);
        if wake_dl != 0 { klog::write_raw(b" wake_dl_ns="); klog::write_dec_u64(wake_dl); }
        t.with_exe_path(|p| if let Some(p) = p {
            klog::write_raw(b" exe="); klog::write_raw(p.as_bytes());
        });
        #[cfg(feature = "debug-getdents")]
        super::getdents::emit_getdents(t);
        #[cfg(feature = "debug-syscall-return")]
        super::syscall_return::emit_syscall_return(t);
        klog::write_raw(b"\n");
    }
}

pub fn note_init_exit(code: i32) {
    #[cfg(feature = "debug-watchdog")]
    {
        klog::write_raw(b"\n[INIT-DEATH] PID 1 (init) exited code=");
        klog::write_dec_u64(code as u64);
        klog::write_raw(b" - no init, system will hang (Linux would panic)\n");
        dump_exit_recent("init", code as u64);
        dump_tasks();
    }
    #[cfg(not(feature = "debug-watchdog"))]
    let _ = code;
}

pub fn sysrq_rx(b: u8) -> bool {
    if SYSRQ_ARMED.swap(false, Ordering::Relaxed) {
        #[cfg(feature = "debug-watchdog")]
        sysrq_cmd(b);
        return true;
    }
    if b == SYSRQ_ARM {
        SYSRQ_ARMED.store(true, Ordering::Relaxed);
        return true;
    }
    false
}

#[cfg(feature = "debug-watchdog")]
fn sysrq_cmd(b: u8) {
    match b {
        b't' => dump_tasks(),
        b'w' => {
            klog::write_raw(b"[sysrq] switches=");
            klog::write_dec_u64(switches());
            if let Some(t) = current_task() {
                klog::write_raw(b" current=tid:");
                klog::write_dec_u64(t.tid as u64);
                klog::write_raw(b" state=");
                klog::write_raw(&[t.state().linux_char()]);
                klog::write_raw(b" last_syscall=");
                emit_syscall(t.last_syscall_nr.load(Ordering::Relaxed));
            }
            klog::write_raw(b"\n");
        }
        b'c' => super::percpu::dump_cpus(),
        b'b' => super::nmi::backtrace_all(),
        _ => klog::write_raw(b"[sysrq] keys: t=tasks w=watchdog c=per-cpu b=backtrace-all\n"),
    }
}
