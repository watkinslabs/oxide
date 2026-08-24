//! `/usr/local/bin/ldt_probe` — exercise the x86 LDT ABI on a running guest.

use std::sync::{Arc, Barrier};
use std::thread;

use support::{fail, line, report, Verdict};

const PROBE: &str = "ldt_probe";
const SYS_MODIFY_LDT: libc::c_long = 154;
const WRITE_NEW: libc::c_long = 0x11;
const USER_DESC_BYTES: usize = 16;
const ENTRY: u16 = 1;
const SELECTOR: u16 = (ENTRY << 3) | 0x4;
const CPU_MASK_BYTES: usize = 128;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserDesc { entry: u32, base: u32, limit: u32, flags: u32 }

fn main() -> std::process::ExitCode { report(PROBE, run()) }

fn pin_cpu(cpu: usize) -> Result<(), i32> {
    let mut mask = [0u8; CPU_MASK_BYTES];
    let byte = cpu / 8;
    if byte >= mask.len() { return Err(libc::EINVAL); }
    mask[byte] |= 1 << (cpu % 8);
    // SAFETY: the mask is a live byte array of the size passed to the kernel.
    let rc = unsafe { libc::sched_setaffinity(0, mask.len(), mask.as_ptr().cast()) };
    (rc == 0).then_some(()).ok_or_else(|| unsafe { *libc::__errno_location() })
}

fn current_cpu() -> Result<i32, i32> {
    let mut cpu = 0u32;
    // SAFETY: the kernel writes one u32 to a valid stack location; node is unused.
    let rc = unsafe { libc::syscall(309, &mut cpu, std::ptr::null_mut::<u32>(), 0) };
    (rc == 0).then_some(cpu as i32).ok_or_else(|| unsafe { *libc::__errno_location() })
}

fn sldt() -> u16 {
    let value: u16;
    // SAFETY: SLDT is an unprivileged read of this thread's current LDTR.
    unsafe { std::arch::asm!("sldt {0:x}", out(reg) value, options(nostack, preserves_flags)); }
    value
}

fn load_ds() -> Result<(), ()> {
    // SAFETY: SELECTOR names the present ring-3 data descriptor installed below.
    unsafe { std::arch::asm!("mov ds, {0:x}", in(reg) SELECTOR, options(nostack, preserves_flags)); }
    Ok(())
}

fn install() -> Result<(), i64> {
    let desc = UserDesc {
        entry: ENTRY as u32,
        base: 0,
        limit: u32::MAX,
        // seg_32bit=1, useable=1; data, readable, present, byte-granular.
        flags: (1 << 0) | (1 << 6),
    };
    if std::mem::size_of::<UserDesc>() != USER_DESC_BYTES { return Err(-libc::EINVAL as i64); }
    // SAFETY: desc is a live userspace ABI object and the syscall copies exactly 16 bytes.
    let rc = unsafe { libc::syscall(SYS_MODIFY_LDT, WRITE_NEW, &desc, USER_DESC_BYTES) };
    (rc == 0).then_some(()).ok_or(rc)
}

fn run() -> Verdict {
    if !cfg!(target_arch = "x86_64") { return fail("x86-only"); }
    if let Err(e) = pin_cpu(0) { return fail(&format!("pin-cpu0:{e}")); }
    let ready = Arc::new(Barrier::new(2));
    let go = Arc::new(Barrier::new(2));
    let worker_ready = Arc::clone(&ready);
    let worker_go = Arc::clone(&go);
    let worker = thread::spawn(move || {
        if let Err(e) = pin_cpu(1) { return Err(format!("pin-cpu1:{e}")); }
        let cpu = current_cpu().map_err(|e| format!("getcpu-worker:{e}"))?;
        line(&format!("{PROBE}: worker_cpu={cpu}"));
        worker_ready.wait();
        worker_go.wait();
        let ldt = sldt();
        if ldt == 0 { return Err("worker-ldtr-empty".to_string()); }
        load_ds().map_err(|_| "worker-ds-load".to_string())?;
        Ok(ldt)
    });
    let main_cpu = match current_cpu() {
        Ok(cpu) => cpu,
        Err(e) => return fail(&format!("getcpu-main:{e}")),
    };
    line(&format!("{PROBE}: main_cpu={main_cpu}"));
    ready.wait();
    if let Err(e) = install() { return fail(&format!("modify_ldt:{e}")); }
    let local_ldt = sldt();
    if local_ldt == 0 { return fail("local-ldtr-empty"); }
    if load_ds().is_err() { return fail("local-ds-load"); }
    go.wait();
    let remote_ldt = match worker.join() {
        Ok(Ok(value)) => value,
        Ok(Err(e)) => return fail(&e),
        Err(_) => return fail("worker-panicked"),
    };
    line(&format!("{PROBE}: local_ldtr={local_ldt:#x} remote_ldtr={remote_ldt:#x} selector={SELECTOR:#x}"));
    Verdict::Pass(format!("local_ldtr={local_ldt:#x} remote_ldtr={remote_ldt:#x}"))
}
