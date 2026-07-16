// Linux IRQ KPI exports for loadable drivers.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Modules as ModulesLockClass, Spinlock};

type IrqHandler = unsafe extern "C" fn(i32, *mut c_void) -> i32;

mod ids;

const MAX_IRQ_RECORDS: usize = 32;
const LINUX_OK: i32 = 0;
const LINUX_EINVAL: i32 = 22;
const LINUX_EBUSY: i32 = 16;
const LINUX_ENOMEM: i32 = 12;
const IRQF_SHARED: u64 = 0x80;
const IRQF_ONESHOT: u64 = 0x0000_2000;
const IRQF_TRIGGER_NONE: u64 = 0;
const IRQ_WAKE_THREAD: i32 = 2;
#[cfg(target_arch = "aarch64")]
const IRQF_TRIGGER_HIGH: u64 = 0x0000_0004;
#[cfg(target_arch = "aarch64")]
const IRQF_TRIGGER_LOW: u64 = 0x0000_0008;
#[derive(Copy, Clone)]
struct IrqRecord {
    irq: u32,
    handler: usize,
    thread_fn: usize,
    dev_id: usize,
    flags: u64,
    enabled: bool,
    pending: u32,
    running: u32,
}

#[derive(Copy, Clone)]
struct IrqCall {
    handler: usize,
    thread_fn: usize,
    dev_id: usize,
    slot: usize,
}

static IRQ_RECORDS: Spinlock<[Option<IrqRecord>; MAX_IRQ_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_IRQ_RECORDS]);
#[cfg(target_os = "oxide-kernel")]
static IRQ_THREAD_WAIT: sched::live::WaitList = sched::live::WaitList::new();
static IRQ_THREAD_STARTED: AtomicBool = AtomicBool::new(false);

/// Register Linux IRQ KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("request_irq",              request_irq              as *const () as usize),
        ("request_threaded_irq",     request_threaded_irq     as *const () as usize),
        ("free_irq",                 free_irq                 as *const () as usize),
        ("enable_irq",               enable_irq               as *const () as usize),
        ("disable_irq",              disable_irq              as *const () as usize),
        ("disable_irq_nosync",       disable_irq_nosync       as *const () as usize),
        ("synchronize_irq",          synchronize_irq          as *const () as usize),
        ("irq_set_affinity_hint",    irq_set_affinity_hint    as *const () as usize),
        ("irq_update_affinity_hint", irq_update_affinity_hint as *const () as usize),
        ("in_irq",                   in_irq                   as *const () as usize),
        ("in_interrupt",             in_interrupt             as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn request_irq(
    irq: u32,
    handler: Option<IrqHandler>,
    flags: u64,
    name: *const u8,
    dev_id: *mut c_void,
) -> i32 {
    request_threaded_irq(irq, handler, None, flags, name, dev_id)
}

extern "C" fn request_threaded_irq(
    irq: u32,
    handler: Option<IrqHandler>,
    thread_fn: Option<IrqHandler>,
    flags: u64,
    _name: *const u8,
    dev_id: *mut c_void,
) -> i32 {
    if handler.is_none() && thread_fn.is_none() { return -LINUX_EINVAL; }
    if (flags & IRQF_SHARED) != 0 && dev_id.is_null() { return -LINUX_EINVAL; }
    let mut g = IRQ_RECORDS.lock();
    let shared = (flags & IRQF_SHARED) != 0;
    let mut has_line = false;
    for rec in g.iter().flatten() {
        if rec.irq != irq { continue; }
        has_line = true;
        if rec.dev_id == dev_id as usize { return -LINUX_EBUSY; }
        if !shared || (rec.flags & IRQF_SHARED) == 0 { return -LINUX_EBUSY; }
    }
    let slot = match g.iter().position(Option::is_none) {
        Some(v) => v,
        None => return -LINUX_ENOMEM,
    };
    if !has_line && install_arch_handler(irq).is_err() { return -LINUX_EINVAL; }
    g[slot] = Some(IrqRecord {
        irq,
        handler: handler.map(|v| v as usize).unwrap_or(0),
        thread_fn: thread_fn.map(|v| v as usize).unwrap_or(0),
        dev_id: dev_id as usize,
        flags,
        enabled: true,
        pending: 0,
        running: 0,
    });
    arch_enable_irq(irq, flags);
    if thread_fn.is_some() { ensure_irq_thread(); }
    LINUX_OK
}

extern "C" fn free_irq(irq: u32, dev_id: *mut c_void) {
    {
        let mut g = IRQ_RECORDS.lock();
        if let Some(rec) = g.iter_mut().flatten().find(|rec| rec.irq == irq && rec.dev_id == dev_id as usize) {
            rec.enabled = false;
        }
    }
    synchronize_irq(irq);
    let free_arch = {
        let mut g = IRQ_RECORDS.lock();
        if let Some(idx) = g.iter().position(|r| {
            r.is_some_and(|rec| rec.irq == irq && rec.dev_id == dev_id as usize)
        }) {
            g[idx] = None;
        }
        !g.iter().flatten().any(|rec| rec.irq == irq)
    };
    if free_arch {
        let _ = free_arch_handler(irq);
        arch_disable_irq(irq);
    }
}

extern "C" fn enable_irq(irq: u32) {
    set_irq_enabled(irq, true);
    arch_enable_irq(irq, IRQF_TRIGGER_NONE);
}

extern "C" fn disable_irq(irq: u32) {
    set_irq_enabled(irq, false);
    arch_disable_irq(irq);
    synchronize_irq(irq);
}

extern "C" fn disable_irq_nosync(irq: u32) {
    set_irq_enabled(irq, false);
    arch_disable_irq(irq);
}

extern "C" fn synchronize_irq(irq: u32) {
    drain_irq_threads();
    #[cfg(target_os = "oxide-kernel")]
    while irq_thread_busy(irq) {
        // SAFETY: synchronize_irq is process context; yielding lets the IRQ worker drain.
        unsafe { sched::live::park_yield(); }
        drain_irq_threads();
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = irq;
}

extern "C" fn irq_set_affinity_hint(_irq: u32, _mask: *const c_void) -> i32 { LINUX_OK }
extern "C" fn irq_update_affinity_hint(_irq: u32, _mask: *const c_void) -> i32 { LINUX_OK }

extern "C" fn in_irq() -> i32 {
    if sched::preempt::in_interrupt() { 1 } else { 0 }
}

extern "C" fn in_interrupt() -> i32 {
    in_irq()
}

fn set_irq_enabled(irq: u32, enabled: bool) {
    let mut g = IRQ_RECORDS.lock();
    for rec in g.iter_mut().flatten() {
        if rec.irq == irq { rec.enabled = enabled; }
    }
}

fn linux_irq_dispatch(irq: u32) {
    let mut calls = [IrqCall { handler: 0, thread_fn: 0, dev_id: 0, slot: 0 }; MAX_IRQ_RECORDS];
    let mut n = 0usize;
    {
        let g = IRQ_RECORDS.lock();
        for (slot, rec) in g.iter().enumerate().filter_map(|(i, r)| r.map(|v| (i, v))) {
            if rec.irq == irq && rec.enabled {
                calls[n] = IrqCall { handler: rec.handler, thread_fn: rec.thread_fn, dev_id: rec.dev_id, slot };
                n += 1;
            }
        }
    }
    for call in calls.iter().take(n) {
        let wake = if call.handler == 0 {
            call.thread_fn != 0
        } else {
            // SAFETY: handler was installed from a non-null C irq_handler_t in request_irq.
            let f: IrqHandler = unsafe { core::mem::transmute(call.handler) };
            // SAFETY: Linux IRQ handlers own their dev_id contract.
            (unsafe { f(irq as i32, call.dev_id as *mut c_void) }) == IRQ_WAKE_THREAD
        };
        if wake && call.thread_fn != 0 { wake_irq_thread(call.slot); }
    }
}

fn ensure_irq_thread() {
    if IRQ_THREAD_STARTED.load(Ordering::Acquire) { return; }
    #[cfg(target_os = "oxide-kernel")]
    if IRQ_THREAD_STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let tid = sched::live::next_tid();
        // SAFETY: request_threaded_irq runs after scheduler init in the kernel module path.
        if let Ok(task) = unsafe { sched::live::spawn_kernel_thread(tid, "irqthread", irq_thread_entry, 0) } {
            core::mem::forget(task);
        } else {
            IRQ_THREAD_STARTED.store(false, Ordering::Release);
        }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    IRQ_THREAD_STARTED.store(true, Ordering::Release);
}

fn wake_irq_thread(slot: usize) {
    {
        let mut g = IRQ_RECORDS.lock();
        if let Some(rec) = g.get_mut(slot).and_then(Option::as_mut) {
            rec.pending = rec.pending.saturating_add(1);
            if (rec.flags & IRQF_ONESHOT) != 0 { rec.enabled = false; }
        }
    }
    #[cfg(target_os = "oxide-kernel")]
    IRQ_THREAD_WAIT.wake_one();
    #[cfg(not(target_os = "oxide-kernel"))]
    drain_irq_threads();
}

#[cfg(target_os = "oxide-kernel")]
extern "C" fn irq_thread_entry(_arg: usize) -> ! {
    loop {
        drain_irq_threads();
        // SAFETY: irqthread is the running task and yields immediately after parking.
        unsafe { IRQ_THREAD_WAIT.park(); }
        // SAFETY: irqthread just parked itself and must schedule away.
        unsafe { sched::live::park_yield(); }
    }
}

fn drain_irq_threads() {
    while let Some(call) = take_pending_thread() {
        // SAFETY: thread_fn was installed from a non-null C irq_handler_t in request_threaded_irq.
        let f: IrqHandler = unsafe { core::mem::transmute(call.thread_fn) };
        // SAFETY: Linux threaded IRQ handlers own their dev_id contract.
        let _ = unsafe { f(call.handler as i32, call.dev_id as *mut c_void) };
        finish_thread(call.slot);
    }
}

fn take_pending_thread() -> Option<IrqCall> {
    let mut g = IRQ_RECORDS.lock();
    for (slot, rec) in g.iter_mut().enumerate() {
        let rec = match rec { Some(v) => v, None => continue };
        if rec.pending == 0 || rec.thread_fn == 0 { continue; }
        rec.pending -= 1;
        rec.running = rec.running.saturating_add(1);
        return Some(IrqCall { handler: rec.irq as usize, thread_fn: rec.thread_fn, dev_id: rec.dev_id, slot });
    }
    None
}

fn finish_thread(slot: usize) {
    let mut g = IRQ_RECORDS.lock();
    if let Some(rec) = g.get_mut(slot).and_then(Option::as_mut) {
        rec.running = rec.running.saturating_sub(1);
        if rec.running == 0 && rec.pending == 0 && (rec.flags & IRQF_ONESHOT) != 0 {
            rec.enabled = true;
            arch_enable_irq(rec.irq, rec.flags);
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn irq_thread_busy(irq: u32) -> bool {
    let g = IRQ_RECORDS.lock();
    g.iter().flatten().any(|rec| rec.irq == irq && (rec.pending != 0 || rec.running != 0))
}

fn install_arch_handler(irq: u32) -> Result<(), ()> {
    #[cfg(target_arch = "x86_64")]
    { arch_irq::register_irq_line_handler(irq, linux_irq_dispatch) }
    #[cfg(target_arch = "aarch64")]
    {
        if arm_irq_is_msi(irq) {
            arch_irq::register_msi_line_handler(irq, linux_irq_dispatch)
        } else {
            arch_irq::request_arm_irq_line_handler(irq, linux_irq_dispatch)
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = irq; Err(()) }
}

fn free_arch_handler(irq: u32) -> Result<(), ()> {
    #[cfg(target_arch = "x86_64")]
    { arch_irq::free_irq_line_handler(irq) }
    #[cfg(target_arch = "aarch64")]
    {
        if arm_irq_is_msi(irq) { arch_irq::free_msi_line_handler(irq) }
        else { arch_irq::free_arm_irq_line_handler(irq) }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = irq; Err(()) }
}

#[cfg(target_arch = "aarch64")]
fn arm_irq_is_msi(irq: u32) -> bool {
    irq >= ids::ARM_LPI_BASE || arch_irq::intid_is_v2m(irq)
}

fn arch_enable_irq(irq: u32, flags: u64) {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    // SAFETY: request_irq owns the INTID before changing controller state.
    unsafe {
        if (flags & (IRQF_TRIGGER_LOW | IRQF_TRIGGER_HIGH)) != 0 {
            arch_irq::gic::enable_intid_level(irq);
        } else {
            arch_irq::gic::enable_intid(irq);
        }
    }
    #[cfg(not(all(target_os = "oxide-kernel", target_arch = "aarch64")))]
    { let _ = (irq, flags); }
}

fn arch_disable_irq(irq: u32) {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    // SAFETY: free_irq owns the line before changing controller state.
    unsafe {
        arch_irq::gic::disable_intid(irq);
    }
    #[cfg(not(all(target_os = "oxide-kernel", target_arch = "aarch64")))]
    { let _ = irq; }
}

#[cfg(test)]
mod tests;
