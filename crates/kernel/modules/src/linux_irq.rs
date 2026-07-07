// Linux IRQ KPI exports for loadable drivers.

use core::ffi::c_void;
use sync::{Modules as ModulesLockClass, Spinlock};

type IrqHandler = unsafe extern "C" fn(i32, *mut c_void) -> i32;

const MAX_IRQ_RECORDS: usize = 32;
const LINUX_OK: i32 = 0;
const LINUX_EINVAL: i32 = 22;
const LINUX_EBUSY: i32 = 16;
const LINUX_ENOMEM: i32 = 12;
const LINUX_ENOSYS: i32 = 38;
const IRQF_SHARED: u64 = 0x80;
const IRQF_TRIGGER_NONE: u64 = 0;
#[cfg(target_arch = "aarch64")]
const IRQF_TRIGGER_HIGH: u64 = 0x0000_0004;
#[cfg(target_arch = "aarch64")]
const IRQF_TRIGGER_LOW: u64 = 0x0000_0008;
#[cfg(target_arch = "aarch64")]
const ARM_LPI_BASE: u32 = 8192;

#[derive(Copy, Clone)]
struct IrqRecord {
    irq: u32,
    handler: usize,
    dev_id: usize,
    flags: u64,
    enabled: bool,
}

#[derive(Copy, Clone)]
struct IrqCall {
    handler: usize,
    dev_id: usize,
}

static IRQ_RECORDS: Spinlock<[Option<IrqRecord>; MAX_IRQ_RECORDS], ModulesLockClass> =
    Spinlock::new([None; MAX_IRQ_RECORDS]);

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
    if thread_fn.is_some() { return -LINUX_ENOSYS; }
    let handler = match handler { Some(v) => v, None => return -LINUX_EINVAL };
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
        handler: handler as usize,
        dev_id: dev_id as usize,
        flags,
        enabled: true,
    });
    arch_enable_irq(irq, flags);
    LINUX_OK
}

extern "C" fn free_irq(irq: u32, dev_id: *mut c_void) {
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
}

extern "C" fn disable_irq_nosync(irq: u32) {
    disable_irq(irq);
}

extern "C" fn synchronize_irq(_irq: u32) {}

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
    let mut calls = [IrqCall { handler: 0, dev_id: 0 }; MAX_IRQ_RECORDS];
    let mut n = 0usize;
    {
        let g = IRQ_RECORDS.lock();
        for rec in g.iter().flatten() {
            if rec.irq == irq && rec.enabled {
                calls[n] = IrqCall { handler: rec.handler, dev_id: rec.dev_id };
                n += 1;
            }
        }
    }
    for call in calls.iter().take(n) {
        // SAFETY: handler was installed from a non-null C irq_handler_t in request_irq.
        let f: IrqHandler = unsafe { core::mem::transmute(call.handler) };
        // SAFETY: Linux IRQ handlers own their dev_id contract.
        let _ = unsafe { f(irq as i32, call.dev_id as *mut c_void) };
    }
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
    irq >= ARM_LPI_BASE || arch_irq::intid_is_v2m(irq)
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
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    const TEST_DEV_ID: usize = 0x1000;

    unsafe extern "C" fn test_handler(_irq: i32, dev_id: *mut c_void) -> i32 {
        assert_eq!(dev_id as usize, TEST_DEV_ID);
        HITS.fetch_add(1, Ordering::Relaxed);
        1
    }

    #[test]
    fn request_dispatch_disable_and_free_irq() {
        let irq = hal_x86_64::VEC_MSI_POOL_FIRST as u32;
        HITS.store(0, Ordering::Relaxed);
        assert_eq!(request_irq(irq, Some(test_handler), 0, core::ptr::null(), TEST_DEV_ID as *mut c_void), LINUX_OK);
        assert!(arch_irq::invoke_x86_line_handler(irq as u8));
        assert_eq!(HITS.load(Ordering::Relaxed), 1);
        disable_irq(irq);
        assert!(arch_irq::invoke_x86_line_handler(irq as u8));
        assert_eq!(HITS.load(Ordering::Relaxed), 1);
        enable_irq(irq);
        assert!(arch_irq::invoke_x86_line_handler(irq as u8));
        assert_eq!(HITS.load(Ordering::Relaxed), 2);
        free_irq(irq, TEST_DEV_ID as *mut c_void);
        assert!(!arch_irq::invoke_x86_line_handler(irq as u8));
    }

    #[test]
    fn rejects_duplicate_unshared_and_threaded_irq() {
        let irq = hal_x86_64::VEC_MSI_POOL_FIRST as u32 + 1;
        assert_eq!(request_irq(irq, Some(test_handler), 0, core::ptr::null(), TEST_DEV_ID as *mut c_void), LINUX_OK);
        assert_eq!(request_irq(irq, Some(test_handler), 0, core::ptr::null(), (TEST_DEV_ID + 1) as *mut c_void), -LINUX_EBUSY);
        free_irq(irq, TEST_DEV_ID as *mut c_void);
        assert_eq!(
            request_threaded_irq(irq, Some(test_handler), Some(test_handler), 0, core::ptr::null(), TEST_DEV_ID as *mut c_void),
            -LINUX_ENOSYS
        );
    }

    #[test]
    fn export_symbols_registers_irq_surface() {
        crate::symtab::_reset();
        export_symbols();
        for name in [
            "request_irq", "request_threaded_irq", "free_irq", "enable_irq",
            "disable_irq", "disable_irq_nosync", "synchronize_irq", "in_irq",
        ] {
            assert!(crate::symtab::is_exported(name));
        }
    }
}
