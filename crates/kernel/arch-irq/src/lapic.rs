// Local APIC bring-up per `22§6` (x86_64 only).
//
// Maps LAPIC's MMIO page (phys typically 0xFEE00000 from MADT) into
// kernel space via the device mapper, asserts IA32_APIC_BASE.E, and
// programs the Spurious Interrupt Vector Register's software-enable
// bit. Reads back the APIC ID + version as a sanity check.
//
// Timer LVT + IRQ wiring rides alongside the IDT vector binding +
// EOI helper that follow this PR.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use core::arch::asm;
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "x86_64")]
const REG_ID:      usize = 0x020;
#[cfg(target_arch = "x86_64")]
const REG_VERSION: usize = 0x030;
#[cfg(target_arch = "x86_64")]
const REG_SVR:     usize = 0x0F0;
#[cfg(target_arch = "x86_64")]
const REG_LVT_TIMER:  usize = 0x320;
#[cfg(target_arch = "x86_64")]
const REG_TIMER_INIT: usize = 0x380;
#[cfg(target_arch = "x86_64")]
const REG_TIMER_CUR:  usize = 0x390;
#[cfg(target_arch = "x86_64")]
const REG_TIMER_DIV:  usize = 0x3E0;

/// SVR bit 8: APIC software enable.
#[cfg(target_arch = "x86_64")]
const SVR_ENABLE:  u32 = 1 << 8;

/// Default spurious-interrupt vector. Lowest 4 bits must be 1 on
/// pre-Pentium-4 hardware; we set 0xFF for compatibility.
#[cfg(target_arch = "x86_64")]
const SPURIOUS_VECTOR: u32 = 0xFF;

/// IA32_APIC_BASE MSR (0x1B). Bit 11 = global enable.
#[cfg(target_arch = "x86_64")]
const MSR_IA32_APIC_BASE: u32 = 0x1B;
#[cfg(target_arch = "x86_64")]
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;

/// Mapped kernel VA after `enable` runs. `0` until then.
#[cfg(target_arch = "x86_64")]
pub static LAPIC_BASE_VA: AtomicU64 = AtomicU64::new(0);

/// Per-CPU tick counter incremented by the timer-IRQ dispatcher.
#[cfg(target_arch = "x86_64")]
pub static TICK_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Cross-CPU resched IPI receive counter. Incremented by the
/// `VEC_RESCHED` arm of `oxide_irq_dispatch`. v1 smoke uses this
/// to validate the IPI path end-to-end (BSP → AP → handler).
#[cfg(target_arch = "x86_64")]
pub static RESCHED_IPI_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Send EOI to the LAPIC. No-op if `enable` hasn't run.
/// # SAFETY: pair with an in-progress IRQ; writes EOI at offset 0xB0.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn eoi() {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return; }
    // SAFETY: per fn contract -- `va` is a Device-attr 4 KiB mapping; offset 0xB0 lies within.
    unsafe { core::ptr::write_volatile((va + 0xB0) as *mut u32, 0); }
}

/// Rust IRQ dispatcher invoked from the per-vector asm stub. Bumps
/// the tick counter, EOIs, sets NEED_RESCHED, then asks the
/// scheduler for the next task and stages it in
/// `oxide_preempt_next_ctx` so the asm tail switches on IRQ exit
/// (per `14§R07`).
///
/// # SAFETY: invoked only from the IRQ entry asm with IRQs masked
/// (interrupt-gate clears IF on entry).
/// # C: O(1)
/// # Ctx: IRQ
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_irq_dispatch(frame: *const u8) {
    // Frame layout (push order in oxide_irq_vec_NN):
    //   err(0) vec(8) r11..rax -- `mov rdi,rsp` happens AFTER the
    //   9 reg pushes, so frame[0..8] = r11 ... frame[72..80] = vec.
    // SAFETY: caller is the per-vector IRQ asm stub which always pushes the same scaffold; offset 72 lies within.
    let vec_tag = unsafe {
        core::ptr::read_volatile(frame.add(72) as *const u64)
    } as u8;

    // EOI on every IRQ vector -- both timer and IPIs need it.
    // SAFETY: dispatcher is the in-progress IRQ; LAPIC was mapped+enabled before STI.
    unsafe { eoi(); }

    match vec_tag {
        hal_x86_64::VEC_TIMER => {
            TICK_COUNT.fetch_add(1, Ordering::Relaxed);
            crate::irqstat::hit_timer();
            // Per-CPU heartbeat + cross-CPU hard-lockup scan (runs on every
            // CPU that ticks, so a frozen CPU is observed by another).
            sched::diag::percpu::tick();
            sched::live::preempt::set_need_resched();
            // /proc/stat per-CPU cputime accounting runs on EVERY CPU — each
            // charges its OWN tick to its own `cpuN` bucket (Linux per-CPU
            // kcpustat). Was the timer taken in user mode? Saved CS sits at
            // frame+96 (r11@0..vec@72, err@80, rip@88, cs@96); ring 3
            // (CS&3==3) = user code was running.
            // SAFETY: `frame` is the per-vector IRQ scaffold pushed by the stub; +96 is the CPU-pushed CS slot, within the saved frame.
            let from_user = unsafe { (core::ptr::read_volatile(frame.add(96) as *const u64) & 3) == 3 };
            sched::cpustat::account(
                if from_user { sched::cpustat::TickKind::User } else { sched::cpustat::TickKind::Idle });
            // UART poll is BSP-only (only the boot CPU owns the UART). The
            // softirq drain is PER-CPU (Linux: every CPU runs its own
            // __do_softirq from irq_exit) — each CPU drains its OWN pending
            // mask below. APs that arm their own periodic timer reach here too.
            let is_bsp = {
                use hal::CpuOps;
                hal_x86_64::X86CpuOps::current_cpu() == ::cpu::smp::boot_cpu_id()
            };
            if is_bsp {
                // TTY input poll per docs/28: scrape pending UART RX into
                // the ringbuffer + wake stdin waiters before the picker.
                // SAFETY: timer ISR ctx with IRQs masked; BSP owns the UART.
                unsafe { crate::tick_poll(from_user); }
            }
            // Per-CPU softirq bottom-half (fbcon flush, virtio-input/net drain)
            // with IRQs locally enabled so device-ack waits make progress. Each
            // CPU drains its own mask; this CPU's IN_PROGRESS guards re-entry.
            if softirq::pending() {
                // SAFETY: EOI issued above; LAPIC accepts next IRQ; per-CPU run_pending guards re-entry; cli restores ISR masking before tick_pick_next.
                unsafe {
                    core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
                    softirq::run_pending();
                    core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
                }
            }
            // The actual switch happens at IRQ exit via
            // `oxide_irq_resched_on_exit` → `schedule()` (one engine); the
            // tick only requested it by setting need_resched above.
        }
        hal_x86_64::VEC_RESCHED => {
            RESCHED_IPI_COUNT.fetch_add(1, Ordering::Relaxed);
            crate::irqstat::hit_resched();
            // Cross-CPU resched IPI: another CPU asked us to pick a new
            // task. Set need_resched; the IRQ-exit slow path
            // (`oxide_irq_resched_on_exit` → `schedule()`) does the switch.
            sched::live::preempt::set_need_resched();
        }
        v if v >= hal_x86_64::VEC_MSI_POOL_FIRST
          && v <= hal_x86_64::VEC_MSI_POOL_LAST => {
            // F58: per-vector MSI delivery. EOI already issued above.
            // Bump the diagnostic counter, then route to the per-vector
            // handler if installed. Falls through to the legacy shared-
            // vector softirq raise so devices that haven't moved to
            // per-vector registration yet still get drained.
            crate::MSI_FIRES.fetch_add(1, Ordering::Relaxed);
            let idx = (v - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
            crate::irqstat::hit_line(idx);
            let raw = crate::MSI_HANDLERS[idx].load(Ordering::Acquire);
            if !raw.is_null() {
                // SAFETY: raw was installed via `register_msi_handler` with the documented `fn()` signature; reverse cast restores the ABI-compatible fn pointer.
                let f: fn() = unsafe { core::mem::transmute(raw) };
                f();
            } else {
                // No registered handler — fall back to the shared-
                // vector softirq raises so any pending used-rings get
                // drained on the next softirq pass.
                softirq::raise(softirq::Slot::InputDrain);
                softirq::raise(softirq::Slot::NetRx);
            }
            if softirq::pending() {
                // SAFETY: EOI was issued above; nested IRQs into the dispatcher are fine — softirq::run_pending guards re-entry via IN_PROGRESS.
                unsafe {
                    core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
                    softirq::run_pending();
                    core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
                }
            }
        }
        _ => { /* unknown vector -- EOI'd, fall through */ }
    }
}

/// IRQ-exit return-to-user reschedule slow path (`14§R07` / `smp-arch.md`
/// Phase A). Every IRQ stub calls this after the dispatcher returns,
/// passing the interrupted frame's saved CS. VOLUNTARY preempt: switch
/// only when returning to user mode (`CS&3==3`) AND a resched was
/// requested at a safe point (`preempt_count==0`, via
/// `should_resched_to_user`). The one `schedule()` performs the switch —
/// there is no IRQ-tail staging engine. `schedule()` preserves the IRQ
/// state of its caller (here the IRQ-exit context's IF=0), so on return
/// IRQs are still masked and the stub's pop+`iretq` tail is atomic (the
/// `iretq` restores the user IF from the frame).
///
/// # SAFETY: invoked only from the IRQ-exit asm with IRQs masked; the
/// interrupted scratch + iretq image live on the current kernel stack and
/// are restored by `oxide_irq_resume_user` after this returns (across the
/// `schedule()` switch, the stack is preserved by the saved Context).
/// # C: O(log N) when it schedules; O(1) otherwise
/// # Ctx: IRQ-exit
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_irq_resched_on_exit(saved_cs: u64) {
    let from_user = (saved_cs & 3) == 3;
    if sched::preempt::should_resched_to_user(from_user) {
        sched::preempt::take_need_resched();
        // SAFETY: IRQ-exit safe point — should_resched_to_user confirmed
        // preempt_count==0 and user-return; the interrupted frame is on the
        // stack and restored after schedule() returns. schedule() preserves
        // this context's IF=0, so IRQs stay masked through the iretq tail.
        unsafe { sched::live::schedule(); }
    }
}

/// Outcome reported by `enable`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LapicStatus {
    /// `enable` already ran.
    AlreadyOn,
    /// LAPIC mapped + software-enabled. Returns (apic_id, version).
    Enabled { apic_id: u32, version: u32 },
}

/// Map LAPIC at `va` (covering `pa`) and software-enable it via SVR.
///
/// # SAFETY: caller asserts `va` is freshly mapped Device-attr over
/// the LAPIC page; runs single-CPU, IRQ-off; no other path is
/// touching the LAPIC. Caller is responsible for the device-mapping
/// step itself (use `hal_x86_64::vmm::map_device_4k`).
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn enable(va: u64) -> LapicStatus {
    if LAPIC_BASE_VA.load(Ordering::Acquire) != 0 {
        return LapicStatus::AlreadyOn;
    }
    // Make sure IA32_APIC_BASE.E is set (Limine leaves it on, but
    // be defensive -- bit 11 is the global enable).
    // SAFETY: rdmsr/wrmsr on IA32_APIC_BASE are privileged but
    // legal at CPL=0; bit 11 is the well-defined global-enable bit.
    unsafe {
        let cur = rdmsr(MSR_IA32_APIC_BASE);
        if (cur & APIC_GLOBAL_ENABLE) == 0 {
            wrmsr(MSR_IA32_APIC_BASE, cur | APIC_GLOBAL_ENABLE);
        }
    }
    // Software-enable via SVR + park spurious-int on vector 0xFF.
    // SAFETY: `va` is the freshly-mapped Device-attr LAPIC page per fn contract; reads/writes lie within its 4 KiB.
    unsafe {
        let svr_addr = (va + REG_SVR as u64) as *mut u32;
        let cur = core::ptr::read_volatile(svr_addr);
        let new = (cur & !0xFF) | SPURIOUS_VECTOR | SVR_ENABLE;
        core::ptr::write_volatile(svr_addr, new);
    }
    // SAFETY: same contract; offset 0x20 + 0x30 within mapped page.
    let (apic_id, version) = unsafe {
        let id = core::ptr::read_volatile((va + REG_ID as u64) as *const u32);
        let ver = core::ptr::read_volatile((va + REG_VERSION as u64) as *const u32);
        // APIC ID is in bits 31:24 on the x2APIC-aware variants;
        // pre-Pentium-4 used bits 31:24 too. Shift down for log.
        (id >> 24, ver)
    };
    LAPIC_BASE_VA.store(va, Ordering::Release);
    LapicStatus::Enabled { apic_id, version }
}

/// Send a resched IPI to the LAPIC `target_apic_id`. The receiver
/// vectors through `oxide_irq_vec_41`, sets need_resched, and the
/// IRQ-exit picker switches if eligible. Returns false if the
/// LAPIC isn't mapped yet.
///
/// # SAFETY: LAPIC enabled on this CPU; IRQs may be masked or not
/// (ICR write is non-blocking -- wait_icr_idle handles serialization).
/// # C: O(spin) bounded by hardware delivery latency
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn send_resched_ipi(target_apic_id: u32) -> bool {
    // SAFETY: LAPIC enabled per fn contract; ICR delivery completes asynchronously, wait_icr_idle bounds prior write.
    unsafe { wait_icr_idle(); }
    let lo = build_icr_lo(hal_x86_64::VEC_RESCHED, 0b000, true, false);
    // SAFETY: same -- ICR write triggers IPI delivery to target.
    let ok = unsafe { write_icr(target_apic_id, lo) };
    if ok {
        // SAFETY: same -- ensure ICR settled before caller assumes delivery.
        unsafe { wait_icr_idle(); }
    }
    ok
}

/// Send a diagnostic NMI IPI to `apic_id`. Delivery mode 0b100 (NMI) so
/// it lands through IF=0 — a CPU spinning in a spinlock deadlock with
/// interrupts masked still takes it. The NMI handler (fault.rs, vector 2)
/// prints RIP/regs + current task then iretq-resumes, so a poke at a CPU
/// that wasn't actually wedged is harmless.
/// # SAFETY: LAPIC enabled on this CPU; ICR write serialised by wait_icr_idle.
/// # C: O(spin) bounded by delivery latency
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn send_nmi_ipi(apic_id: u32) -> bool {
    // SAFETY: LAPIC enabled per fn contract; serialise prior ICR write.
    unsafe { wait_icr_idle(); }
    let lo = build_icr_lo(0, 0b100, true, false); // vector ignored for NMI delivery
    // SAFETY: ICR write triggers NMI delivery to the target APIC.
    let ok = unsafe { write_icr(apic_id, lo) };
    if ok {
        // SAFETY: ensure ICR settled before the caller assumes delivery.
        unsafe { wait_icr_idle(); }
    }
    ok
}

/// Poke hook (`sched::diag::nmi`): the heartbeat indexes CPUs by
/// `current_cpu()` which on x86 is the APIC id, so the logical id passed
/// here IS the target APIC id — send the NMI directly.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn diag_nmi_poke(apic_id: u32) {
    // SAFETY: boot enabled the LAPIC before diag hooks are installed.
    unsafe { let _ = send_nmi_ipi(apic_id); }
}

/// Install the cross-CPU backtrace poke hook. Called once at boot.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn install_diag_hooks() {
    sched::diag::nmi::set_poke_hook(diag_nmi_poke);
}

/// Enable the LAPIC on this AP. Same software-enable + APIC-base
/// MSR set as `enable` but without the AlreadyOn early-return:
/// each CPU has its own LAPIC SVR + IA32_APIC_BASE MSR, and the
/// MMIO at `LAPIC_BASE_VA` aliases to this CPU's LAPIC page.
/// Returns this CPU's APIC ID + version.
///
/// # SAFETY: caller is the AP bring-up path; BSP ran `enable`
/// previously so `LAPIC_BASE_VA` is non-zero. Single-writer for
/// this CPU's per-CPU LAPIC state.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn enable_for_ap() -> (u32, u32) {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return (u32::MAX, 0); }
    // SAFETY: rdmsr/wrmsr on IA32_APIC_BASE are privileged but legal at CPL=0; bit 11 is global enable on this CPU's LAPIC.
    unsafe {
        let cur = rdmsr(MSR_IA32_APIC_BASE);
        if (cur & APIC_GLOBAL_ENABLE) == 0 {
            wrmsr(MSR_IA32_APIC_BASE, cur | APIC_GLOBAL_ENABLE);
        }
    }
    // SAFETY: `va` aliases this CPU's LAPIC page; SVR offset within.
    unsafe {
        let svr_addr = (va + REG_SVR as u64) as *mut u32;
        let cur = core::ptr::read_volatile(svr_addr);
        let new = (cur & !0xFF) | SPURIOUS_VECTOR | SVR_ENABLE;
        core::ptr::write_volatile(svr_addr, new);
    }
    // SAFETY: same -- read this AP's APIC id + version.
    unsafe {
        let id  = core::ptr::read_volatile((va + REG_ID as u64) as *const u32);
        let ver = core::ptr::read_volatile((va + REG_VERSION as u64) as *const u32);
        (id >> 24, ver)
    }
}

/// This CPU's local APIC ID — LAPIC reg 0x20, bits 24-31 (xAPIC).
/// Used by AP bring-up to identify the BSP (skip self) off the MADT.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn local_apic_id() -> u32 {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return 0; }
    // SAFETY: LAPIC page mapped Device-attr by `enable`; reg 0x20 (APIC
    // ID) is within the page; volatile read with no side effects.
    let v = unsafe { core::ptr::read_volatile((va + 0x20) as *const u32) };
    v >> 24
}

/// Rough busy-wait (~`us` µs) for the INIT→SIPI→SIPI hand-off delays
/// (Intel SDM Vol 3 §8.4.4.1). Uncalibrated `pause` spin — QEMU is
/// lenient on AP-startup timing and this only runs during bring-up;
/// avoids depending on a running/calibrated timer (which could hang).
/// # C: O(us)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn busy_wait_us(us: u64) {
    let iters = us.saturating_mul(100);
    for _ in 0..iters {
        // SAFETY: `pause` is a microarchitectural hint, no side effects.
        unsafe { core::arch::asm!("pause", options(nomem, nostack, preserves_flags)); }
    }
}

/// Disarm the LAPIC timer (write 0 to the Initial Count reg).
/// # SAFETY: `enable` ran; LAPIC mapped Device-attr.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn timer_disarm() {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return; }
    // SAFETY: per fn contract; offset 0x380 within the LAPIC page.
    unsafe { core::ptr::write_volatile((va + REG_TIMER_INIT as u64) as *mut u32, 0); }
}

/// Configure the LAPIC timer in periodic mode unmasked at vector
/// 0x40. Caller must have wired IDT[0x40] to an IRQ stub (the
/// default `install_default_idt` does) and must `sti` afterwards
/// to actually receive ticks.
///
/// # SAFETY: `enable` has run; LAPIC is mapped + software-enabled.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn timer_periodic(initial_count: u32) -> bool {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return false; }
    // SAFETY: per fn contract -- LAPIC was mapped Device-attr; offsets within the 4 KiB page.
    unsafe {
        core::ptr::write_volatile((va + REG_TIMER_DIV  as u64) as *mut u32, 0b1011);
        core::ptr::write_volatile((va + REG_LVT_TIMER as u64) as *mut u32, 0x40 | (1 << 17));
        core::ptr::write_volatile((va + REG_TIMER_INIT as u64) as *mut u32, initial_count);
    }
    true
}

/// Configure the LAPIC timer in one-shot mode, masked (no IRQ
/// delivery yet -- this is purely a hardware-tick smoke). Returns
/// the current count register reading after a brief busy spin so
/// the caller can confirm the counter is decrementing.
///
/// `initial_count` is loaded into the timer's Initial Count
/// Register; with divide=0b1011 (1) the LAPIC bus clock decrements
/// the count register by one per cycle.
///
/// # SAFETY: caller asserts `enable` has run and `LAPIC_BASE_VA`
/// is non-zero. Single-CPU, IRQ-off.
/// # C: O(spin)
/// # Ctx: pre-init, single-CPU
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn timer_smoke(initial_count: u32) -> Option<(u32, u32)> {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return None; }
    // SAFETY: LAPIC was previously mapped Device-attr; `va` lives
    // inside that 4 KiB page.
    let (a, b) = unsafe {
        // Divide config: `1011` = divide-by-1 (full bus rate).
        core::ptr::write_volatile((va + REG_TIMER_DIV  as u64) as *mut u32, 0b1011);
        // Mask LVT timer (bit 16 = 1) -- no IRQ delivery; just count.
        // Vector 0x40 is set so when we later unmask, it has a valid value.
        core::ptr::write_volatile((va + REG_LVT_TIMER as u64) as *mut u32, 0x40 | (1 << 16));
        // Load initial count -- the timer starts decrementing.
        core::ptr::write_volatile((va + REG_TIMER_INIT as u64) as *mut u32, initial_count);
        let a = core::ptr::read_volatile((va + REG_TIMER_CUR as u64) as *const u32);
        // Brief busy spin so the count visibly decreases.
        for _ in 0..1024 { core::hint::spin_loop(); }
        let b = core::ptr::read_volatile((va + REG_TIMER_CUR as u64) as *const u32);
        // Stop the timer (initial count = 0 disables one-shot).
        core::ptr::write_volatile((va + REG_TIMER_INIT as u64) as *mut u32, 0);
        (a, b)
    };
    Some((a, b))
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn rdmsr(idx: u32) -> u64 {
    let lo: u32; let hi: u32;
    // SAFETY: rdmsr at CPL=0 with valid MSR index; no memory effect.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") idx,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn wrmsr(idx: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: wrmsr at CPL=0 with valid MSR index + caller-validated value; no memory effect.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") idx,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// AP startup IPI primitives per `20§7` / Intel SDM Vol 3 §10.4.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
const REG_ICR_LO: usize = 0x300;
#[cfg(target_arch = "x86_64")]
const REG_ICR_HI: usize = 0x310;

/// Build an ICR-low value. Pure helper -- hosted-testable.
/// Layout per Intel SDM Vol 3 §10.6.1:
///   bits 0-7: vector
///   bits 8-10: delivery mode
///   bit 11: dest mode (0=physical)
///   bit 14: level (1=assert)
///   bit 15: trigger (0=edge, 1=level)
///   bits 18-19: dest shorthand (00 = explicit dest in ICR-hi)
/// # C: O(1)
pub fn build_icr_lo(vector: u8, delivery: u8, level_assert: bool, level_trigger: bool) -> u32 {
    let mut v = vector as u32;
    v |= ((delivery as u32) & 0x7) << 8;
    if level_assert  { v |= 1 << 14; }
    if level_trigger { v |= 1 << 15; }
    v
}

/// INIT-IPI value (level-asserted edge-trigger): 0x4500. Writing this
/// to ICR-low while ICR-high holds the target APIC ID asserts INIT
/// on the target. AP enters wait-for-SIPI state.
/// # C: O(1)
pub fn icr_lo_init_assert() -> u32 { build_icr_lo(0, 0b101, true, false) }

/// SIPI ICR-low value: 0x4600 | startup_page. The startup page is the
/// real-mode segment (4 KiB units, < 1 MiB) holding the AP trampoline.
/// AP starts execution at `page << 12`.
/// # C: O(1)
pub fn icr_lo_sipi(startup_page: u8) -> u32 { build_icr_lo(startup_page, 0b110, true, false) }

/// Write the LAPIC ICR. Triggers IPI delivery to `target_apic_id`.
/// Returns false if the LAPIC isn't mapped yet.
///
/// # SAFETY: caller asserts the LAPIC is enabled, the ICR write is
/// the appropriate IPI for the AP's current state (INIT first, then
/// SIPI per Intel SDM Vol 3 §10.4.4.1), and IRQs are masked while
/// the ICR delivery-pending bit is being polled by `wait_icr_idle`.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn write_icr(target_apic_id: u32, lo: u32) -> bool {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return false; }
    // ICR-hi: target APIC ID in bits 24-31 (xAPIC physical-dest).
    // SAFETY: per fn contract -- `va` covers a valid LAPIC page; offsets 0x300/0x310 lie within.
    unsafe {
        core::ptr::write_volatile((va + REG_ICR_HI as u64) as *mut u32, target_apic_id << 24);
        core::ptr::write_volatile((va + REG_ICR_LO as u64) as *mut u32, lo);
    }
    true
}

/// Spin until the LAPIC ICR's delivery-status bit (bit 12 of low DW)
/// clears -- the previous IPI has been accepted by the bus.
///
/// # SAFETY: caller is the boot path during AP startup; LAPIC is
/// mapped; IRQs masked.
/// # C: O(spin) -- bounded by hardware delivery latency
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn wait_icr_idle() {
    let va = LAPIC_BASE_VA.load(Ordering::Acquire);
    if va == 0 { return; }
    loop {
        // SAFETY: per fn contract -- LAPIC mapped; offset 0x300 within.
        let lo = unsafe { core::ptr::read_volatile((va + REG_ICR_LO as u64) as *const u32) };
        if (lo & (1 << 12)) == 0 { break; }
        // SAFETY: spin loop hint; pause has no side effect outside microarch hinting.
        unsafe { core::arch::asm!("pause", options(nomem, nostack, preserves_flags)); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lapic_status_distinct() {
        let a = LapicStatus::AlreadyOn;
        let b = LapicStatus::Enabled { apic_id: 0, version: 0 };
        assert_ne!(a, b);
    }

    #[test]
    fn init_ipi_value_per_sdm() {
        // Intel SDM Vol 3 §10.4.4.1 INIT-IPI canonical: vector=0,
        // delivery=101 (INIT), level=1 (assert), trigger=0 (edge).
        // Result: 0x4500.
        assert_eq!(icr_lo_init_assert(), 0x0000_4500);
    }

    #[test]
    fn sipi_value_carries_startup_page() {
        // SIPI canonical: vector = startup_page, delivery=110 (Startup).
        // Result for page 0x08: 0x4608.
        assert_eq!(icr_lo_sipi(0x08), 0x0000_4608);
        assert_eq!(icr_lo_sipi(0x00), 0x0000_4600);
    }

    #[test]
    fn build_icr_lo_combines_fields() {
        let v = build_icr_lo(0x42, 0b001, true, true);
        assert_eq!(v & 0xff,        0x42);             // vector
        assert_eq!((v >> 8) & 0x7,  0b001);            // delivery
        assert_ne!(v & (1 << 14), 0);                  // level assert
        assert_ne!(v & (1 << 15), 0);                  // level trigger
    }
}
