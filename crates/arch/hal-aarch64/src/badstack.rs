// Linux arm64 `__bad_stack` / `handle_bad_stack` (`54§1.6`, `38§3`).
//
// With `CONFIG_VMAP_STACK` Linux bounds-checks SP on every kernel exception
// entry, because pushing an exception frame onto an out-of-range SP writes
// wherever that SP points. Our guard-paged kstacks are adjacent slots in ONE VA
// window, which makes that worse than a plain overflow: a frame based just past
// a stack top has its low half land in the NEIGHBOURING slot and only its high
// half fault on the guard page. When the neighbour is another CPU's per-CPU IRQ
// stack, the result is a silent cross-CPU scribble whose victim is unrelated to
// the cause — the aarch64 `-smp 2` abort (`scratch/arm-smp2-fault.md`).
//
// The entry asm compares SP against the per-CPU published bounds of the current
// task's stack and, when the frame would not fit, switches to this CPU's
// overflow stack and lands here with the interrupted state as arguments.
// Nothing is pushed onto the bad stack first, so the previous frame is intact
// and the report describes the FIRST bad entry rather than its aftermath.
//
// The overflow stack is the tail of this CPU's own per-CPU page: it is already
// mapped, already per-CPU, and only its first 64 bytes are in use (cpu id,
// preempt, SVC frame, IRQ-stack top, this check's scratch), leaving ~4 KiB that
// nothing else touches. That beats a fresh static — no allocation, and it cannot
// itself be the guard-paged memory under suspicion.

use core::sync::atomic::{AtomicPtr, Ordering};

/// Scheduler-side probe for the bad-stack report. `hal` cannot reach `sched`
/// (the dependency runs the other way), and the numbers that classify an
/// overflow — `preempt_count`'s hardirq/softirq fields, the current task, the
/// slot that owns the SP — all live there. Same shape as `fault::CtxDumpFn`.
pub type BadStackProbe = fn(u64);
static PROBE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the scheduler-side probe. Boot path, before any exception.
/// # SAFETY: `f` must be a `'static` fn with the `BadStackProbe` ABI.
/// # C: O(1)
pub unsafe fn install_probe(f: BadStackProbe) { PROBE.store(f as *mut (), Ordering::Release); }

fn probe(sp: u64) {
    let p = PROBE.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: non-null only after `install_probe` stored a valid `BadStackProbe`.
    let f: BadStackProbe = unsafe { core::mem::transmute(p) };
    f(sp);
}

/// `MPIDR_EL1` affinity bits identifying the PE (`Aff3..Aff0`, `23§4`).
const MPIDR_AFF_MASK: u64 = 0x0000_00ff_00ff_ffff;

/// Reported once per CPU. A bad-stack entry halts, but a second CPU can arrive
/// concurrently and interleave its report with the first; the flag keeps the
/// first report readable, which is the one that matters.
static REPORTED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Exception entry found SP outside the current task's kernel stack.
///
/// `bad_sp` is the interrupted `SP_EL1` — the value the frame WOULD have been
/// pushed at. `lo`/`top` are the bounds the entry asm compared it against, read
/// from this CPU's per-CPU area, so the report states the actual comparison
/// rather than a reconstruction.
///
/// # SAFETY: called only from the entry asm's bad-stack path, already switched
/// to this CPU's overflow stack, DAIF masked. Never returns.
/// # C: O(1) — halts
/// # Ctx: exception, IRQ-off, on the overflow stack
#[no_mangle]
pub unsafe extern "C" fn oxide_handle_bad_stack(bad_sp: u64, esr: u64, elr: u64,
                                                far: u64, lo: u64, top: u64,
                                                site: u64) -> ! {
    if REPORTED.fetch_add(1, Ordering::AcqRel) == 0 {
        klog::write_raw(b"[BADSTACK] exception entry with SP outside the current kernel stack site=");
        // 0 = default vector, 1 = kernel/EL0 IRQ vector, 2 = lower-EL sync (SVC + EL0 faults)
        klog::write_dec_u64(site);
        // SPSR names the EL the exception came FROM, which decides whether the
        // entry should have reset SP (EL0) or bounds-checked it (EL1).
        let spsr: u64;
        // SAFETY: `mrs` of SPSR_EL1 — EL1-readable, holds the interrupted PSTATE
        // until eret; no memory operand and no side effects.
        unsafe { core::arch::asm!("mrs {v}, spsr_el1", v = out(reg) spsr, options(nomem, nostack, preserves_flags)); }
        klog::write_raw(b" spsr=");
        klog::write_hex_u64(spsr);
        klog::write_raw(if (spsr & 0xf) == 0 { b" from=EL0\n" } else { b" from=EL1\n" });
        klog::write_raw(b"[BADSTACK] sp_el1=");
        klog::write_hex_u64(bad_sp);
        klog::write_raw(b" stack=[");
        klog::write_hex_u64(lo);
        klog::write_raw(b",");
        klog::write_hex_u64(top);
        klog::write_raw(b"] ");
        // Which side, and by how much — an overshoot past the top is a stale or
        // foreign SP; an undershoot below the low bound is a true overflow.
        if bad_sp > top {
            klog::write_raw(b"ABOVE-TOP by ");
            klog::write_dec_u64(bad_sp - top);
            klog::write_raw(b" (stale/foreign SP, not an overflow)");
        } else {
            klog::write_raw(b"BELOW-LO by ");
            klog::write_dec_u64(lo.saturating_sub(bad_sp));
            klog::write_raw(b" (stack overflow)");
        }
        klog::write_raw(b"\n[BADSTACK] esr=");
        klog::write_hex_u64(esr);
        klog::write_raw(b" elr=");
        klog::write_hex_u64(elr);
        klog::write_raw(b" far=");
        klog::write_hex_u64(far);
        klog::write_raw(b"\n");
        // PE identity, read with `mrs` only: which CPU took this is the first
        // question for an SMP-only fault, and `bad_sp` is where the frame WOULD
        // have gone, so there is no frame to recover a register file from.
        let (mpidr, tpidr): (u64, u64);
        // SAFETY: `mrs` of MPIDR_EL1 / TPIDR_EL1 — EL1-readable system registers with
        // no memory operand and no side effects, as asserted by nomem/nostack.
        unsafe {
            core::arch::asm!("mrs {m}, MPIDR_EL1", "mrs {t}, TPIDR_EL1",
                             m = out(reg) mpidr, t = out(reg) tpidr,
                             options(nomem, nostack, preserves_flags));
        }
        klog::write_raw(b"[BADSTACK] mpidr=");
        klog::write_hex_u64(mpidr & MPIDR_AFF_MASK);
        klog::write_raw(b" tpidr_el1=");
        klog::write_hex_u64(tpidr);
        klog::write_raw(b"\n");
        // Scheduler-side classification: a large HARDIRQ field means IRQs piled
        // up on this stack (each entry costs a 288-byte frame), which is a very
        // different bug from one deep call chain exhausting it.
        probe(bad_sp);
    }
    // Quiesce this PE's GIC CPU interface before parking: `WFI` wake-up is NOT
    // gated by PSTATE.DAIF (ARM ARM D1), so a pending periodic timer we will
    // never ack would make every WFI return immediately and turn the park into a
    // 100 %-CPU spin. Same reasoning as the fatal-fault park in `vbar/asm.rs`.
    loop {
        // SAFETY: ICC_IGRPEN1_EL1 = 0 disables this PE's group-1 interrupt
        // delivery, then WFE/WFI park it. Legal at EL1; the CPU never resumes.
        unsafe {
            core::arch::asm!(
                "msr s3_0_c12_c12_7, xzr",
                "isb",
                "2: wfe",
                "   wfi",
                "   b 2b",
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}
