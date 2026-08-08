// EL1 exception printer per `21§5`. Called from
// `oxide_default_vector_handler` (asm in `vbar.rs`) with the three
// system registers most useful for triage:
//
//   x0 = ESR_EL1   exception syndrome (cause + ISS)
//   x1 = FAR_EL1   fault address (data/instruction abort)
//   x2 = ELR_EL1   return address (instruction at exception)
//   x3 = saved x30 user link register
//   x4 = SP_EL0    user stack pointer
//   x5 = x8        indirect branch target at the fault
//   x6 = x26       dynamic-loader initializer-list base
//
// Emits a one-line summary via `klog::write_raw` then returns; the
// asm caller halts via `wfi` after `bl`.

// Abort exception classes. Ungated: the runaway guard keys every build's abort
// on FAR_EL1 rather than ELR_EL1 and so reads all four, alongside the uaccess
// exception-table fixup (same-EL only) and the oops printer's DFSC decode.
const EC_INSN_ABORT_SAME: u32 = 0x21;
const EC_DATA_ABORT_SAME: u32 = 0x25;
// Lower-EL (userspace) abort classes. A lower-EL abort is never a candidate for
// the kernel fixup table, so that classifier skips it.
const EC_INSN_ABORT_LOWER: u32 = 0x20;
const EC_DATA_ABORT_LOWER: u32 = 0x24;

/// MPIDR_EL1 affinity bits (Aff3..Aff0), the PE's stable identity.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const MPIDR_AFF_MASK: u64 = 0x0000_00ff_00ff_ffff;

// Consumed by the CPACR_EL1.FPEN re-enable arm, which is kernel-target only.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const EC_FP_SIMD_TRAP: u32 = 0x07;

/// Saved-`ELR_EL1` byte offset in the 288-byte exception frame. Shared by all
/// four vector frames (SVC / software-step / undef / fault) per `vbar/asm.rs`.
// Written only by the exception-table fixup arm (kernel target only).
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const FRAME_ELR_OFF: u64 = 176;

/// Optional fault handler. Default is `default_handler` which
/// returns `false` (= asm halts). Kernel installs a real handler
/// via `install_fault_handler` once VMM AddressSpace integration
/// is in. The returned `bool` is the recovery signal: `true` =
/// asm `eret`s (CPU retries the faulting instruction); `false` =
/// asm `wfi`s forever.
pub type FaultHandler = fn(esr: u64, far: u64, elr: u64) -> bool;

fn default_handler(_esr: u64, _far: u64, _elr: u64) -> bool { false }

/// Fatal-fault context-dump hook. `sched` owns the task / kstack / switch-ring
/// state a register-corruption post-mortem needs, but `sched` depends on this
/// crate — so the printer calls out through a boot-installed fn pointer.
/// Argument is the 288-byte exception-frame base on the interrupted stack.
/// Unconditional here (a null-pointer check on a path that only runs when an
/// abort is unrecoverable); the sched-side producer is gated `debug-armctx`.
pub type CtxDumpFn = fn(frame: u64);

static CTX_DUMP: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Install the fatal-fault context dump. Boot path only.
/// # SAFETY: `f` must live for the rest of the kernel's lifetime; called
/// single-CPU pre-init with no concurrent fault.
/// # C: O(1)
pub unsafe fn install_ctx_dump(f: CtxDumpFn) {
    CTX_DUMP.store(f as *const () as *mut (), core::sync::atomic::Ordering::Release);
}

fn ctx_dump(frame: u64) {
    let p = CTX_DUMP.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: non-null only after `install_ctx_dump` stored a valid `CtxDumpFn`.
    let f: CtxDumpFn = unsafe { core::mem::transmute(p) };
    f(frame);
}

static FAULT_HANDLER: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(default_handler as *const () as *mut ());

/// Install a kernel-side fault handler. Returns the previous one.
/// # SAFETY: caller must guarantee `h` lives for the rest of the
/// kernel's lifetime; single-CPU pre-init context (no concurrent
/// faults during the swap).
/// # C: O(1)
pub unsafe fn install_fault_handler(h: FaultHandler) -> FaultHandler {
    let new = h as *const () as *mut ();
    let prev = FAULT_HANDLER.swap(new, core::sync::atomic::Ordering::AcqRel);
    // SAFETY: `prev` was installed via this same fn (or the default initialiser) which only writes valid `FaultHandler` values; the transmute is sound under that single-writer invariant.
    unsafe { core::mem::transmute::<*mut (), FaultHandler>(prev) }
}

fn current_handler() -> FaultHandler {
    let p = FAULT_HANDLER.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: non-null by initialisation; written only by `install_fault_handler` with valid `FaultHandler` values.
    unsafe { core::mem::transmute::<*mut (), FaultHandler>(p) }
}

/// Which CPU's runaway records this abort belongs to. MPIDR affinity is read
/// straight from the PE, so the guard works before any per-CPU kernel structure
/// is up — an abort during early boot is exactly when it must.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn fault_cpu() -> usize {
    hal::fault_reentry::slot(crate::cpuid::mpidr_el1() & MPIDR_AFF_MASK)
}

/// What makes two aborts "the same" for the runaway guard: an abort repeats on
/// its faulting ADDRESS, every other exception class on the instruction that
/// raised it.
/// # C: O(1)
pub fn fault_key(esr: u64, far: u64, elr: u64) -> u64 {
    let ec = ((esr >> 26) & 0x3f) as u32;
    if matches!(ec, EC_INSN_ABORT_LOWER | EC_INSN_ABORT_SAME
                  | EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME) { far } else { elr }
}

/// Rust-side EL1 fault printer + handler dispatcher. Returns
/// `true` if the registered handler chose to recover (= caller
/// asm should `eret`), `false` to halt.
///
/// # SAFETY: caller is the shared default vector handler. We only
/// read function arguments; klog uses the global byte sink.
/// # C: O(constant)
/// # Ctx: exception, IRQ-off (DAIF set by handler)
#[no_mangle]
pub unsafe extern "C" fn oxide_fault_print_rust(esr: u64, far: u64, elr: u64,
                                                  x30: u64, sp_el0: u64, x8: u64, x26: u64,
                                                  frame: u64) -> bool {
    // EL1-origin only, decided from the frame's saved SPSR. An EL0 abort cannot
    // run away this way: it is either resolved or turned into a signal, and
    // either answer returns to userspace rather than re-entering the dispatcher
    // one frame deeper — and its SP names the USER stack, which says nothing
    // about kernel nesting.
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    let mut from_kernel = false;
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    if frame != 0 {
        // SAFETY: the vector passes its live, 288-byte SvcFrame base.
        let spsr = unsafe { (*(frame as *const crate::SvcFrame)).spsr_el1 };
        let from_user = hal::uregs::aarch64::user_mode(spsr);
        from_kernel = !from_user;
        if from_user {
            // SAFETY: this declaration matches arch-irq's link-time bridge.
            unsafe extern "C" { fn oxide_vtime_user_exit(); }
            // SAFETY: arch-irq supplies the scheduler bridge with this ABI.
            unsafe { oxide_vtime_user_exit(); }
        }
    }
    // Runaway guard, BEFORE the resolver is consulted. An abort already in
    // flight at this address on this kernel stack cannot be resolved by running
    // the same resolver again; doing so is what walked the stack down into its
    // guard page. Report and halt instead, with nothing but raw register values
    // — the resolver, `showregs` and the provenance dumps below all touch
    // memory, and the state that produced a runaway is the last state to trust
    // with that.
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    if from_kernel
        && hal::fault_reentry::enter(fault_cpu(), fault_key(esr, far, elr), frame,
                                     hal::KERNEL_STACK_BYTES as u64) == hal::fault_reentry::Verdict::Runaway {
        klog::write_raw(b"[FAULT] BUG: runaway abort, same address re-entered on this stack - halting. esr=");
        klog::write_hex_u64(esr);
        klog::write_raw(b" far=");
        klog::write_hex_u64(far);
        klog::write_raw(b" elr=");
        klog::write_hex_u64(elr);
        klog::write_raw(b" frame=");
        klog::write_hex_u64(frame);
        klog::write_raw(b"\n");
        return false;
    }

    // Consult the registered handler first. A resolved abort (e.g.
    // demand-page) is normal kernel operation per `11§5` — silent in
    // production, no log line. Only log loudly when the handler can't
    // resolve and we're about to halt.
    // `mut` only on the kernel target: the two recovery blocks below that
    // reassign `handled` are both `#[cfg(aarch64 + oxide-kernel)]`.
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    let mut handled = (current_handler())(esr, far, elr);
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    let handled = (current_handler())(esr, far, elr);
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    if !handled && (((esr >> 26) & 0x3f) as u32) == EC_FP_SIMD_TRAP {
        // v1 keeps FP/SIMD enabled for kernel and userspace. A firmware or
        // exception-return path may clear CPACR_EL1.FPEN; restore that
        // architectural invariant and retry the trapped instruction.
        crate::fpu_enable();
        handled = true;
    }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let ec = ((esr >> 26) & 0x3f) as u32;
        if !handled && matches!(ec, EC_INSN_ABORT_SAME | EC_DATA_ABORT_SAME) && far < hal::USER_VA_END {
            if let Some(fixup) = crate::exception_table::lookup(elr) {
                // Redirect the post-eret PC by patching the FRAME's ELR slot,
                // not the live ELR_EL1: the vector's `kernel_exit` restores
                // ELR/SPSR from the frame (it must — a handler that blocks lets
                // another task's exception clobber the system registers), so a
                // live-register write would be discarded.
                // SAFETY: `frame` is this exception's 288-byte frame base on the
                // current kernel stack, published by oxide_default_vector_handler;
                // FRAME_ELR_OFF is its saved-ELR_EL1 slot. `fixup` is
                // linker-retained executable text.
                unsafe { core::ptr::write_volatile((frame + FRAME_ELR_OFF) as *mut u64, fixup); }
                handled = true;
            }
        }
    }
    if !handled {
        // Default-ON oops (see hal-x86_64 fault.rs): never halt silently.
        // debug-watchdog is default-on via the boot crates; zero bytes on a
        // healthy boot since this only runs when the abort is unrecoverable.
        #[cfg(any(feature = "debug-irq", feature = "debug-watchdog"))]
        {
            let ec = ((esr >> 26) & 0x3f) as u32;        // ESR_EL1.EC bits 26..31
            let iss = esr & 0xff_ffff;                   // ESR_EL1.ISS bits 0..24
            klog::write_raw(b"[FAULT] esr=");
            klog::write_hex_u64(esr);
            klog::write_raw(b" ec=");
            klog::write_hex_u64(ec as u64);
            klog::write_raw(b" (");
            klog::write_raw(ec_label(ec));
            klog::write_raw(b") far=");
            klog::write_hex_u64(far);
            klog::write_raw(b" elr=");
            klog::write_hex_u64(elr);
            klog::write_raw(b" lr=");
            klog::write_hex_u64(x30);
            klog::write_raw(b" sp=");
            klog::write_hex_u64(sp_el0);
            klog::write_raw(b" x8=");
            klog::write_hex_u64(x8);
            klog::write_raw(b" x26=");
            klog::write_hex_u64(x26);
            // For data/instruction-abort EC values, decode the ISS DFSC
            // sub-field per ARM ARM D17.2.40 / D17.2.36.
            if matches!(ec, EC_INSN_ABORT_LOWER | EC_INSN_ABORT_SAME | EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME) {
                klog::write_raw(b" dfsc=");
                klog::write_raw(decode_dfsc(iss as u64));
                // WnR (bit 6 of ISS) only meaningful for data aborts.
                if matches!(ec, EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME) {
                    klog::write_raw(if (iss & (1 << 6)) != 0 { b" W" } else { b" R" });
                }
            }
            klog::write_raw(b"\n");
            // Full register file + PE identity + free-IP provenance over every
            // GPR (`showregs`, Linux `show_regs` parity). Replaces a scan of
            // three hand-picked registers: the register carrying a wild pointer
            // is not knowable in advance, and an SMP-only abort is
            // unattributable without the CPU it fired on.
            // SAFETY: `frame` is this exception's 288-byte frame base on the current
            // kernel stack, published by the vector handler that called us.
            unsafe { crate::showregs::dump(frame); }
        }
        #[cfg(not(any(feature = "debug-irq", feature = "debug-watchdog")))]
        { let _ = (esr, far, elr, x30, sp_el0, x8, x26); }
        // Register-corruption post-mortem (kstack-slot ownership of the
        // interrupted SP, the task's saved arch_ctx, the switch save/restore
        // ring). No-op unless a producer was installed; only ever runs on an
        // unrecoverable abort, so a healthy boot emits nothing.
        ctx_dump(frame);
    }
    // Retire this frame's runaway record. The abort is settled — resolved,
    // fixed up, or about to halt — so it is no longer in flight and must not
    // make the next abort at the same address look like a recursion.
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    if from_kernel { hal::fault_reentry::leave(fault_cpu(), frame); }
    handled
}

/// Map an `ESR_EL1.EC` value to a short label per ARM ARM
/// D17.2.36 Tab. D17-2 (the cases we expect in v1; other classes
/// fall through to `"unknown"`).
// Oops-printer only; the host unit tests below pin the table.
#[cfg(any(test, feature = "debug-irq", feature = "debug-watchdog"))]
const fn ec_label(ec: u32) -> &'static [u8] {
    match ec {
        0x00 => b"unknown",
        0x07 => b"sve/fp/simd-trap",
        0x0e => b"illegal-execution",
        0x15 => b"svc-aarch64",
        0x18 => b"msr/mrs/sys-trap",
        0x20 => b"insn-abort-lower-el",
        0x21 => b"insn-abort-same-el",
        0x22 => b"pc-alignment",
        0x24 => b"data-abort-lower-el",
        0x25 => b"data-abort-same-el",
        0x26 => b"sp-alignment",
        0x2c => b"trapped-fp64",
        0x2f => b"serror",
        0x30 => b"breakpoint-lower-el",
        0x31 => b"breakpoint-same-el",
        0x32 => b"step-lower-el",
        0x33 => b"step-same-el",
        0x34 => b"watchpoint-lower-el",
        0x35 => b"watchpoint-same-el",
        0x3c => b"brk",
        _    => b"unknown",
    }
}

/// Decode the Data/Instruction-abort `DFSC` (ESR.ISS bits 0..5)
/// per ARM ARM D17.2.40 Tab. D17-22. Only the cases we expect are
/// listed; the rest fall through to `"other"`.
// Same gate as `ec_label`: oops-printer-only, plus the host tests below.
#[cfg(any(test, feature = "debug-irq", feature = "debug-watchdog"))]
const fn decode_dfsc(iss: u64) -> &'static [u8] {
    match iss & 0x3f {
        0b000000 => b"address-size-l0",
        0b000001 => b"address-size-l1",
        0b000010 => b"address-size-l2",
        0b000011 => b"address-size-l3",
        0b000100 => b"translation-l0",
        0b000101 => b"translation-l1",
        0b000110 => b"translation-l2",
        0b000111 => b"translation-l3",
        0b001001 => b"access-flag-l1",
        0b001010 => b"access-flag-l2",
        0b001011 => b"access-flag-l3",
        0b001101 => b"permission-l1",
        0b001110 => b"permission-l2",
        0b001111 => b"permission-l3",
        0b010000 => b"sync-external",
        0b010001 => b"tag-check",
        0b100001 => b"alignment",
        _        => b"other",
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_dfsc, ec_label, fault_key};

    /// The runaway guard keys an abort on FAR_EL1 — the address it faulted at —
    /// and every other exception class on ELR_EL1, the instruction that raised
    /// it. FAR_EL1 is not architecturally valid for a non-abort class, so
    /// keying on it there would compare a stale register.
    #[test]
    fn fault_key_is_far_for_aborts_and_elr_otherwise() {
        const ELR: u64 = 0xffff_0000_0800_0000;
        const FAR: u64 = 0x7ffe_dead_0000;
        for ec in [0x20u64, 0x21, 0x24, 0x25] {
            assert_eq!(fault_key(ec << 26, FAR, ELR), FAR, "abort class keys on FAR_EL1");
        }
        for ec in [0x07u64, 0x15, 0x2f] {
            assert_eq!(fault_key(ec << 26, FAR, ELR), ELR, "non-abort class keys on ELR_EL1");
        }
    }

    #[test]
    fn ec_label_matches_arm_arm_d17_2_36() {
        assert_eq!(ec_label(0x15), b"svc-aarch64");
        assert_eq!(ec_label(0x21), b"insn-abort-same-el");
        assert_eq!(ec_label(0x25), b"data-abort-same-el");
        assert_eq!(ec_label(0x99), b"unknown");
    }

    #[test]
    fn decode_dfsc_translation_levels() {
        assert_eq!(decode_dfsc(0b000100), b"translation-l0");
        assert_eq!(decode_dfsc(0b000111), b"translation-l3");
    }

    #[test]
    fn decode_dfsc_permission_levels() {
        assert_eq!(decode_dfsc(0b001101), b"permission-l1");
        assert_eq!(decode_dfsc(0b001111), b"permission-l3");
    }

    #[test]
    fn decode_dfsc_uses_only_low_6_bits() {
        // ISS bits above DFSC (incl. WnR) don't perturb the decode.
        assert_eq!(decode_dfsc(0xffff_ffff_ffff_ff04), decode_dfsc(0b000100));
    }
}
