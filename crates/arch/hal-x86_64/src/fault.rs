// CPU-exception fault handler per `22§4`.
//
// Fault entry stubs live in `stubs`; this file is the manifest and
// public dispatch surface for x86_64 exception handling.

mod stubs;

pub use stubs::vector_stub_addr;

/// Frame layout at `oxide_fault_common` entry — see module-level
/// stack diagram. Mutable via `*mut` so the user-trap hook can
/// clear RFLAGS.TF after a single-step #DB.
#[repr(C)]
pub struct FaultFrame {
    pub vector:    u64,
    pub error:     u64,
    pub rip:       u64,
    pub cs:        u64,
    pub rflags:    u64,
    pub rsp:       u64,
    pub ss:        u64,
}

/// Snapshot of every general-purpose register at the moment of
/// the fault. Pushed by the per-vector stub in the order shown by
/// the module-level stack diagram, then handed to
/// `oxide_fault_print_rust` so the diagnostic can name the bad
/// register on a user-mode #GP / #UD / etc. Callee-saved regs
/// (rbx, rbp, r12-r15) are captured BEFORE the Rust dispatcher
/// runs — by SysV they survive the call, so on stub entry they
/// still hold the user's values.
#[repr(C)]
pub struct FaultGprs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9:  u64,
    pub r8:  u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
}

/// Read CR2 (page-fault linear address). Only meaningful for vec 14.
/// # SAFETY: privileged read; legal at CPL=0.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn read_cr2() -> u64 {
    let v: u64;
    // SAFETY: `mov rax, cr2` is privileged; legal at CPL=0; pure read.
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Rust side of the fault handler. Called from `oxide_fault_common`
/// with `frame_ptr = rsp at common entry`. Emits a one-line fault
/// summary on the boot UART then returns to the asm halt loop.
///
/// # SAFETY: caller (asm stub) passes a valid pointer to a
/// `FaultFrame` on the kernel stack. We only read.
/// # C: O(constant)
/// # Ctx: exception context, IRQs off
// Per `04§4.0` (R06): emit-path call sites gated under `debug-irq`.
// Default builds halt silently on a fault; the diagnostic dump rides
// the same gate as the rest of the IRQ/exception trace surface.
#[cfg(feature = "debug-irq")]
macro_rules! debug_irq { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-irq"))]
macro_rules! debug_irq { ($($t:tt)*) => {} }

/// Optional fault handler. Default is `default_handler` which
/// returns `false` (= asm halts). Kernel installs a real handler
/// via `install_fault_handler` once VMM AddressSpace integration
/// is in. The returned `bool` is the recovery signal: `true` =
/// asm pops the frame and `iretq`s (CPU retries the faulting
/// instruction); `false` = asm halts forever.
pub type FaultHandler = fn(vec: u64, error: u64, rip: u64, cr2: u64) -> bool;

fn default_handler(_vec: u64, _error: u64, _rip: u64, _cr2: u64) -> bool { false }

static FAULT_HANDLER: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(default_handler as *const () as *mut ());

/// Kernel-installed hook invoked from `oxide_fault_print_rust` BEFORE
/// the generic FaultHandler chain when the trap originates in user
/// mode (CS RPL == 3) and the vector is software-debug related.
/// Receives a mutable frame so the hook can clear RFLAGS.TF after a
/// PTRACE_SINGLESTEP #DB. Returns true if it consumed the trap and
/// the asm should `iretq` back to user (with the mutated frame).
pub type UserTrapHook = fn(frame: &mut FaultFrame) -> bool;

fn default_user_trap_hook(_f: &mut FaultFrame) -> bool { false }

static USER_TRAP_HOOK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(default_user_trap_hook as *const () as *mut ());

/// Install the user-trap hook (PTRACE_SINGLESTEP #DB delivery, etc.).
/// Returns the previous one so callers can compose / restore.
/// # SAFETY: caller guarantees `h` lives for the rest of the kernel's
/// lifetime; single-CPU pre-init context.
/// # C: O(1)
pub unsafe fn install_user_trap_hook(h: UserTrapHook) -> UserTrapHook {
    let new = h as *const () as *mut ();
    let prev = USER_TRAP_HOOK.swap(new, core::sync::atomic::Ordering::AcqRel);
    // SAFETY: `prev` was installed via this same fn (or default initialiser) which only writes valid `UserTrapHook` values; transmute is sound under that single-writer invariant.
    unsafe { core::mem::transmute::<*mut (), UserTrapHook>(prev) }
}

fn current_user_trap_hook() -> UserTrapHook {
    let p = USER_TRAP_HOOK.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: non-null by initialisation; written only via install_user_trap_hook with valid values.
    unsafe { core::mem::transmute::<*mut (), UserTrapHook>(p) }
}

/// Install a kernel-side fault handler. Returns the previous one
/// so callers can compose / restore.
/// # SAFETY: caller must guarantee `h` lives for the rest of the
/// kernel's lifetime; single-CPU pre-init context (no concurrent
/// faults during the swap).
/// # C: O(1)
pub unsafe fn install_fault_handler(h: FaultHandler) -> FaultHandler {
    let new = h as *const () as *mut ();
    let prev = FAULT_HANDLER.swap(new, core::sync::atomic::Ordering::AcqRel);
    // SAFETY: `prev` was installed via this same fn (or the default
    // initialiser) which only writes valid `FaultHandler` values;
    // the transmute is sound under that single-writer invariant.
    unsafe { core::mem::transmute::<*mut (), FaultHandler>(prev) }
}

fn current_handler() -> FaultHandler {
    let p = FAULT_HANDLER.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: non-null by initialisation; written only by `install_fault_handler` with valid `FaultHandler` values.
    unsafe { core::mem::transmute::<*mut (), FaultHandler>(p) }
}

/// F158: stash for the live FaultFrame pointer while
/// `oxide_fault_print_rust` is on the stack. Lets the kernel-side
/// FaultHandler (which doesn't get the frame as an arg) reach over
/// and rewrite RIP/RSP/etc. to deliver a Linux-style catchable
/// SIGSEGV via a user-installed signal handler. Cleared on exit
/// from the rust-side print fn.
static CUR_FAULT_FRAME: core::sync::atomic::AtomicPtr<FaultFrame>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static CUR_FAULT_GPRS: core::sync::atomic::AtomicPtr<FaultGprs>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Snapshot of the live `*mut FaultFrame` while in fault context.
/// Returns null if no fault is active (i.e., not called from a
/// FaultHandler invocation). Used by the kernel SIGSEGV path to
/// rewrite the iretq frame for catchable signal delivery.
/// # SAFETY: caller is in fault dispatch context with IRQs masked.
/// # C: O(1)
pub fn current_fault_frame() -> *mut FaultFrame {
    CUR_FAULT_FRAME.load(core::sync::atomic::Ordering::Acquire)
}

/// B45: pointer to the saved-GPR block on the kernel stack while
/// `oxide_fault_print_rust` is on the stack. Lets the SIGSEGV
/// terminator dump every general-purpose register on a user-mode
/// #GP / #UD so we can name the bad register without re-entering
/// QEMU under gdb. Cleared on exit from the rust-side print fn.
/// # SAFETY: caller is in fault dispatch with IRQs masked.
/// # C: O(1)
pub fn current_fault_gprs() -> *const FaultGprs {
    CUR_FAULT_GPRS.load(core::sync::atomic::Ordering::Acquire)
}

/// NMI backtrace: dump this CPU's id + RIP/RSP/RFLAGS + GPRs. Called from
/// the vector-2 path on a cross-CPU backtrace poke. Print-only (caller
/// resumes). hal-x86_64 can't read the sched task (would be a dep cycle),
/// so the cross-CPU detector prints the task; this adds the exact RIP.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel", feature = "debug-watchdog"))]
fn nmi_backtrace(f: &FaultFrame, gprs_ptr: *const FaultGprs) {
    use hal::CpuOps;
    klog::write_raw(b"[NMI-BT] cpu=");
    klog::write_hex_u64(crate::X86CpuOps::current_cpu() as u64);
    klog::write_raw(b" rip=");
    klog::write_hex_u64(f.rip);
    klog::write_raw(b" rsp=");
    klog::write_hex_u64(f.rsp);
    klog::write_raw(b" rflags=");
    klog::write_hex_u64(f.rflags);
    klog::write_raw(b" cs=");
    klog::write_hex_u64(f.cs);
    if !gprs_ptr.is_null() {
        // SAFETY: gprs_ptr is the stub-built GPR block on the kernel stack, valid for read while the vector-2 stub frame is live.
        let g = unsafe { &*gprs_ptr };
        klog::write_raw(b"\n[NMI-BT] rbp="); klog::write_hex_u64(g.rbp);
        klog::write_raw(b" rbx=");           klog::write_hex_u64(g.rbx);
        klog::write_raw(b" r12=");           klog::write_hex_u64(g.r12);
        klog::write_raw(b" r13=");           klog::write_hex_u64(g.r13);
        klog::write_raw(b" r14=");           klog::write_hex_u64(g.r14);
        klog::write_raw(b" r15=");           klog::write_hex_u64(g.r15);
    }
    klog::write_raw(b"\n");
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_fault_print_rust(frame_ptr: *mut FaultFrame, gprs_ptr: *const FaultGprs) -> bool {
    // SAFETY: stub-built frame on the kernel stack, valid for read+write.
    let f = unsafe { &mut *frame_ptr };
    // F158: publish the live FaultFrame so the kernel SIGSEGV
    // delivery path can rewrite it for catchable user signals.
    CUR_FAULT_FRAME.store(frame_ptr, core::sync::atomic::Ordering::Release);
    CUR_FAULT_GPRS.store(gprs_ptr as *mut FaultGprs, core::sync::atomic::Ordering::Release);
    struct ClearOnDrop;
    impl Drop for ClearOnDrop {
        fn drop(&mut self) {
            CUR_FAULT_FRAME.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
            CUR_FAULT_GPRS.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
        }
    }
    let _guard = ClearOnDrop;
    // NMI (vector 2): cross-CPU backtrace poke from the hard-lockup
    // detector / sysrq. NMI is delivered through IF=0, so this lands even
    // on a CPU spinning in a spinlock deadlock with interrupts masked.
    // Print this CPU's RIP/regs then RESUME (return true → iretq): a poke
    // at a CPU that wasn't actually wedged must be non-destructive.
    if f.vector == 2 {
        #[cfg(feature = "debug-watchdog")]
        nmi_backtrace(f, gprs_ptr);
        return true;
    }
    // Kalloc corruption hunt (`debug-hw-watchpoint`): a KERNEL-mode #DB
    // (vector 1, CPL=0) with a DR0..DR3 data-watchpoint status bit set is a
    // write into a currently-armed just-freed HoleHdr. Print the writer's
    // rip + which watched word it hit, clear the consumed DR6 status, then
    // RESUME (return true → iretq): the goal is to catch the writer and keep
    // booting, not to halt. Runs before the generic handler chain so no
    // fault-handler install can shadow it (mirrors the vec==2 NMI inline).
    #[cfg(feature = "debug-hw-watchpoint")]
    if f.vector == 1 && (f.cs & 3) == 0 {
        // SAFETY: DR6/DR0/DR1 reads are privileged, legal at CPL=0; in fault
        // dispatch with IRQs masked, this CPU is the sole debug-reg reader.
        let dr6 = unsafe { crate::read_clear_dr6() };
        let (dr0, dr1) = unsafe { crate::read_dr0_dr1() };
        // DR6 bits 0-3 (B0-B3) name which watchpoint matched.
        if dr6 & 0b1111 != 0 {
            klog::write_raw(b"[HWWP] freed-block WRITE rip=");
            klog::write_hex_u64(f.rip);
            klog::write_raw(b" dr6=");
            klog::write_hex_u64(dr6);
            if dr6 & 0b0001 != 0 {
                klog::write_raw(b" hit=size@");
                klog::write_hex_u64(dr0);
            }
            if dr6 & 0b0010 != 0 {
                klog::write_raw(b" hit=next@");
                klog::write_hex_u64(dr1);
            }
            klog::write_raw(b"\n");
            return true;
        }
    }
    // Early-handle user-mode software-debug traps (#DB, #BP) via the
    // installed UserTrapHook. The hook consumes the trap (returns true)
    // and may mutate the frame (clear RFLAGS.TF) before iretq resumes
    // the user task.
    if (f.cs & 3) == 3 && (f.vector == 1 || f.vector == 3) {
        if (current_user_trap_hook())(f) {
            return true;
        }
    }
    let cr2 = if f.vector == 14 {
        // SAFETY: read_cr2 is a privileged register read, legal at CPL=0.
        unsafe { read_cr2() }
    } else { 0 };

    // Consult the registered handler first. A resolved fault (e.g.
    // demand-page) is normal kernel operation per `11§5` — silent in
    // production, no log line. Only log loudly when we're about to
    // halt (handler returned false → unrecoverable).
    let mut handled = (current_handler())(f.vector, f.error, f.rip, cr2);
    if !handled && f.vector == 14 && (f.cs & 3) == 0 && cr2 < hal::USER_VA_END {
        if let Some(fixup) = crate::exception_table::lookup(f.rip) {
            f.rip = fixup;
            handled = true;
        }
    }
    if !handled {
        // Default-ON oops: an unrecoverable fault must never halt the CPU
        // silently (that reads as a mysterious freeze). Gated under
        // debug-watchdog (default-on via the boot crates) OR debug-irq, so
        // every build prints vec/rip/cr2/GPRs before halting — zero bytes
        // on a healthy boot since this only runs when handled==false.
        #[cfg(any(feature = "debug-irq", feature = "debug-watchdog"))]
        {
            klog::write_raw(b"[FAULT] vec=");
            klog::write_hex_u64(f.vector);
            klog::write_raw(b" (");
            klog::write_raw(vector_label(f.vector));
            klog::write_raw(b") err=");
            klog::write_hex_u64(f.error);
            klog::write_raw(b" rip=");
            klog::write_hex_u64(f.rip);
            klog::write_raw(b" rflags=");
            klog::write_hex_u64(f.rflags);
            if f.vector == 14 {
                klog::write_raw(b" cr2=");
                klog::write_hex_u64(cr2);
                klog::write_raw(b" pf=");
                klog::write_raw(decode_pfec(f.error));
            }
            klog::write_raw(b"\n");
            // B45: full GPR dump when we're about to halt. Helps name
            // the bad register on a kernel-mode trip without needing
            // to re-attach gdb. User-mode trips also get this dump
            // before the SIGSEGV terminator (which logs its own line).
            if !gprs_ptr.is_null() {
                // SAFETY: gprs_ptr is the stub-built GPR block on the
                // kernel stack; valid for read while we're in fault
                // dispatch (the stub doesn't pop until after we return).
                let g = unsafe { &*gprs_ptr };
                klog::write_raw(b"[FAULT] rax=");  klog::write_hex_u64(g.rax);
                klog::write_raw(b" rbx=");          klog::write_hex_u64(g.rbx);
                klog::write_raw(b" rcx=");          klog::write_hex_u64(g.rcx);
                klog::write_raw(b" rdx=");          klog::write_hex_u64(g.rdx);
                klog::write_raw(b"\n[FAULT] rsi="); klog::write_hex_u64(g.rsi);
                klog::write_raw(b" rdi=");          klog::write_hex_u64(g.rdi);
                klog::write_raw(b" rbp=");          klog::write_hex_u64(g.rbp);
                klog::write_raw(b" rsp=");          klog::write_hex_u64(f.rsp);
                klog::write_raw(b"\n[FAULT] r8=");  klog::write_hex_u64(g.r8);
                klog::write_raw(b" r9=");           klog::write_hex_u64(g.r9);
                klog::write_raw(b" r10=");          klog::write_hex_u64(g.r10);
                klog::write_raw(b" r11=");          klog::write_hex_u64(g.r11);
                klog::write_raw(b"\n[FAULT] r12="); klog::write_hex_u64(g.r12);
                klog::write_raw(b" r13=");          klog::write_hex_u64(g.r13);
                klog::write_raw(b" r14=");          klog::write_hex_u64(g.r14);
                klog::write_raw(b" r15=");          klog::write_hex_u64(g.r15);
                klog::write_raw(b"\n");
                // debug-heappoison: if any GPR points into a still-quarantined
                // (freed+poisoned) block, this fault is a use-after-free. The
                // block size names the victim type (ArcInner<File>/<Task>/dentry
                // …). No-op (returns None) unless kalloc's poison feature is on.
                let cands: [(&[u8], u64); 15] = [
                    (b"rax", g.rax), (b"rbx", g.rbx), (b"rcx", g.rcx), (b"rdx", g.rdx),
                    (b"rsi", g.rsi), (b"rdi", g.rdi), (b"rbp", g.rbp), (b"r8", g.r8),
                    (b"r9", g.r9), (b"r10", g.r10), (b"r11", g.r11), (b"r12", g.r12),
                    (b"r13", g.r13), (b"r14", g.r14), (b"r15", g.r15),
                ];
                for (name, v) in cands.iter() {
                    if let Some((base, size, free_ip)) = kalloc::uaf_lookup(*v) {
                        klog::write_raw(b"[UAF] reg="); klog::write_raw(name);
                        klog::write_raw(b" ptr="); klog::write_hex_u64(*v);
                        klog::write_raw(b" IN FREED block base="); klog::write_hex_u64(base);
                        klog::write_raw(b" size="); klog::write_dec_u64(size as u64);
                        klog::write_raw(b" free_ip=");
                        if free_ip == kalloc::UAF_FREE_IP_UNKNOWN { klog::write_raw(b"unknown"); }
                        else { klog::write_raw(b"0x"); klog::write_hex_u64(free_ip); }
                        klog::write_raw(b"\n");
                    }
                }
                // B1347: the offset-0/8 corruptor also manifests as a fault on a
                // LIVE structure (xrstor #GP on a scribbled XSAVE header, #PF on a
                // scribbled pointer) BEFORE a kalloc op catches it. Dump the recent
                // kalloc-op ring + current IRQ seq so a hard IRQ in the write window
                // is visible on the fault path too (no-op unless dealloc-diag+armed).
                kalloc::dump_corruption_diag();
            }
        }
        #[cfg(not(any(feature = "debug-irq", feature = "debug-watchdog")))]
        { let _ = (f, gprs_ptr); }
    }
    handled
}

/// Map an Intel-SDM exception vector to a short label (Vol. 3
/// Tab. 6-1). Returns a static byte slice; unknown vectors fall
/// through to `"reserved"`.
const fn vector_label(vec: u64) -> &'static [u8] {
    match vec {
         0 => b"#DE",        1 => b"#DB",        2 => b"NMI",        3 => b"#BP",
         4 => b"#OF",        5 => b"#BR",        6 => b"#UD",        7 => b"#NM",
         8 => b"#DF",       10 => b"#TS",       11 => b"#NP",       12 => b"#SS",
        13 => b"#GP",       14 => b"#PF",       16 => b"#MF",       17 => b"#AC",
        18 => b"#MC",       19 => b"#XM",       20 => b"#VE",       21 => b"#CP",
        _  => b"reserved",
    }
}

/// Decode the page-fault error code (PFEC) per Intel SDM Vol. 3
/// §6.15. Returns a fixed label encoding the four bits we care
/// about: P/!P (present?), W/R (write?), U/K (user/kernel?), I
/// (instruction fetch). Sixteen possible labels statically.
const fn decode_pfec(err: u64) -> &'static [u8] {
    let p   = (err & (1 << 0)) != 0;     // 1 = protection violation, 0 = not present
    let w   = (err & (1 << 1)) != 0;     // 1 = write, 0 = read
    let u   = (err & (1 << 2)) != 0;     // 1 = user, 0 = kernel
    let id  = (err & (1 << 4)) != 0;     // 1 = instruction fetch
    match (p, w, u, id) {
        (false, false, false, false) => b"NP-R-K",
        (false, false, false, true ) => b"NP-R-K-IFetch",
        (false, false, true,  false) => b"NP-R-U",
        (false, false, true,  true ) => b"NP-R-U-IFetch",
        (false, true,  false, false) => b"NP-W-K",
        (false, true,  false, true ) => b"NP-W-K-IFetch",
        (false, true,  true,  false) => b"NP-W-U",
        (false, true,  true,  true ) => b"NP-W-U-IFetch",
        (true,  false, false, false) => b"PV-R-K",
        (true,  false, false, true ) => b"PV-R-K-IFetch",
        (true,  false, true,  false) => b"PV-R-U",
        (true,  false, true,  true ) => b"PV-R-U-IFetch",
        (true,  true,  false, false) => b"PV-W-K",
        (true,  true,  false, true ) => b"PV-W-K-IFetch",
        (true,  true,  true,  false) => b"PV-W-U",
        (true,  true,  true,  true ) => b"PV-W-U-IFetch",
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_pfec, vector_label};

    #[test]
    fn vector_label_matches_intel_sdm_vol3_tab_6_1() {
        assert_eq!(vector_label(0),  b"#DE");
        assert_eq!(vector_label(13), b"#GP");
        assert_eq!(vector_label(14), b"#PF");
        assert_eq!(vector_label(99), b"reserved");
    }

    #[test]
    fn decode_pfec_writes_kernel_not_present() {
        // err = 0b00010 (W=1, P=0, U=0, I=0) — kernel write to a
        // not-present page; common kalloc failure path.
        assert_eq!(decode_pfec(0b00010), b"NP-W-K");
    }

    #[test]
    fn decode_pfec_user_protection_violation_instruction_fetch() {
        // err = 0b10101 (P=1, W=0, U=1, I=1) — user instruction
        // fetch from a no-exec mapping; the W^X enforcement signal.
        assert_eq!(decode_pfec(0b10101), b"PV-R-U-IFetch");
    }

    #[test]
    fn decode_pfec_uses_only_low_5_bits() {
        // High garbage bits don't perturb the decode.
        assert_eq!(decode_pfec(0xffff_ffff_ffff_0001), decode_pfec(0b1));
    }
}
