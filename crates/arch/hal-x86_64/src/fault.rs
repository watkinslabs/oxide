// CPU-exception fault handler per `22§4`.
//
// Module manifest:
//   stubs    — per-vector entry stubs + the regular/paranoid common paths.
//   paranoid — which vectors take the paranoid entry and their IST slots.
// This file is the manifest and public dispatch surface for x86_64
// exception handling.

pub mod paranoid;
mod stubs;

pub use stubs::vector_stub_addr;

use crate::pt_regs::PtRegs;

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

/// Kernel-installed hook that NAMES the kernel stack an address belongs to.
///
/// A guard-page hit reports `rsp` sitting on a slot boundary, and that alone
/// cannot say which stack overflowed: task stacks and the per-CPU interrupt
/// stack are slots of one allocator window. The reference classifies the
/// faulting address in its double-fault handler and prints the stack's name and
/// bounds; without it the same question has been answered by hand, from a
/// register dump, more than once.
///
/// Fills `(name, guard_lo, stack_lo, stack_hi)` and returns true when the
/// address is inside the window. Must not lock: it runs from the fault path.
#[derive(Copy, Clone)]
pub struct StackReport {
    pub name: &'static [u8],
    pub guard_lo: u64,
    pub stack_lo: u64,
    pub stack_hi: u64,
    /// Most-repeated code address on the dead stack, and how often. A stack
    /// consumed by one site repeating is unbounded nesting, not a deep chain —
    /// the two need opposite fixes, and a static depth walk cannot tell them
    /// apart because it measures a single pass.
    pub repeat_site: u64,
    pub repeat_count: u32,
}

impl StackReport {
    /// # C: O(1)
    pub const fn empty() -> Self {
        Self { name: b"", guard_lo: 0, stack_lo: 0, stack_hi: 0, repeat_site: 0, repeat_count: 0 }
    }
}

pub type StackNameHook = fn(va: u64, out: &mut StackReport) -> bool;

fn default_stack_name_hook(_va: u64, _o: &mut StackReport) -> bool { false }

static STACK_NAME_HOOK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(default_stack_name_hook as *const () as *mut ());

/// Install the stack-naming hook.
/// # SAFETY: caller guarantees `h` lives for the rest of the kernel's lifetime.
/// # C: O(1)
pub unsafe fn install_stack_name_hook(h: StackNameHook) {
    STACK_NAME_HOOK.store(h as *const () as *mut (), core::sync::atomic::Ordering::Release);
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn current_stack_name_hook() -> StackNameHook {
    let p = STACK_NAME_HOOK.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: only ever written by install_stack_name_hook with a valid StackNameHook, or the default initialiser.
    unsafe { core::mem::transmute::<*mut (), StackNameHook>(p) }
}

/// Kernel-installed hook invoked from `oxide_fault_print_rust` BEFORE
/// the generic FaultHandler chain when the trap originates in user
/// mode (CS RPL == 3) and the vector is software-debug related.
/// Receives a mutable frame so the hook can clear RFLAGS.TF after a
/// PTRACE_SINGLESTEP #DB. Returns true if it consumed the trap and
/// the asm should `iretq` back to user (with the mutated frame).
pub type UserTrapHook = fn(regs: &mut PtRegs) -> bool;

fn default_user_trap_hook(_r: &mut PtRegs) -> bool { false }

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

// Sole caller is `oxide_fault_print_rust`, which only exists on the kernel target.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
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

// Sole caller is `oxide_fault_print_rust`, which only exists on the kernel target.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn current_handler() -> FaultHandler {
    let p = FAULT_HANDLER.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: non-null by initialisation; written only by `install_fault_handler` with valid `FaultHandler` values.
    unsafe { core::mem::transmute::<*mut (), FaultHandler>(p) }
}

/// F158: stash for the live `PtRegs` pointer while
/// `oxide_fault_print_rust` is on the stack. Lets the kernel-side
/// FaultHandler (which doesn't get the frame as an arg) reach over
/// and rewrite RIP/RSP/etc. to deliver a Linux-style catchable
/// SIGSEGV via a user-installed signal handler, and lets the SIGSEGV
/// terminator dump every GPR (B45). Cleared on exit from the
/// rust-side print fn.
static CUR_FAULT_FRAME: core::sync::atomic::AtomicPtr<PtRegs>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Snapshot of the live `*mut PtRegs` while in fault context.
/// Returns null if no fault is active (i.e., not called from a
/// FaultHandler invocation). Used by the kernel SIGSEGV path to
/// rewrite the iretq frame for catchable signal delivery, and by the
/// diagnostics that name the bad register on a user-mode #GP / #UD.
/// # SAFETY: caller is in synchronous fault dispatch on the faulting task.
/// # C: O(1)
pub fn current_fault_frame() -> *mut PtRegs {
    CUR_FAULT_FRAME.load(core::sync::atomic::Ordering::Acquire)
}

/// NMI backtrace: dump this CPU's id + RIP/RSP/RFLAGS + GPRs. Called from
/// the vector-2 path on a cross-CPU backtrace poke. Print-only (caller
/// resumes). hal-x86_64 can't read the sched task (would be a dep cycle),
/// so the cross-CPU detector prints the task; this adds the exact RIP.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel", feature = "debug-watchdog"))]
fn nmi_backtrace(f: &PtRegs) {
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
    klog::write_raw(b"\n[NMI-BT] rbp="); klog::write_hex_u64(f.rbp);
    klog::write_raw(b" rbx=");           klog::write_hex_u64(f.rbx);
    klog::write_raw(b" r12=");           klog::write_hex_u64(f.r12);
    klog::write_raw(b" r13=");           klog::write_hex_u64(f.r13);
    klog::write_raw(b" r14=");           klog::write_hex_u64(f.r14);
    klog::write_raw(b" r15=");           klog::write_hex_u64(f.r15);
    klog::write_raw(b"\n");
}

/// Rust side of the fault handler. Called from `oxide_fault_common`
/// with `regs = rsp after the 15 GPR pushes`. Emits a one-line fault
/// summary on the boot UART then returns to the asm halt loop.
///
/// # SAFETY: caller (asm stub) passes a valid pointer to a
/// `PtRegs` on the kernel stack.
/// # C: O(constant)
/// # Ctx: synchronous exception; process page faults inherit IRQs enabled
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_fault_print_rust(regs: *mut PtRegs) -> bool {
    // SAFETY: stub-built PtRegs on the kernel stack, valid for read+write.
    let f = unsafe { &mut *regs };
    // F158: publish the live frame so the kernel SIGSEGV delivery path
    // can rewrite it for catchable user signals.
    CUR_FAULT_FRAME.store(regs, core::sync::atomic::Ordering::Release);
    struct ClearOnDrop;
    impl Drop for ClearOnDrop {
        fn drop(&mut self) {
            CUR_FAULT_FRAME.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
        }
    }
    let _guard = ClearOnDrop;
    // NMI (vector 2): cross-CPU backtrace poke from the hard-lockup
    // detector / sysrq. NMI is delivered through IF=0, so this lands even
    // on a CPU spinning in a spinlock deadlock with interrupts masked.
    // Print this CPU's RIP/regs then RESUME (return true → iretq): a poke
    // at a CPU that wasn't actually wedged must be non-destructive.
    if f.vector == crate::PT_REGS_VECTOR_NMI {
        #[cfg(feature = "debug-watchdog")]
        nmi_backtrace(f);
        return true;
    }
    if f.from_user() {
        // SAFETY: this declaration matches arch-irq's link-time bridge.
        unsafe extern "C" { fn oxide_vtime_user_exit(); }
        // SAFETY: the kernel links the arch-irq bridge with this exact ABI;
        // the user CS proves this is a user→kernel transition.
        unsafe { oxide_vtime_user_exit(); }
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
        // SAFETY: DR0/DR1 reads are privileged, legal at CPL=0; the values are
        // only formatted into the trace, so a concurrent re-arm cannot be unsound.
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

    // Runaway guard, BEFORE the resolver is consulted. A fault already in
    // flight at this address on this kernel stack cannot be resolved by running
    // the same resolver again; doing so is what walked the stack down into its
    // guard page. Report and halt instead, with nothing but raw register values
    // — the resolver, the stack-name hook and the diagnostic dumps below all
    // touch memory, and the state that produced a runaway is the last state to
    // trust with that.
    // KERNEL-mode only. A user-mode fault carries the USER stack pointer, which
    // says nothing about kernel nesting, and cannot run away this way: it is
    // either resolved or turned into a signal, and either answer returns to
    // userspace rather than re-entering the dispatcher one frame deeper.
    if (f.cs & 3) == 0
        && hal::fault_reentry::enter(fault_cpu(), fault_key(f.vector, f.rip, cr2), f.rsp,
                                     hal::KERNEL_STACK_BYTES as u64) == hal::fault_reentry::Verdict::Runaway {
        // Same emit gate as the oops printer below: `debug-watchdog` is
        // default-on via the boot crates, so every shipped build carries this
        // line and a healthy boot emits none of it.
        #[cfg(any(feature = "debug-irq", feature = "debug-watchdog"))]
        {
            klog::write_raw(b"[FAULT] BUG: runaway fault, same address re-entered on this stack - halting. vec=");
            klog::write_hex_u64(f.vector);
            klog::write_raw(b" rip=");
            klog::write_hex_u64(f.rip);
            klog::write_raw(b" cr2=");
            klog::write_hex_u64(cr2);
            klog::write_raw(b" rsp=");
            klog::write_hex_u64(f.rsp);
            klog::write_raw(b"\n");
        }
        return false;
    }

    // Consult the registered handler first. A resolved fault (e.g.
    // demand-page) is normal kernel operation per `11§5` — silent in
    // production, no log line. Only log loudly when we're about to
    // halt (handler returned false → unrecoverable).
    let mut handled = (current_handler())(f.vector, f.error, f.rip, cr2);
    if !handled && (f.cs & 3) == 0 && fixup_eligible(f.vector, cr2) {
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
            if f.vector == 14 || f.vector == 8 {
                // #DF too: the page fault that escalated set CR2, and on a
                // guard-page hit that address IS the overflow. The reference
                // reads it in its double-fault handler for exactly this.
                klog::write_raw(b" cr2=");
                klog::write_hex_u64(cr2);
                if f.vector == 14 {
                    klog::write_raw(b" pf=");
                    klog::write_raw(decode_pfec(f.error));
                }
            }
            klog::write_raw(b"\n");
            // Name the stack. `rsp` first — on a guard-page hit it sits on the
            // slot boundary and is the reliable witness; CR2 is the byte that
            // was touched and can be below the guard page on a large frame.
            {
                let mut o = StackReport::empty();
                let hook = current_stack_name_hook();
                let hit = if hook(f.rsp, &mut o) { true }
                          else { (f.vector == 14 || f.vector == 8) && hook(cr2, &mut o) };
                if hit {
                    klog::write_raw(b"[FAULT] BUG: ");
                    klog::write_raw(o.name);
                    klog::write_raw(b" stack guard page was hit (stack is ");
                    klog::write_hex_u64(o.stack_lo);
                    klog::write_raw(b"..");
                    klog::write_hex_u64(o.stack_hi);
                    klog::write_raw(b", guard ");
                    klog::write_hex_u64(o.guard_lo);
                    klog::write_raw(b", rsp=");
                    klog::write_hex_u64(f.rsp);
                    klog::write_raw(b", headroom=");
                    klog::write_dec_u64(if f.rsp >= o.stack_lo && f.rsp <= o.stack_hi
                                        { f.rsp - o.stack_lo } else { 0 });
                    klog::write_raw(b")\n");
                    // What filled it. One site repeating is unbounded nesting;
                    // many distinct sites is a genuinely deep chain.
                    klog::write_raw(b"[FAULT] BUG: deepest repeated site ");
                    klog::write_hex_u64(o.repeat_site);
                    klog::write_raw(b" x");
                    klog::write_dec_u64(o.repeat_count as u64);
                    klog::write_raw(b"\n");
                }
            }
            // B45: full GPR dump when we're about to halt. Helps name
            // the bad register on a kernel-mode trip without needing
            // to re-attach gdb. User-mode trips also get this dump
            // before the SIGSEGV terminator (which logs its own line).
            {
                let g = &*f;
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
        { let _ = f; }
    }
    // Retire this frame's runaway record. The fault is settled — resolved,
    // fixed up, or about to halt — so it is no longer in flight and must not
    // make the next fault at the same address look like a recursion.
    if (f.cs & 3) == 0 { hal::fault_reentry::leave(fault_cpu(), f.rsp); }
    handled
}

/// Which CPU's runaway records this fault belongs to. The initial APIC id is
/// read straight from the CPU, so the guard works before any per-CPU kernel
/// structure is up — a fault during early boot is exactly when it must.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn fault_cpu() -> usize { hal::fault_reentry::slot(crate::cpuid::initial_apic_id() as u64) }

/// What makes two faults "the same" for the runaway guard: a #PF repeats on its
/// faulting ADDRESS, everything else on the instruction that raised it.
/// # C: O(1)
pub fn fault_key(vector: u64, rip: u64, cr2: u64) -> u64 {
    if vector == VEC_PF { cr2 } else { rip }
}

/// Intel-SDM vector numbers the exception-table fixup path names.
pub const VEC_GP: u64 = 13;
pub const VEC_PF: u64 = 14;

/// May a kernel-mode fault at this vector be resolved by an
/// `__ex_table` fixup?
///
/// #PF is the uaccess case, and it stays restricted to a user-range `cr2`:
/// a kernel-address page fault inside a `rep movsb` is a kernel bug, not a
/// user pointer that went bad, and silently jumping to the fixup would hide
/// it.
///
/// #GP is the MSR case — the `rdmsr`/`wrmsr` of a register the CPU does not
/// implement raises #GP with no `cr2` to bound. Without this arm, probing a
/// model-specific register a hypervisor omits is unrecoverable: the CPU halts
/// in the oops printer instead of taking the recorded fixup, which is why the
/// capability probes that need it cannot be written at all.
/// # C: O(1)
pub fn fixup_eligible(vector: u64, cr2: u64) -> bool {
    match vector {
        VEC_PF => cr2 < hal::USER_VA_END,
        VEC_GP => true,
        _ => false,
    }
}

/// Map an Intel-SDM exception vector to a short label (Vol. 3
/// Tab. 6-1). Returns a static byte slice; unknown vectors fall
/// through to `"reserved"`.
// Consumed only by the oops printer inside `oxide_fault_print_rust`, which is
// itself gated on the kernel target plus the debug-irq / debug-watchdog emit
// gate; the host unit tests below pin the table.
#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel",
                    any(feature = "debug-irq", feature = "debug-watchdog"))))]
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
// Same gate as `vector_label`: oops-printer-only, plus the host tests below.
#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel",
                    any(feature = "debug-irq", feature = "debug-watchdog"))))]
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
