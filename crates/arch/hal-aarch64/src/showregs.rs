// Linux `show_regs()` parity for the aarch64 oops path (`54§1.6`, `38§3`).
//
// A fatal abort must name the CPU it happened on and the COMPLETE register
// file. Neither was printed: an SMP-only fault is unattributable without the
// CPU id, and a wild pointer is unattributable without knowing which register
// carried it — the previous dump exposed only x8/x26/lr, chosen by guess.
//
// Every value read here comes either from the exception frame (memory the
// vector just wrote on the current kernel stack) or from an `mrs` of a system
// register. Nothing dereferences per-CPU state, so a corrupt `TPIDR_EL1`
// cannot make this dump fault recursively — which is exactly the state it
// exists to report on.

/// `(name, frame byte offset)` for x0..x30 in the 288-byte frame that
/// `vbar/asm.rs` builds. x19..x28 sit above ELR/SPSR/SP_EL0 because Linux's
/// `kernel_entry` order saves the callee-saved block last; x29/x30 sit below.
const GPRS: [(&[u8], u64); 31] = [
    (b"x0 ", 0),   (b"x1 ", 8),   (b"x2 ", 16),  (b"x3 ", 24),
    (b"x4 ", 32),  (b"x5 ", 40),  (b"x6 ", 48),  (b"x7 ", 56),
    (b"x8 ", 64),  (b"x9 ", 72),  (b"x10", 80),  (b"x11", 88),
    (b"x12", 96),  (b"x13", 104), (b"x14", 112), (b"x15", 120),
    (b"x16", 128), (b"x17", 136), (b"x18", 144), (b"x19", 208),
    (b"x20", 216), (b"x21", 224), (b"x22", 232), (b"x23", 240),
    (b"x24", 248), (b"x25", 256), (b"x26", 264), (b"x27", 272),
    (b"x28", 280), (b"x29", 152), (b"x30", 160),
];

/// Frame slots the vector fills from system registers.
const FRAME_ELR: u64 = 176;
const FRAME_SPSR: u64 = 184;
const FRAME_SP_EL0: u64 = 192;
/// Total frame size — the interrupted SP_EL1 is the frame base plus this.
const FRAME_BYTES: u64 = 288;

/// Registers printed per output line. Linux uses 3; klog lines stay under the
/// PL011 FIFO drain window at 4 columns of `xNN=0x<16>`.
const COLS: usize = 4;

/// `MPIDR_EL1` affinity bits identifying the PE (`Aff3..Aff0`, `23§4`).
const MPIDR_AFF_MASK: u64 = 0x0000_00ff_00ff_ffff;

/// Read the interrupted PE's identity without touching memory: `MPIDR_EL1` is
/// the architectural PE id and `TPIDR_EL1` is our per-CPU base. Printing the
/// raw `TPIDR_EL1` (rather than the cpu id it points at) is deliberate — a
/// corrupt or not-yet-installed per-CPU base is itself a candidate cause, and
/// loading through it here would fault inside the fault handler.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn pe_identity() -> (u64, u64) {
    let mpidr: u64;
    let tpidr: u64;
    // SAFETY: `mrs` of MPIDR_EL1 / TPIDR_EL1 in pe_identity — both are EL1-readable
    // system registers, no memory operand, no side effects; nomem/nostack asserts that.
    unsafe {
        core::arch::asm!("mrs {m}, MPIDR_EL1", "mrs {t}, TPIDR_EL1",
                         m = out(reg) mpidr, t = out(reg) tpidr,
                         options(nomem, nostack, preserves_flags));
    }
    (mpidr & MPIDR_AFF_MASK, tpidr)
}
#[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
fn pe_identity() -> (u64, u64) { (0, 0) }

/// Print the full interrupted register file plus the PE identity, then report
/// any GPR that points into a quarantined-freed heap block along with the
/// **free site** that released it — the provenance method that named the
/// victim allocation for the heap-corruption campaign (CLAUDE.md lesson 12),
/// now applied to every register instead of three hand-picked ones.
///
/// # SAFETY: `frame` must be the current exception's 288-byte frame base as
/// published by the vector handler; the whole frame is readable kernel stack.
/// # C: O(1) — 31 fixed loads and one bounded UAF-ring probe per GPR
/// # Ctx: exception, IRQ-off (DAIF masked by the vector)
pub unsafe fn dump(frame: u64) {
    if frame == 0 { return; }
    let (mpidr, tpidr) = pe_identity();
    // SAFETY: per fn contract — `frame` is the vector's own 288-byte frame on this
    // CPU's kernel stack; ELR/SPSR/SP_EL0 slots were stored by `kernel_entry`.
    let (elr, spsr, sp_el0) = unsafe {
        (core::ptr::read_volatile((frame + FRAME_ELR) as *const u64),
         core::ptr::read_volatile((frame + FRAME_SPSR) as *const u64),
         core::ptr::read_volatile((frame + FRAME_SP_EL0) as *const u64))
    };
    klog::write_raw(b"[REGS] mpidr=");
    klog::write_hex_u64(mpidr);
    klog::write_raw(b" tpidr_el1=");
    klog::write_hex_u64(tpidr);
    // SPSR.M[3:0]: 0b0000 = EL0t (fault came from userspace), 0b0101 = EL1h
    // (kernel). SPSR.DAIF says whether IRQs were enabled at fault time — the
    // question the IRQs-on migration turns on.
    klog::write_raw(b" spsr=");
    klog::write_hex_u64(spsr);
    klog::write_raw(if (spsr & 0xf) == 0 { b" from=EL0" } else { b" from=EL1" });
    klog::write_raw(if (spsr & (1 << 7)) != 0 { b" I=masked" } else { b" I=enabled" });
    klog::write_raw(b" elr=");
    klog::write_hex_u64(elr);
    klog::write_raw(b" sp_el1=");
    klog::write_hex_u64(frame + FRAME_BYTES);
    klog::write_raw(b" sp_el0=");
    klog::write_hex_u64(sp_el0);
    klog::write_raw(b"\n");
    percpu_line(tpidr, frame + FRAME_BYTES);
    for (i, (name, off)) in GPRS.iter().enumerate() {
        if i % COLS == 0 { klog::write_raw(b"[REGS]"); }
        klog::write_raw(b" ");
        klog::write_raw(name);
        klog::write_raw(b"=");
        // SAFETY: per fn contract — `frame + off` is a GPR slot inside the vector's
        // own 288-byte frame; every offset in GPRS is < FRAME_BYTES by construction.
        klog::write_hex_u64(unsafe { core::ptr::read_volatile((frame + off) as *const u64) });
        if i % COLS == COLS - 1 || i == GPRS.len() - 1 { klog::write_raw(b"\n"); }
    }
    // Free-IP provenance over the whole register file: `uaf_lookup` reports
    // only while a freed block is quarantined (debug-heappoison), so this is
    // silent otherwise.
    for (name, off) in GPRS.iter() {
        // SAFETY: as above — reading a GPR slot within this exception's frame.
        let v = unsafe { core::ptr::read_volatile((frame + off) as *const u64) };
        if let Some((base, size, free_ip)) = kalloc::uaf_lookup(v) { report_uaf(name, v, base, size, free_ip); }
    }
}

/// Per-CPU state that decides whether a bad SP came from the IRQ-stack switch
/// or from the interrupted task's kernel stack: the CPU id and the IRQ-stack
/// top this CPU published (`vbar::set_irq_stack_top`), plus where the
/// interrupted `SP_EL1` sits relative to that 16 KiB window. `on=yes` means the
/// abort happened on the per-CPU IRQ stack; `above` means SP was past its top,
/// i.e. in the next slot's guard page — the switch or a restore is wrong, not
/// the task.
///
/// `tpidr` was already read by `pe_identity`; a zero base means per-CPU state
/// is not yet armed and there is nothing to read.
fn percpu_line(tpidr: u64, sp_el1: u64) {
    if tpidr == 0 { return; }
    /// `vbar::PERCPU_IRQ_STACK_TOP_OFF` — slot @32 of the per-CPU page.
    const IRQ_TOP_OFF: u64 = 32;
    /// `sched::kstack::KSTACK_BYTES`, reverse-asserted there and in the entry asm.
    const IRQ_STACK_BYTES: u64 = 0x4000;
    // SAFETY: `tpidr` is this CPU's per-CPU page base (TPIDR_EL1, just read by
    // pe_identity); slot 0 holds the cpu id and slot 32 the IRQ-stack top.
    let (id, top) = unsafe {
        (core::ptr::read_volatile(tpidr as *const u32),
         core::ptr::read_volatile((tpidr + IRQ_TOP_OFF) as *const u64))
    };
    klog::write_raw(b"[REGS] cpu=");
    klog::write_dec_u64(id as u64);
    klog::write_raw(b" irq_stack_top=");
    klog::write_hex_u64(top);
    if top != 0 {
        klog::write_raw(b" sp_el1-vs-irqstack=");
        if sp_el1 >= top { klog::write_raw(b"ABOVE-TOP+"); klog::write_dec_u64(sp_el1 - top); }
        else if sp_el1 >= top - IRQ_STACK_BYTES { klog::write_raw(b"on=yes depth="); klog::write_dec_u64(top - sp_el1); }
        else { klog::write_raw(b"below (task kstack)"); }
    }
    klog::write_raw(b"\n");
}

/// One `[UAF]` line: which register held the stale pointer, the freed block it
/// falls in, and the IP that freed it (`addr2line` → the Drop glue → the type).
fn report_uaf(name: &[u8], ptr: u64, base: u64, size: u32, free_ip: u64) {
    klog::write_raw(b"[UAF] reg=");
    klog::write_raw(name);
    klog::write_raw(b" ptr=");
    klog::write_hex_u64(ptr);
    klog::write_raw(b" IN FREED block base=");
    klog::write_hex_u64(base);
    klog::write_raw(b" size=");
    klog::write_dec_u64(size as u64);
    klog::write_raw(b" free_ip=");
    if free_ip == kalloc::UAF_FREE_IP_UNKNOWN { klog::write_raw(b"unknown"); }
    else { klog::write_raw(b"0x"); klog::write_hex_u64(free_ip); }
    klog::write_raw(b"\n");
}
