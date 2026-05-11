// GICv3 bring-up per `22§5` (aarch64).
//
// Replaces the GICv2 implementation as part of F55 silent-MSI fix.
// QEMU virt is launched with `gic-version=3,its=on`; the CPU
// interface is now system-register only (ICC_*) — no GICC MMIO.
// The Distributor stays MMIO at the same base; per-CPU state lives
// in the Redistributor (GICR) region. SPI affinity routing is via
// GICD_IROUTER (writes a 64-bit MPIDR target), replacing v2's
// GICD_ITARGETSR. ITS is a separate driver (`its.rs`); MSI delivery
// targets ITS_BASE + GITS_TRANSLATER.

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU64, Ordering};

// ---- Distributor offsets (shared with v2) ---------------------------------

#[cfg(target_arch = "aarch64")]
const GICD_CTLR:       usize = 0x0000;
#[cfg(target_arch = "aarch64")]
const GICD_TYPER:      usize = 0x0004;
#[cfg(target_arch = "aarch64")]
const GICD_IIDR:       usize = 0x0008;
#[cfg(target_arch = "aarch64")]
const GICD_ISENABLER:  usize = 0x0100;
#[cfg(target_arch = "aarch64")]
const GICD_IPRIORITYR: usize = 0x0400;
#[cfg(target_arch = "aarch64")]
const GICD_ICFGR:      usize = 0x0C00;
#[cfg(target_arch = "aarch64")]
const GICD_ISPENDR:    usize = 0x0200;
/// GICv3-only: SPI affinity-routing register (8 bytes per INTID, base 0x6000).
#[cfg(target_arch = "aarch64")]
const GICD_IROUTER:    usize = 0x6000;

/// GICD_CTLR bits (GICv3 with ARE_NS=1):
///   bit 0 — EnableGrp0
///   bit 1 — EnableGrp1NS
///   bit 4 — ARE_NS (MUST be 1 for GICv3)
#[cfg(target_arch = "aarch64")]
const CTLR_ENGRP0:  u32 = 1 << 0;
#[cfg(target_arch = "aarch64")]
const CTLR_ENGRP1:  u32 = 1 << 1;
#[cfg(target_arch = "aarch64")]
const CTLR_ARE_NS:  u32 = 1 << 4;

// ---- Redistributor offsets (RD frame at gicr_va, SGI frame at +0x10000) ----

#[cfg(target_arch = "aarch64")]
const GICR_CTLR:        usize = 0x0000;
#[cfg(target_arch = "aarch64")]
const GICR_TYPER:       usize = 0x0008;
#[cfg(target_arch = "aarch64")]
const GICR_WAKER:       usize = 0x0014;
/// LPI configuration table base + size (RD frame).
#[cfg(target_arch = "aarch64")]
const GICR_PROPBASER:   usize = 0x0070;
/// LPI pending table base (RD frame, per-PE).
#[cfg(target_arch = "aarch64")]
const GICR_PENDBASER:   usize = 0x0078;
/// SGI frame is at gicr_va + 0x10000.
#[cfg(target_arch = "aarch64")]
const GICR_SGI_OFFSET:  u64   = 0x10000;
/// In the SGI frame (relative to gicr_va + GICR_SGI_OFFSET).
#[cfg(target_arch = "aarch64")]
const GICR_ISENABLER0:  usize = 0x0100;
#[cfg(target_arch = "aarch64")]
const GICR_IPRIORITYR:  usize = 0x0400;
#[cfg(target_arch = "aarch64")]
const GICR_ICFGR1:      usize = 0x0C04;

/// WAKER bits.
#[cfg(target_arch = "aarch64")]
const WAKER_PROCESSOR_SLEEP:  u32 = 1 << 1;
#[cfg(target_arch = "aarch64")]
const WAKER_CHILDREN_ASLEEP:  u32 = 1 << 2;

// ---- Misc ------------------------------------------------------------------

/// IAR INTID field width on GICv3 (bits[23:0]).
#[cfg(target_arch = "aarch64")]
const IAR_INTID_MASK: u32 = 0x00FF_FFFF;
/// Spurious INTID — IAR returns 1023 (or 1022/1021 for special) when no IRQ pending.
#[cfg(target_arch = "aarch64")]
const SPURIOUS_INTID: u32 = 1023;

/// Stash GICD/GICR bases so EOI / IAR helpers + ITS can find them.
#[cfg(target_arch = "aarch64")]
static GICD_VA: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "aarch64")]
static GICR_VA: AtomicU64 = AtomicU64::new(0);

/// Per-CPU tick counter incremented by the timer-IRQ dispatcher.
#[cfg(target_arch = "aarch64")]
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Last INTID acknowledged by the Rust dispatcher (debug aid).
#[cfg(target_arch = "aarch64")]
pub static LAST_INTID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Count of PL011 RX/RT IRQs (INTID 33) the dispatcher has handled.
#[cfg(target_arch = "aarch64")]
pub static UART_IRQ_FIRES: AtomicU64 = AtomicU64::new(0);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GicStatus {
    AlreadyOn,
    Enabled { typer: u32, gicd_iidr: u32, gicr_typer_lo: u32 },
}

/// Bring up GICv3: assert ARE_NS + EnableGrp1NS in GICD; wake the
/// per-CPU redistributor; enable the system-register CPU interface
/// (ICC_SRE_EL1, ICC_PMR_EL1, ICC_IGRPEN1_EL1).
///
/// # SAFETY: caller asserts both `gicd_va` and `gicr_va` are
/// freshly Device-attr-mapped; runs single-CPU pre-init, IRQ-off.
/// # C: O(spin until ChildrenAsleep)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn enable(gicd_va: u64, gicr_va: u64) -> GicStatus {
    if GICD_VA.load(Ordering::Acquire) != 0 {
        return GicStatus::AlreadyOn;
    }
    // SAFETY: VAs freshly Device-nGnRnE mapped; single-CPU pre-init; sole writer to GIC state during boot.
    unsafe {
        // 1. Distributor: ARE_NS=1, both group enables on.
        let gicd_ctlr = (gicd_va + GICD_CTLR as u64) as *mut u32;
        let cur = core::ptr::read_volatile(gicd_ctlr);
        core::ptr::write_volatile(
            gicd_ctlr,
            cur | CTLR_ARE_NS | CTLR_ENGRP0 | CTLR_ENGRP1,
        );

        // 2. Redistributor: clear ProcessorSleep, wait ChildrenAsleep=0.
        let waker = (gicr_va + GICR_WAKER as u64) as *mut u32;
        let w = core::ptr::read_volatile(waker);
        core::ptr::write_volatile(waker, w & !WAKER_PROCESSOR_SLEEP);
        let mut spin = 0u32;
        while core::ptr::read_volatile(waker) & WAKER_CHILDREN_ASLEEP != 0 {
            spin = spin.wrapping_add(1);
            if spin > 1_000_000 { break; }
            core::hint::spin_loop();
        }

        // 3. CPU interface via system registers.
        //    ICC_SRE_EL1.SRE=1: enable sysreg interface.
        //    ICC_PMR_EL1=0xFF: let every priority through.
        //    ICC_IGRPEN1_EL1=1: enable Group 1 NS interrupts.
        // SAFETY: ICC_* sysregs are privileged at EL1; sequence per ARM ARM D7 (GICv3 architecture).
        core::arch::asm!(
            "mrs  x9,  s3_0_c12_c12_5",   // ICC_SRE_EL1
            "orr  x9,  x9,  #1",
            "msr  s3_0_c12_c12_5, x9",
            "isb",
            "mov  x9,  #0xff",
            "msr  s3_0_c4_c6_0,   x9",    // ICC_PMR_EL1
            "mov  x9,  #1",
            "msr  s3_0_c12_c12_7, x9",    // ICC_IGRPEN1_EL1
            "isb",
            out("x9") _,
            options(nostack, preserves_flags),
        );

        let typer         = core::ptr::read_volatile((gicd_va + GICD_TYPER as u64) as *const u32);
        let gicd_iidr     = core::ptr::read_volatile((gicd_va + GICD_IIDR  as u64) as *const u32);
        let gicr_typer_lo = core::ptr::read_volatile((gicr_va + GICR_TYPER as u64) as *const u32);

        GICD_VA.store(gicd_va, Ordering::Release);
        GICR_VA.store(gicr_va, Ordering::Release);

        GicStatus::Enabled { typer, gicd_iidr, gicr_typer_lo }
    }
}

/// Enable an SGI/PPI/SPI INTID. SGIs/PPIs (INTID < 32) live in the
/// per-CPU Redistributor (SGI frame); SPIs (INTID >= 32) live in
/// the Distributor and additionally need GICD_IROUTER set so the
/// SPI is routed to a participating PE.
///
/// # SAFETY: caller asserts `enable` has run; runs single-CPU,
/// IRQ-off; the chosen INTID is owned by the caller.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn enable_intid(intid: u32) {
    let gicd = GICD_VA.load(Ordering::Acquire);
    let gicr = GICR_VA.load(Ordering::Acquire);
    if gicd == 0 || gicr == 0 { return; }
    // SAFETY: GICD/GICR are Device-attr-mapped; offsets stay within their regions.
    unsafe {
        if intid < 32 {
            // SGI/PPI: per-CPU banked in GICR SGI frame.
            let sgi_base   = gicr + GICR_SGI_OFFSET;
            let isenabler  = (sgi_base + GICR_ISENABLER0 as u64) as *mut u32;
            core::ptr::write_volatile(isenabler, 1u32 << (intid & 31));
            let prio = (sgi_base + GICR_IPRIORITYR as u64 + intid as u64) as *mut u8;
            core::ptr::write_volatile(prio, 0x80);
            // PPIs typically default to level-sensitive; leave ICFGR alone.
        } else {
            // SPI: distributor.
            let word = (intid / 32) as u64 * 4;
            let isenabler = (gicd + GICD_ISENABLER as u64 + word) as *mut u32;
            core::ptr::write_volatile(isenabler, 1u32 << (intid & 31));
            let prio = (gicd + GICD_IPRIORITYR as u64 + intid as u64) as *mut u8;
            core::ptr::write_volatile(prio, 0x80);
            // ICFGR: 2 bits per INTID, edge-triggered (0b10) for MSI-class lines.
            let icfgr_off = (intid / 16) as u64 * 4;
            let shift     = ((intid % 16) * 2) as u32;
            let icfgr     = (gicd + GICD_ICFGR as u64 + icfgr_off) as *mut u32;
            let cur       = core::ptr::read_volatile(icfgr);
            let cleared   = cur & !(0b11u32 << shift);
            core::ptr::write_volatile(icfgr, cleared | (0b10u32 << shift));
            // IROUTER: route to CPU 0 (MPIDR.Aff{3,2,1,0} = 0). v1 is
            // single-CPU UP; widen to per-CPU when SMP lands.
            let irouter = (gicd + GICD_IROUTER as u64 + (intid as u64) * 8) as *mut u64;
            core::ptr::write_volatile(irouter, 0u64);
        }
    }
}

// ---- LPI bring-up (F56-04) ------------------------------------------------

/// Number of LPI ID bits we configure. The minimum legal value is
/// 14 on QEMU (LPIs 8192..(1<<14)-1=16383); going lower than the
/// hardware-reported support floor causes GICR_PROPBASER.IDbits to
/// be RAZ/WI. 14 → 16 KiB config table, 2 KiB pending bitmap (but
/// allocation is rounded up to the 64 KiB minimum the architecture
/// mandates for the pending region).
#[cfg(target_arch = "aarch64")]
const LPI_ID_BITS: u32 = 14;

/// PROPBASER bit composition (ARM IHI 0069 §11.4.10):
///   [47:12] PA — alignment ≥ 4 KiB
///   [11:10] Shareability — 0b01 = Inner-Shareable
///   [9:7]   InnerCache  — 0b001 = Normal Inner Non-Cacheable
///   [4:0]   IDbits-1
#[cfg(target_arch = "aarch64")]
const PROPBASER_IC_NC:    u64 = 1 << 7;
#[cfg(target_arch = "aarch64")]
const PROPBASER_INNER_SH: u64 = 1 << 10;

/// PENDBASER bit composition (ARM IHI 0069 §11.4.9):
///   [62]    PTZ — Pending-Table Zero
///   [47:16] PA — 64 KiB aligned
///   [11:10] Shareability
///   [9:7]   InnerCache
#[cfg(target_arch = "aarch64")]
const PENDBASER_PTZ:      u64 = 1 << 62;
#[cfg(target_arch = "aarch64")]
const PENDBASER_IC_NC:    u64 = 1 << 7;
#[cfg(target_arch = "aarch64")]
const PENDBASER_INNER_SH: u64 = 1 << 10;

/// GICR_CTLR.EnableLPI = bit 0. Latched: once set, GICR_PROPBASER and
/// GICR_PENDBASER are RO and the RD begins consuming LPI deliveries.
#[cfg(target_arch = "aarch64")]
const GICR_CTLR_ENABLE_LPI: u32 = 1 << 0;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LpisStatus {
    AlreadyOn,
    AllocFailed,
    Ready {
        prop_pa:        u64,
        pend_pa:        u64,
        propbaser_rd:   u64,
        pendbaser_rd:   u64,
        ctlr_post:      u32,
    },
}

/// Track whether LPIs were enabled on the boot CPU's RD already.
#[cfg(target_arch = "aarch64")]
static LPIS_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// PA of the global LPI configuration table (one byte per LPI).
/// Written by `lpi_set_config` after `lpis_enable` publishes it.
#[cfg(target_arch = "aarch64")]
static LPI_PROP_PA: AtomicU64 = AtomicU64::new(0);

/// First LPI INTID (per ARM ARM, LPIs occupy [8192, 8192 + N)).
#[cfg(target_arch = "aarch64")]
pub const LPI_BASE: u32 = 8192;

/// Default LPI configuration byte: priority 0xA0 + Group1 RES1 +
/// Enable=1. ARM IHI 0069 §11.2.1 byte layout: [7:2] priority,
/// [1] RES1, [0] Enable.
#[cfg(target_arch = "aarch64")]
pub const LPI_PROP_DEFAULT: u8 = 0xA0 | 0x02 | 0x01;

/// Bring up LPIs on the boot CPU's redistributor: allocate +
/// zero the global LPI configuration table (16 KiB) and the per-RD
/// pending table (64 KiB; the architecture-required minimum), program
/// `GICR_PROPBASER` + `GICR_PENDBASER`, then set `GICR_CTLR.EnableLPI`.
///
/// LPI configuration writes after this point require an INV/INVALL
/// command via the ITS to take effect (handled in F56-06+).
///
/// # SAFETY: caller asserts `enable` already published `GICR_VA`,
/// PMM is up, single-CPU pre-init IRQ-off.
/// # C: O(prop_zero + pend_zero) ≈ 80 KiB writes
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn lpis_enable(hhdm: u64) -> LpisStatus {
    use core::sync::atomic::Ordering as O;
    if LPIS_ENABLED.load(O::Acquire) {
        return LpisStatus::AlreadyOn;
    }
    let gicr = GICR_VA.load(Ordering::Acquire);
    if gicr == 0 {
        return LpisStatus::AllocFailed;
    }
    // LPI configuration table size = (1 << ID_BITS) bytes, one
    // priority+enable byte per LPI. ID_BITS=14 → 16 KiB → Order 2.
    // Pending table architecturally requires ≥ 64 KiB → Order 4.
    let prop_pa = match pmm::setup::alloc_contig(pmm::Order(2)) {
        Some(p) => p,
        None    => return LpisStatus::AllocFailed,
    };
    let pend_pa = match pmm::setup::alloc_contig(pmm::Order(4)) {
        Some(p) => p,
        None    => return LpisStatus::AllocFailed,
    };
    if hhdm != 0 {
        // SAFETY: HHDM-mapped contig PMM regions; aligned u64 stores within the region bounds.
        unsafe {
            let prop_va = hhdm.wrapping_add(prop_pa) as *mut u64;
            for i in 0..(0x4000 / 8) {
                core::ptr::write_volatile(prop_va.add(i), 0);
            }
            let pend_va = hhdm.wrapping_add(pend_pa) as *mut u64;
            for i in 0..(0x10000 / 8) {
                core::ptr::write_volatile(pend_va.add(i), 0);
            }
        }
    }
    let propbaser = PROPBASER_IC_NC
                  | PROPBASER_INNER_SH
                  | (prop_pa & 0x0000_FFFF_FFFF_F000)
                  | ((LPI_ID_BITS - 1) as u64 & 0x1f);
    let pendbaser = PENDBASER_PTZ
                  | PENDBASER_IC_NC
                  | PENDBASER_INNER_SH
                  | (pend_pa & 0x0000_FFFF_FFFF_0000);
    // SAFETY: GICR RD frame Device-attr mapped via smoke_device_map_arm; offsets within first 4 KiB.
    let (propbaser_rd, pendbaser_rd, ctlr_post) = unsafe {
        core::ptr::write_volatile((gicr + GICR_PROPBASER as u64) as *mut u64, propbaser);
        core::ptr::write_volatile((gicr + GICR_PENDBASER as u64) as *mut u64, pendbaser);
        let p_rd = core::ptr::read_volatile((gicr + GICR_PROPBASER as u64) as *const u64);
        let e_rd = core::ptr::read_volatile((gicr + GICR_PENDBASER as u64) as *const u64);
        let cur = core::ptr::read_volatile((gicr + GICR_CTLR as u64) as *mut u32);
        core::ptr::write_volatile((gicr + GICR_CTLR as u64) as *mut u32, cur | GICR_CTLR_ENABLE_LPI);
        let post = core::ptr::read_volatile((gicr + GICR_CTLR as u64) as *const u32);
        (p_rd, e_rd, post)
    };
    LPI_PROP_PA.store(prop_pa, Ordering::Release);
    LPIS_ENABLED.store(true, O::Release);
    LpisStatus::Ready { prop_pa, pend_pa, propbaser_rd, pendbaser_rd, ctlr_post }
}

/// Write one byte of the LPI configuration table for `lpi_id`. The
/// caller MUST follow with an ITS `INV` (or `INVALL`) command so the
/// ITS reloads the cached entry.
///
/// # SAFETY: `lpis_enable` must have published `LPI_PROP_PA`; HHDM
/// must cover the table; runs single-CPU pre-init.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn lpi_set_config(hhdm: u64, lpi_id: u32, byte: u8) -> bool {
    if lpi_id < LPI_BASE { return false; }
    let prop_pa = LPI_PROP_PA.load(Ordering::Acquire);
    if prop_pa == 0 || hhdm == 0 { return false; }
    let off = (lpi_id - LPI_BASE) as u64;
    // SAFETY: HHDM-mapped LPI prop table; offset within (1 << ID_BITS) bytes.
    unsafe {
        core::ptr::write_volatile(
            hhdm.wrapping_add(prop_pa + off) as *mut u8,
            byte,
        );
    }
    true
}

/// Read the GICD_ISPENDR word covering `intid`. Diagnostic only.
///
/// # SAFETY: distributor must have been mapped via `enable`.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn ispendr_word(intid: u32) -> u32 {
    let gicd = GICD_VA.load(Ordering::Acquire);
    if gicd == 0 { return 0; }
    let off = (intid / 32) as u64 * 4;
    // SAFETY: distributor freshly mapped Device-attr; ISPENDR within the 64 KiB GICD region.
    unsafe { core::ptr::read_volatile((gicd + GICD_ISPENDR as u64 + off) as *const u32) }
}

/// Acknowledge the highest-priority pending INTID via ICC_IAR1_EL1.
///
/// # SAFETY: pair with an in-progress IRQ at EL1.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn iar() -> u32 {
    let v: u64;
    // SAFETY: ICC_IAR1_EL1 is a privileged sysreg legal at EL1; per fn contract.
    unsafe {
        core::arch::asm!(
            "mrs {v}, s3_0_c12_c12_0",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v as u32
}

/// End-of-interrupt via ICC_EOIR1_EL1.
///
/// # SAFETY: must mirror a prior `iar()` for the same INTID.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn eoi(intid: u32) {
    // SAFETY: ICC_EOIR1_EL1 is privileged sysreg, legal at EL1; per fn contract.
    unsafe {
        core::arch::asm!(
            "msr s3_0_c12_c12_1, {v:x}",
            v = in(reg) intid as u64,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Rust IRQ dispatcher invoked from `oxide_irq_vector_handler`.
/// Reads ICC_IAR1_EL1, dispatches by INTID, then writes ICC_EOIR1_EL1.
///
/// # SAFETY: invoked only from the asm vector entry with IRQs masked.
/// # C: O(1)
/// # Ctx: IRQ
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_arm_irq_dispatch() {
    // SAFETY: dispatcher runs inside an in-progress IRQ; GIC was mapped+enabled before any IRQ unmask.
    let raw = unsafe { iar() };
    let intid = raw & IAR_INTID_MASK;
    LAST_INTID.store(intid, Ordering::Relaxed);
    if intid != SPURIOUS_INTID {
        TICK_COUNT.fetch_add(1, Ordering::Relaxed);
        // F39 + F56-08: count MSI deliveries via either the legacy
        // GICv2m SPI range or the GICv3 LPI range (≥ 8192).
        if crate::intid_is_v2m(intid) || intid >= LPI_BASE {
            crate::MSI_FIRES.fetch_add(1, Ordering::Relaxed);
        }
        // CNTV virtual timer INTID is 27 on QEMU virt. Reload TVAL
        // so the level-triggered line drops and re-arms for the next
        // period; otherwise the IRQ would re-fire immediately on
        // eret. Period is published by `arm_timer::timer_periodic`.
        if intid == 27 {
            let p = hal_aarch64::timer::PERIOD.load(Ordering::Relaxed) as u64;
            // SAFETY: CNTV_TVAL_EL0 is an unprivileged sysreg; writing it advances CVAL past the current count, deasserting the line.
            unsafe {
                core::arch::asm!("msr cntv_tval_el0, {v:x}", v = in(reg) p, options(nomem, nostack, preserves_flags));
            }
        }
        if intid == 33 {
            // F47: PL011 RX/RT IRQ — drain FIFO via tick_poll_uart
            // below, then write-1-to-clear the IMSC-matched bits in
            // UARTICR so the line drops and re-arms for the next
            // batch of input.
            // SAFETY: dispatcher context, IRQs masked; pl011 was enabled in smoke_device_map_arm; single-CPU.
            unsafe { hal_aarch64::pl011::ack_rx_irq(); }
            UART_IRQ_FIRES.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: mirrors the IAR read above; same INTID; CPU interface state via system regs.
        unsafe { eoi(raw); }
        // F54: PL011 RX FIFO drain is SPI-33-only.
        if intid == 33 {
            // SAFETY: SPI 33 dispatch context, IRQs masked; tty path is single-CPU UP.
            unsafe { crate::tick_poll(); }
        }
        sched::live::preempt::set_need_resched();
        // Linux-style softirq bottom-half: see lapic.rs comment.
        // EOI'd above; unmask IRQs for the drain so virtio-gpu /
        // virtio-input handlers that wait on device acks can run.
        if softirq::pending() {
            // SAFETY: EOI was issued above; softirq::run_pending guards re-entry. daifset on the tail restores IRQ masking before tick_pick_next.
            unsafe {
                core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags));
                softirq::run_pending();
                core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags));
            }
        }
        // SAFETY: tick_pick_next runs in IRQ context with IRQs masked; per-CPU SCHED state is single-CPU at this point in v1.
        unsafe { sched::live::preempt::tick_pick_next(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gic_status_distinct() {
        let a = GicStatus::AlreadyOn;
        let b = GicStatus::Enabled { typer: 0, gicd_iidr: 0, gicr_typer_lo: 0 };
        assert_ne!(a, b);
    }
}
