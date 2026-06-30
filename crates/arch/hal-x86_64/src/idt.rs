// x86_64 IDT install + default handler per `22§4`.
//
// v1 lands the data path: IDT entry layout (Intel SDM Vol. 3 Fig. 6-7),
// 256-entry static IDT, IDTR struct + `lidt` asm, and a single default
// handler that disables IRQs and halts so the first exception stops
// the CPU cleanly instead of triple-faulting.
//
// The full per-vector stub fan-out (each pushing its vector number
// and jumping to a common `pt_regs`-saving entry per `22§4`) lands
// alongside the APIC bring-up in `22§6`. Until then any exception
// reaches `oxide_idt_default_handler` which just halts.

use core::cell::UnsafeCell;

/// 256 hardware vectors per Intel SDM Vol. 3 §6.10.
pub const IDT_LEN: usize = 256;

/// Kernel code selector. Filled in once GDT bring-up exists; until
/// then the bootloader-provided CS works (Limine sets up flat 64-bit
/// segments at offset 0x28).
pub const KERNEL_CS: u16 = 0x28;

/// IDT entry per Intel SDM Vol. 3 Fig. 6-7. 16 bytes; field order
/// asm-coupled with the CPU's hardware decoder.
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
pub struct IdtEntry {
    pub offset_low:  u16,
    pub selector:    u16,
    pub ist:         u8,   // bits 0..2 = IST index, 3..7 = reserved
    pub type_attr:   u8,   // P|DPL|0|TYPE
    pub offset_mid:  u16,
    pub offset_high: u32,
    pub zero:        u32,  // reserved, must be 0
}

/// `type_attr` for a 64-bit interrupt gate at DPL=0 (P=1, DPL=0,
/// gate type = 0xE).
pub const GATE_INT64_KERNEL: u8 = 0x8e;

/// `type_attr` for a 64-bit interrupt gate at DPL=3 (P=1, DPL=3,
/// gate type = 0xE). User-initiable software interrupts (#BP / #OF)
/// must use this so a CPL=3 `int3` / `into` is dispatched instead
/// of #GP'd. Hardware-only vectors keep `GATE_INT64_KERNEL`.
pub const GATE_INT64_USER: u8 = 0xee;

impl IdtEntry {
    /// # C: O(1)
    pub const fn empty() -> Self {
        Self {
            offset_low: 0, selector: 0, ist: 0, type_attr: 0,
            offset_mid: 0, offset_high: 0, zero: 0,
        }
    }

    /// Build an interrupt-gate entry pointing at `handler`. `ist=0`
    /// = use TSS RSP0 stack; `ist=1..=7` selects an IST slot once
    /// the TSS bring-up registers them.
    /// # C: O(1)
    pub const fn new_int_gate(handler: u64, selector: u16, ist: u8) -> Self {
        Self {
            offset_low:  handler        as u16,
            selector,
            ist:         ist & 0x07,
            type_attr:   GATE_INT64_KERNEL,
            offset_mid: (handler >> 16) as u16,
            offset_high:(handler >> 32) as u32,
            zero:        0,
        }
    }

    /// Reassemble the 64-bit handler address from the split fields.
    /// # C: O(1)
    pub const fn handler(self) -> u64 {
        let lo  = self.offset_low  as u64;
        let mid = self.offset_mid  as u64;
        let hi  = self.offset_high as u64;
        lo | (mid << 16) | (hi << 32)
    }
}

/// IDTR per Intel SDM Vol. 3 Fig. 2-7. `limit` = byte size minus
/// one; `base` = linear address of the IDT.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct IdtPointer {
    pub limit: u16,
    pub base:  u64,
}

/// Kernel-wide IDT. Single instance; populated via `install_default`.
#[repr(C, align(16))]
struct Idt(UnsafeCell<[IdtEntry; IDT_LEN]>);

// SAFETY: cross-thread access is mediated by single-threaded boot
// install + the CPU itself reading entries via `lidt`. After install,
// entries are read-only from kernel code; the CPU dereferences them
// asynchronously on every interrupt.
unsafe impl Sync for Idt {}

static IDT: Idt = Idt(UnsafeCell::new([IdtEntry::empty(); IDT_LEN]));

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",
    ".globl oxide_idt_default_handler",
    ".type  oxide_idt_default_handler, @function",
    "oxide_idt_default_handler:",
    "    cli",
    "1:  hlt",
    "    jmp 1b",
    ".size oxide_idt_default_handler, . - oxide_idt_default_handler",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_idt_default_handler() -> !;
}

/// Address of the default handler, or 0 on host where the asm symbol
/// doesn't exist.
fn default_handler_addr() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { oxide_idt_default_handler as *const () as usize as u64 }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Populate every IDT entry with a default-handler interrupt gate
/// then load `IDTR` via `lidt`. Single-shot at boot.
///
/// # SAFETY: caller is the boot path; runs single-CPU with IRQs
/// masked. Re-installation overwrites entries the CPU may otherwise
/// be reading via `iretq`-driven vector dispatch.
/// # C: O(IDT_LEN)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn install_default() {
    let _ = default_handler_addr;  // kept for back-compat; see fault.rs
    // SAFETY: single-CPU boot; we own the IDT static during install.
    // The UnsafeCell is the only legal way to write the array given
    // `06§11` + `07§5` ban `static mut`.
    let idt = unsafe { &mut *IDT.0.get() };
    for (i, entry) in idt.iter_mut().enumerate() {
        // IRQ stubs win over fault stubs when both exist for `vec`;
        // the IRQ path saves regs + iretq instead of halt.
        let h_irq = crate::irq::irq_stub_addr(i as u8);
        let h = if h_irq != 0 { h_irq } else { crate::fault::vector_stub_addr(i as u8) };
        *entry = IdtEntry::new_int_gate(h, KERNEL_CS, 0);
        // Vectors 3 (#BP) + 4 (#OF) are user-initiable via `int3` /
        // `into`; their gate DPL must be 3 or a CPL=3 dispatch
        // raises #GP(IDT,vec) instead. Override the type_attr.
        if i == 3 || i == 4 {
            entry.type_attr = GATE_INT64_USER;
        }
    }
    // Now load IDTR.
    let pointer = IdtPointer {
        limit: (core::mem::size_of::<[IdtEntry; IDT_LEN]>() - 1) as u16,
        base:  idt.as_ptr() as u64,
    };
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `lidt [m16:64]` loads IDTR from memory; legal at
        // CPL=0; the operand we built above is correctly sized + aligned.
        unsafe {
            core::arch::asm!(
                "lidt [{p}]",
                p = in(reg) &pointer,
                options(readonly, nostack, preserves_flags),
            );
        }
    }
    // Host fallback: nothing to do; `pointer` constructed for the
    // side-effect of validating the layout.
    let _ = pointer;
}

/// Patch CPU-exception vector `vec`'s gate to dispatch on IST index `ist`
/// (1..=7; 0 = use the TSS RSP0 stack). The IDT is shared across CPUs, so
/// this sets the index ONCE; the actual stack the index selects is per-CPU
/// via the running CPU's TSS IST slot. The CPU re-reads the gate on every
/// dispatch, so an in-place single-byte field patch after `lidt` is safe.
///
/// # SAFETY: caller asserts every CPU that can take vector `vec` has its
/// TSS IST[`ist`] slot populated (`tss::setup_ist_stacks`) BEFORE this runs
/// — otherwise the fault vectors to a zero stack top. Single u8 store into
/// the IDT static the CPU only reads asynchronously.
/// # C: O(1)
pub unsafe fn set_gate_ist(vec: u8, ist: u8) {
    // SAFETY: single-CPU boot; we own the IDT static for this patch. The
    // CPU reads `ist` (bits 0..2) when it next dispatches `vec`.
    let idt = unsafe { &mut *IDT.0.get() };
    idt[vec as usize].ist = ist & 0x07;
}

/// Point the fatal / nesting-prone CPU-exception gates at their per-CPU IST
/// stacks (Linux-faithful: #DF→IST1, NMI→IST2, #DB→IST3, #MC→IST4). #PF is
/// intentionally NOT IST-routed (Linux keeps it on RSP0 — page faults nest
/// legitimately and a single per-CPU IST is non-reentrant). Call ONCE from
/// the BSP boot path AFTER `tss::setup_ist_stacks(0)`; APs inherit the same
/// gates via the shared IDT and only need their own TSS slots populated.
///
/// # SAFETY: caller asserts the BSP's TSS IST slots are populated; runs
/// single-CPU IRQ-off at boot. Vector numbers are the Intel SDM Vol. 3
/// §6.15 fixed exception assignments.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU (BSP only)
pub unsafe fn install_ist_gates() {
    use crate::tss::{IST_DF, IST_NMI, IST_DB, IST_MC};
    // SAFETY: see fn contract; each call is a single masked u8 field store.
    unsafe {
        set_gate_ist(1,  IST_DB);  // #DB  debug
        set_gate_ist(2,  IST_NMI); // NMI
        set_gate_ist(8,  IST_DF);  // #DF  double fault
        set_gate_ist(18, IST_MC);  // #MC  machine check
    }
}

/// Load IDTR on this CPU using the IDT already populated by an
/// earlier `install_default` call. Used by AP startup so each AP
/// gets the same vector dispatch table without rewriting the
/// shared array.
///
/// # SAFETY: caller asserts `install_default` has run on the boot
/// CPU before any AP calls this; runs in CPL=0 IRQ-off context;
/// the IDT static remains valid for the lifetime of the kernel.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn load_idtr_for_ap() {
    // SAFETY: caller asserts the IDT was populated by install_default; this only reads `idt.as_ptr()`.
    let pointer = unsafe {
        let idt = &*IDT.0.get();
        IdtPointer {
            limit: (core::mem::size_of::<[IdtEntry; IDT_LEN]>() - 1) as u16,
            base:  idt.as_ptr() as u64,
        }
    };
    // SAFETY: `lidt [m16:64]` loads IDTR from a stack-local operand the asm reads as input; legal at CPL=0.
    unsafe {
        core::arch::asm!(
            "lidt [{p}]",
            p = in(reg) &pointer,
            options(readonly, nostack, preserves_flags),
        );
    }
}

/// Hosted-build stub matching the kernel-side surface.
/// # SAFETY: trivially safe -- no asm.
/// # C: O(1)
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
pub unsafe fn load_idtr_for_ap() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idt_entry_size_matches_intel_sdm() {
        // Vol. 3 Fig. 6-7: 16 bytes per entry.
        assert_eq!(core::mem::size_of::<IdtEntry>(), 16);
    }

    #[test]
    fn idt_pointer_size_matches_intel_sdm() {
        // 2-byte limit + 8-byte base = 10 bytes packed.
        assert_eq!(core::mem::size_of::<IdtPointer>(), 10);
    }

    #[test]
    fn gate_int64_kernel_bits_match_spec() {
        // P=1, DPL=00, S=0, type=0xE ⇒ 0x8E.
        assert_eq!(GATE_INT64_KERNEL, 0x8e);
    }

    #[test]
    fn gate_int64_user_bits_match_spec() {
        // P=1, DPL=11, S=0, type=0xE ⇒ 0xEE. User-initiable softint.
        assert_eq!(GATE_INT64_USER, 0xee);
        // DPL field = bits 5..6.
        assert_eq!((GATE_INT64_USER >> 5) & 3, 3);
    }

    #[test]
    fn idt_static_storage_is_4096_bytes() {
        // 256 × 16 = 4096; one page.
        assert_eq!(core::mem::size_of::<[IdtEntry; IDT_LEN]>(), 4096);
    }

    #[test]
    fn new_int_gate_packs_handler_correctly() {
        let h: u64 = 0x0123_4567_89ab_cdef;
        let e = IdtEntry::new_int_gate(h, KERNEL_CS, 0);
        let lo  = e.offset_low;
        let mid = e.offset_mid;
        let hi  = e.offset_high;
        let cs  = e.selector;
        let ta  = e.type_attr;
        assert_eq!(lo,  0xcdef);
        assert_eq!(mid, 0x89ab);
        assert_eq!(hi,  0x0123_4567);
        assert_eq!(cs,  KERNEL_CS);
        assert_eq!(ta,  GATE_INT64_KERNEL);
        assert_eq!(e.handler(), h);
    }

    #[test]
    fn new_int_gate_clamps_ist_to_low_three_bits() {
        let e = IdtEntry::new_int_gate(0, KERNEL_CS, 0xff);
        assert_eq!(e.ist & 0xf8, 0, "high bits of ist must be reserved zero");
        assert_eq!(e.ist & 0x07, 0x07, "low 3 bits should retain caller value");
    }

    #[test]
    fn install_ist_gates_sets_linux_scheme() {
        use crate::tss::{IST_DF, IST_NMI, IST_DB, IST_MC};
        // SAFETY: hosted test; install_default populates the array branch,
        // install_ist_gates patches the gate ist fields (no asm on host).
        unsafe { install_default(); install_ist_gates(); }
        // SAFETY: hosted single-threaded test reads the IDT static.
        let idt = unsafe { &*IDT.0.get() };
        assert_eq!(idt[1].ist,  IST_DB,  "#DB → IST3");
        assert_eq!(idt[2].ist,  IST_NMI, "NMI → IST2");
        assert_eq!(idt[8].ist,  IST_DF,  "#DF → IST1");
        assert_eq!(idt[18].ist, IST_MC,  "#MC → IST4");
        // #PF (vec 14) must stay on RSP0 (ist = 0), Linux-faithful.
        assert_eq!(idt[14].ist, 0, "#PF must NOT be IST-routed");
        // A regular IRQ vector (timer 0x40) is untouched.
        assert_eq!(idt[0x40].ist, 0);
    }

    #[test]
    fn install_default_compiles_on_host() {
        // SAFETY: hosted test; the asm path is cfg'd out so install
        // exercises only the array-population branch and dropping
        // the constructed IDTR pointer.
        unsafe { install_default() };
    }
}
