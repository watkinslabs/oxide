// LDTR programming: build this CPU's GDT LDT descriptor and load it.
//
// The reference has a per-CPU GDT and can therefore keep one LDT index; this
// port shares a single GDT across every CPU, so each CPU owns its own
// descriptor pair (`gdt::LDT_GDT_INDEX_BASE + cpu*2`). Two CPUs running
// different address spaces then program independent LDTRs without either
// seeing the other's base.
//
// The table itself is ordinary kernel memory reached through the kernel half
// of every address space, so no user mapping and no PTI alias is involved:
// userspace never sees the descriptors, it only sees their effect through a
// segment register.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::gdt;

/// Bytes per LDT entry — one 8-byte segment descriptor.
pub const LDT_ENTRY_SIZE: u32 = 8;

/// Architectural maximum entries (13-bit selector index).
pub const LDT_ENTRIES: u32 = 8192;

/// Access byte of an LDT descriptor: P=1, DPL=0, S=0 (system), type=0x2.
///
/// DPL is 0 and not 3: the descriptor lives in the GDT and is loaded by
/// `lldt` at CPL 0. Userspace reaches the table only through the LDT
/// selectors it installs, never through this GDT entry.
const ACCESS_LDT: u8 = 0x82;

/// Granularity nibble: byte-granular. The full table is 64 KiB − 1 at most,
/// which fits a byte-granular 20-bit limit with room to spare.
const FLAGS_LDT: u8 = 0x0;

/// Low half of the 16-byte LDT system descriptor.
/// # C: O(1)
pub const fn ldt_low(base: u64, limit: u32) -> u64 {
    let mut d: u64 = 0;
    d |= (limit & 0xFFFF) as u64;                  // limit[15:0]
    d |= (base & 0xFF_FFFF) << 16;                 // base[23:0]
    d |= (ACCESS_LDT as u64) << 40;                // access byte
    d |= (((limit >> 16) & 0xF) as u64) << 48;     // limit[19:16]
    d |= ((FLAGS_LDT & 0xF) as u64) << 52;         // flags nibble
    d |= ((base >> 24) & 0xFF) << 56;              // base[31:24]
    d
}

/// High half: `base[63:32]`, everything else reserved zero.
/// # C: O(1)
pub const fn ldt_high(base: u64) -> u64 { (base >> 32) & 0xFFFF_FFFF }

/// Selector CPU `cpu` uses for `lldt`. RPL/TI are zero: it names a GDT entry
/// loaded at CPL 0.
/// # C: O(1)
pub const fn ldt_selector(cpu: usize) -> u16 {
    ((gdt::LDT_GDT_INDEX_BASE + cpu * 2) * 8) as u16
}

/// The descriptor limit for a table of `nr_entries` entries.
///
/// `nr_entries * 8 - 1`, so the last byte of the last entry is the last byte
/// inside the limit. An off-by-one here either hides the top entry (a #GP on
/// a selector the process legitimately installed) or exposes eight bytes past
/// the table.
/// # C: O(1)
pub const fn ldt_limit(nr_entries: u32) -> u32 { nr_entries * LDT_ENTRY_SIZE - 1 }

/// What each CPU currently has in LDTR, as `(generation << 1) | loaded`.
///
/// Read by the return-to-user path to decide whether this CPU's LDTR is
/// behind the address space it is about to return into. Zero means "nothing
/// loaded", which is also the state after `clear`.
static LOADED: [AtomicU64; crate::tss::NR_TSS] =
    [const { AtomicU64::new(0) }; crate::tss::NR_TSS];

/// Token stored in `LOADED` for a table at `generation`. Generation zero can
/// never reach here (a table exists only after at least one install), so the
/// `+1` keeps "loaded" distinguishable from "nothing loaded".
/// # C: O(1)
pub const fn load_token(generation: u64) -> u64 { generation.wrapping_add(1) }

/// The token this CPU last loaded. `0` = no LDT.
/// # C: O(1)
pub fn current_token(cpu: usize) -> u64 {
    LOADED[cpu.min(crate::tss::NR_TSS - 1)].load(Ordering::Acquire)
}

/// Point this CPU's LDTR at `base`/`nr_entries`, recording `generation` so a
/// later reload can be skipped when nothing changed.
///
/// # SAFETY: `base` must name a live, kernel-mapped table of at least
/// `nr_entries` descriptors that stays alive for as long as this CPU may run
/// the owning address space. `nr_entries` must be in `1..=LDT_ENTRIES`.
/// # C: O(1)
/// # Ctx: CPL 0, preempt-off
pub unsafe fn load(cpu: usize, base: u64, nr_entries: u32, generation: u64) {
    let cpu = cpu.min(crate::tss::NR_TSS - 1);
    if nr_entries == 0 || nr_entries > LDT_ENTRIES {
        // SAFETY: clearing LDTR is always defined and needs no table.
        unsafe { clear(cpu) };
        return;
    }
    let index = gdt::LDT_GDT_INDEX_BASE + cpu * 2;
    // SAFETY: `index` is this CPU's own reserved descriptor pair, inside
    // `GDT_LEN` by construction, and no segment register holds it — LDTR is
    // reloaded immediately below, and nothing else references an LDT
    // descriptor.
    unsafe { gdt::write_system_descriptor(index, ldt_low(base, ldt_limit(nr_entries)), ldt_high(base)); }
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let sel = ldt_selector(cpu);
        // SAFETY: `sel` names the descriptor pair just written, which is a
        // present LDT descriptor over a live kernel-mapped table; `lldt` at
        // CPL 0 with a valid GDT selector cannot fault.
        unsafe { core::arch::asm!("lldt {0:x}", in(reg) sel, options(nostack, preserves_flags)); }
    }
    LOADED[cpu].store(load_token(generation), Ordering::Release);
}

/// Selector bit 2 — the table indicator. Set means the selector names the
/// LDT rather than the GDT.
pub const SEGMENT_TI_LDT: u16 = 1 << 2;

/// Reload any of this CPU's data segment registers that still name an LDT
/// selector, so the descriptor the CPU has cached for them is re-read from
/// the table just installed (the reference's `refresh_ldt_segments`).
///
/// A segment register keeps a hidden copy of the descriptor it was loaded
/// with; changing the table entry underneath it changes nothing until the
/// selector is loaded again. In 64-bit kernel mode DS and ES are normally
/// null, so this is usually a pair of reads and no writes.
///
/// # SAFETY: only selectors that already passed a load are reloaded, from a
/// table that is present and live; CS/SS are deliberately untouched, since a
/// user context never has an LDT selector in either and reloading SS at CPL 0
/// is not a thing this path may do.
/// # C: O(1)
/// # Ctx: CPL 0, preempt-off, interrupts masked
pub unsafe fn refresh_segments() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let mut sel: u16;
        // SAFETY: reading a segment selector into a register is always legal.
        unsafe { core::arch::asm!("mov {0:x}, ds", out(reg) sel, options(nomem, nostack, preserves_flags)); }
        if sel & SEGMENT_TI_LDT != 0 {
            // SAFETY: `sel` is the selector DS already holds, so its
            // descriptor is present in the table now loaded in LDTR.
            unsafe { core::arch::asm!("mov ds, {0:x}", in(reg) sel, options(nostack, preserves_flags)); }
        }
        // SAFETY: reading a segment selector into a register is always legal.
        unsafe { core::arch::asm!("mov {0:x}, es", out(reg) sel, options(nomem, nostack, preserves_flags)); }
        if sel & SEGMENT_TI_LDT != 0 {
            // SAFETY: `sel` is the selector ES already holds, so its
            // descriptor is present in the table now loaded in LDTR.
            unsafe { core::arch::asm!("mov es, {0:x}", in(reg) sel, options(nostack, preserves_flags)); }
        }
    }
}

/// Load a null LDT on this CPU (the reference's `clear_LDT`). Every segment
/// register referencing the LDT becomes unusable, which is exactly what a
/// switch to an address space without a table must produce.
///
/// # SAFETY: no segment register may still name an LDT selector when this
/// returns to user mode; the switch path clears LDTR only when moving to an
/// address space whose descriptors the incoming user context does not use.
/// # C: O(1)
/// # Ctx: CPL 0, preempt-off
pub unsafe fn clear(cpu: usize) {
    let cpu = cpu.min(crate::tss::NR_TSS - 1);
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: loading the null selector into LDTR is architecturally
        // defined and requires no descriptor.
        unsafe { core::arch::asm!("lldt {0:x}", in(reg) 0u16, options(nostack, preserves_flags)); }
    }
    LOADED[cpu].store(0, Ordering::Release);
}

#[cfg(test)]
mod tests;
