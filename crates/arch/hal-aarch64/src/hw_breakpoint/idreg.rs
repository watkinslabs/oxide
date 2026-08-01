// `ID_AA64DFR0_EL1` debug-feature decode + the per-boot slot-count cache, and
// the `dbg_info` word the hardware-debug regsets report.
//
// Pure decode, no target gate, so `cargo test -p hal-aarch64` reaches every
// branch. The one privileged read lives at the bottom behind the crate's
// standard kernel-target gate.

use core::sync::atomic::{AtomicU8, Ordering};

/// Architectural ceiling on implemented breakpoint registers (DBGBVR/DBGBCR).
pub const ARM_MAX_BRP: usize = 16;
/// Architectural ceiling on implemented watchpoint registers (DBGWVR/DBGWCR).
pub const ARM_MAX_WRP: usize = 16;

/// `ID_AA64DFR0_EL1.DebugVer` — bits 3:0. Debug architecture version.
pub const DFR0_DEBUGVER_SHIFT: u32 = 0;
/// `ID_AA64DFR0_EL1.BRPs` — bits 15:12. Holds (breakpoint count - 1).
pub const DFR0_BRPS_SHIFT: u32 = 12;
/// `ID_AA64DFR0_EL1.WRPs` — bits 23:20. Holds (watchpoint count - 1).
pub const DFR0_WRPS_SHIFT: u32 = 20;
/// Every `ID_AA64DFR0_EL1` field this module reads is 4 bits wide.
pub const DFR0_FIELD_MASK: u64 = 0xf;

/// `DebugVer` value for ARMv8 debug architecture v8.0 — the baseline every
/// AArch64 core reports, and the floor below which no debug register exists.
pub const DEBUGVER_V8: u8 = 0x6;

/// Extract a 4-bit unsigned `ID_AA64DFR0_EL1` field.
/// # C: O(1)
pub const fn dfr0_field(id: u64, shift: u32) -> u8 { ((id >> shift) & DFR0_FIELD_MASK) as u8 }

/// Implemented breakpoint registers. The register holds count-1, so the
/// decoded value is always in `1..=ARM_MAX_BRP`.
/// # C: O(1)
pub const fn brps(id_aa64dfr0: u64) -> u8 { dfr0_field(id_aa64dfr0, DFR0_BRPS_SHIFT) + 1 }

/// Implemented watchpoint registers. The register holds count-1, so the
/// decoded value is always in `1..=ARM_MAX_WRP`.
/// # C: O(1)
pub const fn wrps(id_aa64dfr0: u64) -> u8 { dfr0_field(id_aa64dfr0, DFR0_WRPS_SHIFT) + 1 }

/// Debug architecture version — the value the debug regsets report in the
/// high half of `dbg_info`.
/// # C: O(1)
pub const fn debug_ver(id_aa64dfr0: u64) -> u8 { dfr0_field(id_aa64dfr0, DFR0_DEBUGVER_SHIFT) }

/// Self-hosted debug is implemented at all.
/// # C: O(1)
pub const fn debug_implemented(id_aa64dfr0: u64) -> bool { debug_ver(id_aa64dfr0) >= DEBUGVER_V8 }

// ---------------------------------------------------------------------------
// `dbg_info` — `user_hwdebug_state.dbg_info`
// ---------------------------------------------------------------------------

/// Slot count occupies the low byte of `dbg_info`.
pub const DBG_INFO_NUM_MASK: u32 = 0xff;
/// Debug architecture version sits one byte up.
pub const DBG_INFO_ARCH_SHIFT: u32 = 8;

/// Pack the debug architecture version and implemented-slot count into the
/// `dbg_info` word a hardware-debug GETREGSET reports.
/// # C: O(1)
pub const fn dbg_info(arch: u8, num_slots: u8) -> u32 {
    ((arch as u32) << DBG_INFO_ARCH_SHIFT) | (num_slots as u32 & DBG_INFO_NUM_MASK)
}

/// Debug architecture version carried by a `dbg_info` word.
/// # C: O(1)
pub const fn dbg_info_arch(info: u32) -> u8 { (info >> DBG_INFO_ARCH_SHIFT) as u8 }

/// Implemented-slot count carried by a `dbg_info` word.
/// # C: O(1)
pub const fn dbg_info_slots(info: u32) -> u8 { (info & DBG_INFO_NUM_MASK) as u8 }

// ---------------------------------------------------------------------------
// Boot-time cache
// ---------------------------------------------------------------------------

/// Cached implemented-breakpoint count; zero until `init_from_id` runs.
static N_BRPS: AtomicU8 = AtomicU8::new(0);
/// Cached implemented-watchpoint count; zero until `init_from_id` runs.
static N_WRPS: AtomicU8 = AtomicU8::new(0);
/// Cached `DebugVer`; zero until `init_from_id` runs.
static DEBUG_VER: AtomicU8 = AtomicU8::new(0);

/// Latch the decoded counts from a raw `ID_AA64DFR0_EL1`. Idempotent — every
/// CPU in a system we support reports the same debug topology, and the
/// architectural ceiling is enforced here so no later index can escape the
/// register files. A core reporting no self-hosted debug latches zero slots.
/// # C: O(1)
pub fn init_from_id(id_aa64dfr0: u64) {
    let (b, w) = if debug_implemented(id_aa64dfr0) {
        (brps(id_aa64dfr0).min(ARM_MAX_BRP as u8), wrps(id_aa64dfr0).min(ARM_MAX_WRP as u8))
    } else {
        (0, 0)
    };
    N_BRPS.store(b, Ordering::Relaxed);
    N_WRPS.store(w, Ordering::Relaxed);
    DEBUG_VER.store(debug_ver(id_aa64dfr0), Ordering::Relaxed);
}

/// Implemented breakpoint slots on this machine; 0 before `init_from_id`.
/// # C: O(1)
pub fn num_brps() -> u8 { N_BRPS.load(Ordering::Relaxed) }

/// Implemented watchpoint slots on this machine; 0 before `init_from_id`.
/// # C: O(1)
pub fn num_wrps() -> u8 { N_WRPS.load(Ordering::Relaxed) }

/// Cached debug architecture version; 0 before `init_from_id`.
/// # C: O(1)
pub fn arch_version() -> u8 { DEBUG_VER.load(Ordering::Relaxed) }

/// `dbg_info` for the instruction-breakpoint regset.
/// # C: O(1)
pub fn break_dbg_info() -> u32 { dbg_info(arch_version(), num_brps()) }

/// `dbg_info` for the data-watchpoint regset.
/// # C: O(1)
pub fn watch_dbg_info() -> u32 { dbg_info(arch_version(), num_wrps()) }

/// Read `ID_AA64DFR0_EL1` and latch the decoded debug topology. Boot calls
/// this once per machine before any task may install a debug slot.
/// # SAFETY: `mrs ID_AA64DFR0_EL1` is an EL1 read of a read-only feature
/// register with no memory effects; caller must be at EL1.
/// # C: O(1)
/// # Ctx: boot
pub unsafe fn init() {
    // SAFETY: delegates to `read_id_aa64dfr0`, whose contract (EL1, read-only
    // feature register, no memory effects) this fn's own contract restates.
    let id = unsafe { read_id_aa64dfr0() };
    init_from_id(id);
}

/// Raw `ID_AA64DFR0_EL1`. Zero off the kernel target so hosted builds link.
/// # SAFETY: `mrs` of a read-only feature register at EL1; no memory effects.
/// # C: O(1)
pub unsafe fn read_id_aa64dfr0() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mrs ID_AA64DFR0_EL1` reads the AArch64 debug-feature
        // identification register — read-only, EL1-accessible, no memory
        // effects. Caller asserts EL1 per `read_id_aa64dfr0`'s contract.
        unsafe {
            core::arch::asm!(
                "mrs {v}, id_aa64dfr0_el1",
                v = out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}
