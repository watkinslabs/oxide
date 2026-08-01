// Memory protection keys on aarch64 — FEAT_S1POE, the Stage-1 Permission
// Overlay Extension. Linux `arch/arm64/include/asm/por.h`,
// `arch/arm64/include/asm/pkeys.h`, `cpu_enable_poe()`.
//
// The overlay is the same idea as x86's PKRU with a different shape: a page's
// descriptor carries a 3-bit Permission Overlay index, and `POR_EL0` holds a
// 4-bit permission field per index that NARROWS what the descriptor already
// allows. `POR_EL0` is readable and writable from EL0 once `CPACR_EL1.E0POE`
// is set, so a thread revokes and restores its own access without a syscall —
// which is why the kernel must re-READ the register rather than assume its
// last write survived (see the switch path).
//
// Two differences from x86 worth holding on to:
//   * a key's field is a POSITIVE permission set (`POE_RWX` = full access,
//     `POE_NONE` = none), not a set of disable bits;
//   * the overlay can revoke EXECUTE and READ independently, which PKRU
//     cannot express — hence the two extra `PKEY_DISABLE_*` bits that exist
//     only on this arch.
//
// The field arithmetic and the ID-register decode are ungated so hosted
// `cargo test` reaches them; only the system-register access is target-gated.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// `POR_ELx` permission encodings — a positive permission set per key.
pub const POE_NONE: u64 = 0x0;
/// Read.
pub const POE_R: u64 = 0x1;
/// Execute.
pub const POE_X: u64 = 0x2;
/// Read + execute.
pub const POE_RX: u64 = 0x3;
/// Write.
pub const POE_W: u64 = 0x4;
/// Read + write.
pub const POE_RW: u64 = 0x5;
/// Write + execute.
pub const POE_WX: u64 = 0x6;
/// Full access — what key 0 holds, and what a freshly allocated key starts at
/// before `pkey_alloc`'s rights are applied.
pub const POE_RWX: u64 = 0x7;
/// Width of one key's field, and hence its value mask.
pub const POE_MASK: u64 = 0xf;

/// Bits of `POR_ELx` per key index.
pub const POR_BITS_PER_IDX: u32 = 4;

/// Keys the descriptor's 3-bit Permission Overlay index can name. `POR_EL0`
/// has room for 16 fields, but only 8 are reachable from a page table, so 8 is
/// the key space.
pub const MAX_PKEY: u16 = 8;

/// `ID_AA64MMFR3_EL1.S1POE` — bits 19:16.
pub const MMFR3_S1POE_SHIFT: u32 = 16;
/// `ID_AA64MMFR3_EL1.TCRX` — bits 3:0. `TCR2_EL1` only exists with FEAT_TCR2,
/// and `TCR2_EL1.E0POE` is the switch that turns the overlay on, so the
/// overlay is unusable without it however the S1POE field reads.
pub const MMFR3_TCRX_SHIFT: u32 = 0;

/// `TCR2_EL1.E0POE` — apply the Stage-1 permission overlay to EL0 accesses.
pub const TCR2_EL1_E0POE: u64 = 1 << 2;
/// `CPACR_EL1.E0POE` — let EL0 read and write `POR_EL0`. Without it the
/// register traps and userspace cannot change its own rights, which is the
/// feature's whole purpose.
pub const CPACR_EL1_E0POE: u64 = 1 << 29;

/// The `POR_EL0` a thread starts with: key 0 fully open, every other key
/// closed.
///
/// Key 0 is the key every ordinary page carries, so closing it would fault a
/// thread on its own stack. Every other key starts at `POE_NONE` so a thread
/// cloned early in a process cannot hold access to data a later `pkey_alloc`
/// protects.
pub const POR_EL0_INIT: u64 = POE_RWX;

/// Latched once on the BSP: this system has FEAT_S1POE (and the FEAT_TCR2 it
/// needs) and the kernel enabled the overlay. Every later decision reads THIS
/// rather than re-reading the ID registers, so a secondary CPU cannot silently
/// disagree with the BSP.
static POE: AtomicBool = AtomicBool::new(false);

/// Kernel-wide default `POR_EL0`.
static INIT_POR: AtomicU64 = AtomicU64::new(POR_EL0_INIT);

/// Is the permission overlay enabled? # C: O(1)
pub fn poe_enabled() -> bool { POE.load(Ordering::Relaxed) }

/// `arch_max_pkey()` — 8 keys with the overlay, key 0 alone without.
/// # C: O(1)
pub fn arch_max_pkey() -> u16 { if poe_enabled() { MAX_PKEY } else { 1 } }

/// The default a thread is born with / `execve` resets to. # C: O(1)
pub fn por_init_value() -> u64 { INIT_POR.load(Ordering::Relaxed) }

/// Install a new kernel-wide default. Refuses any value that does not leave
/// key 0 fully open, which would fault every thread on its own stack.
/// # C: O(1)
pub fn set_por_init_value(v: u64) -> Result<(), ()> {
    if por_perm(v, 0) != POE_RWX { return Err(()); }
    INIT_POR.store(v, Ordering::Relaxed);
    Ok(())
}

/// Bit position of `pkey`'s field. # C: O(1)
pub const fn por_shift(pkey: u16) -> u32 { pkey as u32 * POR_BITS_PER_IDX }

/// `POR_ELx_PERM_GET` — `pkey`'s permission set. # C: O(1)
pub const fn por_perm(por: u64, pkey: u16) -> u64 { (por >> por_shift(pkey)) & POE_MASK }

/// `POR_ELx_PERM_PREP` — `perm` positioned for `pkey`. # C: O(1)
pub const fn por_perm_prep(pkey: u16, perm: u64) -> u64 { (perm & POE_MASK) << por_shift(pkey) }

/// `por_elx_allows_read`. # C: O(1)
pub const fn por_allows_read(por: u64, pkey: u16) -> bool { por_perm(por, pkey) & POE_R != 0 }
/// `por_elx_allows_write`. # C: O(1)
pub const fn por_allows_write(por: u64, pkey: u16) -> bool { por_perm(por, pkey) & POE_W != 0 }
/// `por_elx_allows_exec`. # C: O(1)
pub const fn por_allows_exec(por: u64, pkey: u16) -> bool { por_perm(por, pkey) & POE_X != 0 }

/// `arch_set_user_pkey_access`'s permission derivation: start from full access
/// and subtract what the caller asked to disable, leaving every other key's
/// field untouched.
///
/// `disable_access` clears READ and WRITE but NOT execute — the two are
/// independent here, so a key can be execute-only. That asymmetry is the
/// reason this arch has `PKEY_DISABLE_READ` and `PKEY_DISABLE_EXECUTE` at all.
/// # C: O(1)
pub const fn por_set_pkey_access(por: u64, pkey: u16, disable_access: bool, disable_write: bool,
    disable_read: bool, disable_execute: bool) -> u64
{
    let mut perm = POE_RWX;
    if disable_write { perm &= !POE_W; }
    if disable_access { perm &= !POE_RW; }
    if disable_read { perm &= !POE_R; }
    if disable_execute { perm &= !POE_X; }
    (por & !(POE_MASK << por_shift(pkey))) | por_perm_prep(pkey, perm)
}

/// Extract a 4-bit ID-register field. # C: O(1)
pub const fn id_field(reg: u64, shift: u32) -> u64 { (reg >> shift) & 0xf }

/// Does `ID_AA64MMFR3_EL1` report the Stage-1 permission overlay AND the
/// `TCR2_EL1` that switches it on? Both are required; reporting S1POE without
/// FEAT_TCR2 leaves no way to enable the overlay. # C: O(1)
pub const fn mmfr3_has_poe(mmfr3: u64) -> bool {
    id_field(mmfr3, MMFR3_S1POE_SHIFT) >= 1 && id_field(mmfr3, MMFR3_TCRX_SHIFT) >= 1
}

/// `TCR2_EL1` with the EL0 overlay enabled. # C: O(1)
pub const fn tcr2_with_e0poe(tcr2: u64) -> u64 { tcr2 | TCR2_EL1_E0POE }
/// `CPACR_EL1` with EL0 access to `POR_EL0` permitted. # C: O(1)
pub const fn cpacr_with_e0poe(cpacr: u64) -> u64 { cpacr | CPACR_EL1_E0POE }

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod hw {
    use core::arch::asm;

    /// `ID_AA64MMFR3_EL1`. Named by encoding: the assembler in the pinned
    /// toolchain does not know the mnemonic. # C: O(1)
    pub fn id_aa64mmfr3_el1() -> u64 {
        let v: u64;
        // SAFETY: `mrs S3_0_C0_C7_3` (ID_AA64MMFR3_EL1) is privileged at EL1 with no memory side-effects. ARM ARM D19.2.
        unsafe { asm!("mrs {v}, S3_0_C0_C7_3", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
        v
    }

    /// `POR_EL0` (`S3_3_C10_C2_4`).
    /// # SAFETY: caller guarantees FEAT_S1POE, or the access is UNDEFINED.
    /// # C: O(1)
    pub unsafe fn read_por_el0() -> u64 {
        let v: u64;
        // SAFETY: `mrs S3_3_C10_C2_4` (POR_EL0) has no memory side-effects; the caller's POE gate proves FEAT_S1POE is implemented so the access is defined.
        unsafe { asm!("mrs {v}, S3_3_C10_C2_4", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
        v
    }

    /// Write `POR_EL0`, with the `isb` the architecture requires before the
    /// new permissions govern a subsequent access.
    /// # SAFETY: caller guarantees FEAT_S1POE, or the access is UNDEFINED.
    /// # C: O(1)
    pub unsafe fn write_por_el0(v: u64) {
        // SAFETY: `msr S3_3_C10_C2_4` (POR_EL0) is a context-synchronising permission change made self-consistent by the following isb; the caller's POE gate proves FEAT_S1POE is implemented.
        unsafe { asm!("msr S3_3_C10_C2_4, {v}", "isb", v = in(reg) v, options(nostack, preserves_flags)); }
    }

    /// Enable the EL0 permission overlay on this CPU: `TCR2_EL1.E0POE` applies
    /// the overlay to EL0 accesses, `CPACR_EL1.E0POE` lets EL0 reach `POR_EL0`
    /// to change its own rights.
    /// # SAFETY: caller guarantees FEAT_S1POE + FEAT_TCR2; both registers are
    /// per-CPU and this runs once per CPU before it executes user code.
    /// # C: O(1)
    pub unsafe fn enable_overlay() {
        // SAFETY: per fn contract — privileged per-CPU RMW of TCR2_EL1/CPACR_EL1 at EL1, run once pre-userspace, with an isb so the change is in effect before any EL0 access.
        unsafe {
            asm!(
                "mrs {r}, S3_0_C2_C0_3",
                "orr {r}, {r}, {e0poe}",
                "msr S3_0_C2_C0_3, {r}",
                "mrs {r}, cpacr_el1",
                "orr {r}, {r}, {cp}",
                "msr cpacr_el1, {r}",
                "isb",
                r = out(reg) _,
                e0poe = in(reg) super::TCR2_EL1_E0POE,
                cp = in(reg) super::CPACR_EL1_E0POE,
                options(nostack, preserves_flags),
            );
        }
    }
}

/// `ID_AA64MMFR3_EL1`, or 0 where the register cannot be read. # C: O(1)
pub fn id_aa64mmfr3_el1() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { hw::id_aa64mmfr3_el1() }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// This thread's live `POR_EL0`, or 0 when the overlay is off. Must be READ,
/// never assumed: EL0 writes this register itself. # C: O(1)
pub fn read_por() -> u64 {
    if !poe_enabled() { return 0; }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    // SAFETY: poe_enabled() proves the BSP found FEAT_S1POE, so POR_EL0 is implemented.
    unsafe { return hw::read_por_el0(); }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    0
}

/// Load `por` into this thread's register, skipping a write that would change
/// nothing — the write carries an `isb`, which a context switch between two
/// threads holding the same rights should not pay. # C: O(1)
pub fn write_por(por: u64) {
    if !poe_enabled() { return; }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    // SAFETY: poe_enabled() proves the BSP found FEAT_S1POE, so POR_EL0 is implemented.
    unsafe {
        if por != hw::read_por_el0() { hw::write_por_el0(por); }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    let _ = por;
}

/// Reset this thread's rights to the kernel default. # C: O(1)
pub fn por_write_default() { write_por(por_init_value()); }

/// Per-CPU permission-overlay enablement, run from the SAME point on the BSP
/// and on every secondary CPU.
///
/// The BSP decides from the ID registers and latches the answer; a secondary
/// CPU follows that latch rather than re-deciding, so a big.LITTLE package
/// cannot end up with some CPUs applying the overlay and others ignoring it —
/// which would make a key's protection depend on which core a thread happened
/// to be running on.
///
/// # SAFETY: privileged per-CPU system-register writes, legal at EL1; called
/// once per CPU before that CPU runs user code.
/// # C: O(1)
pub unsafe fn setup_poe(is_bsp: bool) {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    // SAFETY: per fn-level contract — this CPU's own single pre-userspace enablement of its own per-CPU registers.
    unsafe {
        if is_bsp {
            if !mmfr3_has_poe(hw::id_aa64mmfr3_el1()) { return; }
        } else if !poe_enabled() {
            return;
        }
        hw::enable_overlay();
        if is_bsp {
            POE.store(true, Ordering::Relaxed);
            // Same reporting rule as the x86 side: the line appears only when
            // the overlay was actually enabled, so its presence is the proof
            // that TCR2_EL1.E0POE took on a CPU that implements FEAT_S1POE.
            klog::write_raw(b"[cpu] detected: Stage-1 Permission Overlay Extension (S1POE), ");
            klog::write_dec_u64(MAX_PKEY as u64);
            klog::write_raw(b" keys\n");
        }
        // Every CPU starts at the restrictive default; a task's own value is
        // loaded by the first switch onto it.
        por_write_default();
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    let _ = is_bsp;
}

#[cfg(test)]
mod tests;
