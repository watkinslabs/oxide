// Memory protection keys for userspace (PKU) — the PKRU register and the
// CR4.PKE enablement that turns it on. Linux `arch/x86/mm/pkeys.c`,
// `arch/x86/include/asm/pkru.h`, `setup_pku()` in `arch/x86/kernel/cpu/common.c`.
//
// PKRU is a per-thread 32-bit register holding two bits per key: AD
// (access-disable) and WD (write-disable), for 16 keys. The hardware consults
// it on every user data access whose PTE carries that key, so it enforces a
// permission NARROWING that the page tables themselves do not express — and it
// is writable from userspace with an unprivileged `WRPKRU`, which is the whole
// point (a thread can revoke and restore its own access without a syscall).
//
// Because userspace can change PKRU behind the kernel's back, the value must be
// re-READ at every switch-out rather than assumed; see [`read_pkru`].
//
// The bit arithmetic and the CPUID decode are ungated so hosted `cargo test`
// reaches them; only the instructions themselves are target-gated.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Access-disable bit, low bit of a key's PKRU field.
pub const PKRU_AD_BIT: u32 = 0x1;
/// Write-disable bit, high bit of a key's PKRU field.
pub const PKRU_WD_BIT: u32 = 0x2;
/// PKRU field width per key.
pub const PKRU_BITS_PER_PKEY: u32 = 2;

/// Keys the hardware implements once OSPKE is active.
pub const MAX_PKEY_OSPKE: u16 = 16;
/// Keys available without OSPKE: key 0 only, the implicit default every PTE
/// carries.
pub const MAX_PKEY_NO_OSPKE: u16 = 1;

/// CR4.PKE — enables PKU and makes `RDPKRU`/`WRPKRU` legal.
pub const CR4_PKE: u64 = 1 << 22;

/// `CPUID.(EAX=7,ECX=0):ECX.PKU` — the CPU implements protection keys.
pub const CPUID7_ECX_PKU: u32 = 1 << 3;
/// `CPUID.(EAX=7,ECX=0):ECX.OSPKE` — the OS has set CR4.PKE. Hardware sets
/// this bit as a consequence, so it reads back the enablement rather than the
/// capability.
pub const CPUID7_ECX_OSPKE: u32 = 1 << 4;

/// The PKRU a thread starts with: every key EXCEPT key 0 access-disabled.
///
/// Deliberately the most restrictive value, so a thread cloned early in a
/// process's life cannot accidentally hold access to data that a later
/// `pkey_alloc` protects. Key 0 must stay open — it is the key every ordinary
/// page carries, so disabling it would fault the thread on its own stack.
pub const INIT_PKRU_VALUE: u32 = init_pkru_value();

/// Build [`INIT_PKRU_VALUE`]: AD set for keys `1..MAX_PKEY_OSPKE`.
const fn init_pkru_value() -> u32 {
    let mut v = 0u32;
    let mut pkey = 1u16;
    while pkey < MAX_PKEY_OSPKE {
        v |= PKRU_AD_BIT << (pkey as u32 * PKRU_BITS_PER_PKEY);
        pkey += 1;
    }
    v
}

/// Latched once on the BSP: this CPU family has PKU and the kernel enabled it.
/// Every later decision reads THIS rather than re-running CPUID, so an AP that
/// somehow lacks the feature cannot silently diverge from the BSP's answer.
static OSPKE: AtomicBool = AtomicBool::new(false);

/// Kernel-wide default PKRU (Linux `init_pkru_value`, writable through its
/// debugfs knob). Held as an atomic so the knob can land without changing any
/// caller.
static INIT_PKRU: AtomicU32 = AtomicU32::new(INIT_PKRU_VALUE);

/// Is PKU enabled on this system? False makes every PKRU access a no-op and
/// caps the key space at key 0. # C: O(1)
pub fn ospke_enabled() -> bool { OSPKE.load(Ordering::Relaxed) }

/// `arch_max_pkey()` — 16 keys with OSPKE, otherwise key 0 alone. # C: O(1)
pub fn arch_max_pkey() -> u16 {
    if ospke_enabled() { MAX_PKEY_OSPKE } else { MAX_PKEY_NO_OSPKE }
}

/// The default PKRU a thread is born with / `execve` resets to. # C: O(1)
pub fn pkru_init_value() -> u32 { INIT_PKRU.load(Ordering::Relaxed) }

/// Install a new kernel-wide default PKRU. Refuses a value that disables
/// access or writes for key 0, which would fault every thread on its own stack
/// the moment it took effect. # C: O(1)
pub fn set_pkru_init_value(v: u32) -> Result<(), ()> {
    if v & (PKRU_AD_BIT | PKRU_WD_BIT) != 0 { return Err(()); }
    INIT_PKRU.store(v, Ordering::Relaxed);
    Ok(())
}

/// Bit position of `pkey`'s two-bit PKRU field. # C: O(1)
pub const fn pkru_shift(pkey: u16) -> u32 { pkey as u32 * PKRU_BITS_PER_PKEY }

/// Both of `pkey`'s bits, positioned. # C: O(1)
pub const fn pkru_mask(pkey: u16) -> u32 { (PKRU_AD_BIT | PKRU_WD_BIT) << pkru_shift(pkey) }

/// `__pkru_allows_read` — reads are denied only by AD. # C: O(1)
pub const fn pkru_allows_read(pkru: u32, pkey: u16) -> bool {
    pkru & (PKRU_AD_BIT << pkru_shift(pkey)) == 0
}

/// `__pkru_allows_write` — a write needs BOTH bits clear, because
/// access-disable implies write-disable. # C: O(1)
pub const fn pkru_allows_write(pkru: u32, pkey: u16) -> bool {
    pkru & pkru_mask(pkey) == 0
}

/// `arch_set_user_pkey_access`'s bit work: replace `pkey`'s field with the
/// rights `pkey_alloc`/`pkey_set` asked for, leaving every other key's field
/// untouched. `disable_access` implies no writes either, which the read/write
/// predicates already encode.
/// # C: O(1)
pub const fn pkru_set_pkey_access(pkru: u32, pkey: u16, disable_access: bool, disable_write: bool) -> u32 {
    let mut bits = 0u32;
    if disable_access { bits |= PKRU_AD_BIT; }
    if disable_write { bits |= PKRU_WD_BIT; }
    (pkru & !pkru_mask(pkey)) | (bits << pkru_shift(pkey))
}

/// Does `ecx` from `CPUID.(EAX=7,ECX=0)` report PKU? # C: O(1)
pub const fn cpuid_has_pku(ecx: u32) -> bool { ecx & CPUID7_ECX_PKU != 0 }

/// Does `ecx` report OSPKE, i.e. did CR4.PKE take? # C: O(1)
pub const fn cpuid_has_ospke(ecx: u32) -> bool { ecx & CPUID7_ECX_OSPKE != 0 }

/// CR4 with PKE set. # C: O(1)
pub const fn cr4_with_pke(cr4: u64) -> u64 { cr4 | CR4_PKE }

/// CR4 with PKE cleared. # C: O(1)
pub const fn cr4_without_pke(cr4: u64) -> u64 { cr4 & !CR4_PKE }

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
mod hw {
    use core::arch::asm;

    /// `RDPKRU`: PKRU into EAX, EDX clobbered, requires ECX = 0.
    /// # SAFETY: caller guarantees CR4.PKE is set, or the instruction #UDs.
    /// # C: O(1)
    pub unsafe fn rdpkru() -> u32 {
        let pkru: u32;
        let _edx: u32;
        // SAFETY: RDPKRU is unprivileged and has no memory effects; the caller's OSPKE gate guarantees CR4.PKE is set so it cannot #UD.
        unsafe {
            asm!("rdpkru", out("eax") pkru, out("edx") _edx, in("ecx") 0u32,
                options(nomem, nostack, preserves_flags));
        }
        pkru
    }

    /// `WRPKRU`: EAX into PKRU, requires ECX = EDX = 0.
    /// # SAFETY: caller guarantees CR4.PKE is set, or the instruction #UDs.
    /// # C: O(1)
    pub unsafe fn wrpkru(pkru: u32) {
        // SAFETY: WRPKRU is unprivileged and has no memory effects; the caller's OSPKE gate guarantees CR4.PKE is set so it cannot #UD.
        unsafe {
            asm!("wrpkru", in("eax") pkru, in("ecx") 0u32, in("edx") 0u32,
                options(nomem, nostack, preserves_flags));
        }
    }
}

/// This thread's live PKRU, or 0 when PKU is off (no key can deny anything, so
/// an all-zero register is the honest answer rather than a fabricated one).
///
/// Must be READ, never assumed: `WRPKRU` is unprivileged, so userspace changes
/// this register without the kernel's knowledge.
/// # C: O(1)
pub fn read_pkru() -> u32 {
    if !ospke_enabled() { return 0; }
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: ospke_enabled() proves CR4.PKE was set on this CPU by setup_pku, so RDPKRU cannot #UD.
    unsafe { return hw::rdpkru(); }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    0
}

/// Load `pkru` into this thread's register. Skips the write when the register
/// already holds the value: `WRPKRU` is a serialising, comparatively expensive
/// instruction and a context switch between two threads with the same rights
/// is the common case.
/// # C: O(1)
pub fn write_pkru(pkru: u32) {
    if !ospke_enabled() { return; }
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: ospke_enabled() proves CR4.PKE was set on this CPU by setup_pku, so RDPKRU/WRPKRU cannot #UD.
    unsafe {
        if pkru != hw::rdpkru() { hw::wrpkru(pkru); }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    let _ = pkru;
}

/// Reset this thread's PKRU to the kernel default. # C: O(1)
pub fn pkru_write_default() { write_pkru(pkru_init_value()); }

/// `setup_pku()` — per-CPU PKU enablement, run from the SAME point on the BSP
/// and on every AP.
///
/// The BSP decides: it reads CPUID for PKU and latches the answer. An AP does
/// NOT re-decide — it either follows the BSP's latch or does nothing, so a
/// heterogeneous package can never leave half the CPUs enforcing keys and half
/// ignoring them. Setting CR4.PKE makes the hardware report OSPKE, which is
/// then the bit every later decision reads.
///
/// # SAFETY: privileged CR4 write, legal at CPL=0; called once per CPU before
/// that CPU runs user code, and CR4 is per-CPU so each CPU is its own writer.
/// # C: O(1)
pub unsafe fn setup_pku(is_bsp: bool) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: per fn-level contract — CR4 write is legal at CPL=0, this CPU is the sole writer of its own CR4, and it runs pre-userspace.
    unsafe {
        if is_bsp {
            // Leaf 7 has to exist before its subleaf 0 means anything.
            let (max_leaf, _, _, _) = crate::cpuid::cpuid(0);
            if max_leaf < 7 { return; }
            let (_, _, ecx7, _) = crate::cpuid::cpuid_count(7, 0);
            if !cpuid_has_pku(ecx7) { return; }
        } else if !ospke_enabled() {
            return;
        }
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 = cr4_with_pke(cr4);
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
        if is_bsp {
            // Confirm the hardware accepted it rather than trusting the write.
            let (_, _, ecx7, _) = crate::cpuid::cpuid_count(7, 0);
            if !cpuid_has_ospke(ecx7) {
                cr4 = cr4_without_pke(cr4);
                core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
                return;
            }
            OSPKE.store(true, Ordering::Relaxed);
            // One line per detected CPU feature, as the kernel reports every
            // other optional facility it turns on. Absence prints nothing, so
            // the line's PRESENCE is the proof CR4.PKE took — the CPUID bit
            // that produced it only reads back after the write landed.
            klog::write_raw(b"[cpu] detected: Memory Protection Keys for Userspace (PKU/OSPKE), ");
            klog::write_dec_u64(MAX_PKEY_OSPKE as u64);
            klog::write_raw(b" keys\n");
        }
        // Every CPU starts at the restrictive default; a task's own value is
        // loaded by the first switch onto it.
        pkru_write_default();
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    let _ = is_bsp;
}

#[cfg(test)]
mod tests;
