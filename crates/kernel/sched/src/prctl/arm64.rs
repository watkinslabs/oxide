// The arm64-only `prctl` options: the tagged-address ABI, SVE/SME vector
// lengths, and pointer authentication.
//
// Each answers EINVAL on a CPU (or kernel) without the feature and does real
// work otherwise, so every arm here is gated on a CPU FEATURE READ rather than
// on a compile-time assumption — a fixed EINVAL would be wrong the moment this
// kernel ran on hardware that has the feature. On x86_64 the whole group is
// EINVAL: the generic `prctl` switch calls per-arch macros that no
// non-arm64 target defines.
//
// Support is the CONJUNCTION of two things, and both are checked:
//   * the CPU implements it — read from the `ID_AA64*_EL1` registers;
//   * this kernel manages the per-task state it implies.
// Reporting success on the first alone would be the worst possible answer:
// `PR_SVE_SET_VL` returning a vector length while the context switch saves
// only the FPSIMD registers means userspace's `Z`/`P` state is silently
// destroyed by the next preemption. Where the second conjunct is false the
// constant below says so by name, and flipping it is the single edit that
// turns the option on once the state management exists.

use syscall::errno::Errno;

use super::uapi::*;
use crate::task::Task;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[path = "arm64/cpu_real.rs"] mod cpu;
#[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
#[path = "arm64/cpu_none.rs"] mod cpu;

pub use cpu::Features;

/// Whether this kernel saves and restores SVE `Z`/`P`/`FFR` state across a
/// context switch. The aarch64 FPU area is FPSIMD-only (`ArchFpuBuf` holds
/// the 32 `q` registers plus `FPSR`/`FPCR`), so it does not — which is the
/// same position as a Linux built without its SVE support, where `PR_SVE_*`
/// is the `(-EINVAL)` macro. Advertising a vector length this kernel cannot
/// preserve would corrupt every SVE-using thread at its first preemption.
pub const KERNEL_MANAGES_SVE_STATE: bool = false;

/// Whether this kernel saves and restores SME `ZA`/`ZT0` state and the
/// streaming-mode `SVCR`. Same reasoning and same FPSIMD-only save area.
pub const KERNEL_MANAGES_SME_STATE: bool = false;

/// Whether this kernel owns per-task pointer-authentication keys — the five
/// `AP*Key_EL1` register pairs installed on context switch — and the
/// `SCTLR_EL1.En{IA,IB,DA,DB}` enables that go with them. It does not, so the
/// PAC options answer EINVAL as they do on a Linux without pointer-auth
/// support. Enabling the `SCTLR_EL1` bits without per-task keys would make
/// every task authenticate against one shared key, which is strictly worse
/// than no authentication at all.
pub const KERNEL_MANAGES_PAC_KEYS: bool = false;

fn err<T>(e: Errno) -> Result<T, Errno> { Err(e) }

/// `sve_get_current_vl()` / `sve_set_current_vl(arg)` availability, and the
/// SME pair. Both are `!system_supports_X() -> -EINVAL` before any argument
/// is looked at, so the availability test comes first here too.
/// # C: O(1)
pub fn sve_available(f: Features) -> bool { f.sve && KERNEL_MANAGES_SVE_STATE }

/// # C: O(1)
pub fn sme_available(f: Features) -> bool { f.sme && KERNEL_MANAGES_SME_STATE }

/// `system_supports_address_auth()` && this kernel owns the keys. # C: O(1)
pub fn address_auth_available(f: Features) -> bool { f.address_auth && KERNEL_MANAGES_PAC_KEYS }

/// `system_supports_generic_auth()` && this kernel owns the keys. # C: O(1)
pub fn generic_auth_available(f: Features) -> bool { f.generic_auth && KERNEL_MANAGES_PAC_KEYS }

/// `ptrauth_prctl_reset_keys(tsk, arg)` argument rules, minus the key
/// regeneration itself.
///
/// Order matters and is Linux's: availability first (so a CPU without
/// pointer auth answers EINVAL for `arg == 0` too, rather than "reset
/// nothing, success"), then the all-zero "reset every key" form, then the
/// undefined-bit test, then the per-algorithm test that refuses an address
/// key on a generic-auth-only CPU.
/// # C: O(1)
pub fn pac_reset_keys_check(f: Features, arg: u64) -> Result<(), Errno> {
    if !address_auth_available(f) && !generic_auth_available(f) { return err(Errno::Einval); }
    if arg == 0 { return Ok(()); }
    let key_mask = PR_PAC_ENABLED_KEYS_MASK | PR_PAC_APGAKEY;
    if arg & !key_mask != 0 { return err(Errno::Einval); }
    if (arg & PR_PAC_ENABLED_KEYS_MASK != 0) && !address_auth_available(f) {
        return err(Errno::Einval);
    }
    if (arg & PR_PAC_APGAKEY != 0) && !generic_auth_available(f) { return err(Errno::Einval); }
    Ok(())
}

/// `ptrauth_set_enabled_keys(tsk, keys, enabled)` argument rules.
///
/// `enabled & ~keys` is rejected: the call names the keys it is CHANGING in
/// `keys` and their new state in `enabled`, so enabling a key the caller did
/// not name is a malformed request, not a wider one.
/// # C: O(1)
pub fn pac_set_enabled_keys_check(f: Features, keys: u64, enabled: u64) -> Result<(), Errno> {
    if !address_auth_available(f) { return err(Errno::Einval); }
    if keys & !PR_PAC_ENABLED_KEYS_MASK != 0 || enabled & !keys != 0 { return err(Errno::Einval); }
    Ok(())
}

/// Whether the tagged-address ABI exists on this target at all.
///
/// arm64 only. It is not an optional CPU FEATURE there — the top-byte-ignore
/// behaviour comes from `TCR_EL1.TBI0`, which this kernel programs at boot for
/// every core, so even an ARMv8.0 part has it. x86_64 has no equivalent
/// translation-regime control, which is why Linux leaves the option on the
/// generic `(-EINVAL)` macro on that arch.
pub const TAGGED_ADDR_ABI: bool = cfg!(target_arch = "aarch64");

/// `set_tagged_addr_ctrl(task, arg)` — the mask of bits this system accepts,
/// or `None` where the ABI does not exist.
///
/// The `PR_MTE_*` bits ride the same argument word and are admitted only on a
/// CPU with memory tagging, so a caller cannot ask for a tag-check mode the
/// hardware cannot perform.
/// # C: O(1)
pub fn tagged_addr_valid_mask(f: Features) -> Option<u64> {
    if !TAGGED_ADDR_ABI { return None; }
    let mut mask = PR_TAGGED_ADDR_ENABLE;
    if f.mte { mask |= PR_MTE_TCF_SYNC | PR_MTE_TCF_ASYNC | PR_MTE_TAG_MASK; }
    Some(mask)
}

/// `set_tagged_addr_ctrl` argument check, returning the flag to install.
/// # C: O(1)
pub fn tagged_addr_set_check(f: Features, arg: u64) -> Result<bool, Errno> {
    let Some(mask) = tagged_addr_valid_mask(f) else { return err(Errno::Einval) };
    if arg & !mask != 0 { return err(Errno::Einval); }
    Ok(arg & PR_TAGGED_ADDR_ENABLE != 0)
}

/// `get_tagged_addr_ctrl(task)` availability — EINVAL off arm64, where Linux
/// never reaches a real implementation. # C: O(1)
pub fn tagged_addr_get(enabled: bool) -> Result<i64, Errno> {
    if !TAGGED_ADDR_ABI { return err(Errno::Einval); }
    Ok(tagged_addr_report(enabled))
}

/// `get_tagged_addr_ctrl(task)` — the flag plus this task's MTE control
/// bits. With no MTE the second term is zero, exactly as `get_mte_ctrl`
/// returns 0 on a CPU without tagging.
/// # C: O(1)
pub fn tagged_addr_report(enabled: bool) -> i64 {
    if enabled { PR_TAGGED_ADDR_ENABLE as i64 } else { 0 }
}

/// `untagged_addr(addr)` — Linux `sign_extend64(addr, 55)` used as a mask, so
/// bits 63:56 are forced to copies of bit 55.
///
/// A user address has bit 55 clear, so this clears the top byte; a kernel
/// address has it set, so this leaves the address alone rather than turning it
/// into a different kernel address. Applying a blanket `& 0x00ff_ffff_...`
/// instead would silently rewrite kernel pointers.
/// # C: O(1)
pub fn untagged_addr(addr: u64) -> u64 {
    addr & (((addr as i64) << 8 >> 8) as u64)
}

/// The address `access_ok` should range-check for `cur`.
///
/// Linux untags in `access_ok` when the task opted into the tagged-address ABI
/// (or is a kernel thread borrowing the mm, which has no thread flag of its
/// own). Untagging unconditionally would let a task that never opted in pass a
/// pointer with garbage in the top byte and have the kernel quietly accept it.
/// # C: O(1)
pub fn user_ptr_for_check(cur: Option<&Task>, addr: u64) -> u64 {
    match cur {
        Some(t) if t.tagged_addr.load(core::sync::atomic::Ordering::Acquire) => untagged_addr(addr),
        // No current task = a kernel context acting on a borrowed mm, Linux's
        // `current->flags & PF_KTHREAD` arm: always untag, because the thread
        // flag belongs to the process that owns the mm, not to this thread.
        None => untagged_addr(addr),
        Some(_) => addr,
    }
}

/// Read this CPU's optional-feature set. # C: O(1)
pub fn features() -> Features { cpu::features() }

// The `access_ok` range check sits BELOW the scheduler and upcalls into this
// flag; the symbol only exists on the target that has the ABI.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[path = "arm64/upcall.rs"] mod upcall;

#[cfg(test)]
#[path = "arm64/tests.rs"]
mod tests;
