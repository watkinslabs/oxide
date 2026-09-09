// Current-task adapter for vDSO image publication and signal-restorer lookup.
#![cfg(target_os = "oxide-kernel")]

#[cfg(target_arch = "x86_64")]
pub const VDSO_BLOB: &[u8] = include_bytes!("../vdso/vdso-x86_64.so");
#[cfg(target_arch = "aarch64")]
pub const VDSO_BLOB: &[u8] = include_bytes!("../vdso/vdso-aarch64.so");

#[cfg(target_arch = "x86_64")]
const MACHINE: u16 = elf::EM_X86_64;
#[cfg(target_arch = "aarch64")]
const MACHINE: u16 = elf::EM_AARCH64;

/// Resolve the signal restorer within the mapped image. # C: O(N_dynsym)
#[cfg(target_arch = "aarch64")]
pub fn rt_sigreturn_addr(base: u64) -> Option<u64> {
    base.checked_add(crate::vdso_elf::dynsym_vaddr(VDSO_BLOB, crate::vdso_elf::VDSO_SIGRETURN_SYMBOL)?)
}

/// Publish the current task's vDSO and return its ELF header address. # C: O(N_vmas)
pub fn map_into_current() -> Option<u64> {
    let cur = sched::live::current()?;
    let mm = cur.clone_mm()?;
    elf_load::vdso::map_into(&mm, VDSO_BLOB, MACHINE, crate::vvar::pa())
}
