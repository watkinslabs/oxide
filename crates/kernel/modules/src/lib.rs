// Loadable kernel modules (signed) per docs/18.
//
// `symtab.rs` lands the kernel symbol table per `18§7`:
// `EXPORT_SYMBOL` / `EXPORT_SYMBOL_GPL` registration, name-based
// resolution with GPL gating, per-module export bookkeeping for the
// unload path. `module_mem.rs` owns loader section backing and final
// W^X permissions.
//
// Out of scope (follow-ups): signature verification; async drain; CRC
// of built-in symtab; `__ksymtab` linker section walking.

#![no_std]
#![feature(c_variadic)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod symtab;
pub use symtab::{
    export, export_module, is_exported, license_is_gpl, resolve, unexport_module,
    KResult as SymKResult, KsymEntry, SymError,
};

pub mod relocator;
pub use relocator::{
    apply as apply_reloc, apply_for_machine as apply_reloc_for_machine, apply_dynamic, RelocError,
    R_X86_64_NONE, R_X86_64_64, R_X86_64_PC32, R_X86_64_PLT32,
    R_X86_64_32, R_X86_64_32S, R_X86_64_GOTPCREL, R_X86_64_REX_GOTPCRELX,
    R_X86_64_COPY, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE,
    R_AARCH64_NONE, R_AARCH64_ABS64, R_AARCH64_ABS32, R_AARCH64_ABS16,
    R_AARCH64_PREL64, R_AARCH64_PREL32, R_AARCH64_PREL16,
    R_AARCH64_MOVW_UABS_G0, R_AARCH64_MOVW_UABS_G0_NC,
    R_AARCH64_MOVW_UABS_G1, R_AARCH64_MOVW_UABS_G1_NC,
    R_AARCH64_MOVW_UABS_G2, R_AARCH64_MOVW_UABS_G2_NC, R_AARCH64_MOVW_UABS_G3,
    R_AARCH64_LD_PREL_LO19, R_AARCH64_ADR_PREL_LO21, R_AARCH64_ADR_PREL_PG_HI21,
    R_AARCH64_ADR_PREL_PG_HI21_NC,
    R_AARCH64_ADD_ABS_LO12_NC, R_AARCH64_LDST8_ABS_LO12_NC, R_AARCH64_TSTBR14,
    R_AARCH64_CONDBR19, R_AARCH64_JUMP26, R_AARCH64_CALL26,
    R_AARCH64_LDST16_ABS_LO12_NC, R_AARCH64_LDST32_ABS_LO12_NC,
    R_AARCH64_LDST64_ABS_LO12_NC, R_AARCH64_MOVW_PREL_G0, R_AARCH64_MOVW_PREL_G0_NC,
    R_AARCH64_MOVW_PREL_G1, R_AARCH64_MOVW_PREL_G1_NC, R_AARCH64_MOVW_PREL_G2,
    R_AARCH64_MOVW_PREL_G2_NC, R_AARCH64_MOVW_PREL_G3, R_AARCH64_LDST128_ABS_LO12_NC,
};

pub mod modinfo;
pub use modinfo::{KERNEL_VERMAGIC, ModuleInfo, ModuleParam};

pub mod linux_alloc;
pub mod linux_block;
pub mod linux_chrdev;
pub mod linux_device;
pub mod linux_dma;
mod linux_dma_sgl;
#[cfg(test)]
mod linux_dma_tests;
pub mod linux_io;
pub mod linux_irq;
pub mod linux_firmware;
pub mod linux_input;
pub mod linux_module;
pub mod linux_crypto;
pub mod linux_configfs;
pub mod linux_debugfs;
pub mod linux_debugfs_automount;
pub mod linux_debugfs_extra;
pub mod linux_debugfs_file;
pub mod linux_netdev;
pub mod linux_pci;
pub mod linux_platform;
pub mod linux_pm;
pub mod linux_runtime;
pub mod linux_seq_file;
pub mod linux_scsi;
pub mod linux_string;
pub mod linux_sync;
pub mod linux_time;
pub mod linux_usercopy;
pub mod linux_usb;

pub mod loader;
pub use loader::{load_module, LoadedModule, LoadError, PlacedSection, SymResolver};
pub mod module_mem;

/// Encode a Linux-compatible negative errno for module ABI entry points.
pub(crate) const fn linux_errno(errno: syscall::errno::Errno) -> i32 {
    -errno.as_i32()
}

#[cfg(test)]
mod tests;

/// Subsystem-level error per `38`. Kept for the existing skeleton
/// `init` shim; the canonical symtab error is `SymError`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
}

#[allow(dead_code)]
pub(crate) type StubResult<T> = core::result::Result<T, Error>;

/// Initialization entry; called by the kernel boot phase per `00§3` /
/// `boot-flow.md`.
///
/// # SAFETY: caller is the boot path, runs single-CPU with IRQs off
/// per `boot-flow.md`. Subsystem-specific preconditions documented at
/// the implementation site.
///
/// # C: O(1) once at boot
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> StubResult<()> {
    #[cfg(target_os = "oxide-kernel")]
    {
        // SAFETY: caller is the boot path before module loading is visible.
        unsafe { registry::init_exports() };
    }
    Ok(())
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn init_succeeds() {
        // SAFETY: hosted-test entry; nothing else has touched the subsystem; init's preconditions trivially hold.
        let r = unsafe { init() };
        assert_eq!(r, Ok(()));
    }
}


pub mod registry;
