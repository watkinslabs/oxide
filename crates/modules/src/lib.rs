// Loadable kernel modules (signed) per docs/18.
//
// `symtab.rs` lands the kernel symbol table per `18§7`:
// `EXPORT_SYMBOL` / `EXPORT_SYMBOL_GPL` registration, name-based
// resolution with GPL gating, per-module export bookkeeping for the
// unload path.
//
// Out of scope (follow-ups): full `finit_module` / `delete_module`
// flow (`18§5`/`§6`) — needs ELF relocation + page mapping + signature
// verification; per-module W^X memory; refcount + unload safety;
// CRC of built-in symtab; `__ksymtab` linker section walking.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod symtab;
pub use symtab::{
    export, export_module, is_exported, license_is_gpl, resolve, unexport_module,
    KResult as SymKResult, KsymEntry, SymError,
};

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
/// `boot-flow.md`. v1 returns `NotImplemented`; bodies in P1-N.
///
/// # SAFETY: caller is the boot path, runs single-CPU with IRQs off
/// per `boot-flow.md`. Subsystem-specific preconditions documented at
/// the implementation site.
///
/// # C: O(N_pfn) once at boot
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> StubResult<()> {
    klog::kinfo!("modules: init stub");
    Err(Error::NotImplemented)
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn init_returns_not_implemented() {
        // SAFETY: hosted-test entry; nothing else has touched the subsystem; init's preconditions trivially hold.
        let r = unsafe { init() };
        assert_eq!(r, Err(Error::NotImplemented));
    }
}
