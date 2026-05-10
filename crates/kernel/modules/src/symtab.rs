// Kernel symbol table per `18§7`. Built-in `EXPORT_SYMBOL` /
// `EXPORT_SYMBOL_GPL` entries register here at boot; loaded modules
// append their own exports via the same `export` call. Symbol
// resolution during relocation walks this table; GPL-only symbols
// gate non-GPL modules with `Eacces` per `18§2` invariant 5.
//
// Out of scope: built-in linker-generated `__ksymtab` table walking
// (linker section emulated by an explicit `register_builtin` call
// here), CRC checking (`18§4`), per-module export removal on unload
// (lands with the unload flow).

extern crate alloc;
use alloc::collections::BTreeMap;

use sync::{Modules as ModulesClass, Spinlock};

/// Lookup error type. Numeric reps Linux-aligned.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SymError {
    Enoent = 2,   // unresolved symbol
    Eacces = 13,  // GPL-only symbol used by non-GPL module
}

pub type KResult<T> = core::result::Result<T, SymError>;

/// One exported symbol. `addr` is opaque — relocation writes
/// `addr.cast::<u8>().wrapping_add(addend)` into the target slot.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KsymEntry {
    pub addr:     usize,
    pub gpl_only: bool,
    /// Identity of the providing module; `None` for built-ins.
    pub module:   Option<&'static str>,
}

/// True iff `license` is GPL-compatible per `MODULE_LICENSE()`. Linux
/// recognizes "GPL", "GPL v2", "GPL and additional rights",
/// "Dual BSD/GPL", "Dual MIT/GPL", "Dual MPL/GPL" — those are the
/// strings allowed to consume `EXPORT_SYMBOL_GPL`.
/// # C: O(1)
pub fn license_is_gpl(license: &str) -> bool {
    matches!(license,
        "GPL"
        | "GPL v2"
        | "GPL and additional rights"
        | "Dual BSD/GPL"
        | "Dual MIT/GPL"
        | "Dual MPL/GPL")
}

static SYMTAB: Spinlock<BTreeMap<&'static str, KsymEntry>, ModulesClass>
    = Spinlock::new(BTreeMap::new());

/// Register an in-kernel symbol. Idempotent on identical
/// `(addr, gpl_only, module)` tuples; conflicting re-registration
/// updates the slot (last writer wins) and returns the prior entry.
/// # C: O(log N)
pub fn export(name: &'static str, addr: usize, gpl_only: bool) -> Option<KsymEntry> {
    let entry = KsymEntry { addr, gpl_only, module: None };
    let mut g = SYMTAB.lock();
    g.insert(name, entry)
}

/// Register a per-module export. Same shape as `export` but stamps
/// the providing module name; `unexport_module` walks `module ==
/// Some(name)` to drop everything on unload.
/// # C: O(log N)
pub fn export_module(
    name: &'static str,
    addr: usize,
    gpl_only: bool,
    module: &'static str,
) -> Option<KsymEntry> {
    let entry = KsymEntry { addr, gpl_only, module: Some(module) };
    let mut g = SYMTAB.lock();
    g.insert(name, entry)
}

/// Drop every export whose `module` matches `name`. Returns the
/// number of entries removed.
/// # C: O(N)
pub fn unexport_module(name: &str) -> usize {
    let mut g = SYMTAB.lock();
    let keys: alloc::vec::Vec<&'static str> = g.iter()
        .filter_map(|(k, v)| match v.module {
            Some(m) if m == name => Some(*k),
            _ => None,
        })
        .collect();
    let n = keys.len();
    for k in keys { g.remove(k); }
    n
}

/// Resolve `name` per `18§2` invariants 3 and 5. `module_is_gpl` is
/// the result of `license_is_gpl(module.license)` for the consuming
/// module — pass `true` for built-in callers (the kernel itself is
/// GPL-compatible by construction).
/// # C: O(log N)
pub fn resolve(name: &str, module_is_gpl: bool) -> KResult<KsymEntry> {
    let g = SYMTAB.lock();
    let entry = *g.get(name).ok_or(SymError::Enoent)?;
    if entry.gpl_only && !module_is_gpl {
        return Err(SymError::Eacces);
    }
    Ok(entry)
}

/// True iff `name` is a registered symbol (no GPL gating applied).
/// # C: O(log N)
pub fn is_exported(name: &str) -> bool {
    SYMTAB.lock().contains_key(name)
}

/// Snapshot of `(name, entry)` pairs for `/proc/kallsyms`-style
/// readers. Hosted-only signature; the kernel walks via dedicated
/// readers that don't allocate.
/// # C: O(N)
pub fn snapshot() -> alloc::vec::Vec<(&'static str, KsymEntry)> {
    SYMTAB.lock().iter().map(|(k, v)| (*k, *v)).collect()
}

/// Number of registered symbols.
/// # C: O(1)
pub fn count() -> usize { SYMTAB.lock().len() }

/// Test-only: drop every entry. Lets each test start from a known
/// empty state without coordinating with siblings.
/// # C: O(N)
#[cfg(any(test, feature = "hosted"))]
pub fn _reset() { SYMTAB.lock().clear(); }
