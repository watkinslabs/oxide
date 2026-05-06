// Kernel modules surface — wraps `modules::loader` with a global
// registry + a resolver backed by `modules::symtab`. NR_INIT_MODULE
// / NR_FINIT_MODULE / NR_DELETE_MODULE dispatch into this.
//
// v1: no signature verification; no per-module W^X (the loader's
// section bytes live in the heap, so they're RW; future P10-05+
// work allocates with `mmap(EXEC)`).

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;

use modules::{load_module, LoadedModule, SymResolver};
use sync::{Spinlock, Modules as ModulesLockClass};

/// Kernel-wide resolver: forward to `modules::symtab::resolve`
/// (the EXPORT_SYMBOL surface).
struct KernelSymResolver;
impl SymResolver for KernelSymResolver {
    fn resolve(&self, name: &str) -> Option<u64> {
        modules::symtab::resolve(name, false).ok().map(|e| e.addr as u64)
    }
}

/// Process-global registry. Each `LoadedModule` is held by an
/// `Arc` so look-up + concurrent unload are tractable; v1 only
/// pushes (no remove yet).
static REGISTRY: Spinlock<Vec<Arc<LoadedModule>>, ModulesLockClass>
    = Spinlock::new(Vec::new());

/// Load + register a module from raw ELF ET_REL bytes.
/// Returns the new module's index in the registry, or
/// `None` on parse / reloc / undefined-symbol failure.
/// # C: O(N_sections + N_relocs)
pub fn load_blob(bytes: &[u8]) -> Option<usize> {
    let r = KernelSymResolver;
    match load_module(bytes, &r) {
        Ok(m) => {
            let mut g = REGISTRY.lock();
            g.push(Arc::new(m));
            Some(g.len() - 1)
        }
        Err(_) => None,
    }
}

/// Snapshot the registry (id, section_count, named_symbol_count)
/// for `/proc/modules`-style introspection. v1 stores no name on
/// the module; the name comes from the .modinfo section once we
/// parse it.
/// # C: O(N modules)
pub fn snapshot() -> Vec<(usize, usize, usize)> {
    REGISTRY.lock().iter().enumerate()
        .map(|(i, m)| (i, m.sections.len(), m.symbols.len()))
        .collect()
}

/// Number of currently-loaded modules.
/// # C: O(1)
pub fn count() -> usize { REGISTRY.lock().len() }

/// Module name for the boot trace. Currently fixed; real impl
/// reads .modinfo "name=…".
#[allow(dead_code)]
pub fn module_name(_idx: usize) -> Option<String> { Some(String::from("module")) }
