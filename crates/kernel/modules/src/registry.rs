// Kernel modules surface — wraps `crate::loader` with a global
// registry + a resolver backed by `crate::symtab`. NR_INIT_MODULE
// / NR_FINIT_MODULE / NR_DELETE_MODULE dispatch into this.
//
// v1: no signature verification; no per-module W^X (the loader's
// section bytes live in the heap, so they're RW; future P10-05+
// work allocates with `mmap(EXEC)`).



use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::{load_module, LoadedModule, SymResolver};
use sync::{Spinlock, Modules as ModulesLockClass};

/// Kernel-wide resolver: forward to `crate::symtab::resolve`
/// (the EXPORT_SYMBOL surface).
struct KernelSymResolver;
impl SymResolver for KernelSymResolver {
    fn resolve(&self, name: &str) -> Option<u64> {
        crate::symtab::resolve(name, false).ok().map(|e| e.addr as u64)
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

/// Unload module at registry slot `idx`. Replaces the entry
/// with `None`-equivalent (we use a tombstone Arc clone of an
/// empty marker since the registry is Vec<Arc<…>>; v1 takes a
/// simpler path: drain, drop, rebuild). Returns `false` if the
/// idx is out of range. Real Linux delete_module checks ref
/// count before unloading; v1 always unloads.
/// # C: O(N)
pub fn unload(idx: usize) -> bool {
    let mut g = REGISTRY.lock();
    if idx >= g.len() { return false; }
    g.remove(idx);
    true
}

/// Module name for the boot trace. Currently fixed; real impl
/// reads .modinfo "name=…".
#[allow(dead_code)]
/// # C: O(1)
pub fn module_name(_idx: usize) -> Option<String> { Some(String::from("module")) }

/// Register the kernel's canonical exported symbols so modules
/// can resolve common helpers without hand-rolled stubs. Called
/// once at boot.
/// # SAFETY: caller is the boot path; no other CPU has yet seen
/// the symtab entries.
/// # C: O(1)
pub unsafe fn init_exports() {
    use crate::symtab::export;
    export("klog_write_raw",     klog_write_raw_thunk     as usize, false);
    export("klog_write_dec_u64", klog_write_dec_u64_thunk as usize, false);
    export("kassert_thunk",      kassert_thunk            as usize, false);
}

extern "C" fn klog_write_raw_thunk(p: *const u8, len: usize) {
    if p.is_null() { return; }
    #[cfg(feature = "debug-modules")] {
        // SAFETY: caller is a kernel module passing a valid kernel-static slice; len bounded by caller.
        let s = unsafe { core::slice::from_raw_parts(p, len) };
        klog::write_raw(s);
    }
    #[cfg(not(feature = "debug-modules"))] { let _ = (p, len); }
}

extern "C" fn klog_write_dec_u64_thunk(_v: u64) {
    #[cfg(feature = "debug-modules")] {
        klog::write_dec_u64(_v);
    }
}

extern "C" fn kassert_thunk(cond: u64, msg_p: *const u8, msg_len: usize) {
    if cond != 0 { return; }
    #[cfg(feature = "debug-modules")] {
        klog::write_raw(b"[ASSERT] ");
        if !msg_p.is_null() {
            // SAFETY: caller is a kernel module passing a valid kernel-static slice; len bounded by caller.
            let s = unsafe { core::slice::from_raw_parts(msg_p, msg_len) };
            klog::write_raw(s);
        }
        klog::write_raw(b"\n");
    }
    #[cfg(not(feature = "debug-modules"))] { let _ = (msg_p, msg_len); }
}
