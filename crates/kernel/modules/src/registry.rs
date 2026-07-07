// Kernel modules registry: load, name, snapshot, unload lifecycle state.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{load_module, LoadedModule, ModuleInfo, ModuleParam, SymResolver};
use sync::{Spinlock, Modules as ModulesLockClass};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ModuleState {
    Coming,
    Live,
    Going,
}

impl ModuleState {
    /// # C: O(1)
    pub fn as_str(self) -> &'static str {
        match self {
            ModuleState::Coming => "Loading",
            ModuleState::Live   => "Live",
            ModuleState::Going  => "Unloading",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleSnapshot {
    pub name:     String,
    pub license:  Option<String>,
    pub vermagic: Option<String>,
    pub params:   Vec<ModuleParam>,
    pub size:     usize,
    pub refcnt:   usize,
    pub state:    ModuleState,
    pub sections: usize,
    pub symbols:  usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    Inval,
    Exists,
    Load,
    Vermagic,
    Busy,
    Noent,
}

struct KernelSymResolver {
    module_is_gpl: bool,
}
impl SymResolver for KernelSymResolver {
    fn resolve(&self, name: &str) -> Option<u64> {
        crate::symtab::resolve(name, self.module_is_gpl).ok().map(|e| e.addr as u64)
    }
}

struct ModuleRecord {
    name:   String,
    module: LoadedModule,
    refcnt: usize,
    state:  ModuleState,
}

static REGISTRY: Spinlock<Vec<Option<ModuleRecord>>, ModulesLockClass>
    = Spinlock::new(Vec::new());
static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// Load + register a module from raw ELF ET_REL bytes.
/// # C: O(N_sections + N_relocs)
pub fn load_blob(bytes: &[u8]) -> Option<usize> {
    load_blob_named(bytes, None).ok()
}

/// Load + register a module with an optional caller-supplied name.
/// # C: O(N_sections + N_relocs + N_modules)
pub fn load_blob_named(bytes: &[u8], name: Option<&str>) -> Result<usize, RegistryError> {
    let info = ModuleInfo::parse_elf(bytes).ok_or(RegistryError::Load)?;
    if !info.vermagic_matches() { return Err(RegistryError::Vermagic); }
    let r = KernelSymResolver { module_is_gpl: info.is_gpl_compatible() };
    let m = load_module(bytes, &r).map_err(|_| RegistryError::Load)?;
    let final_name = match name {
        Some(n) => { validate_name(n)?; String::from(n) }
        None if m.info.name.as_deref().is_some() => {
            let n = m.info.name.as_deref().unwrap();
            validate_name(n)?;
            String::from(n)
        }
        None => synthetic_name(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
    };
    let mut g = REGISTRY.lock();
    if g.iter().any(|slot| slot.as_ref().is_some_and(|r| r.name == final_name)) {
        return Err(RegistryError::Exists);
    }
    let idx = g.len();
    g.push(Some(ModuleRecord { name: final_name, module: m, refcnt: 0, state: ModuleState::Live }));
    Ok(idx)
}

/// Snapshot for `/proc/modules`-style introspection.
/// # C: O(N modules)
pub fn snapshot() -> Vec<ModuleSnapshot> {
    REGISTRY.lock().iter()
        .filter_map(|slot| slot.as_ref().map(|r| ModuleSnapshot {
            name:     r.name.clone(),
            license:  r.module.info.license.clone(),
            vermagic: r.module.info.vermagic.clone(),
            params:   r.module.info.params.clone(),
            size:     module_size(&r.module),
            refcnt:   r.refcnt,
            state:    r.state,
            sections: r.module.sections.len(),
            symbols:  r.module.symbols.len(),
        }))
        .collect()
}

/// Number of currently-loaded modules.
/// # C: O(N)
pub fn count() -> usize {
    REGISTRY.lock().iter().filter(|m| m.is_some()).count()
}

/// Legacy slot unload retained for internal callers; sys_delete_module uses names.
/// # C: O(1)
pub fn unload(idx: usize) -> bool {
    let mut g = REGISTRY.lock();
    unload_slot(&mut g, idx).is_ok()
}

/// Linux-shaped unload by module name.
/// # C: O(N)
pub fn unload_by_name(name: &str) -> Result<(), RegistryError> {
    validate_name(name)?;
    let mut g = REGISTRY.lock();
    let idx = g.iter().position(|slot| slot.as_ref().is_some_and(|r| r.name == name))
        .ok_or(RegistryError::Noent)?;
    unload_slot(&mut g, idx)
}

/// # C: O(1)
pub fn module_name(idx: usize) -> Option<String> {
    REGISTRY.lock().get(idx).and_then(|s| s.as_ref().map(|r| r.name.clone()))
}

/// Register built-in exported symbols at boot.
/// # SAFETY: caller is the boot path; no other CPU has yet seen the symtab entries.
/// # C: O(1)
pub unsafe fn init_exports() {
    use crate::symtab::export;
    export("klog_write_raw",     klog_write_raw_thunk     as *const () as usize, false);
    export("klog_write_dec_u64", klog_write_dec_u64_thunk as *const () as usize, false);
    export("kassert_thunk",      kassert_thunk            as *const () as usize, false);
    crate::linux_alloc::export_symbols();
    crate::linux_chrdev::export_symbols();
    crate::linux_device::export_symbols();
    crate::linux_dma::export_symbols();
    crate::linux_firmware::export_symbols();
    crate::linux_io::export_symbols();
    crate::linux_irq::export_symbols();
    crate::linux_pci::export_symbols();
    crate::linux_sync::export_symbols();
    crate::linux_time::export_symbols();
}

fn unload_slot(g: &mut Vec<Option<ModuleRecord>>, idx: usize) -> Result<(), RegistryError> {
    let rec = g.get_mut(idx).ok_or(RegistryError::Noent)?
        .as_mut().ok_or(RegistryError::Noent)?;
    if rec.refcnt != 0 { return Err(RegistryError::Busy); }
    rec.state = ModuleState::Going;
    g[idx] = None;
    Ok(())
}

fn validate_name(name: &str) -> Result<(), RegistryError> {
    if name.is_empty() || name.len() > 56 { return Err(RegistryError::Inval); }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err(RegistryError::Inval);
    }
    Ok(())
}

fn module_size(m: &LoadedModule) -> usize {
    m.sections.iter().map(|s| s.bytes.len()).sum()
}

fn synthetic_name(id: usize) -> String {
    let mut s = String::from("module_");
    push_dec(&mut s, id);
    s
}

fn push_dec(s: &mut String, mut n: usize) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 { break; }
    }
    for b in &buf[i..] { s.push(*b as char); }
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use crate::PlacedSection;

    fn reset() {
        REGISTRY.lock().clear();
        NEXT_ID.store(0, Ordering::Relaxed);
    }

    fn empty_module() -> LoadedModule {
        LoadedModule { sections: Vec::new(), symbols: BTreeMap::new(), info: ModuleInfo::default() }
    }

    fn insert(name: &str, refcnt: usize) {
        REGISTRY.lock().push(Some(ModuleRecord {
            name: String::from(name),
            module: empty_module(),
            refcnt,
            state: ModuleState::Live,
        }));
    }

    #[test]
    fn snapshot_reports_name_state_and_counts() {
        reset();
        let mut m = empty_module();
        m.sections.push(PlacedSection {
            name: String::from(".text"),
            bytes: alloc::vec![0u8; 12],
            vbase: 0,
            flags: 0,
        });
        m.symbols.insert(String::from("init_module"), 1);
        REGISTRY.lock().push(Some(ModuleRecord {
            name: String::from("sample"),
            module: m,
            refcnt: 2,
            state: ModuleState::Live,
        }));
        let s = snapshot();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "sample");
        assert_eq!(s[0].license, None);
        assert_eq!(s[0].vermagic, None);
        assert_eq!(s[0].params.len(), 0);
        assert_eq!(s[0].size, 12);
        assert_eq!(s[0].refcnt, 2);
        assert_eq!(s[0].state.as_str(), "Live");
        assert_eq!(s[0].sections, 1);
        assert_eq!(s[0].symbols, 1);
    }

    #[test]
    fn unload_by_name_removes_only_matching_live_record() {
        reset();
        insert("one", 0);
        insert("two", 0);
        assert_eq!(unload_by_name("one"), Ok(()));
        assert_eq!(count(), 1);
        assert_eq!(module_name(1), Some(String::from("two")));
        assert_eq!(unload_by_name("one"), Err(RegistryError::Noent));
    }

    #[test]
    fn unload_busy_module_fails() {
        reset();
        insert("busy", 1);
        assert_eq!(unload_by_name("busy"), Err(RegistryError::Busy));
        assert_eq!(count(), 1);
    }

    #[test]
    fn invalid_names_are_rejected() {
        reset();
        assert_eq!(unload_by_name(""), Err(RegistryError::Inval));
        assert_eq!(unload_by_name("bad/name"), Err(RegistryError::Inval));
    }
}
