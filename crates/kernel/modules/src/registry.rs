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
    pub taints:   u64,
    pub state:    ModuleState,
    pub sections: usize,
    pub symbols:  usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    Inval,
    Exists,
    Load,
    Init,
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
    name:           String,
    module:         LoadedModule,
    refcnt:         usize,
    taints:         u64,
    state:          ModuleState,
    unload_pending: bool,
}

type InitFn = unsafe extern "C" fn() -> i32;
type ExitFn = unsafe extern "C" fn();

static REGISTRY: Spinlock<Vec<Option<ModuleRecord>>, ModulesLockClass>
    = Spinlock::new(Vec::new());
static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

const TAINT_PROPRIETARY_MODULE: u64 = 1 << 0;
const TAINT_FORCED_MODULE:      u64 = 1 << 1;
const TAINT_FORCED_RMMOD:       u64 = 1 << 3;
const TAINT_OOT_MODULE:         u64 = 1 << 12;

/// Load + register a module from raw ELF ET_REL bytes.
/// # C: O(N_sections + N_relocs)
pub fn load_blob(bytes: &[u8]) -> Option<usize> {
    load_blob_named(bytes, None).ok()
}

/// Load + register a module with an optional caller-supplied name.
/// # C: O(N_sections + N_relocs + N_modules)
pub fn load_blob_named(bytes: &[u8], name: Option<&str>) -> Result<usize, RegistryError> {
    load_blob_named_with_flags(bytes, name, false)
}

/// Load one module while honoring finit_module's force-vermagic flag.
/// # C: O(N_sections + N_relocs + N_modules)
pub fn load_blob_named_with_flags(
    bytes: &[u8],
    name: Option<&str>,
    ignore_vermagic: bool,
) -> Result<usize, RegistryError> {
    let info = ModuleInfo::parse_elf(bytes).ok_or(RegistryError::Load)?;
    let forced = !info.vermagic_matches();
    if !vermagic_admitted(&info, ignore_vermagic) { return Err(RegistryError::Vermagic); }
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
    register_loaded_module_with_taints(final_name, m, if forced { TAINT_FORCED_MODULE } else { 0 })
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
            taints:   r.taints,
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
    unload_slot(idx, false).is_ok()
}

/// Linux-shaped unload by module name.
/// # C: O(N)
pub fn unload_by_name(name: &str) -> Result<(), RegistryError> {
    unload_by_name_flags(name, false)
}

/// Linux-shaped unload by module name with force-taint intent.
/// # C: O(N)
pub fn unload_by_name_flags(name: &str, force: bool) -> Result<(), RegistryError> {
    validate_name(name)?;
    let idx = {
        let g = REGISTRY.lock();
        g.iter().position(|slot| slot.as_ref().is_some_and(|r| r.name == name))
            .ok_or(RegistryError::Noent)?
    };
    unload_slot(idx, force)
}

/// Try to pin a live or coming module by name.
/// # C: O(N)
pub fn try_get_by_name(name: &str) -> bool {
    if validate_name(name).is_err() { return false; }
    let mut g = REGISTRY.lock();
    let Some(rec) = g.iter_mut()
        .filter_map(|slot| slot.as_mut())
        .find(|r| r.name == name) else { return false; };
    if rec.state == ModuleState::Going || rec.unload_pending { return false; }
    rec.refcnt = rec.refcnt.saturating_add(1);
    true
}

/// Drop a module pin and drain a pending unload when the last pin leaves.
/// # C: O(N)
pub fn put_by_name(name: &str) -> Result<(), RegistryError> {
    if validate_name(name).is_err() { return Err(RegistryError::Inval); }
    let drain = {
        let mut g = REGISTRY.lock();
        let Some((idx, rec)) = g.iter_mut().enumerate()
            .filter_map(|(idx, slot)| slot.as_mut().map(|r| (idx, r)))
            .find(|(_, r)| r.name == name) else { return Err(RegistryError::Noent); };
        if rec.refcnt == 0 { return Err(RegistryError::Inval); }
        rec.refcnt -= 1;
        if rec.refcnt == 0 && rec.unload_pending { Some(idx) } else { None }
    };
    if let Some(idx) = drain { finish_unload_slot(idx)?; }
    Ok(())
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
    crate::linux_block::export_symbols();
    crate::linux_chrdev::export_symbols();
    crate::linux_crypto::export_symbols();
    crate::linux_configfs::export_symbols();
    crate::linux_debugfs::export_symbols();
    crate::linux_device::export_symbols();
    crate::linux_dma::export_symbols();
    crate::linux_dma_buf::export_symbols();
    crate::linux_dma_fence::export_symbols();
    crate::linux_firmware::export_symbols();
    crate::linux_input::export_symbols();
    crate::linux_module::export_symbols();
    crate::linux_mempool::export_symbols();
    crate::linux_nvme_auth::export_symbols();
    crate::linux_io::export_symbols();
    crate::linux_ida::export_symbols();
    crate::linux_irq::export_symbols();
    crate::linux_led::export_symbols();
    crate::linux_netdev::export_symbols();
    crate::linux_pci::export_symbols();
    crate::linux_resource::export_symbols();
    crate::linux_drm::export_symbols();
    crate::linux_platform::export_symbols();
    crate::linux_pm::export_symbols();
    crate::linux_runtime::export_symbols();
    crate::linux_seq_file::export_symbols();
    crate::linux_scsi::export_symbols();
    crate::linux_string::export_symbols();
    crate::linux_sync::export_symbols();
    crate::linux_time::export_symbols();
    crate::linux_usercopy::export_symbols();
    crate::linux_usb::export_symbols();
    crate::linux_video::export_symbols();
    crate::linux_xarray::export_symbols();
}

#[cfg(test)]
fn register_loaded_module(name: String, module: LoadedModule) -> Result<usize, RegistryError> {
    register_loaded_module_with_taints(name, module, 0)
}

fn register_loaded_module_with_taints(
    name: String,
    module: LoadedModule,
    extra_taints: u64,
) -> Result<usize, RegistryError> {
    validate_name(&name)?;
    let init = init_fns(&module)?;
    let idx = {
        let mut g = REGISTRY.lock();
        if g.iter().any(|slot| slot.as_ref().is_some_and(|r| r.name == name)) {
            return Err(RegistryError::Exists);
        }
        let idx = g.len();
        let taints = module_taints(&module) | extra_taints;
        g.push(Some(ModuleRecord {
            name, module, refcnt: 0, taints, state: ModuleState::Coming, unload_pending: false,
        }));
        idx
    };
    if run_init(&init).is_err() {
        remove_after_init_failure(idx);
        return Err(RegistryError::Init);
    }
    let mut g = REGISTRY.lock();
    if let Some(Some(rec)) = g.get_mut(idx) {
        rec.state = ModuleState::Live;
    }
    Ok(idx)
}

fn unload_slot(idx: usize, force: bool) -> Result<(), RegistryError> {
    {
        let mut g = REGISTRY.lock();
        let rec = g.get_mut(idx).ok_or(RegistryError::Noent)?
            .as_mut().ok_or(RegistryError::Noent)?;
        if rec.state == ModuleState::Going { return Err(RegistryError::Busy); }
        rec.state = ModuleState::Going;
        rec.unload_pending = true;
        if force { rec.taints |= TAINT_FORCED_RMMOD; }
        if rec.refcnt != 0 { return Err(RegistryError::Busy); }
    }
    finish_unload_slot(idx)
}

fn finish_unload_slot(idx: usize) -> Result<(), RegistryError> {
    let (name, exit) = {
        let g = REGISTRY.lock();
        let rec = g.get(idx).ok_or(RegistryError::Noent)?
            .as_ref().ok_or(RegistryError::Noent)?;
        if rec.refcnt != 0 { return Err(RegistryError::Busy); }
        (rec.name.clone(), exit_fns(&rec.module)?)
    };
    for f in exit.iter().rev() {
        // SAFETY: function addresses come from relocated module exit sections or cleanup_module.
        unsafe { f() };
    }
    let mut g = REGISTRY.lock();
    if let Some(slot) = g.get_mut(idx) {
        *slot = None;
    }
    crate::symtab::unexport_module(&name);
    Ok(())
}

fn remove_after_init_failure(idx: usize) {
    let mut g = REGISTRY.lock();
    if let Some(slot) = g.get_mut(idx) {
        if let Some(rec) = slot.as_mut() {
            rec.state = ModuleState::Going;
        }
        *slot = None;
    }
}

fn run_init(init: &[InitFn]) -> Result<(), ()> {
    for f in init {
        // SAFETY: function addresses come from relocated module init sections or init_module.
        let rc = unsafe { f() };
        if rc != 0 { return Err(()); }
    }
    Ok(())
}

fn init_fns(m: &LoadedModule) -> Result<Vec<InitFn>, RegistryError> {
    if let Some(addr) = m.symbols.get("init_module").copied() {
        // SAFETY: ET_REL symbol `init_module` has Linux module init ABI.
        return Ok(alloc::vec![unsafe { init_fn(addr as usize) }]);
    }
    collect_initcall_sections(m)
}

fn exit_fns(m: &LoadedModule) -> Result<Vec<ExitFn>, RegistryError> {
    if let Some(addr) = m.symbols.get("cleanup_module").copied() {
        // SAFETY: ET_REL symbol `cleanup_module` has Linux module exit ABI.
        return Ok(alloc::vec![unsafe { exit_fn(addr as usize) }]);
    }
    collect_exitcall_sections(m)
}

fn collect_initcall_sections(m: &LoadedModule) -> Result<Vec<InitFn>, RegistryError> {
    let mut out = Vec::new();
    for s in &m.sections {
        if !is_initcall_section(&s.name) { continue; }
        for addr in section_ptrs(s.bytes())? {
            // SAFETY: initcall section entries are relocated function pointers.
            out.push(unsafe { init_fn(addr) });
        }
    }
    Ok(out)
}

fn collect_exitcall_sections(m: &LoadedModule) -> Result<Vec<ExitFn>, RegistryError> {
    let mut out = Vec::new();
    for s in &m.sections {
        if s.name != ".exitcall.exit" { continue; }
        for addr in section_ptrs(s.bytes())? {
            // SAFETY: exitcall section entries are relocated function pointers.
            out.push(unsafe { exit_fn(addr) });
        }
    }
    Ok(out)
}

fn is_initcall_section(name: &str) -> bool {
    name.starts_with(".initcall") && name.ends_with(".init")
}

fn section_ptrs(bytes: &[u8]) -> Result<Vec<usize>, RegistryError> {
    const PTR: usize = core::mem::size_of::<usize>();
    if bytes.len() % PTR != 0 { return Err(RegistryError::Load); }
    let mut out = Vec::new();
    let mut off = 0;
    while off < bytes.len() {
        let mut raw = [0u8; PTR];
        raw.copy_from_slice(&bytes[off..off + PTR]);
        let addr = usize::from_ne_bytes(raw);
        if addr != 0 { out.push(addr); }
        off += PTR;
    }
    Ok(out)
}

unsafe fn init_fn(addr: usize) -> InitFn {
    // SAFETY: caller proves addr is an init function pointer with Linux module ABI.
    unsafe { core::mem::transmute::<usize, InitFn>(addr) }
}

unsafe fn exit_fn(addr: usize) -> ExitFn {
    // SAFETY: caller proves addr is an exit function pointer with Linux module ABI.
    unsafe { core::mem::transmute::<usize, ExitFn>(addr) }
}

fn validate_name(name: &str) -> Result<(), RegistryError> {
    if name.is_empty() || name.len() > 56 { return Err(RegistryError::Inval); }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err(RegistryError::Inval);
    }
    Ok(())
}

fn module_size(m: &LoadedModule) -> usize {
    m.sections.iter().map(|s| s.len()).sum()
}

fn module_taints(m: &LoadedModule) -> u64 {
    let mut t = TAINT_OOT_MODULE;
    match m.info.license.as_deref() {
        Some(license) if crate::symtab::license_is_gpl(license) => {}
        _ => { t |= TAINT_PROPRIETARY_MODULE; }
    }
    t
}

fn vermagic_admitted(info: &ModuleInfo, ignore_vermagic: bool) -> bool {
    info.vermagic_matches() || ignore_vermagic
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
mod tests;
