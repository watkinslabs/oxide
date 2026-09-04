use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sync::{Modules, Spinlock};
use vmm::AddressSpace;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeRuntimeModule {
    pub base: u64,
    pub size: u32,
    pub exception_rva: u32,
    pub exception_size: u32,
}

/// Validate one PE32+ runtime-function record against its mapped image. # C: O(1)
pub fn runtime_function_valid(begin: u32, end: u32, unwind_data: u32, image_size: u32) -> bool {
    if begin >= end || end > image_size { return false; }
    let target = unwind_data & !1;
    if target & 3 != 0 { return false; }
    if unwind_data & 1 != 0 {
        target.checked_add(12).map_or(false, |last| last <= image_size)
    } else {
        target.checked_add(4).map_or(false, |last| last <= image_size)
    }
}

static MODULES: Spinlock<BTreeMap<u64, Vec<PeRuntimeModule>>, Modules> = Spinlock::new(BTreeMap::new());
static EXPORTS: Spinlock<BTreeMap<u64, BTreeMap<u64, Vec<u32>>>, Modules> = Spinlock::new(BTreeMap::new());

pub fn register(as_: &AddressSpace, modules: &[PeRuntimeModule]) {
    MODULES.lock().insert(as_.root_pa(), modules.to_vec());
}

/// Append one dynamically mapped PE to the address-space runtime metadata.
/// # C: O(N_modules)
pub fn append(as_: &AddressSpace, module: PeRuntimeModule) {
    MODULES.lock().entry(as_.root_pa()).or_default().push(module);
}

pub fn find(root: u64, pc: u64) -> Option<PeRuntimeModule> {
    MODULES.lock().get(&root).and_then(|modules| modules.iter().copied().find(|module| pc >= module.base && pc - module.base < module.size as u64))
}

pub fn register_exports(as_: &AddressSpace, base: u64, rvas: Vec<u32>) {
    EXPORTS.lock().entry(as_.root_pa()).or_default().insert(base, rvas);
}

pub fn original_export(root: u64, base: u64, index: u32) -> Option<u64> {
    let rva = EXPORTS.lock().get(&root)?.get(&base)?.get(index as usize).copied()?;
    (rva != 0).then(|| base.checked_add(rva as u64)).flatten()
}

pub fn clear(root: u64) { MODULES.lock().remove(&root); EXPORTS.lock().remove(&root); }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_finds_module_by_pc_and_preserves_exception_directory() {
        let as_ = AddressSpace::new(0x8_0000).unwrap();
        let modules = [PeRuntimeModule { base: 0x1400_0000, size: 0x9000, exception_rva: 0x3000, exception_size: 0x60 }];
        register(&as_, &modules);
        assert_eq!(find(as_.root_pa(), 0x1400_1000), Some(modules[0]));
        assert_eq!(find(as_.root_pa(), 0x1400_9000), None);
        clear(as_.root_pa());
        assert_eq!(find(as_.root_pa(), 0x1400_1000), None);
    }

    #[test]
    fn export_snapshot_returns_original_eat_rva_by_ordinal_index() {
        let as_ = AddressSpace::new(0x9_0000).unwrap();
        register_exports(&as_, 0x1800_0000, alloc::vec![0x19c90, 0x6fcc]);
        assert_eq!(original_export(as_.root_pa(), 0x1800_0000, 0), Some(0x1801_9c90));
        assert_eq!(original_export(as_.root_pa(), 0x1800_0000, 1), Some(0x1800_6fcc));
        assert_eq!(original_export(as_.root_pa(), 0x1800_0000, 2), None);
        clear(as_.root_pa());
    }

    #[test]
    fn runtime_function_validation_rejects_ranges_and_unwind_targets_outside_image() {
        assert!(runtime_function_valid(0x100, 0x180, 0x200, 0x1000));
        assert!(!runtime_function_valid(0x180, 0x180, 0x200, 0x1000));
        assert!(!runtime_function_valid(0x100, 0x1001, 0x200, 0x1000));
        assert!(!runtime_function_valid(0x100, 0x180, 0x1001, 0x1000));
        assert!(!runtime_function_valid(0x100, 0x180, 0xffd, 0x1000));
        assert!(runtime_function_valid(0x100, 0x180, 0x3fd, 0x1000));
    }
}
