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

static MODULES: Spinlock<BTreeMap<u64, Vec<PeRuntimeModule>>, Modules> = Spinlock::new(BTreeMap::new());

pub fn register(as_: &AddressSpace, modules: &[PeRuntimeModule]) {
    MODULES.lock().insert(as_.root_pa(), modules.to_vec());
}

pub fn find(root: u64, pc: u64) -> Option<PeRuntimeModule> {
    MODULES.lock().get(&root).and_then(|modules| modules.iter().copied().find(|module| pc >= module.base && pc - module.base < module.size as u64))
}

pub fn clear(root: u64) { MODULES.lock().remove(&root); }

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
}
