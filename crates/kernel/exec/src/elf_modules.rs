//! Runtime metadata for loaded ELF images.
//!
//! The ELF loader is the only publisher. Consumers (including the NT Wine
//! boundary) query this snapshot by address space and instruction pointer;
//! they never maintain a second image list.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sync::{Modules, Spinlock};
use vmm::AddressSpace;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfRuntimeModule {
    pub base: u64,
    pub size: u64,
    pub eh_frame_address: u64,
    pub eh_frame: Vec<u8>,
}

static MODULES: Spinlock<BTreeMap<u64, Vec<ElfRuntimeModule>>, Modules> =
    Spinlock::new(BTreeMap::new());

pub fn register(as_: &AddressSpace, modules: &[ElfRuntimeModule]) {
    MODULES.lock().insert(as_.root_pa(), modules.to_vec());
}

pub fn append(as_: &AddressSpace, module: ElfRuntimeModule) {
    MODULES.lock().entry(as_.root_pa()).or_default().push(module);
}

pub fn find(root: u64, pc: u64) -> Option<ElfRuntimeModule> {
    MODULES.lock().get(&root).and_then(|modules| modules.iter()
        .find(|module| pc >= module.base && pc - module.base < module.size).cloned())
}

pub fn clear(root: u64) { MODULES.lock().remove(&root); }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_finds_eh_frame_metadata_by_instruction_pointer() {
        let as_ = AddressSpace::new(0x7_0000).unwrap();
        let module = ElfRuntimeModule { base: 0x4000, size: 0x2000,
            eh_frame_address: 0x5100, eh_frame: alloc::vec![1, 2, 3] };
        register(&as_, core::slice::from_ref(&module));
        assert_eq!(find(as_.root_pa(), 0x4fff), Some(module.clone()));
        assert_eq!(find(as_.root_pa(), 0x6000), None);
        clear(as_.root_pa());
        assert_eq!(find(as_.root_pa(), 0x4fff), None);
    }
}
