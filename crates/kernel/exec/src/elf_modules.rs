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

/// One process-visible ELF symbol exported by a loaded native object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfRuntimeSymbol {
    pub name: Vec<u8>,
    pub address: u64,
}

/// Address-space-owned bounds for one Wine Unixlib function table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ElfUnixlibDescriptor {
    pub table_address: u64,
    pub entry_count: u64,
    pub module_base: u64,
    pub module_end: u64,
}

static MODULES: Spinlock<BTreeMap<u64, Vec<ElfRuntimeModule>>, Modules> =
    Spinlock::new(BTreeMap::new());
static SYMBOLS: Spinlock<BTreeMap<u64, Vec<ElfRuntimeSymbol>>, Modules> =
    Spinlock::new(BTreeMap::new());
static UNIXLIBS: Spinlock<BTreeMap<u64, ElfUnixlibDescriptor>, Modules> =
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

/// Publish the ELF export scope for one address space after all images are
/// mapped. Duplicate names are replaced in registration order.
/// # C: O(N_symbols²) worst case, O(N_symbols) expected for normal catalogs
pub fn register_symbols(as_: &AddressSpace, symbols: &[ElfRuntimeSymbol]) {
    let mut scope = Vec::with_capacity(symbols.len());
    for symbol in symbols {
        if let Some(old) = scope.iter_mut().find(|old: &&mut ElfRuntimeSymbol| old.name == symbol.name) {
            *old = symbol.clone();
        } else { scope.push(symbol.clone()); }
    }
    SYMBOLS.lock().insert(as_.root_pa(), scope);
}

/// Append exports from one newly mapped ELF image to the process scope.
/// # C: O(N_symbols²) worst case
pub fn append_symbols(as_: &AddressSpace, symbols: &[ElfRuntimeSymbol]) {
    let mut scopes = SYMBOLS.lock();
    let scope = scopes.entry(as_.root_pa()).or_default();
    for symbol in symbols {
        if let Some(old) = scope.iter_mut().find(|old| old.name == symbol.name) { *old = symbol.clone(); }
        else { scope.push(symbol.clone()); }
    }
}

/// Publish the one canonical Unixlib descriptor for an address space.
/// # C: O(log N) for the address-space registry
pub fn register_unixlib_descriptor(as_: &AddressSpace, descriptor: ElfUnixlibDescriptor) {
    UNIXLIBS.lock().insert(as_.root_pa(), descriptor);
}

/// Read the Unixlib descriptor owned by an address space.
/// # C: O(log N)
pub fn unixlib_descriptor(root: u64) -> Option<ElfUnixlibDescriptor> {
    UNIXLIBS.lock().get(&root).copied()
}

/// Resolve one exact ELF symbol name in the current process scope.
/// # C: O(N_symbols)
pub fn resolve_symbol(root: u64, name: &[u8]) -> Option<u64> {
    SYMBOLS.lock().get(&root)?.iter().find(|symbol| symbol.name == name).map(|symbol| symbol.address)
}

pub fn clear(root: u64) {
    MODULES.lock().remove(&root);
    SYMBOLS.lock().remove(&root);
    UNIXLIBS.lock().remove(&root);
}

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

    #[test]
    fn symbol_scope_replaces_exact_name_without_case_folding() {
        let as_ = AddressSpace::new(0x7_1000).unwrap();
        register_symbols(&as_, &[
            ElfRuntimeSymbol { name: b"wine_symbol".to_vec(), address: 0x4100 },
            ElfRuntimeSymbol { name: b"Wine_symbol".to_vec(), address: 0x4200 },
            ElfRuntimeSymbol { name: b"wine_symbol".to_vec(), address: 0x4300 },
        ]);
        assert_eq!(resolve_symbol(as_.root_pa(), b"wine_symbol"), Some(0x4300));
        assert_eq!(resolve_symbol(as_.root_pa(), b"Wine_symbol"), Some(0x4200));
        assert_eq!(resolve_symbol(as_.root_pa(), b"WINE_SYMBOL"), None);
        clear(as_.root_pa());
    }

    #[test]
    fn unixlib_descriptor_is_scoped_to_one_address_space() {
        let as_ = AddressSpace::new(0x7_2000).unwrap();
        let descriptor = ElfUnixlibDescriptor { table_address: 0x4200, entry_count: 3,
            module_base: 0x4000, module_end: 0x5000 };
        register_unixlib_descriptor(&as_, descriptor);
        assert_eq!(unixlib_descriptor(as_.root_pa()), Some(descriptor));
        assert_eq!(unixlib_descriptor(as_.root_pa() + 1), None);
        clear(as_.root_pa());
        assert_eq!(unixlib_descriptor(as_.root_pa()), None);
    }
}
