//! Owned DLL catalog for a runtime-controlled PE module search policy.

use alloc::vec::Vec;

use crate::{parse, Error, ModuleSource, OwnedModule};

/// Ordered, owned PE module source. The first matching name wins, so the
/// runtime controls search precedence without exposing filesystem semantics.
#[derive(Clone, Default)]
pub struct ModuleCatalog { modules: Vec<OwnedModule> }

impl ModuleCatalog {
    /// Create an empty runtime module catalog. # C: O(1)
    pub fn new() -> Self { Self { modules: Vec::new() } }

    /// Validate and append one runtime-supplied PE module. # C: O(image)
    pub fn add(&mut self, name: &[u8], blob: &[u8]) -> Result<(), Error> {
        if name.is_empty() || self.modules.iter().any(|module| module.name.eq_ignore_ascii_case(name)) {
            return Err(Error::Einval);
        }
        parse(blob)?;
        self.modules.push(OwnedModule { name: name.to_vec(), blob: blob.to_vec() });
        Ok(())
    }

    /// Return the catalog's ordered module list for loader handoff. # C: O(1)
    pub fn modules(&self) -> &[OwnedModule] { &self.modules }

    /// Look up a module using runtime-defined case-insensitive DLL matching. # C: O(N_modules)
    pub fn load(&self, name: &[u8]) -> Option<&[u8]> {
        self.modules.iter().find(|module| crate::loader_name::matches_ascii(name, &module.name)).map(|module| module.blob.as_slice())
    }
}

impl<'a> ModuleSource<'a> for &'a ModuleCatalog {
    fn load(&self, name: &[u8]) -> Option<&'a [u8]> { (*self).load(name) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::image;

    #[test]
    fn catalog_validates_owns_and_matches_modules_without_path_policy() {
        let blob = image();
        let mut catalog = ModuleCatalog::new();
        assert_eq!(catalog.add(b"kernel32.dll", &blob), Ok(()));
        assert_eq!(catalog.load(b"KERNEL32.DLL"), Some(blob.as_slice()));
        assert_eq!(catalog.modules().len(), 1);
        assert_eq!(catalog.add(b"KERNEL32.dll", &blob), Err(Error::Einval));
        assert_eq!(catalog.add(b"user32.dll", b"not-pe"), Err(Error::Enoexec));
    }

    #[test]
    fn catalog_is_usable_by_transitive_dependency_discovery() {
        let root = crate::tests::imports_image(b"dep.dll");
        let dependency = image();
        let mut catalog = ModuleCatalog::new();
        catalog.add(b"dep.dll", &dependency).unwrap();
        let source = &catalog;
        let modules = crate::discover_owned_modules(b"root.exe", &root, &source).unwrap();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[1].name, b"dep.dll");
    }
}
