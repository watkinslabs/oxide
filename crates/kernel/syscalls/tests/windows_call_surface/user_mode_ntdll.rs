//! The Windows ABI publishes ntdll as a user-mode image: its system-service
//! entries are stubs that trap, and every other export is library code that
//! runs at user privilege. This audit measures the closure against that shape
//! instead of against a kernel-published export page, so the cost of the
//! current arrangement, and what closes it, are both a number rather than an
//! opinion a boot has to discover.

use std::collections::BTreeMap;
use std::path::Path;

use super::{catalog, closure, report, FIRST_MODULE_BASE, MODULE_BASE_STRIDE};
use elf_load::pe_loader::{ImportResolver, PeExportRef, PeGraphResolver};

/// Resolves nothing: with a real ntdll image in the closure there is no name
/// left for a kernel-published page to answer, and a resolver that answered
/// would hide exactly the gap this audit measures.
struct NoFallback;
impl ImportResolver for NoFallback {
    fn resolve(&self, _dll: &[u8], _import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> { Err(pe::Error::Unsupported) }
}

/// Names the closure cannot bind when ntdll is the runtime's own image, with
/// the number of modules audited so a vacuous pass is visible.
/// `None` when the catalog carries no ntdll image to audit.
/// # C: O(closure imports)
pub fn unbound_against_the_runtime_image(root: &Path) -> Option<(usize, Vec<String>)> {
    if catalog::read(root, catalog::RUNTIME_MODULE).is_none() { return None; }
    let discovered = closure::discover_with_runtime_image(root);
    let modules: Vec<(String, pe::Image<'_>)> = discovered.modules.iter()
        .filter_map(|(name, blob)| pe::parse(blob).ok().map(|image| (name.clone(), image))).collect();
    // The catalog carries the image, so a closure that lost it is a defect in
    // the walk, not a reason to report nothing and pass.
    assert!(modules.iter().any(|(name, _)| name == catalog::RUNTIME_MODULE),
        "the runtime image is in the catalog but absent from the closure");
    let exports: Vec<PeExportRef<'_, '_>> = modules.iter().enumerate()
        .map(|(index, (name, image))| PeExportRef { name: name.as_bytes(), image,
            base: FIRST_MODULE_BASE + index as u64 * MODULE_BASE_STRIDE }).collect();
    let resolver = PeGraphResolver { modules: &exports, fallback: &NoFallback };
    let mut unbound = Vec::new();
    for (name, image) in &modules {
        for import in image.imports().unwrap_or_default() {
            for thunk in image.import_thunks(&import).unwrap_or_default() {
                if resolver.resolve(import.name, &thunk).is_ok() { continue; }
                let pe::ImportThunk::Name { name: symbol, .. } = thunk else { continue };
                unbound.push(format!("{name} imports {}!{}", catalog::normalize(import.name), report::text(symbol)));
            }
        }
    }
    Some((modules.len(), unbound))
}

/// Resolve names directly against the runtime's own ntdll image.
/// `None` when the catalog carries no ntdll image to audit.
/// # C: O(names * export table)
pub fn resolve_in_the_runtime_image(root: &Path, names: &[&[u8]]) -> Option<Vec<String>> {
    let blob = catalog::read(root, catalog::RUNTIME_MODULE)?;
    let image = pe::parse(&blob).ok()?;
    let exports = [PeExportRef { name: catalog::RUNTIME_MODULE.as_bytes(), image: &image, base: FIRST_MODULE_BASE }];
    let resolver = PeGraphResolver { modules: &exports, fallback: &NoFallback };
    Some(names.iter().filter(|name| resolver.resolve(catalog::RUNTIME_MODULE.as_bytes(),
        &pe::ImportThunk::Name { hint: 0, name }).is_err())
        .map(|name| report::text(name)).collect())
}

/// Every export the closure reaches, split by which side of the boundary the
/// Windows ABI puts it on. # C: O(ntdll exports reached)
pub fn boundary_split(root: &Path) -> Option<(usize, usize)> {
    let discovered = closure::discover_with_runtime_image(root);
    let modules: Vec<(String, pe::Image<'_>)> = discovered.modules.iter()
        .filter_map(|(name, blob)| pe::parse(blob).ok().map(|image| (name.clone(), image))).collect();
    let imports: BTreeMap<_, _> = closure::imports_of(&modules, catalog::RUNTIME_MODULE).into_iter().collect();
    if imports.is_empty() { return None; }
    let services = imports.keys().filter(|name| pe::ntdll::syscalls::is_kernel_syscall(name)).count();
    Some((services, imports.len() - services))
}
