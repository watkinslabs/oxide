//! Static module closure of the root image: import descriptors, delay-load
//! descriptors, forwarded-export targets, and the names loaded at init.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::catalog;

pub struct Closure {
    /// Catalog name in discovery order, with the bytes each parse borrows.
    pub modules: Vec<(String, Vec<u8>)>,
    /// Names reached by the graph that the catalog does not contain.
    pub missing: BTreeMap<String, BTreeSet<String>>,
}

/// Names one module pulls in: static, delayed, forwarded, and init-loaded.
/// # C: O(import descriptors + export functions)
fn dependencies(name: &str, blob: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |value: String| if !out.contains(&value) { out.push(value); };
    if let Ok(image) = pe::parse(blob) {
        for dep in image.loader_dependencies().unwrap_or_default() { push(catalog::normalize(&dep)); }
        for dep in image.delay_dependencies().unwrap_or_default() { push(catalog::normalize(dep)); }
    }
    for (owner, loaded) in catalog::RUNTIME_LOADED {
        if owner == name { for value in loaded { push(value.to_string()); } }
    }
    out
}

/// Breadth-first closure from the root image. The synthetic runtime module is
/// a leaf: its exports are owned by the kernel, not by a catalog PE.
/// # C: O(closure modules * (module bytes + import descriptors))
pub fn discover(root: &Path) -> Closure { walk(root, true) }

/// Breadth-first closure that reads the runtime module from the catalog like
/// any other image, for auditing the boundary the Windows ABI actually
/// publishes: a user-mode ntdll whose system-service entries are stubs.
/// # C: as `discover`
pub fn discover_with_runtime_image(root: &Path) -> Closure { walk(root, false) }

fn walk(root: &Path, runtime_is_a_leaf: bool) -> Closure {
    let mut queue = std::collections::VecDeque::from([catalog::ROOT_MODULE.to_string()]);
    let mut seen = BTreeSet::from([catalog::ROOT_MODULE.to_string()]);
    if runtime_is_a_leaf { seen.insert(catalog::RUNTIME_MODULE.to_string()); }
    else { queue.push_back(catalog::RUNTIME_MODULE.to_string()); seen.insert(catalog::RUNTIME_MODULE.to_string()); }
    let mut modules: Vec<(String, Vec<u8>)> = Vec::new();
    let mut missing: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut requesters: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    while let Some(name) = queue.pop_front() {
        let Some(blob) = catalog::read(root, &name) else {
            missing.insert(name.clone(), requesters.remove(&name).unwrap_or_default());
            continue;
        };
        for dep in dependencies(&name, &blob) {
            requesters.entry(dep.clone()).or_default().insert(name.clone());
            if seen.insert(dep.clone()) { queue.push_back(dep); }
        }
        modules.push((name, blob));
    }
    Closure { modules, missing }
}

/// Every distinct symbol the closure imports from one module, with the
/// importers that name it. # C: O(closure imports)
pub fn imports_of(modules: &[(String, pe::Image<'_>)], from: &str) -> BTreeMap<Vec<u8>, BTreeSet<String>> {
    let mut out: BTreeMap<Vec<u8>, BTreeSet<String>> = BTreeMap::new();
    for (name, image) in modules {
        for import in image.imports().unwrap_or_default() {
            if catalog::normalize(import.name) != from { continue; }
            for thunk in image.import_thunks(&import).unwrap_or_default() {
                if let pe::ImportThunk::Name { name: symbol, .. } = thunk {
                    out.entry(symbol.to_vec()).or_default().insert(name.clone());
                }
            }
        }
    }
    out
}
