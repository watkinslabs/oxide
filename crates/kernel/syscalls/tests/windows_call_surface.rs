//! Static audit of every Windows call the shipped Notepad module closure can
//! make, gated hosted so an unclaimed win32u ordinal, an absent NT runtime
//! export, or an unbindable import is a red test rather than a boot discovery.
//!
//! Skips when the Wine PE catalog is absent, like the loader graph tests.
//!
//! Admission is the gate for win32u: the ordinal routing tables live in
//! kernel-gated modules, while `argument_count` is the single table every
//! raw entry consults before any routing runs, so an ordinal missing there
//! can never reach a router.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use elf_load::pe_loader::{map_nt_runtime, ImportResolver, NtRuntime, PeExportRef, PeGraphResolver};
use vmm::AddressSpace;

#[path = "../src/nt_wine_window/font_query_raw.rs"] mod nt_wine_font_query_contract;
// Only the ordinal table is needed here; the typed decode carries an alloc dependency.
#[path = "../src/nt_wine_window/gdi_shape_raw/ordinals.rs"] mod gdi_shape_ordinals;
mod nt_wine_gdi_shape { pub(crate) use super::gdi_shape_ordinals as ordinals; }

#[path = "../src/nt_wine_window/dc_state_raw.rs"] mod nt_dc_state_raw;
#[path = "../src/nt_wine_window/xform_raw.rs"] mod nt_xform_raw;
#[path = "../src/nt_wine_window/draw_raw.rs"] mod nt_draw_raw;
#[path = "../src/nt_wine_window/print_raw.rs"] mod nt_print_raw;

#[path = "../src/nt_wine_window/gdi_bitmap_shape.rs"] mod nt_gdi_bitmap_shape;
#[path = "../src/nt_wine_window/raw_args.rs"] mod raw_args;
#[path = "windows_call_surface/baseline.rs"] mod baseline;
#[path = "windows_call_surface/catalog.rs"] mod catalog;
#[path = "windows_call_surface/closure.rs"] mod closure;
#[path = "windows_call_surface/report.rs"] mod report;
#[path = "windows_call_surface/win32u.rs"] mod win32u;

const WIN32U: &str = "win32u.dll";
const MODULE_BASE_STRIDE: u64 = 0x1000_0000;
const FIRST_MODULE_BASE: u64 = 0x1_0000_0000;

/// Records every name the graph resolver hands to the synthetic NT runtime,
/// which is where forwarder chains that land in ntdll arrive.
struct TracingRuntime<'a> { runtime: &'a NtRuntime, seen: RefCell<BTreeMap<Vec<u8>, bool>> }
impl ImportResolver for TracingRuntime<'_> {
    fn resolve(&self, dll: &[u8], import: &pe::ImportThunk<'_>) -> Result<u64, pe::Error> {
        let result = self.runtime.resolve(dll, import);
        if let pe::ImportThunk::Name { name, .. } = import {
            let entry = self.seen.borrow().get(*name).copied().unwrap_or(false);
            self.seen.borrow_mut().insert(name.to_vec(), entry || result.is_ok());
        }
        result
    }
}

fn symbol_text(thunk: &pe::ImportThunk<'_>) -> String {
    match thunk {
        pe::ImportThunk::Name { name, .. } => report::text(name),
        pe::ImportThunk::Ordinal(value) => format!("#{value}"),
    }
}

fn audit() -> Option<report::Findings> {
    let root = catalog::root()?;
    let discovered = closure::discover(&root);
    let modules: Vec<(String, pe::Image<'_>)> = discovered.modules.iter()
        .filter_map(|(name, blob)| pe::parse(blob).ok().map(|image| (name.clone(), image))).collect();

    let win32u_calls = win32u_findings(&modules);
    let exports: Vec<PeExportRef<'_, '_>> = modules.iter().enumerate()
        .map(|(index, (name, image))| PeExportRef { name: name.as_bytes(), image,
            base: FIRST_MODULE_BASE + index as u64 * MODULE_BASE_STRIDE }).collect();
    let space = AddressSpace::new(0x100_000).expect("audit address space must initialize");
    let runtime = map_nt_runtime(&space).expect("synthetic NT runtime must map");
    let tracing = TracingRuntime { runtime: &runtime, seen: RefCell::new(BTreeMap::new()) };
    let resolver = PeGraphResolver { modules: &exports, fallback: &tracing };
    let mut unbound = Vec::new();
    for (name, image) in &modules {
        for import in image.imports().unwrap_or_default() {
            let dll = catalog::normalize(import.name);
            for thunk in image.import_thunks(&import).unwrap_or_default() {
                if resolver.resolve(import.name, &thunk).is_ok() { continue; }
                unbound.push(report::UnboundImport { importer: name.clone(), dll: dll.clone(), symbol: symbol_text(&thunk) });
            }
        }
    }
    let ntdll = tracing.seen.borrow().iter()
        .map(|(name, present)| report::NtdllCall { name: name.clone(), present: *present }).collect();
    Some(report::Findings {
        root: root.display().to_string(),
        modules: modules.iter().map(|(name, _)| name.clone()).collect(),
        missing: discovered.missing.into_iter().collect(),
        win32u: win32u_calls, ntdll, unbound,
    })
}

fn win32u_findings(modules: &[(String, pe::Image<'_>)]) -> Vec<report::Win32uCall> {
    let imports = closure::imports_of(modules, WIN32U);
    let image = modules.iter().find(|(name, _)| name == WIN32U).map(|(_, image)| image);
    imports.into_iter().map(|(name, importers)| {
        let ordinal = image.and_then(|image| win32u::ordinal_of(image, &name));
        let admitted = ordinal.is_some_and(|ordinal| raw_args::argument_count(ordinal).is_some());
        report::Win32uCall { name, ordinal, importers, admitted }
    }).collect()
}

fn findings_or_skip() -> Option<report::Findings> {
    let Some(findings) = audit() else { eprintln!("windows-call-surface: Wine PE catalog absent, audit skipped"); return None; };
    eprintln!("windows-call-surface: report at {}", report::emit(&findings));
    if baseline::update(&findings.keys()) { eprintln!("windows-call-surface: baseline rewritten"); }
    Some(findings)
}

/// New gaps fail on the commit that introduces them; the ratchet direction is
/// enforced separately so a closed gap cannot be left in the baseline.
fn assert_no_new(label: &str, current: Vec<String>) {
    let known = baseline::load();
    let new: Vec<String> = current.into_iter().filter(|key| !known.contains(key)).collect();
    assert!(new.is_empty(), "new {label} ({}) — a boot would have found these:\n{}", new.len(), new.join("\n"));
}

#[test]
fn no_new_unadmitted_win32u_ordinal_reaches_the_notepad_closure() {
    let Some(findings) = findings_or_skip() else { return };
    assert!(!findings.win32u.is_empty(), "the Notepad closure must import win32u services");
    assert_no_new("unadmitted win32u ordinals", findings.win32u_keys());
}

#[test]
fn no_new_ntdll_name_in_the_closure_lacks_a_runtime_export() {
    let Some(findings) = findings_or_skip() else { return };
    assert!(!findings.ntdll.is_empty(), "the Notepad closure must reach the NT runtime");
    assert_no_new("ntdll names with no runtime export", findings.ntdll_keys());
}

#[test]
fn no_new_import_in_the_closure_fails_to_bind_through_the_graph_resolver() {
    let Some(findings) = findings_or_skip() else { return };
    assert_no_new("catalog names the closure needs and the catalog lacks", findings.missing_keys());
    assert_no_new("imports that do not bind", findings.bind_keys());
}

/// The ratchet only runs one way: a gap the tree has closed must leave the
/// baseline in the same change that closes it.
#[test]
fn the_baseline_names_no_gap_the_tree_has_already_closed() {
    let Some(findings) = findings_or_skip() else { return };
    let current = findings.keys();
    let stale: Vec<String> = baseline::load().into_iter().filter(|key| !current.contains(key)).collect();
    assert!(stale.is_empty(), "baseline entries the tree has closed ({}) — delete them:\n{}", stale.len(), stale.join("\n"));
}

#[test]
fn the_stub_decoder_reads_the_ordinal_immediate_and_rejects_other_bodies() {
    assert_eq!(win32u::stub_ordinal(&[0x4c, 0x8b, 0xd1, 0xb8, 0xbd, 0x15, 0x00, 0x00]), Some(0x15bd));
    assert_eq!(win32u::stub_ordinal(&[0x4c, 0x8b, 0xd1, 0xb9, 0xbd, 0x15, 0x00, 0x00]), None);
    assert_eq!(win32u::stub_ordinal(&[0x48, 0x8b, 0xd1, 0xb8, 0xbd, 0x15, 0x00, 0x00]), None);
    assert_eq!(win32u::stub_ordinal(&[0x4c, 0x8b, 0xd1, 0xb8, 0x00]), None);
}

/// A delayed descriptor names its DLL but binds symbols on first use, so a
/// delayed win32u or NT runtime dependency would carry calls this audit's
/// import walk cannot see. The closure must never delay either of them.
#[test]
fn the_closure_delays_no_module_whose_symbols_this_audit_must_see() {
    let Some(root) = catalog::root() else { return };
    let discovered = closure::discover(&root);
    let mut delayed: Vec<String> = Vec::new();
    for (name, blob) in &discovered.modules {
        let Ok(image) = pe::parse(blob) else { continue };
        for dependency in image.delay_dependencies().unwrap_or_default() {
            let dll = catalog::normalize(dependency);
            if dll == WIN32U || dll == catalog::RUNTIME_MODULE { delayed.push(format!("{name} delays {dll}")); }
        }
    }
    assert!(delayed.is_empty(), "delayed dependencies whose symbols the audit cannot enumerate:\n{}", delayed.join("\n"));
}
