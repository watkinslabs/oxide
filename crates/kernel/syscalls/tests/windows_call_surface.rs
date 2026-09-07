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

#[path = "../src/nt_wine_window/font_family_raw.rs"] mod nt_wine_font_family_contract;
#[path = "../src/nt_wine_window/raw_args.rs"] mod raw_args;
#[path = "windows_call_surface/baseline.rs"] mod baseline;
#[path = "windows_call_surface/catalog.rs"] mod catalog;
#[path = "windows_call_surface/closure.rs"] mod closure;
#[path = "windows_call_surface/ntdll_services.rs"] mod ntdll_services;
#[path = "windows_call_surface/report.rs"] mod report;
#[path = "windows_call_surface/user_mode_ntdll.rs"] mod user_mode_ntdll;
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
        .map(|(name, present)| report::NtdllCall { name: name.clone(), present: *present,
            user_mode: !pe::ntdll::syscalls::is_kernel_syscall(name) }).collect();
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

/// The Windows ABI runs every ntdll export but the system services in user
/// mode. Each user-mode routine the kernel publishes as a trap costs a
/// privilege transition the ABI never asks for, so the set only shrinks:
/// a routine added to the kernel runtime instead of a loaded image fails here.
#[test]
fn no_new_user_mode_ntdll_routine_is_served_as_a_kernel_trap() {
    let Some(findings) = findings_or_skip() else { return };
    assert!(!findings.ntdll.is_empty(), "the Notepad closure must reach the NT runtime");
    assert_no_new("user-mode ntdll routines served as kernel traps", findings.user_mode_trap_keys());
}

/// The boundary the audit classifies against must be the runtime's own, not a
/// prefix guess: the closure's system services and its user-mode routines both
/// have to land on the right side for the ratchet above to mean anything.
#[test]
fn the_audit_classifies_the_service_boundary_the_runtime_publishes() {
    assert!(pe::ntdll::syscalls::is_kernel_syscall(b"NtReadFile"));
    assert!(pe::ntdll::syscalls::is_kernel_syscall(b"NtCreateThreadEx"));
    assert!(!pe::ntdll::syscalls::is_kernel_syscall(b"RtlAllocateHeap"));
    assert!(!pe::ntdll::syscalls::is_kernel_syscall(b"memcpy"));
    assert!(!pe::ntdll::syscalls::is_kernel_syscall(b"NtdllDefWindowProc_W"));
}

/// The prize the split buys: with the runtime's own ntdll image in the
/// closure, every import binds without a kernel-published export page. The
/// names this audit's ratchet lists as absent are exactly the ones that image
/// already carries, so this test is what proves the direction is right before
/// anything is moved.
#[test]
fn every_import_binds_against_the_runtime_own_ntdll_image() {
    let Some(root) = catalog::root() else { return };
    let Some((audited, unbound)) = user_mode_ntdll::unbound_against_the_runtime_image(&root) else {
        eprintln!("windows-call-surface: no ntdll image in the catalog, user-mode audit skipped"); return;
    };
    // A closure that collapsed to a handful of modules would pass this
    // vacuously, which is the failure mode the whole audit exists to avoid.
    assert!(audited > 10, "the user-mode audit must reach the whole closure, reached {audited}");
    assert!(unbound.is_empty(), "imports that do not bind against a user-mode ntdll ({}):\n{}",
        unbound.len(), unbound.join("\n"));
    eprintln!("windows-call-surface: {audited} modules bind with no kernel-published ntdll page");
}

/// The names the current arrangement cannot bind, resolved directly against
/// the runtime's own ntdll image. These are the compiler, unwinder, lock and
/// RTL support routines our PE toolchain emits calls to; the image carries
/// every one, which is why none of them is work for this tree to write.
const UNBOUND_TODAY: [&[u8]; 19] = [
    b"__chkstk", b"__C_specific_handler", b"RtlAcquireSRWLockExclusive", b"RtlAcquireSRWLockShared",
    b"RtlAddFunctionTable", b"RtlCompareString", b"RtlComputeCrc32", b"RtlCopyUnicodeString",
    b"RtlDeleteFunctionTable", b"RtlEqualUnicodeString", b"RtlImageRvaToSection", b"RtlInitString",
    b"RtlInstallFunctionTableCallback", b"RtlIsCurrentProcess", b"RtlReleaseSRWLockExclusive",
    b"RtlReleaseSRWLockShared", b"RtlTryAcquireSRWLockExclusive", b"RtlWakeConditionVariable", b"_wcslwr",
];

#[test]
fn the_runtime_own_ntdll_image_carries_every_name_the_kernel_page_lacks() {
    let Some(root) = catalog::root() else { return };
    let Some(absent) = user_mode_ntdll::resolve_in_the_runtime_image(&root, &UNBOUND_TODAY) else {
        panic!("the catalog must carry an ntdll image for this audit; found none under {}", root.display());
    };
    assert!(absent.is_empty(), "names the runtime's own ntdll image does not export ({}):\n{}",
        absent.len(), absent.join("\n"));
}

/// The size of the misplacement, as a number the tree can watch: of the ntdll
/// exports the closure reaches, how many are system services and how many are
/// library code. Every name on the library side that the kernel serves as a
/// trap is a privilege transition the ABI never asks for.
#[test]
fn the_closure_reaches_more_library_routines_than_system_services() {
    let Some(root) = catalog::root() else { return };
    let Some((services, library)) = user_mode_ntdll::boundary_split(&root) else { return };
    eprintln!("windows-call-surface: ntdll boundary split services={services} library={library}");
    assert!(services > 0, "the closure must reach system services");
    assert!(library > services, "the library side is the larger half: services={services} library={library}");
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

/// The service numbering is fixed when the runtime is built, so it is read out
/// of the module the image stages rather than transcribed here. This is what
/// makes a version bump unable to renumber the services under the tree: the
/// boundary table only claims which names are services, and the module the
/// guest runs supplies every number.
#[test]
fn the_shipped_runtime_module_numbers_its_own_system_services() {
    let Some(root) = catalog::root() else { return };
    let Some(decoded) = ntdll_services::decode(&root) else {
        eprintln!("windows-call-surface: no ntdll image in the catalog, service decode skipped"); return;
    };
    // A handful of decoded stubs would pass every assertion below vacuously.
    assert!(decoded.len() > 200, "the runtime module must carry its service table, decoded {}", decoded.len());
    let by_name = ntdll_services::by_name(&decoded);
    // Each service is exported twice, once as `Nt` and once as the `Zw`
    // alias, and both names carry the same ordinal. Counting names as if they
    // were services would double the table, so the identity is asserted here:
    // every ordinal is reached by exactly one `Nt` name and one `Zw` alias.
    let mut names_by_ordinal: BTreeMap<u32, Vec<&str>> = BTreeMap::new();
    for service in &decoded { names_by_ordinal.entry(service.ordinal).or_default().push(&service.name); }
    let malformed: Vec<String> = names_by_ordinal.iter()
        .filter(|(_, names)| names.len() != 2
            || names.iter().filter(|name| name.starts_with("Nt")).count() != 1
            || names.iter().filter(|name| name.starts_with("Zw")).count() != 1)
        .map(|(ordinal, names)| format!("service {ordinal} is exported as {names:?}")).collect();
    assert!(malformed.is_empty(), "services not exported as one Nt name and one Zw alias ({}):\n{}",
        malformed.len(), malformed.join("\n"));
    let ordinals: Vec<u32> = names_by_ordinal.keys().copied().collect();
    assert_eq!(*ordinals.first().unwrap(), 0, "the service numbering starts at zero");
    assert_eq!(*ordinals.last().unwrap() as usize, ordinals.len() - 1, "the service numbering is dense");
    eprintln!("windows-call-surface: {} services decoded from the shipped module, {} exported names",
        ordinals.len(), decoded.len());
    // Every decoded name must be one the boundary table calls a service, and
    // every service the boundary table names must be one the module numbers.
    let mut misclassified: Vec<String> = by_name.keys()
        .filter(|name| !pe::ntdll::syscalls::is_kernel_syscall(name.as_bytes()))
        .map(|name| format!("{name} has a service stub the boundary table calls user mode")).collect();
    misclassified.extend(pe::ntdll::syscalls::service_names()
        .filter(|name| !by_name.contains_key(*name))
        .map(|name| format!("{name} is a boundary-table service the module does not number")));
    assert!(misclassified.is_empty(), "boundary disagreements ({}):\n{}", misclassified.len(), misclassified.join("\n"));
}

/// Every service stub reaches the kernel the same way: it tests one byte of
/// the fixed shared page and, while that byte is clear, executes the
/// architectural syscall instruction. A stub testing some other address would
/// read a byte this kernel does not control.
#[test]
fn every_shipped_service_stub_tests_the_shared_page_this_kernel_maps() {
    let Some(root) = catalog::root() else { return };
    let Some(decoded) = ntdll_services::decode(&root) else { return };
    assert!(decoded.len() > 200, "the service decode must reach the whole table, decoded {}", decoded.len());
    let elsewhere: Vec<String> = decoded.iter()
        .filter(|service| service.flag_address != elf_load::process_env::USER_SHARED_DATA_SYSTEM_CALL_ADDRESS)
        .map(|service| format!("{} tests {:#x}", service.name, service.flag_address)).collect();
    assert!(elsewhere.is_empty(), "service stubs testing an address this kernel does not map ({}):\n{}",
        elsewhere.len(), elsewhere.join("\n"));
}

/// The size of the service work the split needs, as a number the tree can
/// watch: of the services the shipped module numbers, how many does the
/// Notepad closure actually reach. That subset, not the whole table, is what
/// the kernel entry has to answer.
#[test]
fn the_closure_reaches_a_bounded_subset_of_the_shipped_service_table() {
    let Some(root) = catalog::root() else { return };
    let Some(decoded) = ntdll_services::decode(&root) else { return };
    let Some(findings) = audit() else { return };
    let by_name = ntdll_services::by_name(&decoded);
    let reached: Vec<(&report::NtdllCall, String)> = findings.ntdll.iter()
        .map(|call| (call, report::text(&call.name)))
        .filter(|(_, name)| by_name.contains_key(name.as_str())).collect();
    assert!(!reached.is_empty(), "the closure must reach system services");
    eprintln!("windows-call-surface: closure reaches {} of {} shipped service names",
        reached.len(), decoded.len());
    // The names the closure reaches that the kernel page cannot answer today.
    let unserved: Vec<String> = reached.iter().filter(|(call, _)| !call.present)
        .map(|(_, name)| format!("{name} (service {})", by_name[name.as_str()])).collect();
    assert!(unserved.is_empty(), "shipped services the closure reaches that no runtime export answers ({}):\n{}",
        unserved.len(), unserved.join("\n"));
}
