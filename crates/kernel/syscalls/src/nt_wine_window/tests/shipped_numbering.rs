//! The service numbering the SHIPPED window module actually uses.
//!
//! Every win32u ordinal this dispatcher admits is transcribed into these
//! tables, so a runtime version bump that renumbers a service would silently
//! route an admitted call to a different function. The shipped module's own
//! stub bodies are the authority: they are decoded here and every admitted
//! ordinal is checked against them.

use alloc::vec::Vec;
use crate::nt_wine_raw_args_contract as raw_args;
use crate::nt_wine_unclaimed_contract as unclaimed;

/// The staged module the guest actually runs.
fn shipped_image() -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../target/artifacts/wine/x86_64/x86_64-windows/win32u.dll");
    assert!(path.is_file(), "staged window module missing at {}", path.display());
    std::fs::read(&path).unwrap_or_else(|error| panic!("staged {} unreadable: {error}", path.display()))
}

/// Every service the shipped module exports, as (ordinal, name).
fn shipped_services(bytes: &[u8]) -> Vec<(u32, &[u8])> {
    let image = pe::parse(bytes).expect("the staged window module parses as a PE image");
    let decoded = pe::ntdll::services::decode_all(&image).expect("the staged window module's exports decode");
    assert!(decoded.len() > 1000, "only {} service stubs decoded; the stub shape moved", decoded.len());
    decoded.iter().map(|service| (service.ordinal, service.name)).collect()
}

/// Every ordinal this dispatcher converts arguments for, in the window
/// module's own table. Probing the admission function rather than any one
/// table covers the per-family tables too.
fn admitted() -> Vec<u64> {
    (0x1000u64..0x2000).filter(|ordinal| raw_args::argument_count(*ordinal).is_some()).collect()
}

#[test]
fn every_admitted_ordinal_is_a_service_the_shipped_module_asks_for() {
    let bytes = shipped_image();
    let shipped = shipped_services(&bytes);
    let admitted = admitted();
    assert!(admitted.len() > 300, "only {} ordinals admitted; the admission tables moved", admitted.len());
    let absent = admitted.iter().copied()
        .filter(|ordinal| !shipped.iter().any(|(number, _)| *number as u64 == *ordinal))
        .collect::<Vec<_>>();
    assert!(absent.is_empty(), "admitted ordinals the shipped module does not export: {absent:x?}");
}

#[test]
fn the_multiplexer_ordinals_name_the_multiplexers_in_the_shipped_module() {
    let bytes = shipped_image();
    let shipped = shipped_services(&bytes);
    let named = |name: &[u8]| shipped.iter().find(|(_, export)| *export == name).map(|(ordinal, _)| *ordinal as u64);
    // A refusal report reads the method code out of a fixed argument index, so
    // these four numbers naming any other service would misreport every
    // unclaimed call and mis-decode the method of a claimed one.
    for (name, index) in [(&b"NtUserCallHwnd"[..], 1usize), (&b"NtUserCallHwndParam"[..], 2),
                          (&b"NtUserCallTwoParam"[..], 2), (&b"NtUserQueryWindow"[..], 1)] {
        let ordinal = named(name).unwrap_or_else(|| panic!("the shipped module exports no {}", core::str::from_utf8(name).unwrap()));
        assert_eq!(unclaimed::method_arg(ordinal), Some(index),
            "{} is {ordinal:#x} in the shipped module", core::str::from_utf8(name).unwrap());
    }
}

#[test]
fn the_window_and_bitmap_services_the_runtime_starts_with_keep_their_numbers() {
    let bytes = shipped_image();
    let shipped = shipped_services(&bytes);
    for (name, ordinal) in [(&b"NtUserCreateWindowEx"[..], 0x136bu64), (&b"NtGdiCreateDIBSection"[..], 0x10b0)] {
        let found = shipped.iter().find(|(_, export)| *export == name).map(|(number, _)| *number as u64);
        assert_eq!(found, Some(ordinal), "{} moved", core::str::from_utf8(name).unwrap());
        assert!(unclaimed::is_win32u_ordinal(ordinal), "{ordinal:#x} is outside the window module's table");
    }
}

#[test]
fn every_service_the_shipped_module_exports_is_in_the_table_the_dispatcher_claims() {
    let bytes = shipped_image();
    let shipped = shipped_services(&bytes);
    let outside = shipped.iter().filter(|(ordinal, _)| !unclaimed::is_win32u_ordinal(*ordinal as u64))
        .map(|(ordinal, _)| *ordinal).collect::<Vec<_>>();
    assert!(outside.is_empty(), "shipped services outside the claimed table: {outside:x?}");
}

/// The window module the shipped editor's frame library actually calls into.
fn shipped_frame_library() -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../target/artifacts/wine/x86_64/x86_64-windows/user32.dll");
    assert!(path.is_file(), "staged frame library missing at {}", path.display());
    std::fs::read(&path).unwrap_or_else(|error| panic!("staged {} unreadable: {error}", path.display()))
}

/// Every window-module service the frame library imports by name.
fn frame_library_imports(bytes: &[u8]) -> Vec<alloc::vec::Vec<u8>> {
    let image = pe::parse(bytes).expect("the staged frame library parses as a PE image");
    let mut out = Vec::new();
    for import in image.imports().expect("the staged frame library's import directory decodes") {
        if !import.name.eq_ignore_ascii_case(b"win32u.dll") { continue; }
        for thunk in image.import_thunks(&import).expect("the window module's thunks decode") {
            if let pe::ImportThunk::Name { name, .. } = thunk { out.push(name.to_vec()); }
        }
    }
    out
}

/// The frame library builds a window's menu bar out of these services, so one
/// of them unadmitted leaves the bar with no items, or no bar at all.
#[test]
fn every_menu_service_the_frame_library_imports_is_admitted() {
    let module = shipped_image();
    let shipped = shipped_services(&module);
    let frame = shipped_frame_library();
    let imported = frame_library_imports(&frame);
    assert!(imported.len() > 100, "only {} window services imported; the import shape moved", imported.len());
    let menu = imported.iter().filter(|name| name.windows(4).any(|window| window == b"Menu")).collect::<Vec<_>>();
    assert!(menu.len() > 5, "only {} menu services imported; the menu path moved", menu.len());
    let admitted = admitted();
    let missing = menu.iter().filter(|name| {
        let ordinal = shipped.iter().find(|(_, export)| *export == name.as_slice()).map(|(number, _)| *number as u64);
        !ordinal.is_some_and(|ordinal| admitted.contains(&ordinal))
    }).map(|name| alloc::string::String::from_utf8_lossy(name).into_owned()).collect::<Vec<_>>();
    assert!(missing.is_empty(), "menu services the frame library imports and this dispatcher refuses: {missing:?}");
}
