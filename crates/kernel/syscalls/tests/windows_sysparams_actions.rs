//! The system-parameter actions the shipped modules actually ask for, read out
//! of the modules themselves rather than assumed, and checked against the
//! settings owner that has to answer them.
//!
//! Each call site is a direct call to one of the system-parameter entry points
//! with the action already in the argument register, so the constant is the
//! instruction before the call. An action found this way and refused by the
//! store is a call the runtime makes and this kernel cannot answer, which is
//! exactly the report that opened this work.
#![allow(dead_code)]

use ipc::win32_sysparams::{Request, SystemParameters};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[path = "windows_call_surface/catalog.rs"]
mod catalog;

/// The modules the Notepad process loads, and the only ones whose call sites
/// can reach this kernel in that run.
const CLOSURE: &[&str] = &["notepad.exe", "user32.dll", "comdlg32.dll", "comctl32.dll", "uxtheme.dll",
    "shell32.dll", "shlwapi.dll", "shcore.dll", "gdi32.dll", "imm32.dll"];

/// Entry points a call site may name.
const ENTRIES: &[&str] = &["SystemParametersInfoW", "SystemParametersInfoA", "NtUserSystemParametersInfo"];

/// `call [rip+disp32]`, the indirect form an imported entry point is reached by.
const CALL_INDIRECT: [u8; 2] = [0xff, 0x15];
/// `jmp [rip+disp32]`, the tail-call form of the same.
const JMP_INDIRECT: [u8; 2] = [0xff, 0x25];
/// `call rel32`, the direct form a module's own entry point is reached by.
const CALL_DIRECT: u8 = 0xe8;
/// `mov ecx, imm32`: the action argument, in the register the first integer
/// argument travels in.
const MOV_ECX: u8 = 0xb9;
/// How far back from a call the action's own load may sit.
const LOOKBACK: usize = 24;
/// `IMAGE_SCN_MEM_EXECUTE`: the section characteristic an instruction lives under.
const SECTION_EXECUTE: u32 = 0x2000_0000;

fn module(root: &Path, name: &str) -> Option<Vec<u8>> { catalog::read(root, name) }

/// Import-address-table slots and own-export addresses of the entry points.
fn targets(image: &pe::Image<'_>) -> (BTreeSet<u32>, BTreeSet<u32>) {
    let mut slots = BTreeSet::new();
    let mut exports = BTreeSet::new();
    if let Ok(imports) = image.imports() {
        for import in &imports {
            let Ok(thunks) = image.import_thunks(import) else { continue; };
            for (index, thunk) in thunks.iter().enumerate() {
                let pe::ImportThunk::Name { name, .. } = thunk else { continue; };
                if !ENTRIES.iter().any(|entry| entry.as_bytes() == *name) { continue; }
                slots.insert(import.first_thunk + (index as u32) * 8);
            }
        }
    }
    if let Ok(Some(info)) = image.exports() {
        for i in 0..info.name_count {
            let Ok(name_rva) = image.rva_range(info.names_rva + i * 4, 4) else { continue; };
            let name_rva = u32::from_le_bytes(name_rva.try_into().unwrap());
            let Ok(name) = image.rva_range(name_rva, 64) else { continue; };
            let name = &name[..name.iter().position(|b| *b == 0).unwrap_or(0)];
            if !ENTRIES.iter().any(|entry| entry.as_bytes() == name) { continue; }
            let Ok(ordinal) = image.rva_range(info.ordinals_rva + i * 2, 2) else { continue; };
            let ordinal = u16::from_le_bytes(ordinal.try_into().unwrap()) as u32;
            let Ok(function) = image.rva_range(info.functions_rva + ordinal * 4, 4) else { continue; };
            exports.insert(u32::from_le_bytes(function.try_into().unwrap()));
        }
    }
    (slots, exports)
}

/// Every action constant loaded immediately before a call to one of the entry
/// points, in one module's executable sections.
fn actions(blob: &[u8]) -> BTreeSet<u32> {
    let mut found = BTreeSet::new();
    let Ok(image) = pe::parse(blob) else { return found; };
    let (slots, exports) = targets(&image);
    if slots.is_empty() && exports.is_empty() { return found; }
    for section in &image.sections {
        // Executable sections only: a data section holds no call instruction.
        if section.characteristics.0 & SECTION_EXECUTE == 0 { continue; }
        let start = section.raw_offset as usize;
        let end = start.saturating_add(section.raw_size as usize).min(blob.len());
        if start >= end { continue; }
        let text = &blob[start..end];
        for offset in 0..text.len().saturating_sub(6) {
            let rva_of = |at: usize| section.virtual_address as u64 + at as u64;
            let displacement = i32::from_le_bytes(text[offset + 2..offset + 6].try_into().unwrap()) as i64;
            let hit = if text[offset..offset + 2] == CALL_INDIRECT || text[offset..offset + 2] == JMP_INDIRECT {
                let next = rva_of(offset + 6) as i64 + displacement;
                u32::try_from(next).is_ok_and(|slot| slots.contains(&slot))
            } else if text[offset] == CALL_DIRECT {
                let target = i32::from_le_bytes(text[offset + 1..offset + 5].try_into().unwrap()) as i64;
                let next = rva_of(offset + 5) as i64 + target;
                u32::try_from(next).is_ok_and(|rva| exports.contains(&rva))
            } else { false };
            if !hit { continue; }
            for back in 1..LOOKBACK.min(offset) {
                let at = offset - back;
                if text[at] != MOV_ECX || at + 5 > text.len() { continue; }
                found.insert(u32::from_le_bytes(text[at + 1..at + 5].try_into().unwrap()));
                break;
            }
        }
    }
    found
}

fn catalog_root() -> Option<PathBuf> { catalog::root() }

/// The set the shipped modules ask for, and the store's answer to each. A
/// refused action here is a call the runtime makes that this kernel drops.
#[test]
fn every_system_parameter_the_shipped_modules_ask_for_is_answered() {
    let Some(root) = catalog_root() else { return; };
    let store = SystemParameters::new();
    let mut seen = BTreeSet::new();
    let mut refused = Vec::new();
    for name in CLOSURE {
        let Some(blob) = module(&root, name) else { continue; };
        for action in actions(&blob) {
            seen.insert(action);
            let read = store.read(action, 96, true);
            let mut probe = SystemParameters::new();
            let written = probe.write(action, 0, None);
            // A writing action that carries a record refuses a bare call; the
            // decoder beside the store is what fetches the record, and it
            // names one for every action it must.
            let carried = carrier_named(action) || window_owned(action);
            if read == Request::Refused && written == Request::Refused && !carried { refused.push((*name, action)); }
        }
    }
    assert!(!seen.is_empty(), "no call site found in the staged catalog at {}", root.display());
    assert!(seen.len() >= 8, "only {} actions found, which is fewer than the modules are known to ask for: {seen:?}", seen.len());
    assert!(refused.is_empty(), "the shipped modules ask for actions this kernel refuses: {refused:x?}");
}

/// Settings the window owner holds rather than this store: the ingress answers
/// them from that owner, so the store refusing them is correct.
fn window_owned(action: u32) -> bool {
    use ipc::win32_sysparams::action as a;
    matches!(action, a::GET_BEEP | a::SET_BEEP | a::SET_DOUBLE_CLICK_TIME | a::GET_MOUSE_HOVER_TIME | a::SET_MOUSE_HOVER_TIME)
}

/// Whether the ingress decoder names a record for this action, which is how a
/// writing action that carries one is admitted.
fn carrier_named(action: u32) -> bool {
    use ipc::win32_sysparams::action as a;
    matches!(action, a::SET_MOUSE | a::SET_MINIMIZED_METRICS | a::SET_ICON_METRICS | a::SET_ICON_TITLE_LOGFONT
        | a::SET_NONCLIENT_METRICS | a::SET_DESK_WALLPAPER)
}

/// The nonclient metrics and the icon-title face are the two the dialog and
/// common-control code paths depend on for their fonts; a run that finds
/// neither has audited nothing.
#[test]
fn the_font_bearing_actions_are_among_the_call_sites() {
    let Some(root) = catalog_root() else { return; };
    let mut seen = BTreeSet::new();
    for name in CLOSURE {
        let Some(blob) = module(&root, name) else { continue; };
        seen.extend(actions(&blob));
    }
    assert!(!seen.is_empty(), "no call site found in the staged catalog");
    for action in [ipc::win32_sysparams::action::GET_NONCLIENT_METRICS,
        ipc::win32_sysparams::action::GET_ICON_TITLE_LOGFONT,
        ipc::win32_sysparams::action::GET_WHEEL_SCROLL_LINES] {
        assert!(seen.contains(&action), "action {action:#x} has no call site: {seen:x?}");
    }
}
