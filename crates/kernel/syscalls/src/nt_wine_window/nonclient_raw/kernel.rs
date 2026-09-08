//! Perform one system-parameter call: fetch what a writing action carries,
//! ask the settings owner, and transfer the answer. Every decision this file
//! acts on belongs to the owner or to the decoder beside it.
use alloc::vec::Vec;
use ipc::win32_sysparams::{Request, StructWrite, SystemParameters, LOGFONTW_BYTES};
use super::{carrier, decode, record_size_admitted, Call, Carrier, MAX_PATH_UNITS, SYSTEM_PARAMETERS_INFO};

/// The one session-wide settings record. One process's write is the value the
/// next process reads, as a session-wide setting is.
static PARAMETERS: sync::Spinlock<SystemParameters, sync::TaskList> =
    sync::Spinlock::new(SystemParameters::new());

/// Dots per inch every unscaled system-parameter answer is quoted at.
const DEFAULT_DPI: u32 = 96;

/// True, as the window ABI spells a successful system-parameter call.
const TRUE: u64 = 1;
/// False, which is what an action no entry names answers with.
const FALSE: u64 = 0;

/// The nonclient profile as the settings record currently holds it. The
/// graphics owner normalizes its faces against the font backend from here, so
/// the record a client wrote is the record the next reader is handed.
/// # C: O(1), fixed record
pub(crate) fn live_profile(size: u32, dpi: u32) -> Option<[u8; ipc::win32_gdi::NONCLIENT_BYTES]> {
    PARAMETERS.lock().nonclient_profile(size, dpi).ok()
}

/// Answer one system-parameter call. Some for every call on this ordinal: the
/// reference answers an action it does not implement FALSE and never leaves
/// the service unclaimed. # C: O(N_entries) plus one bounded usercopy
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let call = decode(ordinal, args)?;
    Some(perform(call))
}

/// The same call, with the DPI a scaled caller names. # C: O(N_entries)
pub(crate) fn route_for_dpi(action: u32, val: u32, ptr: u64, winini: u32, dpi: u32) -> u64 {
    perform_at(Call { action, val, ptr, winini }, if dpi == 0 { DEFAULT_DPI } else { dpi })
}

fn perform(call: Call) -> u64 { perform_at(call, DEFAULT_DPI) }

fn perform_at(call: Call, dpi: u32) -> u64 {
    // The nonclient record is answered by the graphics owner, because its
    // faces are normalized by the font backend and not by this store.
    if call.action == super::GET_NONCLIENT_METRICS {
        return super::route(SYSTEM_PARAMETERS_INFO, &[call.action as u64, call.val as u64, call.ptr, call.winini as u64],
            |pointer| uaccess::get_user_u32(pointer).ok(),
            |pointer, size| crate::nt_native_gdi::begin_nonclient_at(pointer, size, dpi)).unwrap_or(FALSE);
    }
    if let Some(result) = window_owned(call) { return result; }
    let pointer = call.ptr != 0;
    let request = PARAMETERS.lock().read(call.action, dpi, pointer);
    if request != Request::Refused { return answer(call, dpi, request); }
    apply(call, dpi)
}

/// The settings the window owner already holds. Duplicating them here would
/// let a caller's read and the paths that act on the same setting disagree,
/// so those actions are answered from that owner and from nowhere else.
/// # C: O(1) plus one bounded usercopy
fn window_owned(call: Call) -> Option<u64> {
    use ipc::win32_sysparams::action as a;
    use crate::nt_window::settings;
    Some(match call.action {
        a::GET_BEEP => write_words(call.ptr, &[settings::beep_enabled() as u32]),
        a::SET_BEEP => { settings::set_beep_enabled(call.val != 0); TRUE }
        a::SET_DOUBLE_CLICK_TIME => { settings::set_double_click_time(call.val); TRUE }
        a::GET_MOUSE_HOVER_TIME => match settings::mouse_hover_time_for_current() {
            Some(value) => write_words(call.ptr, &[value]), None => FALSE },
        a::SET_MOUSE_HOVER_TIME => { settings::set_mouse_hover_time(call.val); TRUE }
        _ => return None,
    })
}

/// Transfer what a reading action produced. # C: O(N_words)
fn answer(call: Call, dpi: u32, request: Request) -> u64 {
    match request {
        Request::Word(value) => write_words(call.ptr, &[value]),
        Request::Words(values) => {
            if !leading_size_admitted(call.action, call.ptr) { return FALSE; }
            let skip = if size_word_leads(call.action) { 4 } else { 0 };
            match call.ptr.checked_add(skip) { Some(base) => write_words(base, &values), None => FALSE }
        }
        Request::IconMetrics(values) => {
            if !leading_size_admitted(call.action, call.ptr) { return FALSE; }
            let (Some(base), Some(face)) = (call.ptr.checked_add(4), call.ptr.checked_add(16)) else { return FALSE; };
            if write_words(base, &values) == FALSE { return FALSE; }
            write_font(face)
        }
        Request::Font => write_font(call.ptr),
        Request::Path => write_path(call.ptr, call.val as usize),
        Request::Nonclient | Request::Applied => TRUE,
        Request::Refused => { let _ = dpi; FALSE }
    }
}

/// Fetch what a writing action carries and hand it to the settings owner. The
/// fetch happens before the store is locked, because a user-memory read may
/// fault. # C: O(N_words) plus one bounded usercopy
fn apply(call: Call, dpi: u32) -> u64 {
    let _ = dpi;
    match carrier(call.action) {
        Carrier::None => match PARAMETERS.lock().write(call.action, call.val as i32, None) {
            Request::Applied => TRUE, Request::Path => FALSE, _ => FALSE,
        },
        Carrier::Words { count, skip, sized } => {
            let Some(words) = read_words(call.ptr, count, skip, sized, call.action) else { return FALSE; };
            match PARAMETERS.lock().write(call.action, call.val as i32, Some(StructWrite { words: &words, font: None })) {
                Request::Applied => TRUE, _ => FALSE,
            }
        }
        Carrier::Font => {
            let Some(font) = read_font(call.ptr) else { return FALSE; };
            match PARAMETERS.lock().write(call.action, call.val as i32, Some(StructWrite { words: &[], font: Some(&font) })) {
                Request::Applied => TRUE, _ => FALSE,
            }
        }
        Carrier::IconMetrics => {
            let Some(words) = read_words(call.ptr, 3, 4, Some(super::ICON_METRICS_BYTES), call.action) else { return FALSE; };
            let Some(base) = call.ptr.checked_add(16) else { return FALSE; };
            let Some(font) = read_font(base) else { return FALSE; };
            match PARAMETERS.lock().write(call.action, call.val as i32, Some(StructWrite { words: &words, font: Some(&font) })) {
                Request::Applied => TRUE, _ => FALSE,
            }
        }
        Carrier::Nonclient => {
            let Some(words) = read_words(call.ptr, ipc::win32_sysparams::NONCLIENT_DIMENSIONS.len(), 0, None, call.action) else { return FALSE; };
            let Some(menu) = call.ptr.checked_add(ipc::win32_sysparams::NONCLIENT_FACE_OFFSETS[ipc::win32_sysparams::NONCLIENT_MENU_FACE] as u64) else { return FALSE; };
            let Some(font) = read_font(menu) else { return FALSE; };
            match PARAMETERS.lock().write(call.action, call.val as i32, Some(StructWrite { words: &words, font: Some(&font) })) {
                Request::Applied => TRUE, _ => FALSE,
            }
        }
        Carrier::Path => {
            let Some(path) = read_path(call.ptr) else { return FALSE; };
            if PARAMETERS.lock().set_wallpaper(&path) { TRUE } else { FALSE }
        }
    }
}

/// Whether a record whose first word is its own size quotes an admitted one.
/// # C: O(1)
fn leading_size_admitted(action: u32, ptr: u64) -> bool {
    if !size_word_leads(action) { return ptr != 0; }
    if ptr == 0 { return false; }
    uaccess::get_user_u32(ptr).is_ok_and(|size| record_size_admitted(action, size))
}

/// Records whose first word is the caller's own quoted size. # C: O(1)
fn size_word_leads(action: u32) -> bool {
    use ipc::win32_sysparams::action as a;
    matches!(action, a::GET_MINIMIZED_METRICS | a::SET_MINIMIZED_METRICS | a::GET_ICON_METRICS | a::SET_ICON_METRICS)
}

fn write_words(ptr: u64, values: &[u32]) -> u64 {
    if ptr == 0 { return FALSE; }
    for (index, value) in values.iter().enumerate() {
        let Some(address) = ptr.checked_add(index as u64 * 4) else { return FALSE; };
        if uaccess::copy_to_user(address, &value.to_le_bytes()).is_err() { return FALSE; }
    }
    TRUE
}

/// The icon-title face: the one a client wrote, or the profile's own message
/// face while none was written. # C: O(1)
fn write_font(ptr: u64) -> u64 {
    if ptr == 0 { return FALSE; }
    let stored = PARAMETERS.lock().icon_font().copied();
    let bytes = match stored {
        Some(bytes) => bytes,
        None => match ipc::win32_gdi::logfont(ipc::win32_gdi::NonclientFont::Message) { Ok(bytes) => bytes, Err(_) => return FALSE },
    };
    if uaccess::copy_to_user(ptr, &bytes).is_err() { return FALSE; }
    TRUE
}

/// The stored wallpaper path, bounded by the caller's own unit count and
/// always NUL-terminated. # C: O(N_units)
fn write_path(ptr: u64, units: usize) -> u64 {
    if ptr == 0 || units == 0 { return FALSE; }
    let path = { let store = PARAMETERS.lock(); let path = store.wallpaper(); let mut owned = Vec::new();
        if owned.try_reserve_exact(path.len()).is_err() { return FALSE; } owned.extend_from_slice(path); owned };
    let copied = path.len().min(units - 1);
    for (index, unit) in path.iter().take(copied).enumerate() {
        let Some(address) = ptr.checked_add(index as u64 * 2) else { return FALSE; };
        if uaccess::copy_to_user(address, &unit.to_le_bytes()).is_err() { return FALSE; }
    }
    let Some(terminator) = ptr.checked_add(copied as u64 * 2) else { return FALSE; };
    if uaccess::copy_to_user(terminator, &[0, 0]).is_err() { return FALSE; }
    TRUE
}

fn read_words(ptr: u64, count: usize, skip: u32, sized: Option<u32>, action: u32) -> Option<Vec<i32>> {
    if ptr == 0 { return None; }
    if let Some(expected) = sized {
        let size = uaccess::get_user_u32(ptr).ok()?;
        if size != expected || !record_size_admitted(action, size) { return None; }
    }
    let mut values = Vec::new();
    values.try_reserve_exact(count).ok()?;
    for index in 0..count {
        let address = ptr.checked_add(u64::from(skip) + index as u64 * 4)?;
        values.push(uaccess::get_user_u32(address).ok()? as i32);
    }
    Some(values)
}

fn read_font(ptr: u64) -> Option<[u8; LOGFONTW_BYTES]> {
    if ptr == 0 { return None; }
    ptr.checked_add(LOGFONTW_BYTES as u64)?;
    let mut bytes = [0; LOGFONTW_BYTES];
    uaccess::copy_from_user(&mut bytes, ptr).ok()?;
    Some(bytes)
}

fn read_path(ptr: u64) -> Option<Vec<u16>> {
    if ptr == 0 { return None; }
    let mut units = Vec::new();
    units.try_reserve_exact(MAX_PATH_UNITS).ok()?;
    for index in 0..MAX_PATH_UNITS {
        let address = ptr.checked_add(index as u64 * 2)?;
        let mut bytes = [0u8; 2];
        uaccess::copy_from_user(&mut bytes, address).ok()?;
        let unit = u16::from_le_bytes(bytes);
        if unit == 0 { return Some(units); }
        units.push(unit);
    }
    Some(units)
}
