//! System-parameter ingress: the four arguments of the system-parameters
//! ordinal, what each action carries in from user memory, and the bounded
//! nonclient-metrics redirect. The values themselves belong to the settings
//! owner; this module decides only what one call must transfer.
//!
//! Module manifest: `kernel` performs the transfers and reaches the store.
pub(crate) const SYSTEM_PARAMETERS_INFO: u64 = 0x15cb;
pub(crate) const GET_NONCLIENT_METRICS: u32 = ipc::win32_sysparams::action::GET_NONCLIENT_METRICS;
pub(crate) const LEGACY_BYTES: u32 = ipc::win32_gdi::NONCLIENT_LEGACY_BYTES as u32;
pub(crate) const MODERN_BYTES: u32 = ipc::win32_gdi::NONCLIENT_BYTES as u32;
/// Bytes one `LOGFONTW` occupies.
pub(crate) const FONT_BYTES: u32 = ipc::win32_gdi::LOGFONTW_BYTES as u32;
/// Bytes the icon-metrics record occupies: its size word, three dimensions,
/// then the face.
pub(crate) const ICON_METRICS_BYTES: u32 = 16 + FONT_BYTES;
/// Bytes the minimized-metrics record occupies: its size word and four values.
pub(crate) const MINIMIZED_METRICS_BYTES: u32 = 20;
/// Units a wallpaper path may carry, as the reference bounds one.
pub(crate) const MAX_PATH_UNITS: usize = 260;

/// The four arguments the ordinal carries.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Call { pub action: u32, pub val: u32, pub ptr: u64, pub winini: u32 }

/// What one action reads out of user memory before the settings owner may be
/// asked to apply it. A reading action carries nothing in.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Carrier {
    /// Nothing: the call's `uiParam` is the whole input.
    None,
    /// This many four-byte words, starting at `pvParam` plus `skip` bytes.
    Words { count: usize, skip: u32, sized: Option<u32> },
    /// One `LOGFONTW` at `pvParam`.
    Font,
    /// Three dimensions and a face, behind the record's size word.
    IconMetrics,
    /// A whole nonclient record, whose own size word bounds it.
    Nonclient,
    /// A NUL-terminated path at `pvParam`.
    Path,
}

/// Decode the ordinal's arguments. None means this family does not own the
/// call, which is the only way the ordinal may be left unclaimed.
/// # C: O(1)
pub(crate) fn decode(ordinal: u64, args: &[u64]) -> Option<Call> {
    if ordinal != SYSTEM_PARAMETERS_INFO || args.len() < 4 { return None; }
    Some(Call { action: args[0] as u32, val: args[1] as u32, ptr: args[2], winini: args[3] as u32 })
}

/// What a writing action brings in from user memory. A reading action, and any
/// action the settings owner names no entry for, carries nothing.
/// # C: O(1)
pub(crate) fn carrier(action: u32) -> Carrier {
    use ipc::win32_sysparams::action as a;
    match action {
        a::SET_MOUSE => Carrier::Words { count: 3, skip: 0, sized: None },
        a::SET_MINIMIZED_METRICS => Carrier::Words { count: 4, skip: 4, sized: Some(MINIMIZED_METRICS_BYTES) },
        a::SET_ICON_METRICS => Carrier::IconMetrics,
        a::SET_ICON_TITLE_LOGFONT => Carrier::Font,
        a::SET_NONCLIENT_METRICS => Carrier::Nonclient,
        a::SET_DESK_WALLPAPER => Carrier::Path,
        _ => Carrier::None,
    }
}

/// Whether one record's own size word admits the record. A caller that quotes
/// a size the record cannot have is refused before any transfer.
/// # C: O(1)
pub(crate) fn record_size_admitted(action: u32, size: u32) -> bool {
    use ipc::win32_sysparams::action as a;
    match action {
        a::GET_NONCLIENT_METRICS | a::SET_NONCLIENT_METRICS => matches!(size, LEGACY_BYTES | MODERN_BYTES),
        a::GET_ICON_METRICS | a::SET_ICON_METRICS => size == ICON_METRICS_BYTES,
        a::GET_MINIMIZED_METRICS | a::SET_MINIMIZED_METRICS => size == MINIMIZED_METRICS_BYTES,
        _ => true,
    }
}

/// Decode before usercopy; caller record cbSize, not uiParam, controls output length.
/// # C: O(1) plus four-byte read and one native owner call
pub(crate) fn route(ordinal: u64, args: &[u64], read_size: impl FnOnce(u64) -> Option<u32>,
    begin: impl FnOnce(u64, u32) -> u64) -> Option<u64> {
    let call = decode(ordinal, args)?;
    if call.action != GET_NONCLIENT_METRICS { return None; }
    if call.ptr == 0 || call.ptr.checked_add(4).is_none() { return Some(0); }
    let Some(size) = read_size(call.ptr) else { return Some(0); };
    if !record_size_admitted(call.action, size) || call.ptr.checked_add(size as u64).is_none() { return Some(0); }
    Some(begin(call.ptr, size))
}

#[cfg(target_os = "oxide-kernel")]
#[path = "nonclient_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/nonclient_raw.rs"]
mod tests;
