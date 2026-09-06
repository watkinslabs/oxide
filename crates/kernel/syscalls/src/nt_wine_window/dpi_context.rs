//! Process DPI awareness context: `NtUserGetProcessDpiAwarenessContext` and
//! `NtUserSetProcessDpiAwarenessContext`. The context word packs awareness,
//! version, DPI and flags; an unset process answers the unaware context.
pub(crate) const GET_ORDINAL: u64 = 0x1435;
pub(crate) const SET_ORDINAL: u64 = 0x1577;
/// `GetCurrentProcess()` pseudo-handle.
pub(crate) const CURRENT_PROCESS: u64 = u64::MAX;
pub(crate) const USER_DEFAULT_SCREEN_DPI: u32 = 96;
const AWARENESS_UNAWARE: u32 = 0;
const AWARENESS_SYSTEM: u32 = 1;
const AWARENESS_PER_MONITOR: u32 = 2;
const FLAG_GDISCALED: u32 = 0x4000_0000;
const FLAG_PROCESS: u32 = 0x8000_0000;
const FLAG_VALID_MASK: u32 = FLAG_PROCESS | FLAG_GDISCALED;
pub(crate) const ERROR_ACCESS_DENIED: u32 = 5;
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;

/// # C: O(1)
pub(crate) const fn make(awareness: u32, version: u32, dpi: u32, flags: u32) -> u32 { awareness | (version << 4) | (dpi << 8) | flags }
pub(crate) const UNAWARE: u32 = make(AWARENESS_UNAWARE, 1, USER_DEFAULT_SCREEN_DPI, 0);
const fn awareness(ctx: u32) -> u32 { ctx & 0x0f }
const fn version(ctx: u32) -> u32 { (ctx & 0xf0) >> 4 }
const fn dpi(ctx: u32) -> u32 { (ctx & 0x1ff00) >> 8 }
const fn flags(ctx: u32) -> u32 { ctx & 0xfffe_0000 }

/// # C: O(1)
pub(crate) const fn is_valid(ctx: u32, system_dpi: u32) -> bool {
    match awareness(ctx) {
        AWARENESS_UNAWARE => flags(ctx) & !FLAG_VALID_MASK == 0 && version(ctx) == 1 && dpi(ctx) == USER_DEFAULT_SCREEN_DPI,
        AWARENESS_SYSTEM => flags(ctx) & !FLAG_VALID_MASK == 0 && flags(ctx) & FLAG_GDISCALED == 0 && version(ctx) == 1
            && (system_dpi == 0 || dpi(ctx) == system_dpi),
        AWARENESS_PER_MONITOR => flags(ctx) & !FLAG_VALID_MASK == 0 && flags(ctx) & FLAG_GDISCALED == 0
            && (version(ctx) == 1 || version(ctx) == 2) && dpi(ctx) == 0,
        _ => false,
    }
}

/// Another process's context is not reported; an unset context is unaware. # C: O(1)
pub(crate) const fn get(stored: u32, process: u64) -> u32 {
    if process != 0 && process != CURRENT_PROCESS { return UNAWARE; }
    if stored == 0 { UNAWARE } else { stored }
}

/// The context is set once; a second set is refused. Err carries the Win32 error. # C: O(1)
pub(crate) fn set(stored: &mut u32, ctx: u32, system_dpi: u32) -> Result<(), u32> {
    if !is_valid(ctx, system_dpi) { return Err(ERROR_INVALID_PARAMETER); }
    if *stored != 0 { return Err(ERROR_ACCESS_DENIED); }
    *stored = ctx;
    Ok(())
}

#[cfg(target_os = "oxide-kernel")]
#[path = "dpi_context/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path = "tests/dpi_context.rs"]
mod tests;
