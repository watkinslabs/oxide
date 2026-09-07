//! Display ordinal numbers and the pure decisions each entry makes.

pub(crate) const CHANGE_DISPLAY_SETTINGS: u64 = 0x1342;
pub(crate) const DISPLAY_CONFIG_GET_DEVICE_INFO: u64 = 0x138c;
pub(crate) const ENUM_DISPLAY_DEVICES: u64 = 0x13bf;
pub(crate) const ENUM_DISPLAY_MONITORS: u64 = 0x13c0;
pub(crate) const ENUM_DISPLAY_SETTINGS: u64 = 0x13c1;
pub(crate) const GET_DISPLAY_CONFIG_BUFFER_SIZES: u64 = 0x13f4;
pub(crate) const GET_DPI_FOR_MONITOR: u64 = 0x13f7;
pub(crate) const IS_CHILD_WINDOW_DPI_MESSAGE_ENABLED: u64 = 0x148e;
pub(crate) const LOGICAL_TO_PHYSICAL_POINT: u64 = 0x14a7;
pub(crate) const PHYSICAL_TO_LOGICAL_POINT: u64 = 0x14cb;
pub(crate) const QUERY_DISPLAY_CONFIG: u64 = 0x14db;
pub(crate) const SYSTEM_PARAMETERS_INFO_FOR_DPI: u64 = 0x15cc;
pub(crate) const GET_PROCESS_DEFAULT_LAYOUT: u64 = 0x1434;
pub(crate) const SET_PROCESS_DEFAULT_LAYOUT: u64 = 0x1576;

pub(crate) const ERROR_BAD_ARGUMENTS: u32 = 160;
pub(crate) const ERROR_INVALID_ADDRESS: u32 = 487;
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
pub(crate) const ERROR_NOACCESS: u32 = 998;
pub(crate) const ERROR_NO_MORE_FILES: u32 = 18;
pub(crate) const ERROR_SUCCESS: u32 = 0;
pub(crate) const ERROR_NOT_SUPPORTED: u32 = 50;

/// `ChangeDisplaySettings` outcomes.
pub(crate) const DISP_CHANGE_SUCCESSFUL: u64 = 0;
pub(crate) const DISP_CHANGE_BADMODE: u64 = 0xffff_ffff_ffff_ffff;
pub(crate) const DISP_CHANGE_BADPARAM: u64 = 0xffff_ffff_ffff_fffb;
/// `CDS_TEST` and `CDS_NORESET` ask whether a mode is possible without applying it.
#[allow(dead_code)] // KI-0530: ChangeDisplaySettings does not yet persist CDS_UPDATEREGISTRY
pub(crate) const CDS_UPDATEREGISTRY: u32 = 0x0000_0001;
pub(crate) const CDS_TEST: u32 = 0x0000_0002;
pub(crate) const CDS_NORESET: u32 = 0x0001_0000;

/// Monitor DPI types: effective, angular and raw. Anything higher names none.
pub(crate) const MDT_MAXIMUM: u32 = 2;
pub(crate) const USER_DEFAULT_SCREEN_DPI: u32 = 96;

/// Which DPI a monitor query reports, given the caller's awareness. An unaware
/// caller always sees the default screen DPI and a system-aware caller always
/// sees the system DPI, whichever monitor was named. # C: O(1)
pub(crate) const fn monitor_dpi(awareness: u32, system_dpi: u32, monitor_dpi: u32) -> u32 {
    match awareness { 0 => USER_DEFAULT_SCREEN_DPI, 1 => system_dpi, _ => monitor_dpi }
}

/// A point conversion applies only inside the window it names. # C: O(1)
pub(crate) const fn point_inside(point: (i32, i32), rect: ipc::win32_window::WindowRect) -> bool {
    point.0 >= rect.left && point.1 >= rect.top && point.0 <= rect.right && point.1 <= rect.bottom
}

/// A mode is accepted when every field the request names matches one the
/// display can produce. A request naming no field accepts the current mode.
/// # C: O(1)
pub(crate) const fn mode_matches(requested: (u32, u32, u32, u32), available: (u32, u32, u32, u32)) -> bool {
    (requested.0 == 0 || requested.0 == available.0)
        && (requested.1 == 0 || requested.1 == available.1)
        && (requested.2 == 0 || requested.2 == available.2)
        && (requested.3 == 0 || requested.3 == available.3)
}

/// A test or no-reset request never applies the mode it names. # C: O(1)
pub(crate) const fn applies_mode(flags: u32) -> bool { flags & (CDS_TEST | CDS_NORESET) == 0 }

#[cfg(test)]
#[path = "../tests/display_raw.rs"]
mod tests;
