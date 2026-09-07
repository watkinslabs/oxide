//! Window-station and desktop ordinals. The NT object namespace owns the
//! objects; this module decodes the object attributes and encodes handles.

pub(crate) const CLOSE_DESKTOP: u64 = 0x1352;
pub(crate) const CLOSE_WINDOW_STATION: u64 = 0x1353;
pub(crate) const CREATE_DESKTOP_EX: u64 = 0x1362;
pub(crate) const CREATE_WINDOW_STATION: u64 = 0x136d;
pub(crate) const BUILD_NAME_LIST: u64 = 0x132e;
pub(crate) const GET_OBJECT_INFORMATION: u64 = 0x1420;
pub(crate) const GET_PROCESS_WINDOW_STATION: u64 = 0x1437;
pub(crate) const GET_THREAD_DESKTOP: u64 = 0x144d;
pub(crate) const OPEN_DESKTOP: u64 = 0x14c3;
pub(crate) const OPEN_INPUT_DESKTOP: u64 = 0x14c4;
pub(crate) const OPEN_WINDOW_STATION: u64 = 0x14c6;
pub(crate) const SET_OBJECT_INFORMATION: u64 = 0x1573;
pub(crate) const SET_PROCESS_WINDOW_STATION: u64 = 0x157d;
pub(crate) const SET_THREAD_DESKTOP: u64 = 0x158f;
pub(crate) const SWITCH_DESKTOP: u64 = 0x15c9;

/// `OBJECT_ATTRIBUTES`: its length, the root directory, the name and the
/// attribute flags.
pub(crate) const OBJECT_ATTRIBUTES_ROOT: u64 = 8;
pub(crate) const OBJECT_ATTRIBUTES_NAME: u64 = 16;
pub(crate) const OBJECT_ATTRIBUTES_FLAGS: u64 = 24;

/// Object-information classes.
pub(crate) const UOI_FLAGS: i32 = 1;
pub(crate) const UOI_NAME: i32 = 2;
pub(crate) const UOI_TYPE: i32 = 3;
pub(crate) const UOI_USER_SID: i32 = 4;

/// `USEROBJECTFLAGS`: whether handles inherit, a reserved word and the flags.
pub(crate) const USEROBJECTFLAGS_BYTES: u32 = 12;
pub(crate) const USEROBJECTFLAGS_INHERIT: u64 = 0;
pub(crate) const USEROBJECTFLAGS_FLAGS: u64 = 8;

/// Rights every desktop open adds, whatever the caller asked for.
pub(crate) const DESKTOP_READOBJECTS: u32 = 0x0001;
pub(crate) const DESKTOP_WRITEOBJECTS: u32 = 0x0080;

/// A name longer than this cannot address a station or desktop.
pub(crate) const MAX_OBJECT_NAME: usize = 260;

/// Win32 errors this family reports.
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
pub(crate) const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub(crate) const ERROR_BUFFER_OVERFLOW: u32 = 111;
pub(crate) const ERROR_FILENAME_EXCED_RANGE: u32 = 206;

/// Type names the information query answers, as UTF-16 with terminators.
pub(crate) const DESKTOP_TYPE_NAME: [u16; 8] = [b'D' as u16, b'e' as u16, b's' as u16, b'k' as u16,
    b't' as u16, b'o' as u16, b'p' as u16, 0];
pub(crate) const STATION_TYPE_NAME: [u16; 14] = [b'W' as u16, b'i' as u16, b'n' as u16, b'd' as u16,
    b'o' as u16, b'w' as u16, b'S' as u16, b't' as u16, b'a' as u16, b't' as u16, b'i' as u16,
    b'o' as u16, b'n' as u16, 0];

/// Whether one ordinal belongs to this family. # C: O(1)
pub(crate) const fn claims(ordinal: u64) -> bool {
    matches!(ordinal, CLOSE_DESKTOP | CLOSE_WINDOW_STATION | CREATE_DESKTOP_EX | CREATE_WINDOW_STATION
        | BUILD_NAME_LIST | GET_OBJECT_INFORMATION | GET_PROCESS_WINDOW_STATION | GET_THREAD_DESKTOP
        | OPEN_DESKTOP | OPEN_INPUT_DESKTOP | OPEN_WINDOW_STATION | SET_OBJECT_INFORMATION
        | SET_PROCESS_WINDOW_STATION | SET_THREAD_DESKTOP | SWITCH_DESKTOP)
}

/// A desktop open always carries the read and write rights, whatever the
/// caller asked for. # C: O(1)
pub(crate) const fn desktop_access(requested: u32) -> u32 {
    requested | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS
}

/// Whether a name length in bytes is addressable. # C: O(1)
pub(crate) const fn name_length_ok(bytes: u16) -> bool { (bytes as usize) < MAX_OBJECT_NAME * 2 }

/// A desktop creation refuses a display device name, and refuses a display
/// mode unless the caller asked for a virtual desktop. # C: O(1)
pub(crate) const fn admit_desktop_creation(device_length: u16, devmode: u64, flags: u32) -> bool {
    const DF_WINE_VIRTUAL_DESKTOP: u32 = 0x8000_0000;
    if device_length != 0 { return false; }
    if devmode != 0 && flags & DF_WINE_VIRTUAL_DESKTOP == 0 { return false; }
    true
}

/// Which type name one object answers, and the error a short buffer reports.
/// # C: O(1)
pub(crate) const fn type_name(is_desktop: bool) -> &'static [u16] {
    if is_desktop { &DESKTOP_TYPE_NAME } else { &STATION_TYPE_NAME }
}

/// Whether an information query can answer at all, and with which error when
/// the caller's buffer is too small. A flags query reports overflow; every
/// other class reports an insufficient buffer. # C: O(1)
pub(crate) const fn short_buffer_error(class: i32) -> u32 {
    if class == UOI_FLAGS { ERROR_BUFFER_OVERFLOW } else { ERROR_INSUFFICIENT_BUFFER }
}

/// Whether one information class is answerable. The user identity class is
/// not carried by these objects. # C: O(1)
pub(crate) const fn queryable(class: i32) -> bool {
    matches!(class, UOI_FLAGS | UOI_NAME | UOI_TYPE)
}

/// Only the flags class is settable. # C: O(1)
pub(crate) const fn settable(class: i32, length: u32) -> bool {
    class == UOI_FLAGS && length >= USEROBJECTFLAGS_BYTES
}

#[cfg(target_os = "oxide-kernel")]
#[path = "station_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/station_raw.rs"]
mod tests;
