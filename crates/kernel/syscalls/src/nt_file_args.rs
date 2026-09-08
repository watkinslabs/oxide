//! Argument records for the native NT file services.
//!
//! The shipped runtime passes its first four arguments in registers and every
//! later one in a word of its own frame. A `ULONG` argument written into such
//! a word is a 32-bit store: the upper half of the eight-byte slot keeps
//! whatever the frame held before the call. Reading the whole word and
//! refusing values above `u32::MAX` therefore refuses a perfectly ordinary
//! call — the share mode and open options of every module the loader opens
//! arrive that way, and refusing them fails process startup before any path
//! is looked up.

/// The `ULONG` a caller passed in an argument slot, discarding the upper half
/// of the slot, which is not part of the value. # C: O(1)
pub(crate) const fn ulong(raw: u64) -> u32 { raw as u32 }

/// `NtOpenFile` arguments after narrowing. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeOpen {
    pub(crate) handle_out: u64,
    pub(crate) desired: u32,
    pub(crate) attributes: u64,
    pub(crate) io_status: u64,
    pub(crate) share: u32,
    pub(crate) options: u32,
}

/// Decode the six `NtOpenFile` arguments. Only the two output pointers the
/// service must write are required; every scalar narrows. # C: O(1)
pub(crate) const fn native_open(args: [u64; 6]) -> Option<NativeOpen> {
    if args[0] == 0 || args[2] == 0 { return None; }
    Some(NativeOpen { handle_out: args[0], desired: ulong(args[1]), attributes: args[2],
        io_status: args[3], share: ulong(args[4]), options: ulong(args[5]) })
}

/// `NtCreateFile` arguments after narrowing. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeCreate {
    pub(crate) handle_out: u64,
    pub(crate) desired: u32,
    pub(crate) attributes: u64,
    pub(crate) io_status: u64,
    pub(crate) file_attributes: u32,
    pub(crate) share: u32,
    pub(crate) disposition: u32,
    pub(crate) options: u32,
}

/// Decode `NtCreateFile`: six register-or-frame arguments plus the share
/// mode, disposition, and options that follow them in the caller's frame.
/// # C: O(1)
pub(crate) const fn native_create(args: [u64; 6], share: u64, disposition: u64, options: u64)
    -> Option<NativeCreate> {
    if args[0] == 0 || args[2] == 0 { return None; }
    Some(NativeCreate { handle_out: args[0], desired: ulong(args[1]), attributes: args[2],
        io_status: args[3], file_attributes: ulong(args[5]), share: ulong(share),
        disposition: ulong(disposition), options: ulong(options) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upper halves the caller never wrote. A frame word left over from an
    /// earlier call carries them, and none of them belongs to the value.
    const STALE_HIGH: u64 = 0x7fff_0a00_0000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const GENERIC_READ: u32 = 0x8000_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_TRAVERSE: u32 = 0x0000_0020;

    /// The open a loader makes for every module candidate on its search path.
    #[test]
    fn a_module_open_survives_stale_upper_halves_in_its_frame_words() {
        let share = FILE_SHARE_READ | FILE_SHARE_DELETE;
        let options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE;
        let decoded = native_open([0x1000, (GENERIC_READ | SYNCHRONIZE) as u64, 0x2000, 0x3000,
            STALE_HIGH | share as u64, STALE_HIGH | options as u64]).unwrap();
        assert_eq!(decoded.share, share);
        assert_eq!(decoded.options, options);
        assert_eq!(decoded.desired, GENERIC_READ | SYNCHRONIZE);
        assert_eq!(decoded.handle_out, 0x1000);
        assert_eq!(decoded.attributes, 0x2000);
        assert_eq!(decoded.io_status, 0x3000);
    }

    /// The open a runtime makes for its own working directory.
    #[test]
    fn a_working_directory_open_survives_stale_upper_halves_in_its_frame_words() {
        let options = FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
        let decoded = native_open([0x1000, (FILE_TRAVERSE | SYNCHRONIZE) as u64, 0x2000, 0,
            STALE_HIGH | 3, STALE_HIGH | options as u64]).unwrap();
        assert_eq!(decoded.options, options);
        assert_eq!(decoded.share, 3);
        assert_eq!(decoded.io_status, 0);
    }

    #[test]
    fn an_open_without_its_output_pointers_is_not_a_call() {
        assert_eq!(native_open([0, 0, 0x2000, 0, 0, 0]), None);
        assert_eq!(native_open([0x1000, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn create_narrows_every_frame_carried_scalar() {
        let decoded = native_create([0x1000, 0x8000_0000, 0x2000, 0x3000, 0x4000, STALE_HIGH | 0x80],
            STALE_HIGH | 7, STALE_HIGH | 5, STALE_HIGH | 0x60).unwrap();
        assert_eq!(decoded.file_attributes, 0x80);
        assert_eq!(decoded.share, 7);
        assert_eq!(decoded.disposition, 5);
        assert_eq!(decoded.options, 0x60);
        assert_eq!(decoded.desired, 0x8000_0000);
        assert_eq!(native_create([0, 0, 0x2000, 0, 0, 0], 0, 1, 0), None);
    }

    #[test]
    fn narrowing_keeps_the_whole_thirty_two_bit_value() {
        assert_eq!(ulong(0xffff_ffff), u32::MAX);
        assert_eq!(ulong(STALE_HIGH | 0xffff_ffff), u32::MAX);
        assert_eq!(ulong(STALE_HIGH), 0);
    }
}
