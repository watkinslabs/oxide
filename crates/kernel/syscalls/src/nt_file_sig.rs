//! Argument narrowing for the native NT file and object-directory services.
//!
//! A Windows caller passes its first four arguments in registers and every
//! later one in a word of its own frame. A `ULONG` written into such a word is
//! a 32-bit store and a `BOOLEAN` is a one-byte store: the rest of the eight
//! byte slot keeps whatever the frame held before the call. Reading the whole
//! word turns a byte count into a value derived from stale frame contents and
//! turns `FALSE` into `TRUE`, so every scalar a service declares is narrowed
//! to its declared width here, and no scalar is ever refused for exceeding a
//! width its caller never wrote.

use crate::nt_file_args::ulong;

/// The `BOOLEAN` a caller passed in an argument slot. `BOOLEAN` is one byte
/// wide, so only the low byte of the slot belongs to the value. # C: O(1)
pub(crate) const fn boolean(raw: u64) -> bool { raw as u8 != 0 }

/// The `HANDLE` a caller passed, as the process-local table index this kernel
/// mints. Handles are pointer sized and are never refused for being wide.
/// # C: O(1)
pub(crate) const fn handle(raw: u64) -> u32 { raw as u32 }

/// `NtCreateNamedPipeFile` arguments after narrowing. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamedPipeCreate {
    pub(crate) handle_out: u64,
    pub(crate) access: u32,
    pub(crate) attributes: u64,
    pub(crate) io_status: u64,
    pub(crate) sharing: u32,
    pub(crate) disposition: u32,
    pub(crate) options: u32,
    pub(crate) pipe_type: u32,
    pub(crate) read_mode: u32,
    pub(crate) completion_mode: u32,
    pub(crate) max_instances: u32,
    pub(crate) inbound_quota: u32,
    pub(crate) outbound_quota: u32,
    pub(crate) timeout: u64,
}

/// Decode the fourteen `NtCreateNamedPipeFile` arguments: the handle slot, the
/// access mask, the object attributes, the status block, and the nine pipe
/// parameters that follow, then the timeout pointer. # C: O(1)
pub(crate) const fn named_pipe_create(args: [u64; 6], tail: [u64; 8]) -> Option<NamedPipeCreate> {
    if args[0] == 0 || args[2] == 0 { return None; }
    Some(NamedPipeCreate { handle_out: args[0], access: ulong(args[1]), attributes: args[2],
        io_status: args[3], sharing: ulong(args[4]), disposition: ulong(args[5]),
        options: ulong(tail[0]), pipe_type: ulong(tail[1]), read_mode: ulong(tail[2]),
        completion_mode: ulong(tail[3]), max_instances: ulong(tail[4]),
        inbound_quota: ulong(tail[5]), outbound_quota: ulong(tail[6]), timeout: tail[7] })
}

/// `NtReadFile`/`NtWriteFile` arguments after narrowing. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileIo {
    pub(crate) file: u32,
    pub(crate) event: u64,
    pub(crate) io_status: u64,
    pub(crate) buffer: u64,
    pub(crate) length: u32,
    pub(crate) offset_ptr: u64,
}

/// Decode the nine `NtReadFile`/`NtWriteFile` arguments. The byte count is the
/// seventh; the byte offset and the lock key that follow it are pointers.
/// # C: O(1)
pub(crate) const fn file_io(args: [u64; 6], length: u64, offset_ptr: u64) -> Option<FileIo> {
    if args[4] == 0 || args[5] == 0 { return None; }
    Some(FileIo { file: handle(args[0]), event: args[1], io_status: args[4], buffer: args[5],
        length: ulong(length), offset_ptr })
}

/// `NtReadFileScatter`/`NtWriteFileGather` arguments after narrowing. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct SegmentIo {
    pub(crate) file: u32,
    pub(crate) apc_context: u64,
    pub(crate) io_status: u64,
    pub(crate) segments: u64,
    pub(crate) length: u32,
    pub(crate) offset_ptr: u64,
}

/// Decode the nine segmented-transfer arguments. # C: O(1)
pub(crate) const fn segment_io(args: [u64; 6], length: u64, offset_ptr: u64) -> SegmentIo {
    SegmentIo { file: handle(args[0]), apc_context: args[3], io_status: args[4],
        segments: args[5], length: ulong(length), offset_ptr }
}

/// `NtQueryDirectoryObject` arguments after narrowing. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryObjectQuery {
    pub(crate) directory: u32,
    pub(crate) buffer: u64,
    pub(crate) size: u32,
    pub(crate) single_entry: bool,
    pub(crate) restart: bool,
    pub(crate) context: u64,
    pub(crate) return_length: u64,
}

/// Decode the seven `NtQueryDirectoryObject` arguments. The two enumeration
/// flags are `BOOLEAN`, and the context and returned-length slots are pointers
/// the service writes rather than counts it may bound. # C: O(1)
pub(crate) const fn directory_object_query(args: [u64; 6], tail: [u64; 1])
    -> Option<DirectoryObjectQuery> {
    if args[1] == 0 || args[5] == 0 { return None; }
    Some(DirectoryObjectQuery { directory: handle(args[0]), buffer: args[1], size: ulong(args[2]),
        single_entry: boolean(args[3]), restart: boolean(args[4]), context: args[5],
        return_length: tail[0] })
}

/// `NtNotifyChangeDirectoryFile` arguments after narrowing. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryWatch {
    pub(crate) directory: u32,
    pub(crate) event: u32,
    pub(crate) apc: u64,
    pub(crate) apc_context: u64,
    pub(crate) io_status: u64,
    pub(crate) buffer: u64,
    pub(crate) length: u32,
    pub(crate) filter: u32,
    pub(crate) subtree: bool,
}

/// Decode the nine `NtNotifyChangeDirectoryFile` arguments. # C: O(1)
pub(crate) const fn directory_watch(args: [u64; 6], tail: [u64; 3]) -> Option<DirectoryWatch> {
    if args[4] == 0 || args[5] == 0 { return None; }
    Some(DirectoryWatch { directory: handle(args[0]), event: handle(args[1]), apc: args[2],
        apc_context: args[3], io_status: args[4], buffer: args[5], length: ulong(tail[0]),
        filter: ulong(tail[1]), subtree: boolean(tail[2]) })
}

/// `NtLockFile` arguments after narrowing. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileLock {
    pub(crate) file: u32,
    pub(crate) event: u64,
    pub(crate) apc: u64,
    pub(crate) apc_context: u64,
    pub(crate) io_status: u64,
    pub(crate) offset_ptr: u64,
    pub(crate) count_ptr: u64,
    pub(crate) key_ptr: u64,
    pub(crate) dont_wait: bool,
    pub(crate) exclusive: bool,
}

/// Decode the ten `NtLockFile` arguments. The byte range arrives as two
/// pointers to sixty-four-bit values, the key as a pointer, and the two mode
/// flags as `BOOLEAN`. # C: O(1)
pub(crate) const fn file_lock(args: [u64; 6], tail: [u64; 4]) -> Option<FileLock> {
    if args[5] == 0 || tail[0] == 0 { return None; }
    Some(FileLock { file: handle(args[0]), event: args[1], apc: args[2], apc_context: args[3],
        io_status: args[4], offset_ptr: args[5], count_ptr: tail[0], key_ptr: tail[1],
        dont_wait: boolean(tail[2]), exclusive: boolean(tail[3]) })
}

/// `NtUnlockFile` arguments after narrowing. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileUnlock {
    pub(crate) file: u32,
    pub(crate) io_status: u64,
    pub(crate) offset_ptr: u64,
    pub(crate) count_ptr: u64,
    pub(crate) key_ptr: u64,
}

/// Decode the five `NtUnlockFile` arguments; every one after the handle is a
/// pointer. # C: O(1)
pub(crate) const fn file_unlock(args: [u64; 6]) -> Option<FileUnlock> {
    if args[2] == 0 || args[3] == 0 { return None; }
    Some(FileUnlock { file: handle(args[0]), io_status: args[1], offset_ptr: args[2],
        count_ptr: args[3], key_ptr: args[4] })
}

/// `NtQueryInformationFile`/`NtSetInformationFile`/`NtQueryVolumeInformationFile`
/// arguments after narrowing. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileInformation {
    pub(crate) file: u32,
    pub(crate) io_status: u64,
    pub(crate) buffer: u64,
    pub(crate) length: u32,
    pub(crate) class: u32,
}

/// Decode the five information-class arguments shared by the file and volume
/// information services. # C: O(1)
pub(crate) const fn file_information(args: [u64; 6]) -> Option<FileInformation> {
    if args[1] == 0 || args[2] == 0 { return None; }
    Some(FileInformation { file: handle(args[0]), io_status: args[1], buffer: args[2],
        length: ulong(args[3]), class: ulong(args[4]) })
}

/// `NtQueryDirectoryFile` arguments after narrowing. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryEnumeration {
    pub(crate) directory: u32,
    pub(crate) event: u64,
    pub(crate) io_status: u64,
    pub(crate) buffer: u64,
    pub(crate) length: u32,
    pub(crate) class: u32,
    pub(crate) single_entry: bool,
    pub(crate) mask: u64,
    pub(crate) restart: bool,
}

/// Decode the eleven `NtQueryDirectoryFile` arguments. # C: O(1)
pub(crate) const fn directory_enumeration(args: [u64; 6], tail: [u64; 5])
    -> Option<DirectoryEnumeration> {
    if args[4] == 0 || args[5] == 0 { return None; }
    Some(DirectoryEnumeration { directory: handle(args[0]), event: args[1], io_status: args[4],
        buffer: args[5], length: ulong(tail[0]), class: ulong(tail[1]),
        single_entry: boolean(tail[2]), mask: tail[3], restart: boolean(tail[4]) })
}

/// `NtDeviceIoControlFile`/`NtFsControlFile` arguments after narrowing.
/// # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceControl {
    pub(crate) file: u32,
    pub(crate) event: u64,
    pub(crate) apc_context: u64,
    pub(crate) io_status: u64,
    pub(crate) code: u32,
    pub(crate) input: u64,
    pub(crate) input_length: u32,
    pub(crate) output: u64,
    pub(crate) output_length: u32,
}

/// Decode the ten control-transfer arguments. # C: O(1)
pub(crate) const fn device_control(args: [u64; 6], tail: [u64; 4]) -> Option<DeviceControl> {
    if args[4] == 0 { return None; }
    Some(DeviceControl { file: handle(args[0]), event: args[1], apc_context: args[3],
        io_status: args[4], code: ulong(args[5]), input: tail[0], input_length: ulong(tail[1]),
        output: tail[2], output_length: ulong(tail[3]) })
}

#[cfg(test)]
#[path = "tests/nt_file_sig.rs"]
mod tests;
