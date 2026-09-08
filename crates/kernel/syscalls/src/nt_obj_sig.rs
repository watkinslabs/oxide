//! Argument widths and positions for the object, synchronisation and
//! completion services.
//!
//! A stock service stub passes the first four arguments in registers and every
//! later one in a word of the caller's own frame. A `ULONG` stored there is a
//! 32-bit store, so the slot's upper half keeps whatever the frame held
//! before; a `BOOLEAN` is one byte, so the rest of the word is not part of the
//! value at all. Reading the whole word turns a caller's count into a value
//! derived from the previous frame and reads FALSE as TRUE.
//!
//! Pointer, `SIZE_T`, `ULONG_PTR` and handle arguments are full words and are
//! never narrowed here; a handle keeps its pseudo-handle values.
//!
//! Ungated so each service's positions and widths are testable without a
//! target build.

/// The `ULONG` a caller passed, discarding the word's upper half.
/// # C: O(1)
pub const fn ulong(raw: u64) -> u32 { raw as u32 }

/// The signed `LONG` a caller passed.
/// # C: O(1)
pub const fn long(raw: u64) -> i32 { raw as u32 as i32 }

/// The `BOOLEAN` a caller passed: one byte, and any nonzero value is true.
/// # C: O(1)
pub const fn boolean(raw: u64) -> bool { raw as u8 != 0 }

/// The handle-table value a caller passed. Handles are full words, so a
/// pseudo-handle keeps its value and is resolved by the handle owner rather
/// than refused for its width.
/// # C: O(1)
pub const fn handle(raw: u64) -> u32 { raw as u32 }

/// `NtSetTimer(handle, when, callback, arg, resume, period, state)`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetTimer { pub handle: u32, pub when: u64, pub callback: u64, pub argument: u64,
    pub resume: bool, pub period: u32, pub state: u64 }

/// # C: O(1)
pub const fn set_timer(a: [u64; 7]) -> SetTimer {
    SetTimer { handle: handle(a[0]), when: a[1], callback: a[2], argument: a[3],
        resume: boolean(a[4]), period: ulong(a[5]), state: a[6] }
}

/// `NtSetIoCompletion(handle, key, value, status, count)`. The key, value and
/// count are pointer-width; the status is a 32-bit `NTSTATUS`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SetIoCompletion { pub handle: u32, pub key: u64, pub value: u64, pub status: u32, pub information: u64 }

/// # C: O(1)
pub const fn set_io_completion(a: [u64; 5]) -> SetIoCompletion {
    SetIoCompletion { handle: handle(a[0]), key: a[1], value: a[2], status: ulong(a[3]), information: a[4] }
}

/// `NtRemoveIoCompletion(handle, key, value, io, timeout)`; every argument
/// after the handle is an output or timeout pointer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RemoveIoCompletion { pub handle: u32, pub key: u64, pub value: u64, pub io: u64, pub timeout: u64 }

/// # C: O(1)
pub const fn remove_io_completion(a: [u64; 5]) -> RemoveIoCompletion {
    RemoveIoCompletion { handle: handle(a[0]), key: a[1], value: a[2], io: a[3], timeout: a[4] }
}

/// `NtRemoveIoCompletionEx(handle, info, count, written, timeout, alertable)`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RemoveIoCompletionEx { pub handle: u32, pub info: u64, pub count: u32, pub written: u64,
    pub timeout: u64, pub alertable: bool }

/// # C: O(1)
pub const fn remove_io_completion_ex(a: [u64; 6]) -> RemoveIoCompletionEx {
    RemoveIoCompletionEx { handle: handle(a[0]), info: a[1], count: ulong(a[2]), written: a[3],
        timeout: a[4], alertable: boolean(a[5]) }
}

/// `NtDuplicateObject(source_process, source, target_process, target, access,
/// attributes, options)`. The three handles keep their full words so a
/// pseudo-handle reaches the handle owner.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DuplicateObject { pub source_process: u64, pub source: u32, pub target_process: u64,
    pub target: u64, pub access: u32, pub attributes: u32, pub options: u32 }

/// # C: O(1)
pub const fn duplicate_object(a: [u64; 7]) -> DuplicateObject {
    DuplicateObject { source_process: a[0], source: handle(a[1]), target_process: a[2], target: a[3],
        access: ulong(a[4]), attributes: ulong(a[5]), options: ulong(a[6]) }
}

/// `NtCreateSemaphore(handle, access, attributes, initial, maximum)`: the two
/// counts are signed 32-bit values, the second of them a frame word.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CreateSemaphore { pub handle: u64, pub access: u32, pub attributes: u64, pub initial: i32, pub maximum: i32 }

/// # C: O(1)
pub const fn create_semaphore(a: [u64; 5]) -> CreateSemaphore {
    CreateSemaphore { handle: a[0], access: ulong(a[1]), attributes: a[2], initial: long(a[3]), maximum: long(a[4]) }
}

/// `NtQueryInformationAtom(atom, class, buffer, size, return_size)`: an atom
/// is sixteen bits wide.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct QueryInformationAtom { pub atom: u16, pub class: u32, pub buffer: u64, pub size: u32, pub return_size: u64 }

/// # C: O(1)
pub const fn query_information_atom(a: [u64; 5]) -> QueryInformationAtom {
    QueryInformationAtom { atom: a[0] as u16, class: ulong(a[1]), buffer: a[2], size: ulong(a[3]), return_size: a[4] }
}

/// `NtNotifyChangeKey(key, event, apc, apc_context, io, filter, subtree,
/// buffer, length, async)`: the last four arguments are frame words, two of
/// them one-byte booleans.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NotifyChangeKey { pub key: u32, pub event: u32, pub apc: u64, pub apc_context: u64,
    pub io: u64, pub filter: u32, pub subtree: bool, pub buffer: u64, pub length: u32, pub asynchronous: bool }

/// # C: O(1)
pub const fn notify_change_key(a: [u64; 10]) -> NotifyChangeKey {
    NotifyChangeKey { key: handle(a[0]), event: handle(a[1]), apc: a[2], apc_context: a[3], io: a[4],
        filter: ulong(a[5]), subtree: boolean(a[6]), buffer: a[7], length: ulong(a[8]), asynchronous: boolean(a[9]) }
}

#[cfg(test)]
#[path = "tests/nt_obj_sig.rs"]
mod tests;
