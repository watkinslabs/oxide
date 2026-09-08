//! Who serves the runtime module's own Unix-call handle.
//!
//! The runtime module reads one fixed handle out of its own data slot and
//! passes it to every Unix call it makes on its own behalf. On this system the
//! functions behind that handle are implemented by the kernel, not by a guest
//! Unix-side object: the handle names the kernel's own table.
//!
//! That matters because a process may have published some other module's
//! Unix-side table. Answering the runtime's handle out of whichever table
//! happened to be published first would route the runtime's calls into a
//! stranger's function list, and requiring such a table to exist would make
//! the runtime's own calls fail in a process that has published none.

/// Entries in the runtime's own Unix-call table. An index outside it names no
/// function in that table.
pub const RUNTIME_FUNCTION_COUNT: u64 = syscall::nt_wine_unix::WINE_UNIX_FUNCTION_COUNT as u64;

/// Where one Unix call is served.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixCallOwner {
    /// The kernel's own function table answers this call. No guest object is
    /// consulted, so no published table has to exist for the call to work.
    Kernel,
    /// A guest Unix-side object published this table; the call enters it.
    Published(u64),
}

/// Which table serves one `__wine_unix_call`. The runtime's fixed handle is
/// the kernel's table; every other handle is a table identity a guest object
/// published and is answered by entering that object.
/// # C: O(1)
pub fn owner_of(handle: u64, runtime_handle: u64) -> UnixCallOwner {
    if handle == runtime_handle { UnixCallOwner::Kernel } else { UnixCallOwner::Published(handle) }
}

/// Whether an index names a function in the runtime's own table.
/// # C: O(1)
pub const fn runtime_index_valid(index: u64) -> bool { index < RUNTIME_FUNCTION_COUNT }

#[cfg(test)]
mod tests {
    use super::*;
    const RUNTIME: u64 = syscall::nt::WINE_UNIXLIB_HANDLE;

    #[test]
    fn the_runtime_handle_is_served_by_the_kernel_table() {
        assert_eq!(owner_of(RUNTIME, RUNTIME), UnixCallOwner::Kernel);
    }

    #[test]
    fn the_runtime_handle_needs_no_guest_object_to_have_published_a_table() {
        // A process that has published nothing still serves the runtime's own
        // calls: the previous contract resolved this handle to "the first
        // table published" and failed the call when there was none.
        assert_eq!(owner_of(RUNTIME, RUNTIME), UnixCallOwner::Kernel);
        assert_ne!(owner_of(RUNTIME, RUNTIME), UnixCallOwner::Published(RUNTIME));
    }

    #[test]
    fn another_modules_table_is_entered_rather_than_answered_by_the_kernel() {
        assert_eq!(owner_of(0x9000, RUNTIME), UnixCallOwner::Published(0x9000));
        assert_eq!(owner_of(0x4000, RUNTIME), UnixCallOwner::Published(0x4000));
    }

    #[test]
    fn the_runtime_table_holds_the_reference_function_count() {
        assert_eq!(RUNTIME_FUNCTION_COUNT, 8);
        assert!(runtime_index_valid(0));
        assert!(runtime_index_valid(7));
        assert!(!runtime_index_valid(8));
        assert!(!runtime_index_valid(u64::MAX));
    }
}
