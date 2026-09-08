//! Which published Unix-call table serves the runtime's own handle.
//!
//! The runtime module reads one fixed handle out of its own data slot and
//! passes it to every Unix call it makes on its own behalf. That handle names
//! the runtime's Unix-side table, not whichever module happened to publish a
//! table first: a process that has loaded another module's Unix side must not
//! have the runtime's calls checked against, or answered from, that module.

/// The name the runtime module's Unix side is published under.
pub const RUNTIME_UNIXLIB_NAME: &[u8] = b"ntdll.so";

/// Entries in the runtime's own Unix-call table. An index outside it names no
/// function in that table.
pub const RUNTIME_FUNCTION_COUNT: u64 = syscall::nt_wine_unix::WINE_UNIX_FUNCTION_COUNT as u64;

/// Table identity serving the runtime's handle: the runtime module's own table
/// when it has been published, and otherwise the only table the process has.
/// # C: O(1)
pub fn runtime_table(runtime_named: Option<u64>, first_published: Option<u64>) -> Option<u64> {
    runtime_named.or(first_published)
}

/// Whether an index names a function in the runtime's own table.
/// # C: O(1)
pub const fn runtime_index_valid(index: u64) -> bool { index < RUNTIME_FUNCTION_COUNT }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runtime_module_owns_its_handle_even_when_another_table_came_first() {
        assert_eq!(runtime_table(Some(0x4000), Some(0x9000)), Some(0x4000));
    }

    #[test]
    fn a_process_with_only_one_published_table_uses_it() {
        assert_eq!(runtime_table(None, Some(0x9000)), Some(0x9000));
        assert_eq!(runtime_table(None, None), None);
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
