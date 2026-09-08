//! The system-wide HWND value space.
//!
//! A window handle names a window for every process on the desktop, not only
//! for the one that created it: the desktop window is resolved by handle in
//! processes that never created a window at all, and clipboard, input-context
//! and desktop ownership all resolve one handle to one window. A per-process
//! counter cannot carry that meaning — two processes both numbering from one
//! give two different windows the same handle, and every cross-process
//! resolution then answers whichever process was recorded first.
//!
//! The space is therefore partitioned once: each window owner draws its
//! handles from a block of its own, so a value identifies both the owner and
//! the window within it. Block zero belongs to the window server itself and
//! holds the desktop windows, which no application owns.

/// Handles one owner's block can carry, as a power of two.
pub const BLOCK_BITS: u32 = 20;
/// Handle values in one owner's block.
pub const BLOCK_SIZE: u32 = 1 << BLOCK_BITS;
/// Highest block the 32-bit handle space can name.
pub const MAX_BLOCK: u32 = u32::MAX >> BLOCK_BITS;
/// The window server's own block: desktop windows, owned by no application.
pub const SERVER_BLOCK: u32 = 0;
/// First block an application window owner may be assigned.
pub const FIRST_OWNER_BLOCK: u32 = SERVER_BLOCK + 1;

/// First handle value in one block. Handle zero is not a window, so the
/// server's block starts one past its base. # C: O(1)
pub const fn block_first(block: u32) -> Option<u32> {
    if block > MAX_BLOCK { return None; }
    Some(block * BLOCK_SIZE + 1)
}

/// One past the last handle value in one block. # C: O(1)
pub const fn block_end(block: u32) -> Option<u32> {
    if block > MAX_BLOCK { return None; }
    if block == MAX_BLOCK { return Some(u32::MAX); }
    Some((block + 1) * BLOCK_SIZE)
}

/// Which owner's block one handle value falls in. # C: O(1)
pub const fn block_of(hwnd: u32) -> u32 { hwnd >> BLOCK_BITS }

/// Whether one handle value belongs to the window server rather than to an
/// application window owner. # C: O(1)
pub const fn is_server_handle(hwnd: u32) -> bool { hwnd != 0 && block_of(hwnd) == SERVER_BLOCK }

/// The block one window owner is assigned, from the count already handed
/// out. A count past the end of the space names no block, and an owner given
/// none can create no window rather than sharing another owner's handles.
/// # C: O(1)
pub const fn owner_block(taken: u32) -> u32 {
    let block = FIRST_OWNER_BLOCK.saturating_add(taken);
    if block > MAX_BLOCK { u32::MAX } else { block }
}

/// The handle one desktop window is given, from the count of desktop windows
/// already named. Past the end of the server's own block this names nothing
/// rather than reaching into the first application owner's block. # C: O(1)
pub const fn desktop_handle(named: u32) -> u32 {
    let (Some(first), Some(end)) = (block_first(SERVER_BLOCK), block_end(SERVER_BLOCK)) else { return 0; };
    let handle = first.saturating_add(named);
    if handle >= end { 0 } else { handle }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_block_is_not_an_owner_block() {
        assert_eq!(SERVER_BLOCK, 0);
        assert_eq!(FIRST_OWNER_BLOCK, 1);
        assert_ne!(block_of(block_first(SERVER_BLOCK).unwrap()), block_of(block_first(FIRST_OWNER_BLOCK).unwrap()));
    }

    #[test]
    fn no_handle_value_belongs_to_two_blocks() {
        // The defect this partition exists for: two owners numbering from one
        // gave two different windows the same handle.
        for block in [SERVER_BLOCK, FIRST_OWNER_BLOCK, 2, 7, MAX_BLOCK - 1] {
            let first = block_first(block).unwrap();
            let end = block_end(block).unwrap();
            assert!(first < end);
            assert_eq!(block_of(first), block);
            assert_eq!(block_of(end - 1), block);
            assert_ne!(block_of(end), block);
        }
    }

    #[test]
    fn blocks_are_contiguous_and_disjoint() {
        for block in [SERVER_BLOCK, FIRST_OWNER_BLOCK, 5, 4094] {
            assert_eq!(block_end(block).unwrap(), block_first(block + 1).unwrap() - 1);
        }
    }

    #[test]
    fn a_block_beyond_the_handle_space_names_nothing() {
        assert_eq!(block_first(MAX_BLOCK + 1), None);
        assert_eq!(block_end(MAX_BLOCK + 1), None);
        assert!(block_first(MAX_BLOCK).is_some());
    }

    #[test]
    fn handle_zero_is_not_in_the_server_block() {
        assert!(!is_server_handle(0));
        assert!(is_server_handle(1));
        assert!(is_server_handle(BLOCK_SIZE - 1));
        assert!(!is_server_handle(BLOCK_SIZE));
        assert!(!is_server_handle(block_first(FIRST_OWNER_BLOCK).unwrap()));
    }

    #[test]
    fn no_owner_is_given_the_window_servers_own_block() {
        for taken in [0, 1, 2, 4093] { assert_ne!(owner_block(taken), SERVER_BLOCK); }
        assert_eq!(owner_block(0), FIRST_OWNER_BLOCK);
        assert_eq!(owner_block(1), FIRST_OWNER_BLOCK + 1);
        assert_ne!(owner_block(0), owner_block(1));
    }

    /// An owner past the end of the space gets no block at all. Handing it
    /// another owner's block is what the partition exists to prevent.
    #[test]
    fn an_owner_past_the_handle_space_gets_no_block() {
        assert_eq!(owner_block(MAX_BLOCK), u32::MAX);
        assert_eq!(block_first(owner_block(MAX_BLOCK)), None);
    }

    /// The defect this exists for: the desktop window was whichever process
    /// published a top-level window first, so its handle was that process's
    /// handle — and a second process's own first window carried the same value.
    #[test]
    fn a_desktop_window_handle_is_never_an_application_window_handle() {
        assert!(is_server_handle(desktop_handle(0)));
        assert_ne!(desktop_handle(0), 0);
        assert_ne!(desktop_handle(0), desktop_handle(1));
        for taken in [0, 1, 7] {
            let owner_first = block_first(owner_block(taken)).unwrap();
            assert!(!is_server_handle(owner_first));
            assert_ne!(desktop_handle(0), owner_first);
            assert_ne!(desktop_handle(BLOCK_SIZE - 2), owner_first);
        }
    }

    #[test]
    fn a_desktop_handle_past_the_server_block_names_nothing() {
        assert_eq!(desktop_handle(BLOCK_SIZE - 1), 0);
        assert_eq!(desktop_handle(u32::MAX), 0);
        assert!(is_server_handle(desktop_handle(BLOCK_SIZE - 2)));
    }

    #[test]
    fn one_owner_block_holds_a_windows_worth_of_handles() {
        assert_eq!(BLOCK_SIZE, 1 << 20);
        assert_eq!(MAX_BLOCK, 4095);
    }
}
