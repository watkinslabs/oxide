// Linux `filp_close` / `filp_flush` (`fs/open.c:1460`): the tail every
// descriptor-removal path shares. `close(2)`, `close_range(2)`, exec's
// close-on-exec sweep and descriptor-table teardown all run it, so POSIX
// record-lock release cannot be forgotten on one of them.

extern crate alloc;

use alloc::sync::Arc;

use crate::file::File;
use crate::inode::RecordOwner;
use crate::types::KResult;

/// Owner identity a descriptor table presents to record locks. Linux passes
/// `current->files` as `fl_owner_t` from `close_fd`/`close_files`
/// (`fs/open.c:1475`), so the table's address IS the owner. # C: O(1)
pub fn files_owner(table: *const super::FdTable) -> RecordOwner {
    RecordOwner::Files(table as *const u8 as usize)
}

/// Linux `filp_flush` + `fput`: flush the description, drop every POSIX
/// byte-range record `owner` holds on its inode, wake anyone parked on that
/// inode, then release the reference.
///
/// The record release is per-CLOSE, not per-final-fput: Linux
/// `locks_remove_posix` (`fs/locks.c:2768`) runs from `filp_flush` for every
/// descriptor removal, so closing ONE descriptor for a file drops all of that
/// descriptor table's locks on it even while a `dup(2)` stays open. OFD
/// records and BSD flocks are the last-reference case instead and ride
/// `File::drop` (`locks_remove_file`). # C: O(N_records)
pub fn filp_close(owner: RecordOwner, file: Arc<File>) -> KResult<()> {
    let result = file.flush();
    {
        let flctx = file.inode().file_lock_context();
        if flctx.remove_records_for(owner) { crate::file_lock_wake(flctx.wait_key()); }
    }
    drop(file);
    super::fire_file_ref_drop_hook();
    result
}
