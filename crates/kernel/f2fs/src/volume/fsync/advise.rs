//! The two hint bits an inode carries that change what durability means.

use crate::flags::{FADVISE_KEEP_SIZE_BIT, FADVISE_LOST_PINO_BIT};

/// Whether the recorded parent is stale, so nothing can restore the file's
/// directory entry from it. # C: O(1)
pub fn wrong_pino(advise: u8) -> bool { advise & FADVISE_LOST_PINO_BIT != 0 }

/// Whether replay must leave the recorded size alone rather than growing it to
/// cover the blocks it put back. # C: O(1)
pub fn keep_isize(advise: u8) -> bool { advise & FADVISE_KEEP_SIZE_BIT != 0 }
