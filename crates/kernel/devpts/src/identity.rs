// Who a pty endpoint inode IS.
//
// Linux answers this with the ops vector: `tty_paranoia_check` compares
// `file->f_op` against the one `tty_fops` the tty layer installs, and the pty
// half comes from `file->private_data`. An inode NUMBER is never the answer —
// two filesystems may legitimately carry the same `st_ino` because `st_dev`
// separates them.
//
// Oxide resolved a pty from `ino & 0xFFFF_8000` against a private base. That
// base was `0x6000_0000`, which cgroupfs ALSO claimed for its directory
// inodes, so a cgroup2 directory with a small cgroup id decoded as a live PTY
// master. Nothing reached it only because devpts' consumers happened to gate
// on `FileType::CharDev` first and cgroup dirs are Directory — luck, not
// design. Identity now comes from the `PtyEndpointData` the ONE endpoint
// constructor installs (`crate::inodes`), so a foreign inode carrying the same
// number resolves to nothing.

use alloc::sync::Arc;

use vfs::Inode;

use crate::pair::LockedPair;

/// Backend-private state (`i_private`) of a Unix98 pty endpoint inode: the
/// shared pair, and WHICH half of it this inode is. Only
/// [`crate::inodes::make_master_inode`] / [`crate::inodes::make_slave_inode`]
/// mint one, so holding it is proof of devpts ownership.
pub struct PtyEndpointData {
    pair:   Arc<LockedPair>,
    master: bool,
}

impl PtyEndpointData {
    /// Bind an inode to `pair`'s master (`master = true`) or slave half.
    /// # C: O(1)
    pub(crate) fn new(pair: Arc<LockedPair>, master: bool) -> Self { Self { pair, master } }
    /// The pair both halves share. # C: O(1)
    pub fn pair(&self) -> &Arc<LockedPair> { &self.pair }
    /// Whether this inode is the master (`/dev/ptmx` side) half. # C: O(1)
    pub fn is_master(&self) -> bool { self.master }
}

/// The pty endpoint state `inode` owns, or `None` when it is not a pty
/// endpoint. # C: O(1)
pub fn endpoint_of(inode: &Inode) -> Option<&PtyEndpointData> {
    inode.private::<PtyEndpointData>()
}

/// Whether `inode` is either half of a Unix98 pty. # C: O(1)
pub fn is_pty_endpoint(inode: &Inode) -> bool { endpoint_of(inode).is_some() }

/// Whether `inode` is a Unix98 PTY MASTER. False for a slave, and for
/// everything devpts does not own. # C: O(1)
pub fn is_master_inode(inode: &Inode) -> bool {
    endpoint_of(inode).map(|d| d.master).unwrap_or(false)
}

/// The pair backing either half of a Unix98 pty, or `None`. # C: O(1)
pub fn pair_for_inode(inode: &Inode) -> Option<Arc<LockedPair>> {
    endpoint_of(inode).map(|d| Arc::clone(&d.pair))
}

#[cfg(test)]
#[path = "identity/tests.rs"]
mod tests;
