// BSD process accounting (Linux `kernel/acct.c`, `CONFIG_BSD_PROCESS_ACCT`).
//
// `acct(2)` names a file; from then on the kernel appends one 64-byte
// `struct acct_v3` record per exiting process, and `sa`/`lastcomm` read it
// back. Slot 163 answered a blanket EPERM before F757 — a lie about the
// reason, since no amount of privilege makes an unimplemented feature appear.
//
// Module manifest:
//   record — the `acct_v3` wire layout + `encode_comp_t`/`encode_float` (pure)
//   state  — per-pid-namespace accounting file, append cursor, free-space
//            suspend/resume hysteresis
//   tests  — hosted proof of the layout, the encodings and the admission ladder
//
// The admission ladder itself (`acct_on`'s check order) is `admit_file` below,
// pure over the facts the caller resolved, so `cargo test -p fs` proves the
// ORDER — which is the only observable part of a rejected `acct(2)`.

pub mod record;
pub mod state;
#[cfg(test)]
mod tests;

pub use record::{AcctFacts, ACCT_V3_LEN, AFORK, AGROUP, ACORE, ASU, AXSIG};

/// Why `acct_on` refused a file, in Linux's own test order.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AcctFileError {
    /// `!S_ISREG(file_inode(file)->i_mode)` → EACCES. Accounting appends a
    /// fixed-size binary record; a directory, device or fifo cannot hold one.
    NotRegular,
    /// `i_sb->s_flags & (SB_NOUSER | SB_KERNMOUNT)`, or the filesystem carries
    /// `FS_USERNS_MOUNT_RESTRICTED` (procfs, sysfs) → EINVAL. Accounting to a
    /// pseudo file would write into kernel state, not a log.
    KernelInternal,
    /// `!(file->f_mode & FMODE_CAN_WRITE)` → EIO. The file opened, but its
    /// filesystem has no write path, so no record could ever land.
    NotWritable,
}

/// The facts `acct_on` needs about the resolved file, gathered by the caller
/// (which owns path resolution) so the DECISION stays pure.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AcctFileFacts {
    /// `S_ISREG(inode->i_mode)`.
    pub is_regular:       bool,
    /// `sb->s_flags & (SB_NOUSER | SB_KERNMOUNT)` is non-zero, or the fs type
    /// carries `FS_USERNS_MOUNT_RESTRICTED`.
    pub kernel_internal:  bool,
    /// `file->f_mode & FMODE_CAN_WRITE`.
    pub can_write:        bool,
}

/// Linux `acct_on`'s post-open check ladder, in order:
/// `S_ISREG` → EACCES, kernel-internal superblock → EINVAL, no write path →
/// EIO. The order is observable: a caller naming `/proc/self/status` must see
/// EINVAL (it IS a regular file on a restricted fs), while one naming a
/// directory must see EACCES before the filesystem is ever considered.
/// # C: O(1)
pub fn admit_file(f: AcctFileFacts) -> Result<(), AcctFileError> {
    if !f.is_regular      { return Err(AcctFileError::NotRegular); }
    if f.kernel_internal  { return Err(AcctFileError::KernelInternal); }
    if !f.can_write       { return Err(AcctFileError::NotWritable); }
    Ok(())
}

/// `acct(path)` once the caller has resolved and admitted the file: bind it to
/// `ns_id`'s accounting slot. # C: O(log N_namespaces)
pub fn acct_on(ns_id: u64, inode: vfs::InodeRef) { state::enable(ns_id, inode); }

/// `acct(NULL)`: stop accounting for `ns_id`. Linux returns success whether or
/// not a file was bound. # C: O(log N_namespaces)
pub fn acct_off(ns_id: u64) { state::disable(ns_id); }

/// Whether any namespace is accounting — the exit path's guard, so a boot that
/// never calls `acct(2)` pays one lock-and-check per process exit and nothing
/// more. # C: O(1)
pub fn accounting_active() -> bool { state::any_active() }

/// Linux `acct_process()`: write `facts` as an `acct_v3` record to the
/// accounting file of every namespace in `chain` (the exiting task's pid
/// namespace followed by its ancestors) that has one.
/// # C: O(depth * log N_namespaces)
pub fn acct_process(chain: &[u64], facts: &AcctFacts) {
    if chain.is_empty() { return; }
    state::append(chain, &facts.encode());
}
