// BSD process accounting (`acct(2)`, the CONFIG_BSD_PROCESS_ACCT facility).
//
// `acct(2)` names a file; from then on the kernel appends one 64-byte
// `struct acct_v3` record per exiting process, and `sa`/`lastcomm` read it
// back. Slot 163 answered a blanket EPERM before F757 — a lie about the
// reason, since no amount of privilege makes an unimplemented feature appear.
//
// Module manifest:
//   record — the `acct_v3` wire layout + `encode_comp_t`/`encode_float` (pure)
//   space  — free-space suspend/resume hysteresis + the interval between
//            checks (pure)
//   parm   — the three `kernel/acct` tunables and their `/proc/sys` vector leaf
//   state  — per-pid-namespace accounting file, append cursor, superblock pin
//   tests  — hosted proof of the layout, the encodings, the hysteresis, the
//            tunable leaf and the admission ladder
//
// The admission ladder itself (`acct_on`'s check order) is `admit_file` below,
// pure over the facts the caller resolved, so `cargo test -p fs` proves the
// ORDER — which is the only observable part of a rejected `acct(2)`.

pub mod record;
pub mod space;
pub mod parm;
pub mod state;
#[cfg(test)]
mod tests;

pub use record::{AcctFacts, ACCT_V3_LEN, AFORK, AGROUP, ACORE, ASU, AXSIG};
pub use state::NsTarget;

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
pub fn acct_on(ns_id: u64, inode: vfs::InodeRef, now_ns: u64) {
    state::enable(ns_id, inode, now_ns);
}

/// `acct(NULL)`: stop accounting for `ns_id`. Success whether or not a file was
/// bound. # C: O(log N_namespaces)
pub fn acct_off(ns_id: u64) { state::disable(ns_id); }

/// A pid namespace has died with accounting still on: close its file, so the
/// namespace's last reference to the accounting filesystem goes away with it.
/// # C: O(log N_namespaces)
pub fn acct_exit_ns(ns_id: u64) { state::disable(ns_id); }

/// Whether `ns_id` is accounting. # C: O(log N_namespaces)
pub fn accounting_on_for(ns_id: u64) -> bool { state::is_enabled(ns_id) }

/// Whether any namespace is accounting — the exit path's guard, so a boot that
/// never calls `acct(2)` pays one lock-and-check per process exit and nothing
/// more. # C: O(1)
pub fn accounting_active() -> bool { state::any_active() }

/// Write `facts` as an `acct_v3` record to the accounting file of every target
/// namespace that has one — the exiting task's pid namespace followed by its
/// ancestors. Each record carries the pids that ITS namespace sees, so a
/// container's log and the host's log name the same process by their own
/// numbers. # C: O(depth * log N_namespaces)
pub fn acct_process(targets: &[NsTarget], facts: &AcctFacts, now_ns: u64) {
    if targets.is_empty() { return; }
    state::append(targets, facts, now_ns);
}

/// Bind the `/proc/sys/kernel/acct` leaf to the live tunables at boot. Without
/// it the file would report a triple no free-space check ever consults.
/// # C: O(1)
pub fn register_sysctl_hooks() {
    procfs::hooks::set_acct_parm_hooks(parm::sysctl_read, parm::sysctl_write);
}
