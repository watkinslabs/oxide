use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{FdTable, File, OpenFlags, VfsError};

/// Result of one Linux SCM_RIGHTS receive publication batch.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReceiveFdResult {
    pub installed: usize,
    pub truncated: bool,
    pub failure: Option<VfsError>,
}

/// Publish the installable prefix, discard the suffix, then collect SCM cycles. # C: O(files * fd words + SCM graph)
pub fn install_received_fds<F>(table: &FdTable, limit: usize, cloexec: bool,
    files: Vec<Arc<File>>, capacity: usize, mut copyout: F) -> ReceiveFdResult
where F: FnMut(usize, i32) -> vfs::KResult<()>
{
    // The one point every socket-side rights transfer enters the global graph.
    #[cfg(test)]
    crate::test_support::assert_scm_owned();
    let _transfer = net::transfer_guard();
    let total = files.len();
    let flags = if cloexec { OpenFlags::O_CLOEXEC } else { OpenFlags::empty() };
    let mut pending = files.into_iter();
    let mut installed = 0usize;
    let mut failure = None;
    for index in 0..capacity {
        let Some(file) = pending.next() else { break; };
        match table.scm_install_fd(file, flags, limit, |fd| copyout(index, fd)) {
            Ok(_) => installed += 1,
            Err(error) => { failure = Some(error); break; }
        }
    }
    ReceiveFdResult { installed, truncated: installed < total, failure }
}
