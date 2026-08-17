// The policy-load node and the image it hands back.

use alloc::boxed::Box;

use vfs::{InodeRef, KResult, VfsError};

use crate::ops::PolicyOps;
use crate::server::with_ops;

use super::plumb::{dyn_file, ro_file, ReadFn, WriteFn};

/// Permission a policy load is checked against.
pub const PERM_LOAD_POLICY: &str = "load_policy";
/// Permission reading the loaded image is checked against.
pub const PERM_READ_POLICY: &str = "read_policy";

/// Mode of the load node.
const LOAD_MODE: u16 = 0o600;
/// Mode of the image node.
const POLICY_MODE: u16 = 0o444;

/// Accept a whole policy image. # C: O(image)
///
/// The image arrives in ONE write. A write at a non-zero offset is a caller
/// streaming the image in pieces, and each piece would be parsed as a whole
/// policy — refusing it is what keeps a partial image from being read as a
/// malformed one, or worse, from replacing a working policy with a fragment.
pub fn write_load(ops: &mut dyn PolicyOps, off: u64, body: &[u8]) -> KResult<usize> {
    if off != 0 { return Err(VfsError::Einval); }
    if body.is_empty() { return Err(VfsError::Einval); }
    ops.check(PERM_LOAD_POLICY)?;
    ops.load_policy(body)?;
    // Every cached decision in every userspace AVC was answered by the policy
    // this load just replaced.
    crate::notify::policy_changed(ops);
    Ok(body.len())
}

/// Copy out part of the loaded image. # C: O(buf)
pub fn read_policy(ops: &mut dyn PolicyOps, off: u64, buf: &mut [u8]) -> KResult<usize> {
    ops.check(PERM_READ_POLICY)?;
    ops.read_policy_image(off as usize, buf)
}

/// Build the `load` node. # C: O(1)
pub fn make_load() -> InodeRef {
    let write: WriteFn = Box::new(|off, buf| {
        let n = with_ops(|o| write_load(o, off, buf))?;
        // Every node built from the policy's own tables is stale the moment a
        // new policy is in force, so the rebuild is part of the load rather
        // than something a later reader has to notice.
        crate::root::rebuild_policy_nodes();
        let _ = audit::log_if_enabled(audit::uapi::AUDIT_MAC_POLICY_LOAD, b"mac_policy_load");
        Ok(n)
    });
    dyn_file(LOAD_MODE, None, Some(write))
}

/// Build the `policy` node. # C: O(1)
pub fn make_policy() -> InodeRef {
    // The image can be megabytes, so the read reaches the stored bytes at the
    // caller's offset rather than rendering the whole policy per read.
    let read: ReadFn = Box::new(|off, buf| with_ops(|o| read_policy(o, off, buf)));
    ro_file(POLICY_MODE, read)
}

#[cfg(test)]
#[path = "../tests/load.rs"]
mod tests;
