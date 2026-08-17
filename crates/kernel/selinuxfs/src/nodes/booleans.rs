// Per-boolean values and the node that commits them.
//
// A write STAGES a value; nothing changes until the commit node is written.
// Applying a write immediately would let a caller setting several related
// booleans be observed in a combination no policy author ever wrote, and each
// intermediate state would invalidate the decision cache.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use vfs::{InodeRef, KResult, VfsError};

use crate::format::response::bool_response;
use crate::format::scalar::{parse_flag, request_text};
use crate::ops::PolicyOps;
use crate::server::with_ops;

use super::plumb::{body_reader, dyn_file, wo_file, WriteFn};

/// Permission a boolean write and a commit are checked against.
pub const PERM_SETBOOL: &str = "setbool";

/// Directory holding one node per boolean.
pub const BOOLEANS_DIR: &str = "booleans";
/// Mode of a boolean node.
const BOOL_MODE: u16 = 0o644;
/// Mode of the commit node.
const COMMIT_MODE: u16 = 0o200;

/// Render one boolean's committed and pending values. # C: O(booleans)
pub fn read_bool(ops: &mut dyn PolicyOps, name: &str) -> KResult<String> {
    let (committed, pending) = ops.bool_value(name).ok_or(VfsError::Einval)?;
    Ok(bool_response(committed, pending))
}

/// Stage a boolean value. # C: O(booleans)
pub fn write_bool(ops: &mut dyn PolicyOps, name: &str, body: &[u8]) -> KResult<usize> {
    let value = parse_flag(request_text(body)?)?;
    ops.check(PERM_SETBOOL)?;
    ops.set_bool_pending(name, value)?;
    Ok(body.len())
}

/// Apply every staged boolean value. # C: O(conditional rules)
///
/// A zero is a caller explicitly asking for nothing to happen, so it is
/// accepted and applies nothing rather than being refused.
pub fn write_commit(ops: &mut dyn PolicyOps, body: &[u8]) -> KResult<usize> {
    let apply = parse_flag(request_text(body)?)?;
    ops.check(PERM_SETBOOL)?;
    if apply {
        ops.commit_bools()?;
        // A commit re-evaluates every conditional rule, so the answers the
        // policy gives changed even though the policy did not — the reference
        // announces it exactly as it announces a load.
        crate::notify::policy_changed(ops);
    }
    Ok(body.len())
}

/// Build one boolean's node. # C: O(1)
pub fn make_bool(name: &str) -> InodeRef {
    let read_name: Arc<str> = Arc::from(name);
    let write_name = Arc::clone(&read_name);
    let read = body_reader(move || {
        let n = read_name.to_string();
        Ok(with_ops(|o| read_bool(o, &n))?.into_bytes())
    });
    let write: WriteFn = Box::new(move |_off, buf| {
        let n = write_name.to_string();
        with_ops(|o| write_bool(o, &n, buf))
    });
    dyn_file(BOOL_MODE, Some(read), Some(write))
}

/// Build the `commit_pending_bools` node. # C: O(1)
pub fn make_commit() -> InodeRef {
    wo_file(COMMIT_MODE, Box::new(|_off, buf| {
        let n = with_ops(|o| write_commit(o, buf))?;
        let _ = audit::log_if_enabled(audit::uapi::AUDIT_MAC_CONFIG_CHANGE,
                                      b"mac_config_change bools=committed");
        Ok(n)
    }))
}

#[cfg(test)]
#[path = "../tests/booleans.rs"]
mod tests;
