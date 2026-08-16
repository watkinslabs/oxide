// The enforcement-mode control.

use alloc::boxed::Box;
use alloc::string::String;

use vfs::{InodeRef, KResult};

use crate::format::scalar::{parse_flag, render_flag, request_text};
use crate::ops::PolicyOps;
use crate::server::with_ops;

use super::plumb::{dyn_file, ReadFn, WriteFn};

/// Permission a change of enforcement mode is checked against.
pub const PERM_SETENFORCE: &str = "setenforce";

/// Mode of the enforcement control.
const ENFORCE_MODE: u16 = 0o644;

/// Render the current enforcement mode. # C: O(1)
pub fn read_enforce(ops: &mut dyn PolicyOps) -> String { render_flag(ops.enforcing()) }

/// Apply a written enforcement mode. # C: O(1)
///
/// The permission check runs only when the write CHANGES the mode: a write
/// that asks for the state already in force changes nothing, and refusing it
/// would make a caller that re-asserts its own setting fail. A write that
/// does change the mode is refused outright when the policy denies it —
/// nothing is applied and nothing partially applied.
pub fn write_enforce(ops: &mut dyn PolicyOps, body: &[u8]) -> KResult<usize> {
    let want = parse_flag(request_text(body)?)?;
    if want == ops.enforcing() { return Ok(body.len()); }
    ops.check(PERM_SETENFORCE)?;
    ops.set_enforcing(want)?;
    Ok(body.len())
}

/// Build the `enforce` node. # C: O(1)
pub fn make_enforce() -> InodeRef {
    let read: ReadFn = super::plumb::body_reader(|| Ok(with_ops(|o| read_enforce(o)).into_bytes()));
    let write: WriteFn = Box::new(|_off, buf| {
        let before = with_ops(|o| o.enforcing());
        let n = with_ops(|o| write_enforce(o, buf))?;
        let after = with_ops(|o| o.enforcing());
        // The record states what enforcement became, not that a write
        // happened: a write that asked for the mode already in force is not a
        // status change and must not read as one in the audit trail.
        if before != after {
            let body = if after { b"mac_status enforcing=1".as_slice() }
                       else { b"mac_status enforcing=0".as_slice() };
            let _ = audit::log_if_enabled(audit::uapi::AUDIT_MAC_STATUS, body);
        }
        Ok(n)
    });
    dyn_file(ENFORCE_MODE, Some(read), Some(write))
}

#[cfg(test)]
#[path = "../tests/enforce.rs"]
mod tests;
