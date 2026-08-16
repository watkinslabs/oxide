// Version and policy-disposition nodes, the compatibility controls, the
// relabel-validation node, and the null device.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;

use selinux::uapi::version::POLICYDB_VERSION_MAX;
use vfs::file_ops::FileOps;
use vfs::inode::{Inode, InodeBuilder};
use vfs::inode_ops::{default_inode_ops, mk_mode};
use vfs::{FileType, InodeRef, KResult};

use crate::format::request::parse_validatetrans_request;
use crate::format::response::policyvers_response;
use crate::format::scalar::{parse_flag, render_flag, request_text};
use crate::ops::PolicyOps;
use crate::server::with_ops;

use super::plumb::{dyn_file, text_file, wo_file, WriteFn};

/// Permission validating a relabel is checked against.
pub const PERM_VALIDATE_TRANS: &str = "validate_trans";

/// Mode of a read-only report.
const REPORT_MODE: u16 = 0o444;
/// Mode of a retained read/write control.
const COMPAT_RW_MODE: u16 = 0o644;
/// Mode of a retained write-only control.
const COMPAT_WO_MODE: u16 = 0o200;
/// Mode of the relabel-validation node.
const VALIDATETRANS_MODE: u16 = 0o222;
/// Mode of the null device.
const NULL_MODE: u16 = 0o666;

/// Device number of the null device: major 1, minor 3.
const DEV_MEM_NULL: u32 = (1 << 8) | 3;

/// Value the retained compatibility controls report.
///
/// `checkreqprot` and `disable` are INERT BY CONTRACT, not unimplemented: the
/// behaviour each once selected no longer exists, and a kernel that refused
/// them would break the callers that still write them at boot. Reads report
/// the one state that holds.
const COMPAT_VALUE: bool = false;

/// Render the highest policy version the engine reads. # C: O(1)
pub fn read_policyvers() -> String { policyvers_response(POLICYDB_VERSION_MAX) }

/// Render whether the loaded policy carries MLS. # C: O(1)
pub fn read_mls(ops: &dyn PolicyOps) -> String { render_flag(ops.facts().mls) }

/// Render whether the policy refuses an unknown class. # C: O(1)
pub fn read_reject_unknown(ops: &dyn PolicyOps) -> String {
    render_flag(ops.facts().reject_unknown)
}

/// Render whether the policy denies permissions on an unknown class. # C: O(1)
pub fn read_deny_unknown(ops: &dyn PolicyOps) -> String { render_flag(ops.facts().deny_unknown) }

/// Render a retained compatibility control. # C: O(1)
pub fn read_compat() -> String { render_flag(COMPAT_VALUE) }

/// Accept a write to a retained compatibility control. # C: O(len)
///
/// The value must still be a number: accepting anything at all would make a
/// caller writing a word believe the kernel understood it.
pub fn write_compat(body: &[u8]) -> KResult<usize> {
    parse_flag(request_text(body)?)?;
    Ok(body.len())
}

/// Validate a written relabel. # C: O(constraints)
pub fn write_validatetrans(ops: &mut dyn PolicyOps, body: &[u8]) -> KResult<usize> {
    ops.check(PERM_VALIDATE_TRANS)?;
    let r = parse_validatetrans_request(request_text(body)?)?;
    ops.validate_trans(&r.old, &r.new, r.class, &r.task)?;
    Ok(body.len())
}

/// Build the `policyvers` node. # C: O(1)
pub fn make_policyvers() -> InodeRef { text_file(REPORT_MODE, read_policyvers) }

/// Build the `mls` node. # C: O(1)
pub fn make_mls() -> InodeRef { text_file(REPORT_MODE, || with_ops(|o| read_mls(o))) }

/// Build the `reject_unknown` node. # C: O(1)
pub fn make_reject_unknown() -> InodeRef {
    text_file(REPORT_MODE, || with_ops(|o| read_reject_unknown(o)))
}

/// Build the `deny_unknown` node. # C: O(1)
pub fn make_deny_unknown() -> InodeRef {
    text_file(REPORT_MODE, || with_ops(|o| read_deny_unknown(o)))
}

/// Build the `checkreqprot` node. # C: O(1)
pub fn make_checkreqprot() -> InodeRef {
    let read = super::plumb::body_reader(|| Ok(read_compat().into_bytes()));
    let write: WriteFn = Box::new(|_off, buf| write_compat(buf));
    dyn_file(COMPAT_RW_MODE, Some(read), Some(write))
}

/// Build the `disable` node. # C: O(1)
pub fn make_disable() -> InodeRef {
    wo_file(COMPAT_WO_MODE, Box::new(|_off, buf| write_compat(buf)))
}

/// Build the `validatetrans` node. # C: O(1)
pub fn make_validatetrans() -> InodeRef {
    wo_file(VALIDATETRANS_MODE, Box::new(|_off, buf| with_ops(|o| write_validatetrans(o, buf))))
}

/// The null device: reads end, writes are discarded.
struct NullFileOps;
impl FileOps for NullFileOps {
    /// # C: O(1)
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Ok(0) }
    /// # C: O(1)
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

/// Build the `null` node. # C: O(1)
///
/// A character device, not a regular file: a policy that revokes a descriptor
/// replaces it with this one, and the replacement must behave as the null
/// device for a caller that goes on using it.
pub fn make_null() -> InodeRef {
    InodeBuilder::new(crate::root::alloc_ino(), mk_mode(FileType::CharDev, NULL_MODE),
                      default_inode_ops(), Arc::new(NullFileOps))
        .fsid(crate::root::SELINUXFS_FSID)
        .rdev(DEV_MEM_NULL)
        .build()
}

#[cfg(test)]
#[path = "../tests/readonly.rs"]
mod tests;
