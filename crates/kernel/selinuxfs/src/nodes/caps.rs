// One node per policy capability.
//
// The set of NAMES is fixed by the engine's ABI, and every one is published
// whether or not the loaded policy enables it: userspace reads a name's
// presence to learn the kernel knows the capability and its contents to learn
// whether the policy asked for it. Publishing only the enabled ones would
// make an old policy look like an old kernel.

use alloc::string::String;
use alloc::vec::Vec;

use selinux::uapi::policycap::{POLICYCAP_NAMES, POLICYDB_CAP_MAX};
use vfs::InodeRef;

use crate::format::scalar::render_flag;
use crate::ops::PolicyOps;
use crate::server::with_ops;

use super::plumb::text_file;

/// Directory holding one node per capability.
pub const POLICYCAP_DIR: &str = "policy_capabilities";
/// Mode of a capability node.
const CAP_MODE: u16 = 0o444;

/// Render whether the loaded policy enables one capability. # C: O(log chunks)
pub fn read_cap(ops: &dyn PolicyOps, bit: u32) -> String { render_flag(ops.policycap(bit)) }

/// Paths and inodes of the capability nodes, relative to the mount root. # C: O(caps)
pub fn cap_nodes() -> Vec<(String, InodeRef)> {
    (0..POLICYDB_CAP_MAX).map(|bit| {
        let name = POLICYCAP_NAMES[bit as usize];
        let node = text_file(CAP_MODE, move || with_ops(|o| read_cap(o, bit)));
        (alloc::format!("{POLICYCAP_DIR}/{name}"), node)
    }).collect()
}
