// The contexts of the initial SIDs.
//
// Only the slots policy NAMES are published. The unnamed slots are historical
// placeholders that keep the numbering stable and that no policy declares, so
// a node for one would publish a context nothing ever set.

use alloc::string::String;
use alloc::vec::Vec;

use selinux::uapi::initsid::{initsid_name, SECINITSID_NUM};
use vfs::InodeRef;

use crate::ops::PolicyOps;
use crate::server::with_ops;

use super::plumb::text_file;

/// Directory holding one node per named initial SID.
pub const INITIAL_CONTEXTS_DIR: &str = "initial_contexts";
/// Mode of an initial-context node.
const INITCON_MODE: u16 = 0o444;
/// Rendering of a slot the loaded policy supplies no context for.
const NO_CONTEXT: &str = "";

/// Render one initial SID's context. # C: O(categories)
pub fn read_initial_context(ops: &dyn PolicyOps, sid: u32) -> String {
    ops.initial_context(sid).unwrap_or_else(|| String::from(NO_CONTEXT))
}

/// Paths and inodes of the initial-context nodes. # C: O(initial SIDs)
pub fn initial_context_nodes() -> Vec<(String, InodeRef)> {
    let mut out = Vec::new();
    for sid in 1..=SECINITSID_NUM {
        let Some(name) = initsid_name(sid) else { continue };
        let node = text_file(INITCON_MODE, move || with_ops(|o| read_initial_context(o, sid)));
        out.push((alloc::format!("{INITIAL_CONTEXTS_DIR}/{name}"), node));
    }
    out
}
