// The loaded policy's classes and their permissions.
//
// The tree is built from the POLICY's tables, not the kernel's: a policy
// numbers its classes and permissions itself, and userspace reads these files
// to translate a name into the number the transaction nodes take. Publishing
// the kernel's own numbering here would hand out values the loaded policy
// does not use.

use alloc::string::String;

use vfs::InodeRef;

use crate::format::scalar::render_u32;
use crate::ops::ClassEntry;

use super::plumb::text_file;

/// Directory holding one subdirectory per class.
pub const CLASS_DIR: &str = "class";
/// Subdirectory of a class holding one node per permission.
pub const PERMS_DIR: &str = "perms";
/// Node naming a class's value.
pub const INDEX_NODE: &str = "index";
/// Mode of a class or permission value node.
const VALUE_MODE: u16 = 0o444;

/// Render a class or permission value. # C: O(digits)
pub fn value_response(value: u32) -> String { render_u32(value) }

/// Build the value node of one class or permission. # C: O(1)
pub fn make_value(value: u32) -> InodeRef {
    text_file(VALUE_MODE, move || value_response(value))
}

/// Paths and inodes of one class's subtree, relative to the mount root. # C: O(perms)
pub fn class_nodes(class: &ClassEntry) -> alloc::vec::Vec<(String, InodeRef)> {
    let mut out = alloc::vec::Vec::new();
    let base = alloc::format!("{CLASS_DIR}/{}", class.name);
    out.push((alloc::format!("{base}/{INDEX_NODE}"), make_value(class.value)));
    for perm in &class.perms {
        out.push((alloc::format!("{base}/{PERMS_DIR}/{}", perm.name), make_value(perm.value)));
    }
    out
}
