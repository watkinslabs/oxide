extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use crate::dentry::Dentry;

/// Render mountinfo field 4 (`root`) from mount identity, relative to the
/// superblock root. # C: O(depth)
pub fn mountinfo_root_field(m: &Arc<super::Mount>) -> String {
    render_mount_root_field(m.mnt_root(), m.sb().s_root())
}

/// Render mountinfo field 4 from explicit root dentries. The result is `/` for
/// a whole-filesystem mount and a slash-prefixed subpath for bind roots.
/// # C: O(depth)
pub fn render_mount_root_field(root: Option<Arc<Dentry>>, sb_root: Option<Arc<Dentry>>) -> String {
    let Some(r) = root else { return String::from("/"); };
    let rp = r.absolute_path();
    let Some(sr) = sb_root else {
        return String::from_utf8(rp).unwrap_or_else(|_| String::from("/"));
    };
    let sp = sr.absolute_path();
    let rel = if rp.starts_with(sp.as_slice()) {
        let strip = if sp.as_slice() == b"/" { 0 } else { sp.len() };
        &rp[strip..]
    } else {
        rp.as_slice()
    };
    match core::str::from_utf8(rel) {
        Ok("") => String::from("/"),
        Ok(s) if s.starts_with('/') => String::from(s),
        Ok(s) => {
            let mut out = String::from("/");
            out.push_str(s);
            out
        }
        Err(_) => String::from("/"),
    }
}
