extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::dentry::Dentry;
use super::Propagation;

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

/// Render mountinfo field 6 (`mount options`) from mount identity. # C: O(len opts)
pub fn mountinfo_mount_options(m: &Arc<super::Mount>) -> String {
    let rw = if (m.flags.load(Ordering::Acquire) & super::MNT_RDONLY) != 0 { "ro" } else { "rw" };
    let mut out = String::from(rw);
    out.push_str(",relatime");
    out.push_str(&m.sb().show_options());
    out
}

/// Render mountinfo optional propagation fields, including their leading
/// separator when present. # C: O(len field)
pub fn mountinfo_optional_fields(m: &Arc<super::Mount>) -> String {
    let pg = m.peer_group.load(Ordering::Acquire);
    match Propagation::from_u8(m.propagation.load(Ordering::Acquire)) {
        Propagation::Shared => format!(" shared:{}", pg),
        Propagation::Slave if pg != 0 => format!(" master:{}", pg),
        Propagation::Unbindable => String::from(" unbindable"),
        Propagation::Slave | Propagation::Private => String::new(),
    }
}

/// Render mountinfo field 10 (`source`) from VFS/SB ownership. # C: O(len name)
pub fn mountinfo_source_field(m: &Arc<super::Mount>) -> String {
    m.sb().show_devname().unwrap_or_else(|| String::from(m.fs().name()))
}

/// Render mountinfo field 11 (`super options`). # C: O(1)
pub fn mountinfo_super_options(m: &Arc<super::Mount>) -> &'static str {
    if (m.flags.load(Ordering::Acquire) & super::MNT_RDONLY) != 0 { "ro" } else { "rw" }
}
