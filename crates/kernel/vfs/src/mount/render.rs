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
///
/// Linux `show_path()` (`fs/namespace.c`) → `seq_dentry()` → `dentry_path()` →
/// `__dentry_path()` (`fs/d_path.c`): a plain `d_parent` walk terminating at
/// `IS_ROOT`, with `//deleted` appended for an unlinked root. It never consults
/// the mount table.
///
/// This previously built two GLOBAL `absolute_path()`s and subtracted them as
/// strings. `absolute_path` resolves every mount crossing through
/// `mountpoint_for_root_ptr`, a linear scan of the system-wide mount table
/// under its lock, so field 4 cost O(depth × N_mounts_system_wide) per row —
/// and systemd re-reads `/proc/self/mountinfo` after every mount operation
/// while setting up a sandboxed unit (B1475).
/// # C: O(depth)
pub fn render_mount_root_field(root: Option<Arc<Dentry>>, sb_root: Option<Arc<Dentry>>) -> String {
    let Some(r) = root else { return String::from("/"); };
    if let Some(dyn_name) = r.d_dname() { return dyn_name; }
    // Stop at the superblock root by IDENTITY. Linux's `IS_ROOT` (`d_parent ==
    // dentry`) is the same boundary: a real superblock root's parent link ends
    // the walk, and `sb_root` names it explicitly for callers whose fixture
    // trees share one parent chain across filesystems.
    let stop = sb_root.as_ref().map(Arc::as_ptr);
    let me = r.as_ref() as *const Dentry;
    let mut parts: alloc::vec::Vec<String> = alloc::vec::Vec::new();
    if stop != Some(me) && !r.is_root() && !r.is_disconnected() {
        if !r.name().is_empty() { parts.push(String::from(r.name())); }
        let mut cur = r.parent().cloned();
        while let Some(d) = cur {
            if stop == Some(Arc::as_ptr(&d)) || d.is_root() || d.is_disconnected() { break; }
            if !d.name().is_empty() { parts.push(String::from(d.name())); }
            cur = d.parent().cloned();
        }
    }
    let mut out = String::new();
    if parts.is_empty() { out.push('/'); }
    else { for name in parts.iter().rev() { out.push('/'); out.push_str(name); } }
    // Linux `dentry_path()` prepends `"//deleted"` into a backwards-filling
    // buffer, which lands it at the END of the rendered path.
    if r.is_unlinked() { out.push_str("//deleted"); }
    out
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
    m.sb().show_devname().unwrap_or_else(|| String::from(m.sb().s_type.name()))
}

/// Render mountinfo field 11 (`super options`). # C: O(1)
pub fn mountinfo_super_options(m: &Arc<super::Mount>) -> &'static str {
    if (m.flags.load(Ordering::Acquire) & super::MNT_RDONLY) != 0 { "ro" } else { "rw" }
}
