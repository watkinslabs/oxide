use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::Dentry;

impl Dentry {
    /// Absolute global path for this dentry. # C: O(depth × N_mounts)
    pub fn absolute_path(&self) -> Vec<u8> {
        if let Some(dyn_name) = self.d_dname() { return dyn_name.into_bytes(); }
        let mut parts: Vec<String> = Vec::new();
        if !self.name.name().is_empty() { parts.push(String::from(self.name.name())); }
        let mut cur: Option<Arc<Dentry>> = match self.parent.clone() {
            Some(p) => Some(p),
            None if self.is_root() => crate::mount::mountpoint_for_root_ptr(self as *const Dentry),
            None => None,
        };
        while let Some(d) = cur {
            if !d.name.name().is_empty() { parts.push(String::from(d.name.name())); }
            cur = match d.parent.clone() {
                Some(p) => Some(p),
                None if d.is_root() => crate::mount::mountpoint_for_root_ptr(Arc::as_ptr(&d)),
                None => None,
            };
        }
        if parts.is_empty() { return alloc::vec![b'/']; }
        let mut out: Vec<u8> = Vec::new();
        for name in parts.iter().rev() {
            out.push(b'/');
            out.extend_from_slice(name.as_bytes());
        }
        out
    }

    /// Filesystem-internal path string for this dentry. # C: O(depth)
    pub fn dentry_path(&self, root: Option<&Arc<Dentry>>) -> String {
        if let Some(dyn_name) = self.d_dname() { return dyn_name; }
        let root_ptr = root.map(Arc::as_ptr);
        let me_ptr = self as *const Dentry;
        let mut parts: Vec<String> = Vec::new();
        if root_ptr != Some(me_ptr) && !self.is_root() && !self.is_disconnected() {
            if !self.name().is_empty() { parts.push(String::from(self.name())); }
            let mut cur = self.parent.clone();
            while let Some(d) = cur {
                if root_ptr == Some(Arc::as_ptr(&d)) || d.is_root() || d.is_disconnected() { break; }
                if !d.name().is_empty() { parts.push(String::from(d.name())); }
                cur = d.parent.clone();
            }
        }
        let mut out = String::new();
        if parts.is_empty() { out.push('/'); }
        else { for name in parts.iter().rev() { out.push('/'); out.push_str(name); } }
        if self.is_unlinked() || self.is_disconnected() { out.push_str(" (deleted)"); }
        out
    }
}
