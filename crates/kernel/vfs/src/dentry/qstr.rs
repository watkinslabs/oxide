use alloc::string::String;
use alloc::sync::Arc;

use super::Dentry;

/// Max name length stored inline in the dentry (Linux `DNAME_INLINE_LEN`,
/// 32 on 64-bit). Names `<=` this avoid the per-dentry heap allocation.
pub const DNAME_INLINE_LEN: usize = 32;

/// Name storage backing a `QStr`: inline UTF-8 bytes (Linux `d_iname`) for
/// short names, external `String` (Linux `d_name.name`) for long names.
/// `Inline.buf[..len]` always holds the bytes of a once-valid `&str`.
enum DName { Inline { buf: [u8; DNAME_INLINE_LEN], len: u8 }, Heap(String) }

/// Hashed path component. `hash` is `full_name_hash(parent, name)` so the
/// same name under different parents lands in different hash buckets and
/// `d_op->d_hash` can fold case before hashing.
pub struct QStr {
    pub(super) hash: u32,
    name: DName,
}

impl QStr {
    /// # C: O(name.len())
    pub fn new(parent: Option<&Arc<Dentry>>, name: &str) -> Self {
        let hash = Dentry::compute_hash(parent, name);
        let b = name.as_bytes();
        let name = if b.len() <= DNAME_INLINE_LEN {
            let mut buf = [0u8; DNAME_INLINE_LEN];
            buf[..b.len()].copy_from_slice(b);
            DName::Inline { buf, len: b.len() as u8 }
        } else { DName::Heap(String::from(name)) };
        QStr { hash, name }
    }
    /// # C: O(1)
    pub fn hash(&self) -> u32 { self.hash }
    /// # C: O(1)
    pub fn name(&self) -> &str {
        match &self.name {
            // Bytes were copied from a valid `&str` in `new`; checked decode
            // can never fail, `unwrap_or` keeps it unsafe-free.
            DName::Inline { buf, len } => core::str::from_utf8(&buf[..*len as usize]).unwrap_or(""),
            DName::Heap(s) => s,
        }
    }
    /// Test probe: is the name stored inline (not heap)? # C: O(1)
    #[doc(hidden)]
    pub fn is_inline(&self) -> bool { matches!(self.name, DName::Inline { .. }) }
}
