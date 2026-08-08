use alloc::sync::{Arc, Weak};

use crate::inode::InodeRef;
use crate::superblock::SuperBlock;

use super::{Dentry, DentryOps, Lockref, QStr, D_ROOT, D_DISCONNECTED, D_NEGATIVE, D_OP_MASK, D_TYPE_MASK, op_flags_for, type_bits_for};
use sync::RwLock;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

/// Name hash for a dentry whose `d_hash` hook declines to fold (Linux
/// `full_name_hash` with no case folding). The same function the no-hook path
/// uses, narrowed to the width a hook returns. # C: O(name.len())
pub(crate) fn default_name_hash(name: &str) -> u32 { Dentry::fnv1a(name.as_bytes()) as u32 }

impl Dentry {
    /// `full_name_hash(parent, name)` (`16§96`). # C: O(name.len())
    pub fn compute_hash(parent: Option<&Arc<Dentry>>, name: &str) -> u32 {
        let salt = match parent { Some(p) => Arc::as_ptr(p) as usize as u64, None => 0 };
        let name_hash = match parent.and_then(|p| p.d_op).and_then(|o| o.d_hash) {
            Some(f) => f(parent.expect("d_op comes from the parent"), name) as u64,
            None    => Self::fnv1a(name.as_bytes()),
        };
        let mut h = salt.wrapping_mul(0x100000001B3) ^ name_hash;
        h ^= h >> 32;
        (h as u32) ^ ((h >> 13) as u32)
    }

    /// FNV-1a 64 over `bytes`. # C: O(bytes.len())
    pub(super) fn fnv1a(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in bytes { h = (h ^ b as u64).wrapping_mul(0x100000001B3); }
        h
    }

    /// Shared builder. # C: O(name.len())
    pub(super) fn build(parent: Option<Arc<Dentry>>, name: &str, inode: Option<InodeRef>, sb: Weak<SuperBlock>, d_op: Option<&'static DentryOps>, mut flags: u32) -> Arc<Self> {
        if inode.is_none() { flags |= D_NEGATIVE; }
        flags = (flags & !D_TYPE_MASK) | type_bits_for(&inode);
        flags = (flags & !D_OP_MASK) | op_flags_for(d_op);
        let qname = QStr::new(parent.as_ref(), name);
        let d = Arc::new(Self {
            parent,
            name: qname,
            inode: RwLock::new(inode),
            sb,
            d_op,
            d_count: Lockref::new(),
            d_flags: AtomicU32::new(flags),
            children: RwLock::new(BTreeMap::new()),
            d_time: AtomicU64::new(0),
            d_fsdata: AtomicU64::new(0),
            d_seq: AtomicU32::new(0),
            counted: AtomicBool::new(false),
        });
        if let Some(f) = d_op.and_then(|o| o.d_init) { f(&d); }
        d
    }

    /// Construct a positive dentry. # C: O(name.len())
    pub fn new(parent: Option<Arc<Dentry>>, name: alloc::string::String, inode: InodeRef) -> Arc<Self> {
        Self::build(parent, &name, Some(inode), Weak::new(), None, 0)
    }

    /// Construct a negative dentry. # C: O(name.len())
    pub fn new_negative(parent: Option<Arc<Dentry>>, name: alloc::string::String) -> Arc<Self> {
        Self::build(parent, &name, None, Weak::new(), None, 0)
    }

    /// Construct a free-floating root dentry. # C: O(1)
    pub fn new_root(inode: InodeRef) -> Arc<Self> {
        Self::build(None, "", Some(inode), Weak::new(), None, D_ROOT)
    }

    /// Construct a child dentry under `parent`, inheriting `d_sb` and `d_op`.
    /// The parent directory may claim the child instead (`i_op->child_d_op`,
    /// Linux `d_splice_alias_ops`): that is how a `/proc/<pid>` subtree gets the
    /// revalidating vector while `/proc`'s static children keep the default.
    /// # C: O(name.len())
    pub fn new_child(parent: &Arc<Dentry>, name: &str, inode: Option<InodeRef>) -> Arc<Self> {
        let d_op = parent.inode()
            .and_then(|i| i.i_op().child_d_op(&i, name))
            .or(parent.d_op);
        Self::build(Some(parent.clone()), name, inode, parent.sb.clone(), d_op, 0)
    }

    /// Construct a superblock root dentry. # C: O(1)
    pub fn new_root_in_sb(inode: InodeRef, sb: &Arc<SuperBlock>) -> Arc<Self> {
        Self::new_root_in_sb_ops(inode, sb, None)
    }

    /// Construct a superblock root dentry carrying the instance-wide dentry
    /// operations (Linux `sb->s_d_op`, propagated to every child at `d_alloc`).
    /// A casefolded filesystem passes what
    /// [`crate::dentry::casefold::sb_enable_casefold`] returned, so the whole
    /// tree hashes and compares names through the instance's encoding.
    /// # C: O(1)
    pub fn new_root_in_sb_ops(inode: InodeRef, sb: &Arc<SuperBlock>, d_op: Option<&'static DentryOps>) -> Arc<Self> {
        Self::build(None, "", Some(inode), Arc::downgrade(sb), d_op, D_ROOT)
    }

    /// Construct an anonymous disconnected dentry. # C: O(1)
    pub fn new_anon(inode: InodeRef) -> Arc<Self> {
        let sb = match inode.i_sb() { Some(s) => Arc::downgrade(&s), None => Weak::new() };
        Self::build(None, "/", Some(inode), sb, None, D_DISCONNECTED)
    }

    /// Construct a pseudo dentry with dynamic `d_dname`. # C: O(name.len())
    pub fn new_pseudo(name: &str, inode: InodeRef, d_op: &'static DentryOps) -> Arc<Self> {
        let sb = match inode.i_sb() { Some(s) => Arc::downgrade(&s), None => Weak::new() };
        Self::build(None, name, Some(inode), sb, Some(d_op), 0)
    }
}
