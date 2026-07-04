use alloc::sync::{Arc, Weak};

use crate::inode::InodeRef;
use crate::superblock::SuperBlock;

use super::{Dentry, DentryOps, Lockref, QStr, D_ROOT, D_DISCONNECTED, D_NEGATIVE, D_OP_MASK, D_TYPE_MASK, op_flags_for, type_bits_for};
use sync::RwLock;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

impl Dentry {
    /// `full_name_hash(parent, name)` (`16§96`). # C: O(name.len())
    pub fn compute_hash(parent: Option<&Arc<Dentry>>, name: &str) -> u32 {
        let salt = match parent { Some(p) => Arc::as_ptr(p) as usize as u64, None => 0 };
        let name_hash = match parent.and_then(|p| p.d_op).and_then(|o| o.d_hash) {
            Some(f) => f(name) as u64,
            None    => Self::fnv1a(name.as_bytes()),
        };
        let mut h = salt.wrapping_mul(0x100000001B3) ^ name_hash;
        h ^= h >> 32;
        (h as u32) ^ ((h >> 13) as u32)
    }

    /// FNV-1a 64 over `bytes`. # C: O(bytes.len())
    fn fnv1a(bytes: &[u8]) -> u64 {
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
    /// # C: O(name.len())
    pub fn new_child(parent: &Arc<Dentry>, name: &str, inode: Option<InodeRef>) -> Arc<Self> {
        Self::build(Some(parent.clone()), name, inode, parent.sb.clone(), parent.d_op, 0)
    }

    /// Construct a superblock root dentry. # C: O(1)
    pub fn new_root_in_sb(inode: InodeRef, sb: &Arc<SuperBlock>) -> Arc<Self> {
        Self::build(None, "", Some(inode), Arc::downgrade(sb), None, D_ROOT)
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
