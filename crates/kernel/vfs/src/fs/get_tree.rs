extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Devices as FsClass, Spinlock};

use crate::dentry::Dentry;
use crate::superblock::{SuperBlock, SB_RDONLY};

use super::api::KResult;
use super::fs_context::{self, FsParameter, SB_FLAGS_USER_MASK};
struct SharedSuper {
    fs_name: String,
    key:     String,
    sb:      Weak<SuperBlock>,
}

static SHARED_SUPERS: Spinlock<Vec<SharedSuper>, FsClass> = Spinlock::new(Vec::new());

fn stamp_sb_flags(sb: &SuperBlock, fc: &fs_context::FsContext) {
    let mask = fc.sb_flags_mask();
    let set = fc.sb_flags() & mask;
    let clear = !fc.sb_flags() & mask;
    sb.set_s_flags(set, clear);
    sb.set_readonly(set & SB_RDONLY != 0);
}

fn sget_probe(fs_name: &str, key: &str) -> Option<Arc<SuperBlock>> {
    let mut list = SHARED_SUPERS.lock();
    list.retain(|e| e.sb.strong_count() > 0);
    for e in list.iter() {
        if e.fs_name == fs_name && e.key == key {
            if let Some(sb) = e.sb.upgrade() {
                if sb.grab_active() { return Some(sb); }
            }
        }
    }
    None
}

pub fn get_tree_nodev<F>(fc: &mut fs_context::FsContext, fill: F) -> KResult<Arc<SuperBlock>>
where F: FnOnce(&mut fs_context::FsContext) -> KResult<Arc<SuperBlock>> {
    let sb = fill(fc)?;
    stamp_sb_flags(&sb, fc);
    Ok(sb)
}

pub fn get_tree_keyed<F>(fc: &mut fs_context::FsContext, key: &str, fill: F) -> KResult<Arc<SuperBlock>>
where F: FnOnce(&mut fs_context::FsContext) -> KResult<Arc<SuperBlock>> {
    let fs_name = fc.fs_type().name().to_string();
    if let Some(sb) = sget_probe(&fs_name, key) { return Ok(sb); }
    let sb = fill(fc)?;
    stamp_sb_flags(&sb, fc);
    let mut list = SHARED_SUPERS.lock();
    list.retain(|e| e.sb.strong_count() > 0);
    for e in list.iter() {
        if e.fs_name == fs_name && e.key == key {
            if let Some(shared) = e.sb.upgrade() {
                if shared.grab_active() { return Ok(shared); }
            }
        }
    }
    list.push(SharedSuper { fs_name, key: key.to_string(), sb: Arc::downgrade(&sb) });
    Ok(sb)
}

pub fn get_tree_single<F>(fc: &mut fs_context::FsContext, fill: F) -> KResult<Arc<SuperBlock>>
where F: FnOnce(&mut fs_context::FsContext) -> KResult<Arc<SuperBlock>> {
    get_tree_keyed(fc, "", fill)
}

pub fn reconfigure_single(sb: Arc<SuperBlock>, sb_flags: u64, params: &[FsParameter]) -> KResult<()> {
    let root: Arc<Dentry> = sb.s_root().ok_or(crate::types::VfsError::Einval)?;
    let mut fc = fs_context::FsContext::for_reconfigure(sb, root, sb_flags, SB_FLAGS_USER_MASK);
    for p in params {
        if let Err(e) = fs_context::vfs_parse_fs_param(&mut fc, p) {
            fc.fail();
            fs_context::put_fs_context(fc);
            return Err(e);
        }
    }
    let r = fs_context::reconfigure_super(&mut fc);
    fs_context::put_fs_context(fc);
    r
}
