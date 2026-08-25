use super::*;
use crate::inotify::types::{FAN_DELETE_SELF, FAN_EVENT_ON_CHILD};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use crate::inotify::path::resolve_watch_path_at;
use vfs::{CreateCtx, Cred, Dentry, FileType, Inode, InodeBuilder, InodeOps,
    InodeRef, KResult, VfsError, default_file_ops, mk_mode};

struct DirData { kids: BTreeMap<&'static str, InodeRef> }
struct DirOps;

impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        inode.private::<DirData>().ok_or(VfsError::Enotdir)?
            .kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
    fn create(&self, _inode: &Inode, _name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        Err(VfsError::Eio)
    }
    fn mkdir(&self, _inode: &Inode, _name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        Err(VfsError::Eio)
    }
    fn symlink(&self, _inode: &Inode, _name: &str, _target: &[u8], _ctx: &CreateCtx) -> KResult<()> {
        Err(VfsError::Eio)
    }
}

fn cred(uid: u32) -> Cred {
    Cred {
        uid, gid: uid, cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}

fn reg(ino: u64, mode: u16, uid: u32) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, mode), vfs::default_inode_ops(), default_file_ops())
        .owner(uid, uid).build()
}

fn dir(ino: u64, mode: u16, uid: u32, kids: &[(&'static str, InodeRef)]) -> InodeRef {
    let mut map = BTreeMap::new();
    for (name, inode) in kids { map.insert(*name, inode.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, mode), Arc::new(DirOps), default_file_ops())
        .owner(uid, uid).private(Arc::new(DirData { kids: map })).build()
}

fn errno(e: syscall::errno::Errno) -> i64 { -(e.as_i32() as i64) }

/// Both halves of `fanotify_init` argument validation in the order the syscall
/// runs them, with the per-user group charge (which sits between them) elided.
fn init_args(flags: u32, event_f_flags: u32, admin: bool, audit: bool) -> i32 {
    let e = crate::inotify::validate::validate_fanotify_init_args(flags, event_f_flags, admin);
    if e != 0 { return e; }
    crate::inotify::validate::validate_fanotify_init_post_charge(flags, audit)
}

fn path_err(r: Result<InodeRef, i64>) -> i64 {
    match r {
        Ok(_) => 0,
        Err(e) => e,
    }
}

fn read_event_pair(ino: &InotifyData) -> (i32, u32) {
    let mut buf = [0u8; 16];
    assert_eq!(ino.read(0, &mut buf), Ok(16));
    (
        i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
    )
}


mod core;
mod fanotify;
mod events;

fn parse_events(buf: &[u8], n: usize) -> alloc::vec::Vec<(i32, u32, u32, alloc::vec::Vec<u8>)> {
    let mut out = alloc::vec::Vec::new();
    let mut o = 0usize;
    while o + 16 <= n {
        let wd = i32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        let mask = u32::from_le_bytes([buf[o + 4], buf[o + 5], buf[o + 6], buf[o + 7]]);
        let cookie = u32::from_le_bytes([buf[o + 8], buf[o + 9], buf[o + 10], buf[o + 11]]);
        let len = u32::from_le_bytes([buf[o + 12], buf[o + 13], buf[o + 14], buf[o + 15]]) as usize;
        assert_eq!(len % 16, 0, "len must be a whole multiple of sizeof(struct inotify_event)");
        let tail = &buf[o + 16..o + 16 + len];
        let name = tail.iter().position(|b| *b == 0).map_or(tail, |i| &tail[..i]).to_vec();
        out.push((wd, mask, cookie, name));
        o += 16 + len;
    }
    assert_eq!(o, n, "records must tile the returned byte count exactly");
    out
}

fn watched_dir(g: &Arc<InotifyData>, ino: u64, mask: u32) -> (InodeRef, i32) {
    let d = dir(ino, 0o755, 0, &[]);
    let wd = add_or_update_watch(g, inode_key(&d), d.fsid(), mask, true, None).unwrap();
    (d, wd)
}

