// Hosted tests for D4b: idmap (stat-out map + chown-in), getattr/Kstat,
// setattr_prepare DAC gate (utimes EPERM), get_link, utimensat UTIME_OMIT.

extern crate alloc;

use crate::getattr::{generic_fillattr, S_IFREG};
use crate::idmap::Idmap;
use crate::inode::InodeBuilder;
use crate::inode::InodeRef;
use crate::inode_ops::{default_inode_ops, mk_mode};
use crate::file_ops::default_file_ops;
use crate::namei::Cred;
use crate::setattr::{notify_change, setattr_prepare, Iattr, ATTR_ATIME, ATTR_MTIME, ATTR_MTIME_SET, ATTR_UID};
use crate::types::{FileType, VfsError};

// Mutable test inode recording perm/owner/times so apply paths are observable.
// The concrete `Inode` owns these fields natively (mode/owner/atime/mtime via
// `InodeBuilder` + the inherent `set_perm`/`set_owner`/`set_times` writers), so
// the old per-method overrides collapse into builder calls. A symlink stamps
// its target into the inline `i_link` (so `get_link` returns it; a regular file
// has no `i_link`, so `get_link` → `readlink` default `Einval`). Linux symlinks
// always carry `0o777`, so the old `perm()==None → default_perm_for` fallback
// is now just the literal mode and the assertions hold unchanged.
struct MetaInode;
impl MetaInode {
    fn reg(perm: u16, uid: u32, gid: u32) -> InodeRef {
        InodeBuilder::new(1, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
            .owner(uid, gid).build()
    }
    fn symlink(target: &[u8]) -> InodeRef {
        InodeBuilder::new(1, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops())
            .link(target.to_vec().into_boxed_slice()).build()
    }
}

fn cred_with(uid: u32) -> Cred {
    let mut c = Cred::root();
    c.uid = uid; c.gid = uid;
    c.cap_dac_override = false; c.cap_dac_read_search = false;
    c.cap_fowner = false; c.cap_chown = false; c.cap_fsetid = false;
    c
}

// T1: idmapped mount maps stat uid out; identity leaves it raw.
#[test]
fn t1_idmap_maps_stat_uid() {
    let inode = MetaInode::reg(0o644, 1000, 1000);
    let map = Idmap::uniform(0, 100_000, 65536);
    let st = generic_fillattr(inode.as_ref(), &map, None);
    assert_eq!(st.uid, 101_000);
    assert_eq!(st.gid, 101_000);
    assert_eq!(st.mode, S_IFREG | 0o644);
    let id = generic_fillattr(inode.as_ref(), &Idmap::identity(), None);
    assert_eq!(id.uid, 1000);
    assert_eq!(id.gid, 1000);
}

// T1b: chown-in maps the vfs uid to the fs uid stored on the inode.
#[test]
fn t1b_idmap_chown_in() {
    let inode: InodeRef = MetaInode::reg(0o644, 1000, 1000);
    let map = Idmap::uniform(0, 100_000, 65536);
    // chown to vfsuid 101000 with CAP_CHOWN; stored fs uid must be 1000.
    let mut ia = Iattr { valid: ATTR_UID, uid: 101_000, ..Default::default() };
    notify_change(&map, &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.uid(), Some(1000));
}

// T2: setattr_prepare non-owner specific-time utimes -> EPERM; owner -> Ok;
//     non-owner BOTH-to-now with MAY_WRITE granted -> Ok via the write branch.
//     A single-field "now" (e.g. {UTIME_OMIT, UTIME_NOW}) is owner-gated like a
//     specific time (Linux ATTR_TIMES_SET), so the write branch covers only the
//     both-atime+mtime-to-now case (NULL times / both UTIME_NOW).
#[test]
fn t2_setattr_prepare_utimes_eperm() {
    let inode: InodeRef = MetaInode::reg(0o666, 1000, 1000); // other-write set
    // non-owner, specific mtime -> EPERM
    let mut ia = Iattr { valid: ATTR_MTIME | ATTR_MTIME_SET, mtime_ns: 123, ..Default::default() };
    assert_eq!(setattr_prepare(&Idmap::identity(), &inode, &mut ia, &cred_with(2000)), Err(VfsError::Eperm));
    // owner, specific mtime -> Ok
    let mut ia2 = Iattr { valid: ATTR_MTIME | ATTR_MTIME_SET, mtime_ns: 123, ..Default::default() };
    assert!(setattr_prepare(&Idmap::identity(), &inode, &mut ia2, &cred_with(1000)).is_ok());
    // non-owner, BOTH-to-now (no _SET), write permitted by other-write -> Ok
    let mut ia3 = Iattr { valid: ATTR_ATIME | ATTR_MTIME, atime_ns: 999, mtime_ns: 999, ..Default::default() };
    assert!(setattr_prepare(&Idmap::identity(), &inode, &mut ia3, &cred_with(2000)).is_ok());
    // non-owner, single-field "now" {UTIME_OMIT, UTIME_NOW} -> EPERM (ATTR_TIMES_SET)
    let mut ia3b = Iattr { valid: ATTR_MTIME, mtime_ns: 999, ..Default::default() };
    assert_eq!(setattr_prepare(&Idmap::identity(), &inode, &mut ia3b, &cred_with(2000)), Err(VfsError::Eperm));
    // non-owner, BOTH-to-now, no write perm -> EACCES
    let ro: InodeRef = MetaInode::reg(0o644, 1000, 1000);
    let mut ia4 = Iattr { valid: ATTR_ATIME | ATTR_MTIME, atime_ns: 999, mtime_ns: 999, ..Default::default() };
    assert_eq!(setattr_prepare(&Idmap::identity(), &ro, &mut ia4, &cred_with(2000)), Err(VfsError::Eacces));
}

// T3: get_link returns the symlink target; non-symlink -> Einval.
#[test]
fn t3_get_link() {
    let link: InodeRef = MetaInode::symlink(b"/target");
    assert_eq!(link.get_link().unwrap(), b"/target".to_vec());
    let reg: InodeRef = MetaInode::reg(0o644, 0, 0);
    assert_eq!(reg.get_link(), Err(VfsError::Einval));
}

// T4: utimensat UTIME_OMIT semantics — only the set field changes.
#[test]
fn t4_utimensat_omit_leaves_other() {
    let inode: InodeRef = MetaInode::reg(0o644, 1000, 1000);
    inode.set_times(Some(11), Some(22), 0).unwrap();
    // Update mtime only (atime omitted), owner cred so the gate passes.
    let mut ia = Iattr { valid: ATTR_MTIME, mtime_ns: 555, ctime_ns: 1, ..Default::default() };
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.atime(), Some(11)); // preserved (UTIME_OMIT)
    assert_eq!(inode.mtime(), Some(555)); // updated
}

// T5: generic_fillattr overlay + perm()==None reproduces the default fallback.
#[test]
fn t5_fillattr_default_perm_fallback() {
    let inode: InodeRef = MetaInode::symlink(b"/x"); // perm()==None, Symlink
    let st = generic_fillattr(inode.as_ref(), &Idmap::identity(), None);
    assert_eq!(st.mode & 0o7777, 0o777); // default_perm_for(Symlink)
}
