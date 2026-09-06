use super::*;
use std::sync::Arc;
// Linux 7.2.0-rc4 net/unix/af_unix.c unix_find_bsd: normal path permission
// MAY_WRITE precedes S_ISSOCK; abstract addresses have no filesystem DAC.
struct InodeOps;
impl vfs::InodeOps for InodeOps {}
struct FileOps;
impl vfs::FileOps for FileOps {}
const OWNER:u32=1000;
const GROUP:u32=2000;
fn cred(uid:u32,gid:u32)->vfs::Cred {
    vfs::Cred {uid,gid,cap_dac_override:false,cap_dac_read_search:false,
        cap_fowner:false,cap_chown:false,cap_fsetid:false,groups:vfs::GroupList::empty()}
}
fn setup(mode:u32,cred:vfs::Cred) {
    let inode=vfs::inode::InodeBuilder::new(92001,mode,Arc::new(InodeOps),Arc::new(FileOps)).owner(OWNER,GROUP).build();
    let dentry=vfs::Dentry::new_root(inode.clone());
    PATH.with(|p|*p.borrow_mut()=Some(vfs::VfsPath{mnt_id:0,dentry,inode,last_component:None}));
    CRED.with(|c|*c.borrow_mut()=Some(cred));LOOKUPS.set(0);CREDENTIALS.set(0);
}
fn resolve()->Result<net::UnixAddr,i64>{resolve_unix_addr(b"/endpoint".to_vec())}
#[test]
fn owner_write_admitted_and_read_only_denied() {
    setup(vfs::types::S_IFSOCK as u32|0o600,cred(OWNER,999));assert!(resolve().is_ok());
    assert_eq!(LOOKUPS.get(),1);assert_eq!(CREDENTIALS.get(),1);
    setup(vfs::types::S_IFSOCK as u32|0o400,cred(OWNER,GROUP));
    assert_eq!(resolve().err(),Some(-(Errno::Eacces as i32 as i64)));
}
#[test]
fn foreign_denied_primary_group_write_allowed() {
    setup(vfs::types::S_IFSOCK as u32|0o620,cred(3000,3001));
    assert_eq!(resolve().err(),Some(-(Errno::Eacces as i32 as i64)));
    setup(vfs::types::S_IFSOCK as u32|0o620,cred(3000,GROUP));assert!(resolve().is_ok());
    setup(vfs::types::S_IFSOCK as u32|0o640,cred(3000,GROUP));
    assert_eq!(resolve().err(),Some(-(Errno::Eacces as i32 as i64)));
}
#[test]
fn supplementary_group_write_allowed_but_owner_class_takes_precedence() {
    let mut member=cred(3000,3001);
    member.groups=vfs::GroupList::from_sorted(Arc::from([GROUP]));
    setup(vfs::types::S_IFSOCK as u32|0o020,member);assert!(resolve().is_ok());
    setup(vfs::types::S_IFSOCK as u32|0o020,cred(OWNER,GROUP));
    assert_eq!(resolve().err(),Some(-(Errno::Eacces as i32 as i64)));
}
#[test]
fn nonwritable_nonsocket_denied_before_type_check() {
    setup(vfs::types::S_IFREG as u32|0o400,cred(OWNER,GROUP));
    assert_eq!(resolve().err(),Some(-(Errno::Eacces as i32 as i64)));
    setup(vfs::types::S_IFREG as u32|0o600,cred(OWNER,GROUP));
    assert_eq!(resolve().err(),Some(-(Errno::Econnrefused as i32 as i64)));
}
#[test]
fn abstract_skips_lookup_and_credentials() {
    PATH.with(|p|*p.borrow_mut()=None);CRED.with(|c|*c.borrow_mut()=None);
    LOOKUPS.set(0);CREDENTIALS.set(0);
    let address=resolve_unix_addr(b"\0private".to_vec()).unwrap();assert!(!address.is_pathname());
    assert_eq!(LOOKUPS.get(),0);assert_eq!(CREDENTIALS.get(),0);
}
