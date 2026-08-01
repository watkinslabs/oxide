// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

extern crate alloc;

mod userbuf {
    pub fn validate_user_buf(addr: u64, len: u64, _align: u64) -> Result<(), i64> {
        if len != 0 && addr == 0 { return Err(-(syscall::errno::Errno::Efault.as_i32() as i64)); }
        Ok(())
    }
    pub fn validate_user_buf_writable(addr: u64, len: u64, _align: u64) -> Result<(), i64> {
        validate_user_buf(addr, len, _align)
    }
}

#[path = "../../vfs/tests/common/mod.rs"]
mod common;

#[path = "../src/statmount_abi.rs"]
mod statmount_abi;
#[path = "../src/statmount_target.rs"]
mod statmount_target;
#[path = "../src/457_statmount.rs"]
mod s457_statmount;
#[path = "../src/458_listmount.rs"]
mod s458_listmount;
use s457_statmount as statmount;
use s458_listmount as listmount;

/// `statmount(2)`/`listmount(2)` speak the UNIQUE mount-id space, which is
/// offset above the tree's internal `mnt_id`. Feeding a raw internal id is
/// EINVAL, and that rung is what tells the two id spaces apart.
fn uid_of(mnt_id: u64) -> u64 { vfs::mount::unique_mnt_id(mnt_id) }

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);

const LSMT_ROOT: u64 = u64::MAX;
const REQ_SIZE: u32 = 24;
const STATMOUNT_ALL: u64 = statmount_abi::STATMOUNT_SUPPORTED;
const U64_SIZE: usize = 8;

fn cur_ns() -> vfs::mntns::MntNamespaceRef {
    CUR_NS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().expect("current namespace owner").clone()
}
fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    common::install();
    vfs::mount::set_current_ns_provider(cur_ns);
    g
}

struct TestFs { name: &'static str, ino: u64 }
struct TestDirOps;
impl vfs::InodeOps for TestDirOps {
    fn lookup(&self, _inode: &vfs::inode::Inode, _n: &str) -> vfs::KResult<vfs::InodeRef> {
        Ok(test_dir(0xB810_D100))
    }
}
fn test_dir(ino: u64) -> vfs::InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(vfs::FileType::Directory, 0o755),
        Arc::new(TestDirOps), vfs::default_file_ops()).build()
}
impl vfs::fs::FileSystem for TestFs {
    fn name(&self) -> &str { self.name }
    fn root(&self) -> Option<vfs::InodeRef> {
        Some(test_dir(self.ino))
    }
}

fn new_ns() -> vfs::mntns::MntNamespaceRef {
    let init = vfs::mntns::initial();
    let namespace = vfs::mntns::allocate(init.owner_user_namespace()).expect("allocate mount namespace");
    *CUR_NS.lock().unwrap_or_else(|e| e.into_inner()) = Some(namespace.clone());
    namespace
}

fn mount_tree(tag: &'static str) -> (vfs::mntns::MntNamespaceRef, u64, u64, u64) {
    let namespace = new_ns();
    let ns = namespace.id();
    common::register("/", Arc::new(TestFs { name: tag, ino: ns })).expect("root mount");
    common::register("/sys", Arc::new(TestFs { name: tag, ino: ns + 1 })).expect("sys mount");
    common::register("/sys/kernel/debug", Arc::new(TestFs { name: tag, ino: ns + 2 })).expect("debug mount");
    let root = vfs::mount::root_mount_id(ns).expect("root id");
    let sys = common::mount_at_path_exact("/sys").expect("sys id").mnt_id;
    let debug = common::mount_at_path_exact("/sys/kernel/debug").expect("debug id").mnt_id;
    (namespace, root, sys, debug)
}

fn req(mnt_id: u64, param: u64) -> [u8; 24] {
    let mut r = [0u8; 24];
    r[0..4].copy_from_slice(&REQ_SIZE.to_le_bytes());
    r[8..16].copy_from_slice(&mnt_id.to_le_bytes());
    r[16..24].copy_from_slice(&param.to_le_bytes());
    r
}

fn list_ids(mnt_id: u64, param: u64, cap: usize) -> (i64, Vec<u64>) {
    list_flags(mnt_id, param, cap, 0)
}

fn list_flags(mnt_id: u64, param: u64, cap: usize, flags: u64) -> (i64, Vec<u64>) {
    let r = req(mnt_id, param);
    let mut ids = vec![0u64; cap.max(1)];
    let rv = listmount::sys_listmount(&SyscallArgs {
        a0: r.as_ptr() as u64,
        a1: ids.as_mut_ptr() as u64,
        a2: cap as u64,
        a3: flags,
        a4: 0,
        a5: 0,
    });
    ids.truncate(rv.max(0) as usize);
    (rv, ids)
}

fn statmount_id(mnt_id: u64) -> i64 { statmount_buf(mnt_id, STATMOUNT_ALL).0 }

/// Drive `statmount` and hand back both the return value and the raw reply, so
/// a test can assert on the encoded bytes rather than only on the errno.
fn statmount_buf(mnt_id: u64, mask: u64) -> (i64, Vec<u8>) {
    let r = req(mnt_id, mask);
    let mut buf = vec![0u8; 4096];
    let rv = statmount::sys_statmount(&SyscallArgs {
        a0: r.as_ptr() as u64,
        a1: buf.as_mut_ptr() as u64,
        a2: buf.len() as u64,
        a3: 0,
        a4: 0,
        a5: 0,
    });
    (rv, buf)
}

fn u64_at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }
fn u32_at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn str_at(b: &[u8], off: u32) -> String {
    let s = &b[statmount_abi::SM_SIZE + off as usize..];
    let end = s.iter().position(|c| *c == 0).unwrap();
    String::from_utf8(s[..end].to_vec()).unwrap()
}
const OFF_MASK: usize = 8;
const OFF_MNT_ID: usize = 40;
const OFF_MNT_PARENT_ID: usize = 48;
const OFF_FS_TYPE: usize = 36;
const OFF_MNT_POINT: usize = 108;

#[test]
fn listmount_root_is_current_namespace_recursive_and_resumable() {
    let _g = guard();
    let (_a_namespace, _a_root, _a_sys, a_debug) = mount_tree("mount-api-a");
    let (_b_namespace, _b_root, b_sys, b_debug) = mount_tree("mount-api-b");

    let (rv, ids) = list_ids(LSMT_ROOT, 0, 16);
    assert!(rv >= 3, "current namespace tree returned");
    assert!(ids.contains(&uid_of(b_sys)), "current namespace child is listed");
    assert!(ids.contains(&uid_of(b_debug)), "current namespace descendant is listed");
    assert!(!ids.contains(&uid_of(a_debug)), "foreign namespace mount must not leak");

    let (rv, tail) = list_ids(LSMT_ROOT, uid_of(b_sys), 16);
    assert!(rv >= 1, "resume after /sys should still expose later descendants");
    assert!(!tail.contains(&uid_of(b_sys)), "resume cursor excludes prior id");
    assert!(tail.contains(&uid_of(b_debug)), "resume cursor keeps later mount");
}

#[test]
fn listmount_ids_are_the_unique_space_and_a_raw_mount_id_is_einval() {
    let _g = guard();
    let (_ns, _root, sys, _debug) = mount_tree("mount-api-uid");
    let (_rv, ids) = list_ids(LSMT_ROOT, 0, 16);
    // Every id handed out is a unique id, never the tree-internal one.
    assert!(ids.iter().all(|id| *id > vfs::mount::MNT_UNIQUE_ID_OFFSET));
    assert!(ids.contains(&uid_of(sys)));
    // ...and feeding an internal id straight back in is rejected rather than
    // silently naming some other mount.
    assert_eq!(statmount_id(sys), eno(Errno::Einval));
    let (rv, _) = list_ids(sys, 0, 16);
    assert_eq!(rv, eno(Errno::Einval));
    // The cursor lives in the same space.
    let (rv, _) = list_ids(LSMT_ROOT, sys, 16);
    assert_eq!(rv, eno(Errno::Einval));
}

#[test]
fn listmount_lists_a_subtree_by_topology_and_excludes_the_subtree_root() {
    let _g = guard();
    let (_ns, root, sys, debug) = mount_tree("mount-api-sub");
    let (rv, ids) = list_ids(uid_of(sys), 0, 16);
    assert!(rv >= 1, "the subtree under /sys is listed");
    assert!(ids.contains(&uid_of(debug)), "descendant of the named mount is listed");
    assert!(!ids.contains(&uid_of(sys)), "the named mount itself is excluded");
    assert!(!ids.contains(&uid_of(root)), "an ancestor is not under the named mount");
}

#[test]
fn listmount_reverse_returns_the_same_set_newest_first() {
    let _g = guard();
    let (_ns, _root, _sys, _debug) = mount_tree("mount-api-rev");
    let (_rv, fwd) = list_ids(LSMT_ROOT, 0, 16);
    let (_rv, rev) = list_flags(LSMT_ROOT, 0, 16, 1);
    let mut expect = fwd.clone();
    expect.reverse();
    assert_eq!(rev, expect, "reverse is the forward list read backwards");
    assert!(fwd.windows(2).all(|w| w[0] < w[1]), "forward is mount-id ascending");
}

#[test]
fn listmount_honours_the_caller_supplied_capacity() {
    let _g = guard();
    let (_ns, _root, _sys, _debug) = mount_tree("mount-api-cap");
    let (all, _) = list_ids(LSMT_ROOT, 0, 16);
    assert!(all >= 3);
    let (rv, ids) = list_ids(LSMT_ROOT, 0, 2);
    assert_eq!(rv, 2, "no more ids are written than the caller asked for");
    assert_eq!(ids.len(), 2);
    // A zero-capacity probe writes nothing and reports nothing.
    let (rv, _) = list_ids(LSMT_ROOT, 0, 0);
    assert_eq!(rv, 0);
}

#[test]
fn statmount_rejects_foreign_namespace_mount_id() {
    let _g = guard();
    let (_a_namespace, _a_root, _a_sys, a_debug) = mount_tree("mount-api-c");
    let (_b_namespace, _b_root, _b_sys, b_debug) = mount_tree("mount-api-d");

    assert_eq!(statmount_id(uid_of(b_debug)), 0, "current namespace mount id is visible");
    assert_eq!(statmount_id(uid_of(a_debug)), eno(Errno::Enoent),
        "foreign namespace mount id is hidden");
}

#[test]
fn statmount_reports_only_the_requested_fields() {
    let _g = guard();
    let (_ns, _root, sys, _debug) = mount_tree("mount-api-mask");

    // Asking for one field yields exactly that field.
    let (rv, buf) = statmount_buf(uid_of(sys), statmount_abi::STATMOUNT_MNT_BASIC);
    assert_eq!(rv, 0);
    assert_eq!(u64_at(&buf, OFF_MASK), statmount_abi::STATMOUNT_MNT_BASIC);
    assert_eq!(u64_at(&buf, OFF_MNT_ID), uid_of(sys));
    assert_eq!(u32_at(&buf, OFF_FS_TYPE), 0, "an unrequested string has no offset");

    // Asking for a different one yields that one instead.
    let (rv, buf) = statmount_buf(uid_of(sys), statmount_abi::STATMOUNT_FS_TYPE);
    assert_eq!(rv, 0);
    assert_eq!(u64_at(&buf, OFF_MASK), statmount_abi::STATMOUNT_FS_TYPE);
    assert_eq!(str_at(&buf, u32_at(&buf, OFF_FS_TYPE)), "mount-api-mask");
    assert_eq!(u64_at(&buf, OFF_MNT_ID), 0, "an unrequested scalar stays zero");
}

#[test]
fn statmount_agrees_with_listmount_on_parentage() {
    let _g = guard();
    let (_ns, root, sys, debug) = mount_tree("mount-api-parent");
    let want = statmount_abi::STATMOUNT_MNT_BASIC | statmount_abi::STATMOUNT_MNT_POINT;

    let (rv, buf) = statmount_buf(uid_of(debug), want);
    assert_eq!(rv, 0);
    assert_eq!(u64_at(&buf, OFF_MNT_ID), uid_of(debug));
    assert_eq!(u64_at(&buf, OFF_MNT_PARENT_ID), uid_of(sys),
        "the parent statmount reports is the mount listmount nests it under");
    assert_eq!(str_at(&buf, u32_at(&buf, OFF_MNT_POINT)), "/sys/kernel/debug");

    let (rv, buf) = statmount_buf(uid_of(root), want);
    assert_eq!(rv, 0);
    assert_eq!(u64_at(&buf, OFF_MNT_PARENT_ID), uid_of(root),
        "the root mount is its own parent");
}

#[test]
fn statmount_reports_the_supported_mask_and_never_exceeds_it() {
    let _g = guard();
    let (_ns, _root, sys, _debug) = mount_tree("mount-api-supp");
    let (rv, buf) = statmount_buf(uid_of(sys), u64::MAX);
    assert_eq!(rv, 0, "an over-broad request is satisfied, not rejected");
    assert_eq!(u64_at(&buf, OFF_MASK) & !STATMOUNT_ALL, 0,
        "no bit outside the supported set is ever raised");
}

#[test]
fn mount_api_rejects_bad_flags_and_short_requests() {
    let _g = guard();
    let (_namespace, _root, _sys, debug) = mount_tree("mount-api-e");
    let r = req(uid_of(debug), 0);
    let mut one = [0u64; 1];
    let bad_list = listmount::sys_listmount(&SyscallArgs {
        a0: r.as_ptr() as u64,
        a1: one.as_mut_ptr() as u64,
        a2: one.len() as u64,
        a3: 2,
        a4: 0,
        a5: 0,
    });
    assert_eq!(bad_list, eno(Errno::Einval));

    let bad_stat = statmount::sys_statmount(&SyscallArgs {
        a0: r.as_ptr() as u64,
        a1: one.as_mut_ptr() as u64,
        a2: U64_SIZE as u64,
        a3: 2,
        a4: 0,
        a5: 0,
    });
    assert_eq!(bad_stat, eno(Errno::Einval), "an unknown statmount flag is rejected");

    let short = [0u8; 24];
    let rv = listmount::sys_listmount(&SyscallArgs {
        a0: short.as_ptr() as u64,
        a1: one.as_mut_ptr() as u64,
        a2: one.len() as u64,
        a3: 0,
        a4: 0,
        a5: 0,
    });
    assert_eq!(rv, eno(Errno::Einval));
}

#[test]
fn a_string_request_that_does_not_fit_is_eoverflow_not_a_truncated_reply() {
    let _g = guard();
    let (_ns, _root, sys, _debug) = mount_tree("mount-api-of");
    let r = req(uid_of(sys), statmount_abi::STATMOUNT_FS_TYPE);
    let mut buf = vec![0u8; statmount_abi::SM_SIZE];
    let rv = statmount::sys_statmount(&SyscallArgs {
        a0: r.as_ptr() as u64,
        a1: buf.as_mut_ptr() as u64,
        a2: buf.len() as u64,
        a3: 0,
        a4: 0,
        a5: 0,
    });
    assert_eq!(rv, eno(Errno::Eoverflow));
    assert!(buf.iter().all(|b| *b == 0), "a refused call writes nothing at all");
}
