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

#[path = "../src/457_statmount.rs"]
mod statmount;
#[path = "../src/458_listmount.rs"]
mod listmount;

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);

const LSMT_ROOT: u64 = u64::MAX;
const REQ_SIZE: u32 = 24;
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
    let r = req(mnt_id, param);
    let mut ids = vec![0u64; cap];
    let rv = listmount::sys_listmount(&SyscallArgs {
        a0: r.as_ptr() as u64,
        a1: ids.as_mut_ptr() as u64,
        a2: cap as u64,
        a3: 0,
        a4: 0,
        a5: 0,
    });
    ids.truncate(rv.max(0) as usize);
    (rv, ids)
}

fn statmount_id(mnt_id: u64) -> i64 {
    let r = req(mnt_id, 0);
    let mut buf = vec![0u8; 640];
    statmount::sys_statmount(&SyscallArgs {
        a0: r.as_ptr() as u64,
        a1: buf.as_mut_ptr() as u64,
        a2: buf.len() as u64,
        a3: 0,
        a4: 0,
        a5: 0,
    })
}

#[test]
fn listmount_root_is_current_namespace_recursive_and_resumable() {
    let _g = guard();
    let (_a_namespace, _a_root, _a_sys, a_debug) = mount_tree("mount-api-a");
    let (_b_namespace, _b_root, b_sys, b_debug) = mount_tree("mount-api-b");

    let (rv, ids) = list_ids(LSMT_ROOT, 0, 16);
    assert!(rv >= 3, "current namespace tree returned");
    assert!(ids.contains(&b_sys), "current namespace child is listed");
    assert!(ids.contains(&b_debug), "current namespace descendant is listed");
    assert!(!ids.contains(&a_debug), "foreign namespace mount must not leak");

    let (rv, tail) = list_ids(LSMT_ROOT, b_sys, 16);
    assert!(rv >= 1, "resume after /sys should still expose later descendants");
    assert!(!tail.contains(&b_sys), "resume cursor excludes prior id");
    assert!(tail.contains(&b_debug), "resume cursor keeps later mount");
}

#[test]
fn statmount_rejects_foreign_namespace_mount_id() {
    let _g = guard();
    let (_a_namespace, _a_root, _a_sys, a_debug) = mount_tree("mount-api-c");
    let (_b_namespace, _b_root, _b_sys, b_debug) = mount_tree("mount-api-d");

    assert_eq!(statmount_id(b_debug), 0, "current namespace mount id is visible");
    assert_eq!(statmount_id(a_debug), eno(Errno::Enoent), "foreign namespace mount id is hidden");
}

#[test]
fn mount_api_rejects_bad_flags_and_short_requests() {
    let _g = guard();
    let (_namespace, _root, _sys, debug) = mount_tree("mount-api-e");
    let r = req(debug, 0);
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
        a3: 1,
        a4: 0,
        a5: 0,
    });
    assert_eq!(bad_stat, eno(Errno::Einval));

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
