// B1696: `mount(2)` builds an `FsContext` and admits its option string through
// the SAME verdict `fsconfig(2)` uses.
//
// Fails-before: `dispatch_mount` called the filesystem constructor with the raw
// comma-separated blob, so the parameter table `FileSystemType::parameters()`
// publishes was consulted on the `fsopen`/`fsconfig` PROBE path only. A
// filesystem could answer "unsupported" to a probe and still swallow the same
// key on the real mount — which is exactly backwards, because the probe is
// advisory and the mount is what enforces.
//
// Drives the ungated `mount_dispatch::dispatch_mount` against the real `vfs`
// mount engine, hosted, no boot.
//
// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's.
#![allow(dead_code)]
use std::sync::{Arc, Mutex, MutexGuard};

extern crate alloc;

use syscall::errno::Errno;
use vfs::fs::{FileSystem, FsFlags, FsParamSpec, FsParamType, FsType};
use mount_dispatch::MountCaps;
use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeBuilder, InodeOps, InodeRef, KResult};

#[path = "../../vfs/tests/common/mod.rs"]
mod common;

#[path = "../src/namei_common/errno.rs"]
mod namei_common;

#[path = "../src/fsmount_common/mount_dispatch.rs"]
mod mount_dispatch;

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);

/// What the last constructor invocation was handed: `(source, target, data)`.
/// This is the whole question — the option string the filesystem SEES must be
/// the one admission produced, not a second rendering of it.
static SEEN: Mutex<Option<(Option<String>, String, String)>> = Mutex::new(None);

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

const ROOT_CAPS: MountCaps = MountCaps { init_user_ns: true, mnt_user_ns: true };
/// Unprivileged in the initial user namespace, privileged in its own.
const USERNS_CAPS: MountCaps = MountCaps { init_user_ns: false, mnt_user_ns: true };

fn cur_ns() -> vfs::mntns::MntNamespaceRef {
    CUR_NS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().expect("current namespace owner").clone()
}

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    common::install();
    vfs::mount::set_current_ns_provider(cur_ns);
    *SEEN.lock().unwrap_or_else(|e| e.into_inner()) = None;
    g
}

fn seen() -> (Option<String>, String, String) {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone().expect("constructor ran")
}

fn new_ns() {
    let init = vfs::mntns::initial();
    let namespace = vfs::mntns::allocate(init.owner_user_namespace()).expect("allocate mount namespace");
    *CUR_NS.lock().unwrap_or_else(|e| e.into_inner()) = Some(namespace);
}

struct RootDirOps;
impl InodeOps for RootDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(plain_dir(0xC680_0100)) }
}
fn plain_dir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), Arc::new(RootDirOps), vfs::default_file_ops()).build()
}
struct RootFs { tag: &'static str }
impl FileSystem for RootFs {
    fn name(&self) -> &str { self.tag }
    fn root(&self) -> Option<InodeRef> { Some(plain_dir(1)) }
}

fn mount_tree(tag: &'static str) -> Arc<Dentry> {
    new_ns();
    common::register("/", Arc::new(RootFs { tag })).expect("root mount");
    common::dentry("/mnt/point")
}

const LEAF_INO: u64 = 0xB169_6001;
struct LeafFs { name: &'static str }
impl FileSystem for LeafFs {
    fn name(&self) -> &str { self.name }
    fn root(&self) -> Option<InodeRef> {
        Some(InodeBuilder::new(LEAF_INO, vfs::mk_mode(FileType::Directory, 0o755),
            vfs::default_inode_ops(), vfs::default_file_ops()).build())
    }
}

/// The table under test: one value key, one flag key. Modelled on the shape
/// every real table has, so the verdict is exercised rather than a special case.
const SPECS: &[FsParamSpec] = &[
    FsParamSpec::value("size", FsParamType::Size),
    FsParamSpec::value("mode", FsParamType::U32Oct),
    FsParamSpec::flag("noswap"),
];

fn record_ctor(source: Option<&str>, target: &str, data: &str) {
    *SEEN.lock().unwrap_or_else(|e| e.into_inner()) =
        Some((source.map(str::to_string), target.to_string(), data.to_string()));
}

/// A filesystem that PUBLISHES a table — real admission.
fn register_declared(name: &'static str, flags: FsFlags) {
    let _ = vfs::fs::register_fs(FsType::with_parameters(name, 0xB169_6000, flags,
        Box::new(move |ty, s, t, d, sb_flags| {
            record_ctor(s, t, d);
            let fs: Arc<dyn FileSystem> = Arc::new(LeafFs { name: "declared" });
            vfs::fs::superblock_from_filesystem(ty, fs, None, t.into(), sb_flags)
        }), Some(SPECS)));
}

/// A filesystem that publishes NO table — the unconverted backend every
/// pseudo-filesystem still is (devpts, cgroup2, sysfs…). Its blob must arrive
/// verbatim, and no key in it may be refused: getting this wrong loses
/// `/dev/pts`, and with it every tty.
fn register_legacy(name: &'static str) {
    let _ = vfs::fs::register_fs(FsType::new(name, 0xB169_6100, FsFlags::empty(),
        Box::new(move |ty, s, t, d, sb_flags| {
            record_ctor(s, t, d);
            let fs: Arc<dyn FileSystem> = Arc::new(LeafFs { name: "legacy" });
            vfs::fs::superblock_from_filesystem(ty, fs, None, t.into(), sb_flags)
        })));
}

// ---- the admission verdict now reaches the real mount -----------------------

#[test]
fn an_undeclared_option_now_fails_the_real_mount() {
    let _g = guard();
    register_declared("adm_decl_a", FsFlags::empty());
    let target_d = mount_tree("adm-a");

    // FAILS-BEFORE: this returned 0 and grafted a mount whose option string was
    // handed to the constructor unexamined.
    let rv = mount_dispatch::dispatch_mount(None, "adm_decl_a", "/mnt/point", &target_d, None,
        "size=64m,nosuchoption=1", 0, ROOT_CAPS);
    assert_eq!(rv, eno(Errno::Einval), "a key outside the table must fail the mount");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none(),
        "a refused mount grafts nothing");
    assert!(SEEN.lock().unwrap().is_none(),
        "the constructor must never run for a refused option string");
}

#[test]
fn a_declared_option_still_mounts_and_reaches_the_constructor() {
    let _g = guard();
    register_declared("adm_decl_b", FsFlags::empty());
    let target_d = mount_tree("adm-b");

    let rv = mount_dispatch::dispatch_mount(None, "adm_decl_b", "/mnt/point", &target_d, None,
        "size=64m,mode=0700,noswap", 0, ROOT_CAPS);
    assert_eq!(rv, 0);
    let (_src, target, data) = seen();
    assert_eq!(data, "size=64m,mode=0700,noswap",
        "every admitted key reaches the backend, in order, unchanged");
    assert_eq!(target, "/mnt/point", "the mount target still reaches the constructor");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_some());
}

// A bare word where a value belongs is a DIFFERENT refusal from an unknown
// key, and must not fall through to `source` — or `mount -o size` would name a
// device.
#[test]
fn a_value_key_given_as_a_bare_word_is_refused_not_read_as_a_device() {
    let _g = guard();
    register_declared("adm_decl_c", FsFlags::empty());
    let target_d = mount_tree("adm-c");
    assert_eq!(mount_dispatch::dispatch_mount(None, "adm_decl_c", "/mnt/point", &target_d, None,
        "size", 0, ROOT_CAPS), eno(Errno::Einval));
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none());
}

// The superblock keywords are consumed by the VFS before the table is
// consulted, so `-o ro` in the DATA string still makes a read-only superblock
// on a filesystem that declares a table — and does not reach the backend as an
// unknown key.
#[test]
fn superblock_keywords_in_the_data_string_are_consumed_not_refused() {
    let _g = guard();
    register_declared("adm_decl_d", FsFlags::empty());
    let target_d = mount_tree("adm-d");
    assert_eq!(mount_dispatch::dispatch_mount(None, "adm_decl_d", "/mnt/point", &target_d, None,
        "ro,noswap", 0, ROOT_CAPS), 0);
    let (_s, _t, data) = seen();
    assert_eq!(data, "noswap", "`ro` is a superblock flag, not a backend option");
    let m = vfs::mount::mount_at_path_exact(&target_d).expect("grafted");
    assert!(m.sb().is_readonly(), "`-o ro` in the data string reached the superblock");
}

// ---- the unconverted backend is untouched -----------------------------------

// Nothing about this change may cost a filesystem that publishes no table. Its
// blob arrives verbatim and every key in it is still accepted — `/dev/pts` is
// mounted `-o gid=5,mode=620,ptmxmode=000` and none of those are honoured yet.
#[test]
fn a_filesystem_without_a_table_still_receives_its_blob_verbatim() {
    let _g = guard();
    register_legacy("adm_legacy_a");
    let target_d = mount_tree("adm-legacy-a");

    let blob = "gid=5,mode=620,ptmxmode=000,nosuchoption";
    assert_eq!(mount_dispatch::dispatch_mount(None, "adm_legacy_a", "/mnt/point", &target_d, None,
        blob, 0, ROOT_CAPS), 0, "an unconverted filesystem refuses nothing");
    let (_s, _t, data) = seen();
    assert_eq!(data, blob, "the blob is not split, reordered, or re-rendered");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_some());
}

#[test]
fn the_source_and_target_still_reach_an_unconverted_constructor() {
    let _g = guard();
    register_legacy("adm_legacy_b");
    let target_d = mount_tree("adm-legacy-b");
    assert_eq!(mount_dispatch::dispatch_mount(Some("/dev/vda1"), "adm_legacy_b", "/mnt/point",
        &target_d, None, "", 0, ROOT_CAPS), 0);
    let (src, target, data) = seen();
    assert_eq!(src.as_deref(), Some("/dev/vda1"));
    assert_eq!(target, "/mnt/point");
    assert_eq!(data, "");
}

// ---- ordering ---------------------------------------------------------------

// The reference parses the options BEFORE `mount_capable`, so a bad option is
// reported on its own merits. Deciding privilege first would make the errno
// tell an unprivileged caller whether its option was valid — and would report
// EPERM for a request that is malformed for everyone.
#[test]
fn options_are_judged_before_privilege() {
    let _g = guard();
    register_declared("adm_decl_e", FsFlags::empty());   // no FS_USERNS_MOUNT
    let target_d = mount_tree("adm-e");

    assert_eq!(mount_dispatch::dispatch_mount(None, "adm_decl_e", "/mnt/point", &target_d, None,
        "nosuchoption", 0, USERNS_CAPS), eno(Errno::Einval),
        "the malformed option is the reason, not the caller's privilege");
    // Same caller, same filesystem, VALID options: now privilege is the reason.
    assert_eq!(mount_dispatch::dispatch_mount(None, "adm_decl_e", "/mnt/point", &target_d, None,
        "noswap", 0, USERNS_CAPS), eno(Errno::Eperm));
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none());
}

// A filesystem that requires a device and is given none fails before any
// constructor runs, with the reference's EINVAL.
#[test]
fn a_device_backed_filesystem_without_a_source_is_einval() {
    let _g = guard();
    register_declared("adm_decl_f", FsFlags::FS_REQUIRES_DEV);
    let target_d = mount_tree("adm-f");
    assert_eq!(mount_dispatch::dispatch_mount(None, "adm_decl_f", "/mnt/point", &target_d, None,
        "noswap", 0, ROOT_CAPS), eno(Errno::Einval));
    assert!(SEEN.lock().unwrap().is_none(), "no constructor runs without the device");
    assert!(vfs::mount::mount_at_path_exact(&target_d).is_none());
}
