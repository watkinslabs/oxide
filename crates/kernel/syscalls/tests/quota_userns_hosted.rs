// Quota identities are namespace-relative. This harness drives the real
// `quotactl` dispatch with a CALLER inside a container-style user namespace
// against a filesystem stamped with that same namespace, and pins:
//
//   * an id the caller's namespace cannot name is EINVAL, never silently
//     charged to the overflow account;
//   * a mapped id reaches the filesystem as the INTERNAL identity, not the
//     number userspace typed;
//   * ids reported back are named in the caller's namespace again;
//   * permission runs BEFORE the mapping check, so an unprivileged caller
//     naming an out-of-range id gets EPERM rather than a range oracle;
//   * the "query the dquot you own" exemption compares in the caller's own
//     id space.
//
// This test compiles production modules directly via `#[path]` to assert their
// ABI shape, and exercises only the part of each module the shape under test
// needs. dead_code here measures the test's reach, not the kernel's.
#![allow(dead_code)]
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::errno::Errno;

use namespace_identity::{allocate, initial, NamespaceKind, NamespacePin, NamespaceRef};
use nscg::user_ns::{write_map, IdMapExtent, IdMapKind};

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `ns id 0..N` maps to `host id 100000..` — the shape a container gets.
const NS_BASE: u32 = 100_000;
const NS_SPAN: u32 = 65_536;
/// An id inside the container's range, and the internal identity it names.
const IN_NS_UID: u32 = 1000;
const HOST_UID: u32 = NS_BASE + IN_NS_UID;
/// One past the container's range: nameable by nobody inside it.
const OUT_OF_NS_UID: u32 = NS_SPAN;

static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());
static MOUNT_NS: Mutex<Option<NamespacePin>> = Mutex::new(None);

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(_addr: u64) -> Result<String, i64> {
        Err(-(syscall::errno::Errno::Efault.as_i32() as i64))
    }
}

mod pathresolve {
    pub fn resolve_path_raw(_raw: &str, _follow: bool) -> vfs::KResult<vfs::VfsPath> {
        Err(vfs::VfsError::Enoent)
    }
}

#[path = "../src/179_quotactl/abi.rs"]
mod abi;
#[path = "../src/179_quotactl/cmd.rs"]
mod cmd;
#[path = "../src/179_quotactl/dispatch.rs"]
mod dispatch;
#[path = "../src/179_quotactl/qidns.rs"]
mod qidns;
#[path = "../src/179_quotactl_xfs/core.rs"]
mod xfs;

struct UsernsType;
impl vfs::FileSystemType for UsernsType {
    fn name(&self) -> &str { "quota-userns-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

/// Records the identity the quota hooks were actually handed.
struct RecordingOps {
    get_id:  AtomicU32,
    set_id:  AtomicU32,
    /// Identity `Q_GETNEXTQUOTA` reports as the next existing account.
    next_id: u32,
}

impl RecordingOps {
    fn new(next_id: u32) -> Self {
        Self { get_id: AtomicU32::new(u32::MAX), set_id: AtomicU32::new(u32::MAX), next_id }
    }
}

impl vfs::SuperOps for RecordingOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_get_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid) -> vfs::KResult<vfs::MemDqblk> {
        self.get_id.store(qid.id, Ordering::SeqCst);
        Ok(vfs::MemDqblk::new())
    }
    fn quota_get_next_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid)
        -> vfs::KResult<(vfs::Kqid, vfs::MemDqblk)>
    {
        self.get_id.store(qid.id, Ordering::SeqCst);
        Ok((vfs::Kqid { kind: qid.kind, id: self.next_id }, vfs::MemDqblk::new()))
    }
    fn quota_set_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_set_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid, _dq: vfs::MemDqblk,
        _mask: u32, _now: u64) -> vfs::KResult<()>
    {
        self.set_id.store(qid.id, Ordering::SeqCst);
        Ok(())
    }
}

/// A fresh user namespace mapping `0..NS_SPAN` to `NS_BASE..` for every class.
fn container_ns() -> NamespaceRef {
    let init = initial(NamespaceKind::User);
    let ns = allocate(NamespaceKind::User, init.clone(), Some(init)).unwrap();
    for kind in [IdMapKind::Uid, IdMapKind::Gid, IdMapKind::Projid] {
        write_map(&ns, kind, true, 0,
            &[IdMapExtent { ns_id: 0, host_id: NS_BASE, count: NS_SPAN }]).unwrap();
    }
    ns
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests store leaked Task pointers and clear only between serialized cases.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

fn mounting_user_ns() -> Option<NamespacePin> { MOUNT_NS.lock().unwrap().clone() }

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CURRENT_TASK_PTR.store(0, Ordering::Release);
    *MOUNT_NS.lock().unwrap() = None;
    sched::set_current_hook(hosted_current_task);
    vfs::superblock::set_current_user_ns_hook(mounting_user_ns);
    guard
}

/// Build a superblock owned by `owner`, the way a mount performed from inside
/// that namespace would stamp it.
fn sb_owned_by(owner: &NamespaceRef, ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    *MOUNT_NS.lock().unwrap() = Some(owner.pin());
    let sb = vfs::SuperBlock::new(Arc::new(UsernsType), ops, 0x5155_5253, 0x443, 4096,
        "quota-userns-hosted".into(), Arc::new(()));
    *MOUNT_NS.lock().unwrap() = None;
    sb
}

/// Publish a caller living in `ns` with the given in-namespace euid.
fn install_current_in(ns: &NamespaceRef, euid: u32, cap_sys_admin: bool) -> &'static sched::Task {
    let task = Box::leak(Box::new(sched::Task::new(0x443, "quota-userns-hosted",
        sched::SchedClass::Normal { weight: 1024 })));
    task.creds.euid.store(euid, Ordering::Release);
    task.creds.egid.store(euid, Ordering::Release);
    if !cap_sys_admin {
        let mask = !(1u64 << sched::cap::SYS_ADMIN);
        task.creds.cap_effective.fetch_and(mask, Ordering::AcqRel);
    }
    assert!(task.replace_namespace(ns.clone()).is_ok(), "install the caller's user namespace");
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
    task
}

/// `struct fs_disk_quota` as userspace lays it out. # C: O(1)
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TestFsDiskQuota {
    d_version: i8,
    d_flags: i8,
    d_fieldmask: u16,
    d_id: u32,
    d_blk_hardlimit: u64,
    d_blk_softlimit: u64,
    d_ino_hardlimit: u64,
    d_ino_softlimit: u64,
    d_bcount: u64,
    d_icount: u64,
    d_itimer: i32,
    d_btimer: i32,
    d_iwarns: u16,
    d_bwarns: u16,
    d_itimer_hi: i8,
    d_btimer_hi: i8,
    d_rtbtimer_hi: i8,
    d_padding2: i8,
    d_rtb_hardlimit: u64,
    d_rtb_softlimit: u64,
    d_rtbcount: u64,
    d_rtbtimer: i32,
    d_rtbwarns: u16,
    d_padding3: i16,
    d_padding4: [u8; 8],
}

#[repr(C)]
#[derive(Default)]
struct TestIfDqblk {
    dqb_bhardlimit: u64,
    dqb_bsoftlimit: u64,
    dqb_curspace:   u64,
    dqb_ihardlimit: u64,
    dqb_isoftlimit: u64,
    dqb_curinodes:  u64,
    dqb_btime:      u64,
    dqb_itime:      u64,
    dqb_valid:      u32,
}

/// `Q_XGETQUOTA` — reaches the filesystem's record hook, so the identity it
/// was handed is observable.
fn getquota(sb: &vfs::SuperBlock, id: u64, out: &mut TestFsDiskQuota) -> i64 {
    dispatch::quotactl_dispatch_sb(sb, cmd::qcmd(xfs::Q_XGETQUOTA, cmd::USRQUOTA), id,
        out as *mut TestFsDiskQuota as u64)
}

struct NoopDqOps;
impl vfs::DquotOperations for NoopDqOps {
    fn as_any(&self) -> &dyn core::any::Any { self }
}

#[test]
fn an_id_the_callers_namespace_cannot_name_is_rejected_hosted() {
    let _guard = begin_test();
    let ns = container_ns();
    let ops = Arc::new(RecordingOps::new(0));
    let sb = sb_owned_by(&ns, ops.clone());
    install_current_in(&ns, 0, true);

    let mut out = TestFsDiskQuota::default();
    assert_eq!(getquota(&sb, OUT_OF_NS_UID as u64, &mut out), eno(Errno::Einval),
        "an unmapped id must be refused, not munged to the overflow account");
    assert_eq!(ops.get_id.load(Ordering::SeqCst), u32::MAX,
        "the filesystem must never see an unmapped identity");
}

#[test]
fn a_mapped_id_reaches_the_filesystem_as_the_internal_identity_hosted() {
    let _guard = begin_test();
    let ns = container_ns();
    let ops = Arc::new(RecordingOps::new(0));
    let sb = sb_owned_by(&ns, ops.clone());
    install_current_in(&ns, 0, true);

    let mut out = TestFsDiskQuota::default();
    assert_eq!(getquota(&sb, IN_NS_UID as u64, &mut out), 0);
    assert_eq!(ops.get_id.load(Ordering::SeqCst), HOST_UID,
        "the number userspace typed is not the account the filesystem charges");
}

#[test]
fn the_reported_next_id_is_named_in_the_callers_namespace_hosted() {
    let _guard = begin_test();
    let ns = container_ns();
    // The filesystem's next existing account is an INTERNAL identity; the
    // caller must be told the number its own namespace calls it.
    let ops = Arc::new(RecordingOps::new(NS_BASE + 4242));
    let sb = sb_owned_by(&ns, ops.clone());
    install_current_in(&ns, 0, true);

    let mut out = TestFsDiskQuota::default();
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb,
        cmd::qcmd(xfs::Q_XGETNEXTQUOTA, cmd::USRQUOTA), IN_NS_UID as u64,
        &mut out as *mut TestFsDiskQuota as u64), 0);
    assert_eq!(out.d_id, 4242);
}

#[test]
fn an_identity_the_caller_cannot_name_is_reported_as_the_invalid_id_hosted() {
    let _guard = begin_test();
    let ns = container_ns();
    // An account that exists on disk but lies outside the container's range.
    let ops = Arc::new(RecordingOps::new(7));
    let sb = sb_owned_by(&ns, ops.clone());
    install_current_in(&ns, 0, true);

    let mut out = TestFsDiskQuota::default();
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb,
        cmd::qcmd(xfs::Q_XGETNEXTQUOTA, cmd::USRQUOTA), IN_NS_UID as u64,
        &mut out as *mut TestFsDiskQuota as u64), 0);
    assert_eq!(out.d_id, u32::MAX,
        "an unnameable account is the invalid id, not account 65534");
}

#[test]
fn permission_is_decided_before_the_mapping_check_hosted() {
    let _guard = begin_test();
    let ns = container_ns();
    let ops = Arc::new(RecordingOps::new(0));
    let sb = sb_owned_by(&ns, ops.clone());
    // Unprivileged, and asking about an id its namespace cannot name.
    install_current_in(&ns, IN_NS_UID, false);

    let mut out = TestFsDiskQuota::default();
    assert_eq!(getquota(&sb, OUT_OF_NS_UID as u64, &mut out), eno(Errno::Eperm),
        "an unprivileged caller must be refused before the id range is disclosed");
}

#[test]
fn the_own_dquot_exemption_compares_in_the_callers_id_space_hosted() {
    let _guard = begin_test();
    let ns = container_ns();
    let ops = Arc::new(RecordingOps::new(0));
    let sb = sb_owned_by(&ns, ops.clone());
    // euid is an INTERNAL id; the caller names itself with its in-namespace
    // number. Comparing the two raw would deny this and allow the wrong one.
    install_current_in(&ns, HOST_UID, false);

    let mut out = TestFsDiskQuota::default();
    assert_eq!(getquota(&sb, IN_NS_UID as u64, &mut out), 0,
        "a caller may query its own dquot without CAP_SYS_ADMIN");
    assert_eq!(ops.get_id.load(Ordering::SeqCst), HOST_UID);

    let mut other = TestFsDiskQuota::default();
    assert_eq!(getquota(&sb, (IN_NS_UID + 1) as u64, &mut other), eno(Errno::Eperm),
        "the exemption covers exactly one account");
}

#[test]
fn an_id_the_filesystem_cannot_name_is_rejected_hosted() {
    let _guard = begin_test();
    // Caller in the INITIAL namespace (identity map) against a filesystem
    // whose ids live in a container namespace: the caller can name id 7, the
    // filesystem cannot, so the command is refused.
    let fs_ns = container_ns();
    let ops = Arc::new(RecordingOps::new(0));
    let sb = sb_owned_by(&fs_ns, ops.clone());
    let init = initial(NamespaceKind::User);
    install_current_in(&init, 0, true);

    let mut out = TestFsDiskQuota::default();
    assert_eq!(getquota(&sb, 7, &mut out), eno(Errno::Einval));
    assert_eq!(ops.get_id.load(Ordering::SeqCst), u32::MAX);
    // An id the filesystem CAN name goes through untranslated, because the
    // initial namespace is the identity map.
    assert_eq!(getquota(&sb, HOST_UID as u64, &mut out), 0);
    assert_eq!(ops.get_id.load(Ordering::SeqCst), HOST_UID);
}

#[test]
fn the_xfs_limit_setter_translates_the_id_too_hosted() {
    let _guard = begin_test();
    let ns = container_ns();
    let ops = Arc::new(RecordingOps::new(0));
    let sb = sb_owned_by(&ns, ops.clone());
    install_current_in(&ns, 0, true);

    let mut q = TestFsDiskQuota::default();
    let addr = &mut q as *mut TestFsDiskQuota as u64;
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb,
        cmd::qcmd(xfs::Q_XSETQLIM, cmd::USRQUOTA), IN_NS_UID as u64, addr), 0);
    assert_eq!(ops.set_id.load(Ordering::SeqCst), HOST_UID);

    assert_eq!(dispatch::quotactl_dispatch_sb(&sb,
        cmd::qcmd(xfs::Q_XSETQLIM, cmd::USRQUOTA), OUT_OF_NS_UID as u64, addr),
        eno(Errno::Einval));
    assert_eq!(ops.set_id.load(Ordering::SeqCst), HOST_UID, "unchanged: the hook was not called");
}

#[test]
fn a_superblock_built_with_no_mounting_task_belongs_to_the_initial_namespace_hosted() {
    let _guard = begin_test();
    let sb = vfs::SuperBlock::new(Arc::new(UsernsType), Arc::new(RecordingOps::new(0)),
        0x5155_5253, 0x444, 4096, "quota-userns-initial".into(), Arc::new(()));
    assert!(sb.s_user_ns.is_initial(),
        "a kernel-internal mount's ids are the identity map, not an empty one");
}

#[test]
fn the_classic_record_path_reads_the_limits_of_the_translated_account_hosted() {
    // The classic `Q_GETQUOTA` goes through the generic quota core rather than
    // a filesystem hook, so its translation is proved by the DATA: limits
    // stored against the internal identity come back for the in-namespace id,
    // and the raw number userspace typed names nothing.
    let _guard = begin_test();
    let ns = container_ns();
    let sb = sb_owned_by(&ns, Arc::new(RecordingOps::new(0)));
    vfs::quota_on(&sb, vfs::QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(NoopDqOps))
        .expect("enable user quota accounting");
    install_current_in(&ns, 0, true);

    const HARD_INODES: u64 = 4242;
    let mut limits = vfs::MemDqblk::new();
    limits.dqb_ihardlimit = HARD_INODES;
    vfs::quota_setquota(&sb, vfs::Kqid::user(HOST_UID), limits).expect("seed the account");

    let mut out = TestIfDqblk::default();
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETQUOTA, cmd::USRQUOTA),
        IN_NS_UID as u64, &mut out as *mut TestIfDqblk as u64), 0);
    assert_eq!(out.dqb_ihardlimit, HARD_INODES);

    let mut raw = TestIfDqblk::default();
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETQUOTA, cmd::USRQUOTA),
        HOST_UID as u64, &mut raw as *mut TestIfDqblk as u64), eno(Errno::Einval),
        "the internal number is not nameable inside the namespace");
}
