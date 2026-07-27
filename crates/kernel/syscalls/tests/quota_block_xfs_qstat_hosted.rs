use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const SPECIAL_ADDR: u64 = 0x5155_5150;
const FS_QSTAT_VERSION: i8 = 1;
const FS_QUOTA_UDQ_ACCT: u16 = 1 << 0;
const FS_QUOTA_UDQ_ENFD: u16 = 1 << 1;
const FS_QUOTA_PDQ_ACCT: u16 = 1 << 4;
const FS_QUOTA_PDQ_ENFD: u16 = 1 << 5;

static SPECIAL_PATH: Mutex<Option<vfs::VfsPath>> = Mutex::new(None);
static READ_USER_PATH_CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsQfilestat { qfs_ino: u64, qfs_nblks: u64, qfs_nextents: u32 }

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsQuotaStat {
    qs_version: i8,
    qs_flags: u16,
    qs_pad: i8,
    qs_uquota: FsQfilestat,
    qs_gquota: FsQfilestat,
    qs_incoredqs: u32,
    qs_btimelimit: i32,
    qs_itimelimit: i32,
    qs_rtbtimelimit: i32,
    qs_bwarnlimit: u16,
    qs_iwarnlimit: u16,
}

const _: [(); 80] = [(); core::mem::size_of::<FsQuotaStat>()];

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(addr: u64) -> Result<String, i64> {
        crate::READ_USER_PATH_CALLS.lock().unwrap().push(addr);
        Ok("/dev/quota-block-xfs-qstat-hosted".into())
    }
}

mod pathresolve {
    pub fn resolve_path_raw(_raw: &str, _follow: bool) -> vfs::KResult<vfs::VfsPath> {
        crate::SPECIAL_PATH.lock().unwrap().clone().ok_or(vfs::VfsError::Enoent)
    }
}

#[path = "../src/179_quotactl/abi.rs"]
mod abi;
#[path = "../src/179_quotactl/cmd.rs"]
mod cmd;
#[path = "../src/179_quotactl/dispatch.rs"]
mod dispatch;
#[path = "../src/179_quotactl/sys.rs"]
mod sys;
#[path = "../src/179_quotactl_xfs.rs"]
mod xfs;

struct BlockType;
impl vfs::FileSystemType for BlockType {
    fn name(&self) -> &str { "quota-block-xfs-qstat-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct XfsQstatOps { state_calls: AtomicU32 }
impl XfsQstatOps {
    fn new() -> Self { Self { state_calls: AtomicU32::new(0) } }
}

impl vfs::SuperOps for XfsQstatOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
        self.state_calls.fetch_add(1, Ordering::SeqCst);
        let mut st = vfs::QuotaState::default();
        st.types[vfs::QuotaType::User.slot()] = vfs::QuotaTypeState {
            accounting: true,
            enforcement: true,
            info: vfs::MemDqinfo {
                dqi_bgrace: 11, dqi_igrace: 22, dqi_rt_bgrace: 33,
                dqi_bwarnlimit: 44, dqi_iwarnlimit: 55,
                ..vfs::MemDqinfo::default()
            },
            file: vfs::QuotaFileStat { ino: 101, blocks: 202, nextents: 3 },
            incoredqs: 7,
        };
        st.types[vfs::QuotaType::Project.slot()] = vfs::QuotaTypeState {
            accounting: true,
            enforcement: true,
            file: vfs::QuotaFileStat { ino: 707, blocks: 808, nextents: 9 },
            incoredqs: 10,
            ..vfs::QuotaTypeState::default()
        };
        Ok(st)
    }
}

fn sb_with_ops(id: &str, s_dev: u64, ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(BlockType), ops, 0x5155_5150, s_dev, 4096, id.into(), Arc::new(()))
}

fn resolved_inode_path(inode_sb: &Arc<vfs::SuperBlock>, rdev: u32) -> vfs::VfsPath {
    let ino = vfs::InodeBuilder::new(0x515, vfs::mk_mode(vfs::FileType::BlockDev, 0o660),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(inode_sb))
        .rdev(rdev)
        .build();
    let d = vfs::Dentry::new(None, "quota-block-xfs-qstat-hosted".into(), Arc::clone(&ino));
    vfs::VfsPath { mnt_id: 0, dentry: d, inode: ino, last_component: None }
}

fn clear_state() {
    *SPECIAL_PATH.lock().unwrap() = None;
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    CURRENT_TASK_PTR.store(0, Ordering::Release);
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests store leaked Task pointers and clear only between serialized cases.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_state();
    sched::set_current_hook(hosted_current_task);
    guard
}

fn install_current() {
    let task = Box::leak(Box::new(sched::Task::new(0x5150, "quotactl-block-xfs-qstat-hosted", sched::SchedClass::Normal { weight: 1024 })));
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
}

fn install_block_target(target_sb: &Arc<vfs::SuperBlock>, special_sb: &Arc<vfs::SuperBlock>) {
    vfs::superblock::register_super(target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(special_sb, target_sb.s_dev as u32));
    READ_USER_PATH_CALLS.lock().unwrap().clear();
}

#[test]
fn sys_quotactl_block_xfs_qgetqstat_success_maps_state_and_project_fallback_hosted() {
    let _guard = begin_test();
    install_current();
    let ops = Arc::new(XfsQstatOps::new());
    let target_sb = sb_with_ops("block-xfs-qstat-target-sb", 0x5155_5151, ops.clone());
    let special_sb = sb_with_ops("block-xfs-qstat-special-sb", 0x5155_5152, Arc::new(XfsQstatOps::new()));
    install_block_target(&target_sb, &special_sb);
    let mut out = FsQuotaStat::default();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XGETQSTAT, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: &mut out as *mut FsQuotaStat as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(ops.state_calls.load(Ordering::SeqCst), 1);
    assert_eq!(out.qs_version, FS_QSTAT_VERSION);
    assert_eq!(out.qs_flags, FS_QUOTA_UDQ_ACCT | FS_QUOTA_UDQ_ENFD | FS_QUOTA_PDQ_ACCT | FS_QUOTA_PDQ_ENFD);
    assert_eq!(out.qs_incoredqs, 17);
    assert_eq!((out.qs_uquota.qfs_ino, out.qs_uquota.qfs_nblks, out.qs_uquota.qfs_nextents), (101, 202, 3));
    assert_eq!((out.qs_gquota.qfs_ino, out.qs_gquota.qfs_nblks, out.qs_gquota.qfs_nextents), (707, 808, 9));
    assert_eq!((out.qs_btimelimit, out.qs_itimelimit, out.qs_rtbtimelimit), (11, 22, 33));
    assert_eq!((out.qs_bwarnlimit, out.qs_iwarnlimit), (44, 55));
    clear_state();
}
