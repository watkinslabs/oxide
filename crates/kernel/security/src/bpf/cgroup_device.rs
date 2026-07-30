//! `BPF_PROG_TYPE_CGROUP_DEVICE` ownership and runtime.
//!
//! Direct and effective attachment arrays live in the cgroup hierarchy.
//! This module translates syscall errors and supplies the one type-specific
//! execution context; it is not a second policy registry.

use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use vfs::InodeRef;

use super::BpfProgInode;
use super::uapi::func_id;
use crate::bpf_interp::{Helper, HelperState};

pub const DEVCG_ACC_MKNOD: u32 = 1;
pub const DEVCG_ACC_READ:  u32 = 2;
pub const DEVCG_ACC_WRITE: u32 = 4;
pub const DEVCG_DEV_BLOCK: u32 = 1;
pub const DEVCG_DEV_CHAR:  u32 = 2;

fn ktime_ns() -> i64 {
    #[cfg(target_os = "oxide-kernel")]
    { sched::live::timer_list::now_ns() as i64 }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

fn helper_ktime(
    _state: &mut HelperState, _a: i64, _b: i64, _c: i64, _d: i64, _e: i64,
) -> i64 { ktime_ns() }

fn helper_cpu(
    _state: &mut HelperState, _a: i64, _b: i64, _c: i64, _d: i64, _e: i64,
) -> i64 {
    sched::current().map(|task| task.cpu.load(Ordering::Acquire) as i64).unwrap_or(0)
}

fn helper_pid_tgid(
    _state: &mut HelperState, _a: i64, _b: i64, _c: i64, _d: i64, _e: i64,
) -> i64 {
    let Some(task) = sched::current() else { return -(Errno::Einval.as_i32() as i64) };
    ((task.tgid.load(Ordering::Acquire) as u64) << 32 | task.tid as u64) as i64
}

fn helper_uid_gid(
    _state: &mut HelperState, _a: i64, _b: i64, _c: i64, _d: i64, _e: i64,
) -> i64 {
    let Some(task) = sched::current() else { return -(Errno::Einval.as_i32() as i64) };
    let uid = task.creds.ruid.load(Ordering::Acquire);
    let gid = task.creds.rgid.load(Ordering::Acquire);
    ((gid as u64) << 32 | uid as u64) as i64
}

fn helper_numa(
    _state: &mut HelperState, _a: i64, _b: i64, _c: i64, _d: i64, _e: i64,
) -> i64 {
    // Oxide exposes one NUMA node, matching its rseq node-id contract.
    0
}

fn helper_cgroup_id(
    _state: &mut HelperState, _a: i64, _b: i64, _c: i64, _d: i64, _e: i64,
) -> i64 {
    sched::current()
        .map(|task| cgroup::cgroup_of(task.tid as u64) as i64)
        .unwrap_or(0)
}

// get/set_retval are not exposed: VFS's DevicePermissionHook result cannot
// preserve their arbitrary errno. IDs come from Linux's __BPF_FUNC_MAPPER.
static HELPERS: [Helper; 7] = [
    Helper { id: func_id::KTIME_GET_NS, f: helper_ktime },
    Helper { id: func_id::GET_SMP_PROCESSOR_ID, f: helper_cpu },
    Helper { id: func_id::GET_CURRENT_PID_TGID, f: helper_pid_tgid },
    Helper { id: func_id::GET_CURRENT_UID_GID, f: helper_uid_gid },
    Helper { id: func_id::GET_NUMA_NODE_ID, f: helper_numa },
    Helper { id: func_id::GET_CURRENT_CGROUP_ID, f: helper_cgroup_id },
    Helper { id: func_id::KTIME_GET_BOOT_NS, f: helper_ktime },
];

/// Enforce the effective cgroup-device program chain for an inode operation.
/// # C: O(effective programs * program instructions)
pub(crate) fn inode_permission(
    file_type: vfs::FileType,
    rdev: u32,
    mask: u32,
) -> vfs::KResult<()> {
    let dev_type = match file_type {
        vfs::FileType::BlockDev => DEVCG_DEV_BLOCK,
        vfs::FileType::CharDev => DEVCG_DEV_CHAR,
        _ => return Ok(()),
    };
    let dev = vfs::Devt::from_raw(rdev);
    let mut access = 0;
    if mask & vfs::MAY_READ != 0 { access |= DEVCG_ACC_READ; }
    if mask & vfs::MAY_WRITE != 0 { access |= DEVCG_ACC_WRITE; }
    check(dev_type, dev.major(), dev.minor(), access).map_err(|_| vfs::VfsError::Eperm)
}

pub(super) fn attach(
    cgid: u64,
    prog: InodeRef,
    mode: cgroup::BpfDeviceMode,
    replace: Option<&InodeRef>,
    expected_revision: u64,
) -> Result<(), Errno> {
    cgroup::bpf::device_attach(cgid, prog, mode, replace, expected_revision).map_err(map_error)
}

pub(super) fn detach(
    cgid: u64,
    prog: Option<&InodeRef>,
    expected_revision: u64,
) -> Result<(), Errno> {
    cgroup::bpf::device_detach(cgid, prog, expected_revision).map_err(map_error)
}

pub(super) fn map_error(error: cgroup::BpfDeviceError) -> Errno {
    match error {
        cgroup::BpfDeviceError::Offline => Errno::Enoent,
        cgroup::BpfDeviceError::Duplicate => Errno::Einval,
        cgroup::BpfDeviceError::Missing => Errno::Enoent,
        cgroup::BpfDeviceError::Full => Errno::E2big,
        cgroup::BpfDeviceError::Stale => Errno::Estale,
        cgroup::BpfDeviceError::Denied => Errno::Eperm,
        cgroup::BpfDeviceError::Invalid => Errno::Einval,
    }
}

/// Linux `__cgroup_bpf_check_dev_permission`: every effective program must
/// return nonzero.  The hierarchy snapshot pins all program objects while the
/// interpreter runs without the cgroup lock. # C: O(effective programs * insns)
pub fn check(dev_type: u32, major: u32, minor: u32, access: u32) -> Result<(), Errno> {
    let Some(task) = sched::current() else { return Ok(()) };
    let Some(programs) = cgroup::bpf::device_effective_for_task(task.tid as u64) else {
        return Ok(());
    };
    if programs.is_empty() { return Ok(()); }

    let mut ctx = [0u8; 12];
    ctx[0..4].copy_from_slice(&((access << 16) | dev_type).to_le_bytes());
    ctx[4..8].copy_from_slice(&major.to_le_bytes());
    ctx[8..12].copy_from_slice(&minor.to_le_bytes());
    run_effective(&programs, &ctx)
}

fn run_effective(programs: &[InodeRef], ctx: &[u8; 12]) -> Result<(), Errno> {
    let mut state = HelperState::default();
    if evaluate(programs, ctx, &mut state, &HELPERS) == 0 { Ok(()) } else { Err(Errno::Eperm) }
}

fn evaluate(
    programs: &[InodeRef],
    ctx: &[u8; 12],
    state: &mut HelperState,
    helpers: &[Helper],
) -> i32 {
    for inode in programs.iter() {
        let allowed = inode.private::<BpfProgInode>().is_some_and(|prog| {
            prog.prog_type == super::uapi::prog_type::CGROUP_DEVICE
                && crate::bpf_interp::run_with_helpers_and_state(
                    &prog.insns, ctx, helpers, state,
                ).is_some_and(|result| result != 0)
        });
        if !allowed && state.retval >= 0 { state.retval = -(Errno::Eperm.as_i32()); }
    }
    state.retval
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{make_bpf_prog_inode, prog_by_id, uapi};
    use core::sync::atomic::{AtomicU32, Ordering};

    static LATE_CALLS: AtomicU32 = AtomicU32::new(0);
    const TEST_HELPER_ID: u32 = 0x7fff;

    fn count_call(
        _state: &mut HelperState, _a: i64, _b: i64, _c: i64, _d: i64, _e: i64,
    ) -> i64 {
        LATE_CALLS.fetch_add(1, Ordering::Relaxed);
        0
    }

    fn raw(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let off = off.to_le_bytes();
        let imm = imm.to_le_bytes();
        [opcode, (src << 4) | dst, off[0], off[1], imm[0], imm[1], imm[2], imm[3]]
    }

    fn program(insns: &[[u8; 8]]) -> InodeRef {
        let bytes = insns.iter().flat_map(|i| i.iter().copied()).collect();
        make_bpf_prog_inode(uapi::prog_type::CGROUP_DEVICE, bytes)
    }

    #[test]
    fn every_effective_program_must_allow() {
        let allow = program(&[raw(0xb7, 0, 0, 0, 1), raw(0x95, 0, 0, 0, 0)]);
        let deny = program(&[raw(0xb7, 0, 0, 0, 0), raw(0x95, 0, 0, 0, 0)]);
        assert_eq!(run_effective(&[allow.clone()], &[0; 12]), Ok(()));
        assert_eq!(run_effective(&[allow, deny], &[0; 12]), Err(Errno::Eperm));
    }

    #[test]
    fn denial_does_not_skip_later_programs() {
        let deny = program(&[raw(0xb7, 0, 0, 0, 0), raw(0x95, 0, 0, 0, 0)]);
        let count_then_allow = program(&[
            raw(0x85, 0, 0, 0, TEST_HELPER_ID as i32),
            raw(0xb7, 0, 0, 0, 1),
            raw(0x95, 0, 0, 0, 0),
        ]);
        let helpers = [Helper { id: TEST_HELPER_ID, f: count_call }];
        LATE_CALLS.store(0, Ordering::Relaxed);
        let mut state = HelperState::default();
        assert_eq!(
            evaluate(&[deny, count_then_allow], &[0; 12], &mut state, &helpers),
            -(Errno::Eperm.as_i32()),
        );
        assert_eq!(LATE_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn runner_reads_the_canonical_device_context() {
        let major_is_verdict = program(&[
            raw(0x61, 0, 1, 4, 0),
            raw(0x95, 0, 0, 0, 0),
        ]);
        let mut ctx = [0u8; 12];
        ctx[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(run_effective(&[major_is_verdict.clone()], &ctx), Ok(()));
        ctx[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(run_effective(&[major_is_verdict], &ctx), Err(Errno::Eperm));
    }

    #[test]
    fn final_program_drop_releases_the_global_id() {
        let inode = program(&[raw(0xb7, 0, 0, 0, 1), raw(0x95, 0, 0, 0, 0)]);
        let id = inode.private::<BpfProgInode>().unwrap().id;
        assert!(prog_by_id(id).is_some());
        drop(inode);
        assert!(prog_by_id(id).is_none());
    }
}
