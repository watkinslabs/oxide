use hal::USER_VA_END;
use syscall::errno::Errno;

use super::eno;

const QIF_BLIMITS: u32 = 1 << 0;
const QIF_SPACE:   u32 = 1 << 1;
const QIF_ILIMITS: u32 = 1 << 2;
const QIF_INODES:  u32 = 1 << 3;
const QIF_BTIME:   u32 = 1 << 4;
const QIF_ITIME:   u32 = 1 << 5;
const QIF_ALL:     u32 = QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES | QIF_BTIME | QIF_ITIME;
const QIF_DQBLKSIZE_BITS: u32 = 10;
const QIF_DQBLKSIZE: u64 = 1 << QIF_DQBLKSIZE_BITS;
const IIF_CLASSIC_ALL: u32 = vfs::IIF_BGRACE | vfs::IIF_IGRACE | vfs::IIF_FLAGS;

#[repr(C)]
#[derive(Clone, Copy)]
struct IfDqblk {
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

#[repr(C)]
#[derive(Clone, Copy)]
struct IfNextDqblk {
    dqb_bhardlimit: u64,
    dqb_bsoftlimit: u64,
    dqb_curspace:   u64,
    dqb_ihardlimit: u64,
    dqb_isoftlimit: u64,
    dqb_curinodes:  u64,
    dqb_btime:      u64,
    dqb_itime:      u64,
    dqb_valid:      u32,
    dqb_id:         u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfDqinfo {
    dqi_bgrace: u64,
    dqi_igrace: u64,
    dqi_flags:  u32,
    dqi_valid:  u32,
}

const _: [(); 72] = [(); core::mem::size_of::<IfDqblk>()];
const _: [(); 72] = [(); core::mem::size_of::<IfNextDqblk>()];
const _: [(); 24] = [(); core::mem::size_of::<IfDqinfo>()];

pub(super) fn user_range(addr: u64, len: u64) -> bool {
    addr != 0 && addr.checked_add(len).map(|end| end <= USER_VA_END).unwrap_or(false)
}

pub(super) fn write_raw<T: Copy>(addr: u64, value: T) -> i64 {
    if !user_range(addr, core::mem::size_of::<T>() as u64) { return eno(Errno::Efault); }
    // SAFETY: user range validated for a T-sized store; trap handling is owned by the arch usercopy path.
    unsafe { core::ptr::write_volatile(addr as *mut T, value); }
    0
}

pub(super) fn write_u32(addr: u64, value: u32) -> i64 {
    write_raw(addr, value)
}

pub(super) fn read_dqblk(addr: u64) -> Result<vfs::MemDqblk, i64> {
    if !user_range(addr, core::mem::size_of::<IfDqblk>() as u64) { return Err(eno(Errno::Efault)); }
    // SAFETY: user range validated for an if_dqblk-sized load; trap handling is owned by the arch usercopy path.
    let dq = unsafe { core::ptr::read_volatile(addr as *const IfDqblk) };
    Ok(if_to_mem_dqblk(dq))
}

pub(super) fn write_dqblk(addr: u64, dqblk: vfs::MemDqblk) -> i64 {
    write_raw(addr, mem_to_if_dqblk(dqblk))
}

pub(super) fn read_dqinfo(addr: u64) -> Result<vfs::MemDqinfo, i64> {
    if !user_range(addr, core::mem::size_of::<IfDqinfo>() as u64) { return Err(eno(Errno::Efault)); }
    // SAFETY: user range validated for an if_dqinfo-sized load; trap handling is owned by the arch usercopy path.
    let info = unsafe { core::ptr::read_volatile(addr as *const IfDqinfo) };
    Ok(vfs::MemDqinfo {
        dqi_bgrace: info.dqi_bgrace,
        dqi_igrace: info.dqi_igrace,
        dqi_flags:  info.dqi_flags,
        dqi_valid:  info.dqi_valid,
        ..vfs::MemDqinfo::default()
    })
}

pub(super) fn dqinfo_classic_valid(info: vfs::MemDqinfo) -> bool {
    info.dqi_valid & !IIF_CLASSIC_ALL == 0
}

pub(super) fn write_dqinfo(addr: u64, info: vfs::MemDqinfo) -> i64 {
    write_raw(addr, IfDqinfo {
        dqi_bgrace: info.dqi_bgrace,
        dqi_igrace: info.dqi_igrace,
        dqi_flags:  info.dqi_flags,
        dqi_valid:  IIF_CLASSIC_ALL,
    })
}

pub(super) fn write_next_dqblk(addr: u64, id: u32, dqblk: vfs::MemDqblk) -> i64 {
    if !user_range(addr, core::mem::size_of::<IfNextDqblk>() as u64) { return eno(Errno::Efault); }
    let dq = mem_to_if_dqblk(dqblk);
    let out = IfNextDqblk {
        dqb_bhardlimit: dq.dqb_bhardlimit,
        dqb_bsoftlimit: dq.dqb_bsoftlimit,
        dqb_curspace:   dq.dqb_curspace,
        dqb_ihardlimit: dq.dqb_ihardlimit,
        dqb_isoftlimit: dq.dqb_isoftlimit,
        dqb_curinodes:  dq.dqb_curinodes,
        dqb_btime:      dq.dqb_btime as u64,
        dqb_itime:      dq.dqb_itime as u64,
        dqb_valid:      dq.dqb_valid,
        dqb_id:         id,
    };
    // SAFETY: user range validated for an if_nextdqblk-sized store; trap handling is owned by the arch usercopy path.
    unsafe { core::ptr::write_volatile(addr as *mut IfNextDqblk, out); }
    0
}

fn if_to_mem_dqblk(dq: IfDqblk) -> vfs::MemDqblk {
    vfs::MemDqblk {
        dqb_bhardlimit: qbtos(dq.dqb_bhardlimit),
        dqb_bsoftlimit: qbtos(dq.dqb_bsoftlimit),
        dqb_curspace:   dq.dqb_curspace,
        dqb_rsvspace:   0,
        dqb_ihardlimit: dq.dqb_ihardlimit,
        dqb_isoftlimit: dq.dqb_isoftlimit,
        dqb_curinodes:  dq.dqb_curinodes,
        dqb_btime:      dq.dqb_btime as i64,
        dqb_itime:      dq.dqb_itime as i64,
        dqb_valid:      dq.dqb_valid,
        ..vfs::MemDqblk::new()
    }
}

fn mem_to_if_dqblk(dq: vfs::MemDqblk) -> IfDqblk {
    IfDqblk {
        dqb_bhardlimit: stoqb(dq.dqb_bhardlimit),
        dqb_bsoftlimit: stoqb(dq.dqb_bsoftlimit),
        dqb_curspace:   dq.dqb_curspace,
        dqb_ihardlimit: dq.dqb_ihardlimit,
        dqb_isoftlimit: dq.dqb_isoftlimit,
        dqb_curinodes:  dq.dqb_curinodes,
        dqb_btime:      dq.dqb_btime as u64,
        dqb_itime:      dq.dqb_itime as u64,
        dqb_valid:      QIF_ALL,
    }
}

fn qbtos(blocks: u64) -> u64 {
    blocks.checked_shl(QIF_DQBLKSIZE_BITS).unwrap_or(u64::MAX)
}

fn stoqb(space: u64) -> u64 {
    space.saturating_add(QIF_DQBLKSIZE - 1) >> QIF_DQBLKSIZE_BITS
}

pub(super) fn if_dqblk_fieldmask(valid: u32) -> u32 {
    let mut mask = 0;
    if valid & QIF_BLIMITS != 0 { mask |= vfs::DQB_SPC_HARD | vfs::DQB_SPC_SOFT; }
    if valid & QIF_SPACE != 0 { mask |= vfs::DQB_SPACE; }
    if valid & QIF_ILIMITS != 0 { mask |= vfs::DQB_INO_HARD | vfs::DQB_INO_SOFT; }
    if valid & QIF_INODES != 0 { mask |= vfs::DQB_INO_COUNT; }
    if valid & QIF_BTIME != 0 { mask |= vfs::DQB_SPC_TIMER; }
    if valid & QIF_ITIME != 0 { mask |= vfs::DQB_INO_TIMER; }
    mask
}
