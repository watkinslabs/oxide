const V2R0_DQBLK: usize = 48;
pub(super) const V2R1_DQBLK: usize = 72;
const QBLK_BITS: u32 = 10;

pub(super) fn entry_size(fmt: u32) -> vfs::KResult<usize> {
    match fmt {
        vfs::QFMT_VFS_V0 => Ok(V2R0_DQBLK),
        vfs::QFMT_VFS_V1 => Ok(V2R1_DQBLK),
        _ => Err(vfs::VfsError::Einval),
    }
}

pub(super) fn disk_to_mem(d: &[u8]) -> vfs::MemDqblk {
    if d.len() == V2R0_DQBLK {
        return vfs::MemDqblk {
            dqb_ihardlimit: le32(d, 4) as u64,
            dqb_isoftlimit: le32(d, 8) as u64,
            dqb_curinodes:  le32(d, 12) as u64,
            dqb_bhardlimit: (le32(d, 16) as u64) << QBLK_BITS,
            dqb_bsoftlimit: (le32(d, 20) as u64) << QBLK_BITS,
            dqb_curspace:   le64(d, 24),
            dqb_btime:      le64(d, 32) as i64,
            dqb_itime:      le64(d, 40) as i64,
            ..vfs::MemDqblk::new()
        };
    }
    vfs::MemDqblk {
        dqb_ihardlimit: le64(d, 8),
        dqb_isoftlimit: le64(d, 16),
        dqb_curinodes:  le64(d, 24),
        dqb_bhardlimit: le64(d, 32) << QBLK_BITS,
        dqb_bsoftlimit: le64(d, 40) << QBLK_BITS,
        dqb_curspace:   le64(d, 48),
        dqb_btime:      le64(d, 56) as i64,
        dqb_itime:      le64(d, 64) as i64,
        ..vfs::MemDqblk::new()
    }
}

pub(super) fn mem_to_disk(id: u32, m: vfs::MemDqblk, out: &mut [u8]) {
    out.fill(0);
    out[0..4].copy_from_slice(&id.to_le_bytes());
    if out.len() == V2R0_DQBLK {
        out[4..8].copy_from_slice(&(m.dqb_ihardlimit as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(m.dqb_isoftlimit as u32).to_le_bytes());
        out[12..16].copy_from_slice(&(m.dqb_curinodes as u32).to_le_bytes());
        out[16..20].copy_from_slice(&(((m.dqb_bhardlimit + 1023) >> QBLK_BITS) as u32).to_le_bytes());
        out[20..24].copy_from_slice(&(((m.dqb_bsoftlimit + 1023) >> QBLK_BITS) as u32).to_le_bytes());
        out[24..32].copy_from_slice(&m.dqb_curspace.to_le_bytes());
        out[32..40].copy_from_slice(&(m.dqb_btime as u64).to_le_bytes());
        out[40..48].copy_from_slice(&(m.dqb_itime as u64).to_le_bytes());
        return;
    }
    out[8..16].copy_from_slice(&m.dqb_ihardlimit.to_le_bytes());
    out[16..24].copy_from_slice(&m.dqb_isoftlimit.to_le_bytes());
    out[24..32].copy_from_slice(&m.dqb_curinodes.to_le_bytes());
    out[32..40].copy_from_slice(&((m.dqb_bhardlimit + 1023) >> QBLK_BITS).to_le_bytes());
    out[40..48].copy_from_slice(&((m.dqb_bsoftlimit + 1023) >> QBLK_BITS).to_le_bytes());
    out[48..56].copy_from_slice(&m.dqb_curspace.to_le_bytes());
    out[56..64].copy_from_slice(&(m.dqb_btime as u64).to_le_bytes());
    out[64..72].copy_from_slice(&(m.dqb_itime as u64).to_le_bytes());
}

fn le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn le64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3], buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]])
}
