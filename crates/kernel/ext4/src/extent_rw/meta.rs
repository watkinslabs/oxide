use crate::inode::InodeError;
use crate::mount::{Mount, MountError};
use crate::superblock::{EXT4_LABEL_MAX, SB_OFF_VOLUME_NAME, SUPERBLOCK_LEN, SUPERBLOCK_OFFSET};

// ext4 on-disk inode field byte offsets (Linux `struct ext4_inode`). The data
// path owns size/blocks/nlink/extents; this writer touches only the metadata
// the VFS `notify_change` mutates: mode, owner, and the three timestamps.
const OFF_MODE:        usize = 0x00;
const OFF_UID_LO:      usize = 0x02;
const OFF_ATIME:       usize = 0x08;
const OFF_CTIME:       usize = 0x0C;
const OFF_MTIME:       usize = 0x10;
const OFF_GID_LO:      usize = 0x18;
const OFF_UID_HI:      usize = 0x78; // osd2 `l_i_uid_high`
const OFF_GID_HI:      usize = 0x7A; // osd2 `l_i_gid_high`
const OFF_CTIME_EXTRA: usize = 0x84;
const OFF_MTIME_EXTRA: usize = 0x88;
const OFF_ATIME_EXTRA: usize = 0x8C;
const OFF_CRTIME:       usize = 0x90;
const OFF_CRTIME_EXTRA: usize = 0x94;
const OFF_FLAGS:        usize = 0x20; // i_flags (chattr flag word)
const OFF_GENERATION:   usize = 0x64; // i_generation
const OFF_PROJID:       usize = 0x9C; // i_projid, present in >=160-byte inode

#[derive(Clone, Copy)]
pub(crate) struct InodeMetaUpdate {
    pub(crate) mode: u16,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) atime_ns: u64,
    pub(crate) mtime_ns: u64,
    pub(crate) ctime_ns: u64,
}

impl Mount {
    /// Persist `s_volume_name` through the journal. Linux `FS_IOC_SETFSLABEL`
    /// copies exactly `EXT4_LABEL_MAX` zero-padded bytes. # C: O(SB rw)
    pub fn persist_fs_label(&self, label: &[u8; EXT4_LABEL_MAX]) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let mut sb = m.read_meta_byte_range(SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)?;
            sb[SB_OFF_VOLUME_NAME..SB_OFF_VOLUME_NAME + EXT4_LABEL_MAX].copy_from_slice(label);
            crate::csum::stamp_superblock_csum(&m.sb, &mut sb);
            m.metadata_write(SUPERBLOCK_OFFSET, &sb)
        })
    }

    /// Persist `i_flags` (@0x20) plus ctime to `ino`'s on-disk inode, journaled
    /// — the ext4 half of `FS_IOC_SETFLAGS`. # C: O(1) I/O, 1 txn
    pub fn persist_inode_flags(&self, ino: u32, flags: u32, ctime_ns: u64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            b[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
            let (c_lo, c_ex) = enc_time(ctime_ns);
            b[OFF_CTIME..OFF_CTIME + 4].copy_from_slice(&c_lo.to_le_bytes());
            if isize >= OFF_CTIME_EXTRA + 4 {
                b[OFF_CTIME_EXTRA..OFF_CTIME_EXTRA + 4].copy_from_slice(&c_ex.to_le_bytes());
            }
            m.write_inode_bytes(ino, &b)
        })
    }

    /// Persist only `i_flags` to `ino`'s on-disk inode, journaled. ext4 visible
    /// quota-on dirties the inode after setting protection flags without
    /// changing mtime/ctime. # C: O(1) I/O, 1 txn
    pub fn persist_inode_flags_only(&self, ino: u32, flags: u32) -> Result<(), MountError> {
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            b[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
            m.write_inode_bytes(ino, &b)
        })
    }

    /// Persist `i_flags`, `i_mtime`, and `i_ctime` to `ino`'s on-disk inode,
    /// journaled. ext4 visible quota-off uses this after generic quota teardown
    /// clears the quota-file protection flags. # C: O(1) I/O, 1 txn
    pub fn persist_inode_flags_mctime(&self, ino: u32, flags: u32, mtime_ns: u64, ctime_ns: u64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            b[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
            let (c_lo, c_ex) = enc_time(ctime_ns);
            let (mt_lo, mt_ex) = enc_time(mtime_ns);
            b[OFF_CTIME..OFF_CTIME + 4].copy_from_slice(&c_lo.to_le_bytes());
            b[OFF_MTIME..OFF_MTIME + 4].copy_from_slice(&mt_lo.to_le_bytes());
            if isize >= OFF_MTIME_EXTRA + 4 {
                b[OFF_CTIME_EXTRA..OFF_CTIME_EXTRA + 4].copy_from_slice(&c_ex.to_le_bytes());
                b[OFF_MTIME_EXTRA..OFF_MTIME_EXTRA + 4].copy_from_slice(&mt_ex.to_le_bytes());
            }
            m.write_inode_bytes(ino, &b)
        })
    }

    /// `inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir))` — the
    /// mtime+ctime bump every ext4 directory-entry mutation makes to the
    /// directory it edited (Linux `add_dirent_to_buf`, `ext4_rename`).
    /// # C: O(1) I/O, 1 txn
    pub fn touch_inode_mtime_ctime(&self, ino: u32, now_ns: u64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            let (t_lo, t_ex) = enc_time(now_ns);
            b[OFF_CTIME..OFF_CTIME + 4].copy_from_slice(&t_lo.to_le_bytes());
            b[OFF_MTIME..OFF_MTIME + 4].copy_from_slice(&t_lo.to_le_bytes());
            if isize >= OFF_MTIME_EXTRA + 4 {
                b[OFF_CTIME_EXTRA..OFF_CTIME_EXTRA + 4].copy_from_slice(&t_ex.to_le_bytes());
                b[OFF_MTIME_EXTRA..OFF_MTIME_EXTRA + 4].copy_from_slice(&t_ex.to_le_bytes());
            }
            m.write_inode_bytes(ino, &b)
        })
    }

    /// `inode_set_ctime_current(inode)` — the change-time stamp a renamed or
    /// link-count-adjusted inode gets (Linux `ext4_rename`). # C: O(1) I/O, 1 txn
    pub fn touch_inode_ctime(&self, ino: u32, now_ns: u64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            let (t_lo, t_ex) = enc_time(now_ns);
            b[OFF_CTIME..OFF_CTIME + 4].copy_from_slice(&t_lo.to_le_bytes());
            if isize >= OFF_CTIME_EXTRA + 4 {
                b[OFF_CTIME_EXTRA..OFF_CTIME_EXTRA + 4].copy_from_slice(&t_ex.to_le_bytes());
            }
            m.write_inode_bytes(ino, &b)
        })
    }

    /// Persist `i_projid` (@0x9C) to `ino`'s on-disk inode, journaled. Linux
    /// `ext4_ioctl_setproject` requires the PROJECT feature and enough inode
    /// room for the field; callers enforce feature policy. # C: O(1) I/O, 1 txn
    pub fn persist_inode_project(&self, ino: u32, projid: u32, ctime_ns: u64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            if b.len() < OFF_PROJID + 4 { return Err(MountError::Inode(InodeError::BadLen)); }
            b[OFF_PROJID..OFF_PROJID + 4].copy_from_slice(&projid.to_le_bytes());
            let (c_lo, c_ex) = enc_time(ctime_ns);
            b[OFF_CTIME..OFF_CTIME + 4].copy_from_slice(&c_lo.to_le_bytes());
            if isize >= OFF_CTIME_EXTRA + 4 {
                b[OFF_CTIME_EXTRA..OFF_CTIME_EXTRA + 4].copy_from_slice(&c_ex.to_le_bytes());
            }
            m.write_inode_bytes(ino, &b)
        })
    }

    /// Persist `i_generation` plus ctime to `ino`'s on-disk inode, journaled.
    /// Linux `EXT4_IOC_SETVERSION` also bumps `i_version`; VFS owns that.
    /// # C: O(1) I/O, 1 txn
    pub fn persist_inode_generation(&self, ino: u32, gen: u32, ctime_ns: u64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            b[OFF_GENERATION..OFF_GENERATION + 4].copy_from_slice(&gen.to_le_bytes());
            let (c_lo, c_ex) = enc_time(ctime_ns);
            b[OFF_CTIME..OFF_CTIME + 4].copy_from_slice(&c_lo.to_le_bytes());
            if isize >= OFF_CTIME_EXTRA + 4 {
                b[OFF_CTIME_EXTRA..OFF_CTIME_EXTRA + 4].copy_from_slice(&c_ex.to_le_bytes());
            }
            m.write_inode_bytes(ino, &b)
        })
    }
}

/// Encode an absolute-ns timestamp into the ext4 `(i_*time, i_*time_extra)`
/// pair: seconds low 32 bits in the base field; `(nsec << 2) | epoch_hi2` in
/// the extra field (Linux `ext4_encode_extra_time`). # C: O(1)
pub(crate) fn enc_time(ns: u64) -> (u32, u32) {
    let secs = ns / 1_000_000_000;
    let nsec = (ns % 1_000_000_000) as u32;
    let lo = (secs & 0xFFFF_FFFF) as u32;
    let epoch = ((secs >> 32) & 0x3) as u32;
    (lo, (nsec << 2) | epoch)
}

/// Stamp a freshly-created inode's four timestamps (atime = ctime = mtime =
/// crtime = `now_ns`) into its raw on-disk bytes — the `ext4_new_inode`
/// `current_time(inode)` seeding that keeps a new file off the 1970 epoch.
/// The nanosecond/epoch-high extras + `i_crtime` only exist in a >128-byte
/// inode (`isize`). Caller owns the surrounding inode write. # C: O(1)
pub(crate) fn stamp_new_inode_times(b: &mut [u8], isize: usize, now_ns: u64) {
    let (lo, ex) = enc_time(now_ns);
    b[OFF_ATIME..OFF_ATIME + 4].copy_from_slice(&lo.to_le_bytes());
    b[OFF_CTIME..OFF_CTIME + 4].copy_from_slice(&lo.to_le_bytes());
    b[OFF_MTIME..OFF_MTIME + 4].copy_from_slice(&lo.to_le_bytes());
    if isize >= OFF_CRTIME_EXTRA + 4 {
        b[OFF_ATIME_EXTRA..OFF_ATIME_EXTRA + 4].copy_from_slice(&ex.to_le_bytes());
        b[OFF_CTIME_EXTRA..OFF_CTIME_EXTRA + 4].copy_from_slice(&ex.to_le_bytes());
        b[OFF_MTIME_EXTRA..OFF_MTIME_EXTRA + 4].copy_from_slice(&ex.to_le_bytes());
        b[OFF_CRTIME..OFF_CRTIME + 4].copy_from_slice(&lo.to_le_bytes());
        b[OFF_CRTIME_EXTRA..OFF_CRTIME_EXTRA + 4].copy_from_slice(&ex.to_le_bytes());
    }
}

impl Mount {
    pub(crate) fn stamp_inode_meta_fields(&self, b: &mut [u8], meta: InodeMetaUpdate) {
        b[OFF_MODE..OFF_MODE + 2].copy_from_slice(&meta.mode.to_le_bytes());
        b[OFF_UID_LO..OFF_UID_LO + 2].copy_from_slice(&((meta.uid & 0xFFFF) as u16).to_le_bytes());
        b[OFF_UID_HI..OFF_UID_HI + 2].copy_from_slice(&((meta.uid >> 16) as u16).to_le_bytes());
        b[OFF_GID_LO..OFF_GID_LO + 2].copy_from_slice(&((meta.gid & 0xFFFF) as u16).to_le_bytes());
        b[OFF_GID_HI..OFF_GID_HI + 2].copy_from_slice(&((meta.gid >> 16) as u16).to_le_bytes());
        let (a_lo, a_ex) = enc_time(meta.atime_ns);
        let (c_lo, c_ex) = enc_time(meta.ctime_ns);
        let (m_lo, m_ex) = enc_time(meta.mtime_ns);
        b[OFF_ATIME..OFF_ATIME + 4].copy_from_slice(&a_lo.to_le_bytes());
        b[OFF_CTIME..OFF_CTIME + 4].copy_from_slice(&c_lo.to_le_bytes());
        b[OFF_MTIME..OFF_MTIME + 4].copy_from_slice(&m_lo.to_le_bytes());
        if self.sb.inode_size as usize >= OFF_ATIME_EXTRA + 4 {
            b[OFF_ATIME_EXTRA..OFF_ATIME_EXTRA + 4].copy_from_slice(&a_ex.to_le_bytes());
            b[OFF_CTIME_EXTRA..OFF_CTIME_EXTRA + 4].copy_from_slice(&c_ex.to_le_bytes());
            b[OFF_MTIME_EXTRA..OFF_MTIME_EXTRA + 4].copy_from_slice(&m_ex.to_le_bytes());
        }
    }

    /// Persist an inode's mode / owner / timestamps to its on-disk slot
    /// (journaled) — the ext4 half of `notify_change` (Linux `ext4_setattr` →
    /// `__ext4_mark_inode_dirty`). Size/blocks/nlink/extents are owned by the
    /// data path and left untouched, so a concurrent-in-scope truncate is not
    /// clobbered. Owner ids write both the low u16 and the osd2 high u16 so a
    /// uid/gid > 65535 round-trips. # C: O(1) I/O, one journal transaction
    pub fn persist_inode_meta(&self, ino: u32, mode: u16, uid: u32, gid: u32,
        atime_ns: u64, mtime_ns: u64, ctime_ns: u64) -> Result<(), MountError>
    {
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            m.stamp_inode_meta_fields(&mut b, InodeMetaUpdate { mode, uid, gid, atime_ns, mtime_ns, ctime_ns });
            m.write_inode_bytes(ino, &b)
        })
    }
}
