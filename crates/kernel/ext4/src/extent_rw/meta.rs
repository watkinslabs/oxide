use vfs::Timespec64;

use crate::inode::InodeError;
use crate::mount::{Mount, MountError};
use crate::superblock::{EXT4_LABEL_MAX, SB_OFF_VOLUME_NAME, SUPERBLOCK_LEN, SUPERBLOCK_OFFSET};
use crate::timestamp::{I_ATIME, I_ATIME_EXTRA, I_CTIME, I_CTIME_EXTRA, I_MTIME, I_MTIME_EXTRA,
                       set_crtime, set_xtime};

// ext4 on-disk inode field byte offsets (Linux `struct ext4_inode`). The data
// path owns size/blocks/nlink/extents; this writer touches only the metadata
// the VFS `notify_change` mutates: mode, owner, and the three timestamps. The
// timestamp field offsets + their `(base, extra)` codec are owned by
// `crate::timestamp`.
const OFF_MODE:        usize = 0x00;
const OFF_UID_LO:      usize = 0x02;
const OFF_GID_LO:      usize = 0x18;
const OFF_UID_HI:      usize = 0x78; // osd2 `l_i_uid_high`
const OFF_GID_HI:      usize = 0x7A; // osd2 `l_i_gid_high`
const OFF_FLAGS:        usize = 0x20; // i_flags (chattr flag word)
const OFF_GENERATION:   usize = 0x64; // i_generation
const OFF_PROJID:       usize = 0x9C; // i_projid, present in >=160-byte inode

#[derive(Clone, Copy)]
pub(crate) struct InodeMetaUpdate {
    pub(crate) mode: u16,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) atime: Timespec64,
    pub(crate) mtime: Timespec64,
    pub(crate) ctime: Timespec64,
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
    pub fn persist_inode_flags(&self, ino: u32, flags: u32, ctime: Timespec64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            b[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
            set_xtime(&mut b, isize, I_CTIME, I_CTIME_EXTRA, ctime);
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
    pub fn persist_inode_flags_mctime(&self, ino: u32, flags: u32, mtime: Timespec64, ctime: Timespec64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            b[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
            set_xtime(&mut b, isize, I_CTIME, I_CTIME_EXTRA, ctime);
            set_xtime(&mut b, isize, I_MTIME, I_MTIME_EXTRA, mtime);
            m.write_inode_bytes(ino, &b)
        })
    }

    /// `inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir))` — the
    /// mtime+ctime bump every ext4 directory-entry mutation makes to the
    /// directory it edited (Linux `add_dirent_to_buf`, `ext4_rename`).
    /// # C: O(1) I/O, 1 txn
    pub fn touch_inode_mtime_ctime(&self, ino: u32, now: Timespec64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            set_xtime(&mut b, isize, I_CTIME, I_CTIME_EXTRA, now);
            set_xtime(&mut b, isize, I_MTIME, I_MTIME_EXTRA, now);
            m.write_inode_bytes(ino, &b)
        })
    }

    /// `inode_set_ctime_current(inode)` — the change-time stamp a renamed or
    /// link-count-adjusted inode gets (Linux `ext4_rename`). # C: O(1) I/O, 1 txn
    pub fn touch_inode_ctime(&self, ino: u32, now: Timespec64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            set_xtime(&mut b, isize, I_CTIME, I_CTIME_EXTRA, now);
            m.write_inode_bytes(ino, &b)
        })
    }

    /// Persist `i_projid` (@0x9C) to `ino`'s on-disk inode, journaled. Linux
    /// `ext4_ioctl_setproject` requires the PROJECT feature and enough inode
    /// room for the field; callers enforce feature policy. # C: O(1) I/O, 1 txn
    pub fn persist_inode_project(&self, ino: u32, projid: u32, ctime: Timespec64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            if b.len() < OFF_PROJID + 4 { return Err(MountError::Inode(InodeError::BadLen)); }
            b[OFF_PROJID..OFF_PROJID + 4].copy_from_slice(&projid.to_le_bytes());
            set_xtime(&mut b, isize, I_CTIME, I_CTIME_EXTRA, ctime);
            m.write_inode_bytes(ino, &b)
        })
    }

    /// Persist `i_generation` plus ctime to `ino`'s on-disk inode, journaled.
    /// Linux `EXT4_IOC_SETVERSION` also bumps `i_version`; VFS owns that.
    /// # C: O(1) I/O, 1 txn
    pub fn persist_inode_generation(&self, ino: u32, gen: u32, ctime: Timespec64) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            b[OFF_GENERATION..OFF_GENERATION + 4].copy_from_slice(&gen.to_le_bytes());
            set_xtime(&mut b, isize, I_CTIME, I_CTIME_EXTRA, ctime);
            m.write_inode_bytes(ino, &b)
        })
    }
}

/// Stamp a freshly-created inode's four timestamps (atime = ctime = mtime =
/// crtime = `now`) into its raw on-disk bytes — the `ext4_new_inode`
/// `current_time(inode)` seeding that keeps a new file off the 1970 epoch.
/// `i_crtime` and the nanosecond/epoch-high extras are written only when the
/// inode's extra region covers them (`EXT4_FITS_IN_INODE`). Caller owns the
/// surrounding inode write. # C: O(1)
pub(crate) fn stamp_new_inode_times(b: &mut [u8], isize: usize, now: Timespec64) {
    set_xtime(b, isize, I_ATIME, I_ATIME_EXTRA, now);
    set_xtime(b, isize, I_CTIME, I_CTIME_EXTRA, now);
    set_xtime(b, isize, I_MTIME, I_MTIME_EXTRA, now);
    set_crtime(b, isize, now);
}

impl Mount {
    pub(crate) fn stamp_inode_meta_fields(&self, b: &mut [u8], meta: InodeMetaUpdate) {
        b[OFF_MODE..OFF_MODE + 2].copy_from_slice(&meta.mode.to_le_bytes());
        b[OFF_UID_LO..OFF_UID_LO + 2].copy_from_slice(&((meta.uid & 0xFFFF) as u16).to_le_bytes());
        b[OFF_UID_HI..OFF_UID_HI + 2].copy_from_slice(&((meta.uid >> 16) as u16).to_le_bytes());
        b[OFF_GID_LO..OFF_GID_LO + 2].copy_from_slice(&((meta.gid & 0xFFFF) as u16).to_le_bytes());
        b[OFF_GID_HI..OFF_GID_HI + 2].copy_from_slice(&((meta.gid >> 16) as u16).to_le_bytes());
        let isize = self.sb.inode_size as usize;
        set_xtime(b, isize, I_ATIME, I_ATIME_EXTRA, meta.atime);
        set_xtime(b, isize, I_CTIME, I_CTIME_EXTRA, meta.ctime);
        set_xtime(b, isize, I_MTIME, I_MTIME_EXTRA, meta.mtime);
    }

    /// Persist an inode's mode / owner / timestamps to its on-disk slot
    /// (journaled) — the ext4 half of `notify_change` (Linux `ext4_setattr` →
    /// `__ext4_mark_inode_dirty`). Size/blocks/nlink/extents are owned by the
    /// data path and left untouched, so a concurrent-in-scope truncate is not
    /// clobbered. Owner ids write both the low u16 and the osd2 high u16 so a
    /// uid/gid > 65535 round-trips. # C: O(1) I/O, one journal transaction
    pub fn persist_inode_meta(&self, ino: u32, mode: u16, uid: u32, gid: u32,
        atime: Timespec64, mtime: Timespec64, ctime: Timespec64) -> Result<(), MountError>
    {
        self.run_journaled(|m| {
            let (mut b, _off) = m.read_inode_bytes(ino)?;
            m.stamp_inode_meta_fields(&mut b, InodeMetaUpdate { mode, uid, gid, atime, mtime, ctime });
            m.write_inode_bytes(ino, &b)
        })
    }
}
