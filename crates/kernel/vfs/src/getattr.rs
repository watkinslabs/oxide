//! `vfs_getattr` / `generic_fillattr` (Linux `fs/stat.c`).
//!
//! A single `Inode::getattr` inode-op (default `generic_fillattr`) assembles
//! the `Kstat` every stat-family syscall encodes, replacing the field-by-field
//! `S_IF*` mapping + overlay-merge + perm-fallback duplicated across
//! stat/lstat/fstat/newfstatat/statx. Backends that carry native metadata
//! (ext4) override `getattr`; pseudo-fs use the default.

extern crate alloc;
use crate::idmap::Idmap;
use crate::inode::Inode;
use crate::inode_times::InodeTimes;
use crate::types::FileType;

/// `S_IF*` file-type bits as the `u32` `Kstat`/stat-ABI surface. Re-derived
/// from the canonical `Umode` (`u16`) defs in `types` — single source of
/// truth, no duplicated magic literals. `mode` (`Kstat`) is `u32`, so these
/// stay `u32` for byte-identical OR-packing with the permission bits.
pub const S_IFMT:   u32 = crate::types::S_IFMT   as u32;
pub const S_IFSOCK: u32 = crate::types::S_IFSOCK as u32;
pub const S_IFLNK:  u32 = crate::types::S_IFLNK  as u32;
pub const S_IFREG:  u32 = crate::types::S_IFREG  as u32;
pub const S_IFBLK:  u32 = crate::types::S_IFBLK  as u32;
pub const S_IFDIR:  u32 = crate::types::S_IFDIR  as u32;
pub const S_IFCHR:  u32 = crate::types::S_IFCHR  as u32;
pub const S_IFIFO:  u32 = crate::types::S_IFIFO  as u32;

/// `STATX_*` result-mask bits (Linux `include/uapi/linux/stat.h`) — set in
/// `Kstat::result_mask` for each field the backend actually filled, so the
/// `statx(2)` ABI can report `stx_mask` exactly. `generic_fillattr` always
/// populates the `STATX_BASIC_STATS` set; `STATX_BTIME` is added only when the
/// inode carries a real creation time.
pub const STATX_TYPE:        u32 = 0x0000_0001;
pub const STATX_MODE:        u32 = 0x0000_0002;
pub const STATX_NLINK:       u32 = 0x0000_0004;
pub const STATX_UID:         u32 = 0x0000_0008;
pub const STATX_GID:         u32 = 0x0000_0010;
pub const STATX_ATIME:       u32 = 0x0000_0020;
pub const STATX_MTIME:       u32 = 0x0000_0040;
pub const STATX_CTIME:       u32 = 0x0000_0080;
pub const STATX_INO:         u32 = 0x0000_0100;
pub const STATX_SIZE:        u32 = 0x0000_0200;
pub const STATX_BLOCKS:      u32 = 0x0000_0400;
/// The eleven base fields every `vfs_getattr` resolves (Linux `STATX_BASIC_STATS`).
pub const STATX_BASIC_STATS: u32 = STATX_TYPE | STATX_MODE | STATX_NLINK | STATX_UID
    | STATX_GID | STATX_ATIME | STATX_MTIME | STATX_CTIME | STATX_INO | STATX_SIZE | STATX_BLOCKS;
pub const STATX_BTIME:       u32 = 0x0000_0800;
/// `STATX_CHANGE_COOKIE` (Linux `include/uapi/linux/stat.h`, bit 30) — the
/// caller wants / the kernel filled `stx_change_attr`, the opaque monotonic
/// change cookie an NFS-style client compares to detect a modification without
/// re-reading content. Only [`vfs_getattr_mask`] sets it (gated on the request
/// mask, like Linux), because querying the cookie LATCHES the inode's i_version
/// QUERIED flag — a plain stat must not pay that side effect.
pub const STATX_CHANGE_COOKIE: u32 = 0x4000_0000;

/// `STATX_ATTR_*` bits (Linux `include/uapi/linux/stat.h`) — reported in
/// `Kstat::attributes`, masked by `Kstat::attributes_mask` (the set of
/// attributes the backend understands). `generic_fillattr` translates the VFS
/// `i_flags` `S_IMMUTABLE`/`S_APPEND` bits into the matching attr bits.
pub const STATX_ATTR_IMMUTABLE: u64 = 0x0000_0010;
pub const STATX_ATTR_APPEND:    u64 = 0x0000_0020;

/// Resolved inode attributes (Linux `struct kstat`). `mode` carries the
/// `S_IF*` type bits OR'd with the permission bits. `fsid` is the raw
/// filesystem identity (`Inode::fsid`); the syscall layer encodes it into the
/// ABI `dev_t`. `result_mask` reports exactly which fields are valid (statx
/// `stx_mask`); `attributes`/`attributes_mask` carry the `STATX_ATTR_*`
/// flag report (statx `stx_attributes`/`stx_attributes_mask`); `btime_ns` is
/// the creation time, valid only when `STATX_BTIME` is set in `result_mask`.
/// `change_cookie` is the statx `stx_change_attr`, valid only when
/// `STATX_CHANGE_COOKIE` is set in `result_mask` (filled by [`vfs_getattr_mask`]
/// from the inode `i_version`).
#[derive(Clone, Copy, Default)]
pub struct Kstat {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub size: u64,
    pub blksize: u32,
    pub blocks: u64,
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
    pub btime_ns: u64,
    pub fsid: u64,
    pub change_cookie: u64,
    pub result_mask: u32,
    pub attributes: u64,
    pub attributes_mask: u64,
}

/// `new_encode_dev` (Linux `include/linux/kdev_t.h`): pack a `(major, minor)`
/// pair into the 32-bit `st_rdev` ABI surface with the huge-dev split — minor's
/// low 8 bits in `[0..8)`, the 12-bit major in `[8..20)`, and minor's HIGH bits
/// in `[20..32)`. The high-minor split is what lets a minor exceed 255 (e.g.
/// dynamic char minors, loop/dm devices) without clobbering the major field;
/// the naive `(major<<8)|minor` legacy form silently truncates those. Byte-
/// identical to `Devt::new(major, minor).raw()` — the one encoding every
/// `Inode::rdev()` impl reports, so `generic_fillattr` copies it through
/// verbatim for device nodes and reports 0 for everything else. # C: O(1)
pub const fn encode_dev(major: u32, minor: u32) -> u32 {
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12)
}

/// Map a filesystem identity (`Inode::fsid()` / `SuperBlock::s_dev`) to the
/// Linux `dev_t` userspace sees in `st_dev` — THE single transform `stat`/
/// `statx` apply (`syscalls::namei_common::fsid_to_dev` delegates here).
/// Reproducing it outside the stat path lets a subsystem match the `st_dev`
/// userspace holds: autofs `AUTOFS_DEV_IOCTL_OPENMOUNT` carries the `devid`
/// systemd took from `fstat`, so the autofs registry MUST key on this
/// user-visible dev — not the raw identity, which neither equals the encoded
/// `st_dev` nor fits the ioctl's `__u32` devid field.
///
/// Linux-faithful path (no more hash): the identity is resolved to a REAL anon
/// `dev_t` `(major 0, unique minor)` by [`crate::superblock::st_dev_for_fsid`]
/// (the `get_anon_bdev`/`unnamed_dev_ida` model every nodev filesystem uses),
/// then `huge_encode_dev`'d to the 64-bit user wire form — exactly what
/// `/proc/mounts` shows as `0:NN` for a nodev fs. Distinct per filesystem,
/// stable across a boot, always `<= u32::MAX`. # C: O(log N_fs)
pub fn fsid_to_dev(fsid: u64) -> u64 {
    crate::devnode::huge_encode_dev(st_dev_for_fsid(fsid))
}

/// `st_dev` identity registry — maps each opaque filesystem identity
/// (`Inode::fsid()`: a per-instance anon `s_dev` OR a per-fs-type constant like
/// `DEVFS_FSID`) to the stable KERNEL anon `dev_t` `(0, minor)` it presents.
/// Pseudo-filesystems that share one constant identity across every inode (and
/// have no per-instance `s_dev`) get a single reserved minor here; per-instance
/// `s_dev` values are anon devs already and pass straight through.
/// # C: O(log N_fs)
static ST_DEV_MAP: sync::Spinlock<alloc::collections::BTreeMap<u64, u32>, sync::Superblock>
    = sync::Spinlock::new(alloc::collections::BTreeMap::new());

/// Map a filesystem identity (`Inode::fsid()`) to the stable KERNEL anon `dev_t`
/// `(0, minor)` it presents to userspace. An identity that is ALREADY a real
/// anon `dev_t` from [`crate::superblock::next_anon_dev`] (major 0, minor in the
/// live anon range) passes through unchanged; a large per-fs-type constant
/// (`0x0102_1994_…`, `CGROUP2_FSID`, …) is assigned — once, stably — a fresh
/// reserved minor from the shared `unnamed_dev_ida` allocator. `0` (a truly anon
/// SB-less inode: pipe/socket) maps to `0`, matching Linux `st_dev == 0`. The
/// single source of truth behind [`fsid_to_dev`]. # C: O(log N_fs)
pub fn st_dev_for_fsid(fsid: u64) -> u32 {
    if fsid == 0 { return 0; }
    // A `next_anon_dev` result is `MKDEV(0, minor)` == `minor` (major 0), so it
    // already fits the kernel `dev_t` minor field — present it directly.
    if fsid <= crate::devnode::MINORMASK as u64 { return fsid as u32; }
    let mut m = ST_DEV_MAP.lock();
    if let Some(&d) = m.get(&fsid) { return d; }
    let d = crate::devnode::mkdev(0, crate::superblock::alloc_anon_minor());
    m.insert(fsid, d);
    d
}

#[cfg(test)]
mod dev_tests {
    use crate::devnode::{Devt, mkdev, kdev_major, kdev_minor, new_encode_dev, huge_encode_dev, MINORMASK};

    /// `MKDEV`/`MAJOR`/`MINOR` round-trip on a KERNEL `dev_t` (12:20 split),
    /// including a high minor that overflows the legacy 8-bit field. # C: O(1)
    #[test]
    fn mkdev_major_minor_roundtrip() {
        for (ma, mi) in [(0u32, 1u32), (0, 21), (1, 3), (8, 0), (10, 200), (240, 0xfffff), (4, 65535)] {
            let kd = mkdev(ma, mi);
            assert_eq!(kdev_major(kd), ma, "major {ma}:{mi}");
            assert_eq!(kdev_minor(kd), mi & MINORMASK, "minor {ma}:{mi}");
        }
    }

    /// `new_encode_dev`/`huge_encode_dev` reproduce the glibc wire form, and the
    /// [`Devt`] user wrapper decodes it back to the same `(major, minor)` — the
    /// `st_rdev` ABI contract, high-minor split included. # C: O(1)
    #[test]
    fn encode_dev_matches_devt_and_decodes() {
        for (ma, mi) in [(1u32, 3u32), (10, 200), (4, 300), (89, 1), (8, 70000)] {
            let kd = mkdev(ma, mi);
            let enc = new_encode_dev(kd);
            assert_eq!(huge_encode_dev(kd), enc as u64, "huge==new for {ma}:{mi}");
            assert_eq!(Devt::new(ma, mi).raw(), enc, "Devt::new packs new_encode_dev {ma}:{mi}");
            let d = Devt::from_raw(enc);
            assert_eq!((d.major(), d.minor()), (ma, mi), "Devt decode {ma}:{mi}");
            assert_eq!(d.to_kdev(), kd, "Devt->kdev {ma}:{mi}");
        }
    }

    /// Every `fsid_to_dev` result must be a REAL anon `dev_t` (major 0) and fit
    /// Linux's effective 32-bit `dev_t`: the autofs `AUTOFS_DEV_IOCTL_OPENMOUNT`
    /// devid field is a `__u32`, so a value above `u32::MAX` would truncate and
    /// never match the registry (the binfmt_misc automount wedge root cause).
    /// # C: O(N samples)
    #[test]
    fn fsid_to_dev_real_anon_and_stable() {
        for fsid in [0u64, 1, 256, 0x0102_1994_0000_0003, 0x0000_0001_0000_000e, u64::MAX] {
            let d = super::fsid_to_dev(fsid);
            assert!(d <= u32::MAX as u64, "fsid {fsid:#x} -> dev {d:#x} exceeds u32");
            assert_eq!(d, super::fsid_to_dev(fsid), "fsid_to_dev not deterministic");
            // Decode back: major must be 0 (anon block device, Linux nodev fs).
            let major = ((d >> 8) & 0xfff) as u32 | ((d >> 32) & !0xfff) as u32;
            assert_eq!(major, 0, "fsid {fsid:#x} -> dev {d:#x} is not a (0,minor) anon dev");
        }
        // Distinct identities → distinct st_dev (the property userspace mount-
        // boundary detection relies on).
        let a = super::fsid_to_dev(0x0102_1994_0000_00aa);
        let b = super::fsid_to_dev(0x0102_1994_0000_00bb);
        assert_ne!(a, b, "distinct fsids must map to distinct st_dev");
        assert_eq!(a, super::fsid_to_dev(0x0102_1994_0000_00aa), "stable across calls");
    }

    /// A `mknod` char-device inode carries a real `(major, minor)` `i_rdev`;
    /// `generic_fillattr` reports it in `Kstat::rdev` in the glibc wire form,
    /// decodable back to the original pair (high-minor split included). # C: O(1)
    #[test]
    fn mknod_chardev_st_rdev_roundtrip() {
        use alloc::sync::Weak;
        use crate::devnode::make_device_node_inode;
        use crate::types::FileType;
        for (ma, mi) in [(1u32, 3u32), (10, 200), (4, 300)] {
            let inode = make_device_node_inode(7, FileType::CharDev, Devt::new(ma, mi), 0o666, Weak::new());
            let st = super::generic_fillattr(&inode, &crate::idmap::IDENTITY, None);
            assert_eq!(st.mode & super::S_IFMT, super::S_IFCHR, "char type bits {ma}:{mi}");
            let d = Devt::from_raw(st.rdev);
            assert_eq!((d.major(), d.minor()), (ma, mi), "st_rdev decode {ma}:{mi}");
        }
        // A regular file reports st_rdev == 0 (Linux leaves it clear).
        let reg = crate::inode::InodeBuilder::new(8, super::S_IFREG | 0o644,
            crate::inode_ops::default_inode_ops(), crate::file_ops::default_file_ops()).build();
        let st = super::generic_fillattr(&reg, &crate::idmap::IDENTITY, None);
        assert_eq!(st.rdev, 0, "regular file st_rdev clear");
    }
}

/// Linux-shaped permission fallback for inodes without a native mode
/// (`Inode::perm() == None` and no overlay). # C: O(1)
pub fn default_perm_for(ft: FileType) -> u16 {
    match ft {
        FileType::Directory => 0o755,
        FileType::Symlink   => 0o777,
        FileType::CharDev | FileType::BlockDev => 0o666,
        FileType::Fifo | FileType::Socket => 0o666,
        FileType::Regular   => 0o644,
    }
}

/// `generic_fillattr` — assemble a `Kstat` from the inode's own fields, applying
/// the mount `idmap` to the owner ids. An identity idmap returns the raw fs ids,
/// so the output is byte-identical to the pre-idmap stat path. D17: the concrete
/// `struct Inode` now always stores its own perm/owner/times, so the legacy
/// `inode_times` overlay is no longer merged — `overlay` is retained as a
/// (now-inert) parameter for ABI/signature stability with the `i_op->getattr`
/// override path and is ignored. # C: O(1)
pub fn generic_fillattr(inode: &Inode, idmap: &Idmap, overlay: Option<InodeTimes>) -> Kstat {
    let _ = &overlay; // D17: overlay no longer consulted (inode owns its fields)
    let ft = inode.file_type();
    // ONE place builds the `S_IFMT` half of the mode: `FileType::to_ifmt`
    // (shared with `Inode::i_mode`). `st_rdev` is only meaningful for device
    // nodes — Linux leaves it 0 for everything else.
    let type_bits: u32 = ft.to_ifmt() as u32;
    let rdev: u32 = match ft {
        FileType::CharDev | FileType::BlockDev => inode.rdev(),
        _ => 0,
    };
    let perm = inode.perm().unwrap_or_else(|| default_perm_for(ft));
    let raw_uid = inode.uid().unwrap_or(0);
    let raw_gid = inode.gid().unwrap_or(0);
    // `st_blksize` is a SUPERBLOCK property (Linux `s_blocksize`), not a
    // per-inode one: route through the owning SB so every inode on one fs
    // reports its mount's block size. `blksize()` is only the fallback for
    // SB-less anon inodes (pidfd/pipe/socket — pending D35's anon SB). The same
    // effective allocation unit also drives `st_blocks` (see `blocks_for`).
    let bsize: u32 = inode.i_sb().map(|s| s.s_blocksize).unwrap_or_else(|| inode.blksize());
    // `stx_btime` is only valid when the inode stores a real creation time.
    // Linux omits `STATX_BTIME` from `stx_mask` otherwise (it does NOT fall
    // back to ctime) — pseudo-fs without an `i_crtime` leave the bit clear.
    let (btime_ns, btime_bit) = match inode.btime() {
        Some(b) => (b, STATX_BTIME),
        None    => (0, 0),
    };
    // `stx_attributes` mirrors the VFS `i_flags` (Linux `generic_fillattr` does
    // not set them; `vfs_getattr` ORs the per-fs `stx_attributes` reported via
    // `request_mask`). The generic backend understands exactly the two flags
    // the VFS itself enforces — immutable (write-deny) and append-only — so the
    // `attributes_mask` advertises only those as authoritative.
    let iflags = inode.i_flags();
    let mut attributes = 0u64;
    if iflags & crate::inode::S_IMMUTABLE != 0 { attributes |= STATX_ATTR_IMMUTABLE; }
    if iflags & crate::inode::S_APPEND    != 0 { attributes |= STATX_ATTR_APPEND; }
    Kstat {
        ino:      inode.ino(),
        mode:     type_bits | perm as u32,
        nlink:    inode.nlink(),
        uid:      idmap.map_out_uid(raw_uid),
        gid:      idmap.map_out_gid(raw_gid),
        rdev,
        size:     inode.size(),
        blksize:  bsize,
        // Linux `generic_fillattr`: `stat->blocks = inode->i_blocks`. A backend
        // that maintains a real `i_blocks` (sparse/preallocated extents) reports
        // it verbatim; only an inode that never set it (`0`) falls back to the
        // size-rounded estimate (`blocks_for`). The old code ALWAYS estimated,
        // silently discarding a stored `i_blocks` — wrong for a sparse file
        // (over-count) or a file with preallocation past EOF (under-count). D20.
        blocks:   if inode.blocks() != 0 { inode.blocks() } else { blocks_for(inode.size(), bsize) },
        atime_ns: inode.atime().unwrap_or(0),
        mtime_ns: inode.mtime().unwrap_or(0),
        ctime_ns: inode.ctime().unwrap_or(0),
        btime_ns,
        fsid:     inode.fsid(),
        // `change_cookie` is NOT filled here: querying the i_version latches the
        // QUERIED flag, a side effect a plain stat must avoid. Only the
        // request-mask-gated `vfs_getattr_mask` populates it (Linux gates the
        // change-cookie on `STATX_CHANGE_COOKIE` for the same reason).
        change_cookie: 0,
        // Every base field above is filled; add BTIME only when present so
        // `stx_mask` reflects exactly the valid fields, no more.
        result_mask: STATX_BASIC_STATS | btime_bit,
        attributes,
        attributes_mask: STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND,
    }
}

/// `st_blocks` (Linux `stat.st_blocks`): the count of 512-byte units the file
/// occupies. With no stored `i_blocks` field (D20 remainder), the best generic
/// estimate of a NON-sparse file is `size` rounded UP to the filesystem
/// allocation unit (`s_blocksize`/`blksize`) and re-expressed in 512-byte
/// sectors — so a sub-block file reports a whole block (a 1-byte file on a 4 KiB
/// fs = 8 sectors), matching `stat(1)` on ext4/tmpfs instead of the
/// `ceil(size/512)` under-count that reported a single sector. Sparse /
/// preallocated extents still need a real per-inode `i_blocks` (and `i_bytes`)
/// to be exact — that is the unaddressed half of D20. # C: O(1)
pub fn blocks_for(size: u64, bsize: u32) -> u64 {
    let unit = (bsize as u64).max(512);          // allocation unit, ≥ one sector
    let units = (size + unit - 1) / unit;         // blocks occupied, rounded up
    units * (unit / 512)                          // → 512-byte sectors
}

/// `vfs_getattr` (Linux `fs/stat.c`): the stat-family entry that dispatches to
/// `i_op->getattr` (override) or `generic_fillattr` (default). # C: O(1)
pub fn vfs_getattr(inode: &crate::inode::InodeRef, idmap: &Idmap, overlay: Option<InodeTimes>) -> Kstat {
    inode.getattr(idmap, overlay)
}

/// `vfs_getattr` with the statx `request_mask` honored for the request-gated
/// fields (Linux `vfs_getattr_nosec`). Runs the base `i_op->getattr` then, when
/// `STATX_CHANGE_COOKIE` is requested AND the inode carries an `i_version`
/// (`IS_I_VERSION`), fills `change_cookie` from `inode_query_iversion` and sets
/// the result bit. The query LATCHES the inode's QUERIED flag so the next
/// modification is guaranteed to bump the version — which is exactly why this is
/// gated on the request mask and not done in the unconditional
/// `generic_fillattr`. # C: O(1)
pub fn vfs_getattr_mask(inode: &crate::inode::InodeRef, idmap: &Idmap,
                        overlay: Option<InodeTimes>, request_mask: u32) -> Kstat {
    let mut st = inode.getattr(idmap, overlay);
    if request_mask & STATX_CHANGE_COOKIE != 0 && inode.i_version_raw().is_some() {
        st.change_cookie = crate::inode::inode_query_iversion(inode.as_ref());
        st.result_mask |= STATX_CHANGE_COOKIE;
    }
    st
}
