// Translation between a 9P server's metadata and this kernel's inode fields.

extern crate alloc;

use ninep::codec::{IattrDotl, Qid, StatDotl};
use ninep::uapi::{dotl, setattr as p9setattr, stats};
use vfs::timespec::NSEC_PER_SEC;
use vfs::{FileType, Iattr, Timespec64};
use vfs::setattr as vattr;

/// Inode number for a server object.
///
/// The server's `qid.path` is 64 bits and its `st_ino` need not agree with it;
/// the PATH is the identity the protocol guarantees is unique for the life of
/// the mount, so it is what an inode number is derived from. Using a reported
/// `st_ino` instead would let two distinct objects share an inode number
/// whenever the server exports more than one underlying filesystem, and the
/// dcache would then alias them. # C: O(1)
pub fn qid_to_ino(q: &Qid) -> u64 { q.path }

/// File class from a `qid.type` — available before any attribute round trip.
/// # C: O(1)
pub fn qid_file_type(q: &Qid) -> FileType {
    if q.is_dir() { FileType::Directory }
    else if q.is_symlink() { FileType::Symlink }
    else { FileType::Regular }
}

/// `S_IFMT` classes, re-declared because a 9P mode is not one of this kernel's.
mod ifmt {
    pub const MASK: u32 = 0o170000;
    pub const FIFO: u32 = 0o010000;
    pub const CHR: u32 = 0o020000;
    pub const DIR: u32 = 0o040000;
    pub const BLK: u32 = 0o060000;
    pub const REG: u32 = 0o100000;
    pub const LNK: u32 = 0o120000;
    pub const SOCK: u32 = 0o140000;
}

/// File class from a `.L` mode word. # C: O(1)
pub fn mode_file_type(mode: u32) -> FileType {
    match mode & ifmt::MASK {
        ifmt::DIR => FileType::Directory,
        ifmt::LNK => FileType::Symlink,
        ifmt::CHR => FileType::CharDev,
        ifmt::BLK => FileType::BlockDev,
        ifmt::FIFO => FileType::Fifo,
        ifmt::SOCK => FileType::Socket,
        _ => FileType::Regular,
    }
}

/// Strip the device, socket and fifo classes a `nodevmap` mount refuses to
/// materialise, leaving a plain file. A server on the other side of a VM
/// boundary is not trusted to hand a guest a character-device node.
/// # C: O(1)
pub fn apply_nodev(mode: u32, nodev: bool) -> u32 {
    if !nodev { return mode; }
    match mode & ifmt::MASK {
        ifmt::CHR | ifmt::BLK | ifmt::FIFO | ifmt::SOCK => (mode & !ifmt::MASK) | ifmt::REG,
        _ => mode,
    }
}

/// A server timestamp as a kernel one. The sub-second field is CLAMPED rather
/// than rejected: a server sending an out-of-range nanosecond has a clock bug,
/// not an unreadable file, and refusing the whole stat would make the object
/// disappear. # C: O(1)
pub fn attr_time(sec: u64, nsec: u64) -> Timespec64 {
    Timespec64 { sec: sec as i64, nsec: (nsec.min((NSEC_PER_SEC - 1) as u64)) as u32 }
}

/// Translate an inode-attribute change into the `.L` request form.
///
/// A field whose bit is not set in `valid` is IGNORED by the server, so the
/// mask is what carries the caller's intent — zeroing a field it did not
/// select would not clear it, and setting a bit for a field the caller did not
/// touch truncates the file or resets its mode. # C: O(1)
pub fn iattr_to_p9(ia: &Iattr) -> IattrDotl {
    let mut out = IattrDotl::default();
    let pairs = [
        (vattr::ATTR_MODE, p9setattr::MODE),
        (vattr::ATTR_UID, p9setattr::UID),
        (vattr::ATTR_GID, p9setattr::GID),
        (vattr::ATTR_SIZE, p9setattr::SIZE),
        (vattr::ATTR_ATIME, p9setattr::ATIME),
        (vattr::ATTR_MTIME, p9setattr::MTIME),
        (vattr::ATTR_CTIME, p9setattr::CTIME),
        (vattr::ATTR_ATIME_SET, p9setattr::ATIME_SET),
        (vattr::ATTR_MTIME_SET, p9setattr::MTIME_SET),
    ];
    for (from, to) in pairs {
        if ia.valid & from != 0 { out.valid |= to; }
    }
    out.mode = u32::from(ia.mode);
    out.uid = ia.uid;
    out.gid = ia.gid;
    out.size = ia.size;
    out.atime_sec = ia.atime.sec as u64;
    out.atime_nsec = u64::from(ia.atime.nsec);
    out.mtime_sec = ia.mtime.sec as u64;
    out.mtime_nsec = u64::from(ia.mtime.nsec);
    out
}

/// Translate this kernel's open flags into the `.L` flag word.
///
/// The `.L` numbering is the PROTOCOL's, deliberately re-derived from named
/// constants rather than passed through: the two happen to agree on this
/// architecture, and a pass-through would break silently on one where they do
/// not, sending `O_DIRECTORY` as something else entirely. # C: O(1)
pub fn open_flags_to_dotl(flags: u32) -> u32 {
    /// This kernel's `O_*` values, named so no bare literal decides a mode.
    mod o {
        pub const ACCMODE: u32 = 0o3;
        pub const CREAT: u32 = 0o100;
        pub const EXCL: u32 = 0o200;
        pub const NOCTTY: u32 = 0o400;
        pub const TRUNC: u32 = 0o1000;
        pub const APPEND: u32 = 0o2000;
        pub const NONBLOCK: u32 = 0o4000;
        pub const DSYNC: u32 = 0o10000;
        pub const DIRECT: u32 = 0o40000;
        pub const LARGEFILE: u32 = 0o100000;
        pub const DIRECTORY: u32 = 0o200000;
        pub const NOFOLLOW: u32 = 0o400000;
        pub const NOATIME: u32 = 0o1000000;
        pub const CLOEXEC: u32 = 0o2000000;
        pub const SYNC: u32 = 0o4000000;
    }
    let mut out = match flags & o::ACCMODE {
        1 => dotl::WRONLY,
        2 => dotl::RDWR,
        3 => dotl::NOACCESS,
        _ => dotl::RDONLY,
    };
    let map = [
        (o::CREAT, dotl::CREATE), (o::EXCL, dotl::EXCL), (o::NOCTTY, dotl::NOCTTY),
        (o::TRUNC, dotl::TRUNC), (o::APPEND, dotl::APPEND), (o::NONBLOCK, dotl::NONBLOCK),
        (o::DSYNC, dotl::DSYNC), (o::DIRECT, dotl::DIRECT), (o::LARGEFILE, dotl::LARGEFILE),
        (o::DIRECTORY, dotl::DIRECTORY), (o::NOFOLLOW, dotl::NOFOLLOW),
        (o::NOATIME, dotl::NOATIME), (o::CLOEXEC, dotl::CLOEXEC), (o::SYNC, dotl::SYNC),
    ];
    for (from, to) in map {
        if flags & from != 0 { out |= to; }
    }
    out
}

/// Fields a lookup asks for: everything a `stat(2)` needs, plus the generation
/// counter that distinguishes a reused inode number from the same object.
pub const LOOKUP_MASK: u64 = stats::BASIC | stats::GEN;

/// What a mount needs to know before it can build an inode from a server's
/// answer, so the inode-building path takes no mount-policy decisions itself.
#[derive(Clone, Copy, Debug)]
pub struct AttrPolicy {
    /// Refuse to materialise device, socket and fifo classes.
    pub nodev: bool,
    /// Owner reported for an object whose server named no numeric one.
    pub dfltuid: u32,
    /// Group counterpart of `dfltuid`.
    pub dfltgid: u32,
}

/// The inode fields one `Rgetattr` establishes.
#[derive(Clone, Copy, Debug)]
pub struct InodeFacts {
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub rdev: u32,
    pub size: u64,
    pub blocks: u64,
    pub atime: Timespec64,
    pub mtime: Timespec64,
    pub ctime: Timespec64,
}

/// Resolve a server attribute reply into inode fields under `policy`.
///
/// A field the server did NOT populate is left at the mount default rather than
/// taken as zero: an unpopulated `MODE` read as zero yields a file nobody can
/// open, and an unpopulated `UID` read as zero attributes the object to root.
/// # C: O(1)
pub fn facts_from_stat(q: &Qid, st: &StatDotl, policy: AttrPolicy) -> InodeFacts {
    let mode = if st.has(stats::MODE) {
        apply_nodev(st.mode, policy.nodev)
    } else {
        // Nothing was reported; the qid still tells us the class, and a
        // conservative permission set is better than an unopenable zero.
        match qid_file_type(q) {
            FileType::Directory => ifmt::DIR | 0o555,
            FileType::Symlink => ifmt::LNK | 0o777,
            _ => ifmt::REG | 0o444,
        }
    };
    InodeFacts {
        ino: qid_to_ino(q),
        mode,
        uid: if st.has(stats::UID) { st.uid } else { policy.dfltuid },
        gid: if st.has(stats::GID) { st.gid } else { policy.dfltgid },
        nlink: if st.has(stats::NLINK) { st.nlink.min(u64::from(u32::MAX)) as u32 } else { 1 },
        rdev: if st.has(stats::RDEV) { st.rdev.min(u64::from(u32::MAX)) as u32 } else { 0 },
        size: if st.has(stats::SIZE) { st.size } else { 0 },
        blocks: if st.has(stats::BLOCKS) { st.blocks } else { 0 },
        atime: attr_time(st.atime_sec, st.atime_nsec),
        mtime: attr_time(st.mtime_sec, st.mtime_nsec),
        ctime: attr_time(st.ctime_sec, st.ctime_nsec),
    }
}
