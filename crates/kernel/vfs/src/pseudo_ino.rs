//! The single owner of pseudo-inode number space.
//!
//! A pseudo-filesystem that mints its own inode numbers used to declare a
//! private `INO_BASE` next to the code that mints from it. Nothing compared
//! those bases, so two subsystems picked the same one: epoll and evdev both
//! took `0x7400_0000`, and `/dev/input/event0` decoded as a live epoll
//! instance — every evdev ioctl was answered EINVAL by the epoll handler and
//! `epoll_ctl` mutated an unrelated instance. Every base now lives in this one
//! table and [`REGIONS_ARE_DISJOINT`] fails the build if two overlap.
//!
//! A region reserves a range of NUMBERS. It is not an identity test: two
//! filesystems may legitimately carry the same `st_ino` because `st_dev`
//! separates them, and an inode number is never proof of who owns an inode.
//! Identity comes from the state the inode owns (`i_private`), the way Linux
//! compares a file's `f_op` against the one ops vector its subsystem installs.
//! Regions exist so that a NUMBER minted by one owner cannot silently become
//! another owner's number, and so that a counter-based minter has a stated
//! bound instead of running into its neighbour.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::types::Ino;

/// One owner's reserved inode-number range, `start..=end`. # C: O(1)
pub struct Region {
    name:  &'static str,
    start: Ino,
    end:   Ino,
}

impl Region {
    /// Declare a region. `end` is inclusive. # C: O(1)
    pub const fn new(name: &'static str, start: Ino, end: Ino) -> Self { Self { name, start, end } }
    /// Owner name, for diagnostics. # C: O(1)
    pub const fn name(&self) -> &'static str { self.name }
    /// First number in the region. # C: O(1)
    pub const fn start(&self) -> Ino { self.start }
    /// Last number in the region (inclusive). # C: O(1)
    pub const fn end(&self) -> Ino { self.end }
    /// Count of numbers the region reserves. # C: O(1)
    pub const fn len(&self) -> u64 { self.end - self.start + 1 }
    /// Whether `ino` falls inside this region. Answers a NUMBERING question,
    /// never an ownership one — see the module note. # C: O(1)
    pub const fn contains(&self, ino: Ino) -> bool { ino >= self.start && ino <= self.end }
    /// `start | (n % len)` — an offset folded into the region, so a caller
    /// deriving a number from an index can never leave its own range. # C: O(1)
    pub const fn at(&self, n: u64) -> Ino { self.start + n % self.len() }
}

// ---------------------------------------------------------------------------
// Low space: inode numbers whose high 32 bits are zero.
// ---------------------------------------------------------------------------

/// `/dev/console`, `/dev/tty`, `/dev/tty0`, `/dev/tty1..63`, `/dev/ttyS0`.
pub const CONSOLE_TTY: Region = Region::new("console-tty", 0x0000_7400, 0x0000_74FF);
/// `/dev/vcs*`.
pub const CONSOLE_VCS: Region = Region::new("console-vcs", 0x0000_7600, 0x0000_76FF);
/// `/dev/vcsa*`.
pub const CONSOLE_VCSA: Region = Region::new("console-vcsa", 0x0000_7700, 0x0000_77FF);
/// autofs filesystem roots.
pub const AUTOFS_ROOT: Region = Region::new("autofs-root", 0x0187_0000, 0x0187_0FFF);
/// `/dev/autofs` control node, keyed by the misc device number. A separate
/// region from [`AUTOFS_ROOT`]: folding a device number into one shared band
/// would let the control node land on a root's number.
pub const AUTOFS_CONTROL: Region = Region::new("autofs-control", 0x0187_1000, 0x0187_1FFF);
/// `get_next_ino()` — the shared counter for anon inodes with no family of
/// their own (pidfd, POSIX message queues, the io_uring low half).
pub const VFS_ANON: Region = Region::new("vfs-anon", 0x0200_0000, 0x02FF_FFFF);
/// `pipe(2)` / `mkfifo` pseudo-inodes.
pub const PIPE: Region = Region::new("pipe", 0x1000_0000, 0x1FFF_FFFF);
/// procfs entries with a fixed identity (`/proc/meminfo`, `/proc/self/status`).
pub const PROCFS_STATIC: Region = Region::new("procfs-static", 0x3000_0000, 0x30FF_FFFF);
/// `make_static_file_inode` — fixed-body files, most of them procfs's, minted
/// from a counter onto the same `s_dev` as [`PROCFS_STATIC`]'s fixed ids.
pub const VFS_STATIC_FILE: Region = Region::new("vfs-static-file", 0x3100_0000, 0x36FF_FFFF);
/// tracefs ring-buffer files.
pub const TRACEFS_RING: Region = Region::new("tracefs-ring", 0x3700_0000, 0x37FF_FFFF);
/// procfs entries minted from a counter at runtime.
pub const PROCFS_DYNAMIC: Region = Region::new("procfs-dynamic", 0x3800_0000, 0x3FFF_FFFF);
/// tmpfs, `/dev/shm`, and every other in-memory filesystem instance.
pub const TMPFS: Region = Region::new("tmpfs", 0x4000_0000, 0x4FFF_FFFF);
/// `/proc/sys/fs/binfmt_misc` entries. Moved off `0x4249_0000`, inside the span
/// [`TMPFS`]'s counter walks.
pub const BINFMT_MISC: Region = Region::new("binfmt-misc", 0x5000_0000, 0x5000_FFFF);
/// `eventfd(2)`. Moved off `0x4000_0000`, which [`TMPFS`] also claimed.
pub const EVENTFD: Region = Region::new("eventfd", 0x5100_0000, 0x51FF_FFFF);
/// cgroup2 directories, one per cgroup id.
pub const CGROUP_DIR: Region = Region::new("cgroup-dir", 0x6000_0000, 0x60FF_FFFF);
/// cgroup2 control files, `(cgid, file-slot)`.
pub const CGROUP_FILE: Region = Region::new("cgroup-file", 0x6100_0000, 0x68FF_FFFF);
/// devpts: both PTY halves plus the two `ptmx` nodes. Moved off `0x6000_0000`,
/// which [`CGROUP_DIR`] also claimed — a cgroup directory inode with a small
/// cgroup id decoded as a PTY master.
pub const DEVPTS: Region = Region::new("devpts", 0x6900_0000, 0x6900_FFFF);
/// configfs items, groups and attributes.
pub const CONFIGFS: Region = Region::new("configfs", 0x6C00_0000, 0x6CFF_FFFF);
/// debugfs files and directories.
pub const DEBUGFS: Region = Region::new("debugfs", 0x6D00_0000, 0x6D0F_FFFF);
/// debugfs automount points.
pub const DEBUGFS_AUTOMOUNT: Region = Region::new("debugfs-automount", 0x6D10_0000, 0x6D1F_FFFF);
/// `inotify_init(2)`.
pub const INOTIFY: Region = Region::new("inotify", 0x7100_0000, 0x71FF_FFFF);
/// `signalfd(2)`.
pub const SIGNALFD: Region = Region::new("signalfd", 0x7200_0000, 0x72FF_FFFF);
/// `timerfd_create(2)`.
pub const TIMERFD: Region = Region::new("timerfd", 0x7300_0000, 0x73FF_FFFF);
/// `epoll_create(2)`.
pub const EPOLL: Region = Region::new("epoll", 0x7400_0000, 0x74FF_FFFF);
/// bpf objects pinned to an fd (prog, map, link, BTF, token). Moved off
/// `0x7300_0000`, which [`TIMERFD`] also claimed.
pub const BPF: Region = Region::new("bpf", 0x7500_0000, 0x7500_FFFF);
/// `/dev/input/eventN`. Moved off `0x7400_0000`, which [`EPOLL`] also claimed.
pub const EVDEV: Region = Region::new("evdev", 0x7600_0000, 0x7600_FFFF);
/// hugetlbfs instances, including the kernel-private mounts
/// `memfd_create(MFD_HUGETLB)` and `mmap(MAP_HUGETLB)` build their files on.
/// A band of its own rather than a share of [`TMPFS`]: the two filesystems mint
/// numbers from independent counters, so one shared range would collide.
pub const HUGETLBFS: Region = Region::new("hugetlbfs", 0x7700_0000, 0x77FF_FFFF);
/// zram's debugfs device directories and their block-state files.
pub const ZRAM_DEBUGFS: Region = Region::new("zram-debugfs", 0x7A72_0000, 0x7A72_FFFF);
/// `/dev/fbN`.
pub const FBDEV: Region = Region::new("fbdev", 0xFB00_0000, 0xFB00_FFFF);
/// procfs `/proc/net/*` entries with a fixed identity.
pub const PROCFS_NET: Region = Region::new("procfs-net", 0xFEED_0000, 0xFEED_FFFF);

// ---------------------------------------------------------------------------
// Tag families: a four-byte tag in the high 32 bits, the owner's own id in the
// low 32. `st_ino` is 64-bit, so a family that needs a full 32-bit id of its
// own (a real ext4 inode number, a socket identity) takes a whole tag.
// ---------------------------------------------------------------------------

/// Build the region one high-32 `tag` reserves. # C: O(1)
const fn tag_region(name: &'static str, tag: u64) -> Region {
    Region::new(name, tag << 32, (tag << 32) | 0xFFFF_FFFF)
}

/// Per-pid/per-tid procfs files: `0x3000_0000 | kind` in the high 32.
pub const PROCFS_PID: Region = Region::new("procfs-pid", 0x3000_0000 << 32,
    (0x3000_00FF << 32) | 0xFFFF_FFFF);
/// `/dev/dri/cardN`.
pub const DRM_CARD: Region = tag_region("drm-card", 0x4452_4D43);
/// `/dev/dri/renderDN`.
pub const DRM_RENDER: Region = tag_region("drm-render", 0x4452_4D52);
/// `io_uring_setup(2)` rings.
pub const IO_URING: Region = tag_region("io-uring", 0x494F_5552);
/// `AF_NETLINK` sockets.
pub const NETLINK: Region = tag_region("netlink", 0x4E4C_534B);
/// `perf_event_open(2)`.
pub const PERF: Region = tag_region("perf", 0x5045_5246);
/// `AF_INET`/`AF_INET6`/`AF_UNIX`/`AF_PACKET` sockets.
pub const INET_SOCK: Region = tag_region("inet-sock", 0x534F_434B);
/// `/dev/snd/*` and the OSS aliases.
pub const SOUND: Region = tag_region("sound", 0x536E_6400);
/// The pstore mount root and the record files under it.
pub const PSTORE: Region = tag_region("pstore", 0x5053_5452);
/// `userfaultfd(2)`.
pub const USERFAULTFD: Region = tag_region("userfaultfd", 0x5546_4644);
/// `AF_VSOCK` sockets.
pub const VSOCK: Region = tag_region("vsock", 0x5653_4F43);
/// ext4: the low 32 bits carry a full on-disk inode number.
pub const EXT4: Region = tag_region("ext4", 0x6E54_0000);

/// Every declared region. Adding an owner means adding it here — that is what
/// subjects it to the overlap check. # C: O(1)
pub const REGIONS: &[Region] = &[
    CONSOLE_TTY, CONSOLE_VCS, CONSOLE_VCSA, AUTOFS_ROOT, AUTOFS_CONTROL, VFS_ANON, PIPE,
    PROCFS_STATIC, VFS_STATIC_FILE, TRACEFS_RING, PROCFS_DYNAMIC, TMPFS,
    BINFMT_MISC, EVENTFD, CGROUP_DIR, CGROUP_FILE,
    DEVPTS, CONFIGFS, DEBUGFS, DEBUGFS_AUTOMOUNT, INOTIFY, SIGNALFD, TIMERFD,
    EPOLL, BPF, EVDEV, ZRAM_DEBUGFS, FBDEV, PROCFS_NET,
    PROCFS_PID, DRM_CARD, DRM_RENDER, IO_URING, NETLINK, PERF, INET_SOCK, SOUND,
    PSTORE, USERFAULTFD, VSOCK, EXT4,
];

/// Whether `a` and `b` reserve any number in common. # C: O(1)
pub const fn overlaps(a: &Region, b: &Region) -> bool { a.start <= b.end && b.start <= a.end }

/// Whether no two regions in `rs` overlap and none is empty. # C: O(N²)
pub const fn all_disjoint(rs: &[Region]) -> bool {
    let mut i = 0;
    while i < rs.len() {
        if rs[i].start > rs[i].end { return false; }
        let mut j = i + 1;
        while j < rs.len() {
            if overlaps(&rs[i], &rs[j]) { return false; }
            j += 1;
        }
        i += 1;
    }
    true
}

/// Compile-time proof that no owner can mint into another owner's range. A new
/// `Region` that collides with a declared one fails the build here rather than
/// at the far end of a misresolved ioctl. # C: O(1)
pub const REGIONS_ARE_DISJOINT: bool = all_disjoint(REGIONS);
const _: () = assert!(REGIONS_ARE_DISJOINT, "two pseudo-inode regions overlap");

/// A counter that mints inode numbers inside one region and cannot leave it.
/// A bare `AtomicU64` seeded with a base runs into whatever was declared above
/// it once enough objects have been created.
pub struct RegionAllocator {
    region: &'static Region,
    next:   AtomicU64,
}

impl RegionAllocator {
    /// Mint from `region`, starting at its first number. # C: O(1)
    pub const fn new(region: &'static Region) -> Self {
        Self { region, next: AtomicU64::new(0) }
    }
    /// Next number in the region, wrapping within it. # C: O(1)
    pub fn alloc(&self) -> Ino {
        self.region.at(self.next.fetch_add(1, Ordering::Relaxed))
    }
    /// The region this allocator draws from. # C: O(1)
    pub fn region(&self) -> &'static Region { self.region }
}

#[cfg(test)]
#[path = "pseudo_ino/tests.rs"]
mod tests;
