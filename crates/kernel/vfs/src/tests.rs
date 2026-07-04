// Hosted tests for the VFS foundation. Per `16§9` test contract: path
// resolution + cache shape + FD lifecycle. Cache impl + symlink +
// mount + RESOLVE_BENEATH ride in follow-up PRs.

extern crate alloc;
use super::*;
use crate::dentry::Dentry;
use crate::fdtable::FdTable;
use crate::file::{File, SeekFrom};
use crate::inode::{Inode, InodeRef};
use crate::path::{components, is_absolute, lexical_normalize, Component};
use crate::types::{FileType, OpenFlags, VfsError};

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use sync::{RwLock, Inode as InodeClass};

mod dentry_paths;
mod file_fd;

// ---------------------------------------------------------------------------
// In-memory test inode — minimal Regular + Directory inodes for the FS surface
// ---------------------------------------------------------------------------

// Per-inode backing state (the old `MemFile` fields), stored in `i_private`.
struct MemFileData {
    body: RwLock<Vec<u8>, InodeClass>,
}

// Data-path ops for the in-memory file. Reads/writes the byte buffer off
// `i_private` and keeps `i_size` in sync (the concrete inode owns its size).
struct MemFileOps;
impl FileOps for MemFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<MemFileData>().unwrap();
        let body = d.body.read();
        if off >= body.len() as u64 { return Ok(0); }
        let start = off as usize;
        let avail = body.len() - start;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&body[start..start + n]);
        Ok(n)
    }
    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<MemFileData>().unwrap();
        let mut body = d.body.write();
        let end = off as usize + buf.len();
        if body.len() < end { body.resize(end, 0); }
        body[off as usize..end].copy_from_slice(buf);
        inode.set_size(body.len() as u64);
        Ok(buf.len())
    }
}

// Namespace facade over the old `MemFile` ZST: `MemFile::new(ino)` now stamps
// the concrete `Inode` (Regular, MemFileOps data path, default i_op).
struct MemFile;
impl MemFile {
    fn new(ino: u64) -> InodeRef {
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(MemFileOps))
            .private(Arc::new(MemFileData { body: RwLock::new(Vec::new()) }))
            .build()
    }
}

// ---------------------------------------------------------------------------
// Path component splitting
// ---------------------------------------------------------------------------

#[test]
fn components_root_only() {
    assert_eq!(components("/"), [Component::Root]);
}

#[test]
fn components_simple_absolute() {
    assert_eq!(
        components("/a/b/c"),
        [Component::Root, Component::Normal("a"), Component::Normal("b"), Component::Normal("c")]
    );
}

#[test]
fn components_collapses_repeated_slashes() {
    assert_eq!(
        components("/a//b///c/"),
        [Component::Root, Component::Normal("a"), Component::Normal("b"), Component::Normal("c")]
    );
}

#[test]
fn components_skips_dots_and_keeps_dotdots() {
    assert_eq!(
        components("./a/./b/../c"),
        [Component::Normal("a"), Component::Normal("b"), Component::ParentDir, Component::Normal("c")]
    );
}

#[test]
fn components_relative_path() {
    assert_eq!(
        components("a/b"),
        [Component::Normal("a"), Component::Normal("b")]
    );
}

#[test]
fn is_absolute_distinguishes() {
    assert!(is_absolute("/"));
    assert!(is_absolute("/foo"));
    assert!(!is_absolute("foo"));
    assert!(!is_absolute(""));
}

#[test]
fn lexical_normalize_resolves_dotdot() {
    assert_eq!(lexical_normalize("/a/b/../c").as_deref(), Some("/a/c"));
    assert_eq!(lexical_normalize("/a/./b").as_deref(),    Some("/a/b"));
    assert_eq!(lexical_normalize("a/b/../c").as_deref(),  Some("a/c"));
    assert_eq!(lexical_normalize("/").as_deref(),          Some("/"));
    assert_eq!(lexical_normalize("a/..").as_deref(),       Some("."));
}

#[test]
fn lexical_normalize_clamps_dotdot_at_absolute_root() {
    assert_eq!(lexical_normalize("/..").as_deref(), Some("/"));
    assert_eq!(lexical_normalize("/a/../..").as_deref(), Some("/"));
    assert_eq!(lexical_normalize("/../../a").as_deref(), Some("/a"));
}

// ---------------------------------------------------------------------------
// fd-link / dup-fd parsing (T8 — /dev/std*, /dev/fd/N, /proc/<pid>/fd/N).
// The Linux magic-fd-link open/readlink/reopen contract: these paths
// resolve by duplicating an existing open file description, NOT by a
// normal path walk. Locks the parsing so the console/serial fd plumbing
// can't silently regress (the `/dev/stdout`→fd 1 reopen path).
// ---------------------------------------------------------------------------

#[test]
fn dup_fd_target_std_streams() {
    use crate::path::dup_fd_target;
    assert_eq!(dup_fd_target("/dev/stdin"),  Some((None, 0)));
    assert_eq!(dup_fd_target("/dev/stdout"), Some((None, 1)));
    assert_eq!(dup_fd_target("/dev/stderr"), Some((None, 2)));
}

#[test]
fn dup_fd_target_dev_fd_n() {
    use crate::path::dup_fd_target;
    assert_eq!(dup_fd_target("/dev/fd/0"),  Some((None, 0)));
    assert_eq!(dup_fd_target("/dev/fd/1"),  Some((None, 1)));
    assert_eq!(dup_fd_target("/dev/fd/42"), Some((None, 42)));
    // Not a valid fd number → not an fd-link (resolve normally).
    assert_eq!(dup_fd_target("/dev/fd/abc"), None);
}

#[test]
fn dup_fd_target_proc_self_and_pid_fd() {
    use crate::path::{dup_fd_target, parse_proc_fd};
    assert_eq!(dup_fd_target("/proc/self/fd/0"), Some((None, 0)));
    assert_eq!(dup_fd_target("/proc/self/fd/2"), Some((None, 2)));
    assert_eq!(dup_fd_target("/proc/1/fd/1"),    Some((Some(1), 1)));
    assert_eq!(parse_proc_fd("/proc/123/fd/7"),  Some((Some(123), 7)));
    // The /proc/self/fd dir itself (no <n>) is not an fd-link target.
    assert_eq!(parse_proc_fd("/proc/self/fd"), None);
}

#[test]
fn dup_fd_target_execve_magic_fd_forms() {
    // execve("/proc/self/fd/N") and execveat(fd,"",AT_EMPTY_PATH) (the
    // latter synthesises "/proc/self/fd/<dirfd>") both route through
    // dup_fd_target so the exec loader reads the OPEN file description's
    // backing inode — the only way a sealed memfd (whose d_path can't be
    // re-resolved) is exec-able, matching Linux do_execveat_common.
    use crate::path::dup_fd_target;
    // The exact strings execve / execveat hand the loader.
    assert_eq!(dup_fd_target("/proc/self/fd/3"),  Some((None, 3)));
    assert_eq!(dup_fd_target("/proc/self/fd/17"), Some((None, 17)));
    assert_eq!(dup_fd_target("/dev/fd/3"),        Some((None, 3)));
    // Per-pid form (/proc/<pid>/fd/<n>) is exec-able too.
    assert_eq!(dup_fd_target("/proc/42/fd/3"),    Some((Some(42), 3)));
}

#[test]
fn dup_fd_target_rejects_non_fd_links() {
    use crate::path::dup_fd_target;
    // Real device + regular paths must resolve via the normal walk.
    assert_eq!(dup_fd_target("/dev/console"), None);
    assert_eq!(dup_fd_target("/dev/tty"),     None);
    assert_eq!(dup_fd_target("/etc/passwd"),  None);
    assert_eq!(dup_fd_target("/proc/self/status"), None);
}

// ---------------------------------------------------------------------------
// Dentry
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// dirent64 packing — `19§4` Linux ABI byte layout
// ---------------------------------------------------------------------------

#[test]
fn dirent64_reclen_pads_to_8_bytes() {
    // header(19) + name + NUL, padded to multiple of 8.
    assert_eq!(crate::dirent::dirent64_reclen(0),  24);  // 19+1=20 → 24
    assert_eq!(crate::dirent::dirent64_reclen(1),  24);  // 19+2=21 → 24
    assert_eq!(crate::dirent::dirent64_reclen(4),  24);  // 19+5=24 → 24
    assert_eq!(crate::dirent::dirent64_reclen(5),  32);  // 19+6=25 → 32
    assert_eq!(crate::dirent::dirent64_reclen(13), 40);  // 19+14=33 → 40
}

#[test]
fn dirent64_pack_layout_matches_linux_abi() {
    let mut buf = [0xAAu8; 64];
    let n = crate::dirent::dirent64_pack(&mut buf, 0x1122_3344_5566_7788, 0x42, 8, b"foo")
        .unwrap();
    assert_eq!(n, 24);
    // d_ino LE
    assert_eq!(&buf[0..8], &0x1122_3344_5566_7788u64.to_le_bytes());
    // d_off LE
    assert_eq!(&buf[8..16], &0x42u64.to_le_bytes());
    // d_reclen LE u16
    assert_eq!(&buf[16..18], &24u16.to_le_bytes());
    // d_type
    assert_eq!(buf[18], 8);
    // name + NUL pad
    assert_eq!(&buf[19..22], b"foo");
    assert_eq!(&buf[22..24], &[0, 0]);
}

#[test]
fn dirent64_pack_returns_none_when_buf_too_small() {
    let mut buf = [0u8; 8];
    assert_eq!(crate::dirent::dirent64_pack(&mut buf, 0, 0, 8, b"x"), None);
}

#[test]
fn dirent64_pack_many_stops_at_first_overflow() {
    let mut buf = [0u8; 48]; // exactly 2 records with name "x" (24 each)
    let names = [b"a".as_slice(), b"b", b"c"];
    let n = crate::dirent::dirent64_pack_many(
        &mut buf,
        names.iter().enumerate(),
        |(i, name)| (i as u64, (i + 1) as u64, 8, name.to_vec()),
    );
    assert_eq!(n, 48);
    // First record d_off (cookie) = 1, second = 2.
    assert_eq!(&buf[8..16], &1u64.to_le_bytes());
    assert_eq!(&buf[24+8..24+16], &2u64.to_le_bytes());
}

// ---------------------------------------------------------------------------
// legacy linux_dirent packing (getdents(2), NR 78) — distinct from dirent64
// ---------------------------------------------------------------------------

#[test]
fn dirent_legacy_reclen_pads_to_8_bytes() {
    // header(18) + name + NUL + d_type byte, padded to multiple of 8.
    assert_eq!(crate::dirent::dirent_reclen(0),  24); // 18+0+2=20 → 24
    assert_eq!(crate::dirent::dirent_reclen(3),  24); // 18+3+2=23 → 24
    assert_eq!(crate::dirent::dirent_reclen(4),  24); // 18+4+2=24 → 24
    assert_eq!(crate::dirent::dirent_reclen(5),  32); // 18+5+2=25 → 32
    assert_eq!(crate::dirent::dirent_reclen(13), 40); // 18+13+2=33 → 40
}

#[test]
fn dirent_legacy_pack_layout_matches_linux_abi() {
    let mut buf = [0xAAu8; 64];
    let n = crate::dirent::dirent_pack(&mut buf, 0x1122_3344_5566_7788, 0x42, 8, b"foo")
        .unwrap();
    assert_eq!(n, 24);
    assert_eq!(&buf[0..8],  &0x1122_3344_5566_7788u64.to_le_bytes()); // d_ino
    assert_eq!(&buf[8..16], &0x42u64.to_le_bytes());                  // d_off
    assert_eq!(&buf[16..18], &24u16.to_le_bytes());                   // d_reclen
    assert_eq!(&buf[18..21], b"foo");                                 // d_name @18
    assert_eq!(buf[21], 0);                                           // NUL term
    // zero padding between NUL and the trailing d_type byte
    assert_eq!(&buf[22..23], &[0]);
    // d_type lives in the LAST byte of the record (legacy ABI wart).
    assert_eq!(buf[n - 1], 8);
}

#[test]
fn dirent_legacy_pack_returns_none_when_buf_too_small() {
    // The handler relies on this None → first-record-overflow → EINVAL.
    let mut buf = [0u8; 8];
    assert_eq!(crate::dirent::dirent_pack(&mut buf, 0, 0, 8, b"x"), None);
}

// ---------------------------------------------------------------------------
// byte-wise (non-UTF-8) path handling — Linux paths are opaque byte strings
// ---------------------------------------------------------------------------

#[test]
fn path_from_bytes_keeps_valid_utf8_verbatim() {
    assert_eq!(crate::path::path_from_bytes(b"/etc/passwd"), "/etc/passwd");
    // multi-byte UTF-8 stays intact and round-trips.
    let s = crate::path::path_from_bytes("/café".as_bytes());
    assert_eq!(crate::path::path_into_bytes(&s), "/café".as_bytes());
}

#[test]
fn path_from_bytes_roundtrips_non_utf8() {
    let raw = b"file\xff\xfename";
    let s = crate::path::path_from_bytes(raw);
    assert_eq!(crate::path::path_into_bytes(&s), raw);
}

// ---------------------------------------------------------------------------
// RENAME_EXCHANGE / RENAME_WHITEOUT + non-UTF-8 resolution against a mock FS
// ---------------------------------------------------------------------------

use alloc::collections::BTreeMap;

/// Single-level directory inode storing byte-exact entry names. Lookups
/// decode the escaped `&str` back to its on-disk bytes, exercising the
/// byte-wise resolution contract.
struct TestDir {
    ino:  u64,
    ents: RwLock<BTreeMap<Vec<u8>, (u64, FileType, u32)>, InodeClass>,
}

impl TestDir {
    fn new() -> Arc<Self> {
        Arc::new(Self { ino: 1, ents: RwLock::new(BTreeMap::new()) })
    }
    fn insert(&self, name: &[u8], ino: u64, ft: FileType, rdev: u32) {
        self.ents.write().insert(name.to_vec(), (ino, ft, rdev));
    }
    fn get(&self, name: &[u8]) -> Option<(u64, FileType, u32)> {
        self.ents.read().get(name).copied()
    }
    // Build the concrete directory inode backed by this `TestDir` (stored as
    // `i_private`; `TestDirOps` reads it back via `inode.private::<TestDir>()`).
    fn inode(self: &Arc<Self>) -> InodeRef {
        InodeBuilder::new(self.ino, mk_mode(FileType::Directory, 0o755),
            Arc::new(TestDirOps), default_file_ops())
            .private(self.clone())
            .build()
    }
}

struct TestDirOps;
impl InodeOps for TestDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<TestDir>().unwrap();
        let key = crate::path::path_into_bytes(name);
        match d.ents.read().get(&key) {
            Some(&(ino, _, _)) => { let r: InodeRef = MemFile::new(ino); Ok(r) }
            None => Err(VfsError::Enoent),
        }
    }
    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, _ctx: &crate::CreateCtx) -> KResult<()> {
        let d = inode.private::<TestDir>().unwrap();
        let key = crate::path::path_into_bytes(name);
        let ft = match mode & 0xF000 {
            0x2000 => FileType::CharDev,
            0x6000 => FileType::BlockDev,
            0x1000 => FileType::Fifo,
            0xC000 => FileType::Socket,
            _      => FileType::Regular,
        };
        d.ents.write().insert(key, (0, ft, rdev));
        Ok(())
    }
}

struct TestFs { dir: Arc<TestDir> }

impl crate::fs::FileSystem for TestFs {
    fn name(&self) -> &str { "testfs" }
    fn root(&self) -> Option<InodeRef> { Some(self.dir.inode()) }
    fn rename(&self, from: &str, to: &str) -> KResult<()> {
        let fk = crate::path::path_into_bytes(from);
        let tk = crate::path::path_into_bytes(to);
        let mut e = self.dir.ents.write();
        let v = e.remove(&fk).ok_or(VfsError::Enoent)?;
        e.insert(tk, v);
        Ok(())
    }
}

#[test]
fn rename_exchange_swaps_two_files() {
    use crate::fs::FileSystem;
    let fs = TestFs { dir: TestDir::new() };
    fs.dir.insert(b"a", 11, FileType::Regular, 0);
    fs.dir.insert(b"b", 22, FileType::Regular, 0);
    fs.exchange("a", "b").unwrap();
    assert_eq!(fs.dir.get(b"a").unwrap().0, 22);
    assert_eq!(fs.dir.get(b"b").unwrap().0, 11);
    assert_eq!(fs.dir.ents.read().len(), 2); // temp name cleaned up
}

#[test]
fn rename_exchange_missing_side_is_enoent() {
    use crate::fs::FileSystem;
    let fs = TestFs { dir: TestDir::new() };
    fs.dir.insert(b"a", 11, FileType::Regular, 0);
    assert_eq!(fs.exchange("a", "nope"), Err(VfsError::Enoent));
}

#[test]
fn rename_whiteout_plants_chardev_at_source() {
    use crate::fs::FileSystem;
    let fs = TestFs { dir: TestDir::new() };
    fs.dir.insert(b"src", 11, FileType::Regular, 0);
    fs.whiteout("src", "dst").unwrap();
    assert_eq!(fs.dir.get(b"dst").unwrap().0, 11); // file moved to dest
    let (_, ft, rdev) = fs.dir.get(b"src").unwrap();
    assert_eq!(ft, FileType::CharDev);             // whiteout = char dev
    assert_eq!(rdev, 0);                           //          rdev 0/0
}

#[test]
fn non_utf8_filename_resolves_and_stats() {
    use crate::fs::FileSystem;
    let fs = TestFs { dir: TestDir::new() };
    let name = b"caf\xe9"; // trailing 0xE9 — invalid UTF-8
    fs.dir.insert(name, 77, FileType::Regular, 0);
    // userspace handed these raw bytes; decode as read_user_path does.
    let path = crate::path::path_from_bytes(name);
    let ino = fs.lookup_path(&path).expect("non-utf8 name resolves");
    assert_eq!(ino.ino(), 77); // stat reads the resolved inode number
}

// Touch the warning-silencer.
#[allow(dead_code)]
fn _unused_silence() {
    let _: AtomicU64 = AtomicU64::new(0);
    let _ = Ordering::Relaxed;
}

#[test]
fn resolve_against_cwd_passthrough_absolute() {
    use crate::path::resolve_against_cwd;
    assert_eq!(resolve_against_cwd("/tmp", "/etc/passwd").as_deref(), Some("/etc/passwd"));
    assert_eq!(resolve_against_cwd("/foo", "/").as_deref(), Some("/"));
}

#[test]
fn resolve_against_cwd_joins_relative() {
    use crate::path::resolve_against_cwd;
    assert_eq!(resolve_against_cwd("/tmp", "x").as_deref(),     Some("/tmp/x"));
    assert_eq!(resolve_against_cwd("/tmp", "./x").as_deref(),   Some("/tmp/x"));
    assert_eq!(resolve_against_cwd("/tmp/", "x").as_deref(),    Some("/tmp/x"));
    assert_eq!(resolve_against_cwd("/", "etc/passwd").as_deref(), Some("/etc/passwd"));
}

#[test]
fn resolve_against_cwd_handles_dotdot() {
    use crate::path::resolve_against_cwd;
    assert_eq!(resolve_against_cwd("/tmp/sub", "../x").as_deref(), Some("/tmp/x"));
    assert_eq!(resolve_against_cwd("/tmp", "..").as_deref(),       Some("/"));
    assert_eq!(resolve_against_cwd("/", "..").as_deref(), Some("/"));
}

#[test]
fn inode_default_truncate_returns_erofs() {
    // MemFile doesn't override truncate → uses the trait default.
    let i = MemFile::new(1);
    assert_eq!(i.truncate(0), Err(VfsError::Erofs));
}

#[test]
fn trim_hostname_strips_trailing_newline_and_nul() {
    use crate::path::trim_hostname;
    assert_eq!(trim_hostname(b"host\n",  64), b"host");
    assert_eq!(trim_hostname(b"host\0",  64), b"host");
    assert_eq!(trim_hostname(b"host\n\0", 64), b"host");
    assert_eq!(trim_hostname(b"plain",   64), b"plain");
}

#[test]
fn trim_hostname_clamps_to_max() {
    use crate::path::trim_hostname;
    let long = b"abcdefghij";
    assert_eq!(trim_hostname(long, 4), b"abcd");
}

#[test]
fn trim_hostname_empty_stays_empty() {
    use crate::path::trim_hostname;
    assert_eq!(trim_hostname(b"",       64), b"");
    assert_eq!(trim_hostname(b"\n",     64), b"");
    assert_eq!(trim_hostname(b"\n\n\0", 64), b"");
}
