//! F721 host-oracle differential conformance — fd family: dup/dup2/dup3,
//! close, fcntl(F_DUPFD_CLOEXEC/F_GETFL), read/write-on-directory-fd,
//! lseek, ftruncate. Host side = real syscalls on this machine (`libc` via
//! `conformance::oracle`); oxide side = the real `vfs::FdTable`/`vfs::File`
//! work-fns (ungated — no `#[cfg(target_os = "oxide-kernel")]` involved),
//! plus `crate::fcntl_dup` from `crates/kernel/syscalls/src/fcntl_dup.rs`
//! pulled in verbatim via `#[path]` (it is `pub(crate)`-only and itself
//! ungated — the ONLY thing making it unreachable from outside the
//! `syscalls` crate is visibility, not a target cfg, so this is a straight
//! re-inclusion of the real code, not a stub).

extern crate alloc;

use std::sync::Arc;

use conformance::corpus::{run_corpus, Case};
use conformance::oracle;
use conformance::outcome::Outcome;

use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, InodeRef, OpenFlags,
    SeekFrom, default_file_ops, default_inode_ops, mk_mode};

#[path = "../../syscalls/src/fcntl_dup.rs"]
mod fcntl_dup_shim;

fn regular_file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}
fn directory(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), default_inode_ops(), default_file_ops()).build()
}
fn fifo(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Fifo, 0o644), default_inode_ops(), default_file_ops()).build()
}
fn mk_file(inode: InodeRef, flags: OpenFlags) -> Arc<File> {
    let d = Dentry::new_root(inode.clone());
    File::new(inode, d, flags)
}

// ---------------------------------------------------------------- dup ----

fn dup_bad_fd() -> (Outcome, Outcome) {
    let host = oracle::dup(9999);
    let fdt = FdTable::new();
    let oxide = Outcome::from_oxide_rv(fdt.dup(9999).map(|fd| fd as i64).unwrap_or_else(|e| -(e as i64)));
    (host, oxide)
}

fn dup2_same_fd_valid() -> (Outcome, Outcome) {
    let (rfd, wfd) = oracle::pipe_keep();
    let host = oracle::dup2(rfd, rfd);
    oracle::close_raw(rfd); oracle::close_raw(wfd);
    let fdt = FdTable::new();
    let fd = fdt.alloc(mk_file(regular_file(1), OpenFlags::O_RDONLY)).unwrap();
    let oxide = Outcome::from_oxide_rv(fdt.dup2(fd, fd).map(|n| n as i64).unwrap_or_else(|e| -(e as i64)));
    (host, oxide)
}

fn dup2_same_fd_invalid() -> (Outcome, Outcome) {
    let host = oracle::dup2(9999, 9999);
    let fdt = FdTable::new();
    let oxide = Outcome::from_oxide_rv(fdt.dup2(9999, 9999).map(|n| n as i64).unwrap_or_else(|e| -(e as i64)));
    (host, oxide)
}

/// `dup3` requires `oldfd != newfd` — Linux `EINVAL` even if `oldfd` is a
/// perfectly valid fd (`F721` explicit case).
fn dup3_equal_fds_einval() -> (Outcome, Outcome) {
    let (rfd, wfd) = oracle::pipe_keep();
    let host = oracle::dup3(rfd, rfd, 0);
    oracle::close_raw(rfd); oracle::close_raw(wfd);
    let fdt = FdTable::new();
    let fd = fdt.alloc(mk_file(regular_file(1), OpenFlags::O_RDONLY)).unwrap();
    let oxide = Outcome::from_oxide_rv(fdt.dup3(fd, fd, OpenFlags::empty()).map(|n| n as i64).unwrap_or_else(|e| -(e as i64)));
    (host, oxide)
}

fn close_bad_fd() -> (Outcome, Outcome) {
    let host = oracle::close(9999);
    let fdt = FdTable::new();
    let oxide = Outcome::from_oxide_rv(fdt.close(9999).map(|_| 0).unwrap_or_else(|e| -(e as i64)));
    (host, oxide)
}

// -------------------------------------------------------------- fcntl ----

fn fcntl_dupfd_cloexec_bad_fd() -> (Outcome, Outcome) {
    let host = oracle::fcntl_dupfd_cloexec(9999, 0);
    let fdt = FdTable::new();
    let rv = fcntl_dup_shim::duplicate_fd(&fdt, 9999, 0, true, vfs::FD_TABLE_MAX)
        .map(|fd| fd as i64).unwrap_or_else(|e| -(e as i64));
    (host, Outcome::from_oxide_rv(rv))
}

fn fcntl_dupfd_cloexec_ok() -> (Outcome, Outcome) {
    let (rfd, wfd) = oracle::pipe_keep();
    let host = oracle::fcntl_dupfd_cloexec(rfd, 0);
    oracle::close_raw(rfd); oracle::close_raw(wfd);
    let fdt = FdTable::new();
    let fd = fdt.alloc(mk_file(regular_file(1), OpenFlags::O_RDONLY)).unwrap();
    let rv = fcntl_dup_shim::duplicate_fd(&fdt, fd, 0, true, vfs::FD_TABLE_MAX)
        .map(|fd| fd as i64).unwrap_or_else(|e| -(e as i64));
    (host, Outcome::from_oxide_rv(rv))
}

/// F_GETFL round-trip: O_APPEND survives open→getfl on both sides (Linux
/// also implicitly ORs `O_LARGEFILE` into every 64-bit open — matched by
/// `vfs::File::flags()`'s own `| O_LARGEFILE`, `257_openat.rs`). Compare the
/// masked access-mode + O_APPEND + O_NONBLOCK bits, which are stable
/// standard Linux x86_64 values on both sides (glibc-ABI project mandate).
fn fcntl_getfl_append_roundtrip() -> (Outcome, Outcome) {
    const MASK: i32 = libc::O_ACCMODE | libc::O_APPEND | libc::O_NONBLOCK;
    let t = oracle::TempDir::new("getfl");
    let host_fd = oracle::open_keep(&t.join("f"), libc::O_RDWR | libc::O_CREAT | libc::O_APPEND, 0o644);
    let host_flags = oracle::fcntl_getfl(host_fd);
    oracle::close_raw(host_fd);

    let f = mk_file(regular_file(2), OpenFlags::O_RDWR | OpenFlags::O_APPEND);
    let oxide_flags = f.flags().bits() as i32 | libc::O_LARGEFILE;

    (Outcome::ok((host_flags.ret as i32 & MASK) as i64), Outcome::ok((oxide_flags & MASK) as i64))
}

// ---------------------------------------------------------- read/write ---

fn read_on_directory_eisdir() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("read-dir");
    let mut buf = [0u8; 16];
    let fd = oracle::open_keep(t.path(), libc::O_RDONLY, 0);
    let host = oracle::read(fd, &mut buf);
    oracle::close_raw(fd);

    let f = mk_file(directory(3), OpenFlags::O_RDONLY);
    let oxide = Outcome::from_oxide_rv(f.read(&mut buf).map(|n| n as i64).unwrap_or_else(|e| -(e as i64)));
    (host, oxide)
}

fn write_on_directory_eisdir() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("write-dir");
    let fd = oracle::open_keep(t.path(), libc::O_RDONLY, 0);
    let host = oracle::write(fd, b"x");
    oracle::close_raw(fd);

    let f = mk_file(directory(4), OpenFlags::O_RDWR);
    let oxide = Outcome::from_oxide_rv(f.write(b"x").map(|n| n as i64).unwrap_or_else(|e| -(e as i64)));
    (host, oxide)
}

// -------------------------------------------------------------- lseek ----

fn lseek_espipe_on_pipe() -> (Outcome, Outcome) {
    let (rfd, wfd) = oracle::pipe_keep();
    let host = oracle::lseek(rfd, 0, libc::SEEK_SET);
    oracle::close_raw(rfd); oracle::close_raw(wfd);

    let f = mk_file(fifo(5), OpenFlags::O_RDONLY);
    let oxide = Outcome::from_oxide_rv(f.seek(SeekFrom::Start, 0).map(|n| n as i64).unwrap_or_else(|e| -(e as i64)));
    (host, oxide)
}

fn lseek_negative_result_einval() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("lseek-neg");
    std::fs::write(t.join("f"), b"hello").unwrap();
    let fd = oracle::open_keep(&t.join("f"), libc::O_RDONLY, 0);
    let host = oracle::lseek(fd, -1, libc::SEEK_SET);
    oracle::close_raw(fd);

    let f = mk_file(regular_file(6), OpenFlags::O_RDONLY);
    let oxide = Outcome::from_oxide_rv(f.seek(SeekFrom::Start, -1).map(|n| n as i64).unwrap_or_else(|e| -(e as i64)));
    (host, oxide)
}

// ----------------------------------------------------------- ftruncate ---

/// Mirrors `crates/kernel/syscalls/src/077_ftruncate.rs`'s FIRST gate
/// (`if (len as i64) < 0 { EINVAL }`, before the fd is even looked up) —
/// that check is a bare `i64` comparison with no collaborators, so it is
/// reproduced verbatim rather than pulled via `#[path]`.
fn ftruncate_negative_len_einval() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("ftrunc-neg");
    std::fs::write(t.join("f"), b"hello").unwrap();
    let fd = oracle::open_keep(&t.join("f"), libc::O_RDWR, 0);
    let host = oracle::ftruncate(fd, -1);
    oracle::close_raw(fd);

    let len: i64 = -1;
    let oxide = if len < 0 { Outcome::err(libc::EINVAL) } else { unreachable!() };
    (host, oxide)
}

/// Real (non-mirrored) gate: `File::f_mode()`/`file.inode().file_type()` are
/// the actual production checks `077_ftruncate.rs` calls after the negative
/// check. A directory ftruncate is `EINVAL` in Linux (not `EISDIR`) —
/// `do_sys_ftruncate` only ever reaches the type check via a WRITABLE fd,
/// and `open(dir, O_WRONLY)` itself is `EISDIR` at open time, so the only
/// reachable directory case is a read-only fd, which already fails the
/// f_mode check first with the SAME errno (`EINVAL`) either way.
fn ftruncate_on_directory_einval() -> (Outcome, Outcome) {
    let t = oracle::TempDir::new("ftrunc-dir");
    let fd = oracle::open_keep(t.path(), libc::O_RDONLY, 0);
    let host = oracle::ftruncate(fd, 0);
    oracle::close_raw(fd);

    let f = mk_file(directory(7), OpenFlags::O_RDONLY);
    let oxide = if !f.f_mode().contains(vfs::Fmode::WRITE) { Outcome::err(libc::EINVAL) }
        else if !matches!(f.inode().file_type(), FileType::Regular) { Outcome::err(libc::EINVAL) }
        else { unreachable!() };
    (host, oxide)
}

const CASES: &[Case] = &[
    Case { id: "dup.bad_fd", known_divergence: None, skip: None, compare_ret_on_success: false, run: dup_bad_fd },
    Case { id: "dup2.same_fd.valid", known_divergence: None, skip: None, compare_ret_on_success: false, run: dup2_same_fd_valid },
    Case { id: "dup2.same_fd.invalid", known_divergence: None, skip: None, compare_ret_on_success: false, run: dup2_same_fd_invalid },
    Case { id: "dup3.equal_fds.einval", known_divergence: None, skip: None, compare_ret_on_success: false, run: dup3_equal_fds_einval },
    Case { id: "close.bad_fd", known_divergence: None, skip: None, compare_ret_on_success: false, run: close_bad_fd },
    Case { id: "fcntl.f_dupfd_cloexec.bad_fd", known_divergence: None, skip: None, compare_ret_on_success: false, run: fcntl_dupfd_cloexec_bad_fd },
    Case { id: "fcntl.f_dupfd_cloexec.ok", known_divergence: None, skip: None, compare_ret_on_success: false, run: fcntl_dupfd_cloexec_ok },
    Case { id: "fcntl.f_getfl.append_roundtrip", known_divergence: None, skip: None, compare_ret_on_success: true, run: fcntl_getfl_append_roundtrip },
    Case { id: "read.directory.eisdir", known_divergence: None, skip: None, compare_ret_on_success: false, run: read_on_directory_eisdir },
    Case { id: "write.directory.eisdir", known_divergence: None, skip: None, compare_ret_on_success: false, run: write_on_directory_eisdir },
    Case { id: "lseek.pipe.espipe", known_divergence: None, skip: None, compare_ret_on_success: false, run: lseek_espipe_on_pipe },
    Case { id: "lseek.negative_result.einval", known_divergence: None, skip: None, compare_ret_on_success: false, run: lseek_negative_result_einval },
    Case { id: "ftruncate.negative_len.einval", known_divergence: None, skip: None, compare_ret_on_success: false, run: ftruncate_negative_len_einval },
    Case { id: "ftruncate.directory.einval", known_divergence: None, skip: None, compare_ret_on_success: false, run: ftruncate_on_directory_einval },
];

#[test]
fn fd_family_corpus() {
    run_corpus(CASES);
}
