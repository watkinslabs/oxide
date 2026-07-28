// `splice(2)` / `tee(2)` / `vmsplice(2)` driven against the REAL anonymous-pipe
// ring (`fs::pipe`), not a mock: the whole point of the F754 rewrite is that
// these syscalls are defined over pipe semantics, and the pre-fix code — a bare
// read/write loop — could not express any of them.
//
// Linux references: `fs/splice.c` `do_splice` (:1300-1395), `do_tee`
// (:1938-1975), `vmsplice_to_pipe`/`vmsplice_to_user` (:1501-1560).

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use fs::pipe::{make_pipe_inode, pipe_data, queued};
use fs::splice::{do_splice, do_tee, do_vmsplice_to_pipe, do_vmsplice_to_user};
use syscall::errno::Errno;
use vfs::{Dentry, File, FileType, InodeBuilder, InodeRef, OpenFlags,
          default_file_ops, default_inode_ops, mk_mode};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// A live anonymous pipe with both ends open: `readers`/`writers` primed the
/// way `sys_pipe2` primes them, so the EOF / EPIPE decisions are real.
fn pipe_pair() -> (InodeRef, Arc<File>, Arc<File>) {
    let inode = make_pipe_inode();
    let p = pipe_data(&inode).expect("anon pipe carries its ring");
    p.readers.store(1, Ordering::Release);
    p.writers.store(1, Ordering::Release);
    let d = Dentry::new_root(inode.clone());
    let rd = File::new(inode.clone(), d.clone(), OpenFlags::empty());
    let wr = File::new(inode.clone(), d, OpenFlags::O_WRONLY);
    (inode, rd, wr)
}

/// A non-pipe description (regular file inode with the default no-op ops) —
/// enough to make the "at least one end must be a pipe" rule observable.
fn plain_file(ino: u64, flags: OpenFlags) -> Arc<File> {
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops()).build();
    let d = Dentry::new_root(inode.clone());
    File::new(inode, d, flags)
}

fn fill(wr: &File, bytes: &[u8]) {
    assert_eq!(wr.write(bytes).expect("pipe write"), bytes.len());
}

fn drain(rd: &File, n: usize) -> alloc::vec::Vec<u8> {
    let mut buf = alloc::vec![0u8; n];
    let got = rd.read(&mut buf).expect("pipe read");
    buf.truncate(got);
    buf
}

/// THE `tee` contract: the bytes it copies into the output pipe are STILL
/// readable from the input pipe. The pre-fix implementation forwarded `tee` to
/// the splice read/write loop, which consumed the input — so the data `tee`
/// exists to preserve was destroyed. This test fails against that behaviour.
#[test]
fn tee_duplicates_and_does_not_consume_the_input() {
    let (_ia, rd_a, wr_a) = pipe_pair();
    let (_ib, rd_b, wr_b) = pipe_pair();
    fill(&wr_a, b"hello world");

    let n = do_tee(&rd_a, &wr_b, 11, 0);
    assert_eq!(n, 11, "tee must report the duplicated byte count");

    // The OUTPUT pipe now holds a copy ...
    assert_eq!(drain(&rd_b, 32), b"hello world");
    // ... and the INPUT pipe still holds the original.
    assert_eq!(drain(&rd_a, 32), b"hello world");
}

/// `tee` is bounded by the output pipe's free space and by `len`, and reports
/// the short count rather than claiming the whole request.
#[test]
fn tee_is_bounded_by_len_and_by_output_space() {
    let (_ia, rd_a, wr_a) = pipe_pair();
    let (_ib, rd_b, wr_b) = pipe_pair();
    fill(&wr_a, b"0123456789");
    assert_eq!(do_tee(&rd_a, &wr_b, 4, 0), 4);
    assert_eq!(drain(&rd_b, 32), b"0123");
    // Input untouched.
    assert_eq!(drain(&rd_a, 32), b"0123456789");
}

/// `tee` needs BOTH ends to be pipes, and they must be different pipes.
/// EINVAL for every other shape (`fs/splice.c:1943`, `:1953`).
#[test]
fn tee_rejects_non_pipes_and_self() {
    let (_ia, rd_a, wr_a) = pipe_pair();
    fill(&wr_a, b"xyz");
    let reg_w = plain_file(0x9001, OpenFlags::O_WRONLY);
    let reg_r = plain_file(0x9002, OpenFlags::empty());
    assert_eq!(do_tee(&rd_a, &reg_w, 3, 0), errno(Errno::Einval), "output not a pipe");
    assert_eq!(do_tee(&reg_r, &wr_a, 3, 0), errno(Errno::Einval), "input not a pipe");
    // Same pipe on both sides.
    assert_eq!(do_tee(&rd_a, &wr_a, 3, 0), errno(Errno::Einval), "self-tee");
    // Unreadable input / unwritable output → EBADF, checked before the pipe test.
    let (_ib, rd_b, wr_b) = pipe_pair();
    assert_eq!(do_tee(&wr_b, &wr_a, 3, 0), errno(Errno::Ebadf), "input lacks FMODE_READ");
    assert_eq!(do_tee(&rd_a, &rd_b, 3, 0), errno(Errno::Ebadf), "output lacks FMODE_WRITE");
}

/// `tee` on an input pipe whose writers have all closed is EOF → 0, NOT EAGAIN,
/// even though the ring is empty (`ipipe_prep`, `fs/splice.c:1661`).
#[test]
fn tee_reports_eof_as_zero_not_eagain() {
    let (ia, rd_a, _wr_a) = pipe_pair();
    let (_ib, _rd_b, wr_b) = pipe_pair();
    pipe_data(&ia).unwrap().writers.store(0, Ordering::Release);
    assert_eq!(do_tee(&rd_a, &wr_b, 8, 0), 0, "closed writers is EOF");
}

/// `splice` MOVES between two pipes: the input is drained, unlike `tee`.
#[test]
fn splice_pipe_to_pipe_consumes_the_input() {
    let (_ia, rd_a, wr_a) = pipe_pair();
    let (_ib, rd_b, wr_b) = pipe_pair();
    fill(&wr_a, b"abcdef");
    assert_eq!(do_splice(&rd_a, None, &wr_b, None, 6, 0), 6);
    assert_eq!(drain(&rd_b, 32), b"abcdef");
    // Hosted builds have no scheduler, so a read of an empty-but-open pipe
    // parks-and-degrades to EAGAIN; assert emptiness on the ring itself.
    assert_eq!(queued(pipe_data(&_ia).unwrap()), 0, "splice must have consumed the source");
}

/// Splicing a pipe to ITSELF is EINVAL (`fs/splice.c:1320`).
#[test]
fn splice_same_pipe_is_einval() {
    let (_ia, rd_a, wr_a) = pipe_pair();
    fill(&wr_a, b"abc");
    assert_eq!(do_splice(&rd_a, None, &wr_a, None, 3, 0), errno(Errno::Einval));
}

/// Neither end a pipe → EINVAL (`fs/splice.c:1380-1382`). The pre-fix code
/// happily copied between two regular files here.
#[test]
fn splice_between_two_regular_files_is_einval() {
    let src = plain_file(0x9101, OpenFlags::empty());
    let dst = plain_file(0x9102, OpenFlags::O_WRONLY);
    assert_eq!(do_splice(&src, None, &dst, None, 16, 0), errno(Errno::Einval));
}

/// An offset supplied for a PIPE end is ESPIPE, and it fires before the FMODE
/// gate (`fs/splice.c:1409-1418`).
#[test]
fn splice_offset_on_a_pipe_end_is_espipe() {
    let (_ia, rd_a, _wr_a) = pipe_pair();
    let (_ib, _rd_b, wr_b) = pipe_pair();
    let mut off = 0u64;
    assert_eq!(do_splice(&rd_a, Some(&mut off), &wr_b, None, 4, 0), errno(Errno::Espipe));
    let mut off = 0u64;
    assert_eq!(do_splice(&rd_a, None, &wr_b, Some(&mut off), 4, 0), errno(Errno::Espipe));
}

/// `vmsplice` direction comes from `f_mode`: a WRITE end takes user pages into
/// the pipe, a READ end drains the pipe into user memory. The pre-fix code only
/// ever wrote, so the read direction appended instead of draining.
#[test]
fn vmsplice_direction_follows_fmode() {
    let (_i, rd, wr) = pipe_pair();
    let src: &[u8] = b"payload";
    assert_eq!(do_vmsplice_to_pipe(&wr, &[src], 0), 7);
    let mut dst = [0u8; 16];
    let mut bufs: [&mut [u8]; 1] = [&mut dst[..]];
    assert_eq!(do_vmsplice_to_user(&rd, &mut bufs, 0), 7);
    assert_eq!(&dst[..7], b"payload");
    // The pipe is now empty and its writers are still open, so a further
    // non-blocking drain is EAGAIN rather than EOF.
    let mut dst2 = [0u8; 4];
    let mut bufs2: [&mut [u8]; 1] = [&mut dst2[..]];
    assert_eq!(do_vmsplice_to_user(&rd, &mut bufs2, fs::splice::SPLICE_F_NONBLOCK),
        errno(Errno::Eagain));
}

/// `vmsplice` on a description that is not a pipe is EBADF, not EINVAL
/// (`fs/splice.c:1512`, `:1545`).
#[test]
fn vmsplice_on_a_non_pipe_is_ebadf() {
    let reg = plain_file(0x9201, OpenFlags::O_RDWR);
    assert_eq!(do_vmsplice_to_pipe(&reg, &[b"x".as_slice()], 0), errno(Errno::Ebadf));
    let mut d = [0u8; 4];
    let mut bufs: [&mut [u8]; 1] = [&mut d[..]];
    assert_eq!(do_vmsplice_to_user(&reg, &mut bufs, 0), errno(Errno::Ebadf));
}

/// A zero-length vector returns 0 without touching the pipe.
#[test]
fn vmsplice_zero_length_is_zero() {
    let (_i, rd, wr) = pipe_pair();
    assert_eq!(do_vmsplice_to_pipe(&wr, &[], 0), 0);
    let mut none: [&mut [u8]; 0] = [];
    assert_eq!(do_vmsplice_to_user(&rd, &mut none, 0), 0);
}
