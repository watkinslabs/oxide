// `BPF_TASK_FD_QUERY` classification + `bpf_task_fd_query_copy()` contract.
//
// The write-back tests aim the "user" pointers at this process's own memory,
// which is what `user::write_bytes` copies through on a hosted build, so the
// exact bytes the caller would observe are readable back here.

use alloc::vec;
use alloc::vec::Vec;
use alloc::sync::Arc;

use syscall::errno::Errno;

use super::*;
use super::super::super::super::{
    make_bpf_prog_inode, make_bpf_iter_link_inode, prime_bpf_raw_tracepoint_link_with,
    prog_facts, IterTarget, PerfHooks, RawTracepointHooks,
};
use super::super::super::super::uapi::{fd_type, off::task_fd_query as o};

const TP_NAME: &[u8] = b"sys_enter";
const TEST_PROG_ID: u32 = 7;
const TEST_PROBE_OFFSET: u64 = 0x40;
const TEST_PROBE_ADDR: u64 = 0xffff_8000_dead_beef;

/// A staging `union bpf_attr` naming a caller buffer of `buf_len` bytes.
fn attr_with(buf: u64, buf_len: u32) -> Attr {
    let mut a = Attr::zeroed();
    a.bytes[o::BUF..o::BUF + 8].copy_from_slice(&buf.to_ne_bytes());
    a.bytes[o::BUF_LEN..o::BUF_LEN + 4].copy_from_slice(&buf_len.to_ne_bytes());
    a
}

/// The `union bpf_attr` the kernel writes its answer back into.
fn uattr() -> Vec<u8> { vec![0u8; super::super::super::super::uapi::ATTR_SIZE] }

fn u32_at(bytes: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(bytes[off..off + 8].try_into().unwrap())
}

/// Hooks answering "every inode is a perf event" / "none is", with no
/// attached program; the arms that need one build their own.
fn hooks(is_perf: bool) -> PerfHooks {
    fn yes(_: &vfs::InodeRef) -> bool { true }
    fn no(_: &vfs::InodeRef) -> bool { false }
    fn no_prog(_: &vfs::InodeRef) -> Option<vfs::InodeRef> { None }
    PerfHooks { is_perf: if is_perf { yes } else { no }, attached_prog: no_prog }
}

fn copy_tracepoint(a: &Attr, out: &mut [u8]) -> Result<i64, Errno> {
    copy_out(a, out.as_mut_ptr() as u64, TEST_PROG_ID, fd_type::TRACEPOINT,
             TP_NAME, TEST_PROBE_OFFSET, TEST_PROBE_ADDR)
}

#[test]
fn the_fd_type_numbers_are_the_uapi_enum_order() {
    assert_eq!(fd_type::RAW_TRACEPOINT, 0);
    assert_eq!(fd_type::TRACEPOINT, 1);
    assert_eq!(fd_type::KPROBE, 2);
    assert_eq!(fd_type::KRETPROBE, 3);
    assert_eq!(fd_type::UPROBE, 4);
    assert_eq!(fd_type::URETPROBE, 5);
}

/// The link arm is tested before the perf predicate, so a link fd is never
/// offered to perf; a program fd is neither and falls through to `Other`.
#[test]
fn a_link_is_classified_before_the_perf_predicate_is_consulted() {
    let prog = make_bpf_prog_inode(super::super::super::super::uapi::prog_type::TRACING, Vec::new());
    let link = make_bpf_iter_link_inode(IterTarget::BpfProg, prog.clone());
    assert!(matches!(classify(&link, hooks(true)), QueriedFd::OtherLink));
    assert!(matches!(classify(&prog, hooks(true)), QueriedFd::PerfEvent));
    assert!(matches!(classify(&prog, hooks(false)), QueriedFd::Other));
}

/// The raw-link operation test is inside the generic BPF-link arm and wins
/// before `perf_get_event()`, even if that predicate would claim the inode.
#[test]
fn a_raw_tracepoint_link_is_classified_before_perf() {
    fn attach(_: &[u8], _: u64, _: vfs::InodeRef, _: u64)
        -> Result<&'static str, Errno> { unreachable!() }
    fn detach(_: &str, _: u64) {}
    let prog = make_bpf_prog_inode(
        super::super::super::super::uapi::prog_type::RAW_TRACEPOINT, Vec::new());
    let fdt = Arc::new(vfs::FdTable::new());
    let primer = prime_bpf_raw_tracepoint_link_with(
        Arc::clone(&fdt), 1, prog, 0,
        RawTracepointHooks { attach, detach },
    ).unwrap();
    assert_eq!(primer.settle("sys_enter"), 0);
    let file = fdt.get(0).unwrap();
    assert!(matches!(classify(file.inode(), hooks(true)),
                     QueriedFd::RawTracepoint(_)));
}

/// The raw-link arm reports the link's pinned program and canonical event
/// name. Its cookie belongs to execution context and is not part of this UAPI.
#[test]
fn a_raw_tracepoint_link_reports_its_program_and_event_name() {
    let prog = make_bpf_prog_inode(
        super::super::super::super::uapi::prog_type::RAW_TRACEPOINT, Vec::new());
    let prog_id = prog_facts(&prog).unwrap().id;
    let info = RawTracepointLinkInfo { prog, name: "sys_enter", cookie: 0xfeed };
    let mut name = [0xAAu8; TP_NAME.len() + 1];
    let mut out = uattr();
    let a = attr_with(name.as_mut_ptr() as u64, name.len() as u32);

    assert_eq!(describe(&a, out.as_mut_ptr() as u64,
                        QueriedFd::RawTracepoint(info), None), Ok(0));
    assert_eq!(&name, b"sys_enter\0");
    assert_eq!(u32_at(&out, o::PROG_ID), prog_id);
    assert_eq!(u32_at(&out, o::FD_TYPE), fd_type::RAW_TRACEPOINT);
    assert_eq!(u64_at(&out, o::PROBE_OFFSET), 0);
    assert_eq!(u64_at(&out, o::PROBE_ADDR), 0);
}

/// Neither describable kind: `-ENOTSUPP` (524), not `-EOPNOTSUPP` (95).
#[test]
fn a_link_of_another_kind_and_a_plain_descriptor_are_enotsupp() {
    let a = Attr::zeroed();
    assert_eq!(describe(&a, 0, QueriedFd::OtherLink, None), Err(Errno::Enotsupp));
    assert_eq!(describe(&a, 0, QueriedFd::Other, None), Err(Errno::Enotsupp));
    assert_eq!(Errno::Enotsupp.as_i32(), 524);
}

/// `bpf_get_perf_event_info()` reads the description off the program attached
/// to the event. Without one the answer is `-ENOENT` — and nothing is written
/// back, since the copy runs only on the success path.
#[test]
fn a_perf_event_with_no_attached_program_is_enoent_and_writes_nothing() {
    let mut out = uattr();
    let a = attr_with(0, 0);
    assert_eq!(describe(&a, out.as_mut_ptr() as u64, QueriedFd::PerfEvent, None),
               Err(Errno::Enoent));
    assert!(out.iter().all(|b| *b == 0));
}

/// An event carrying a perf-event program is a different answer from one
/// carrying none: `-EOPNOTSUPP` (95), not `-ENOENT` and not the `-ENOTSUPP`
/// (524) an undescribable descriptor gets. Still nothing is written back.
#[test]
fn a_perf_event_program_is_eopnotsupp_not_enoent() {
    let prog = make_bpf_prog_inode(
        super::super::super::super::uapi::prog_type::PERF_EVENT, Vec::new());
    let facts = prog_facts(&prog).unwrap();
    let mut out = uattr();
    let a = attr_with(0, 0);
    assert_eq!(describe(&a, out.as_mut_ptr() as u64, QueriedFd::PerfEvent, Some(facts)),
               Err(Errno::Eopnotsupp));
    assert_eq!(Errno::Eopnotsupp.as_i32(), 95);
    assert_ne!(Errno::Eopnotsupp.as_i32(), Errno::Enotsupp.as_i32());
    assert!(out.iter().all(|b| *b == 0));
}

/// A buffer holding the name and its terminator gets both, and every scalar
/// field lands at its own offset.
#[test]
fn a_buffer_that_fits_the_name_and_its_terminator_copies_both() {
    let mut buf = vec![0xAAu8; TP_NAME.len() + 1];
    let mut out = uattr();
    let a = attr_with(buf.as_mut_ptr() as u64, buf.len() as u32);
    assert_eq!(copy_tracepoint(&a, &mut out), Ok(0));
    assert_eq!(&buf[..TP_NAME.len()], TP_NAME);
    assert_eq!(buf[TP_NAME.len()], 0);
    assert_eq!(u32_at(&out, o::BUF_LEN), TP_NAME.len() as u32);
    assert_eq!(u32_at(&out, o::PROG_ID), TEST_PROG_ID);
    assert_eq!(u32_at(&out, o::FD_TYPE), fd_type::TRACEPOINT);
    assert_eq!(u64_at(&out, o::PROBE_OFFSET), TEST_PROBE_OFFSET);
    assert_eq!(u64_at(&out, o::PROBE_ADDR), TEST_PROBE_ADDR);
}

/// One byte short of the terminator is already short: the copy keeps
/// `buf_len - 1` name bytes, terminates them, and reports `-ENOSPC` — with
/// every scalar field still written, so the caller learns the real length.
#[test]
fn a_short_buffer_truncates_terminates_and_reports_enospc() {
    for room in 1..=TP_NAME.len() {
        let mut buf = vec![0xAAu8; room + 1];
        let mut out = uattr();
        let a = attr_with(buf.as_mut_ptr() as u64, room as u32);
        assert_eq!(copy_tracepoint(&a, &mut out), Err(Errno::Enospc));
        assert_eq!(&buf[..room - 1], &TP_NAME[..room - 1]);
        assert_eq!(buf[room - 1], 0);
        // The byte past the caller's declared length is untouched.
        assert_eq!(buf[room], 0xAA);
        assert_eq!(u32_at(&out, o::BUF_LEN), TP_NAME.len() as u32);
        assert_eq!(u32_at(&out, o::PROG_ID), TEST_PROG_ID);
        assert_eq!(u32_at(&out, o::FD_TYPE), fd_type::TRACEPOINT);
        assert_eq!(u64_at(&out, o::PROBE_ADDR), TEST_PROBE_ADDR);
    }
    // Exactly name + terminator is the first size that is not short.
    let mut buf = vec![0xAAu8; TP_NAME.len() + 1];
    let mut out = uattr();
    let a = attr_with(buf.as_mut_ptr() as u64, TP_NAME.len() as u32 + 1);
    assert_eq!(copy_tracepoint(&a, &mut out), Ok(0));
}

/// An attach point with no name reports length zero and leaves the caller's
/// buffer holding just a terminator — a kprobe by address has no name.
#[test]
fn a_nameless_attach_point_leaves_only_a_terminator() {
    let mut buf = [0xAAu8; 4];
    let mut out = uattr();
    let a = attr_with(buf.as_mut_ptr() as u64, buf.len() as u32);
    assert_eq!(
        copy_out(&a, out.as_mut_ptr() as u64, TEST_PROG_ID, fd_type::KPROBE, b"",
                 TEST_PROBE_OFFSET, TEST_PROBE_ADDR),
        Ok(0),
    );
    assert_eq!(buf, [0, 0xAA, 0xAA, 0xAA]);
    assert_eq!(u32_at(&out, o::BUF_LEN), 0);
    assert_eq!(u32_at(&out, o::FD_TYPE), fd_type::KPROBE);
    assert_eq!(u64_at(&out, o::PROBE_OFFSET), TEST_PROBE_OFFSET);
}

/// A caller that wants only the scalars — no buffer, or a zero-length one —
/// still gets every field, including the name length it would need.
#[test]
fn a_caller_with_no_name_buffer_still_gets_every_field() {
    for a in [attr_with(0, 64), attr_with(1, 0)] {
        let mut out = uattr();
        assert_eq!(copy_tracepoint(&a, &mut out), Ok(0));
        assert_eq!(u32_at(&out, o::BUF_LEN), TP_NAME.len() as u32);
        assert_eq!(u32_at(&out, o::PROG_ID), TEST_PROG_ID);
        assert_eq!(u32_at(&out, o::FD_TYPE), fd_type::TRACEPOINT);
        assert_eq!(u64_at(&out, o::PROBE_OFFSET), TEST_PROBE_OFFSET);
        assert_eq!(u64_at(&out, o::PROBE_ADDR), TEST_PROBE_ADDR);
    }
}

/// A `union bpf_attr` address that would wrap while the field offsets are
/// added is `-EFAULT` rather than an arithmetic wrap into a live mapping.
#[test]
fn a_wrapping_attr_address_is_efault() {
    let a = attr_with(0, 0);
    assert_eq!(copy_out(&a, u64::MAX, TEST_PROG_ID, fd_type::TRACEPOINT, TP_NAME, 0, 0),
               Err(Errno::Efault));
}
