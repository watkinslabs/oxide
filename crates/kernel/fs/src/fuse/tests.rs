// Hosted unit tests for the FUSE codec + channel state machine. These drive the
// REAL wire protocol and the `FuseConn` request/reply broker WITHOUT a live
// scheduler: the codec is pure, and every channel path exercised here
// (`new_request`/`dequeue`/`submit_reply`/`abort`/INIT negotiation) is
// scheduler-free. The blocking `wait_reply`/`park` paths are `oxide-kernel`-only
// and are covered by construction (a completed slot carries the reply bytes the
// waiter would return).

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::PollSubscribers;

use super::conn::FuseConn;
use super::proto::*;

fn conn() -> Arc<FuseConn> { FuseConn::new(Arc::new(PollSubscribers::new())) }

/// Build a daemon reply buffer: `fuse_out_header{len,error,unique}` + `body`.
fn reply(unique: u64, error: i32, body: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    OutHeader { len: (FUSE_OUT_HEADER_SIZE + body.len()) as u32, error, unique }.encode(&mut b);
    b.extend_from_slice(body);
    b
}

// ---- codec: fixed sizes match uapi/linux/fuse.h -----------------------------

#[test]
fn struct_sizes_match_uapi() {
    assert_eq!(FUSE_IN_HEADER_SIZE, 40);
    assert_eq!(FUSE_OUT_HEADER_SIZE, 16);
    assert_eq!(FUSE_INIT_IN_SIZE, 16);
    assert_eq!(FUSE_INIT_OUT_SIZE, 64);
    assert_eq!(FUSE_ATTR_SIZE, 88);
    assert_eq!(FUSE_ENTRY_OUT_SIZE, 128);
    assert_eq!(FUSE_ATTR_OUT_SIZE, 104);
    assert_eq!(FUSE_OPEN_OUT_SIZE, 16);
    assert_eq!(FUSE_READ_IN_SIZE, 40);
    assert_eq!(FUSE_DIRENT_HEADER_SIZE, 24);
}

#[test]
fn in_header_roundtrip() {
    let h = InHeader { len: 60, opcode: FUSE_LOOKUP, unique: 0x1122334455667788, nodeid: 1, uid: 5, gid: 6, pid: 7 };
    let mut b = Vec::new();
    h.encode(&mut b);
    assert_eq!(b.len(), FUSE_IN_HEADER_SIZE);
    assert_eq!(InHeader::decode(&b).unwrap(), h);
}

#[test]
fn out_header_roundtrip_negative_error() {
    let h = OutHeader { len: 16, error: -38, unique: 99 };
    let mut b = Vec::new();
    h.encode(&mut b);
    assert_eq!(b.len(), FUSE_OUT_HEADER_SIZE);
    let d = OutHeader::decode(&b).unwrap();
    assert_eq!(d.error, -38);
    assert_eq!(d, h);
}

#[test]
fn init_roundtrip() {
    let i = InitIn { major: 7, minor: 31, max_readahead: 131072, flags: FUSE_ASYNC_READ | FUSE_BIG_WRITES };
    let mut b = Vec::new();
    i.encode(&mut b);
    assert_eq!(b.len(), FUSE_INIT_IN_SIZE);
    assert_eq!(InitIn::decode(&b).unwrap(), i);

    let o = InitOut { major: 7, minor: 27, max_readahead: 131072, flags: FUSE_ASYNC_READ,
        max_background: 12, congestion_threshold: 9, max_write: 1 << 17, time_gran: 1,
        max_pages: 32, map_alignment: 0 };
    let mut ob = Vec::new();
    o.encode(&mut ob);
    assert_eq!(ob.len(), FUSE_INIT_OUT_SIZE);
    assert_eq!(InitOut::decode(&ob).unwrap(), o);
}

#[test]
fn attr_entry_attrout_roundtrip() {
    let attr = Attr { ino: 2, size: 4096, blocks: 8, atime: 1, mtime: 2, ctime: 3,
        atimensec: 10, mtimensec: 20, ctimensec: 30, mode: 0o100644, nlink: 1,
        uid: 1000, gid: 1000, rdev: 0, blksize: 512 };
    let mut ab = Vec::new();
    attr.encode(&mut ab);
    assert_eq!(ab.len(), FUSE_ATTR_SIZE);
    assert_eq!(Attr::decode(&ab, 0).unwrap(), attr);

    let e = EntryOut { nodeid: 42, generation: 1, entry_valid: 5, attr_valid: 6,
        entry_valid_nsec: 7, attr_valid_nsec: 8, attr };
    let mut eb = Vec::new();
    e.encode(&mut eb);
    assert_eq!(eb.len(), FUSE_ENTRY_OUT_SIZE);
    assert_eq!(EntryOut::decode(&eb).unwrap(), e);

    let ao = AttrOut { attr_valid: 9, attr_valid_nsec: 10, attr };
    let mut aob = Vec::new();
    ao.encode(&mut aob);
    assert_eq!(aob.len(), FUSE_ATTR_OUT_SIZE);
    assert_eq!(AttrOut::decode(&aob).unwrap(), ao);
}

#[test]
fn open_read_getattr_roundtrip() {
    let o = OpenOut { fh: 0xdead_beef, open_flags: 1 };
    let mut ob = Vec::new();
    o.encode(&mut ob);
    assert_eq!(ob.len(), FUSE_OPEN_OUT_SIZE);
    assert_eq!(OpenOut::decode(&ob).unwrap(), o);

    let r = ReadIn { fh: 7, offset: 8192, size: 4096, read_flags: 0, lock_owner: 0, flags: 0 };
    let mut rb = Vec::new();
    r.encode(&mut rb);
    assert_eq!(rb.len(), FUSE_READ_IN_SIZE);
    assert_eq!(ReadIn::decode(&rb).unwrap(), r);

    let g = GetattrIn { getattr_flags: 0, fh: 3 };
    let mut gb = Vec::new();
    g.encode(&mut gb);
    assert_eq!(gb.len(), FUSE_GETATTR_IN_SIZE);
    assert_eq!(GetattrIn::decode(&gb).unwrap(), g);
}

// ---- codec: readdir dirent stream -------------------------------------------

#[test]
fn dirent_stream_roundtrip_and_alignment() {
    // DT_DIR = 4, DT_REG = 8.
    let ents = alloc::vec![
        Dirent { ino: 1, off: 1, d_type: 4, name: b".".to_vec() },
        Dirent { ino: 1, off: 2, d_type: 4, name: b"..".to_vec() },
        Dirent { ino: 9, off: 3, d_type: 8, name: b"hello.txt".to_vec() },
    ];
    let mut buf = Vec::new();
    for e in &ents { e.encode(&mut buf); }
    // Every entry must be 8-byte aligned on the wire.
    assert_eq!(buf.len() % 8, 0);
    let back = decode_dirent_stream(&buf).unwrap();
    assert_eq!(back, ents);
    // A specific alignment check: "hello.txt" is 9 bytes → 24+9=33 → padded 40.
    assert_eq!(ents[2].wire_len(), 40);
}

#[test]
fn dirent_stream_truncated_is_none() {
    let e = Dirent { ino: 1, off: 1, d_type: 8, name: b"abc".to_vec() };
    let mut buf = Vec::new();
    e.encode(&mut buf);
    buf.truncate(buf.len() - 4); // chop the padding + a name byte
    // Truncated within the padded region still parses the entry; chop into the
    // header instead to force a None.
    let mut hdr_only = Vec::new();
    e.encode(&mut hdr_only);
    hdr_only.truncate(10);
    assert!(decode_dirent_stream(&hdr_only).is_none());
}

// ---- channel state machine --------------------------------------------------

#[test]
fn request_enqueue_then_daemon_read() {
    let c = conn();
    let slot = c.new_request(FUSE_GETATTR, 1, &[0xAB; 4]);
    let mut buf = [0u8; 256];
    let n = c.dequeue(&mut buf).unwrap();
    assert_eq!(n, FUSE_IN_HEADER_SIZE + 4);
    let h = InHeader::decode(&buf).unwrap();
    assert_eq!(h.opcode, FUSE_GETATTR);
    assert_eq!(h.nodeid, 1);
    assert_eq!(h.unique, slot.unique);
    assert_eq!(h.len as usize, n);
    // Queue is now empty.
    assert_eq!(c.dequeue(&mut buf).unwrap(), 0);
    assert!(!c.has_pending());
}

#[test]
fn reply_completes_matching_slot() {
    let c = conn();
    let slot = c.new_request(FUSE_LOOKUP, 1, b"x\0");
    assert!(!slot.done.load(core::sync::atomic::Ordering::Acquire));
    let body = [0x55u8; 8];
    let n = c.submit_reply(&reply(slot.unique, 0, &body)).unwrap();
    assert!(n > 0);
    assert!(slot.done.load(core::sync::atomic::Ordering::Acquire));
    assert_eq!(slot.error.load(core::sync::atomic::Ordering::Acquire), 0);
    assert_eq!(&*slot.reply.lock(), &body);
}

#[test]
fn reply_unknown_unique_is_dropped() {
    let c = conn();
    let slot = c.new_request(FUSE_LOOKUP, 1, b"x\0");
    // A reply for a different unique must not touch our slot.
    let _ = c.submit_reply(&reply(slot.unique.wrapping_add(999), 0, &[1, 2, 3, 4])).unwrap();
    assert!(!slot.done.load(core::sync::atomic::Ordering::Acquire));
}

#[test]
fn reply_carries_daemon_error() {
    let c = conn();
    let slot = c.new_request(FUSE_LOOKUP, 1, b"y\0");
    let _ = c.submit_reply(&reply(slot.unique, -2 /* -ENOENT */, &[])).unwrap();
    assert!(slot.done.load(core::sync::atomic::Ordering::Acquire));
    assert_eq!(slot.error.load(core::sync::atomic::Ordering::Acquire), -2);
}

#[test]
fn abort_wakes_pending_with_enotconn() {
    let c = conn();
    let slot = c.new_request(FUSE_READ, 1, &[0u8; 40]);
    c.abort();
    assert!(c.is_aborted());
    assert!(slot.done.load(core::sync::atomic::Ordering::Acquire));
    assert_eq!(slot.error.load(core::sync::atomic::Ordering::Acquire), super::FUSE_WIRE_ENOTCONN);
    // A daemon read on an aborted channel reports ENODEV.
    let mut buf = [0u8; 64];
    assert_eq!(c.dequeue(&mut buf), Err(vfs::VfsError::Enodev));
}

#[test]
fn init_negotiation_compatible_major() {
    let c = conn();
    c.send_init();
    // Daemon read of the INIT request.
    let mut buf = [0u8; 256];
    let n = c.dequeue(&mut buf).unwrap();
    let h = InHeader::decode(&buf).unwrap();
    assert_eq!(h.opcode, FUSE_INIT);
    let ii = InitIn::decode(&buf[FUSE_IN_HEADER_SIZE..n]).unwrap();
    assert_eq!(ii.major, FUSE_KERNEL_VERSION);
    // Daemon replies with a LOWER minor → negotiated down.
    let out = InitOut { major: 7, minor: 27, max_readahead: 0, flags: FUSE_ASYNC_READ,
        max_background: 0, congestion_threshold: 0, max_write: 1 << 17, time_gran: 1,
        max_pages: 0, map_alignment: 0 };
    let mut ob = Vec::new();
    out.encode(&mut ob);
    let _ = c.submit_reply(&reply(h.unique, 0, &ob)).unwrap();
    let st = c.init_state();
    assert!(st.done && !st.failed);
    assert_eq!(st.minor, 27);
    assert_eq!(st.max_write, 1 << 17);
}

#[test]
fn init_negotiation_incompatible_major_fails() {
    let c = conn();
    c.send_init();
    let mut buf = [0u8; 256];
    let n = c.dequeue(&mut buf).unwrap();
    let h = InHeader::decode(&buf[..n]).unwrap();
    let out = InitOut { major: 8, minor: 0, ..Default::default() };
    let mut ob = Vec::new();
    out.encode(&mut ob);
    let _ = c.submit_reply(&reply(h.unique, 0, &ob)).unwrap();
    let st = c.init_state();
    assert!(st.done && st.failed);
}

/// F767: the `fuse_attr` seconds field is `uint64_t` on the wire, but Linux
/// assigns it straight into a `time64_t` (`fs/fuse/inode.c`
/// `fuse_change_attributes_common`), so it is REINTERPRETED as signed. A daemon
/// reporting a pre-1970 mtime sends `(u64)(-2_000_000_000)`; that must land as
/// second `-2_000_000_000`, not as year ~2554. Before F767 the fuse backend
/// dropped every daemon timestamp on the floor (`build_inode` never called
/// `.times()`), so no value at all reached the inode.
#[test]
fn attr_time_reinterprets_wire_seconds_as_signed() {
    use super::fs::attr_time;
    assert_eq!(attr_time(1_700_000_000, 123), vfs::Timespec64::new(1_700_000_000, 123));
    assert_eq!(attr_time((-2_000_000_000i64) as u64, 123),
               vfs::Timespec64 { sec: -2_000_000_000, nsec: 123 });
    assert_eq!(attr_time((-1i64) as u64, 0), vfs::Timespec64 { sec: -1, nsec: 0 });
    assert_eq!(attr_time(0, 0), vfs::Timespec64::ZERO);
}

/// Linux CLAMPS an out-of-range daemon `*nsec` rather than rejecting it
/// (`min_t(u32, attr->atimensec, NSEC_PER_SEC - 1)`, fs/fuse/inode.c:245).
#[test]
fn attr_time_clamps_an_out_of_range_subsecond_field() {
    use super::fs::attr_time;
    use vfs::timespec::NSEC_PER_SEC;
    assert_eq!(attr_time(5, NSEC_PER_SEC), vfs::Timespec64::new(5, NSEC_PER_SEC - 1));
    assert_eq!(attr_time(5, u32::MAX), vfs::Timespec64::new(5, NSEC_PER_SEC - 1));
    // A pre-epoch second with an over-range nsec clamps the nsec only.
    assert_eq!(attr_time((-5i64) as u64, u32::MAX),
               vfs::Timespec64 { sec: -5, nsec: NSEC_PER_SEC - 1 });
}
