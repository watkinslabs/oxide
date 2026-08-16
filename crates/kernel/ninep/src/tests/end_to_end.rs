// The whole client driven against the scripted server: handshake, attach,
// walk, open, read, write, readdir, statfs — and the fid/tag bookkeeping that
// only shows up when real sequences run.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::client::Client;
use crate::codec::{Dialect, DirEntries};
use crate::err::NpError;
use crate::transport::TransportRef;
use crate::uapi::{dotl, limits, op, stats, version};
use super::server::ScriptedServer;

fn session() -> (Arc<ScriptedServer>, Arc<Client>) {
    let srv = ScriptedServer::new();
    let t: TransportRef = srv.clone();
    let c = Client::new(t, Dialect::DotL, limits::DEFAULT_MSIZE).unwrap();
    c.version().unwrap();
    (srv, c)
}

#[test]
fn the_handshake_settles_the_dialect_and_the_frame_size() {
    let srv = ScriptedServer::new();
    srv.state.lock().unwrap().msize = 16384;
    let t: TransportRef = srv.clone();
    let c = Client::new(t, Dialect::DotL, limits::DEFAULT_MSIZE).unwrap();
    let n = c.version().unwrap();
    assert_eq!(n.dialect, Dialect::DotL);
    assert_eq!(n.msize, 16384);
    assert_eq!(c.msize(), 16384);
    assert_eq!(c.dialect(), Dialect::DotL);
    assert_eq!(srv.opcodes(), &[op::TVERSION]);
    // The handshake released its reserved slot.
    assert_eq!(c.in_flight(), 0);
}

#[test]
fn a_server_offering_only_the_legacy_dialect_downgrades_the_session() {
    let srv = ScriptedServer::new();
    srv.state.lock().unwrap().version_answer = version::V9P2000.into();
    let t: TransportRef = srv.clone();
    let c = Client::new(t, Dialect::DotL, limits::DEFAULT_MSIZE).unwrap();
    assert_eq!(c.version().unwrap().dialect, Dialect::Legacy);
    assert_eq!(c.dialect(), Dialect::Legacy);
}

#[test]
fn a_frame_size_the_transport_cannot_carry_is_capped_before_the_handshake() {
    let srv = ScriptedServer::new();
    let t: TransportRef = srv.clone();
    let c = Client::new(t, Dialect::DotL, u32::MAX).unwrap();
    assert!(c.msize() <= limits::MAX_SOCK_MSIZE);
    // And a request below the floor is refused rather than raised.
    let srv2 = ScriptedServer::new();
    let t2: TransportRef = srv2;
    assert_eq!(Client::new(t2, Dialect::DotL, 100).unwrap_err(), NpError::BadVersion);
}

#[test]
fn attach_then_drop_clunks_the_root_handle() {
    let (srv, c) = session();
    {
        let root = c.attach(None, "root", "", 0).unwrap();
        assert_eq!(root.qid().path, 0);
        assert!(root.qid().is_dir());
        assert_eq!(c.live_fids(), 1);
    }
    assert_eq!(c.live_fids(), 0);
    assert!(srv.leaked_fids().is_empty(), "leaked {:?}", srv.leaked_fids());
    assert!(srv.opcodes().contains(&op::TCLUNK));
}

#[test]
fn a_walk_clone_produces_an_independent_handle_and_both_are_clunked() {
    let (srv, c) = session();
    let sub = srv.add_dir(0, "sub");
    srv.add_file(sub, "hello.txt", b"hi");
    {
        let root = c.attach(None, "root", "", 0).unwrap();
        let f = c.walk(&root, &["sub", "hello.txt"], true).unwrap();
        assert_ne!(f.fid, root.fid);
        assert!(!f.qid().is_dir());
        assert_eq!(c.live_fids(), 2);
    }
    assert_eq!(c.live_fids(), 0);
    assert!(srv.leaked_fids().is_empty(), "leaked {:?}", srv.leaked_fids());
}

#[test]
fn a_walk_that_cannot_resolve_reports_enoent_and_leaks_no_handle() {
    let (srv, c) = session();
    srv.add_dir(0, "sub");
    let root = c.attach(None, "root", "", 0).unwrap();
    // A partial walk must NOT succeed on the prefix: the handle would name an
    // ancestor and every later operation would address the wrong object.
    let e = c.walk(&root, &["sub", "missing"], true).unwrap_err();
    assert_eq!(e, NpError::Server(2));
    drop(root);
    assert_eq!(c.live_fids(), 0);
    assert!(srv.leaked_fids().is_empty(), "leaked {:?}", srv.leaked_fids());
}

#[test]
fn a_deep_path_is_split_into_chunks_that_the_wire_can_carry() {
    let (srv, c) = session();
    let mut names: Vec<alloc::string::String> = Vec::new();
    let mut at = 0usize;
    for i in 0..(limits::MAXWELEM * 2 + 3) {
        let n = alloc::format!("d{i}");
        at = srv.add_dir(at, &n);
        names.push(n);
    }
    let root = c.attach(None, "root", "", 0).unwrap();
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let deep = c.walk(&root, &refs, true).unwrap();
    assert_eq!(deep.qid().path, at as u64);
    let walks = srv.opcodes().iter().filter(|t| **t == op::TWALK).count();
    // A single message would exceed the element limit; the server would answer
    // the first sixteen and the client would believe it reached the target.
    assert_eq!(walks, refs.len().div_ceil(limits::MAXWELEM));
    assert!(walks >= 3);
}

#[test]
fn a_zero_element_walk_duplicates_a_handle() {
    let (srv, c) = session();
    let root = c.attach(None, "root", "", 0).unwrap();
    let dup = c.clone_fid(&root).unwrap();
    assert_ne!(dup.fid, root.fid);
    assert_eq!(dup.qid(), root.qid());
    assert_eq!(srv.opcodes().iter().filter(|t| **t == op::TWALK).count(), 1);
}

#[test]
fn walk_chunk_boundaries_cover_the_path_exactly_once() {
    use crate::client::walk::walk_chunks;
    for n in [0usize, 1, 15, 16, 17, 32, 33, 100] {
        let chunks: Vec<(usize, usize)> = walk_chunks(n).collect();
        if n == 0 { assert_eq!(chunks, alloc::vec![(0, 0)]); continue; }
        assert_eq!(chunks.first().unwrap().0, 0);
        assert_eq!(chunks.last().unwrap().1, n);
        for w in chunks.windows(2) { assert_eq!(w[0].1, w[1].0); }
        for (a, b) in &chunks { assert!(b - a <= limits::MAXWELEM && b > a); }
        assert_eq!(chunks.len(), n.div_ceil(limits::MAXWELEM));
    }
}

#[test]
fn open_and_read_return_the_servers_bytes() {
    let (srv, c) = session();
    srv.add_file(0, "f", b"the quick brown fox");
    let root = c.attach(None, "root", "", 0).unwrap();
    let f = c.walk(&root, &["f"], true).unwrap();
    let (qid, _iounit) = c.lopen(&f, dotl::RDONLY).unwrap();
    assert!(!qid.is_dir());
    assert_eq!(f.open_mode(), Some(dotl::RDONLY));
    let mut buf = [0u8; 32];
    let n = c.read(&f, 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"the quick brown fox");
}

#[test]
fn a_read_larger_than_one_message_is_split_and_reassembled() {
    let (srv, c) = session();
    let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    srv.add_file(0, "big", &data);
    srv.state.lock().unwrap().read_chunk = 512;
    let root = c.attach(None, "root", "", 0).unwrap();
    let f = c.walk(&root, &["big"], true).unwrap();
    c.lopen(&f, dotl::RDONLY).unwrap();
    let mut buf = alloc::vec![0u8; data.len()];
    let n = c.read(&f, 0, &mut buf).unwrap();
    assert_eq!(n, data.len());
    assert_eq!(buf, data);
    let reads = srv.opcodes().iter().filter(|t| **t == op::TREAD).count();
    assert!(reads >= data.len().div_ceil(512), "only {reads} reads for {} bytes", data.len());
}

#[test]
fn a_short_read_at_end_of_file_stops_the_loop_without_an_error() {
    let (srv, c) = session();
    srv.add_file(0, "f", b"12345");
    let root = c.attach(None, "root", "", 0).unwrap();
    let f = c.walk(&root, &["f"], true).unwrap();
    c.lopen(&f, dotl::RDONLY).unwrap();
    let mut buf = [0u8; 1000];
    assert_eq!(c.read(&f, 0, &mut buf).unwrap(), 5);
    // Past the end is zero bytes, not an error.
    assert_eq!(c.read(&f, 99, &mut buf).unwrap(), 0);
}

#[test]
fn a_write_larger_than_one_message_is_split_and_all_of_it_lands() {
    let (srv, c) = session();
    let idx = srv.add_file(0, "w", b"");
    srv.state.lock().unwrap().write_chunk = 300;
    let root = c.attach(None, "root", "", 0).unwrap();
    let f = c.walk(&root, &["w"], true).unwrap();
    c.lopen(&f, dotl::WRONLY).unwrap();
    let payload: Vec<u8> = (0..2048u32).map(|i| (i % 97) as u8).collect();
    assert_eq!(c.write(&f, 0, &payload).unwrap(), payload.len());
    assert_eq!(srv.state.lock().unwrap().nodes[idx].data, payload);
    assert!(srv.opcodes().iter().filter(|t| **t == op::TWRITE).count() >= 7);
}

#[test]
fn create_then_write_then_read_back_round_trips_through_the_server() {
    let (srv, c) = session();
    let root = c.attach(None, "root", "", 0).unwrap();
    let h = c.clone_fid(&root).unwrap();
    c.lcreate(&h, "new.txt", dotl::RDWR, 0o644, 0).unwrap();
    assert_eq!(c.write(&h, 0, b"written by the guest").unwrap(), 20);
    drop(h);
    let f = c.walk(&root, &["new.txt"], true).unwrap();
    c.lopen(&f, dotl::RDONLY).unwrap();
    let mut buf = [0u8; 64];
    let n = c.read(&f, 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"written by the guest");
    drop(f);
    drop(root);
    assert!(srv.leaked_fids().is_empty(), "leaked {:?}", srv.leaked_fids());
}

#[test]
fn readdir_walks_every_entry_across_several_messages() {
    let (srv, c) = session();
    for i in 0..40 { srv.add_file(0, &alloc::format!("entry{i:03}"), b""); }
    let root = c.attach(None, "root", "", 0).unwrap();
    let d = c.clone_fid(&root).unwrap();
    c.lopen(&d, dotl::RDONLY | dotl::DIRECTORY).unwrap();

    let mut names: Vec<alloc::string::String> = Vec::new();
    let mut cookie = 0u64;
    loop {
        // A small request forces the server to answer in several batches, which
        // is what exercises the cookie contract at all.
        let bytes = c.readdir(&d, cookie, 128).unwrap();
        if bytes.is_empty() { break; }
        let mut last = cookie;
        for ent in DirEntries::new(&bytes) {
            let ent = ent.unwrap();
            names.push(core::str::from_utf8(ent.name).unwrap().into());
            last = ent.offset;
        }
        assert_ne!(last, cookie, "the cookie did not advance");
        cookie = last;
    }
    assert_eq!(names.len(), 40);
    for i in 0..40 { assert!(names.contains(&alloc::format!("entry{i:03}"))); }
    // The names came back once each, not duplicated across batches.
    let uniq: alloc::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(uniq.len(), 40);
}

#[test]
fn getattr_reports_the_size_the_server_holds() {
    let (srv, c) = session();
    srv.add_file(0, "sized", &alloc::vec![7u8; 1234]);
    let root = c.attach(None, "root", "", 0).unwrap();
    let f = c.walk(&root, &["sized"], true).unwrap();
    let st = c.getattr(&f, stats::ALL).unwrap();
    assert_eq!(st.size, 1234);
    assert!(st.has(stats::SIZE));
    assert!(st.has(stats::MODE));
    assert_eq!(st.mode & 0o7777, 0o644);
}

#[test]
fn statfs_reports_the_servers_counters() {
    let (_srv, c) = session();
    let root = c.attach(None, "root", "", 0).unwrap();
    let s = c.statfs(&root).unwrap();
    assert_eq!(s.ty as u64, crate::V9FS_MAGIC);
    assert_eq!(s.bsize, 4096);
    assert_eq!(s.namelen, 255);
}

#[test]
fn a_server_error_reaches_the_caller_as_that_error() {
    let (srv, c) = session();
    let root = c.attach(None, "root", "", 0).unwrap();
    srv.state.lock().unwrap().fail_next = Some(13);
    assert_eq!(c.getattr(&root, stats::BASIC).unwrap_err(), NpError::Server(13));
    // The failed request released its tag.
    assert_eq!(c.in_flight(), 0);
}

#[test]
fn a_failed_operation_does_not_leak_its_tag() {
    let (srv, c) = session();
    let root = c.attach(None, "root", "", 0).unwrap();
    for _ in 0..50 {
        srv.state.lock().unwrap().fail_next = Some(5);
        assert!(c.getattr(&root, stats::BASIC).is_err());
    }
    assert_eq!(c.in_flight(), 0);
    assert!(c.getattr(&root, stats::BASIC).is_ok());
}

#[test]
fn no_tag_is_ever_live_twice_across_a_long_sequence() {
    let (srv, c) = session();
    let root = c.attach(None, "root", "", 0).unwrap();
    for i in 0..200 {
        let name = alloc::format!("f{i}");
        srv.add_file(0, &name, b"x");
        let f = c.walk(&root, &[name.as_str()], true).unwrap();
        c.lopen(&f, dotl::RDONLY).unwrap();
        let mut b = [0u8; 4];
        c.read(&f, 0, &mut b).unwrap();
    }
    // The server flags any tag that arrived while its previous reply was owed.
    assert!(srv.tag_collisions().is_empty(), "reused tags {:?}", srv.tag_collisions());
}

#[test]
fn a_long_sequence_of_walks_leaks_no_server_handle() {
    let (srv, c) = session();
    for i in 0..100 { srv.add_file(0, &alloc::format!("g{i}"), b"y"); }
    {
        let root = c.attach(None, "root", "", 0).unwrap();
        for i in 0..100 {
            let name = alloc::format!("g{i}");
            let f = c.walk(&root, &[name.as_str()], true).unwrap();
            drop(f);
        }
    }
    assert_eq!(c.live_fids(), 0);
    assert!(srv.leaked_fids().is_empty(), "leaked {:?}", srv.leaked_fids());
    // Every handle was clunked once and only once.
    let clunked = srv.state.lock().unwrap().clunked.clone();
    let uniq: alloc::collections::BTreeSet<u32> = clunked.iter().copied().collect();
    assert_eq!(uniq.len(), clunked.len(), "double clunk in {clunked:?}");
}

#[test]
fn mkdir_then_walk_into_it() {
    let (srv, c) = session();
    let root = c.attach(None, "root", "", 0).unwrap();
    c.mkdir(&root, "made", 0o755, 0).unwrap();
    let d = c.walk(&root, &["made"], true).unwrap();
    assert!(d.qid().is_dir());
    let h = c.clone_fid(&d).unwrap();
    c.lcreate(&h, "inner", dotl::RDWR, 0o644, 0).unwrap();
    c.write(&h, 0, b"nested").unwrap();
    drop(h);
    let f = c.walk(&root, &["made", "inner"], true).unwrap();
    c.lopen(&f, dotl::RDONLY).unwrap();
    let mut b = [0u8; 16];
    let n = c.read(&f, 0, &mut b).unwrap();
    assert_eq!(&b[..n], b"nested");
    drop(f); drop(d); drop(root);
    assert!(srv.leaked_fids().is_empty(), "leaked {:?}", srv.leaked_fids());
}

#[test]
fn a_disconnected_session_fails_fast_instead_of_parking() {
    let (_srv, c) = session();
    let root = c.attach(None, "root", "", 0).unwrap();
    c.shutdown();
    assert!(c.is_dead());
    assert_eq!(c.getattr(&root, stats::BASIC).unwrap_err(), NpError::Disconnected);
    // Tearing down a dead session releases its handles locally rather than
    // parking on a server that will never answer.
    drop(root);
    assert_eq!(c.live_fids(), 0);
}

#[test]
fn a_failing_flush_is_not_itself_flushed() {
    // A `Tflush` abandoned the way an ordinary request is sends another
    // `Tflush`, whose failure sends another: the recursion runs the stack out
    // and takes the whole kernel with it. Reached here by a transport that
    // never completes anything, which is what a dead server looks like.
    struct DeadTransport;
    impl crate::transport::Transport for DeadTransport {
        fn attach_sink(&self, _sink: alloc::sync::Weak<dyn crate::transport::ReplySink>) {}
        fn submit(&self, _req: &Arc<crate::client::Request>) -> Result<(), NpError> { Ok(()) }
        fn max_msize(&self) -> u32 { limits::DEFAULT_MSIZE }
        fn is_connected(&self) -> bool { true }
    }
    let t: TransportRef = Arc::new(DeadTransport);
    let c = Client::new(t, Dialect::DotL, limits::DEFAULT_MSIZE).unwrap();
    // Every request fails, including the flush each failure would provoke.
    assert!(c.flush(7).is_err());
    assert!(c.statfs(&c.new_fid(0).unwrap()).is_err());
    // And the tags all came back rather than leaking on the way out.
    assert_eq!(c.in_flight(), 0);
}
