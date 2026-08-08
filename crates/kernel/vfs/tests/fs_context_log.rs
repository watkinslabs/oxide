//! `fc->log` diagnostic ring (Linux `struct fc_log`, the
//! `logfc`/`errorf`/`warnf`/`infof`/`invalf` helpers). A failed mount build accumulates
//! human-readable messages on the context that `fsconfig`'s reader returns to
//! userspace. Fails-before: `FsContext` had no log; a rejected param surfaced a
//! bare errno with no diagnostic. These prove the level-tagged ring records
//! messages, bounds itself to `FC_LOG_MAX` (oldest dropped), that `invalf` both
//! logs and returns `Einval`, and that the real parse rejections (unknown param,
//! multiple sources, unsupported value type) are logged through it.
//!
//! The stored form is the WIRE form: `read(2)` on the context descriptor hands
//! an entry back byte for byte, so the level character, the separating space
//! and the terminating newline are all part of the string and are pinned here.

use std::sync::Arc;

use vfs::fs::fs_context::{
    vfs_parse_fs_param, vfs_parse_fs_string, FsContext, FsParameter, FC_LOG_MAX,
};
use vfs::superblock::{FileSystemType, SuperBlock};
use vfs::{KResult, VfsError};

struct Ty;
impl FileSystemType for Ty {
    fn name(&self) -> &str { "logfs" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}
fn ctx() -> FsContext { FsContext::for_mount(Arc::new(Ty), 0) }

#[test]
fn level_tagged_messages_accumulate_oldest_first() {
    let mut fc = ctx();
    fc.errorf("boom");
    fc.warnf("careful");
    fc.infof("fyi");
    let log = fc.log_messages();
    assert_eq!(log.len(), 3);
    assert_eq!(log[0], "e boom\n");
    assert_eq!(log[1], "w careful\n");
    assert_eq!(log[2], "i fyi\n");
}

#[test]
fn ring_is_bounded_dropping_oldest() {
    let mut fc = ctx();
    for i in 0..(FC_LOG_MAX + 3) {
        // distinct message per push
        let m = format!("m{i}");
        fc.errorf(&m);
    }
    let log = fc.log_messages();
    assert_eq!(log.len(), FC_LOG_MAX, "ring capped at FC_LOG_MAX");
    // The first 3 (m0..m2) were dropped; the window starts at m3.
    assert_eq!(log[0], "e m3\n", "oldest entries evicted: {:?}", log);
    assert_eq!(log[FC_LOG_MAX - 1], format!("e m{}\n", FC_LOG_MAX + 2));
}

#[test]
fn invalf_logs_and_returns_einval() {
    let mut fc = ctx();
    let r: KResult<()> = fc.invalf("nope");
    assert_eq!(r.unwrap_err(), VfsError::Einval);
    assert_eq!(fc.log_messages(), &["e nope\n".to_string()]);
}

#[test]
fn unknown_parameter_is_logged_through_invalf() {
    let mut fc = ctx();
    // The classic mount backend declines "frob"; the generic source handler rejects it
    // as an unknown parameter and logs the reason.
    let e = vfs_parse_fs_param(&mut fc, &FsParameter::flag("frob"));
    // flag "frob" is actually consumed by the classic mount backend (any non-source
    // flag/string is accepted), so no error here:
    assert!(e.is_ok());
    // A path value, however, has no legacy form → logged invalf.
    let e2 = vfs_parse_fs_param(&mut fc, &FsParameter::path("upperdir", "/u")).unwrap_err();
    assert_eq!(e2, VfsError::Einval);
    assert!(fc.log_messages().iter().any(|m| m.starts_with("e ") && m.contains("path")),
        "unsupported value type logged: {:?}", fc.log_messages());
}

#[test]
fn multiple_sources_is_logged() {
    let mut fc = ctx();
    vfs_parse_fs_string(&mut fc, "source", "/dev/a").unwrap();
    let e = vfs_parse_fs_string(&mut fc, "source", "/dev/b").unwrap_err();
    assert_eq!(e, VfsError::Einval);
    assert!(fc.log_messages().iter().any(|m| m.contains("Multiple sources")),
        "multiple-sources diagnostic logged: {:?}", fc.log_messages());
}

#[test]
fn take_log_drains_the_ring() {
    let mut fc = ctx();
    fc.errorf("a");
    fc.warnf("b");
    let drained = fc.take_log();
    assert_eq!(drained, vec!["e a\n".to_string(), "w b\n".to_string()]);
    assert!(fc.log_messages().is_empty(), "ring emptied after take_log");
}

// `read(2)` on the context descriptor is the ONLY way userspace ever sees these
// messages: a rejected `fsconfig(2)` reports EINVAL and nothing else. Before
// this, every producer above wrote into a ring with no reader at all.
#[test]
fn one_message_per_read_oldest_first_then_no_data() {
    let mut fc = ctx();
    fc.errorf("first");
    fc.warnf("second");
    assert_eq!(fc.fetch_message(64).unwrap().as_deref(), Some("e first\n"));
    assert_eq!(fc.fetch_message(64).unwrap().as_deref(), Some("w second\n"));
    // An empty ring is "no data available", not end-of-file: the context is
    // quiet, not finished.
    assert_eq!(fc.fetch_message(64).unwrap(), None);
}

// A buffer too short must NOT consume the message. Truncating it would destroy
// the only copy of the diagnostic the caller asked for.
#[test]
fn a_short_buffer_reports_emsgsize_and_leaves_the_message_queued() {
    let mut fc = ctx();
    fc.errorf("a long enough diagnostic");
    let want = "e a long enough diagnostic\n";
    assert_eq!(fc.fetch_message(want.len() - 1).unwrap_err(), VfsError::Emsgsize);
    assert_eq!(fc.log_messages().len(), 1, "still queued after EMSGSIZE");
    // Exactly-fitting is a fit — the count is the byte length, newline
    // included and no NUL.
    assert_eq!(fc.fetch_message(want.len()).unwrap().as_deref(), Some(want));
}

// The reader drains the SAME ring the producers write, oldest first, so a
// rejection reported early is not shadowed by a later one.
#[test]
fn a_rejected_parameter_is_readable_and_names_the_parameter() {
    let mut fc = ctx();
    assert_eq!(vfs_parse_fs_param(&mut fc, &FsParameter::path("upperdir", "/u")).unwrap_err(),
        VfsError::Einval);
    let msg = fc.fetch_message(256).unwrap().expect("the refusal is readable");
    assert!(msg.starts_with("e "), "level-tagged: {msg:?}");
    assert!(msg.ends_with('\n'), "newline-terminated: {msg:?}");
}

// `read_message` is the whole of the descriptor's read: the file-operations
// entry point is `#![cfg(target_os = "oxide-kernel")]`, so anything decided
// there is untestable and the byte count, the ENODATA and the EMSGSIZE all
// belong here.
#[test]
fn read_message_returns_the_byte_count_and_fills_the_caller_buffer() {
    let mut fc = ctx();
    fc.errorf("nope");
    let mut buf = [0u8; 64];
    let n = fc.read_message(&mut buf).expect("one message");
    assert_eq!(&buf[..n], b"e nope\n");
    assert_eq!(n, "e nope\n".len(), "the count is bytes, newline included and no NUL");
    // Nothing is left behind, and the next call says so.
    assert_eq!(fc.read_message(&mut buf).unwrap_err(), VfsError::Enodata);
}

// An empty ring is ENODATA and NOT a zero-byte read: end-of-file would tell a
// caller the context is finished when it is merely quiet, and a userspace
// reader looping until EOF would stop asking.
#[test]
fn an_empty_ring_is_enodata_not_a_zero_length_read() {
    let mut fc = ctx();
    let mut buf = [0u8; 64];
    assert_eq!(fc.read_message(&mut buf).unwrap_err(), VfsError::Enodata);
    assert!(fc.log_messages().is_empty());
}

// A short buffer must not consume the message — the caller retries larger and
// gets it whole. A truncating read destroys the only copy of the diagnostic,
// and the caller cannot tell that it happened.
#[test]
fn read_message_leaves_a_too_long_message_queued_for_a_bigger_buffer() {
    let mut fc = ctx();
    fc.errorf("a long enough diagnostic");
    let want = "e a long enough diagnostic\n";
    let mut small = vec![0u8; want.len() - 1];
    assert_eq!(fc.read_message(&mut small).unwrap_err(), VfsError::Emsgsize);
    assert!(small.iter().all(|&b| b == 0), "nothing was copied out");
    let mut exact = vec![0u8; want.len()];
    let n = fc.read_message(&mut exact).expect("fits exactly");
    assert_eq!(&exact[..n], want.as_bytes());
}
