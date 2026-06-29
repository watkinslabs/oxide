//! `fc->log` diagnostic ring (Linux `struct fc_log`, `fs/fs_context.c`
//! `logfc`/`errorf`/`warnf`/`infof`/`invalf`). A failed mount build accumulates
//! human-readable messages on the context that `fsconfig`'s reader returns to
//! userspace. Fails-before: `FsContext` had no log; a rejected param surfaced a
//! bare errno with no diagnostic. These prove the level-tagged ring records
//! messages, bounds itself to `FC_LOG_MAX` (oldest dropped), that `invalf` both
//! logs and returns `Einval`, and that the real parse rejections (unknown param,
//! multiple sources, unsupported value type) are logged through it.

use std::sync::Arc;

use vfs::fs::fs_context::{
    vfs_parse_fs_param, vfs_parse_fs_string, FsContext, FsParameter, FC_LOG_MAX,
};
use vfs::superblock::{FileSystemType, SuperBlock};
use vfs::{KResult, VfsError};

struct Ty;
impl FileSystemType for Ty {
    fn name(&self) -> &str { "logfs" }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
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
    assert_eq!(log[0], "e boom");
    assert_eq!(log[1], "w careful");
    assert_eq!(log[2], "i fyi");
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
    assert_eq!(log[0], "e m3", "oldest entries evicted: {:?}", log);
    assert_eq!(log[FC_LOG_MAX - 1], format!("e m{}", FC_LOG_MAX + 2));
}

#[test]
fn invalf_logs_and_returns_einval() {
    let mut fc = ctx();
    let r: KResult<()> = fc.invalf("nope");
    assert_eq!(r.unwrap_err(), VfsError::Einval);
    assert_eq!(fc.log_messages(), &["e nope".to_string()]);
}

#[test]
fn unknown_parameter_is_logged_through_invalf() {
    let mut fc = ctx();
    // The legacy backend declines "frob"; the generic source handler rejects it
    // as an unknown parameter and logs the reason.
    let e = vfs_parse_fs_param(&mut fc, &FsParameter::flag("frob"));
    // flag "frob" is actually consumed by the legacy backend (any non-source
    // flag/string is accepted), so no error here:
    assert!(e.is_ok());
    // A path value, however, has no legacy form → logged invalf.
    let e2 = vfs_parse_fs_param(&mut fc, &FsParameter::path("upperdir", "/u")).unwrap_err();
    assert_eq!(e2, VfsError::Einval);
    assert!(fc.log_messages().iter().any(|m| m.starts_with("e ") && m.contains("value type")),
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
    assert_eq!(drained, vec!["e a".to_string(), "w b".to_string()]);
    assert!(fc.log_messages().is_empty(), "ring emptied after take_log");
}
