// Hosted tests for the pseudo-FS primitive. Procfs / sysfs / devfs
// per `19§4`-§5 / `19§6` use this skeleton; per-FS-specific surface
// tests land alongside their consumers.

extern crate alloc;
use super::*;
use crate::pseudo::*;

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

#[test]
fn empty_fs_lists_empty_root() {
    let fs = PseudoFs::new();
    assert!(fs.exists("/"));
    assert_eq!(fs.list("/").unwrap(), Vec::<alloc::string::String>::new());
}

#[test]
fn mkdir_chain_creates_each_component() {
    let fs = PseudoFs::new();
    fs.mkdir("/proc/sys/kernel").unwrap();
    assert!(fs.exists("/proc"));
    assert!(fs.exists("/proc/sys"));
    assert!(fs.exists("/proc/sys/kernel"));
    let l = fs.list("/proc/sys").unwrap();
    assert_eq!(l, vec!["kernel".to_string()]);
}

#[test]
fn mkdir_idempotent() {
    let fs = PseudoFs::new();
    fs.mkdir("/proc/sys").unwrap();
    fs.mkdir("/proc/sys").unwrap(); // no-op
    fs.mkdir("/proc/sys/x").unwrap();
    assert!(fs.exists("/proc/sys/x"));
}

#[test]
fn mkdir_into_leaf_is_enotdir() {
    let fs = PseudoFs::new();
    fs.register("/", PseudoLeaf {
        name: "version".to_string(),
        mode: 0o444,
        ops:  Arc::new(StaticBytesOps(b"oxide v0\n")),
    }).unwrap();
    assert_eq!(fs.mkdir("/version/inside").err(), Some(PseudoError::Enotdir));
}

#[test]
fn register_leaf_then_read_static() {
    let fs = PseudoFs::new();
    fs.register("/", PseudoLeaf {
        name: "version".to_string(),
        mode: 0o444,
        ops:  Arc::new(StaticBytesOps(b"oxide kernel v0.1\n")),
    }).unwrap();
    let bytes = fs.read("/version").unwrap();
    assert_eq!(&bytes[..], b"oxide kernel v0.1\n");
}

#[test]
fn register_collision_is_eexist() {
    let fs = PseudoFs::new();
    fs.register("/", PseudoLeaf {
        name: "x".to_string(), mode: 0, ops: Arc::new(StaticBytesOps(b"a")),
    }).unwrap();
    let err = fs.register("/", PseudoLeaf {
        name: "x".to_string(), mode: 0, ops: Arc::new(StaticBytesOps(b"b")),
    }).err();
    assert_eq!(err, Some(PseudoError::Eexist));
    // Original still readable.
    assert_eq!(fs.read("/x").unwrap(), b"a".to_vec());
}

#[test]
fn read_directory_is_eisdir() {
    let fs = PseudoFs::new();
    fs.mkdir("/proc").unwrap();
    assert_eq!(fs.read("/proc").err(), Some(PseudoError::Eisdir));
}

#[test]
fn read_missing_is_enoent() {
    let fs = PseudoFs::new();
    assert_eq!(fs.read("/nope").err(), Some(PseudoError::Enoent));
}

#[test]
fn dynamic_ops_returns_fresh_value() {
    // Counter that increments on every read — verifies the closure
    // path snapshots per call, not at register time.
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let fs = PseudoFs::new();
    fs.register("/", PseudoLeaf {
        name: "counter".to_string(),
        mode: 0o444,
        ops:  Arc::new(DynamicOps(|| {
            let v = COUNTER.fetch_add(1, Ordering::Relaxed);
            alloc::format!("{v}\n").into_bytes()
        })),
    }).unwrap();
    let a = fs.read("/counter").unwrap();
    let b = fs.read("/counter").unwrap();
    assert_eq!(a, b"0\n".to_vec());
    assert_eq!(b, b"1\n".to_vec());
}

#[test]
fn write_to_readonly_leaf_is_eperm() {
    let fs = PseudoFs::new();
    fs.register("/", PseudoLeaf {
        name: "ro".to_string(), mode: 0o444, ops: Arc::new(StaticBytesOps(b"x")),
    }).unwrap();
    assert_eq!(fs.write("/ro", b"y").err(), Some(PseudoError::Eperm));
}

struct WritableSink(sync::Spinlock<Vec<u8>, sync::Inode>);

impl PseudoOps for WritableSink {
    fn read(&self) -> Vec<u8> { self.0.lock().clone() }
    fn write(&self, buf: &[u8]) -> KResult<usize> {
        let mut g = self.0.lock();
        g.clear();
        g.extend_from_slice(buf);
        Ok(buf.len())
    }
}

#[test]
fn writable_leaf_round_trip() {
    let fs = PseudoFs::new();
    let sink = Arc::new(WritableSink(sync::Spinlock::new(Vec::new())));
    fs.register("/", PseudoLeaf {
        name: "w".to_string(), mode: 0o644, ops: sink.clone(),
    }).unwrap();
    let n = fs.write("/w", b"hello").unwrap();
    assert_eq!(n, 5);
    assert_eq!(fs.read("/w").unwrap(), b"hello".to_vec());
}

#[test]
fn unregister_leaf_removes_it() {
    let fs = PseudoFs::new();
    fs.register("/", PseudoLeaf {
        name: "x".to_string(), mode: 0, ops: Arc::new(StaticBytesOps(b"a")),
    }).unwrap();
    assert!(fs.exists("/x"));
    fs.unregister("/x").unwrap();
    assert!(!fs.exists("/x"));
    assert_eq!(fs.read("/x").err(), Some(PseudoError::Enoent));
}

#[test]
fn unregister_non_empty_dir_is_einval() {
    let fs = PseudoFs::new();
    fs.mkdir("/d").unwrap();
    fs.register("/d", PseudoLeaf {
        name: "k".to_string(), mode: 0, ops: Arc::new(StaticBytesOps(b"v")),
    }).unwrap();
    assert_eq!(fs.unregister("/d").err(), Some(PseudoError::Einval));
    // Once the leaf is gone the directory is removable.
    fs.unregister("/d/k").unwrap();
    fs.unregister("/d").unwrap();
}

#[test]
fn list_returns_sorted_names() {
    let fs = PseudoFs::new();
    for name in ["zzz", "aaa", "mmm"] {
        fs.register("/", PseudoLeaf {
            name: name.to_string(), mode: 0, ops: Arc::new(StaticBytesOps(b"")),
        }).unwrap();
    }
    let l = fs.list("/").unwrap();
    assert_eq!(l, vec!["aaa".to_string(), "mmm".to_string(), "zzz".to_string()]);
}

#[test]
fn split_repeated_slashes_and_dots() {
    let fs = PseudoFs::new();
    // Both forms must reach the same node.
    fs.mkdir("/proc").unwrap();
    fs.register("/proc", PseudoLeaf {
        name: "version".to_string(), mode: 0, ops: Arc::new(StaticBytesOps(b"v0")),
    }).unwrap();
    assert_eq!(fs.read("//proc//./version").unwrap(), b"v0".to_vec());
}

// ---------------------------------------------------------------------------
// /proc/... path parser per `19§4`
// ---------------------------------------------------------------------------

#[test]
fn parse_proc_self_dir() {
    use crate::paths::*;
    assert_eq!(parse_proc_path("/proc/self"), ProcPath::SelfDir);
    assert_eq!(parse_proc_path("/proc/self/"), ProcPath::SelfDir);
}

#[test]
fn parse_proc_self_child() {
    use crate::paths::*;
    assert_eq!(parse_proc_path("/proc/self/status"), ProcPath::SelfChild("status"));
    assert_eq!(parse_proc_path("/proc/self/fd/0"),   ProcPath::SelfChild("fd/0"));
}

#[test]
fn parse_proc_pid_dir() {
    use crate::paths::*;
    assert_eq!(parse_proc_path("/proc/1"),    ProcPath::PidDir(1));
    assert_eq!(parse_proc_path("/proc/1234"), ProcPath::PidDir(1234));
    assert_eq!(parse_proc_path("/proc/4096/"), ProcPath::PidDir(4096));
}

#[test]
fn parse_proc_pid_child() {
    use crate::paths::*;
    assert_eq!(parse_proc_path("/proc/42/status"),
               ProcPath::PidChild(42, "status"));
    assert_eq!(parse_proc_path("/proc/42/fd/3"),
               ProcPath::PidChild(42, "fd/3"));
}

#[test]
fn parse_proc_non_proc() {
    use crate::paths::*;
    assert_eq!(parse_proc_path("/dev/null"),  ProcPath::NotProc);
    assert_eq!(parse_proc_path("/proc"),      ProcPath::NotProc);
    assert_eq!(parse_proc_path("/proc/"),     ProcPath::NotProc);
    // Non-numeric, non-self head is rejected (static /proc/version etc
    // is handled by the flat devfs registry, not the dynamic resolver).
    assert_eq!(parse_proc_path("/proc/bogus"), ProcPath::NotProc);
    assert_eq!(parse_proc_path(""),            ProcPath::NotProc);
}

#[test]
fn parse_proc_pid_overflow_rejected() {
    use crate::paths::*;
    // u32::MAX + 1
    assert_eq!(parse_proc_path("/proc/4294967296/status"), ProcPath::NotProc);
}

#[test]
fn child_under_root() {
    use crate::paths::*;
    assert_eq!(child_under("/", "/null"),     Some("null"));
    assert_eq!(child_under("/", "/dev"),      Some("dev"));
    assert_eq!(child_under("/", "/dev/null"), None);
    assert_eq!(child_under("/", "/"),         None);
}

#[test]
fn child_under_nested() {
    use crate::paths::*;
    assert_eq!(child_under("/dev", "/dev/null"),     Some("null"));
    assert_eq!(child_under("/dev", "/dev/tty1"),     Some("tty1"));
    assert_eq!(child_under("/dev", "/dev/null/x"),   None);
    assert_eq!(child_under("/dev", "/dev"),          None);
    assert_eq!(child_under("/dev", "/devnull"),      None);
    assert_eq!(child_under("/dev", "/etc/passwd"),   None);
}
