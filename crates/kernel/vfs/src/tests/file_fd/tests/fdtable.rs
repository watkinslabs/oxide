use super::*;

#[test]
fn fdtable_alloc_lowest_first() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let c = t.alloc(mk_file()).unwrap();
    assert_eq!((a, b, c), (0, 1, 2));
}

#[test]
fn fdtable_close_then_realloc_fills_hole() {
    let t = FdTable::new();
    let _ = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let _ = t.alloc(mk_file()).unwrap();
    t.close(b).unwrap();
    assert_eq!(t.alloc(mk_file()).unwrap(), b);
}

#[test]
fn fdtable_close_invalid_fd() {
    let t = FdTable::new();
    assert_eq!(t.close(0),  Err::<(), _>(VfsError::Ebadf));
    assert_eq!(t.close(-1), Err::<(), _>(VfsError::Ebadf));
}

#[test]
fn fdtable_dup_yields_new_fd_same_file() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.dup(a).unwrap();
    assert_ne!(a, b);
    assert!(Arc::ptr_eq(&t.get(a).unwrap(), &t.get(b).unwrap()));
}

#[test]
fn fdtable_dup2_replaces_existing() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    assert_eq!(t.dup2(a, b).unwrap(), b);
    assert!(Arc::ptr_eq(&t.get(a).unwrap(), &t.get(b).unwrap()));
}

#[test]
fn fdtable_dup2_same_fd_is_noop() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    assert_eq!(t.dup2(a, a).unwrap(), a);
}

#[test]
fn fdtable_cloexec_set_get() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    assert_eq!(t.cloexec(a).unwrap(), false);
    t.set_cloexec(a, true).unwrap();
    assert_eq!(t.cloexec(a).unwrap(), true);
    assert_eq!(t.set_cloexec(99, true), Err(VfsError::Ebadf));
}

#[test]
fn fdtable_close_on_exec_drops_marked() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let c = t.alloc(mk_file()).unwrap();
    t.set_cloexec(b, true).unwrap();
    t.close_on_exec();
    assert!(t.get(a).is_ok());
    assert_eq!(t.get(b).err(), Some(VfsError::Ebadf));
    assert!(t.get(c).is_ok());
}

#[test]
fn fdtable_concurrent_alloc_close() {
    use std::sync::Arc as StdArc;
    use std::thread;
    let t: StdArc<FdTable> = StdArc::new(FdTable::new());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let t = StdArc::clone(&t);
        handles.push(thread::spawn(move || {
            for _ in 0..200 {
                if let Ok(fd) = t.alloc(mk_file()) { let _ = t.close(fd); }
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(t.count(), 0);
}

#[test]
fn fdtable_live_fds_empty() {
    let t = FdTable::new();
    assert!(t.live_fds().is_empty());
}

#[test]
fn fdtable_live_fds_ascending_skips_holes() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let c = t.alloc(mk_file()).unwrap();
    t.close(b).unwrap();
    assert_eq!(t.live_fds(), alloc::vec![a, c]);
}

#[test]
fn fdtable_live_fds_after_dup_then_close_range_semantics() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let c = t.alloc(mk_file()).unwrap();
    let d = t.alloc(mk_file()).unwrap();
    for fd in t.live_fds() {
        if fd >= b && fd <= d { t.close(fd).unwrap(); }
    }
    assert_eq!(t.live_fds(), alloc::vec![a]);
    let _ = c;
}

#[test]
fn fdtable_live_fds_cloexec_only_range() {
    let t = FdTable::new();
    let a = t.alloc(mk_file()).unwrap();
    let b = t.alloc(mk_file()).unwrap();
    let c = t.alloc(mk_file()).unwrap();
    for fd in t.live_fds() {
        if fd >= a && fd <= b { t.set_cloexec(fd, true).unwrap(); }
    }
    assert!(t.cloexec(a).unwrap());
    assert!(t.cloexec(b).unwrap());
    assert!(!t.cloexec(c).unwrap());
    assert_eq!(t.live_fds(), alloc::vec![a, b, c]);
}

