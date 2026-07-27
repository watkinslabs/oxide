//! `semget` key, creation and permission rules.

use syscall::errno::Errno;

use super::super::super::limits::{IPC_CREAT, IPC_EXCL, IPC_PRIVATE, SEMMSL, S_IRWXUGO};
use super::super::{model, semget_in};
use super::common::{cred, ns, reset, root, TEST_LOCK};

#[test]
fn private_key_always_creates_a_distinct_set() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ns, c) = (ns(), root());
    let a = semget_in(ns, &c, IPC_PRIVATE, 4, 0o600).unwrap();
    let b = semget_in(ns, &c, IPC_PRIVATE, 4, 0o600).unwrap();
    assert_ne!(a, b, "IPC_PRIVATE never joins an existing set");
}

#[test]
fn missing_key_without_ipc_creat_is_enoent() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ns, c) = (ns(), root());
    assert_eq!(semget_in(ns, &c, 7, 1, 0o600), Err(Errno::Enoent));
    assert!(semget_in(ns, &c, 7, 1, IPC_CREAT | 0o600).is_ok());
}

#[test]
fn existing_key_with_creat_excl_is_eexist() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, 7, 2, IPC_CREAT | 0o600).unwrap();
    assert_eq!(semget_in(ns, &c, 7, 2, IPC_CREAT | IPC_EXCL | 0o600), Err(Errno::Eexist));
    assert_eq!(semget_in(ns, &c, 7, 2, IPC_CREAT | 0o600), Ok(id), "plain CREAT rejoins");
    assert_eq!(semget_in(ns, &c, 7, 0, 0o600), Ok(id), "nsems 0 skips the width check");
}

#[test]
fn nsems_out_of_range_is_einval_before_the_key_is_consulted() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ns, c) = (ns(), root());
    assert_eq!(semget_in(ns, &c, IPC_PRIVATE, -1, 0o600), Err(Errno::Einval));
    assert_eq!(semget_in(ns, &c, IPC_PRIVATE, SEMMSL as i32 + 1, 0o600), Err(Errno::Einval));
    // A key that does not exist still reports EINVAL, not ENOENT: ksys_semget
    // bounds nsems before ipcget runs.
    assert_eq!(semget_in(ns, &c, 9, -1, 0o600), Err(Errno::Einval));
    // Creation with nsems == 0 is newary's EINVAL.
    assert_eq!(semget_in(ns, &c, IPC_PRIVATE, 0, 0o600), Err(Errno::Einval));
}

#[test]
fn wider_request_than_existing_set_is_einval() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, 11, 2, IPC_CREAT | 0o600).unwrap();
    assert_eq!(semget_in(ns, &c, 11, 3, 0o600), Err(Errno::Einval), "sem_more_checks");
    assert_eq!(semget_in(ns, &c, 11, 1, 0o600), Ok(id), "narrower is fine");
}

#[test]
fn mode_is_the_low_nine_bits_of_semflg() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 1, IPC_CREAT | IPC_EXCL | 0o642).unwrap();
    let set = model::lookup_checked(ns, id).unwrap();
    let mode = set.perm.mode.load(core::sync::atomic::Ordering::Acquire);
    assert_eq!(mode, 0o642);
    assert_eq!(mode & !S_IRWXUGO, 0, "IPC_CREAT/IPC_EXCL never reach the mode");
}

#[test]
fn permission_mismatch_on_an_existing_key_is_eacces() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let ns = ns();
    let owner = cred(1000, 1000);
    let other = cred(1001, 1001);
    let id = semget_in(ns, &owner, 21, 1, IPC_CREAT | 0o600).unwrap();
    assert_eq!(semget_in(ns, &other, 21, 1, 0o600), Err(Errno::Eacces));
    assert_eq!(semget_in(ns, &owner, 21, 1, 0o600), Ok(id));
    // CAP_IPC_OWNER overrides the mode check, as ipcperms does.
    assert_eq!(semget_in(ns, &root(), 21, 1, 0o600), Ok(id));
}
