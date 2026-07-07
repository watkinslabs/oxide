// Hosted logic tests for the non-user-mem parts of libaio: context
// registry lifecycle, id uniqueness, event-queue push/drain/len bounds,
// io_cancel/io_destroy errno contract. User-ptr paths (setup/submit/
// getevents copy-in/out) need a live AS and are boot-verified via
// userspace/aio_probe.
//
// NOTE: the `syscalls` crate root is `#![cfg(target_os = "oxide-kernel")]`,
// so `cargo test -p syscalls` on the host compiles an empty crate and runs
// these under no configuration. They document + guard the invariants for a
// kernel-context or future hosted-test build.

use super::*;

fn ctx(max: u32) -> AioContext { AioContext::new(max) }

#[test]
fn push_respects_capacity() {
    let c = ctx(2);
    let ev = |r: i64| IoEvent { data: 0, obj: 0, res: r, res2: 0 };
    assert!(c.push(ev(1)));
    assert!(c.push(ev(2)));
    assert!(!c.push(ev(3)));   // full → rejected
    assert_eq!(c.len(), 2);
}

#[test]
fn drain_pops_fifo_and_clamps() {
    let c = ctx(8);
    for r in 0..5i64 { assert!(c.push(IoEvent { data: r as u64, obj: 0, res: r, res2: 0 })); }
    let first = c.drain(3);
    assert_eq!(first.len(), 3);
    assert_eq!(first[0].res, 0);
    assert_eq!(first[2].res, 2);
    assert_eq!(c.len(), 2);
    let rest = c.drain(100);   // clamps to available
    assert_eq!(rest.len(), 2);
    assert_eq!(rest[0].res, 3);
    assert_eq!(c.len(), 0);
    assert!(c.drain(4).is_empty());
}

#[test]
fn registry_insert_lookup_remove() {
    let ctx0 = Arc::new(ctx(4));
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    REG.lock().insert(id, ctx0);
    assert!(lookup(id).is_some());
    assert!(REG.lock().remove(&id).is_some());
    assert!(lookup(id).is_none());
    assert!(REG.lock().remove(&id).is_none());
}

#[test]
fn ids_are_unique_monotonic() {
    let a = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let b = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    assert_ne!(a, b);
    assert!(b > a);
}

#[test]
fn cancel_is_einval() {
    let a = SyscallArgs { a0: 999_999, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 };
    assert_eq!(sys_io_cancel(&a), err(Errno::Einval));
}

#[test]
fn destroy_unknown_is_einval() {
    let a = SyscallArgs { a0: 987_654, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 };
    assert_eq!(sys_io_destroy(&a), err(Errno::Einval));
}

#[test]
fn dispatch_unknown_opcode_is_einval() {
    assert_eq!(dispatch_iocb(4242, 0, 0, 0, 0), Err(err(Errno::Einval)));
}
