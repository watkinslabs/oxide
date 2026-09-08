//! Two NT processes on one desktop must not disturb each other.
//!
//! Driven against the real owners: `ipc`'s window managers stand in for the
//! two processes' GUI state, `sched`'s desktop object for the desktop they
//! share, and the handle space for the values both draw from. The failures
//! reproduced here are the ones a second instance of a Windows application
//! hit: its windows carried the first instance's handle values, its
//! `GetDesktopWindow` answered the first instance's own window, and its
//! `GetDC(NULL)` answered nothing at all.

use alloc::sync::Arc;
extern crate alloc;

use ipc::win32_window::{handle_space, DcLeaseContext, WindowManager, WindowRect};
use sched::nt_object::{DesktopError, NtObject, NtObjectType, ThreadDesktop};

/// One process's GUI state, drawing handles from its own block of the
/// system-wide space, exactly as the kernel's per-process GUI entry does.
fn process(taken: u32) -> WindowManager { WindowManager::new_in_block(handle_space::owner_block(taken)) }

fn station() -> Arc<NtObject> { NtObject::new(NtObjectType::WindowStation, 1) }

/// A desktop with two threads attached, one per process.
fn shared_desktop() -> (Arc<NtObject>, Arc<NtObject>, ThreadDesktop, ThreadDesktop) {
    let station = station();
    let desktop = NtObject::new_desktop(2, Arc::clone(&station)).unwrap();
    let mut first = ThreadDesktop::default();
    let mut second = ThreadDesktop::default();
    first.select(&station, Arc::clone(&desktop), false).unwrap();
    second.select(&station, Arc::clone(&desktop), false).unwrap();
    (station, desktop, first, second)
}

#[test]
fn two_processes_never_give_two_windows_the_same_handle() {
    let (mut first, mut second) = (process(0), process(1));
    let a = first.create(11, None, 0x1000).unwrap();
    let b = second.create(22, None, 0x1000).unwrap();
    assert_ne!(a.raw(), b.raw(), "a second process's first window took the first's handle");
    // Neither process's handle names anything in the other, so nothing that
    // resolves a handle can answer with the wrong process's window.
    assert!(first.get(b).is_none());
    assert!(second.get(a).is_none());
    // Nor do later windows collide as each process goes on creating.
    let mut seen = alloc::vec::Vec::new();
    for _ in 0..8 {
        seen.push(first.create(11, None, 0x1000).unwrap().raw());
        seen.push(second.create(22, None, 0x1000).unwrap().raw());
    }
    let count = seen.len();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), count, "two processes handed out one handle value twice");
}

#[test]
fn both_processes_resolve_one_desktop_window_that_is_neither_of_theirs() {
    let (station, desktop, first_thread, second_thread) = shared_desktop();
    let (mut first, mut second) = (process(0), process(1));
    let first_window = first.create(11, None, 0x1000).unwrap();
    let second_window = second.create(22, None, 0x1000).unwrap();

    // Before anything establishes it, the desktop has no window.
    assert_eq!(first_thread.resolve_root(&station), Err(DesktopError::MissingRoot));

    let established = desktop.desktop().unwrap().publish_root(handle_space::desktop_handle(0)).unwrap();
    assert_eq!(first_thread.resolve_root(&station).unwrap(), established);
    assert_eq!(second_thread.resolve_root(&station).unwrap(), established);

    // The defect: the desktop window used to be the first process's own first
    // top-level window, so the second process's GetDesktopWindow answered a
    // handle that named the second process's own main window locally.
    assert_ne!(established, first_window.raw());
    assert_ne!(established, second_window.raw());
    assert!(first.get(ipc::win32_window::WindowId::from_raw(established).unwrap()).is_none());
    assert!(second.get(ipc::win32_window::WindowId::from_raw(established).unwrap()).is_none());
}

#[test]
fn a_second_process_attaching_later_is_answered_with_the_established_desktop_window() {
    let station = station();
    let desktop = NtObject::new_desktop(2, Arc::clone(&station)).unwrap();
    let payload = desktop.desktop().unwrap();
    // Each process establishes the desktop window on its first request; the
    // second is answered with what the first named, never refused.
    let first = payload.publish_root(handle_space::desktop_handle(0)).unwrap();
    let second = payload.publish_root(handle_space::desktop_handle(1)).unwrap();
    assert_eq!(first, second);
}

#[test]
fn every_process_on_the_desktop_gets_a_desktop_device_context() {
    let (station, desktop, first_thread, second_thread) = shared_desktop();
    let screen = WindowRect { left: 0, top: 0, right: 1280, bottom: 1024 };
    desktop.desktop().unwrap().publish_root(handle_space::desktop_handle(0)).unwrap();

    for thread in [&first_thread, &second_thread] {
        let hwnd = thread.resolve_root(&station).unwrap();
        // The lease comes from the desktop's own rectangle, so it needs no
        // window record in the asking process. The second process used to be
        // refused here and its GetDC(NULL) returned NULL.
        let lease = DcLeaseContext::desktop(hwnd, screen).unwrap();
        assert_eq!(lease.hwnd, hwnd);
        assert_eq!((lease.logical_width, lease.logical_height), (1280, 1024));
        assert_eq!(lease.visible.bounds(), Some(screen));
    }
}

/// A window whose parent is the desktop window is a top-level window: the
/// desktop belongs to no process, so no process's window manager holds it.
#[test]
fn a_window_parented_to_the_desktop_is_top_level_in_either_process() {
    let (station, desktop, first_thread, second_thread) = shared_desktop();
    desktop.desktop().unwrap().publish_root(handle_space::desktop_handle(0)).unwrap();
    let root = first_thread.resolve_root(&station).unwrap();
    assert_eq!(second_thread.resolve_root(&station).unwrap(), root);
    assert!(handle_space::is_server_handle(root));

    for taken in [0, 1] {
        let mut state = process(taken);
        // Passed through as a parent it names nothing, which is why the
        // dispatch boundary must map it to no parent at all instead.
        assert!(state.create(7, ipc::win32_window::WindowId::from_raw(root), 0x1000).is_err());
        let top = state.create(7, None, 0x1000).unwrap();
        assert!(state.get(top).unwrap().parent.is_none());
        assert!(!handle_space::is_server_handle(top.raw()));
    }
}

/// One process exhausting its own block never reaches into another's.
#[test]
fn a_process_that_spends_its_block_takes_no_handle_from_another() {
    let mut starved = WindowManager::new_in_block(handle_space::owner_block(handle_space::MAX_BLOCK));
    assert!(starved.create(7, None, 0x1000).is_err());
    let mut neighbour = process(0);
    assert!(neighbour.create(7, None, 0x1000).is_ok());
}
