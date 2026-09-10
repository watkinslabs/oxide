//! Empty logical geometry must survive the display server's minimum drawable size.
use std::time::{Duration, Instant};
use crate::{Backend, BridgeCommand, BridgeEvent, Rect};
use crate::xvfb_harness::xvfb;

#[test]
fn empty_dimensions_do_not_return_as_real_one_pixel_windows() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    for (hwnd, width, height) in [(0xc1, 750, 0), (0xc2, 0, 480), (0xc3, 0, 0)] {
        backend.handle_command(BridgeCommand::Create { hwnd, title: Vec::new(),
            rect: Rect { left: 0, top: 0, right: width, bottom: height }, parent: 0,
            style: 0, ex_style: 0 }).unwrap();
        // Repeated moves each produce a server ConfigureNotify. Padding is
        // not a one-shot condition: the logical extent is still empty.
        for origin in [10, 20] {
            backend.handle_command(BridgeCommand::Configure { hwnd,
                rect: Rect { left: origin, top: origin, right: origin + width, bottom: origin + height } }).unwrap();
            let until = Instant::now() + Duration::from_millis(100);
            while Instant::now() < until {
                if let Some(BridgeEvent::Configure { hwnd: returned, rect }) = backend.poll_event() {
                    assert_ne!(returned, hwnd, "backing rectangle {rect:?} must not replace empty logical geometry");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(backend.window_layout_for_test(hwnd), Some((false, width as u32, height as u32)));
        }
        // A real one-row window is different: it must remain drawable and
        // keep delivering server position changes after the empty stage.
        backend.handle_command(BridgeCommand::Configure { hwnd,
            rect: Rect { left: 30, top: 30, right: 90, bottom: 31 } }).unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        let mut seen = false;
        while Instant::now() < until {
            if let Some(BridgeEvent::Configure { hwnd: returned, rect }) = backend.poll_event() {
                if returned == hwnd { assert_eq!(rect.bottom - rect.top, 1); seen = true; break; }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(seen, "a nonempty one-row window must report its real configure");
    }
}

#[test]
fn delayed_empty_backing_notification_cannot_undo_a_later_resize() {
    let server = xvfb();
    let mut backend = Backend::connect(Some(&server.display)).unwrap();
    let hwnd = 0xd1;
    backend.handle_command(BridgeCommand::Create { hwnd, title: Vec::new(),
        rect: Rect { left: 0, top: 0, right: 60, bottom: 30 }, parent: 0,
        style: 0, ex_style: 0 }).unwrap();
    backend.handle_command(BridgeCommand::Configure { hwnd,
        rect: Rect { left: 10, top: 10, right: 760, bottom: 10 } }).unwrap();
    // No event pump between requests: the empty backing notification can
    // already be queued when the application restores its logical size.
    backend.handle_command(BridgeCommand::Configure { hwnd,
        rect: Rect { left: 20, top: 20, right: 80, bottom: 50 } }).unwrap();
    let until = Instant::now() + Duration::from_millis(100);
    let mut seen = false;
    while Instant::now() < until {
        if let Some(BridgeEvent::Configure { hwnd: returned, rect }) = backend.poll_event() {
            assert_eq!(returned, hwnd);
            assert_eq!((rect.right - rect.left, rect.bottom - rect.top), (60, 30), "obsolete backing request escaped into application geometry");
            seen = true;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(seen);
}
