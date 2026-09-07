//! The order one pass of kernel-owned drawing reaches the surface in.
use super::*;
use core::cell::RefCell;

/// What the surface saw, in the order it saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event { Fill(u32), Launch(u32), Done(u32), Refused(u32), Present(u64) }

fn nothing(_hwnd: u64, _dc: u64) {}

fn request(id: u32) -> TextRequest {
    TextRequest { version: syscall::nt_native_gdi::VERSION, size: core::mem::size_of::<TextRequest>() as u32,
        dc: 0x40, x: id as i32, y: 0, flags: 0, count: 1, text: 0, advances: 0, rect: [0; 4],
        height: 16, width: 0, weight: 400, italic: 0, foreground: 0, background: 0, has_rect: 0, reserved: 0,
        background_mode: 1, alignment: 0, current_x: 0, current_y: 0, break_extra: 0, break_rem: 0 }
}

struct Thread { queue: Queue, log: alloc::vec::Vec<Event>, backend: Option<u32>, deny: alloc::vec::Vec<u32>, peak: usize }

impl Thread {
    fn new() -> RefCell<Self> {
        RefCell::new(Self { queue: Queue::new(), log: alloc::vec::Vec::new(), backend: None, deny: alloc::vec::Vec::new(), peak: 0 })
    }
}

/// The kernel pass and every later completion both drive the same queue.
fn pump(thread: &RefCell<Thread>, first: Next) {
    drive(first,
        |run| {
            let mut owner = thread.borrow_mut();
            let id = run.request.x as u32;
            if owner.deny.contains(&id) { owner.log.push(Event::Refused(id)); return false; }
            assert!(owner.backend.is_none(), "a second run entered the backend while one was rasterizing");
            owner.backend = Some(id);
            owner.log.push(Event::Launch(id));
            let depth = owner.queue.depth();
            owner.peak = owner.peak.max(depth);
            true
        },
        |owed| { let mut owner = thread.borrow_mut(); owner.log.push(Event::Present(owed.hwnd)); (owed.finish)(owed.hwnd, owed.dc); },
        || thread.borrow_mut().queue.advance());
}

fn fill(thread: &RefCell<Thread>, id: u32) { thread.borrow_mut().log.push(Event::Fill(id)); }

fn text(thread: &RefCell<Thread>, id: u32) {
    let first = thread.borrow_mut().queue.submit(Run { request: request(id), text: alloc::vec![id as u16] });
    pump(thread, first);
}

fn end_paint(thread: &RefCell<Thread>, hwnd: u64) {
    let now = thread.borrow_mut().queue.defer_end(Owed { hwnd, dc: 0x40, finish: nothing });
    if let Some(owed) = now { let mut owner = thread.borrow_mut(); owner.log.push(Event::Present(owed.hwnd)); (owed.finish)(owed.hwnd, owed.dc); }
}

/// The font backend answers the run it was given and the thread continues.
fn backend_completes(thread: &RefCell<Thread>) {
    let id = thread.borrow_mut().backend.take().expect("no run was in the backend");
    thread.borrow_mut().log.push(Event::Done(id));
    let next = thread.borrow_mut().queue.advance();
    pump(thread, next);
}

fn log(thread: &RefCell<Thread>) -> alloc::vec::Vec<Event> { thread.borrow().log.clone() }

#[test]
fn present_follows_every_run_the_paint_issued() {
    let thread = Thread::new();
    // One menu paint: the ground, an item highlight, two item texts, the end.
    fill(&thread, 0); text(&thread, 1); fill(&thread, 2); text(&thread, 3);
    end_paint(&thread, 0x99);
    assert_eq!(log(&thread), alloc::vec![Event::Fill(0), Event::Launch(1), Event::Fill(2)],
        "the pass presents nothing while its first run is still in the backend");
    backend_completes(&thread);
    backend_completes(&thread);
    assert_eq!(log(&thread), alloc::vec![Event::Fill(0), Event::Launch(1), Event::Fill(2),
        Event::Done(1), Event::Launch(3), Event::Done(3), Event::Present(0x99)]);
}

#[test]
fn runs_rasterize_in_issue_order_at_depth_one() {
    let thread = Thread::new();
    for id in 0..8 { text(&thread, id); }
    end_paint(&thread, 1);
    for _ in 0..8 { backend_completes(&thread); }
    let launched: alloc::vec::Vec<u32> = log(&thread).iter().filter_map(|event| match event { Event::Launch(id) => Some(*id), _ => None }).collect();
    assert_eq!(launched, (0..8).collect::<alloc::vec::Vec<u32>>(), "runs must reach the backend in issue order, not reversed");
    assert_eq!(log(&thread).last(), Some(&Event::Present(1)));
    // Only one run is ever redirected: the rest wait in the queue, not on the
    // bounded per-thread continuation stack.
    assert!(thread.borrow().backend.is_none());
}

#[test]
fn a_refused_run_still_presents_the_fills() {
    let thread = Thread::new();
    thread.borrow_mut().deny.push(2);
    fill(&thread, 0); text(&thread, 1); text(&thread, 2); text(&thread, 3);
    end_paint(&thread, 7);
    backend_completes(&thread);
    backend_completes(&thread);
    assert_eq!(log(&thread), alloc::vec![Event::Fill(0), Event::Launch(1), Event::Done(1),
        Event::Refused(2), Event::Launch(3), Event::Done(3), Event::Present(7)]);
}

#[test]
fn a_pass_without_text_presents_in_the_same_pass() {
    let thread = Thread::new();
    fill(&thread, 0);
    end_paint(&thread, 5);
    assert_eq!(log(&thread), alloc::vec![Event::Fill(0), Event::Present(5)]);
    assert!(thread.borrow().queue.idle());
}

#[test]
fn a_second_paint_presents_after_its_own_runs() {
    let thread = Thread::new();
    text(&thread, 1); end_paint(&thread, 10);
    text(&thread, 2); end_paint(&thread, 20);
    backend_completes(&thread);
    backend_completes(&thread);
    assert_eq!(log(&thread), alloc::vec![Event::Launch(1), Event::Done(1), Event::Present(10),
        Event::Launch(2), Event::Done(2), Event::Present(20)]);
}

#[test]
fn teardown_reports_every_owed_end_once() {
    let thread = Thread::new();
    text(&thread, 1); end_paint(&thread, 10); text(&thread, 2); end_paint(&thread, 20);
    let owed = thread.borrow_mut().queue.cancel();
    assert_eq!(owed.len(), 2);
    assert_eq!(owed.iter().map(|end| end.hwnd).collect::<alloc::vec::Vec<u64>>(), alloc::vec![10, 20]);
    assert!(thread.borrow().queue.idle());
}

#[test]
fn the_queue_is_bounded() {
    let thread = Thread::new();
    for id in 0..(MAX_PENDING as u32 + 8) { text(&thread, id); }
    assert!(thread.borrow().queue.depth() <= MAX_PENDING);
    end_paint(&thread, 3);
    while thread.borrow().backend.is_some() { backend_completes(&thread); }
    let presents = log(&thread).iter().filter(|event| matches!(event, Event::Present(_))).count();
    assert_eq!(presents, 1, "the present happens exactly once even when the plan overflowed the queue");
    assert_eq!(log(&thread).last(), Some(&Event::Present(3)), "a full queue still holds the present until its runs drain");
}
