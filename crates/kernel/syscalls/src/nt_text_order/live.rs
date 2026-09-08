//! The current thread's ordered kernel text work: the plan's runs, the paint
//! end that owes its present to them, and the completion that drives both.
use super::{drive, Next, Owed, Queue, Run};
use alloc::vec::Vec;
use sync::{Spinlock, TaskList};
use ipc::win32_gdi::Font;
use syscall::nt_native_gdi::TextRequest;

/// One thread's outstanding work. A row exists only while its thread owes a
/// run or an end, so a thread that never draws kernel text costs nothing.
struct Row { tid: u64, queue: Queue }

static ORDER: Spinlock<Vec<Row>, TaskList> = Spinlock::new(Vec::new());

fn current_tid() -> Option<u64> {
    sched::live::current().filter(|task| task.is_nt_personality()).map(|task| task.tid as u64)
}

/// Run `work` against this thread's queue, creating the row on demand and
/// dropping it as soon as the thread owes nothing. # C: O(N_drawing_threads)
fn with_row<T>(tid: u64, work: impl FnOnce(&mut Queue) -> T) -> Option<T> {
    let mut rows = ORDER.lock();
    let index = match rows.iter().position(|row| row.tid == tid) {
        Some(index) => index,
        None => { rows.try_reserve(1).ok()?; rows.push(Row { tid, queue: Queue::new() }); rows.len() - 1 }
    };
    let value = work(&mut rows[index].queue);
    if rows[index].queue.idle() { rows.swap_remove(index); }
    Some(value)
}

/// As `with_row`, without creating a row for a thread that owes nothing.
/// # C: O(N_drawing_threads)
fn with_existing<T>(tid: u64, work: impl FnOnce(&mut Queue) -> T) -> Option<T> {
    let mut rows = ORDER.lock();
    let index = rows.iter().position(|row| row.tid == tid)?;
    let value = work(&mut rows[index].queue);
    if rows[index].queue.idle() { rows.swap_remove(index); }
    Some(value)
}

/// Perform everything the thread owes that can be done now. The status of a
/// launched redirect is the syscall result its caller must return.
/// # C: O(N_items + backend redirect)
fn drain(tid: u64, first: Next) -> Option<u64> {
    let status = core::cell::Cell::new(None);
    drive(first,
        |run| match crate::nt_native_gdi::begin_kernel_text(run.request, &run.text) {
            Some(value) => { status.set(Some(value)); true }
            None => false,
        },
        |font| match crate::nt_native_gdi::begin_menu_cells(font) {
            Some(value) => { status.set(Some(value)); true }
            None => false,
        },
        |owed| (owed.finish)(owed.hwnd, owed.dc),
        || with_existing(tid, |queue| queue.advance()).unwrap_or(Next::Idle));
    status.get()
}

/// Measure the menu face before the pass that needs it draws again. The
/// answer lands in kernel state, so the next bar the thread lays out is
/// measured on the face's own advances rather than its average.
/// # C: O(1) plus one backend redirect
pub(crate) fn submit_cells_for_current(font: Font) -> Option<u64> {
    let tid = current_tid()?;
    let first = with_row(tid, |queue| queue.submit_cells(font))?;
    drain(tid, first)
}

/// Take one kernel-owned text run of the pass being drawn. The first run of
/// an idle thread enters the font backend at once; the rest of the plan's
/// runs follow it one at a time. `Some` is the redirect status of a run this
/// call launched, which the syscall the pass runs under must return: the
/// callback reads its payload out of the frame the launch rewrote.
/// # C: O(text units)
pub(crate) fn submit_for_current(request: TextRequest, text: &[u16]) -> Option<u64> {
    let tid = current_tid()?;
    let mut owned = Vec::new();
    if owned.try_reserve_exact(text.len()).is_err() { return None; }
    owned.extend_from_slice(text);
    let first = with_row(tid, |queue| queue.submit(Run { request, text: owned }))?;
    drain(tid, first)
}

/// End the paint of one window once every kernel-owned run the same pass
/// issued has rasterized into its device context. # C: O(pixels)
pub(crate) fn end_paint_for_current(hwnd: u64, dc: u64, finish: fn(u64, u64)) {
    let owed = Owed { hwnd, dc, finish };
    let Some(tid) = current_tid() else { finish(hwnd, dc); return; };
    match with_row(tid, |queue| queue.defer_end(owed)) {
        Some(Some(now)) => (now.finish)(now.hwnd, now.dc),
        Some(None) => {}
        None => finish(hwnd, dc),
    }
}

/// Called from the native text completion once the thread's own frame is
/// back. `Some` is the redirect status of a freshly launched run.
/// # C: O(N_items + backend redirect)
pub(crate) fn advance_for_current() -> Option<u64> {
    let tid = current_tid()?;
    let first = with_existing(tid, |queue| queue.advance())?;
    drain(tid, first)
}

/// Thread exit finishes the paints still owed, before the windows, sessions
/// and device contexts they name are torn down. # C: O(N_items + pixels)
pub(crate) fn cancel_for_current() {
    let Some(tid) = current_tid() else { return; };
    let owed = {
        let mut rows = ORDER.lock();
        match rows.iter().position(|row| row.tid == tid) {
            Some(index) => { let mut row = rows.swap_remove(index); row.queue.cancel() }
            None => return,
        }
    };
    for end in owed { (end.finish)(end.hwnd, end.dc); }
}
