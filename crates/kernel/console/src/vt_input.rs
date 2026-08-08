// VT input staging — the same Linux split the serial console uses
// (`static_console::rx_byte` / `flush_input_work`), applied to the keyboard.
//
// virtio-input delivers keystrokes from a SOFTIRQ (`drv-virtio-input`'s
// `raise_drain` -> `handle_key_event` -> `tty::live::input_push_byte`), and a
// softirq drain runs on the per-CPU hardirq stack in this port. Running
// `n_tty_receive_buf` — with its inline echo into the fbcon glyph renderer and
// its `wake_all` — from there puts the whole VT pipeline on the same 16 KiB
// stack whose measured peak is already 14.5 KiB. Linux instead has the VT
// keyboard driver call `tty_insert_flip_char` + `tty_flip_buffer_push`
// (`put_queue`), and `flush_to_ldisc` cooks it from
// a workqueue.
//
// Ordering: `TIOCLINUX` paste (`input_push_byte` from a syscall) and DSR
// answerback go through this SAME staging ring rather than straight into the
// ldisc. Sending one source through the ring and another inline would let a
// pasted block overtake the keystrokes typed before it.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::vt_tty::{self, N_VT};

/// Linux `work_struct`'s `WORK_STRUCT_PENDING` bit, per VT. Held for the whole
/// life of the work item, not just until the callback starts: `flush_to_ldisc`
/// requires that no two flushes of one port run at once, or each takes a chunk
/// and they can reach the line discipline out of order.
static FLUSH_QUEUED: [AtomicBool; N_VT + 1] =
    [const { AtomicBool::new(false) }; N_VT + 1];

/// Stage `bytes` for VT `vt` and schedule the cook. Linux
/// `tty_insert_flip_string` + `tty_flip_buffer_push`.
/// # C: O(len)
/// # Ctx: any, including softirq
/// # Sleeps: no
pub fn stage(vt: u8, bytes: &[u8]) {
    let slot = vt as usize;
    if slot == 0 || slot > N_VT { return; }
    if vt_tty::vt_tty(vt).insert_flip(bytes) == 0 { return; }
    schedule(vt);
}

/// # C: O(1)
fn schedule(vt: u8) {
    if FLUSH_QUEUED[vt as usize].swap(true, Ordering::AcqRel) { return; }
    if !sched::live::workqueue::queue_work(flush_work, vt as usize) {
        FLUSH_QUEUED[vt as usize].store(false, Ordering::Release);
    }
}

/// Linux `flush_to_ldisc`, per VT. # C: O(staged bytes)
/// # Ctx: process (kworker)
fn flush_work(arg: usize) {
    let vt = arg as u8;
    if arg == 0 || arg > N_VT { return; }
    vt_tty::vt_tty(vt).flush_to_ldisc();
    // Release the single-flush token, then re-check: a byte staged during the
    // drain saw the token taken and queued nothing, so this is the only place
    // that can still pick it up.
    FLUSH_QUEUED[arg].store(false, Ordering::Release);
    if vt_tty::vt_tty(vt).flip_pending() > 0 { schedule(vt); }
}
