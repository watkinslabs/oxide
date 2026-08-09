// Publication of a task's port grant into the running CPU's TSS window.
//
// The reference splits this in two: `__switch_to_xtra` invalidates the
// outgoing task's window, and the exit-to-user path programs the incoming
// one. Both halves are done here at switch-in instead, because the window is
// only ever consulted from ring 3 and nothing between the switch and that
// ring-3 instruction can change the grant. The observable result is
// identical; what differs is that a task which is preempted and resumed
// without reaching user mode pays the (sequence-elided) update anyway.
//
// x86-only by construction: aarch64 has no port space, no such syscalls in
// its generic ABI, and therefore nothing to publish.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use core::sync::atomic::Ordering;

use crate::task::Task;

/// Program THIS CPU's I/O window to exactly `task`'s grant.
/// # C: O(bitmap bytes copied); zero when the CPU already holds the revision
/// # Ctx: process|context-switch path, preempt-off
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn update(task: &Task) {
    let level = task.iopl_emul.load(Ordering::Relaxed);
    let g = task.io_bitmap.lock();
    match g.as_ref() {
        // SAFETY: callers hold preemption off on the CPU being programmed at
        // CPL 0, and the guard keeps the byte image alive across the copy.
        Some(m) => unsafe { hal_x86_64::tss_update_io_bitmap(level, Some((m.bytes(), m.max, m.sequence))) },
        // SAFETY: same contract; no map means the window is parked outside the
        // TSS descriptor limit.
        None => unsafe { hal_x86_64::tss_update_io_bitmap(level, None) },
    }
}

/// Park THIS CPU's window: no port access from ring 3. Used when the outgoing
/// task held a grant and the incoming one does not.
/// # C: O(1)
/// # Ctx: context-switch path, preempt-off
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn invalidate() {
    // SAFETY: the context-switch path runs preempt-off at CPL 0 on the CPU
    // whose TSS this is; the call is a single 2-byte store.
    unsafe { hal_x86_64::tss_update_io_bitmap(0, None); }
}

/// # C: O(1)
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
pub fn update(_task: &Task) {}

/// # C: O(1)
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
pub fn invalidate() {}
