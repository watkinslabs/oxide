// D5b-2 DRM SETCRTC + PAGE_FLIP — scan out a userspace dumb buffer via
// virtio-gpu. Real, no façade:
//   - SETCRTC validates crtc_id + fb_id, looks up the FB → its dumb
//     handle → (pa, w, h, format), binds one virtio-gpu resource to
//     that FB if needed, and switches scanout 0 to it.
//   - fb_id == 0 disables the CRTC → restore the boot fbcon scanout.
//   - PAGE_FLIP re-scanouts a (new) fb on the crtc (virtio-gpu has no
//     true double-buffer flip → flip = SET_SCANOUT+transfer+flush of
//     the new fb). DRM_MODE_PAGE_FLIP_EVENT queues a
//     DRM_EVENT_FLIP_COMPLETE the requesting card fd's read() drains.
//
// CONSOLE SAFETY: the boot fbcon scanout (virtio res_id 1) is never
// touched here — SETCRTC uses an FB-owned runtime res_id and switches the
// scanout to it. The OWNER token records that a card fd took the
// scanout; `node::on_release` calls `restore_console_scanout` on
// last-close so the fb console + getty come back. A normal boot
// (no DRM client) never calls SETCRTC, so res_id 1 stays scanned out.
//
// The actual scanout commands run in drv-virtio-gpu via the ScanoutOps
// hook (drm cannot depend on that crate — it depends on us). When the
// hook isn't installed (QEMU without virtio-gpu), SETCRTC honest-fails
// with -EINVAL.
//
// All user copies bounds-check (< hal::USER_VA_END) and use volatile
// reads/writes through the caller's AS at CPL=0. UAPI struct layouts
// match the Linux DRM/KMS ABI byte-for-byte (`47`).

extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};
use sync::{Spinlock, TaskList as CrtcLockClass};
use syscall::errno::Errno;

use crate::node::scanout_ops;

// ============================================================
// UAPI wire structs (DRM/KMS modesetting UAPI)
// ============================================================

/// `struct drm_mode_crtc_page_flip` — 0xc01864b0, 24 bytes. # C: ABI
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeCrtcPageFlip {
    pub crtc_id:   u32,
    pub fb_id:     u32,
    pub flags:     u32,
    pub reserved:  u32,
    pub user_data: u64,
}

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }
/// A user pointer the copy routines could not read: the caller named memory
/// it does not have, which is EFAULT and never a kernel fault. # C: O(1)
fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }

/// True iff `[ptr, ptr+len)` is a usable user range. # C: O(1)
fn user_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && ptr < hal::USER_VA_END && ptr.checked_add(len).is_some_and(|end| end <= hal::USER_VA_END)
}

// ============================================================
// Scanout owner token + flip-event queue
// ============================================================

/// Identifies which card-fd open description currently owns each card's
/// scanout. 0 = the boot fbcon owns it (no client). The token is the
/// `Arc<File>` pointer the syscall layer passes down, stable for one open
/// description.
static OWNERS: Spinlock<alloc::vec::Vec<u64>, CrtcLockClass> = Spinlock::new(alloc::vec::Vec::new());

struct EventQueue {
    card_id: u32,
    token:   u64,
    queue:   VecDeque<crate::DrmEventVblank>,
}

/// Queued page-flip completion events to be drained by the requesting card
/// fd's read(), keyed by stable DRM card id + open-file token.
static EVENTS: Spinlock<Vec<EventQueue>, CrtcLockClass> = Spinlock::new(Vec::new());
static CURRENT_FB: Spinlock<alloc::vec::Vec<u32>, CrtcLockClass> = Spinlock::new(alloc::vec::Vec::new());
/// Blob id of the mode last committed through `MODE_ID`, per stable card id.
/// Lives beside `CURRENT_FB` so `MODE_ID` reads back the committed mode from
/// the one owner of scanout state rather than a parallel property table.
static CURRENT_MODE_BLOB: Spinlock<alloc::vec::Vec<u32>, CrtcLockClass> = Spinlock::new(alloc::vec::Vec::new());

/// Record `token` as the current scanout owner. # C: O(1)
pub fn set_owner(card_id: u32, token: u64) {
    let mut owners = OWNERS.lock();
    let idx = card_id as usize;
    if owners.len() <= idx {
        owners.resize(idx + 1, 0);
    }
    owners[idx] = token;
}
/// The current scanout owner token (0 = none / boot console). # C: O(1)
pub fn owner(card_id: u32) -> u64 {
    OWNERS.lock().get(card_id as usize).copied().unwrap_or(0)
}
/// True iff `token` currently owns the scanout. # C: O(1)
pub fn is_owner(card_id: u32, token: u64) -> bool {
    let o = owner(card_id);
    o != 0 && o == token
}
/// Clear the owner (back to boot console). # C: O(1)
pub fn clear_owner(card_id: u32) {
    if let Some(owner) = OWNERS.lock().get_mut(card_id as usize) {
        *owner = 0;
    }
}

pub(crate) fn set_current_fb(card_id: u32, fb_id: u32) {
    let mut current = CURRENT_FB.lock();
    let idx = card_id as usize;
    if current.len() <= idx {
        current.resize(idx + 1, 0);
    }
    let old_id = current[idx];
    current[idx] = fb_id;
    drop(current);
    crate::dumb::replace_bound_fb(card_id, old_id, fb_id);
}

#[cfg(test)]
pub(crate) fn set_current_fb_for_tests(card_id: u32, fb_id: u32) {
    set_current_fb(card_id, fb_id);
}

fn clear_current_fb(card_id: u32) {
    if let Some(fb_id) = CURRENT_FB.lock().get_mut(card_id as usize) {
        *fb_id = 0;
    }
    set_current_mode_blob(card_id, 0);
}

pub fn current_fb(card_id: u32) -> u32 {
    CURRENT_FB.lock().get(card_id as usize).copied().unwrap_or(0)
}

/// Record the mode blob a modeset committed (0 = no mode). # C: O(1)
pub(crate) fn set_current_mode_blob(card_id: u32, blob_id: u32) {
    let mut current = CURRENT_MODE_BLOB.lock();
    let idx = card_id as usize;
    if current.len() <= idx {
        current.resize(idx + 1, 0);
    }
    current[idx] = blob_id;
}

/// Blob id of the currently committed mode, as `MODE_ID` reports it. # C: O(1)
pub fn current_mode_blob(card_id: u32) -> u32 {
    CURRENT_MODE_BLOB.lock().get(card_id as usize).copied().unwrap_or(0)
}

/// Detach a framebuffer from the live CRTC before RMFB tears down its backend
/// resource. Linux removes an RMFB target from active planes before dropping
/// the framebuffer object; this driver restores the boot fbcon scanout because
/// it has a single primary scanout and no full atomic plane state yet.
/// # C: O(1) + O(scanout repaint)
pub fn detach_fb(card_id: u32, fb_id: u32) {
    if fb_id == 0 || current_fb(card_id) != fb_id {
        return;
    }
    if let Some(ops) = scanout_ops(card_id) {
        let _ = (ops.restore_console)(ops.driver_key);
    }
    clear_current_fb(card_id);
    clear_owner(card_id);
}

/// Clear all CRTC runtime state owned by a stable DRM card id.
/// Called from DRM unregister so a reused card slot cannot inherit stale
/// ownership or unread flip events from the removed device. # C: O(events)
pub fn clear_card_state(card_id: u32) {
    clear_owner(card_id);
    clear_current_fb(card_id);
    EVENTS.lock().retain(|q| q.card_id != card_id);
}

/// Drop unread flip events for one open file description. Called from the
/// DRM file release path. # C: O(event queues)
pub fn clear_file_events(card_id: u32, token: u64) {
    EVENTS.lock().retain(|q| q.card_id != card_id || q.token != token);
}

/// Queue a DRM_EVENT_FLIP_COMPLETE for `crtc_id` carrying `user_data`.
/// Drained by the requesting card fd's read(). # C: O(event queues)
pub fn queue_flip_event(card_id: u32, token: u64, crtc_id: u32, user_data: u64) {
    let ev = crate::DrmEventVblank {
        base: crate::DrmEvent {
            ty: crate::DRM_EVENT_FLIP_COMPLETE,
            length: core::mem::size_of::<crate::DrmEventVblank>() as u32,
        },
        user_data,
        tv_sec: 0, tv_usec: 0,
        sequence: 0,
        crtc_id,
    };
    {
        let mut events = EVENTS.lock();
        if let Some(q) = events.iter_mut().find(|q| q.card_id == card_id && q.token == token) {
            q.queue.push_back(ev);
        } else {
            let mut queue = VecDeque::new();
            queue.push_back(ev);
            events.push(EventQueue { card_id, token, queue });
        }
    }
    // Linux `drm_send_event_locked` wakes `file_priv->event_wait` with
    // `EPOLLIN | EPOLLRDNORM` after every queued event. Without this the queue
    // grew silently and no poll/epoll waiter on the card fd ever learned an
    // event had arrived. Notified OUTSIDE the EVENTS lock: a waiter woken here
    // reads the queue, and waking under the lock invites a self-deadlock.
    crate::node::card_poll_subs(card_id).notify_mask(vfs::POLL_IN);
    #[cfg(target_os = "oxide-kernel")]
    event_waiters(card_id).wake_all();
}

/// Per-card sleepers in `drm_read` — Linux `file_priv->event_wait`.
/// Woken by `queue_flip_event` after the event is queued and the `EVENTS`
/// lock is dropped. Per-card rather than per-file: a wake is a hint, and each
/// sleeper re-checks its own `(card_id, token)` queue on wake, so a spurious
/// wake costs one re-check (Linux's `wait_event_interruptible` is the same
/// shape).
#[cfg(target_os = "oxide-kernel")]
static EVENT_WAITERS: Spinlock<Vec<(u32, alloc::sync::Arc<sched::live::wait_list::WaitList>)>, CrtcLockClass> =
    Spinlock::new(Vec::new());

/// The wait list for `card_id`, created on first use. `sched::live` exists only
/// in a kernel build, so a host build has no sleeper set and the read path
/// answers `EAGAIN` — it never schedules. # C: O(cards)
#[cfg(target_os = "oxide-kernel")]
fn event_waiters(card_id: u32) -> alloc::sync::Arc<sched::live::wait_list::WaitList> {
    let mut g = EVENT_WAITERS.lock();
    if let Some((_, w)) = g.iter().find(|(id, _)| *id == card_id) { return w.clone(); }
    let w = alloc::sync::Arc::new(sched::live::wait_list::WaitList::new());
    g.push((card_id, w.clone()));
    w
}

/// Blocking drain — Linux `drm_read`.
///
/// Empty queue: `EAGAIN` for `O_NONBLOCK`, otherwise sleep on the card's
/// wait list until an event arrives or a signal is deliverable
/// (`ERESTARTSYS`). NEVER returns 0 for an empty queue — a 0-byte read is
/// EOF to a GLib fd source. A buffer too small for the first queued record
/// DOES return 0, exactly as Linux's `put_back_event` → `break` path does;
/// there is no minimum-`count` guard in `drm_read`.
///
/// The emptiness test and the park enqueue are ONE critical section over
/// `EVENTS`, because `queue_flip_event` pushes under that same lock before it
/// wakes — so its push+wake cannot land between "we saw empty" and "we are on
/// the wait list" (same rule as `pipe::ring::read_blocking`, B1422).
/// # C: O(events) + park
pub fn drain_events_blocking(card_id: u32, token: u64, buf: &mut [u8], nonblock: bool)
    -> Result<usize, vfs::VfsError>
{
    loop {
        let mut events = EVENTS.lock();
        if let Some(idx) = events.iter().position(|q| q.card_id == card_id && q.token == token) {
            if !events[idx].queue.is_empty() {
                let n = drain_locked(&mut events, idx, buf);
                drop(events);
                // A short buffer copies nothing and leaves the record queued;
                // Linux returns 0 there rather than blocking or erroring.
                return Ok(n);
            }
        }
        if nonblock { return Err(vfs::VfsError::Eagain); }
        #[cfg(target_os = "oxide-kernel")]
        {
            if sched::live::deliverable_signals_self() != 0 {
                return Err(vfs::VfsError::Erestartsys);
            }
            // SAFETY: running task; preempt-off; park bumps the Arc and marks
            // Sleeping while the EVENTS lock is still held, so a racing
            // queue_flip_event's push+wake cannot land between the emptiness
            // check above and this enqueue.
            unsafe { event_waiters(card_id).park(); }
        }
        drop(events);
        #[cfg(target_os = "oxide-kernel")]
        // SAFETY: process context; runqueue installed; preempt-off; current is
        // Sleeping until queue_flip_event wakes it. EVENTS lock dropped above.
        unsafe { sched::live::schedule::schedule(); }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(vfs::VfsError::Eagain);
    }
}

/// Copy whole records out of `events[idx]`, removing the queue when drained.
/// # C: O(events)
fn drain_locked(events: &mut Vec<EventQueue>, idx: usize, buf: &mut [u8]) -> usize {
    let rec = core::mem::size_of::<crate::DrmEventVblank>();
    let mut off = 0usize;
    let q = &mut events[idx];
    while off + rec <= buf.len() {
        let ev = match q.queue.pop_front() { Some(e) => e, None => break };
        // SAFETY: DrmEventVblank is repr(C) POD (all integer fields); reading its bytes as a [u8; rec] is a valid reinterpretation of an owned stack value.
        let bytes: &[u8] = unsafe { core::slice::from_raw_parts(&ev as *const _ as *const u8, rec) };
        buf[off..off + rec].copy_from_slice(bytes);
        off += rec;
    }
    if q.queue.is_empty() { events.remove(idx); }
    off
}

/// Drain queued flip events into `buf`, returning the bytes written.
/// Copies whole `drm_event_vblank` records only (a partial record is
/// left queued). 0 if the buffer is too small for one record or none
/// pending — matching Linux `drm_read`. # C: O(event queues + events)
pub fn drain_events(card_id: u32, token: u64, buf: &mut [u8]) -> usize {
    let rec = core::mem::size_of::<crate::DrmEventVblank>();
    let mut off = 0usize;
    let mut events = EVENTS.lock();
    let Some(idx) = events.iter().position(|q| q.card_id == card_id && q.token == token) else {
        return 0;
    };
    let q = &mut events[idx];
    while off + rec <= buf.len() {
        let ev = match q.queue.pop_front() { Some(e) => e, None => break };
        // SAFETY: DrmEventVblank is repr(C) POD (all integer fields); reading its bytes as a [u8; rec] is a valid reinterpretation of an owned stack value.
        let bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(&ev as *const _ as *const u8, rec)
        };
        buf[off..off + rec].copy_from_slice(bytes);
        off += rec;
    }
    if q.queue.is_empty() {
        events.remove(idx);
    }
    off
}

/// True iff at least one flip event is pending (for poll/POLLIN).
/// # C: O(1)
pub fn has_events(card_id: u32, token: u64) -> bool {
    EVENTS.lock()
        .iter()
        .any(|q| q.card_id == card_id && q.token == token && !q.queue.is_empty())
}

mod handlers;
pub(crate) use handlers::fb_scanout_resource;
pub use handlers::{page_flip, set_crtc};
