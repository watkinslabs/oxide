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
// copied from linux/include/uapi/drm/drm_mode.h EXACTLY.

extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};
use sync::{Spinlock, TaskList as CrtcLockClass};
use syscall::errno::Errno;

use crate::{DrmModeCrtc, crtc_idx_of};
use crate::node::scanout_ops;

// ============================================================
// UAPI wire structs (drm_mode.h)
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

fn set_current_fb(card_id: u32, fb_id: u32) {
    let mut current = CURRENT_FB.lock();
    let idx = card_id as usize;
    if current.len() <= idx {
        current.resize(idx + 1, 0);
    }
    current[idx] = fb_id;
}

fn clear_current_fb(card_id: u32) {
    if let Some(fb_id) = CURRENT_FB.lock().get_mut(card_id as usize) {
        *fb_id = 0;
    }
}

pub fn current_fb(card_id: u32) -> u32 {
    CURRENT_FB.lock().get(card_id as usize).copied().unwrap_or(0)
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
    let mut events = EVENTS.lock();
    if let Some(q) = events.iter_mut().find(|q| q.card_id == card_id && q.token == token) {
        q.queue.push_back(ev);
    } else {
        let mut queue = VecDeque::new();
        queue.push_back(ev);
        events.push(EventQueue { card_id, token, queue });
    }
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

// ============================================================
// SETCRTC / PAGE_FLIP handlers
// ============================================================

/// Resolve an FB id → its primary dumb buffer's (pa, w, h, fourcc).
/// `None` if the fb or its handle is unknown. # C: O(n)
fn fb_to_scanout(card_id: u32, fb_id: u32) -> Option<(u64, u32, u32, u32, u32)> {
    let t = crate::dumb::TABLES.lock();
    let fb = t.find_fb(card_id, fb_id)?;
    let buf = t.find_buf(card_id, fb.handles[0])?;
    Some((buf.pa, fb.w, fb.h, fb.pixel_format, fb.scanout_res_id))
}

fn release_new_scanout_resource(card_id: u32, res_id: u32) {
    if let Some(ops) = scanout_ops(card_id) {
        let _ = (ops.destroy_resource)(ops.driver_key, res_id);
    }
}

fn fb_scanout_resource(card_id: u32, ops: crate::node::ScanoutOps, fb_id: u32) -> Option<(u32, u32, u32)> {
    let (pa, w, h, fmt, existing) = fb_to_scanout(card_id, fb_id)?;
    if existing != 0 {
        return Some((existing, w, h));
    }
    let res_id = (ops.create_from_pa)(ops.driver_key, pa, w, h, fmt)?;
    if !crate::dumb::bind_fb_scanout_resource(card_id, fb_id, res_id) {
        release_new_scanout_resource(card_id, res_id);
        return None;
    }
    Some((res_id, w, h))
}

/// `MODE_SETCRTC` — parse `drm_mode_crtc`, validate crtc_id + fb_id,
/// drive the scanout. `token` identifies the owning open description.
///
/// - fb_id == 0  → disable the CRTC: restore the boot fbcon scanout,
///   clear the owner. Returns 0.
/// - else        → look up the FB → (pa,w,h,fmt), create a virtio-gpu
///   resource over the contiguous PA, switch scanout 0 to it, record
///   `token` as the scanout owner. Returns 0.
///
/// Honest -EINVAL on a bad crtc_id / unknown fb_id / unsupported format
/// / no virtio-gpu scanout backend installed. # C: O(1) + O(scanout).
pub fn set_crtc(card_id: u32, card: &alloc::sync::Arc<dyn crate::DrmDriver>, arg: u64, token: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeCrtc>() as u64) { return einval(); }
    // SAFETY: arg range validated < USER_VA_END; drm_mode_crtc is 104 bytes; aligned struct read through the caller's AS at CPL=0.
    let c: DrmModeCrtc = unsafe { core::ptr::read_volatile(arg as *const DrmModeCrtc) };
    // Validate the crtc id against the registered card.
    let count = card.crtc_ids().len();
    if crtc_idx_of(c.crtc_id, count).is_none() { return einval(); }
    let ops = match scanout_ops(card_id) { Some(o) => o, None => return einval() };

    if c.fb_id == 0 {
        // Disable / detach: restore the console scanout if WE owned it.
        if is_owner(card_id, token) {
            (ops.restore_console)(ops.driver_key);
            clear_owner(card_id);
            clear_current_fb(card_id);
        } else if owner(card_id) == 0 {
            // No client owns it; SETCRTC(fb=0) is a no-op disable.
            (ops.restore_console)(ops.driver_key);
            clear_current_fb(card_id);
        }
        return 0;
    }

    let (res_id, w, h) = match fb_scanout_resource(card_id, ops, c.fb_id) { Some(v) => v, None => return einval() };
    // Optionally validate the connector array pointer is sane when set.
    if c.set_connectors_ptr != 0
        && !user_ok(c.set_connectors_ptr, (c.count_connectors as u64) * 4) {
        return einval();
    }
    if !(ops.set_scanout)(ops.driver_key, res_id, w, h) { return einval(); }
    set_current_fb(card_id, c.fb_id);
    set_owner(card_id, token);
    0
}

/// `MODE_PAGE_FLIP` — parse `drm_mode_crtc_page_flip`, re-scanout the
/// given fb on the crtc. virtio-gpu has no true double-buffer flip, so
/// flip = SET_SCANOUT + transfer + flush of the new fb (immediate).
/// If `flags & DRM_MODE_PAGE_FLIP_EVENT`, queue a DRM_EVENT_FLIP_COMPLETE
/// the card fd's read() returns. Honest -EINVAL on bad ids / no backend.
/// # C: O(1) + O(scanout).
pub fn page_flip(card_id: u32, card: &alloc::sync::Arc<dyn crate::DrmDriver>, arg: u64, token: u64) -> i64 {
    if !user_ok(arg, core::mem::size_of::<DrmModeCrtcPageFlip>() as u64) { return einval(); }
    // SAFETY: arg range validated < USER_VA_END; drm_mode_crtc_page_flip is 24 bytes; aligned struct read through the caller's AS at CPL=0.
    let f: DrmModeCrtcPageFlip = unsafe { core::ptr::read_volatile(arg as *const DrmModeCrtcPageFlip) };
    let count = card.crtc_ids().len();
    if crtc_idx_of(f.crtc_id, count).is_none() { return einval(); }
    if f.fb_id == 0 { return einval(); }
    let ops = match scanout_ops(card_id) { Some(o) => o, None => return einval() };
    let (res_id, w, h) = match fb_scanout_resource(card_id, ops, f.fb_id) { Some(v) => v, None => return einval() };
    if !(ops.set_scanout)(ops.driver_key, res_id, w, h) { return einval(); }
    set_current_fb(card_id, f.fb_id);
    set_owner(card_id, token);
    if (f.flags & crate::DRM_MODE_PAGE_FLIP_EVENT) != 0 {
        queue_flip_event(card_id, token, f.crtc_id, f.user_data);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_flip_layout() {
        // 4×u32 (16) + u64 (8) = 24.
        assert_eq!(core::mem::size_of::<DrmModeCrtcPageFlip>(), 24);
        assert_eq!(core::mem::offset_of!(DrmModeCrtcPageFlip, fb_id), 4);
        assert_eq!(core::mem::offset_of!(DrmModeCrtcPageFlip, flags), 8);
        assert_eq!(core::mem::offset_of!(DrmModeCrtcPageFlip, user_data), 16);
    }

    #[test]
    fn owner_token_logic() {
        clear_owner(0);
        clear_owner(1);
        clear_current_fb(0);
        clear_current_fb(1);
        assert_eq!(owner(0), 0);
        assert_eq!(owner(1), 0);
        assert_eq!(current_fb(0), 0);
        assert_eq!(current_fb(1), 0);
        assert!(!is_owner(0, 0));       // 0 token never "owns"
        assert!(!is_owner(0, 0x1000));
        set_owner(0, 0x1000);
        set_current_fb(0, 7);
        assert_eq!(owner(0), 0x1000);
        assert_eq!(current_fb(0), 7);
        assert_eq!(owner(1), 0);
        assert!(is_owner(0, 0x1000));
        assert!(!is_owner(1, 0x1000));
        assert!(!is_owner(0, 0x2000));  // a different fd doesn't own it
        detach_fb(0, 8);
        assert_eq!(current_fb(0), 7);
        detach_fb(0, 7);
        clear_owner(0);
        assert_eq!(owner(0), 0);
        assert_eq!(current_fb(0), 0);
        assert!(!is_owner(0, 0x1000));
    }

    #[test]
    fn flip_event_queue_drain() {
        const TOKEN_A: u64 = 0xA11C_E001;
        const TOKEN_B: u64 = 0xB22C_E002;
        // Drain any residue from other tests first.
        let mut scratch = [0u8; 4096];
        let _ = drain_events(0, TOKEN_A, &mut scratch);
        let _ = drain_events(0, TOKEN_B, &mut scratch);
        let _ = drain_events(1, TOKEN_A, &mut scratch);
        assert!(!has_events(0, TOKEN_A));
        assert!(!has_events(0, TOKEN_B));
        assert!(!has_events(1, TOKEN_A));
        queue_flip_event(0, TOKEN_A, 1, 0xDEAD_BEEF);
        queue_flip_event(0, TOKEN_A, 1, 0x1234_5678);
        queue_flip_event(0, TOKEN_B, 1, 0xFEED_FACE);
        assert!(has_events(0, TOKEN_A));
        assert!(has_events(0, TOKEN_B));
        assert!(!has_events(1, TOKEN_A));
        let rec = core::mem::size_of::<crate::DrmEventVblank>();
        // A buffer too small for one record drains nothing.
        let mut tiny = [0u8; 4];
        assert_eq!(drain_events(0, TOKEN_A, &mut tiny), 0);
        assert!(has_events(0, TOKEN_A));
        // A buffer big enough for both drains only TOKEN_A's records.
        let mut buf = [0u8; 4096];
        let n = drain_events(0, TOKEN_A, &mut buf);
        assert_eq!(n, 2 * rec);
        assert!(!has_events(0, TOKEN_A));
        assert!(has_events(0, TOKEN_B));
        // First record's type + user_data decode correctly.
        let ty = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(ty, crate::DRM_EVENT_FLIP_COMPLETE);
        let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(len as usize, rec);
        let ud = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11],
                                     buf[12], buf[13], buf[14], buf[15]]);
        assert_eq!(ud, 0xDEAD_BEEF);
        assert_eq!(drain_events(0, TOKEN_B, &mut buf), rec);
        assert!(!has_events(0, TOKEN_B));
    }

    #[test]
    fn drain_partial_leaves_remainder() {
        const TOKEN: u64 = 0xD0D0;
        let mut scratch = [0u8; 4096];
        let _ = drain_events(0, TOKEN, &mut scratch);
        let rec = core::mem::size_of::<crate::DrmEventVblank>();
        queue_flip_event(0, TOKEN, 1, 1);
        queue_flip_event(0, TOKEN, 1, 2);
        queue_flip_event(0, TOKEN, 1, 3);
        // Buffer fits exactly two records → drains two, leaves one.
        let mut two = alloc::vec![0u8; 2 * rec];
        assert_eq!(drain_events(0, TOKEN, &mut two), 2 * rec);
        assert!(has_events(0, TOKEN));
        let mut one = alloc::vec![0u8; rec];
        assert_eq!(drain_events(0, TOKEN, &mut one), rec);
        assert!(!has_events(0, TOKEN));
    }

    #[test]
    fn clear_card_state_drops_owner_and_events() {
        const TOKEN: u64 = 0xCAFE_BABE;
        let mut scratch = [0u8; 4096];
        let _ = drain_events(2, TOKEN, &mut scratch);
        set_owner(2, 0x2000);
        set_current_fb(2, 17);
        queue_flip_event(2, TOKEN, 1, 0xCAFE);
        assert_eq!(owner(2), 0x2000);
        assert_eq!(current_fb(2), 17);
        assert!(has_events(2, TOKEN));
        clear_card_state(2);
        assert_eq!(owner(2), 0);
        assert_eq!(current_fb(2), 0);
        assert!(!has_events(2, TOKEN));
        assert_eq!(drain_events(2, TOKEN, &mut scratch), 0);
    }
}
