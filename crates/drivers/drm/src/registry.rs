use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{crtc, dumb, node, DrmDriver};
use crate::uapi::*;

static CARDS: Spinlock<Vec<Option<Arc<dyn DrmDriver>>>, DriverLockClass> = Spinlock::new(Vec::new());
static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1);

pub fn register(driver: Arc<dyn DrmDriver>) -> u32 {
    register_with_parent(driver, None)
}

pub fn register_with_parent(
    driver: Arc<dyn DrmDriver>,
    parent: Option<(&'static str, String)>,
) -> u32 {
    let mut driver = Some(driver);
    let card_id = {
        let mut g = CARDS.lock();
        if let Some(idx) = g.iter().position(|slot| slot.is_none()) {
            g[idx] = Some(driver.take().expect("DRM driver consumed once"));
            idx as u32
        } else {
            g.push(Some(driver.take().expect("DRM driver consumed once")));
            (g.len() - 1) as u32
        }
    };
    if !node::register(card_id, parent) {
        let mut g = CARDS.lock();
        if let Some(slot) = g.get_mut(card_id as usize) {
            *slot = None;
        }
        while matches!(g.last(), Some(None)) {
            g.pop();
        }
        return u32::MAX;
    }
    card_id
}

pub fn card(card_id: u32) -> Option<Arc<dyn DrmDriver>> {
    CARDS.lock().get(card_id as usize).and_then(|slot| slot.as_ref().cloned())
}

pub fn primary_card() -> Option<Arc<dyn DrmDriver>> {
    CARDS.lock().iter().find_map(|slot| slot.as_ref().cloned())
}

pub fn cards() -> Vec<Arc<dyn DrmDriver>> {
    CARDS.lock().iter().filter_map(|slot| slot.as_ref().cloned()).collect()
}

pub fn unregister(card_id: u32) -> bool {
    let mut g = CARDS.lock();
    let idx = card_id as usize;
    if idx >= g.len() || g[idx].take().is_none() {
        return false;
    }
    while matches!(g.last(), Some(None)) {
        g.pop();
    }
    drop(g);
    crtc::clear_card_state(card_id);
    dumb::clear_card_state(card_id);
    node::unregister(card_id);
    true
}

pub fn card_count() -> usize {
    CARDS.lock().iter().filter(|slot| slot.is_some()).count()
}

pub fn alloc_handle() -> u32 {
    NEXT_HANDLE.fetch_add(1, Ordering::AcqRel)
}

pub fn default_cap(cap: u64) -> u64 {
    match cap {
        DRM_CAP_DUMB_BUFFER => 1,
        // We do not implement DRM_IOCTL_WAIT_VBLANK or generate vblank
        // events, so advertising either vblank extension would be false.
        DRM_CAP_VBLANK_HIGH_CRTC => 0,
        DRM_CAP_DUMB_PREFERRED_DEPTH => 32,
        DRM_CAP_DUMB_PREFER_SHADOW => 0,
        DRM_CAP_PRIME => 0,
        DRM_CAP_TIMESTAMP_MONOTONIC => 1,
        DRM_CAP_ASYNC_PAGE_FLIP => 0,
        DRM_CAP_CURSOR_WIDTH => 0,
        DRM_CAP_CURSOR_HEIGHT => 0,
        DRM_CAP_ADDFB2_MODIFIERS => 0,
        DRM_CAP_PAGE_FLIP_TARGET => 0,
        DRM_CAP_CRTC_IN_VBLANK_EVENT => 0,
        DRM_CAP_SYNCOBJ => 0,
        DRM_CAP_SYNCOBJ_TIMELINE => 0,
        _ => 0,
    }
}

pub fn advertised_cap(cap: u64, val: u64) -> u64 {
    match cap {
        DRM_CAP_PRIME
        | DRM_CAP_VBLANK_HIGH_CRTC
        | DRM_CAP_ASYNC_PAGE_FLIP
        | DRM_CAP_CURSOR_WIDTH
        | DRM_CAP_CURSOR_HEIGHT
        | DRM_CAP_ADDFB2_MODIFIERS
        | DRM_CAP_PAGE_FLIP_TARGET
        | DRM_CAP_CRTC_IN_VBLANK_EVENT
        | DRM_CAP_SYNCOBJ
        | DRM_CAP_SYNCOBJ_TIMELINE => 0,
        _ => val,
    }
}

pub fn is_master_only(req: u64) -> bool {
    matches!(req,
        DRM_IOCTL_MODE_SETCRTC | DRM_IOCTL_MODE_PAGE_FLIP
        | DRM_IOCTL_MODE_ATOMIC | DRM_IOCTL_SET_MASTER | DRM_IOCTL_DROP_MASTER
        | DRM_IOCTL_MODE_SETPLANE | DRM_IOCTL_MODE_DIRTYFB
        | DRM_IOCTL_MODE_OBJ_SETPROPERTY | DRM_IOCTL_MODE_SETPROPERTY
        | DRM_IOCTL_MODE_CURSOR | DRM_IOCTL_MODE_CURSOR2
    )
}

#[cfg(test)]
pub(crate) fn clear_cards_for_tests() {
    CARDS.lock().clear();
}
