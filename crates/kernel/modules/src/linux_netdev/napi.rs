extern crate alloc;

use super::skb;
use super::types::*;
use alloc::alloc::{alloc_zeroed, Layout};
use core::ffi::c_void;
use core::sync::atomic::Ordering;

const NAPI_STATE_DISABLED: u32 = 1 << 0;
const NAPI_STATE_SCHEDULED: u32 = 1 << 1;
const DEFAULT_NAPI_WEIGHT: i32 = 64;
const FRAG_ALIGN: usize = 64;

/// Register Linux NAPI KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("netif_napi_add_weight_locked", netif_napi_add_weight_locked as *const () as usize, false);
    export("__netif_napi_del_locked", __netif_napi_del_locked as *const () as usize, false);
    export("napi_enable", napi_enable as *const () as usize, false);
    export("napi_disable", napi_disable as *const () as usize, false);
    export("__napi_schedule", __napi_schedule as *const () as usize, false);
    export("__napi_schedule_irqoff", __napi_schedule_irqoff as *const () as usize, false);
    export("napi_schedule_prep", napi_schedule_prep as *const () as usize, false);
    export("napi_complete_done", napi_complete_done as *const () as usize, false);
    export("napi_alloc_skb", napi_alloc_skb as *const () as usize, false);
    export("napi_build_skb", napi_build_skb as *const () as usize, false);
    export("napi_consume_skb", napi_consume_skb as *const () as usize, false);
    export("napi_get_frags", napi_get_frags as *const () as usize, false);
    export("napi_gro_frags", napi_gro_frags as *const () as usize, false);
    export("gro_receive_skb", gro_receive_skb as *const () as usize, false);
    export("__napi_alloc_frag_align", __napi_alloc_frag_align as *const () as usize, false);
    export("skb_page_frag_refill", skb_page_frag_refill as *const () as usize, false);
    export("netif_queue_set_napi", netif_queue_set_napi as *const () as usize, false);
    export("netif_napi_set_irq_locked", netif_napi_set_irq_locked as *const () as usize, false);
}

/// # C: O(1)
unsafe extern "C" fn netif_napi_add_weight_locked(dev: *mut LinuxNetDevice, napi: *mut LinuxNapiStruct, poll: Option<NapiPoll>, weight: i32) {
    if napi.is_null() { return; }
    // SAFETY: caller supplies writable napi storage embedded in the driver.
    unsafe {
        (*napi).dev = dev;
        (*napi).poll = poll;
        (*napi).weight = if weight > 0 { weight } else { DEFAULT_NAPI_WEIGHT };
        (*napi).rxq = 0;
        (*napi).txq = 0;
        (*napi).scheduled.store(0, Ordering::Release);
        (*napi).ingress_generation.store(0, Ordering::Release);
        (*napi).state.store(NAPI_STATE_DISABLED, Ordering::Release);
    }
}

/// # C: O(1)
unsafe extern "C" fn __netif_napi_del_locked(napi: *mut LinuxNapiStruct) {
    if napi.is_null() { return; }
    // SAFETY: caller owns napi and is deleting it from the netdev.
    unsafe {
        (*napi).poll = None;
        (*napi).dev = core::ptr::null_mut();
        (*napi).ingress_generation.store(0, Ordering::Release);
        (*napi).state.store(NAPI_STATE_DISABLED, Ordering::Release);
    }
}

/// # C: O(1)
unsafe extern "C" fn napi_enable(napi: *mut LinuxNapiStruct) {
    if napi.is_null() { return; }
    // SAFETY: napi points to initialized driver-owned storage.
    unsafe { (*napi).state.fetch_and(!NAPI_STATE_DISABLED, Ordering::AcqRel); }
}

/// # C: O(1)
unsafe extern "C" fn napi_disable(napi: *mut LinuxNapiStruct) {
    if napi.is_null() { return; }
    // SAFETY: napi points to initialized driver-owned storage.
    unsafe {
        (*napi).state.fetch_or(NAPI_STATE_DISABLED, Ordering::AcqRel);
        (*napi).ingress_generation.store(0, Ordering::Release);
    }
}

/// # C: O(poll budget)
unsafe extern "C" fn __napi_schedule(napi: *mut LinuxNapiStruct) {
    if napi.is_null() { return; }
    // SAFETY: napi points to initialized driver-owned storage.
    unsafe {
        let state = (*napi).state.load(Ordering::Acquire);
        if state & NAPI_STATE_SCHEDULED == 0 { return; }
        if state & NAPI_STATE_DISABLED != 0 {
            (*napi).state.fetch_and(!NAPI_STATE_SCHEDULED, Ordering::AcqRel);
            (*napi).ingress_generation.store(0, Ordering::Release);
            return;
        }
        let generation = (*napi).ingress_generation.load(Ordering::Acquire);
        let dev = (*napi).dev;
        if dev.is_null() || generation == 0 {
            (*napi).state.fetch_and(!NAPI_STATE_SCHEDULED, Ordering::AcqRel);
            (*napi).ingress_generation.store(0, Ordering::Release);
            return;
        }
        #[cfg(any(target_os = "oxide-kernel", feature = "hosted"))]
        let _lease = {
        let iface = net::NetIfaceId::from_raw((*dev).ifindex);
        let Some(lease) = net::sock::stack().ifaces
            .acquire_ingress_generation(iface, generation) else {
            (*napi).state.fetch_and(!NAPI_STATE_SCHEDULED, Ordering::AcqRel);
            (*napi).ingress_generation.store(0, Ordering::Release);
            return;
        };
            lease
        };
        (*napi).scheduled.fetch_add(1, Ordering::AcqRel);
        if let Some(poll) = (*napi).poll {
            let budget = if (*napi).weight > 0 { (*napi).weight } else { DEFAULT_NAPI_WEIGHT };
            let _ = poll(napi, budget);
        }
        (*napi).state.fetch_and(!NAPI_STATE_SCHEDULED, Ordering::AcqRel);
        (*napi).ingress_generation.store(0, Ordering::Release);
    }
}

/// # C: O(poll budget)
unsafe extern "C" fn __napi_schedule_irqoff(napi: *mut LinuxNapiStruct) {
    // SAFETY: irqoff variant has the same NAPI storage contract; Oxide does not model softirq masking here.
    unsafe { __napi_schedule(napi); }
}

/// # C: O(1)
unsafe extern "C" fn napi_schedule_prep(napi: *mut LinuxNapiStruct) -> bool {
    if napi.is_null() { return false; }
    // SAFETY: napi points to initialized driver-owned storage.
    unsafe {
        let dev = (*napi).dev;
        if dev.is_null() || (*dev).ifindex == 0 { return false; }
        #[cfg(any(target_os = "oxide-kernel", feature = "hosted"))]
        let generation = {
        let iface = net::NetIfaceId::from_raw((*dev).ifindex);
        let Some(lease) = net::sock::stack().ifaces.acquire_ingress(iface) else {
            return false;
        };
            lease.generation()
        };
        #[cfg(all(not(target_os = "oxide-kernel"), not(feature = "hosted")))]
        let generation = 1;
        if (*napi).ingress_generation.compare_exchange(0, generation,
            Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            return false;
        }
        let mut state = (*napi).state.load(Ordering::Acquire);
        loop {
            if state & (NAPI_STATE_DISABLED | NAPI_STATE_SCHEDULED) != 0 {
                let _ = (*napi).ingress_generation.compare_exchange(generation, 0,
                    Ordering::AcqRel, Ordering::Acquire);
                return false;
            }
            match (*napi).state.compare_exchange_weak(state, state | NAPI_STATE_SCHEDULED,
                Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(next) => state = next,
            }
        }
        true
    }
}

/// # C: O(1)
unsafe extern "C" fn napi_complete_done(napi: *mut LinuxNapiStruct, _work_done: i32) -> bool {
    if napi.is_null() { return false; }
    // SAFETY: napi points to initialized driver-owned storage.
    unsafe {
        (*napi).state.fetch_and(!NAPI_STATE_SCHEDULED, Ordering::AcqRel);
        (*napi).ingress_generation.store(0, Ordering::Release);
    }
    true
}

/// # C: O(len)
unsafe extern "C" fn napi_alloc_skb(_napi: *mut LinuxNapiStruct, len: u32) -> *mut LinuxSkBuff {
    skb::dev_alloc_skb(len)
}

/// # C: O(size)
unsafe extern "C" fn napi_build_skb(data: *mut c_void, frag_size: u32) -> *mut LinuxSkBuff {
    // SAFETY: same ABI contract as build_skb.
    unsafe { skb::build_skb(data, frag_size) }
}

/// # C: O(1)
unsafe extern "C" fn napi_consume_skb(skbp: *mut LinuxSkBuff, _budget: i32) {
    // SAFETY: caller transfers skb ownership to the consume path.
    unsafe { skb::consume_skb(skbp); }
}

/// # C: O(1)
unsafe extern "C" fn napi_get_frags(_napi: *mut LinuxNapiStruct) -> *mut LinuxSkBuff {
    skb::alloc_skb(0, 0)
}

/// # C: O(frame)
unsafe extern "C" fn napi_gro_frags(napi: *mut LinuxNapiStruct) -> i32 {
    let skb = unsafe { napi_get_frags(napi) };
    // SAFETY: gro_receive_skb consumes the temporary skb.
    unsafe { gro_receive_skb(napi, skb) }
}

/// # C: O(frame)
unsafe extern "C" fn gro_receive_skb(napi: *mut LinuxNapiStruct, skbp: *mut LinuxSkBuff) -> i32 {
    if !napi.is_null() && !skbp.is_null() {
        // SAFETY: caller supplies live NAPI and skb objects for this receive operation.
        unsafe { (*skbp).queue_mapping = (*napi).rxq.min(u16::MAX as u32) as u16; }
    }
    // SAFETY: GRO compatibility feeds the skb through the normal RX path.
    unsafe { super::core::netif_rx_for_napi(skbp) }
}

/// # C: O(fragsz)
unsafe extern "C" fn __napi_alloc_frag_align(fragsz: u32, align_mask: u32) -> *mut c_void {
    let align = ((align_mask as usize) + 1).max(FRAG_ALIGN).next_power_of_two();
    let layout = match Layout::from_size_align(fragsz as usize, align) { Ok(v) => v, Err(_) => return core::ptr::null_mut() };
    // SAFETY: layout is valid and zeroed memory matches driver RX buffer expectations.
    unsafe { alloc_zeroed(layout) as *mut c_void }
}

/// # C: O(fragsz)
unsafe extern "C" fn skb_page_frag_refill(sz: u32, page_frag: *mut c_void, gfp: u32) -> bool {
    if page_frag.is_null() { return false; }
    let p = unsafe { __napi_alloc_frag_align(sz, 0) };
    let _ = gfp;
    !p.is_null()
}

/// # C: O(1)
unsafe extern "C" fn netif_queue_set_napi(_dev: *mut LinuxNetDevice, q: u16, napi: *mut LinuxNapiStruct) {
    if napi.is_null() { return; }
    // SAFETY: napi points to initialized driver-owned storage.
    unsafe {
        (*napi).rxq = q as u32;
        (*napi).txq = q as u32;
    }
}

/// # C: O(1)
unsafe extern "C" fn netif_napi_set_irq_locked(napi: *mut LinuxNapiStruct, irq: i32) {
    if napi.is_null() { return; }
    // SAFETY: napi points to initialized driver-owned storage; store irq in txq as compatibility metadata.
    unsafe { (*napi).txq = irq.max(0) as u32; }
}

#[cfg(all(test, feature = "hosted"))]
mod tests;
