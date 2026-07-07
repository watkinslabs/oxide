extern crate alloc;

use super::types::*;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::min;
use core::ptr::{copy_nonoverlapping, null_mut};

const SKB_HEADROOM: usize = 64;
const SKB_MIN_CAPACITY: usize = 256;
const SKB_PROTOCOL_OFFSET: usize = 12;

struct SkbOwner {
    skb: LinuxSkBuff,
    buf: Vec<u8>,
}

/// Register Linux skb KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("alloc_skb",      alloc_skb      as *const () as usize, false);
    export("__alloc_skb",    __alloc_skb    as *const () as usize, false);
    export("dev_alloc_skb",  dev_alloc_skb  as *const () as usize, false);
    export("kfree_skb",      kfree_skb      as *const () as usize, false);
    export("dev_kfree_skb",  dev_kfree_skb  as *const () as usize, false);
    export("skb_put",        skb_put        as *const () as usize, false);
    export("skb_push",       skb_push       as *const () as usize, false);
    export("skb_pull",       skb_pull       as *const () as usize, false);
    export("skb_reserve",    skb_reserve    as *const () as usize, false);
    export("skb_tail_pointer", skb_tail_pointer as *const () as usize, false);
    export("eth_type_trans", eth_type_trans as *const () as usize, false);
}

/// # C: O(size)
pub(super) extern "C" fn alloc_skb(size: u32, _priority: u32) -> *mut LinuxSkBuff {
    skb_alloc(size as usize, 0)
}

/// # C: O(size)
pub(super) extern "C" fn __alloc_skb(size: u32, priority: u32, _flags: u32, _node: i32) -> *mut LinuxSkBuff {
    alloc_skb(size, priority)
}

/// # C: O(length + SKB_HEADROOM)
pub(super) extern "C" fn dev_alloc_skb(length: u32) -> *mut LinuxSkBuff {
    skb_alloc(length as usize + SKB_HEADROOM, SKB_HEADROOM)
}

/// # C: O(1)
pub(super) unsafe extern "C" fn kfree_skb(skb: *mut LinuxSkBuff) {
    if skb.is_null() { return; }
    // SAFETY: skb owner was installed by skb_alloc/from_frame.
    let owner = unsafe { (*skb).owner as *mut SkbOwner };
    if owner.is_null() { return; }
    // SAFETY: owner is uniquely reclaimed by the Linux skb free path.
    unsafe { drop(Box::from_raw(owner)); }
}

/// # C: O(1)
pub(super) unsafe extern "C" fn dev_kfree_skb(skb: *mut LinuxSkBuff) {
    unsafe { kfree_skb(skb); }
}

/// # C: O(len)
pub(super) unsafe extern "C" fn skb_put(skb: *mut LinuxSkBuff, len: u32) -> *mut u8 {
    if skb.is_null() { return null_mut(); }
    let len = len as usize;
    // SAFETY: skb points to an owned LinuxSkBuff.
    unsafe {
        if (*skb).tail.add(len) > (*skb).end { return null_mut(); }
        let p = (*skb).tail;
        (*skb).tail = (*skb).tail.add(len);
        (*skb).len = (*skb).len.saturating_add(len as u32);
        p
    }
}

/// # C: O(len)
pub(super) unsafe extern "C" fn skb_push(skb: *mut LinuxSkBuff, len: u32) -> *mut u8 {
    if skb.is_null() { return null_mut(); }
    let len = len as usize;
    // SAFETY: skb points to an owned LinuxSkBuff.
    unsafe {
        if ptr_distance((*skb).head, (*skb).data) < len { return null_mut(); }
        (*skb).data = (*skb).data.sub(len);
        (*skb).len = (*skb).len.saturating_add(len as u32);
        (*skb).data
    }
}

/// # C: O(len)
pub(super) unsafe extern "C" fn skb_pull(skb: *mut LinuxSkBuff, len: u32) -> *mut u8 {
    if skb.is_null() { return null_mut(); }
    let len = len as usize;
    // SAFETY: skb points to an owned LinuxSkBuff.
    unsafe {
        if len > (*skb).len as usize { return null_mut(); }
        (*skb).data = (*skb).data.add(len);
        (*skb).len -= len as u32;
        (*skb).data
    }
}

/// # C: O(len)
pub(super) unsafe extern "C" fn skb_reserve(skb: *mut LinuxSkBuff, len: u32) {
    if skb.is_null() { return; }
    let len = len as usize;
    // SAFETY: skb points to an owned LinuxSkBuff.
    unsafe {
        let room = ptr_distance((*skb).data, (*skb).end);
        let n = min(len, room);
        (*skb).data = (*skb).data.add(n);
        (*skb).tail = (*skb).data;
        (*skb).len = 0;
    }
}

/// # C: O(1)
pub(super) unsafe extern "C" fn skb_tail_pointer(skb: *const LinuxSkBuff) -> *mut u8 {
    if skb.is_null() { return null_mut(); }
    // SAFETY: skb points to a LinuxSkBuff.
    unsafe { (*skb).tail }
}

/// # C: O(ETH_HLEN)
pub(super) unsafe extern "C" fn eth_type_trans(skb: *mut LinuxSkBuff, dev: *mut LinuxNetDevice) -> u16 {
    if skb.is_null() { return 0; }
    // SAFETY: skb points to a LinuxSkBuff; data is checked for Ethernet header length.
    unsafe {
        (*skb).dev = dev;
        if (*skb).len < ETH_HLEN as u32 { return 0; }
        let p = (*skb).data.add(SKB_PROTOCOL_OFFSET);
        let proto = ((*p as u16) << u8::BITS) | (*p.add(1) as u16);
        (*skb).protocol = proto;
        let _ = skb_pull(skb, ETH_HLEN as u32);
        proto
    }
}

/// # C: O(1)
pub(super) fn skb_data(skb: *const LinuxSkBuff) -> Option<&'static [u8]> {
    if skb.is_null() { return None; }
    // SAFETY: caller uses the returned view before freeing the skb.
    unsafe { Some(core::slice::from_raw_parts((*skb).data, (*skb).len as usize)) }
}

/// # C: O(frame)
pub(super) fn skb_from_frame(frame: &[u8], dev: *mut LinuxNetDevice, protocol: u16) -> *mut LinuxSkBuff {
    let skb = skb_alloc(frame.len(), 0);
    if skb.is_null() { return null_mut(); }
    // SAFETY: skb allocation has exactly frame.len() writable tailroom.
    unsafe {
        let dst = skb_put(skb, frame.len() as u32);
        if dst.is_null() {
            kfree_skb(skb);
            return null_mut();
        }
        copy_nonoverlapping(frame.as_ptr(), dst, frame.len());
        (*skb).dev = dev;
        (*skb).protocol = protocol;
    }
    skb
}

fn skb_alloc(size: usize, reserve: usize) -> *mut LinuxSkBuff {
    let cap = size.max(SKB_MIN_CAPACITY);
    let mut owner = Box::new(SkbOwner {
        skb: LinuxSkBuff {
            head: null_mut(), data: null_mut(), tail: null_mut(), end: null_mut(),
            len: 0, protocol: 0, dev: null_mut(), cb: [0; SKB_CB_LEN], owner: null_mut(),
        },
        buf: alloc::vec![0u8; cap],
    });
    let base = owner.buf.as_mut_ptr();
    let n = reserve.min(cap);
    owner.skb.head = base;
    // SAFETY: base is valid for cap bytes, n <= cap.
    unsafe {
        owner.skb.data = base.add(n);
        owner.skb.tail = owner.skb.data;
        owner.skb.end = base.add(cap);
    }
    let ptr = &mut owner.skb as *mut LinuxSkBuff;
    owner.skb.owner = (&mut *owner) as *mut SkbOwner as *mut core::ffi::c_void;
    let _ = Box::into_raw(owner);
    ptr
}

/// # C: O(skb->len)
pub(super) unsafe fn skb_copy_to_vec_and_free(skb: *mut LinuxSkBuff) -> Option<(Vec<u8>, u16, *mut LinuxNetDevice)> {
    let data = skb_data(skb)?.to_vec();
    // SAFETY: skb is valid until kfree_skb below.
    let (proto, dev) = unsafe { ((*skb).protocol, (*skb).dev) };
    // SAFETY: netif_rx consumes the skb, matching Linux ownership.
    unsafe { kfree_skb(skb); }
    Some((data, proto, dev))
}

fn ptr_distance(start: *const u8, end: *const u8) -> usize {
    (end as usize).saturating_sub(start as usize)
}
