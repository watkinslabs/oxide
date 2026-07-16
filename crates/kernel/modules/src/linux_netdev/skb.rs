extern crate alloc;

use super::types::*;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::min;
use core::ffi::c_void;
use core::ptr::{copy_nonoverlapping, null_mut};

const SKB_HEADROOM: usize = 64;
const SKB_MIN_CAPACITY: usize = 256;
const SKB_PROTOCOL_OFFSET: usize = 12;

struct SkbOwner {
    skb: LinuxSkBuff,
    buf: Vec<u8>,
    mac_header: Option<usize>,
    ingress_iface: u32,
    ingress_generation: u64,
}

/// Register Linux skb KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("alloc_skb",      alloc_skb      as *const () as usize, false);
    export("__alloc_skb",    __alloc_skb    as *const () as usize, false);
    export("dev_alloc_skb",  dev_alloc_skb  as *const () as usize, false);
    export("kfree_skb",      kfree_skb      as *const () as usize, false);
    export("consume_skb",    consume_skb    as *const () as usize, false);
    export("dev_kfree_skb",  dev_kfree_skb  as *const () as usize, false);
    export("skb_put",        skb_put        as *const () as usize, false);
    export("skb_push",       skb_push       as *const () as usize, false);
    export("skb_pull",       skb_pull       as *const () as usize, false);
    export("skb_reserve",    skb_reserve    as *const () as usize, false);
    export("skb_tail_pointer", skb_tail_pointer as *const () as usize, false);
    export("eth_type_trans", eth_type_trans as *const () as usize, false);
    export("skb_trim",       skb_trim       as *const () as usize, false);
    export("___pskb_trim",   ___pskb_trim   as *const () as usize, false);
    export("__pskb_pull_tail", __pskb_pull_tail as *const () as usize, false);
    export("pskb_expand_head", pskb_expand_head as *const () as usize, false);
    export("__skb_pad",      __skb_pad      as *const () as usize, false);
    export("skb_copy_bits",  skb_copy_bits  as *const () as usize, false);
    export("skb_partial_csum_set", skb_partial_csum_set as *const () as usize, false);
    export("skb_tstamp_tx",  skb_tstamp_tx  as *const () as usize, false);
    export("skb_clone_tx_timestamp", skb_clone_tx_timestamp as *const () as usize, false);
    export("sk_skb_reason_drop", sk_skb_reason_drop as *const () as usize, false);
    export("skb_add_rx_frag_netmem", skb_add_rx_frag_netmem as *const () as usize, false);
    export("skb_coalesce_rx_frag", skb_coalesce_rx_frag as *const () as usize, false);
    export("skb_to_sgvec",   skb_to_sgvec   as *const () as usize, false);
    export("__skb_flow_dissect", __skb_flow_dissect as *const () as usize, false);
    export("build_skb",      build_skb      as *const () as usize, false);
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

/// # C: O(1)
pub(super) unsafe extern "C" fn consume_skb(skb: *mut LinuxSkBuff) {
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

/// # C: O(1)
pub(super) unsafe extern "C" fn skb_trim(skb: *mut LinuxSkBuff, len: u32) {
    if skb.is_null() { return; }
    // SAFETY: skb points to an owned LinuxSkBuff.
    unsafe {
        if len <= (*skb).len {
            (*skb).len = len;
            (*skb).tail = (*skb).data.add(len as usize);
        }
    }
}

/// # C: O(1)
pub(super) unsafe extern "C" fn ___pskb_trim(skb: *mut LinuxSkBuff, len: u32) -> i32 {
    if skb.is_null() { return -LINUX_EINVAL; }
    // SAFETY: skb points to an owned LinuxSkBuff.
    unsafe { skb_trim(skb, len); }
    LINUX_OK
}

/// # C: O(1)
pub(super) unsafe extern "C" fn __pskb_pull_tail(skb: *mut LinuxSkBuff, delta: u32) -> *mut u8 {
    if skb.is_null() { return null_mut(); }
    // SAFETY: skb points to an owned LinuxSkBuff.
    unsafe {
        if delta > (*skb).len { return null_mut(); }
        (*skb).data.add(delta as usize)
    }
}

/// # C: O(len)
pub(super) unsafe extern "C" fn pskb_expand_head(skb: *mut LinuxSkBuff, nhead: i32, ntail: i32, _gfp: u32) -> i32 {
    if skb.is_null() || nhead < 0 || ntail < 0 { return -LINUX_EINVAL; }
    let add_head = nhead as usize;
    let add_tail = ntail as usize;
    // SAFETY: skb owner was installed by skb_alloc/from_frame.
    unsafe { if ensure_room(skb, add_head, add_tail) { LINUX_OK } else { -LINUX_ENOMEM } }
}

/// # C: O(pad)
pub(super) unsafe extern "C" fn __skb_pad(skb: *mut LinuxSkBuff, pad: u32, free_on_error: bool) -> i32 {
    if skb.is_null() { return -LINUX_EINVAL; }
    // SAFETY: skb points to an owned LinuxSkBuff.
    unsafe {
        if ensure_room(skb, 0, pad as usize) {
            let p = skb_put(skb, pad);
            if !p.is_null() { core::ptr::write_bytes(p, 0, pad as usize); }
            LINUX_OK
        } else {
            if free_on_error { kfree_skb(skb); }
            -LINUX_ENOMEM
        }
    }
}

/// # C: O(len)
pub(super) unsafe extern "C" fn skb_copy_bits(skb: *const LinuxSkBuff, offset: i32, to: *mut c_void, len: i32) -> i32 {
    if skb.is_null() || to.is_null() || offset < 0 || len < 0 { return -LINUX_EINVAL; }
    let off = offset as usize;
    let len = len as usize;
    // SAFETY: skb and destination are valid for the requested checked ranges.
    unsafe {
        if off.checked_add(len).map_or(true, |end| end > (*skb).len as usize) { return -LINUX_EINVAL; }
        copy_nonoverlapping((*skb).data.add(off), to as *mut u8, len);
    }
    LINUX_OK
}

/// # C: O(1)
pub(super) unsafe extern "C" fn skb_partial_csum_set(skb: *mut LinuxSkBuff, start: u16, off: u16) -> bool {
    if skb.is_null() { return false; }
    // SAFETY: skb points to an owned LinuxSkBuff.
    unsafe {
        (*skb).ip_summed = CHECKSUM_PARTIAL;
        (*skb).csum_start = start;
        (*skb).csum_offset = off;
    }
    true
}

/// # C: O(1)
pub(super) unsafe extern "C" fn skb_tstamp_tx(_skb: *mut LinuxSkBuff, _hwtstamps: *const c_void) {}

/// # C: O(1)
pub(super) unsafe extern "C" fn skb_clone_tx_timestamp(_skb: *mut LinuxSkBuff) {}

/// # C: O(1)
pub(super) unsafe extern "C" fn sk_skb_reason_drop(skb: *mut LinuxSkBuff, _reason: u32) {
    unsafe { kfree_skb(skb); }
}

/// # C: O(size)
pub(super) unsafe extern "C" fn skb_add_rx_frag_netmem(skb: *mut LinuxSkBuff, _i: i32, _netmem: *mut c_void, _off: i32, size: i32, _truesize: u32) {
    if skb.is_null() || size <= 0 { return; }
    // SAFETY: skb points to an owned LinuxSkBuff.
    unsafe {
        if ensure_room(skb, 0, size as usize) {
            let p = skb_put(skb, size as u32);
            if !p.is_null() { core::ptr::write_bytes(p, 0, size as usize); }
            (*skb).nr_frags = (*skb).nr_frags.saturating_add(1);
        }
    }
}

/// # C: O(size)
pub(super) unsafe extern "C" fn skb_coalesce_rx_frag(skb: *mut LinuxSkBuff, i: i32, size: u32, truesize: u32) {
    unsafe { skb_add_rx_frag_netmem(skb, i, null_mut(), 0, size as i32, truesize); }
}

/// # C: O(len)
pub(super) unsafe extern "C" fn skb_to_sgvec(skb: *const LinuxSkBuff, _sg: *mut c_void, offset: i32, len: i32) -> i32 {
    if skb.is_null() || offset < 0 || len < 0 { return -LINUX_EINVAL; }
    // SAFETY: skb points to a LinuxSkBuff.
    unsafe {
        if (offset as usize).checked_add(len as usize).map_or(true, |end| end > (*skb).len as usize) { return -LINUX_EINVAL; }
    }
    if len == 0 { 0 } else { 1 }
}

/// # C: O(1)
pub(super) unsafe extern "C" fn __skb_flow_dissect() -> bool { false }

/// # C: O(frag_size)
pub(super) unsafe extern "C" fn build_skb(data: *mut c_void, frag_size: u32) -> *mut LinuxSkBuff {
    if data.is_null() || frag_size == 0 { return null_mut(); }
    let skb = skb_alloc(frag_size as usize, 0);
    if skb.is_null() { return null_mut(); }
    // SAFETY: caller supplies frag_size readable bytes and skb has matching tailroom.
    unsafe {
        let dst = skb_put(skb, frag_size);
        if dst.is_null() {
            kfree_skb(skb);
            return null_mut();
        }
        copy_nonoverlapping(data as *const u8, dst, frag_size as usize);
    }
    skb
}

/// # C: O(ETH_HLEN)
pub(super) unsafe extern "C" fn eth_type_trans(skb: *mut LinuxSkBuff, dev: *mut LinuxNetDevice) -> u16 {
    if skb.is_null() { return 0; }
    // SAFETY: skb points to a LinuxSkBuff; data is checked for Ethernet header length.
    unsafe {
        (*skb).dev = dev;
        stamp_ingress(skb, dev);
        if (*skb).len < ETH_HLEN as u32 { return 0; }
        let p = (*skb).data.add(SKB_PROTOCOL_OFFSET);
        let proto = ((*p as u16) << u8::BITS) | (*p.add(1) as u16);
        let owner = (*skb).owner as *mut SkbOwner;
        if !owner.is_null() {
            (*owner).mac_header = Some((*skb).data.offset_from((*owner).buf.as_ptr()) as usize);
        }
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
            len: 0, protocol: 0, dev: null_mut(), ip_summed: CHECKSUM_NONE,
            csum_start: 0, csum_offset: 0, nr_frags: 0, cb: [0; SKB_CB_LEN], owner: null_mut(),
        },
        buf: alloc::vec![0u8; cap],
        mac_header: None,
        ingress_iface: 0,
        ingress_generation: 0,
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

unsafe fn ensure_room(skb: *mut LinuxSkBuff, add_head: usize, add_tail: usize) -> bool {
    if skb.is_null() { return false; }
    // SAFETY: skb owner was installed by skb_alloc/from_frame.
    let owner = unsafe { (*skb).owner as *mut SkbOwner };
    if owner.is_null() { return false; }
    // SAFETY: owner uniquely owns the backing Vec for this skb.
    unsafe {
        let o = &mut *owner;
        let head_off = (*skb).head.offset_from(o.buf.as_ptr()) as usize;
        let data_off = (*skb).data.offset_from(o.buf.as_ptr()) as usize;
        let tail_off = (*skb).tail.offset_from(o.buf.as_ptr()) as usize;
        let new_data_off = data_off + add_head;
        let new_tail_off = tail_off + add_head;
        let need = new_tail_off.saturating_add(add_tail);
        if need <= o.buf.len() && add_head == 0 { return true; }
        let mut next = alloc::vec![0u8; need.max(o.buf.len().saturating_mul(2)).max(SKB_MIN_CAPACITY)];
        copy_nonoverlapping((*skb).head, next.as_mut_ptr().add(head_off + add_head), tail_off - head_off);
        o.buf = next;
        if let Some(offset) = &mut o.mac_header { *offset += add_head; }
        let base = o.buf.as_mut_ptr();
        (*skb).head = base.add(head_off);
        (*skb).data = base.add(new_data_off);
        (*skb).tail = base.add(new_tail_off);
        (*skb).end = base.add(o.buf.len());
    }
    true
}

/// # C: O(skb->len)
pub(super) unsafe fn skb_copy_to_vec_and_free(skb: *mut LinuxSkBuff)
    -> Option<(Vec<u8>, Option<Vec<u8>>, u16, u32, Option<u64>)>
{
    let data = skb_data(skb)?.to_vec();
    // SAFETY: skb and its owner remain valid until kfree_skb below.
    let (link, proto, fallback_iface, ingress_iface, ingress_generation) = unsafe {
        let dev = (*skb).dev;
        let fallback_iface = if dev.is_null() { 0 } else { (*dev).ifindex };
        let owner = (*skb).owner as *const SkbOwner;
        if owner.is_null() {
            (None, (*skb).protocol, fallback_iface, 0, 0)
        } else {
            let link = (*owner).mac_header.and_then(|start| {
                let tail = (*skb).tail.offset_from((*owner).buf.as_ptr()) as usize;
                (start <= tail).then(|| (&(*owner).buf)[start..tail].to_vec())
            });
            (link, (*skb).protocol, fallback_iface,
                (*owner).ingress_iface, (*owner).ingress_generation)
        }
    };
    // SAFETY: netif_rx consumes the skb, matching Linux ownership.
    unsafe { kfree_skb(skb); }
    let exact_generation = if ingress_iface == 0 { None } else { Some(ingress_generation) };
    let iface = if ingress_iface == 0 { fallback_iface } else { ingress_iface };
    Some((data, link, proto, iface, exact_generation))
}

#[cfg(any(target_os = "oxide-kernel", feature = "hosted"))]
unsafe fn stamp_ingress(skb: *mut LinuxSkBuff, dev: *mut LinuxNetDevice) {
    if skb.is_null() || dev.is_null() { return; }
    // SAFETY: caller holds live skb and net_device objects during RX classification.
    let (owner, iface) = unsafe { ((*skb).owner as *mut SkbOwner, (*dev).ifindex) };
    if owner.is_null() || iface == 0 { return; }
    let id = net::NetIfaceId::from_raw(iface);
    let generation = net::sock::stack().ifaces.acquire_ingress(id)
        .map_or(0, |lease| lease.generation());
    // SAFETY: SkbOwner uniquely owns metadata for this live skb.
    unsafe {
        (*owner).ingress_iface = iface;
        (*owner).ingress_generation = generation;
    }
}

#[cfg(all(not(target_os = "oxide-kernel"), not(feature = "hosted")))]
unsafe fn stamp_ingress(_skb: *mut LinuxSkBuff, _dev: *mut LinuxNetDevice) {}

fn ptr_distance(start: *const u8, end: *const u8) -> usize {
    (end as usize).saturating_sub(start as usize)
}
