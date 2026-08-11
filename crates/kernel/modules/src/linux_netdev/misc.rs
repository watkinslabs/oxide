use super::types::*;
use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicU32, Ordering};

const NETDEV_STATE_PRESENT: u64 = 1 << 3;
const RSS_KEY_BYTES: usize = 40;
static RTNL_DEPTH: AtomicU32 = AtomicU32::new(0);
const fn reverse_byte(mut value: u8) -> u8 {
    let mut out = 0;
    let mut bit = 0;
    while bit < u8::BITS {
        out = (out << 1) | (value & 1);
        value >>= 1;
        bit += 1;
    }
    out
}

const fn byte_reverse_table() -> [u8; 256] {
    let mut table = [0; 256];
    let mut index = 0;
    while index < table.len() {
        table[index] = reverse_byte(index as u8);
        index += 1;
    }
    table
}

#[no_mangle]
pub static byte_rev_table: [u8; 256] = byte_reverse_table();
#[no_mangle]
pub static phys_base: u64 = 0;
#[no_mangle]
pub static __tracepoint_xdp_exception: u64 = 0;

/// Register Linux netdev miscellaneous KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("rtnl_lock", rtnl_lock as *const () as usize, false);
    export("rtnl_unlock", rtnl_unlock as *const () as usize, false);
    export("dev_close", dev_close as *const () as usize, false);
    export("netif_device_attach", netif_device_attach as *const () as usize, false);
    export("netif_device_detach", netif_device_detach as *const () as usize, false);
    export("netif_schedule_queue", netif_schedule_queue as *const () as usize, false);
    export("synchronize_net", synchronize_net as *const () as usize, false);
    export("netdev_notify_peers", netdev_notify_peers as *const () as usize, false);
    export("netdev_update_features", netdev_update_features as *const () as usize, false);
    export("netdev_stats_to_stats64", netdev_stats_to_stats64 as *const () as usize, false);
    export("netdev_stat_queue_sum", netdev_stat_queue_sum as *const () as usize, false);
    export("netdev_rss_key_fill", netdev_rss_key_fill as *const () as usize, false);
    export("net_dim_work_cancel", net_dim_work_cancel as *const () as usize, false);
    export("netdev_printk", netdev_printk as *const () as usize, false);
    export("netdev_err", netdev_err as *const () as usize, false);
    export("netdev_warn", netdev_warn as *const () as usize, false);
    export("netdev_notice", netdev_notice as *const () as usize, false);
    export("netdev_info", netdev_info as *const () as usize, false);
    export("netdev_sw_irq_coalesce_default_on", netdev_sw_irq_coalesce_default_on as *const () as usize, false);
    export("dev_kfree_skb_any_reason", dev_kfree_skb_any_reason as *const () as usize, false);
    export("dev_fetch_sw_netstats", dev_fetch_sw_netstats as *const () as usize, false);
    export("csum_ipv6_magic", csum_ipv6_magic as *const () as usize, false);
    export("xdp_convert_zc_to_xdp_frame", xdp_null as *const () as usize, false);
    export("xdp_do_flush", xdp_do_flush as *const () as usize, false);
    export("xdp_do_redirect", xdp_drop as *const () as usize, false);
    export("xdp_features_clear_redirect_target", xdp_feature as *const () as usize, false);
    export("xdp_features_set_redirect_target", xdp_feature as *const () as usize, false);
    export("xdp_master_redirect", xdp_drop as *const () as usize, false);
    export("xdp_return_frame", xdp_return_frame as *const () as usize, false);
    export("xdp_return_frame_rx_napi", xdp_return_frame_rx_napi as *const () as usize, false);
    export("xdp_rxq_info_reg_mem_model", xdp_ok as *const () as usize, false);
    export("xdp_rxq_info_unreg", xdp_rxq_info_unreg as *const () as usize, false);
    export("xdp_rxq_info_unreg_mem_model", xdp_rxq_info_unreg_mem_model as *const () as usize, false);
    export("xdp_set_features_flag", xdp_feature as *const () as usize, false);
    export("xdp_warn", xdp_warn as *const () as usize, false);
    export("__xdp_rxq_info_reg", __xdp_rxq_info_reg as *const () as usize, false);
    export("bpf_dispatcher_xdp_func", bpf_dispatcher_xdp_func as *const () as usize, false);
    export("bpf_warn_invalid_xdp_action", bpf_warn_invalid_xdp_action as *const () as usize, false);
    export("__SCK__tp_func_xdp_exception", trace_xdp_exception as *const () as usize, false);
    export("__SCT__tp_func_xdp_exception", trace_xdp_exception as *const () as usize, false);
    export("__tracepoint_xdp_exception", (&__tracepoint_xdp_exception as *const u64) as usize, false);
    export("phys_base", (&phys_base as *const u64) as usize, false);
    export("byte_rev_table", byte_rev_table.as_ptr() as usize, false);
}

/// # C: O(1)
unsafe extern "C" fn rtnl_lock() { RTNL_DEPTH.fetch_add(1, Ordering::AcqRel); }
/// # C: O(1)
unsafe extern "C" fn rtnl_unlock() { let _ = RTNL_DEPTH.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| Some(v.saturating_sub(1))); }

/// # C: O(1)
unsafe extern "C" fn dev_close(dev: *mut LinuxNetDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev points to a valid net_device.
    unsafe { (*dev).flags &= !IFF_UP; }
    LINUX_OK
}

/// # C: O(1)
unsafe extern "C" fn netif_device_attach(dev: *mut LinuxNetDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev points to a valid net_device state word.
    unsafe { (*dev).state.fetch_or(NETDEV_STATE_PRESENT, Ordering::AcqRel); }
}

/// # C: O(1)
unsafe extern "C" fn netif_device_detach(dev: *mut LinuxNetDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev points to a valid net_device state word.
    unsafe { (*dev).state.fetch_and(!NETDEV_STATE_PRESENT, Ordering::AcqRel); }
}

/// # C: O(1)
unsafe extern "C" fn netif_schedule_queue(_txq: *mut c_void) {}
/// # C: O(grace period)
unsafe extern "C" fn synchronize_net() { sync::synchronize_rcu(); }

/// # C: O(1)
unsafe extern "C" fn csum_ipv6_magic(src: *const u8, dst: *const u8, len: u32, proto: u8, sum: u32) -> u16 {
    if src.is_null() || dst.is_null() { return 0; }
    // SAFETY: Linux ABI supplies two readable 16-byte IPv6 addresses.
    let (src, dst) = unsafe { (core::slice::from_raw_parts(src, 16), core::slice::from_raw_parts(dst, 16)) };
    let mut acc = sum as u64;
    for pair in src.chunks_exact(2).chain(dst.chunks_exact(2)) { acc += u16::from_ne_bytes([pair[0], pair[1]]) as u64; }
    acc += len.to_be() as u64 + (proto as u32).to_be() as u64;
    while acc >> 16 != 0 { acc = (acc & 0xffff) + (acc >> 16); }
    !(acc as u16)
}
/// # C: O(1)
unsafe extern "C" fn netdev_notify_peers(_dev: *mut LinuxNetDevice) {}
/// # C: O(1)
unsafe extern "C" fn netdev_update_features(_dev: *mut LinuxNetDevice) {}
/// # C: O(1)
unsafe extern "C" fn netdev_sw_irq_coalesce_default_on(_dev: *mut LinuxNetDevice) {}

/// # C: O(1)
unsafe extern "C" fn dev_kfree_skb_any_reason(skb: *mut LinuxSkBuff, _reason: i32) {
    // SAFETY: this KPI consumes the skb on every caller context, matching the common free path.
    unsafe { super::skb::kfree_skb(skb); }
}

/// # C: O(online CPUs)
unsafe extern "C" fn dev_fetch_sw_netstats(dst: *mut LinuxRtnlLinkStats64,
    tstats: *const LinuxPcpuSwNetStats) {
    if dst.is_null() || tstats.is_null() { return; }
    // SAFETY: the current Linux module runtime supplies a single CPU stats slot.
    unsafe {
        (*dst).rx_packets = (*dst).rx_packets.wrapping_add((*tstats).rx_packets);
        (*dst).rx_bytes = (*dst).rx_bytes.wrapping_add((*tstats).rx_bytes);
        (*dst).tx_packets = (*dst).tx_packets.wrapping_add((*tstats).tx_packets);
        (*dst).tx_bytes = (*dst).tx_bytes.wrapping_add((*tstats).tx_bytes);
    }
}

/// # C: O(1)
unsafe extern "C" fn netdev_stats_to_stats64(dst: *mut LinuxRtnlLinkStats64, dev: *const LinuxNetDevice) {
    if dst.is_null() || dev.is_null() { return; }
    // SAFETY: pointers are checked and both structs share the same C layout.
    unsafe { *dst = (*dev).stats.compat; }
}

/// # C: O(1)
unsafe extern "C" fn netdev_stat_queue_sum(dev: *const LinuxNetDevice, dst: *mut LinuxRtnlLinkStats64) {
    // SAFETY: same pointer contract as netdev_stats_to_stats64.
    unsafe { netdev_stats_to_stats64(dst, dev); }
}

/// # C: O(len)
unsafe extern "C" fn netdev_rss_key_fill(buf: *mut c_void, len: usize) {
    if buf.is_null() { return; }
    let n = len.min(RSS_KEY_BYTES);
    // SAFETY: caller supplies len writable bytes.
    unsafe {
        for i in 0..n {
            *(buf as *mut u8).add(i) = (i as u8).wrapping_mul(37).wrapping_add(0xa5);
        }
    }
}

/// # C: O(1)
unsafe extern "C" fn net_dim_work_cancel(_dim: *mut c_void) {}

/// # C: O(1)
unsafe extern "C" fn netdev_printk(_level: *const c_char, _dev: *const LinuxNetDevice, _fmt: *const c_char, mut _args: ...) {}
/// # C: O(1)
unsafe extern "C" fn netdev_err(_dev: *const LinuxNetDevice, _fmt: *const c_char, mut _args: ...) {}
/// # C: O(1)
unsafe extern "C" fn netdev_warn(_dev: *const LinuxNetDevice, _fmt: *const c_char, mut _args: ...) {}
/// # C: O(1)
unsafe extern "C" fn netdev_notice(_dev: *const LinuxNetDevice, _fmt: *const c_char, mut _args: ...) {}
/// # C: O(1)
unsafe extern "C" fn netdev_info(_dev: *const LinuxNetDevice, _fmt: *const c_char, mut _args: ...) {}

/// # C: O(1)
unsafe extern "C" fn xdp_null(_p: *mut c_void) -> *mut c_void { core::ptr::null_mut() }
/// # C: O(1)
unsafe extern "C" fn xdp_do_flush() {}
/// # C: O(1)
unsafe extern "C" fn xdp_drop(_p0: *mut c_void, _p1: *mut c_void, _p2: *mut c_void) -> i32 { -LINUX_EINVAL }
/// # C: O(1)
unsafe extern "C" fn xdp_feature(_dev: *mut LinuxNetDevice) {}
/// # C: O(1)
unsafe extern "C" fn xdp_return_frame(_frame: *mut c_void) {}
/// # C: O(1)
unsafe extern "C" fn xdp_return_frame_rx_napi(_frame: *mut c_void) {}
/// # C: O(1)
unsafe extern "C" fn xdp_ok(_rxq: *mut c_void, _type_id: u32, _allocator: *mut c_void) -> i32 { LINUX_OK }
/// # C: O(1)
unsafe extern "C" fn xdp_rxq_info_unreg(_rxq: *mut c_void) {}
/// # C: O(1)
unsafe extern "C" fn xdp_rxq_info_unreg_mem_model(_rxq: *mut c_void) {}
/// # C: O(1)
unsafe extern "C" fn xdp_warn(_msg: *const c_char) {}
/// # C: O(1)
unsafe extern "C" fn __xdp_rxq_info_reg(_rxq: *mut c_void, _dev: *mut LinuxNetDevice, _queue_index: u32, _napi_id: u32) -> i32 { LINUX_OK }
/// # C: O(1)
unsafe extern "C" fn bpf_dispatcher_xdp_func(_ctx: *mut c_void, _insnsi: *const c_void, _bpf_func: *const c_void) -> u32 { 0 }
/// # C: O(1)
unsafe extern "C" fn bpf_warn_invalid_xdp_action(_dev: *mut LinuxNetDevice, _prog: *mut c_void, _act: u32) {}
/// # C: O(1)
unsafe extern "C" fn trace_xdp_exception(_dev: *mut LinuxNetDevice, _prog: *mut c_void, _act: u32) {}
