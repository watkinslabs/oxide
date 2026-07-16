extern crate alloc;

use super::types::*;
use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use core::ffi::{c_char, c_void};
use core::mem::{align_of, size_of};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};

const NETDEV_MAGIC: u64 = 0x4f58_4b50_494e_4554;
const FIELD_CLEAR: u32 = 0;
const DEFAULT_TXQS: u32 = 1;
const DEFAULT_RXQS: u32 = 1;
const DEFAULT_TSO_MAX_SIZE: u32 = 65_536;
const DEFAULT_TSO_MAX_SEGS: u16 = 64;
const ETH_NAME_TEMPLATE: &[u8] = b"eth%d\0";
const DECIMAL_RADIX: usize = 10;

static NEXT_ETH_INDEX: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
#[derive(Copy, Clone)]
struct NetdevHeader {
    magic: u64,
    total: usize,
    align: usize,
    netdev_off: usize,
}

/// # C: O(sizeof(struct net_device)+sizeof_priv)
pub(super) unsafe extern "C" fn alloc_netdev_mqs(
    sizeof_priv: i32,
    name: *const c_char,
    _name_assign_type: u8,
    setup: Option<NetdevSetup>,
    txqs: u32,
    rxqs: u32,
) -> *mut LinuxNetDevice {
    if sizeof_priv < 0 { return null_mut(); }
    let dev = netdev_alloc(sizeof_priv as usize);
    if dev.is_null() { return null_mut(); }
    // SAFETY: dev points to a zeroed LinuxNetDevice allocation.
    unsafe {
        (*dev).mtu = ETH_DATA_LEN;
        (*dev).tx_queue_len = 1000;
        (*dev).addr_len = ETH_ALEN as u8;
        (*dev).flags = IFF_BROADCAST | IFF_MULTICAST;
        (*dev).num_tx_queues = txqs.max(1);
        (*dev).real_num_tx_queues = txqs.max(1);
        (*dev).real_num_rx_queues = rxqs.max(1);
        (*dev).tso_max_size = DEFAULT_TSO_MAX_SIZE;
        (*dev).tso_max_segs = DEFAULT_TSO_MAX_SEGS;
        set_name_from_template(dev, name);
        if let Some(f) = setup { f(dev); }
    }
    dev
}

/// # C: O(sizeof(struct net_device)+sizeof_priv)
pub(super) unsafe extern "C" fn alloc_netdev(
    sizeof_priv: i32,
    name: *const c_char,
    name_assign_type: u8,
    setup: Option<NetdevSetup>,
) -> *mut LinuxNetDevice {
    unsafe { alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, DEFAULT_TXQS, DEFAULT_RXQS) }
}

/// # C: O(sizeof(struct net_device)+sizeof_priv)
pub(super) unsafe extern "C" fn alloc_etherdev_mqs(
    sizeof_priv: i32,
    txqs: u32,
    rxqs: u32,
) -> *mut LinuxNetDevice {
    unsafe { alloc_netdev_mqs(sizeof_priv, ETH_NAME_TEMPLATE.as_ptr() as *const c_char, NET_NAME_UNKNOWN, Some(ether_setup), txqs, rxqs) }
}

/// # C: O(sizeof(struct net_device)+sizeof_priv)
pub(super) unsafe extern "C" fn alloc_etherdev(sizeof_priv: i32) -> *mut LinuxNetDevice {
    unsafe { alloc_etherdev_mqs(sizeof_priv, DEFAULT_TXQS, DEFAULT_RXQS) }
}

/// # C: O(1)
pub(super) unsafe extern "C" fn free_netdev(dev: *mut LinuxNetDevice) {
    if dev.is_null() { return; }
    let hp = unsafe { (dev as *mut u8).sub(size_of::<NetdevHeader>()) as *mut NetdevHeader };
    // SAFETY: Linux KPI callers must pass a pointer returned by alloc_netdev*.
    let h = unsafe { *hp };
    if h.magic != NETDEV_MAGIC { return; }
    let layout = match Layout::from_size_align(h.total, h.align) {
        Ok(v) => v,
        Err(_) => return,
    };
    // SAFETY: base/layout are reconstructed from the allocation header.
    unsafe { dealloc((dev as *mut u8).sub(h.netdev_off), layout); }
}

/// # C: O(1)
pub(super) unsafe extern "C" fn netdev_priv(dev: *const LinuxNetDevice) -> *mut c_void {
    if dev.is_null() { return null_mut(); }
    // SAFETY: dev is a valid LinuxNetDevice.
    unsafe { (*dev).priv_data }
}

/// # C: O(1)
pub(super) unsafe extern "C" fn ether_setup(dev: *mut LinuxNetDevice) {
    if dev.is_null() { return; }
    // SAFETY: caller passes a valid net_device to Linux setup callback.
    unsafe {
        (*dev).mtu = ETH_DATA_LEN;
        (*dev).addr_len = ETH_ALEN as u8;
        (*dev).flags = IFF_BROADCAST | IFF_MULTICAST;
        (*dev).tso_max_size = DEFAULT_TSO_MAX_SIZE;
        (*dev).tso_max_segs = DEFAULT_TSO_MAX_SEGS;
        (*dev).state.store(FIELD_CLEAR, Ordering::Release);
    }
}

/// # C: O(ETH_ALEN)
pub(super) unsafe extern "C" fn eth_hw_addr_set(dev: *mut LinuxNetDevice, addr: *const u8) {
    if dev.is_null() || addr.is_null() { return; }
    // SAFETY: addr points to ETH_ALEN readable bytes per Linux API.
    unsafe { core::ptr::copy_nonoverlapping(addr, (*dev).dev_addr.as_mut_ptr(), ETH_ALEN); }
}

pub(super) fn ensure_registered_name(dev: *mut LinuxNetDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev is owned by this facade while registering.
    unsafe {
        if name_has_decimal_slot(&(*dev).name) {
            let idx = NEXT_ETH_INDEX.fetch_add(1, Ordering::Relaxed);
            write_eth_name(&mut (*dev).name, idx);
        }
    }
}

fn netdev_alloc(sizeof_priv: usize) -> *mut LinuxNetDevice {
    let dev_align = align_of::<LinuxNetDevice>();
    let priv_align = align_of::<usize>();
    let netdev_off = align_up(size_of::<NetdevHeader>(), dev_align);
    let priv_off = align_up(netdev_off + size_of::<LinuxNetDevice>(), priv_align);
    let total = match priv_off.checked_add(sizeof_priv) { Some(v) => v, None => return null_mut() };
    let layout = match Layout::from_size_align(total, dev_align.max(priv_align)) {
        Ok(v) => v,
        Err(_) => return null_mut(),
    };
    // SAFETY: layout was validated above and zero init matches C allocation expectations.
    let base = unsafe { alloc_zeroed(layout) };
    if base.is_null() { return null_mut(); }
    let dev = unsafe { base.add(netdev_off) as *mut LinuxNetDevice };
    let hdr = NetdevHeader { magic: NETDEV_MAGIC, total, align: layout.align(), netdev_off };
    // SAFETY: header slot and optional private area are inside the allocation.
    unsafe {
        (base.add(netdev_off - size_of::<NetdevHeader>()) as *mut NetdevHeader).write(hdr);
        (*dev).priv_data = if sizeof_priv == 0 { null_mut() } else { base.add(priv_off) as *mut c_void };
    }
    dev
}

unsafe fn set_name_from_template(dev: *mut LinuxNetDevice, name: *const c_char) {
    if name.is_null() { return; }
    let mut i = 0usize;
    // SAFETY: Linux caller supplies a NUL-terminated name template.
    unsafe {
        while i + 1 < IFNAMSIZ && *name.add(i) != 0 {
            (*dev).name[i] = *name.add(i);
            i += 1;
        }
        (*dev).name[i] = 0;
    }
}

fn name_has_decimal_slot(name: &[c_char; IFNAMSIZ]) -> bool {
    let mut i = 0usize;
    while i + 1 < IFNAMSIZ {
        if name[i] == b'%' as c_char && name[i + 1] == b'd' as c_char { return true; }
        if name[i] == 0 { return false; }
        i += 1;
    }
    false
}

fn write_eth_name(name: &mut [c_char; IFNAMSIZ], idx: u32) {
    name.fill(0);
    name[0] = b'e' as c_char;
    name[1] = b't' as c_char;
    name[2] = b'h' as c_char;
    let mut digits = [0u8; DECIMAL_RADIX];
    let mut n = idx;
    let mut len = 0usize;
    loop {
        digits[len] = b'0' + (n % DECIMAL_RADIX as u32) as u8;
        len += 1;
        n /= DECIMAL_RADIX as u32;
        if n == 0 { break; }
    }
    let mut out = 3usize;
    while len != 0 && out + 1 < IFNAMSIZ {
        len -= 1;
        name[out] = digits[len] as c_char;
        out += 1;
    }
}

fn align_up(v: usize, a: usize) -> usize {
    (v + (a - 1)) & !(a - 1)
}
