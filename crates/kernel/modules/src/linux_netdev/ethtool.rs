use super::core as netcore;
use super::types::*;
use core::ffi::{c_char, c_void};
use core::ptr::{copy_nonoverlapping, write_bytes};

const ETH_GSTRING_LEN: usize = 32;
const LINK_MODE_WORD_BITS: usize = 32;

/// Register Linux ethtool/Ethernet KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("ethtool_op_get_link", ethtool_op_get_link as *const () as usize, false);
    export("ethtool_op_get_ts_info", ethtool_op_get_ts_info as *const () as usize, false);
    export("ethtool_virtdev_set_link_ksettings", ethtool_virtdev_set_link_ksettings as *const () as usize, false);
    export("ethtool_convert_legacy_u32_to_link_mode", ethtool_convert_legacy_u32_to_link_mode as *const () as usize, false);
    export("ethtool_convert_link_mode_to_legacy_u32", ethtool_convert_link_mode_to_legacy_u32 as *const () as usize, false);
    export("ethtool_puts", ethtool_puts as *const () as usize, false);
    export("ethtool_sprintf", ethtool_sprintf as *const () as usize, false);
    export("eth_validate_addr", eth_validate_addr as *const () as usize, false);
    export("eth_mac_addr", eth_mac_addr as *const () as usize, false);
    export("eth_prepare_mac_addr_change", eth_prepare_mac_addr_change as *const () as usize, false);
    export("eth_commit_mac_addr_change", eth_commit_mac_addr_change as *const () as usize, false);
    export("eth_platform_get_mac_address", eth_platform_get_mac_address as *const () as usize, false);
}

/// # C: O(1)
unsafe extern "C" fn ethtool_op_get_link(dev: *mut LinuxNetDevice) -> u32 {
    // SAFETY: helper checks NULL and reads the state atomically.
    if unsafe { netcore::carrier_is_on(dev) } { 1 } else { 0 }
}

/// # C: O(sizeof ethtool_ts_info prefix)
unsafe extern "C" fn ethtool_op_get_ts_info(_dev: *mut LinuxNetDevice, info: *mut c_void) -> i32 {
    if !info.is_null() {
        // SAFETY: ethtool callers pass a writable ts_info object; zero means no timestamping support.
        unsafe { write_bytes(info as *mut u8, 0, 64); }
    }
    LINUX_OK
}

/// # C: O(1)
unsafe extern "C" fn ethtool_virtdev_set_link_ksettings(_dev: *mut LinuxNetDevice, _cmd: *const c_void, _speed: u32, _duplex: u8) -> i32 {
    LINUX_OK
}

/// # C: O(nwords)
unsafe extern "C" fn ethtool_convert_legacy_u32_to_link_mode(dst: *mut u64, legacy: u32) {
    if dst.is_null() { return; }
    // SAFETY: Linux helper contract provides at least one link-mode word.
    unsafe { *dst = legacy as u64; }
}

/// # C: O(1)
unsafe extern "C" fn ethtool_convert_link_mode_to_legacy_u32(dst: *mut u32, src: *const u64) -> bool {
    if dst.is_null() || src.is_null() { return false; }
    // SAFETY: Linux helper contract provides at least one link-mode word.
    unsafe { *dst = (*src & u32::MAX as u64) as u32; }
    let _ = LINK_MODE_WORD_BITS;
    true
}

/// # C: O(ETH_GSTRING_LEN)
unsafe extern "C" fn ethtool_puts(data: *mut *mut u8, strp: *const c_char) {
    // SAFETY: write_gstring null-checks both pointers and the loaded *data; the ethtool_puts KPI contract is that *data has ETH_GSTRING_LEN writable bytes and strp is NUL-terminated.
    unsafe { write_gstring(data, strp); }
}

/// # C: O(ETH_GSTRING_LEN)
unsafe extern "C" fn ethtool_sprintf(data: *mut *mut u8, fmt: *const c_char, mut _args: ...) {
    // SAFETY: only the NUL-terminated fmt string is copied (variadic args are never read), and write_gstring null-checks data, *data and fmt before touching the ETH_GSTRING_LEN slot.
    unsafe { write_gstring(data, fmt); }
}

/// # C: O(ETH_ALEN)
unsafe extern "C" fn eth_validate_addr(dev: *mut LinuxNetDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    // SAFETY: dev points to a valid net_device.
    let addr = unsafe { (*dev).dev_addr };
    if valid_unicast_mac(&addr) { LINUX_OK } else { -LINUX_EINVAL }
}

/// # C: O(ETH_ALEN)
unsafe extern "C" fn eth_mac_addr(dev: *mut LinuxNetDevice, p: *mut c_void) -> i32 {
    // SAFETY: eth_prepare_mac_addr_change null-checks both arguments and reads p only as the 16-byte struct sockaddr that ndo_set_mac_address is defined to receive.
    unsafe { eth_prepare_mac_addr_change(dev, p) }
}

/// # C: O(ETH_ALEN)
unsafe extern "C" fn eth_prepare_mac_addr_change(dev: *mut LinuxNetDevice, p: *mut c_void) -> i32 {
    if dev.is_null() || p.is_null() { return -LINUX_EINVAL; }
    // SAFETY: p points to Linux sockaddr-compatible storage.
    let sa = unsafe { &*(p as *const LinuxSockAddr) };
    if !valid_unicast_mac(&sa.sa_data[..ETH_ALEN]) { return -LINUX_EINVAL; }
    // SAFETY: dev points to a valid net_device.
    unsafe { copy_nonoverlapping(sa.sa_data.as_ptr(), (*dev).dev_addr.as_mut_ptr(), ETH_ALEN); }
    LINUX_OK
}

/// # C: O(ETH_ALEN)
unsafe extern "C" fn eth_commit_mac_addr_change(dev: *mut LinuxNetDevice, p: *mut c_void) {
    // SAFETY: same preconditions as the prepare half — dev/p are the pair Linux passes to ndo_set_mac_address, and the callee null-checks both before copying ETH_ALEN bytes.
    let _ = unsafe { eth_prepare_mac_addr_change(dev, p) };
}

/// # C: O(1)
unsafe extern "C" fn eth_platform_get_mac_address(_dev: *mut c_void, _mac: *mut u8) -> i32 {
    -LINUX_ENODEV
}

unsafe fn write_gstring(data: *mut *mut u8, strp: *const c_char) {
    if data.is_null() || strp.is_null() { return; }
    // SAFETY: ethtool string helpers receive a writable ETH_GSTRING_LEN slot.
    unsafe {
        let out = *data;
        if out.is_null() { return; }
        write_bytes(out, 0, ETH_GSTRING_LEN);
        let mut n = 0usize;
        while n + 1 < ETH_GSTRING_LEN && *strp.add(n) != 0 {
            *out.add(n) = *strp.add(n) as u8;
            n += 1;
        }
        *data = out.add(ETH_GSTRING_LEN);
    }
}

fn valid_unicast_mac(addr: &[u8]) -> bool {
    if addr.len() < ETH_ALEN { return false; }
    let any = addr[..ETH_ALEN].iter().any(|b| *b != 0);
    let multicast = addr[0] & 1 != 0;
    any && !multicast
}
