//! Native Wine-compatible debug entry points used by the Windows personality.
//!
//! `__wine_dbg_header`/`__wine_dbg_get_channel_flags` share one lazy-init
//! cache contract (reference `dlls/ntdll/unix/debug.c`): a channel's `flags`
//! byte starts with the init bit (`DEBUG_INIT_FLAG`) set; the FIRST resolve
//! writes the computed value back with that bit cleared, so every later
//! per-call-site static check (`dbch->flags & bit`, inlined in the caller's
//! own compiled code, no kernel entry) sees the cached, narrowed value.
//! `header()` MUST resolve through the same cache as `get_channel_flags()` —
//! a second, uncached copy of the resolve logic leaves the init bit set
//! forever, so every debug-class check at every call site (including
//! disabled classes) re-enters the kernel instead of short-circuiting
//! locally (KI ledger: guest debug-channel syscall volume).

use syscall::nt::NtCall;
#[cfg(target_os = "oxide-kernel")]
use syscall::{nt::NtService, SyscallArgs};

const DEBUG_CLASS_COUNT: u64 = 4;
const DEBUG_INIT_FLAG: u8 = 1 << 7;
const DEFAULT_DEBUG_FLAGS: u8 = (1 << 0) | (1 << 1);

/// Resolve a channel's stored flags byte to the value the caller should use.
/// Mirrors `__wine_dbg_get_channel_flags`'s fast path (init bit clear: return
/// as-is) and lazy-init path (init bit set: fall back to the WINEDEBUG-unset
/// default, err+fixme only). # C: O(1)
pub fn resolve_channel_flags(raw: u8) -> u8 {
    if raw & DEBUG_INIT_FLAG == 0 { raw } else { DEFAULT_DEBUG_FLAGS }
}

/// True when `class` is enabled by a resolved (post-`resolve_channel_flags`)
/// flags byte. Mirrors `__wine_dbg_header`'s `flags & (1 << cls)` test,
/// including out-of-range classes reading as disabled. # C: O(1)
pub fn class_enabled(resolved: u8, class: u64) -> bool {
    class < DEBUG_CLASS_COUNT && resolved & (1 << class) != 0
}

/// Dispatch the debug-header ABI while the per-thread output buffer is added.
/// # C: O(1) plus one user byte read
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::WineDbgGetChannelFlags { return Some(get_channel_flags(call.args.a0)); }
    if call.service == NtService::WineDbgStrdup { return Some(strdup(call.args.a0)); }
    if call.service == NtService::WineDbgOutput { return Some(output(call.args.a0)); }
    if call.service != NtService::WineDbgHeader { return None; }
    Some(header(call.args.a0, call.args.a1))
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn dispatch(_call: NtCall) -> Option<u64> { None }

/// Resolve and cache one channel's flags byte, writing the resolved value
/// back on first (lazy-init) resolve so later static checks in the caller's
/// own code short-circuit without a kernel entry.
#[cfg(target_os = "oxide-kernel")]
fn get_channel_flags(channel: u64) -> u64 {
    if channel == 0 { return 0; }
    let mut flags = [0u8; 1];
    if uaccess::copy_from_user(&mut flags, channel).is_err() { return 0; }
    let resolved = resolve_channel_flags(flags[0]);
    if resolved == flags[0] { return resolved as u64; }
    if uaccess::copy_to_user(channel, &[resolved]).is_err() { return 0; }
    resolved as u64
}

#[cfg(target_os = "oxide-kernel")]
fn strdup(string: u64) -> u64 {
    let Some(task) = sched::live::current() else { return 0; };
    let Some(debug) = task.nt_teb().checked_add(elf_load::process_env::NT_DEBUG_INFO_OFFSET) else { return 0; };
    let mut source = alloc::vec::Vec::new();
    for index in 0..1020usize {
        let mut byte = [0u8; 1];
        if string == 0 || uaccess::copy_from_user(&mut byte, string.saturating_add(index as u64)).is_err() { return 0; }
        source.push(byte[0]);
        if byte[0] == 0 { break; }
        if index == 1019 { return 0; }
    }
    if source.last() != Some(&0) { return 0; }
    let position = uaccess::get_user_u32(debug).unwrap_or(0) as usize;
    let start = if position.saturating_add(source.len()) > 1020 { 0 } else { position };
    let Some(destination) = debug.checked_add(8).and_then(|base| base.checked_add(start as u64)) else { return 0; };
    if uaccess::copy_to_user(destination, &source).is_err() { return 0; }
    if uaccess::put_user_u32(debug, start.saturating_add(source.len()) as u32).is_err() { return 0; }
    destination
}

#[cfg(target_os = "oxide-kernel")]
fn output(string: u64) -> u64 {
    if string == 0 { return 0; }
    let mut bytes = alloc::vec::Vec::new();
    for index in 0..4096usize {
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, string.saturating_add(index as u64)).is_err() { return 0; }
        if byte[0] == 0 { break; }
        bytes.push(byte[0]);
        if index == 4095 { return 0; }
    }
    if bytes.is_empty() { return 0; }
    let result = crate::s001_write::sys_write(&SyscallArgs { a0: 2, a1: string, a2: bytes.len() as u64, a3: 0, a4: 0, a5: 0 });
    if result < 0 { 0 } else { bytes.len() as u64 }
}

/// Resolve through the same cache `get_channel_flags` uses (reference:
/// `__wine_dbg_header` calls `__wine_dbg_get_channel_flags` first thing), so
/// the channel's init bit is cleared here too and later static checks at
/// this call site's channel stop re-entering the kernel.
#[cfg(target_os = "oxide-kernel")]
fn header(class: u64, channel: u64) -> u64 {
    if channel == 0 { return (-1i64) as u64; }
    let resolved = get_channel_flags(channel) as u8;
    if class_enabled(resolved, class) { 0 } else { (-1i64) as u64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninitialized_channel_resolves_to_err_and_fixme_only() {
        assert_eq!(resolve_channel_flags(0xff), DEFAULT_DEBUG_FLAGS);
        assert_eq!(DEFAULT_DEBUG_FLAGS, 0b0000_0011);
    }

    #[test]
    fn already_resolved_channel_is_returned_unchanged() {
        // Init bit clear: the reference's fast path returns the stored byte
        // verbatim, with no re-derivation (dynamic per-channel overrides via
        // a debugger must survive this path).
        assert_eq!(resolve_channel_flags(0b0000_1000), 0b0000_1000);
        assert_eq!(resolve_channel_flags(0x00), 0x00);
    }

    #[test]
    fn default_flags_enable_only_fixme_and_err() {
        let resolved = resolve_channel_flags(0xff);
        assert!(class_enabled(resolved, 0)); // FIXME
        assert!(class_enabled(resolved, 1)); // ERR
        assert!(!class_enabled(resolved, 2)); // WARN
        assert!(!class_enabled(resolved, 3)); // TRACE
    }

    #[test]
    fn out_of_range_class_is_never_enabled() {
        let resolved = resolve_channel_flags(0xff);
        assert!(!class_enabled(resolved, 4));
        assert!(!class_enabled(0xff, 7)); // INIT bit itself is not a class
    }

    #[test]
    fn a_fully_disabled_channel_stays_disabled_after_resolve() {
        // Explicit "-all" style override (all class bits clear, init clear):
        // resolve is a no-op, no class is ever reported enabled.
        let resolved = resolve_channel_flags(0x00);
        for class in 0..4u64 { assert!(!class_enabled(resolved, class)); }
    }
}
