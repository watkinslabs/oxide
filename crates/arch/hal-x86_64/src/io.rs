//! Bounded x86 port-I/O service for firmware-owned accesses.

/// Perform one SystemIO transaction within the architectural port range. # C: O(1)
pub fn operation_region_access(port: u64, width: u64, write: Option<u64>) -> Option<u64> {
    let port = u16::try_from(port).ok()?;
    let bytes = match width { 8 => 1, 16 => 2, 32 => 4, _ => return None };
    if u32::from(port).checked_add(bytes)? > u32::from(u16::MAX) + 1 { return None; }
    // Every arm below shares one argument: port I/O touches no memory the
    // compiler models, so the only hazard is a device side effect, and the
    // descriptor selecting `port`/`width` is firmware-authored (the accessors'
    // precondition). The arm's width literal is the same one `bytes` above
    // range-checked, so no access straddles the top of the 64 KiB port space.
    Some(match (width, write) {
        // SAFETY: 8-bit read of a firmware-named port whose byte was bounds-checked above.
        (8, None) => u64::from(unsafe { in8(port) }),
        // SAFETY: 16-bit read; the checked `bytes` was 2, so port+1 is still in range.
        (16, None) => u64::from(unsafe { in16(port) }),
        // SAFETY: 32-bit read; the checked `bytes` was 4, so port+3 is still in range.
        (32, None) => u64::from(unsafe { in32(port) }),
        // SAFETY: 8-bit write of a firmware-supplied value to a firmware-named port.
        (8, Some(value)) => { unsafe { out8(port, value as u8) }; 0 }
        // SAFETY: 16-bit write; the checked `bytes` was 2, so port+1 is still in range.
        (16, Some(value)) => { unsafe { out16(port, value as u16) }; 0 }
        // SAFETY: 32-bit write; the checked `bytes` was 4, so port+3 is still in range.
        (32, Some(value)) => { unsafe { out32(port, value as u32) }; 0 }
        _ => return None,
    })
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn in8(port: u16) -> u8 {
    let value: u8;
    // SAFETY: operation_region_access admits an architected x86 I/O port.
    unsafe { core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags)); }
    value
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn in8(_: u16) -> u8 { u8::MAX }
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn in16(port: u16) -> u16 {
    let value: u16;
    // SAFETY: operation_region_access admits an architected x86 I/O port.
    unsafe { core::arch::asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags)); }
    value
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn in16(_: u16) -> u16 { u16::MAX }
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn in32(port: u16) -> u32 {
    let value: u32;
    // SAFETY: operation_region_access admits an architected x86 I/O port.
    unsafe { core::arch::asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags)); }
    value
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn in32(_: u16) -> u32 { u32::MAX }
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn out8(port: u16, value: u8) {
    // SAFETY: operation_region_access admits an architected x86 I/O port.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)); }
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn out8(_: u16, _: u8) {}
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn out16(port: u16, value: u16) {
    // SAFETY: operation_region_access admits an architected x86 I/O port.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags)); }
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn out16(_: u16, _: u16) {}
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn out32(port: u16, value: u32) {
    // SAFETY: operation_region_access admits an architected x86 I/O port.
    unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags)); }
}
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
unsafe fn out32(_: u16, _: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_region_access_rejects_overflow_and_bad_width() {
        assert_eq!(operation_region_access(u64::from(u16::MAX), 16, None), None);
        assert_eq!(operation_region_access(0, 64, None), None);
    }
}
