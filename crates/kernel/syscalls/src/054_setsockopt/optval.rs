#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

/// Read a leading `int` operand, or `None` when the option is shorter than an
/// `int` or the pointer faults. # C: O(1)
pub(super) fn read_i32(optval: u64, optlen: u32) -> Option<i32> {
    if optlen < 4 { return None; }
    let mut bytes = [0u8; 4];
    uaccess::copy_from_user(&mut bytes, optval).ok()?;
    Some(i32::from_ne_bytes(bytes))
}

/// `int`-width operand with Linux's precedence: a short option is EINVAL, a
/// long-enough option with a bad pointer is EFAULT. # C: O(1)
pub(super) fn read_i32_required(optval: u64, optlen: u32) -> Result<i32, i64> {
    read_i32(optval, optlen).ok_or(if optlen < 4 {
        -(Errno::Einval.as_i32() as i64)
    } else {
        -(Errno::Efault.as_i32() as i64)
    })
}

/// Linux precedence for the byte-or-int IP options: a zero optlen is EINVAL, a
/// non-zero optlen with a bad pointer is EFAULT. # C: O(1)
pub(super) fn read_u8_or_i32_required(optval: u64, optlen: u32) -> Result<i32, i64> {
    read_u8_or_i32(optval, optlen).ok_or(if optlen == 0 {
        -(Errno::Einval.as_i32() as i64)
    } else {
        -(Errno::Efault.as_i32() as i64)
    })
}

/// The byte-or-int import shared by the IP-level scalar options. # C: O(1)
pub(super) fn read_u8_or_i32(optval: u64, optlen: u32) -> Option<i32> {
    if (1..4).contains(&optlen) {
        let mut byte = [0u8; 1];
        uaccess::copy_from_user(&mut byte, optval).ok()?;
        return Some(byte[0] as i32);
    }
    if optlen >= 4 {
        let mut bytes = [0u8; 4];
        uaccess::copy_from_user(&mut bytes, optval).ok()?;
        return Some(i32::from_ne_bytes(bytes));
    }
    None
}

/// Encode an `Errno` as the negative syscall return. # C: O(1)
pub(super) fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }
