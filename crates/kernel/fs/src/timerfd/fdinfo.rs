//! `/proc/<pid>/fdinfo/<n>` body for a timerfd.

use alloc::vec::Vec;

use super::uapi::Itimerspec;

/// Append the five timerfd lines: clock id, unread expirations, the flags the
/// last arm used (octal, leading zero), and the remaining/interval pair as
/// `(sec, nsec)`.
/// # C: O(1)
pub(super) fn render(out: &mut Vec<u8>, clockid: u64, ticks: u64, settime_flags: u16,
    spec: Itimerspec)
{
    out.extend_from_slice(b"clockid: ");
    push_dec(out, clockid);
    out.extend_from_slice(b"\nticks: ");
    push_dec(out, ticks);
    out.extend_from_slice(b"\nsettime flags: 0");
    push_oct(out, settime_flags as u64);
    out.extend_from_slice(b"\nit_value: ");
    push_pair(out, spec.value_ns);
    out.extend_from_slice(b"\nit_interval: ");
    push_pair(out, spec.interval_ns);
    out.push(b'\n');
}

/// `(sec, nsec)` split of a nanosecond duration. # C: O(1)
fn push_pair(out: &mut Vec<u8>, ns: u64) {
    out.push(b'(');
    push_dec(out, ns / syscall::time::NSEC_PER_SEC);
    out.extend_from_slice(b", ");
    push_dec(out, ns % syscall::time::NSEC_PER_SEC);
    out.push(b')');
}

fn push_radix(out: &mut Vec<u8>, mut v: u64, radix: u64) {
    let mut digits = [0u8; 22];
    let mut n = 0;
    loop { digits[n] = b'0' + (v % radix) as u8; v /= radix; n += 1; if v == 0 { break } }
    for i in (0..n).rev() { out.push(digits[i]); }
}

fn push_dec(out: &mut Vec<u8>, v: u64) { push_radix(out, v, 10) }
fn push_oct(out: &mut Vec<u8>, v: u64) { push_radix(out, v, 8) }
