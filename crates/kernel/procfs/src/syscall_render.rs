//! Hosted-testable `/proc/<pid>/syscall` rendering.

use alloc::vec::Vec;
use sched::SyscallSnapshot;

/// Render Linux's saved syscall record. # C: O(1)
pub fn body(snapshot: SyscallSnapshot, running: bool) -> Vec<u8> {
    if running { return b"running\n".to_vec(); }
    let mut out = Vec::with_capacity(160);
    push_u64(&mut out, u64::from(snapshot.nr));
    for arg in snapshot.args {
        out.push(b' '); out.extend_from_slice(b"0x"); push_hex(&mut out, arg);
    }
    out.push(b' '); out.extend_from_slice(b"0x"); push_hex(&mut out, snapshot.sp);
    out.push(b' '); out.extend_from_slice(b"0x"); push_hex(&mut out, snapshot.ip);
    out.push(b'\n');
    out
}

fn push_u64(out: &mut Vec<u8>, mut n: u64) {
    if n == 0 { out.push(b'0'); return; }
    let mut buf = [0u8; 20]; let mut i = 0;
    while n != 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i != 0 { i -= 1; out.push(buf[i]); }
}

fn push_hex(out: &mut Vec<u8>, mut n: u64) {
    if n == 0 { out.push(b'0'); return; }
    let mut buf = [0u8; 16]; let mut i = 0;
    while n != 0 {
        let nib = (n & 0xf) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
        n >>= 4; i += 1;
    }
    while i != 0 { i -= 1; out.push(buf[i]); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_is_the_only_live_short_form() {
        assert_eq!(body(SyscallSnapshot::default(), true), b"running\n");
    }

    #[test]
    fn stopped_task_carries_nr_args_stack_and_instruction_pointer() {
        let snapshot = SyscallSnapshot { nr: 42, args: [1, 2, 3, 4, 5, 6], sp: 0xabc, ip: 0xdef };
        assert_eq!(body(snapshot, false), b"42 0x1 0x2 0x3 0x4 0x5 0x6 0xabc 0xdef\n");
    }
}
