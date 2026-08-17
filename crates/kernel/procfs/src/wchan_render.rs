//! `/proc/<pid>/wchan` body — the rendering half of `proc_pid_wchan`, kept out
//! of the kernel-gated inode constructor so the contract is testable.
//!
//! The reference prints the symbol naming the address `get_wchan` unwound to,
//! with `seq_puts` — no trailing newline — and a bare `0` whenever the task is
//! not blocked, the reader fails `ptrace_may_access`, or the address resolves
//! to no symbol. This kernel names the site by source position instead of by
//! symbol (`sched::park_site`), so a task with no recorded site takes the
//! reference's own no-symbol path and prints `0`.

use alloc::vec::Vec;

/// The `0` every refusing path prints. `seq_putc(m, '0')` — no newline.
const NOT_BLOCKED: &[u8] = b"0";

/// Render the body for a task whose site is `site` (`None` = nothing recorded)
/// and which `reportable` says is blocked off-CPU. Either input refusing gives
/// the reference's `0`. # C: O(len(file))
pub fn body(site: Option<(&str, u32)>, reportable: bool) -> Vec<u8> {
    if !reportable { return NOT_BLOCKED.to_vec(); }
    let Some((file, line)) = site else { return NOT_BLOCKED.to_vec() };
    let mut out = Vec::with_capacity(file.len() + 8);
    out.extend_from_slice(file.as_bytes());
    out.push(b':');
    push_dec(&mut out, line);
    out
}

/// # C: O(digits)
fn push_dec(out: &mut Vec<u8>, mut n: u32) {
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 { break; }
    }
    out.extend_from_slice(&digits[i..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blocked_task_reports_its_site_with_no_trailing_newline() {
        let out = body(Some(("crates/kernel/sched/src/live/wait_event.rs", 137)), true);
        assert_eq!(out, b"crates/kernel/sched/src/live/wait_event.rs:137");
        assert_ne!(out.last(), Some(&b'\n'), "seq_puts writes no newline");
    }

    #[test]
    fn every_refusing_path_prints_the_references_bare_zero() {
        // Not blocked: the reference's `get_wchan` returned 0.
        assert_eq!(body(Some(("x.rs", 1)), false), b"0");
        // Blocked but nothing recorded: the reference's no-symbol path.
        assert_eq!(body(None, true), b"0");
        assert_eq!(body(None, false), b"0");
    }

    #[test]
    fn a_line_number_is_rendered_in_full_decimal() {
        assert_eq!(body(Some(("a.rs", 0)), true), b"a.rs:0");
        assert_eq!(body(Some(("a.rs", 9)), true), b"a.rs:9");
        assert_eq!(body(Some(("a.rs", 10)), true), b"a.rs:10");
        assert_eq!(body(Some(("a.rs", 4_294_967_295)), true), b"a.rs:4294967295");
    }
}
