// `/proc/net/softnet_stat` — one fixed-width hex row per CPU, no header.
//
// Column order is ABI: `sar -n SOFT`, `netstat -s`-adjacent tooling and every
// hand-written parser index into it positionally. Columns retired upstream are
// still emitted as zeros for exactly that reason.
//
//   0 processed        4..7 (retired, zero)   8  (retired, zero)
//   1 dropped          9 received_rps        10 flow_limit_count
//   2 time_squeeze    11 total backlog qlen  12 cpu index
//   3 (retired, zero) 13 input_pkt_queue len 14 process_queue len

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use super::queue::SoftnetRow;

/// Render the whole file from one row per CPU, in CPU order. # C: O(N cpus)
pub fn render_softnet_stat(rows: &[SoftnetRow]) -> Vec<u8> {
    let mut s = String::new();
    for (cpu, row) in rows.iter().enumerate() { render_row(&mut s, cpu, row); }
    s.into_bytes()
}

/// One CPU's row, newline-terminated. # C: O(1)
fn render_row(out: &mut String, cpu: usize, row: &SoftnetRow) {
    use core::fmt::Write as _;
    let total = row.input_qlen + row.process_qlen;
    let _ = writeln!(out,
        "{:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} \
         {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}",
        row.processed as u32, row.dropped as u32, row.time_squeeze as u32, 0,
        0, 0, 0, 0,
        0,
        // received_rps: no cross-CPU receive steering, so never non-zero.
        0,
        // flow_limit_count: the per-flow backlog limiter is not configured.
        0,
        total as u32, cpu as u32,
        row.input_qlen as u32, row.process_qlen as u32);
}
