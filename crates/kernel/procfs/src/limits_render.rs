// `/proc/<pid>/limits` + `/proc/self/limits` table rendering (Linux
// `proc_pid_limits`, fs/proc/base.c).
//
// Pure formatting over the `(cur, max)` pairs themselves — no `Task`, no
// scheduler, no `live` module — so it compiles in the hosted test build and
// the row set, column widths and unit strings are unit-testable without a
// boot. The `live` callers are `#[cfg(target_os = "oxide-kernel")]`; anything
// written there compiles out SILENTLY, which is how a wrong answer here would
// otherwise ship untested (B1442).

use alloc::vec::Vec;
use sched::rlimit::{format_rlim, rlim};

/// Column width Linux pads the soft/hard value fields to.
const VALUE_COL: usize = 21;
/// Widest `format_rlim` output (`"unlimited"` or a 20-digit u64).
const VALUE_BUF: usize = 32;

/// Header line, then one row per `RLIMIT_*` in Linux's declaration order.
const HEADER: &[u8] = b"Limit                     Soft Limit           Hard Limit           Units\n";

/// `(index, label, units)` per row — Linux `proc_pid_limits`'s `lnames[]`.
const ROWS: &[(usize, &[u8], &[u8])] = &[
    (rlim::CPU,        b"Max cpu time             ", b"seconds"),
    (rlim::FSIZE,      b"Max file size            ", b"bytes"),
    (rlim::DATA,       b"Max data size            ", b"bytes"),
    (rlim::STACK,      b"Max stack size           ", b"bytes"),
    (rlim::CORE,       b"Max core file size       ", b"bytes"),
    (rlim::RSS,        b"Max resident set         ", b"bytes"),
    (rlim::NPROC,      b"Max processes            ", b"processes"),
    (rlim::NOFILE,     b"Max open files           ", b"files"),
    (rlim::MEMLOCK,    b"Max locked memory        ", b"bytes"),
    (rlim::AS,         b"Max address space        ", b"bytes"),
    (rlim::LOCKS,      b"Max file locks           ", b"locks"),
    (rlim::SIGPENDING, b"Max pending signals      ", b"signals"),
    (rlim::MSGQUEUE,   b"Max msgqueue size        ", b"bytes"),
    (rlim::NICE,       b"Max nice priority        ", b""),
    (rlim::RTPRIO,     b"Max realtime priority    ", b""),
    (rlim::RTTIME,     b"Max realtime timeout     ", b"us"),
];

/// Render the whole `/proc/<pid>/limits` body from a resource table. Both the
/// live-task path and the init-default fallback go through here, so the two
/// cannot drift apart. # C: O(1)
pub fn limits_body_for_table(limits: &[(u64, u64); rlim::COUNT]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2048);
    out.extend_from_slice(HEADER);
    let mut buf = [0u8; VALUE_BUF];
    for (i, label, units) in ROWS {
        out.extend_from_slice(label);
        for value in [limits[*i].0, limits[*i].1] {
            let n = format_rlim(&mut buf, value).unwrap_or(0);
            out.extend_from_slice(&buf[..n]);
            for _ in n..VALUE_COL { out.push(b' '); }
        }
        out.extend_from_slice(units);
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
#[path = "limits_render/tests.rs"]
mod tests;
