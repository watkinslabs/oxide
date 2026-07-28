// perf_event_open(2) — Linux `kernel/events/core.c`.
//
// `kernel.perf_event_paranoid` / `perf_event_max_sample_rate` live in
// `sched::perf_sw` — `procfs` binds `/proc/sys/kernel` to them and cannot
// depend on this crate.
//
// Module manifest:
//   uapi     ABI numbers, `struct perf_event_attr` offsets, ioctl encodings
//   attr     `perf_copy_attr` — extensible-struct decode + field validation
//   open     `SYSCALL_DEFINE5(perf_event_open)` admission ladder (pure)
//   counter  software-counter algebra + `read(2)` framing (pure)
//   event    live `struct perf_event` and its counter sources
//   file     the anon inode and its `f_op`
//   ioctl    `_perf_ioctl` classification and per-command rules (pure)
//   glue     user-memory copies, fd install, ioctl dispatch
//
// Scope: oxide registers the *software* PMUs only. `PERF_TYPE_HARDWARE`,
// `HW_CACHE`, `RAW`, `TRACEPOINT` and `BREAKPOINT` therefore resolve to
// `-ENOENT` out of `perf_init_event()`, which is exactly what a Linux whose
// CPU-PMU driver never registered returns — no fabricated counter values.

pub mod uapi;
pub mod attr;
pub mod open;
pub mod counter;
pub mod event;
pub mod file;
pub mod ioctl;
mod glue;
#[cfg(test)]
mod tests;

pub use event::PerfEvent;
pub use file::{event_of, is_perf_inode, make_perf_event_inode};
pub use glue::{handle_perf_ioctl, sys_perf_event_open, task_ctxt_switches};
