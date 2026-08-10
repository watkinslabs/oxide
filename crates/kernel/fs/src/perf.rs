// perf_event_open(2).
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
//   context  the per-task event context: lineage, generation, mid-life sync
//   registry the one table of live events, keyed by task/CPU context
//   inherit  fork propagation + exit fold-back of `attr.inherit` events
//   ring     the mmapped ring buffer and its control page
//   sample   `PERF_RECORD_*` byte layout (pure)
//   overflow sampling-period accounting (pure)
//   throttle per-tick sampling budget + THROTTLE/UNTHROTTLE records
//   mmap     ring mapping admission + ring attach
//   output   `PERF_EVENT_IOC_SET_OUTPUT` redirect ladder (pure)
//   emit     software-counter sites -> `PERF_RECORD_SAMPLE`
//   hrtimer  the clock PMUs' sampling timer (`perf_swevent_hrtimer`)
//   sideband MMAP/COMM/FORK/EXIT/SWITCH records — what resolves a sample's IP
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
pub mod context;
pub mod inherit;
pub mod registry;
pub mod ring;
pub mod sample;
pub mod overflow;
pub mod throttle;
pub mod mmap;
pub mod output;
pub mod emit;
pub mod hrtimer;
pub mod sideband;
mod glue;
#[cfg(test)]
mod tests;

pub use event::PerfEvent;
pub use ring::PerfBuffer;
pub use file::{event_of, is_perf_inode, make_perf_event_inode};
pub use glue::{handle_perf_ioctl, sys_perf_event_open, task_ctxt_switches};
