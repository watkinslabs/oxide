// The perf ring buffer — Linux `struct perf_buffer` plus the `mmap(2)`
// control-page protocol.
//
// Module manifest:
//   sizing    page-count validation, watermark default, mlock accounting (pure)
//   state     head/tail algebra, reservation, wrap split, lost counting (pure)
//   userpage  `struct perf_event_mmap_page` byte layout (pure)
//   buffer    the live frame-backed buffer and its record output path
//
// The first three are pure over explicit inputs so every arithmetic decision
// the ABI depends on — sizing, `CIRC_SPACE`, the wrap boundary, the control
// page's field offsets — is hosted-testable without a running kernel.

pub mod sizing;
pub mod state;
pub mod userpage;
mod buffer;

pub use buffer::PerfBuffer;
