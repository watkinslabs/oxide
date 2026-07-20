#![no_std]
extern crate alloc;

pub mod eventfs;
pub mod fs_impl;
pub mod percpu_ring;
pub mod predicate;
pub mod ring;
pub mod root;
#[cfg(feature = "zram-memory-tracking")]
pub mod zram;

pub use eventfs::{register_dynamic_event, EventDesc};

pub use root::{config_root, debug_root, register, register_config, register_debug, trace_root};

// Boot-time tracefs registration per `37§R01` and v2-arch-plan §1.8.
//
// V1: static directory at /sys/kernel/tracing whose readdir +
// open(leaf) expose the canonical control files with empty-trace
// defaults. Userspace probes (bpftrace feature detect, perf record
// -e probe, trace-cmd start) get sensible read-only data instead
// of ENOENT.
//
// Real per-CPU ring buffers + dynamic tracepoint registration are
// a follow-up once the kernel grows static tracepoint anchors at
// sched_switch / sys_enter / sys_exit per `37§6`.


use vfs::InodeRef;

use vfs::StaticFileInode;

/// Boot-time tracefs population. Called from kernel_main after
/// devfs::init.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
pub fn init() {
    // Mount-point dirs (`/sys/kernel/tracing`, `/sys/kernel/debug`) are
    // created in sysfs's own tree by `sysfs::init` (D1c) so systemd can mount
    // tracefs/debugfs on them; the content below lives in tracefs's OWN
    // `trace_root()` (mount root returned by `TracefsFs::root()`).
    //
    // Real trace buffer: trace / trace_marker / trace_pipe / tracing_on are
    // live inodes (record + render + drain + gate); the rest stay nop-tracer
    // static defaults.
    ring::register();
    #[cfg(feature = "zram-memory-tracking")]
    zram::register();
    register("/sys/kernel/tracing/current_tracer",
        StaticFileInode::new(b"nop\n") as InodeRef);
    register("/sys/kernel/tracing/available_tracers",
        StaticFileInode::new(b"nop\n") as InodeRef);
    register("/sys/kernel/tracing/trace_options",
        StaticFileInode::new(b"") as InodeRef);
    register("/sys/kernel/tracing/buffer_size_kb",
        StaticFileInode::new(b"1408\n") as InodeRef);
    // eventfs: per-event dir hierarchy (enable/id/format/filter + subsystem and
    // root aggregate enables + available_events), table-driven from `eventfs`.
    eventfs::register();
}
