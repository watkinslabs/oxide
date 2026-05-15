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


use alloc::sync::Arc;
use vfs::InodeRef;

use crate::procfs::StaticFileInode;

/// Boot-time tracefs population. Called from kernel_main after
/// devfs::init.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
pub fn init() {
    // Empty-trace defaults — match Linux's "no tracer attached" state.
    crate::devfs::register("/sys/kernel/tracing/tracing_on",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/sys/kernel/tracing/current_tracer",
        StaticFileInode::new(b"nop\n") as InodeRef);
    crate::devfs::register("/sys/kernel/tracing/available_tracers",
        StaticFileInode::new(b"nop\n") as InodeRef);
    crate::devfs::register("/sys/kernel/tracing/available_events",
        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/sys/kernel/tracing/trace",
        StaticFileInode::new(b"# tracer: nop\n#\n") as InodeRef);
    crate::devfs::register("/sys/kernel/tracing/trace_pipe",
        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/sys/kernel/tracing/trace_options",
        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/sys/kernel/tracing/buffer_size_kb",
        StaticFileInode::new(b"1408\n") as InodeRef);
    // Per-event control directory placeholder. Real per-event
    // enable is a follow-up.
    crate::devfs::register("/sys/kernel/tracing/events/header_event",
        StaticFileInode::new(b"") as InodeRef);
}
