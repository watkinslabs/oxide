#![no_std]
extern crate alloc;

pub mod fs_impl;
pub mod percpu_ring;
pub mod ring;

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

use vfs::StaticFileInode;

/// Boot-time tracefs population. Called from kernel_main after
/// devfs::init.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
pub fn init() {
    // Mountpoint directories must exist as walkable dentries BEFORE systemd
    // mounts debugfs/tracefs on them: `vfs::mount::register` resolves the
    // target dentry to wire crossing + compute the parent mount id. An
    // unresolvable mountpoint yields a self-parent mountinfo line that systemd
    // rejects ("no mount") and journald's libmount parse crashes on. `/sys/
    // kernel/tracing` already materialises via its control files below, but
    // `/sys/kernel/debug` has no static files, so register the bare dir.
    devfs::register_dir("/sys/kernel/tracing");
    devfs::register_dir("/sys/kernel/debug");
    // Real trace buffer: trace / trace_marker / trace_pipe / tracing_on are
    // live inodes (record + render + drain + gate); the rest stay nop-tracer
    // static defaults.
    ring::register();
    devfs::register("/sys/kernel/tracing/current_tracer",
        StaticFileInode::new(b"nop\n") as InodeRef);
    devfs::register("/sys/kernel/tracing/available_tracers",
        StaticFileInode::new(b"nop\n") as InodeRef);
    devfs::register("/sys/kernel/tracing/available_events",
        StaticFileInode::new(b"sched:sched_switch\nsyscalls:sys_enter\nsyscalls:sys_exit\n") as InodeRef);
    devfs::register("/sys/kernel/tracing/trace_options",
        StaticFileInode::new(b"") as InodeRef);
    devfs::register("/sys/kernel/tracing/buffer_size_kb",
        StaticFileInode::new(b"1408\n") as InodeRef);
    // Per-event control directory placeholder. Real per-event
    // enable is a follow-up.
    devfs::register("/sys/kernel/tracing/events/header_event",
        StaticFileInode::new(b"") as InodeRef);
}
