#![no_std]
extern crate alloc;

pub mod context;
pub mod debug_file;
pub mod eventfs;
pub mod fs_impl;
pub mod mount_opts;
pub mod percpu_ring;
pub mod predicate;
pub mod raw_bpf;
pub mod ring;
pub mod root;
mod rseq;
#[cfg(target_arch = "x86_64")]
mod pkru;
#[cfg(feature = "zram-memory-tracking")]
pub mod zram;

pub use eventfs::{register_dynamic_event, EventDesc};
pub use raw_bpf::{RawRunner, attach as attach_raw_bpf, detach as detach_raw_bpf};

pub use debug_file::{register_debug_show, show_inode};
pub use root::{config_root, debug_root, register, register_config, register_debug, trace_root};

// Boot-time tracefs registration per `37§6` and v2-arch-plan §1.8.
//
// V1: static directory at /sys/kernel/tracing whose readdir +
// open(leaf) expose the canonical control files with empty-trace
// defaults. Userspace probes (bpftrace feature detect, perf record
// -e probe, trace-cmd start) get sensible read-only data instead
// of ENOENT.
//
// The same canonical event descriptors own the tracefs enable state and
// any raw-BPF probes. Syscall entry/exit have production anchors; an event
// advertises a raw site only when its call path can supply the real raw
// arguments.


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
    rseq::register();
    #[cfg(target_arch = "x86_64")]
    pkru::register();
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

#[cfg(test)]
mod tests {
    #[test]
    fn init_publishes_the_rseq_slice_extension_control() {
        super::init();
        let inode = super::debug_root().lookup_path("rseq/slice_ext_nsec")
            .expect("rseq slice extension debugfs control");
        let mut body = [0u8; 16];
        let n = inode.read(0, &mut body).expect("read slice extension");
        assert_eq!(&body[..n], b"5000\n");
        assert_eq!(inode.write(0, b"50000\n"), Ok(6));
        let n = inode.read(0, &mut body).expect("read changed extension");
        assert_eq!(&body[..n], b"50000\n");
        assert_eq!(sched::rseq_slice::grant_deadline(7), 50_007,
            "the production grant deadline must consume the control");
        assert_eq!(inode.write(0, b"4999\n"), Err(vfs::VfsError::Erange));
        assert_eq!(inode.write(0, b"50001\n"), Err(vfs::VfsError::Erange));
        assert_eq!(inode.write(0, b"broken\n"), Err(vfs::VfsError::Einval));
        assert_eq!(sched::rseq_slice::extension_ns(), 50_000,
            "a rejected write must leave the current extension intact");
        assert_eq!(inode.write(0, b"5000\n"), Ok(5));
    }
}
