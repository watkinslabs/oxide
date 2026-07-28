// debug-mntcost: cost census for the `/proc/*/mountinfo` + `/proc/*/mounts`
// renderers.
//
// systemd re-parses `/proc/self/mountinfo` after every mount operation, and a
// sandboxed unit (`ProtectSystem=`, `ReadWritePaths=`, `PrivateDevices=`, …)
// performs dozens of them per service start. Every one of those parses is a
// fresh open + read-at-0, and both force a full re-render here. That makes this
// renderer's per-call cost a direct multiplier on service start-up latency, so
// it needs to be measured per field, not assumed.
//
// Diagnostic only — off unless `--features debug-mntcost` is passed.
#![cfg(all(target_os = "oxide-kernel", feature = "debug-mntcost"))]

const NS_PER_US: u64 = 1_000;

/// Monotonic ns timestamp. # C: O(1)
pub fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Per-field ns accumulators for one render pass.
#[derive(Default)]
pub struct Census {
    pub mp: u64,
    pub root: u64,
    pub opts: u64,
    pub src: u64,
    pub fmt: u64,
}

/// Emit one render's cost split. # C: O(1)
pub fn report(kind: &'static [u8], rows: u64, global: u64, snap_ns: u64, total_ns: u64, c: &Census) {
    klog::write_raw(b"[MNTBUILD ");
    klog::write_raw(kind);
    klog::write_raw(b" rows=");
    klog::write_dec_u64(rows);
    klog::write_raw(b" global_mounts=");
    klog::write_dec_u64(global);
    klog::write_raw(b" total_us=");
    klog::write_dec_u64(total_ns / NS_PER_US);
    klog::write_raw(b" snapshot_us=");
    klog::write_dec_u64(snap_ns / NS_PER_US);
    klog::write_raw(b" mp_us=");
    klog::write_dec_u64(c.mp / NS_PER_US);
    klog::write_raw(b" root_us=");
    klog::write_dec_u64(c.root / NS_PER_US);
    klog::write_raw(b" opts_us=");
    klog::write_dec_u64(c.opts / NS_PER_US);
    klog::write_raw(b" src_us=");
    klog::write_dec_u64(c.src / NS_PER_US);
    klog::write_raw(b" fmt_us=");
    klog::write_dec_u64(c.fmt / NS_PER_US);
    klog::write_raw(b"]\n");
}
