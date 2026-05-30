// cgroup v2 boot glue (`26§4`,`26§8`): the SIGKILL delivery hook for
// `cgroup.kill` and the `debug-cgroup`-gated boot self-test. Split out
// of lib.rs to honor the 1000-line cap (`08§7`). The leaf `cgroup`
// crate can't depend on `sched`/`vfs`-mount/`klog`, so this kernel-side
// module wires those in.

/// cgroup.kill delivery hook: post `sig` to the task whose global
/// (init-NS) tid is `pid` and wake it. Registered with the cgroup
/// subsystem at boot via `cgroup::set_signal_hook`.
/// # C: O(N tasks) registry lookup
#[cfg(target_os = "oxide-kernel")]
pub fn cgroup_kill_hook(pid: u64, sig: i32) {
    use core::sync::atomic::Ordering;
    if !(1..=64).contains(&sig) { return; }
    if let Some(t) = sched::live::registry::lookup_in_ns(0, pid as u32) {
        t.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
        sched::live::wake_if_sleeping(&t);
    }
}

/// Host-build no-op for `cgroup_kill_hook`.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn cgroup_kill_hook(_pid: u64, _sig: i32) {}

/// vpid → canonical (global) tid resolver for `cgroup.procs`/`threads`
/// writes. A userspace write supplies a pid in the writer's pid
/// namespace; the cgroup tree keys on the global tid (matching
/// `current().tid` used by `/proc/<pid>/cgroup` + fork-inheritance).
/// Identity fallback when the vpid resolves to no live task.
/// Registered via `cgroup::set_pid_resolve_hook`.
/// # C: O(N tasks) registry lookup
#[cfg(target_os = "oxide-kernel")]
pub fn cgroup_pid_resolve_hook(vpid: u64) -> u64 {
    match sched::live::registry::lookup_by_vpid(vpid as u32) {
        Some(t) => t.tid as u64,
        None => vpid,
    }
}

/// Host-build identity for `cgroup_pid_resolve_hook`.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn cgroup_pid_resolve_hook(vpid: u64) -> u64 { vpid }

/// Host-build stub for the self-test — the `debug_cgroup!` call site
/// expands on host too when the feature is on (`cargo test --features
/// debug-cgroup`), so a symbol must exist. No-op off-target.
/// # C: O(1)
#[cfg(all(not(target_os = "oxide-kernel"), feature = "debug-cgroup"))]
pub fn cgroup_selftest() {}

/// Boot-time cgroup v2 self-test, behind `debug-cgroup` (`26§8`).
/// Drives the SAME VFS path userspace uses — `vfs::mount::lookup` then
/// `Inode::read`/`write`/`mkdir` — so a routing or inode-impl
/// regression surfaces as a klog FAIL at boot, not only in an in-guest
/// shell probe. klogs one line per check.
/// # C: O(small) one-shot boot diagnostic
#[cfg(all(target_os = "oxide-kernel", feature = "debug-cgroup"))]
pub fn cgroup_selftest() {
    fn rd(path: &str) -> alloc::vec::Vec<u8> {
        match vfs::mount::lookup(path) {
            Ok(ino) => {
                let mut buf = [0u8; 256];
                match ino.read(0, &mut buf) {
                    Ok(n) => buf[..n].to_vec(),
                    Err(_) => alloc::vec::Vec::new(),
                }
            }
            Err(_) => alloc::vec::Vec::new(),
        }
    }
    fn line(tag: &'static str, body: &[u8]) {
        klog::write_raw(b"[INFO]  cgroup-selftest: ");
        klog::write_raw(tag.as_bytes());
        klog::write_raw(b"='");
        klog::write_raw(body);
        klog::write_raw(b"'\n");
    }
    fn trim(b: &[u8]) -> &[u8] {
        match b.iter().position(|&c| c == b'\n') { Some(i) => &b[..i], None => b }
    }
    // 1. root cgroup.controllers via the mount table.
    let ctrls = rd("/sys/fs/cgroup/cgroup.controllers");
    line("controllers", trim(&ctrls));
    // 2. create a child cgroup via Inode::mkdir on the root dir.
    let mk = match vfs::mount::lookup("/sys/fs/cgroup") {
        Ok(root) => root.mkdir("selftest", 0o755).is_ok(),
        Err(_) => false,
    };
    line("mkdir", if mk { b"ok" } else { b"fail" });
    // 3. enable + write a controller limit, read it back.
    if let Ok(sc) = vfs::mount::lookup("/sys/fs/cgroup/cgroup.subtree_control") {
        let _ = sc.write(0, b"+pids");
    }
    if let Ok(pm) = vfs::mount::lookup("/sys/fs/cgroup/selftest/pids.max") {
        let _ = pm.write(0, b"11");
    }
    let pmax = rd("/sys/fs/cgroup/selftest/pids.max");
    line("pids.max", trim(&pmax));
    // 4. /proc/self/cgroup path.
    let selfcg = rd("/proc/self/cgroup");
    line("proc-self", trim(&selfcg));
    // 5. teardown.
    let rm = match vfs::mount::lookup("/sys/fs/cgroup") {
        Ok(root) => root.rmdir("selftest").is_ok(),
        Err(_) => false,
    };
    line("rmdir", if rm { b"ok" } else { b"fail" });
}
