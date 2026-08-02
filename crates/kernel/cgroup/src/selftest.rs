//! Boot-time cgroup v2 self-test, behind `debug-cgroup` (`26§8`). Drives
//! the SAME VFS path userspace uses (`vfs::resolve_abs` then Inode
//! read/write/mkdir/rmdir) so a routing or inode-impl regression surfaces
//! as a klog FAIL at boot. Lives in the cgroup crate (it tests cgroup).

fn rd(path: &str) -> alloc::vec::Vec<u8> {
    match vfs::resolve_abs(path) {
        Ok(ino) => {
            let mut buf = [0u8; 256];
            match ino.read(0, &mut buf) { Ok(n) => buf[..n].to_vec(), Err(_) => alloc::vec::Vec::new() }
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

/// Run the cgroup v2 boot self-test (klogs one line per check).
/// # C: O(small) one-shot boot diagnostic
pub fn run() {
    let ctrls = rd("/sys/fs/cgroup/cgroup.controllers");
    line("controllers", trim(&ctrls));
    let mk = match vfs::resolve_abs("/sys/fs/cgroup") {
        Ok(root) => root.mkdir("selftest", 0o755, &vfs::CreateCtx::root()).is_ok(), Err(_) => false,
    };
    line("mkdir", if mk { b"ok" } else { b"fail" });
    if let Ok(sc) = vfs::resolve_abs("/sys/fs/cgroup/cgroup.subtree_control") { let _ = sc.write(0, b"+pids"); }
    if let Ok(pm) = vfs::resolve_abs("/sys/fs/cgroup/selftest/pids.max") { let _ = pm.write(0, b"11"); }
    let pmax = rd("/sys/fs/cgroup/selftest/pids.max");
    line("pids.max", trim(&pmax));
    let selfcg = rd("/proc/self/cgroup");
    line("proc-self", trim(&selfcg));
    let rm = match vfs::resolve_abs("/sys/fs/cgroup") {
        Ok(root) => root.rmdir("selftest").is_ok(), Err(_) => false,
    };
    line("rmdir", if rm { b"ok" } else { b"fail" });
}
