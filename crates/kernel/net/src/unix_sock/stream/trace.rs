/// Debug-only D-Bus frame trace for AF_UNIX streams. # C: O(data)
pub(super) fn trace_dbus_stream(data: &[u8]) {
    fn has(h: &[u8], n: &[u8]) -> bool { h.windows(n.len()).any(|w| w == n) }
    if has(data, b"GetSessionByPID") && data.len() >= 4 {
        let n = data.len();
        let pid = u32::from_le_bytes([data[n-4], data[n-3], data[n-2], data[n-1]]);
        klog::write_raw(b"[GETSESSBYPID arg_pid=");
        klog::write_dec_u64(pid as u64);
        klog::write_raw(b" caller=");
        if let Some(c) = sched::live::current() {
            klog::write_dec_u64(c.tid as u64);
            klog::write_raw(b"/");
            let comm = c.comm_bytes();
            klog::write_raw(sched::Task::comm_trim(&comm).as_bytes());
        }
        klog::write_raw(b"]\n");
    }
    let is_tgt = sched::live::current()
        .map(|c| c.with_exe_path(|p| p.map(|s|
            s.contains("gdm") || s.contains("polkit")
            || s.contains("upower") || s.contains("switcheroo") || s.contains("accounts")).unwrap_or(false)))
        .unwrap_or(false);
    let hit = is_tgt
        || has(data, b"login1")
        || has(data, b"PolicyKit1")
        || has(data, b"org.freedesktop.DBus.Error");
    // The full broker stream remains available for protocol diagnosis, but is
    // deliberately a separate flag: normal debug-dbus must reach the login1
    // exchange within a bounded GNOME boot rather than serializing unrelated
    // RequestName/PropertiesChanged traffic for every service.
    #[cfg(feature = "debug-dbus-verbose")]
    let hit = hit
        || sched::live::current()
            .map(|c| c.with_exe_path(|p| p.map(|s| s.contains("dbus-broker")).unwrap_or(false)))
            .unwrap_or(false)
        || has(data, b"RequestName")
        || has(data, b"StartServiceByName")
        || has(data, b"NameAcquired")
        || has(data, b"io.systemd")
        || has(data, b"UserRecord")
        || has(data, b"GroupRecord")
        || has(data, b"groupMembers");
    if !hit { return; }
    let n = core::cmp::min(data.len(), 384);
    klog::write_raw(b"[DBUS t=");
    if let Some(c) = sched::live::current() {
        klog::write_dec_u64(c.tid as u64);
        klog::write_raw(b" ");
        let comm = c.comm_bytes();
        klog::write_raw(sched::Task::comm_trim(&comm).as_bytes());
    }
    klog::write_raw(b"] ");
    for &b in &data[..n] {
        let c = if (0x20..0x7f).contains(&b) { b } else { b'.' };
        klog::write_raw(&[c]);
    }
    klog::write_raw(b"\n");
}
