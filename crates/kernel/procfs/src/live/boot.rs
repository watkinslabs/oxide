use vfs::InodeRef;

fn lookup_child_path(mut node: InodeRef, leaf: &str) -> Option<InodeRef> {
    if leaf.is_empty() {
        return Some(node);
    }
    for seg in leaf.split('/') {
        if seg.is_empty() {
            return None;
        }
        node = node.lookup(seg).ok()?;
    }
    Some(node)
}

pub fn init() {
    crate::static_files::register_static_files();
}

pub fn smoke_test() {
    use hal::kassert;

    fn smoke_resolve(path: &str) -> Option<InodeRef> {
        if let Some(rest) = path.strip_prefix("/proc/") {
            return lookup_child_path(crate::static_files::proc_root() as InodeRef, rest);
        }
        if let Some(rest) = path.strip_prefix("/sys/") {
            return sysfs::sys_root().lookup_path(rest);
        }
        None
    }

    fn is_hex(b: u8) -> bool {
        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
    }

    fn is_uuid_line(buf: &[u8]) -> bool {
        if buf.len() < 37 || buf[36] != b'\n' {
            return false;
        }
        for i in 0..36 {
            match i {
                8 | 13 | 18 | 23 => {
                    if buf[i] != b'-' { return false; }
                }
                _ => {
                    if !is_hex(buf[i]) { return false; }
                }
            }
        }
        buf[..36].iter().any(|&b| b != b'0' && b != b'-')
    }

    let entries: &[(&str, &[u8])] = &[
        ("/proc/version", b"Linux"),
        ("/proc/cpuinfo", b"processor"),
        ("/proc/meminfo", b"MemTotal:"),
        ("/proc/sys/kernel/pid_max", b"32768"),
        ("/proc/sys/kernel/domainname", b"(none)"),
        ("/proc/net/dev", b"Inter-|"),
    ];
    for (path, prefix) in entries {
        let inode = smoke_resolve(path).expect("procfs lookup");
        let mut buf = [0u8; 32];
        let n = inode.read(0, &mut buf).expect("procfs read");
        kassert!(n >= prefix.len(), "procfs read short");
        kassert!(&buf[..prefix.len()] == *prefix, "procfs body mismatch");
    }
    for path in ["/sys/kernel/random/uuid", "/sys/kernel/random/boot_id"] {
        let inode = smoke_resolve(path).expect("procfs lookup");
        let mut buf = [0u8; 40];
        let n = inode.read(0, &mut buf).expect("procfs read");
        kassert!(n == 37, "procfs uuid length mismatch");
        kassert!(is_uuid_line(&buf[..n]), "procfs uuid shape mismatch");
    }
    debug_boot! { klog::write_raw(b"[INFO]  procfs-smoke: ok\n"); }
}
