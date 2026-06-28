// Static-file registrations split out of procfs.rs to keep that
// file under the 1000-line cap. All inodes referenced here are
// defined in `procfs.rs`; this module only carries the boot-time
// `register()` walk.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use vfs::InodeRef;
use sync::{Spinlock, MountTable as RootClass};

use crate::{
    ProcHostnameInode, ProcLoadavgInode, ProcMeminfoInode, ProcRootInode, ProcSelfCmdlineInode,
    ProcSelfCommInode, ProcSelfEnvironInode, ProcSelfFdInode, ProcSelfMapsInode, ProcSelfStatInode,
    ProcSelfStatusInode, ProcUptimeInode, StaticFileInode, FILESYSTEMS, IO_BODY,
    LIMITS_BODY, VERSION_BODY,
};

fn hex_nibble(n: u8) -> u8 {
    match n & 0x0f {
        v @ 0..=9 => b'0' + v,
        v => b'a' + (v - 10),
    }
}

fn fill_hex(dst: &mut [u8], bytes: &[u8]) {
    for (i, b) in bytes.iter().copied().enumerate() {
        dst[i * 2] = hex_nibble(b >> 4);
        dst[i * 2 + 1] = hex_nibble(b);
    }
}

fn random_uuid_bytes() -> [u8; 16] {
    let mut out = [0u8; 16];
    let a = devfs::misc::lcg_next().to_le_bytes();
    let b = devfs::misc::lcg_next().to_le_bytes();
    out[..8].copy_from_slice(&a);
    out[8..].copy_from_slice(&b);
    out[6] = (out[6] & 0x0f) | 0x40;
    out[8] = (out[8] & 0x3f) | 0x80;
    out
}

fn leak_uuid_line(bytes: [u8; 16]) -> &'static [u8] {
    let mut s = Vec::with_capacity(37);
    let mut hex = [0u8; 32];
    fill_hex(&mut hex, &bytes);
    s.extend_from_slice(&hex[0..8]);
    s.push(b'-');
    s.extend_from_slice(&hex[8..12]);
    s.push(b'-');
    s.extend_from_slice(&hex[12..16]);
    s.push(b'-');
    s.extend_from_slice(&hex[16..20]);
    s.push(b'-');
    s.extend_from_slice(&hex[20..32]);
    s.push(b'\n');
    Box::leak(s.into_boxed_slice())
}

fn leak_machine_id_line(bytes: [u8; 16]) -> &'static [u8] {
    let mut s = Vec::with_capacity(33);
    let mut hex = [0u8; 32];
    fill_hex(&mut hex, &bytes);
    s.extend_from_slice(&hex);
    s.push(b'\n');
    Box::leak(s.into_boxed_slice())
}

fn register_ipv4_conf_sysctl(path: &'static str, value: &'static [u8]) {
    devfs::register(path, crate::sysctl::SysctlInode::new(value) as InodeRef);
}

fn register_ipv4_conf_sysctls(base: &'static str) {
    let entries: &[(&str, &[u8])] = match base {
        "/proc/sys/net/ipv4/conf/all" => &[
            ("/proc/sys/net/ipv4/conf/all/rp_filter", b"0\n"),
            ("/proc/sys/net/ipv4/conf/all/arp_ignore", b"0\n"),
            ("/proc/sys/net/ipv4/conf/all/arp_announce", b"0\n"),
            ("/proc/sys/net/ipv4/conf/all/accept_redirects", b"1\n"),
            ("/proc/sys/net/ipv4/conf/all/send_redirects", b"1\n"),
            ("/proc/sys/net/ipv4/conf/all/forwarding", b"0\n"),
        ],
        "/proc/sys/net/ipv4/conf/default" => &[
            ("/proc/sys/net/ipv4/conf/default/rp_filter", b"0\n"),
            ("/proc/sys/net/ipv4/conf/default/arp_ignore", b"0\n"),
            ("/proc/sys/net/ipv4/conf/default/arp_announce", b"0\n"),
            ("/proc/sys/net/ipv4/conf/default/accept_redirects", b"1\n"),
            ("/proc/sys/net/ipv4/conf/default/send_redirects", b"1\n"),
            ("/proc/sys/net/ipv4/conf/default/forwarding", b"0\n"),
        ],
        "/proc/sys/net/ipv4/conf/eth0" => &[
            ("/proc/sys/net/ipv4/conf/eth0/rp_filter", b"0\n"),
            ("/proc/sys/net/ipv4/conf/eth0/arp_ignore", b"0\n"),
            ("/proc/sys/net/ipv4/conf/eth0/arp_announce", b"0\n"),
            ("/proc/sys/net/ipv4/conf/eth0/accept_redirects", b"1\n"),
            ("/proc/sys/net/ipv4/conf/eth0/send_redirects", b"1\n"),
            ("/proc/sys/net/ipv4/conf/eth0/forwarding", b"0\n"),
        ],
        _ => &[],
    };
    for (path, value) in entries.iter().copied() {
        register_ipv4_conf_sysctl(path, value);
    }
}

/// Build the `/proc` root directory's static children — the Linux `proc_create`
/// set (cpuinfo/meminfo/stat/…). Each is a real child inode the directory OWNS
/// (`ProcRootInode::new` takes this map; lookup+readdir walk it). NOT a registry.
/// # C: O(N files)
pub fn build_proc_root() -> alloc::collections::BTreeMap<alloc::string::String, InodeRef> {
    use alloc::string::ToString;
    let mut c: alloc::collections::BTreeMap<alloc::string::String, InodeRef> = Default::default();
    c.insert("version".to_string(),     StaticFileInode::new(VERSION_BODY) as InodeRef);
    c.insert("cpuinfo".to_string(),     Arc::new(crate::cpuinfo::ProcCpuinfoInode) as InodeRef);
    c.insert("meminfo".to_string(),     Arc::new(ProcMeminfoInode) as InodeRef);
    c.insert("uptime".to_string(),      Arc::new(ProcUptimeInode) as InodeRef);
    c.insert("loadavg".to_string(),     Arc::new(ProcLoadavgInode) as InodeRef);
    c.insert("stat".to_string(),        Arc::new(crate::stat::ProcStatInode) as InodeRef);
    c.insert("filesystems".to_string(), StaticFileInode::new(FILESYSTEMS) as InodeRef);
    c.insert("cmdline".to_string(),     Arc::new(crate::ProcCmdlineInode) as InodeRef);
    c.insert("devices".to_string(),     Arc::new(crate::devices::ProcDevicesInode) as InodeRef);
    c.insert("modules".to_string(),     StaticFileInode::new(b"") as InodeRef);
    c.insert("swaps".to_string(),       StaticFileInode::new(b"Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n") as InodeRef);
    c.insert("diskstats".to_string(),   Arc::new(crate::diskstats::ProcDiskstatsInode) as InodeRef);
    c.insert("partitions".to_string(),  Arc::new(crate::partitions::ProcPartitionsInode) as InodeRef);
    c.insert("misc".to_string(),        StaticFileInode::new(b"") as InodeRef);
    c.insert("buddyinfo".to_string(),   Arc::new(crate::buddyinfo::ProcBuddyinfoInode) as InodeRef);
    c.insert("zoneinfo".to_string(),    StaticFileInode::new(b"Node 0, zone Normal\n  pages free 1024\n") as InodeRef);
    c.insert("vmstat".to_string(),       Arc::new(crate::vmstat::ProcVmstatInode) as InodeRef);
    c.insert("interrupts".to_string(),  Arc::new(crate::interrupts::ProcInterruptsInode) as InodeRef);
    c.insert("softirqs".to_string(),    StaticFileInode::new(b"                CPU0       \n      HI:          0\n   TIMER:       1234\n") as InodeRef);
    c.insert("kallsyms".to_string(),    StaticFileInode::new(b"") as InodeRef);
    c.insert("key-users".to_string(),   StaticFileInode::new(b"") as InodeRef);
    c.insert("keys".to_string(),        StaticFileInode::new(b"") as InodeRef);
    c.insert("locks".to_string(),       StaticFileInode::new(b"") as InodeRef);
    c.insert("crypto".to_string(),      StaticFileInode::new(b"") as InodeRef);
    c.insert("execdomains".to_string(), StaticFileInode::new(b"0-0\tLinux           \t[kernel]\n") as InodeRef);
    c.insert("cgroups".to_string(),     StaticFileInode::new(b"#subsys_name\thierarchy\tnum_cgroups\tenabled\ncpuset\t0\t1\t1\ncpu\t0\t1\t1\nio\t0\t1\t1\nmemory\t0\t1\t1\npids\t0\t1\t1\n") as InodeRef);
    c.insert("mounts".to_string(),      Arc::new(crate::mounts::ProcMountsInode) as InodeRef);
    c
}

/// The singleton `/proc` root inode (built once from `build_proc_root`). procfs
/// OWNS /proc and resolves through THIS — a mounted filesystem must not live in
/// the devfs registry (that conflicts with the devfs tree auto-creating a /proc
/// dir for `/proc/net/*` etc).
static PROC_ROOT: Spinlock<Option<Arc<ProcRootInode>>, RootClass> = Spinlock::new(None);

/// The `/proc` root directory inode (cached). `ProcfsFs::lookup` resolves the
/// static-file children + `self` + pid dirs through this.
/// # C: O(1) cached; O(N files) on first build
pub fn proc_root() -> Arc<ProcRootInode> {
    let mut g = PROC_ROOT.lock();
    if let Some(r) = g.as_ref() { return Arc::clone(r); }
    let r = Arc::new(ProcRootInode::new(build_proc_root()));
    *g = Some(Arc::clone(&r));
    r
}

/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N_files)
pub fn register_static_files() {
    let random_uuid = leak_uuid_line(random_uuid_bytes());
    let boot_id = leak_uuid_line(random_uuid_bytes());
    let machine_id = leak_machine_id_line(random_uuid_bytes());

    // /proc/self/cgroup resolves the calling task's real cgroup path at read time.
    devfs::register(
        "/proc/self/cgroup",
        alloc::sync::Arc::new(crate::ProcCgroupInode { tid: None }) as InodeRef,
    );
    devfs::register(
        "/proc/self/status",
        Arc::new(ProcSelfStatusInode) as InodeRef,
    );
    devfs::register(
        "/proc/self/cmdline",
        Arc::new(ProcSelfCmdlineInode) as InodeRef,
    );
    devfs::register("/proc/self/comm", Arc::new(ProcSelfCommInode) as InodeRef);
    devfs::register(
        "/proc/self/environ",
        Arc::new(ProcSelfEnvironInode) as InodeRef,
    );
    devfs::register("/proc/self/stat", Arc::new(ProcSelfStatInode) as InodeRef);
    devfs::register("/proc/self/maps", Arc::new(ProcSelfMapsInode) as InodeRef);
    devfs::register(
        "/proc/self/smaps",
        Arc::new(crate::smaps::ProcSelfSmapsInode) as InodeRef,
    );
    devfs::register("/proc/self/fd", Arc::new(ProcSelfFdInode) as InodeRef);
    devfs::register(
        "/proc/self/exe",
        Arc::new(crate::ProcSelfExeInode) as InodeRef,
    );
    devfs::register(
        "/proc/self/cwd",
        Arc::new(crate::ProcSelfCwdInode) as InodeRef,
    );
    devfs::register(
        "/proc/self/root",
        Arc::new(crate::ProcSelfRootInode) as InodeRef,
    );

    // /sys hierarchy (P3-19). Same Static inode shape; libc/systemd
    // probes look these up before falling back.
    devfs::register(
        "/sys/kernel/osrelease",
        StaticFileInode::new(b"0.1.0-pre\n") as InodeRef,
    );
    devfs::register(
        "/sys/kernel/ostype",
        StaticFileInode::new(b"oxide\n") as InodeRef,
    );
    devfs::register(
        "/sys/kernel/random/uuid",
        StaticFileInode::new(random_uuid) as InodeRef,
    );
    devfs::register(
        "/sys/kernel/random/boot_id",
        StaticFileInode::new(boot_id) as InodeRef,
    );
    devfs::register(
        "/sys/kernel/random/entropy_avail",
        StaticFileInode::new(b"4096\n") as InodeRef,
    );
    // /sys/devices/system/cpu — the CPU device subsystem (Linux
    // drivers/base/cpu.c). ONE dynamic kobject directory owns the whole
    // subtree: control files + a `cpuN` device dir per CPU, enumerated at
    // readdir time so the set tracks the live online_count() rather than a
    // boot-time snapshot taken before the APs are up. nproc / htop /
    // lscpu (`_SC_NPROCESSORS_CONF` reads the cpuN dirs) walk this.
    devfs::register(
        "/sys/devices/system/cpu",
        Arc::new(crate::syscpu::SysCpuRootInode) as InodeRef,
    );
    // /sys/class/net dynamic — readdir walks the live netdev registry,
    // lookup synthesises per-iface attribute files from the NetDev trait
    // (address/mtu/operstate/type/flags/carrier/speed/duplex/ifindex/...).
    // Replaces the prior hard-coded /sys/class/net/lo/* constants.
    sysfs::init();
    devfs::register(
        "/etc/os-release",
        StaticFileInode::new(b"NAME=oxide\nID=oxide\nVERSION=\"0.1.0-pre\"\n") as InodeRef,
    );
    devfs::register(
        "/etc/machine-id",
        StaticFileInode::new(machine_id) as InodeRef,
    );
    devfs::register(
        "/etc/hostname",
        StaticFileInode::new(b"oxide\n") as InodeRef,
    );
    devfs::register(
        "/etc/passwd",
        StaticFileInode::new(b"root:x:0:0:root:/:/bin/sh\n") as InodeRef,
    );
    devfs::register(
        "/etc/group",
        StaticFileInode::new(b"root:x:0:\n") as InodeRef,
    );
    devfs::register(
        "/etc/nsswitch.conf",
        StaticFileInode::new(b"passwd: files\ngroup: files\nhosts: files\n") as InodeRef,
    );
    devfs::register("/etc/resolv.conf", StaticFileInode::new(b"") as InodeRef);
    devfs::register("/etc/localtime", StaticFileInode::new(b"") as InodeRef);
    devfs::register(
        "/etc/shadow",
        StaticFileInode::new(b"root::0:0:99999:7:::\n") as InodeRef,
    );
    devfs::register(
        "/etc/shells",
        StaticFileInode::new(b"/bin/sh\n") as InodeRef,
    );
    devfs::register(
        "/etc/profile",
        StaticFileInode::new(b"export PATH=/bin:/usr/bin\nexport PS1='$ '\n") as InodeRef,
    );
    devfs::register(
        "/etc/issue",
        StaticFileInode::new(b"oxide \\r \\l\n\n") as InodeRef,
    );
    devfs::register(
        "/etc/motd",
        StaticFileInode::new(b"Welcome to oxide.\n") as InodeRef,
    );
    devfs::register(
        "/etc/hosts",
        StaticFileInode::new(b"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n") as InodeRef,
    );
    devfs::register(
        "/etc/services",
        StaticFileInode::new(
            b"\
ssh\t\t22/tcp\nssh\t\t22/udp\n\
http\t\t80/tcp\nhttp\t\t80/udp\n\
https\t\t443/tcp\nhttps\t\t443/udp\n\
domain\t\t53/tcp\ndomain\t\t53/udp\n\
",
        ) as InodeRef,
    );
    devfs::register(
        "/etc/protocols",
        StaticFileInode::new(
            b"\
ip\t0\tIP\nicmp\t1\tICMP\ntcp\t6\tTCP\nudp\t17\tUDP\n\
",
        ) as InodeRef,
    );
    devfs::register("/etc/ld.so.cache", StaticFileInode::new(b"") as InodeRef);
    devfs::register(
        "/etc/ld.so.conf",
        StaticFileInode::new(b"include /etc/ld.so.conf.d/*.conf\n") as InodeRef,
    );
    devfs::register("/etc/timezone", StaticFileInode::new(b"UTC\n") as InodeRef);
    // /proc/self/auxv: Linux passes 16-byte AT_NULL-terminated entry pairs.
    // glibc/musl getauxval falls back to this file when the at-start auxv
    // vector wasn't preserved. We hand back a minimal AT_NULL-only blob
    // (8 bytes a_type=0, 8 bytes a_val=0) which signals "no entries",
    // matching the kernel's behavior for tasks that haven't execve'd.
    devfs::register(
        "/proc/self/auxv",
        StaticFileInode::new(&[0u8; 16]) as InodeRef,
    );
    // /proc/self/wchan: kernel-stack symbol the task is parked on.
    // "0" means runnable / not in kernel — adequate for a non-debugger
    // observer.
    devfs::register("/proc/self/wchan", StaticFileInode::new(b"0") as InodeRef);
    devfs::register(
        "/proc/self/sessionid",
        StaticFileInode::new(b"4294967295\n") as InodeRef,
    );
    devfs::register(
        "/proc/self/oom_adj",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/proc/self/loginuid",
        StaticFileInode::new(b"4294967295\n") as InodeRef,
    );

    // /sys/kernel/tracing — tracefs surface (P30a). v1 exposes the
    // bare minimum: tracing_on, current_tracer, available_tracers,
    // and the trace pipe placeholder. Real ftrace event delivery
    // rides a follow-up.
    devfs::register(
        "/sys/kernel/tracing/tracing_on",
        StaticFileInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/sys/kernel/tracing/current_tracer",
        StaticFileInode::new(b"nop\n") as InodeRef,
    );
    devfs::register(
        "/sys/kernel/tracing/available_tracers",
        StaticFileInode::new(b"nop\n") as InodeRef,
    );
    devfs::register(
        "/sys/kernel/tracing/trace",
        StaticFileInode::new(b"# tracer: nop\n#\n") as InodeRef,
    );
    devfs::register(
        "/sys/kernel/debug/tracing/tracing_on",
        StaticFileInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/sys/kernel/debug/tracing/current_tracer",
        StaticFileInode::new(b"nop\n") as InodeRef,
    );
    devfs::register(
        "/proc/self/oom_score",
        StaticFileInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/proc/self/oom_score_adj",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/proc/self/limits",
        StaticFileInode::new(LIMITS_BODY) as InodeRef,
    );
    devfs::register("/proc/self/io", StaticFileInode::new(IO_BODY) as InodeRef);
    devfs::register(
        "/proc/self/mountinfo",
        Arc::new(crate::mounts::ProcMountinfoInode::new()) as InodeRef,
    );
    devfs::register(
        "/proc/self/mounts",
        Arc::new(crate::mounts::ProcMountsInode) as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/random/boot_id",
        StaticFileInode::new(boot_id) as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/pid_max",
        crate::sysctl::SysctlInode::new(b"32768\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/random/uuid",
        StaticFileInode::new(random_uuid) as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/ngroups_max",
        StaticFileInode::new(b"65536\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/cap_last_cap",
        StaticFileInode::new(b"40\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/osrelease",
        StaticFileInode::new(b"5.15.0-oxide\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/ostype",
        StaticFileInode::new(b"Linux\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/version",
        StaticFileInode::new(b"#1 SMP PREEMPT oxide v0.1.0\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/hostname",
        Arc::new(ProcHostnameInode) as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/domainname",
        StaticFileInode::new(b"(none)\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/threads-max",
        StaticFileInode::new(b"32768\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/file-max",
        crate::sysctl::SysctlInode::new(b"65536\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/file-nr",
        StaticFileInode::new(b"0\t0\t65536\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/nr_open",
        crate::sysctl::SysctlInode::new(b"1048576\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/inotify/max_user_watches",
        StaticFileInode::new(b"65536\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/inotify/max_user_instances",
        StaticFileInode::new(b"128\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/inotify/max_queued_events",
        StaticFileInode::new(b"16384\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/pipe-max-size",
        crate::sysctl::SysctlInode::new(b"4096\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/overcommit_memory",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/swappiness",
        crate::sysctl::SysctlInode::new(b"60\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/core/somaxconn",
        crate::sysctl::SysctlInode::new(b"4096\n") as InodeRef,
    );
    // Common tunables systemd-sysctl / sysctl.d write — writable so the
    // apply step succeeds + reads reflect it (R5).
    devfs::register(
        "/proc/sys/kernel/printk",
        crate::sysctl::SysctlInode::new(b"4\t4\t1\t7\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/ipv4/ip_forward",
        crate::sysctl::IpForwardInode::new() as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/ipv4/tcp_syncookies",
        crate::sysctl::SysctlInode::new(b"1\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/dirty_ratio",
        crate::sysctl::SysctlInode::new(b"20\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/max_map_count",
        crate::sysctl::SysctlInode::new(b"65530\n") as InodeRef,
    );

    // F158: /proc/net/* — Linux networking surface. v1 has loopback
    // only, no real protocol stack tables; we emit the headers + a
    // single 'lo' row so iproute2 / netstat / ifconfig / ss find
    // something parseable.
    devfs::register("/proc/net/dev", StaticFileInode::new(b"\
Inter-|   Receive                                                |  Transmit\n\
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
    lo:       0       0    0    0    0     0          0         0       0       0    0    0    0     0       0          0\n\
") as InodeRef);
    devfs::register(
        "/proc/net/route",
        StaticFileInode::new(
            b"\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n\
",
        ) as InodeRef,
    );
    devfs::register(
        "/proc/net/tcp",
        StaticFileInode::new(
            b"\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
",
        ) as InodeRef,
    );
    devfs::register("/proc/net/tcp6", StaticFileInode::new(b"\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
") as InodeRef);
    devfs::register("/proc/net/udp", StaticFileInode::new(b"\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
") as InodeRef);
    devfs::register("/proc/net/udp6", StaticFileInode::new(b"\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
") as InodeRef);
    devfs::register(
        "/proc/net/unix",
        StaticFileInode::new(
            b"\
Num       RefCount Protocol Flags    Type St Inode Path\n\
",
        ) as InodeRef,
    );
    devfs::register("/proc/net/raw", StaticFileInode::new(b"\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
") as InodeRef);
    devfs::register("/proc/net/raw6", StaticFileInode::new(b"\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
") as InodeRef);
    devfs::register(
        "/proc/net/netlink",
        StaticFileInode::new(
            b"\
sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n\
",
        ) as InodeRef,
    );
    devfs::register(
        "/proc/net/packet",
        StaticFileInode::new(
            b"\
sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n\
",
        ) as InodeRef,
    );
    devfs::register("/proc/net/snmp", StaticFileInode::new(b"\
Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates\n\
Ip: 1 64 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n\
Icmp: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n\
Tcp: 1 200 120000 -1 0 0 0 0 0 0 0 0 0 0 0\n\
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti\n\
Udp: 0 0 0 0 0 0 0 0\n\
") as InodeRef);
    devfs::register("/proc/net/snmp6", StaticFileInode::new(b"") as InodeRef);
    devfs::register(
        "/proc/net/netstat",
        StaticFileInode::new(
            b"\
TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed\n\
TcpExt: 0 0 0\n\
",
        ) as InodeRef,
    );
    devfs::register("/proc/net/protocols", StaticFileInode::new(b"\
protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em\n\
PACKET   1024      0     0   no       0   no  kernel       n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\n\
TCP      2128      0     0   no     320   no  kernel       y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  n\n\
UDP      1024      0     0   no       0   no  kernel       y  y  y  y  y  y  y  n  n  n  n  n  n  n  n  y  y  y  n\n\
RAW       912      0     0   no       0   no  kernel       y  y  y  y  y  y  y  n  y  n  n  n  n  n  n  y  y  n  n\n\
UNIX      640      0     0   no       0   no  kernel       n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\n\
") as InodeRef);
    devfs::register(
        "/proc/net/sockstat",
        StaticFileInode::new(
            b"\
sockets: used 0\n\
TCP: inuse 0 orphan 0 tw 0 alloc 0 mem 0\n\
UDP: inuse 0 mem 0\n\
UDPLITE: inuse 0\n\
RAW: inuse 0\n\
FRAG: inuse 0 memory 0\n\
",
        ) as InodeRef,
    );
    devfs::register(
        "/proc/net/sockstat6",
        StaticFileInode::new(
            b"\
TCP6: inuse 0\nUDP6: inuse 0\nUDPLITE6: inuse 0\nRAW6: inuse 0\nFRAG6: inuse 0 memory 0\n\
",
        ) as InodeRef,
    );
    devfs::register(
        "/proc/net/arp",
        StaticFileInode::new(
            b"\
IP address       HW type     Flags       HW address            Mask     Device\n\
",
        ) as InodeRef,
    );
    devfs::register(
        "/proc/net/if_inet6",
        StaticFileInode::new(
            b"\
00000000000000000000000000000001 01 80 10 80       lo\n\
",
        ) as InodeRef,
    );
    devfs::register(
        "/proc/net/igmp",
        StaticFileInode::new(
            b"\
Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n\
",
        ) as InodeRef,
    );
    devfs::register(
        "/proc/net/wireless",
        StaticFileInode::new(
            b"\
Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n\
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n\
",
        ) as InodeRef,
    );

    // F158: more /proc/sys entries — sysctl knobs Linux exposes that
    // glibc/systemd/networking tools probe at startup.
    devfs::register(
        "/proc/sys/net/ipv4/tcp_syncookies",
        StaticFileInode::new(b"1\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/ipv4/tcp_tw_reuse",
        StaticFileInode::new(b"2\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/ipv4/tcp_fin_timeout",
        StaticFileInode::new(b"60\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/ipv4/tcp_keepalive_time",
        StaticFileInode::new(b"7200\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/ipv4/ip_local_port_range",
        StaticFileInode::new(b"32768\t60999\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/ipv4/icmp_echo_ignore_all",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    register_ipv4_conf_sysctls("/proc/sys/net/ipv4/conf/all");
    register_ipv4_conf_sysctls("/proc/sys/net/ipv4/conf/default");
    register_ipv4_conf_sysctls("/proc/sys/net/ipv4/conf/eth0");
    devfs::register(
        "/proc/sys/fs/protected_regular",
        crate::sysctl::SysctlInode::new(b"2\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/protected_fifos",
        crate::sysctl::SysctlInode::new(b"1\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        StaticFileInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/ipv6/conf/default/disable_ipv6",
        StaticFileInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/core/rmem_default",
        StaticFileInode::new(b"212992\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/core/rmem_max",
        StaticFileInode::new(b"212992\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/core/wmem_default",
        StaticFileInode::new(b"212992\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/core/wmem_max",
        StaticFileInode::new(b"212992\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/net/core/netdev_max_backlog",
        StaticFileInode::new(b"1000\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/min_free_kbytes",
        crate::sysctl::SysctlInode::new(b"4096\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/overcommit_ratio",
        crate::sysctl::SysctlInode::new(b"50\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/dirty_ratio",
        crate::sysctl::SysctlInode::new(b"20\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/dirty_background_ratio",
        crate::sysctl::SysctlInode::new(b"10\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/page-cluster",
        crate::sysctl::SysctlInode::new(b"3\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/max_map_count",
        crate::sysctl::SysctlInode::new(b"65530\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/nr_hugepages",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/vm/mmap_min_addr",
        crate::sysctl::SysctlInode::new(b"65536\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/sched_rr_timeslice_ms",
        crate::sysctl::SysctlInode::new(b"100\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/randomize_va_space",
        crate::sysctl::SysctlInode::new(b"2\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/yama/ptrace_scope",
        crate::sysctl::SysctlInode::new(b"1\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/perf_event_paranoid",
        crate::sysctl::SysctlInode::new(b"2\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/dmesg_restrict",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/kptr_restrict",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/threads-max",
        crate::sysctl::SysctlInode::new(b"32768\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/kernel/io_uring_disabled",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/file-max",
        crate::sysctl::SysctlInode::new(b"4096\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/nr_open",
        crate::sysctl::SysctlInode::new(b"1048576\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/protected_hardlinks",
        StaticFileInode::new(b"1\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/protected_symlinks",
        StaticFileInode::new(b"1\n") as InodeRef,
    );
    devfs::register(
        "/proc/sys/fs/suid_dumpable",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
}
