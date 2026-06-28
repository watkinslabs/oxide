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

fn register_ipv4_conf_sysctl(path: &'static str, value: &'static [u8]) {
    crate::reg::register(path, crate::sysctl::SysctlInode::new(value) as InodeRef);
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
    c.insert("modules".to_string(),     Arc::new(crate::net::ProcModulesInode) as InodeRef);
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
    let reg = crate::reg::proc_reg();
    reg.ensure_dir_path("sys");
    reg.ensure_dir_path("net");
    c.insert("sys".to_string(),         reg.lookup_path("sys").unwrap() as InodeRef);
    c.insert("net".to_string(),         reg.lookup_path("net").unwrap() as InodeRef);
    c
}

/// The singleton `/proc` root inode (built once from `build_proc_root`). procfs
/// OWNS /proc and resolves through THIS: static children here, `/proc/{sys,net,
/// self}` via the `crate::reg` PROC_REG kernfs subtree (D1d), per-pid dirs
/// synthesized. No devfs registry involvement.
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

    // /proc/self/cgroup resolves the calling task's real cgroup path at read time.
    crate::reg::register(
        "/proc/self/cgroup",
        alloc::sync::Arc::new(crate::ProcCgroupInode { tid: None }) as InodeRef,
    );
    crate::reg::register(
        "/proc/self/status",
        Arc::new(ProcSelfStatusInode) as InodeRef,
    );
    crate::reg::register(
        "/proc/self/cmdline",
        Arc::new(ProcSelfCmdlineInode) as InodeRef,
    );
    crate::reg::register("/proc/self/comm", Arc::new(ProcSelfCommInode) as InodeRef);
    crate::reg::register(
        "/proc/self/environ",
        Arc::new(ProcSelfEnvironInode) as InodeRef,
    );
    crate::reg::register("/proc/self/stat", Arc::new(ProcSelfStatInode) as InodeRef);
    crate::reg::register("/proc/self/maps", Arc::new(ProcSelfMapsInode) as InodeRef);
    crate::reg::register(
        "/proc/self/smaps",
        Arc::new(crate::smaps::ProcSelfSmapsInode) as InodeRef,
    );
    crate::reg::register("/proc/self/fd", Arc::new(ProcSelfFdInode) as InodeRef);
    crate::reg::register(
        "/proc/self/exe",
        Arc::new(crate::ProcSelfExeInode) as InodeRef,
    );
    crate::reg::register(
        "/proc/self/cwd",
        Arc::new(crate::ProcSelfCwdInode) as InodeRef,
    );
    crate::reg::register(
        "/proc/self/root",
        Arc::new(crate::ProcSelfRootInode) as InodeRef,
    );

    // /sys hierarchy (P3-19). Same Static inode shape; libc/systemd
    // probes look these up before falling back.
    sysfs::register(
        "/sys/kernel/osrelease",
        StaticFileInode::new(b"0.1.0-pre\n") as InodeRef,
    );
    sysfs::register(
        "/sys/kernel/ostype",
        StaticFileInode::new(b"oxide\n") as InodeRef,
    );
    sysfs::register(
        "/sys/kernel/random/uuid",
        StaticFileInode::new(random_uuid) as InodeRef,
    );
    sysfs::register(
        "/sys/kernel/random/boot_id",
        StaticFileInode::new(boot_id) as InodeRef,
    );
    sysfs::register(
        "/sys/kernel/random/entropy_avail",
        StaticFileInode::new(b"4096\n") as InodeRef,
    );
    // /sys/devices/system/cpu — the CPU device subsystem (Linux
    // drivers/base/cpu.c). ONE dynamic kobject directory owns the whole
    // subtree: control files + a `cpuN` device dir per CPU, enumerated at
    // readdir time so the set tracks the live online_count() rather than a
    // boot-time snapshot taken before the APs are up. nproc / htop /
    // lscpu (`_SC_NPROCESSORS_CONF` reads the cpuN dirs) walk this.
    sysfs::register(
        "/sys/devices/system/cpu",
        Arc::new(crate::syscpu::SysCpuRootInode) as InodeRef,
    );
    sysfs::register_dir("/sys/class/misc/autofs");
    sysfs::register(
        "/sys/class/misc/autofs/dev",
        StaticFileInode::new(b"10:236\n") as InodeRef,
    );
    // /sys/class/net dynamic — readdir walks the live netdev registry,
    // lookup synthesises per-iface attribute files from the NetDev trait
    // (address/mtu/operstate/type/flags/carrier/speed/duplex/ifindex/...).
    // Replaces the prior hard-coded /sys/class/net/lo/* constants.
    sysfs::init();
    // The `/etc/*` overlay (os-release/machine-id/passwd/group/hosts/…) is
    // devfs's own overlay subtree now (D1d) — registered by
    // `devfs::boot::register_etc_overlay`, NOT procfs. procfs owns only /proc.
    // /proc/self/auxv: Linux passes 16-byte AT_NULL-terminated entry pairs.
    // glibc/musl getauxval falls back to this file when the at-start auxv
    // vector wasn't preserved. We hand back a minimal AT_NULL-only blob
    // (8 bytes a_type=0, 8 bytes a_val=0) which signals "no entries",
    // matching the kernel's behavior for tasks that haven't execve'd.
    crate::reg::register(
        "/proc/self/auxv",
        StaticFileInode::new(&[0u8; 16]) as InodeRef,
    );
    // /proc/self/wchan: kernel-stack symbol the task is parked on.
    // "0" means runnable / not in kernel — adequate for a non-debugger
    // observer.
    crate::reg::register("/proc/self/wchan", StaticFileInode::new(b"0") as InodeRef);
    crate::reg::register(
        "/proc/self/sessionid",
        StaticFileInode::new(b"4294967295\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/self/oom_adj",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/self/loginuid",
        StaticFileInode::new(b"4294967295\n") as InodeRef,
    );

    // /sys/kernel/tracing — tracefs surface (P30a). v1 exposes the
    // bare minimum: tracing_on, current_tracer, available_tracers,
    // and the trace pipe placeholder. Real ftrace event delivery
    // rides a follow-up.
    sysfs::register(
        "/sys/kernel/tracing/tracing_on",
        StaticFileInode::new(b"0\n") as InodeRef,
    );
    sysfs::register(
        "/sys/kernel/tracing/current_tracer",
        StaticFileInode::new(b"nop\n") as InodeRef,
    );
    sysfs::register(
        "/sys/kernel/tracing/available_tracers",
        StaticFileInode::new(b"nop\n") as InodeRef,
    );
    sysfs::register(
        "/sys/kernel/tracing/trace",
        StaticFileInode::new(b"# tracer: nop\n#\n") as InodeRef,
    );
    sysfs::register(
        "/sys/kernel/debug/tracing/tracing_on",
        StaticFileInode::new(b"0\n") as InodeRef,
    );
    sysfs::register(
        "/sys/kernel/debug/tracing/current_tracer",
        StaticFileInode::new(b"nop\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/self/oom_score",
        StaticFileInode::new(b"0\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/self/oom_score_adj",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/self/limits",
        StaticFileInode::new(LIMITS_BODY) as InodeRef,
    );
    crate::reg::register("/proc/self/io", StaticFileInode::new(IO_BODY) as InodeRef);
    crate::reg::register(
        "/proc/self/mountinfo",
        Arc::new(crate::mounts::ProcMountinfoInode::new()) as InodeRef,
    );
    crate::reg::register(
        "/proc/self/mounts",
        Arc::new(crate::mounts::ProcMountsInode) as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/random/boot_id",
        StaticFileInode::new(boot_id) as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/pid_max",
        crate::sysctl::SysctlInode::new(b"32768\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/random/uuid",
        StaticFileInode::new(random_uuid) as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/ngroups_max",
        StaticFileInode::new(b"65536\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/cap_last_cap",
        StaticFileInode::new(b"40\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/osrelease",
        StaticFileInode::new(b"5.15.0-oxide\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/ostype",
        StaticFileInode::new(b"Linux\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/version",
        StaticFileInode::new(b"#1 SMP PREEMPT oxide v0.1.0\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/binfmt_misc",
        kernfs::PseudoDir::new_root(
            kernfs::dir_ino("/proc/sys/fs/binfmt_misc"),
            crate::reg::PROCFS_FSID,
            false,
        ) as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/hostname",
        Arc::new(ProcHostnameInode) as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/domainname",
        StaticFileInode::new(b"(none)\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/threads-max",
        StaticFileInode::new(b"32768\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/file-max",
        crate::sysctl::SysctlInode::new(b"65536\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/file-nr",
        StaticFileInode::new(b"0\t0\t65536\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/nr_open",
        crate::sysctl::SysctlInode::new(b"1048576\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/inotify/max_user_watches",
        StaticFileInode::new(b"65536\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/inotify/max_user_instances",
        StaticFileInode::new(b"128\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/inotify/max_queued_events",
        StaticFileInode::new(b"16384\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/pipe-max-size",
        crate::sysctl::SysctlInode::new(b"4096\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/overcommit_memory",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/swappiness",
        crate::sysctl::SysctlInode::new(b"60\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/core/somaxconn",
        crate::sysctl::SysctlInode::new(b"4096\n") as InodeRef,
    );
    // Common tunables systemd-sysctl / sysctl.d write — writable so the
    // apply step succeeds + reads reflect it (R5).
    crate::reg::register(
        "/proc/sys/kernel/printk",
        crate::sysctl::SysctlInode::new(b"4\t4\t1\t7\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/ipv4/ip_forward",
        crate::sysctl::IpForwardInode::new() as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/ipv4/tcp_syncookies",
        crate::sysctl::SysctlInode::new(b"1\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/dirty_ratio",
        crate::sysctl::SysctlInode::new(b"20\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/max_map_count",
        crate::sysctl::SysctlInode::new(b"65530\n") as InodeRef,
    );

    // /proc/net/* — Linux networking surface. Entries with live kernel table
    // backing use procfs inodes, not static header snapshots.
    crate::reg::register("/proc/net/dev", Arc::new(crate::net::ProcNetDevInode) as InodeRef);
    crate::reg::register(
        "/proc/net/route",
        Arc::new(crate::net::ProcNetRouteInode) as InodeRef,
    );
    crate::reg::register(
        "/proc/net/tcp",
        Arc::new(crate::net::ProcNetTcpInode) as InodeRef,
    );
    crate::reg::register("/proc/net/tcp6", Arc::new(crate::net::ProcNetTcp6Inode) as InodeRef);
    crate::reg::register("/proc/net/udp", Arc::new(crate::net::ProcNetUdpInode) as InodeRef);
    crate::reg::register("/proc/net/udp6", Arc::new(crate::net::ProcNetUdp6Inode) as InodeRef);
    crate::reg::register(
        "/proc/net/unix",
        Arc::new(crate::net::ProcNetUnixInode) as InodeRef,
    );
    crate::reg::register("/proc/net/raw", StaticFileInode::new(b"\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
") as InodeRef);
    crate::reg::register("/proc/net/raw6", StaticFileInode::new(b"\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
") as InodeRef);
    crate::reg::register(
        "/proc/net/netlink",
        StaticFileInode::new(
            b"\
sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n\
",
        ) as InodeRef,
    );
    crate::reg::register(
        "/proc/net/packet",
        StaticFileInode::new(
            b"\
sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n\
",
        ) as InodeRef,
    );
    crate::reg::register("/proc/net/snmp", Arc::new(crate::net::ProcNetSnmpInode) as InodeRef);
    crate::reg::register("/proc/net/snmp6", StaticFileInode::new(b"") as InodeRef);
    crate::reg::register(
        "/proc/net/netstat",
        StaticFileInode::new(
            b"\
TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed\n\
TcpExt: 0 0 0\n\
",
        ) as InodeRef,
    );
    crate::reg::register("/proc/net/protocols", StaticFileInode::new(b"\
protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em\n\
PACKET   1024      0     0   no       0   no  kernel       n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\n\
TCP      2128      0     0   no     320   no  kernel       y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  n\n\
UDP      1024      0     0   no       0   no  kernel       y  y  y  y  y  y  y  n  n  n  n  n  n  n  n  y  y  y  n\n\
RAW       912      0     0   no       0   no  kernel       y  y  y  y  y  y  y  n  y  n  n  n  n  n  n  y  y  n  n\n\
UNIX      640      0     0   no       0   no  kernel       n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\n\
") as InodeRef);
    crate::reg::register(
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
    crate::reg::register(
        "/proc/net/sockstat6",
        StaticFileInode::new(
            b"\
TCP6: inuse 0\nUDP6: inuse 0\nUDPLITE6: inuse 0\nRAW6: inuse 0\nFRAG6: inuse 0 memory 0\n\
",
        ) as InodeRef,
    );
    crate::reg::register("/proc/net/arp", Arc::new(crate::net::ProcNetArpInode) as InodeRef);
    crate::reg::register("/proc/net/if_inet6", Arc::new(crate::net::ProcNetIfInet6Inode) as InodeRef);
    crate::reg::register(
        "/proc/net/igmp",
        StaticFileInode::new(
            b"\
Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n\
",
        ) as InodeRef,
    );
    crate::reg::register(
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
    crate::reg::register(
        "/proc/sys/net/ipv4/tcp_syncookies",
        StaticFileInode::new(b"1\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/ipv4/tcp_tw_reuse",
        StaticFileInode::new(b"2\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/ipv4/tcp_fin_timeout",
        StaticFileInode::new(b"60\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/ipv4/tcp_keepalive_time",
        StaticFileInode::new(b"7200\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/ipv4/ip_local_port_range",
        StaticFileInode::new(b"32768\t60999\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/ipv4/icmp_echo_ignore_all",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    register_ipv4_conf_sysctls("/proc/sys/net/ipv4/conf/all");
    register_ipv4_conf_sysctls("/proc/sys/net/ipv4/conf/default");
    register_ipv4_conf_sysctls("/proc/sys/net/ipv4/conf/eth0");
    crate::reg::register(
        "/proc/sys/fs/protected_regular",
        crate::sysctl::SysctlInode::new(b"2\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/protected_fifos",
        crate::sysctl::SysctlInode::new(b"1\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        StaticFileInode::new(b"0\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/ipv6/conf/default/disable_ipv6",
        StaticFileInode::new(b"0\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/core/rmem_default",
        StaticFileInode::new(b"212992\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/core/rmem_max",
        StaticFileInode::new(b"212992\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/core/wmem_default",
        StaticFileInode::new(b"212992\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/core/wmem_max",
        StaticFileInode::new(b"212992\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/net/core/netdev_max_backlog",
        StaticFileInode::new(b"1000\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/min_free_kbytes",
        crate::sysctl::SysctlInode::new(b"4096\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/overcommit_ratio",
        crate::sysctl::SysctlInode::new(b"50\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/dirty_ratio",
        crate::sysctl::SysctlInode::new(b"20\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/dirty_background_ratio",
        crate::sysctl::SysctlInode::new(b"10\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/page-cluster",
        crate::sysctl::SysctlInode::new(b"3\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/max_map_count",
        crate::sysctl::SysctlInode::new(b"65530\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/nr_hugepages",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/vm/mmap_min_addr",
        crate::sysctl::SysctlInode::new(b"65536\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/sched_rr_timeslice_ms",
        crate::sysctl::SysctlInode::new(b"100\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/randomize_va_space",
        crate::sysctl::SysctlInode::new(b"2\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/yama/ptrace_scope",
        crate::sysctl::SysctlInode::new(b"1\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/perf_event_paranoid",
        crate::sysctl::SysctlInode::new(b"2\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/dmesg_restrict",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/kptr_restrict",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/threads-max",
        crate::sysctl::SysctlInode::new(b"32768\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/kernel/io_uring_disabled",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/file-max",
        crate::sysctl::SysctlInode::new(b"4096\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/nr_open",
        crate::sysctl::SysctlInode::new(b"1048576\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/protected_hardlinks",
        StaticFileInode::new(b"1\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/protected_symlinks",
        StaticFileInode::new(b"1\n") as InodeRef,
    );
    crate::reg::register(
        "/proc/sys/fs/suid_dumpable",
        crate::sysctl::SysctlInode::new(b"0\n") as InodeRef,
    );
}
