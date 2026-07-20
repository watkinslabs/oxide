// Static-file registrations split out of procfs.rs to keep that
// file under the 1000-line cap. All inodes referenced here are
// defined in `procfs.rs`; this module only carries the boot-time
// `register()` walk.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use vfs::InodeRef;
use sync::{Spinlock, MountTable as RootClass};

use crate::{
    make_proc_cmdline, make_proc_loadavg, make_proc_meminfo, make_proc_root,
    make_proc_self_cmdline, make_proc_self_comm, make_proc_self_environ, make_proc_self_exe,
    make_proc_self_fd, make_proc_self_maps, make_proc_self_root, make_proc_self_stat,
    make_proc_self_io, make_proc_self_status, make_proc_uptime, StaticFileInode, FILESYSTEMS,
    LIMITS_BODY, VERSION_BODY,
};
use crate::{make_proc_self_cwd, make_proc_cgroup};

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

/// Build the `/proc` root directory's static children — the Linux `proc_create`
/// set (cpuinfo/meminfo/stat/…). Each is a real child inode the directory OWNS
/// (`ProcRootInode::new` takes this map; lookup+readdir walk it). NOT a registry.
/// # C: O(N files)
pub fn build_proc_root() -> alloc::collections::BTreeMap<alloc::string::String, InodeRef> {
    use alloc::string::ToString;
    let mut c: alloc::collections::BTreeMap<alloc::string::String, InodeRef> = Default::default();
    c.insert("version".to_string(),     StaticFileInode::new(VERSION_BODY));
    c.insert("cpuinfo".to_string(),     crate::cpuinfo::make_proc_cpuinfo());
    c.insert("meminfo".to_string(),     make_proc_meminfo());
    c.insert("uptime".to_string(),      make_proc_uptime());
    c.insert("loadavg".to_string(),     make_proc_loadavg());
    c.insert("stat".to_string(),        crate::stat::make_proc_stat());
    c.insert("filesystems".to_string(), StaticFileInode::new(FILESYSTEMS));
    c.insert("cmdline".to_string(),     make_proc_cmdline());
    c.insert("devices".to_string(),     crate::devices::make_proc_devices());
    c.insert("modules".to_string(),     crate::net::make_proc_modules());
    c.insert("swaps".to_string(),       crate::swaps::make_proc_swaps());
    c.insert("diskstats".to_string(),   crate::diskstats::make_proc_diskstats());
    c.insert("partitions".to_string(),  crate::partitions::make_proc_partitions());
    c.insert("misc".to_string(),        StaticFileInode::new(b""));
    c.insert("buddyinfo".to_string(),   crate::buddyinfo::make_proc_buddyinfo());
    c.insert("zoneinfo".to_string(),    StaticFileInode::new(b"Node 0, zone Normal\n  pages free 1024\n"));
    c.insert("vmstat".to_string(),       crate::vmstat::make_proc_vmstat());
    c.insert("interrupts".to_string(),  crate::interrupts::make_proc_interrupts());
    c.insert("softirqs".to_string(),    StaticFileInode::new(b"                CPU0       \n      HI:          0\n   TIMER:       1234\n") as InodeRef);
    c.insert("kallsyms".to_string(),    StaticFileInode::new(b"") as InodeRef);
    c.insert("key-users".to_string(),   StaticFileInode::new(b"") as InodeRef);
    c.insert("keys".to_string(),        StaticFileInode::new(b"") as InodeRef);
    c.insert("locks".to_string(),       StaticFileInode::new(b"") as InodeRef);
    c.insert("crypto".to_string(),      StaticFileInode::new(b"") as InodeRef);
    c.insert("execdomains".to_string(), StaticFileInode::new(b"0-0\tLinux           \t[kernel]\n") as InodeRef);
    c.insert("cgroups".to_string(),     StaticFileInode::new(b"#subsys_name\thierarchy\tnum_cgroups\tenabled\ncpuset\t0\t1\t1\ncpu\t0\t1\t1\nio\t0\t1\t1\nmemory\t0\t1\t1\npids\t0\t1\t1\n") as InodeRef);
    c.insert("mounts".to_string(),      crate::mounts::make_proc_mounts(None));
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
static PROC_ROOT: Spinlock<Option<InodeRef>, RootClass> = Spinlock::new(None);

/// The `/proc` root directory inode (cached). `ProcfsFs::lookup` resolves the
/// static-file children + `self` + pid dirs through this.
/// # C: O(1) cached; O(N files) on first build
pub fn proc_root() -> InodeRef {
    let mut g = PROC_ROOT.lock();
    if let Some(r) = g.as_ref() { return Arc::clone(r); }
    let r = make_proc_root(build_proc_root());
    *g = Some(Arc::clone(&r));
    r
}

/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N_files)
pub fn register_static_files() {
    let random_uuid = leak_uuid_line(random_uuid_bytes());
    let boot_id = leak_uuid_line(random_uuid_bytes());

    // /proc/self/cgroup resolves the calling task's real cgroup path at read time.
    crate::reg::register("/proc/self/cgroup", make_proc_cgroup(None));
    crate::reg::register("/proc/self/status", make_proc_self_status());
    crate::reg::register("/proc/self/cmdline", make_proc_self_cmdline());
    crate::reg::register("/proc/self/comm", make_proc_self_comm());
    crate::reg::register("/proc/self/environ", make_proc_self_environ());
    crate::reg::register("/proc/self/stat", make_proc_self_stat());
    crate::reg::register("/proc/self/maps", make_proc_self_maps());
    crate::reg::register("/proc/self/smaps", crate::smaps::make_proc_self_smaps());
    crate::reg::register("/proc/self/fd", make_proc_self_fd());
    crate::reg::register("/proc/self/exe", make_proc_self_exe());
    crate::reg::register("/proc/self/cwd", make_proc_self_cwd());
    crate::reg::register("/proc/self/root", make_proc_self_root());

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
        crate::syscpu::make_syscpu_root(),
    );
    // Dynamic sysfs class/device trees are registered by sysfs::init below.
    // Device-model owned nodes such as /sys/class/misc/autofs must come from
    // drv::try_device_add, not static procfs-era registrations.
    // /sys/class/net dynamic — readdir walks the live netdev registry,
    // lookup synthesises per-iface attribute files from the NetDev trait
    // (address/mtu/operstate/type/flags/carrier/speed/duplex/ifindex/...).
    // Replaces the prior hard-coded /sys/class/net/lo/* constants.
    sysfs::init();
    // `/etc/*` (os-release/machine-id/passwd/group/hosts/services/…) ships as
    // real rootfs ext4 files (D19, `tools/xtask/src/rootfs_etc.rs`) — no devfs
    // overlay, NOT procfs. procfs owns only /proc.
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
    // WRITABLE: pam_loginuid.so writes the login uid at session open; a
    // read-only inode fails the write and breaks PAM session setup → no greeter.
    crate::reg::register(
        "/proc/self/loginuid",
        crate::sysctl::SysctlInode::new(b"4294967295\n") as InodeRef,
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
        "/proc/self/limits",
        StaticFileInode::new(LIMITS_BODY) as InodeRef,
    );
    crate::reg::register("/proc/self/io", make_proc_self_io());
    // /proc/pressure/{cpu,memory,io} — PSI pressure files (B517). O_RDWR:
    // read renders the snapshot, write registers a poll trigger. Creating
    // these clears systemd's memory-pressure-watch EOPNOTSUPP.
    crate::pressure::register();

    // /proc/sys ctl_table (D22): one declarative table + the dynamic/live-bound
    // handlers, registered into procfs's own PROC_REG subtree. Replaces the
    // ~70 scattered imperative `register("/proc/sys/...")` calls.
    crate::ctl::register_sysctl_table(boot_id, random_uuid);

    // /proc/net/* — Linux networking surface. Entries with live kernel table
    // backing use procfs inodes, not static header snapshots.
    crate::reg::register("/proc/net/dev", crate::net::make_proc_net_dev());
    crate::reg::register("/proc/net/route", crate::net::make_proc_net_route());
    crate::reg::register("/proc/net/tcp", crate::net::make_proc_net_tcp());
    crate::reg::register("/proc/net/tcp6", crate::net::make_proc_net_tcp6());
    crate::reg::register("/proc/net/udp", crate::net::make_proc_net_udp());
    crate::reg::register("/proc/net/udp6", crate::net::make_proc_net_udp6());
    crate::reg::register("/proc/net/unix", crate::net::make_proc_net_unix());
    crate::reg::register("/proc/net/raw", crate::net_raw::make_proc_net_raw());
    crate::reg::register("/proc/net/raw6", crate::net_raw::make_proc_net_raw6());
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
    crate::reg::register("/proc/net/snmp", crate::net::make_proc_net_snmp());
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
    crate::reg::register("/proc/net/arp", crate::net::make_proc_net_arp());
    crate::reg::register("/proc/net/if_inet6", crate::net::make_proc_net_if_inet6());
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

}
