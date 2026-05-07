// Static-file registrations split out of procfs.rs to keep that
// file under the 1000-line cap. All inodes referenced here are
// defined in `procfs.rs`; this module only carries the boot-time
// `register()` walk.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use vfs::InodeRef;

use crate::procfs::{
    StaticFileInode, ProcMeminfoInode, ProcUptimeInode, ProcLoadavgInode,
    ProcSelfStatusInode, ProcSelfCmdlineInode, ProcSelfStatInode,
    ProcSelfMapsInode, ProcSelfFdInode, ProcRootInode, ProcSelfCommInode,
    ProcSelfEnvironInode, ProcHostnameInode,
    VERSION_BODY, CPUINFO_BODY, STAT_BODY, FILESYSTEMS, MOUNTS_BODY,
    LIMITS_BODY, IO_BODY, MOUNTINFO_BODY,
};

/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N_files)
pub fn register_static_files() {
    crate::devfs::register("/proc/version",     StaticFileInode::new(VERSION_BODY)     as InodeRef);
    crate::devfs::register("/proc/cpuinfo",     StaticFileInode::new(CPUINFO_BODY)     as InodeRef);
    crate::devfs::register("/proc/meminfo",     Arc::new(ProcMeminfoInode)             as InodeRef);
    crate::devfs::register("/proc/uptime",      Arc::new(ProcUptimeInode)              as InodeRef);
    crate::devfs::register("/proc/loadavg",     Arc::new(ProcLoadavgInode)             as InodeRef);
    crate::devfs::register("/proc/stat",        StaticFileInode::new(STAT_BODY)        as InodeRef);
    crate::devfs::register("/proc/filesystems", StaticFileInode::new(FILESYSTEMS)      as InodeRef);
    crate::devfs::register("/proc/cmdline",     StaticFileInode::new(b"BOOT_IMAGE=/oxide root=/dev/oxide0 ro quiet console=ttyS0\n") as InodeRef);
    crate::devfs::register("/proc/devices",     StaticFileInode::new(b"\
Character devices:\n  1 mem\n  4 /dev/vc/0\n  5 /dev/tty\n136 pts\nBlock devices:\n") as InodeRef);
    crate::devfs::register("/proc/modules",     StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/swaps",       StaticFileInode::new(b"Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n") as InodeRef);
    crate::devfs::register("/proc/diskstats",   StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/partitions",  StaticFileInode::new(b"major minor  #blocks  name\n") as InodeRef);
    crate::devfs::register("/proc/misc",        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/buddyinfo",   StaticFileInode::new(b"Node 0, zone Normal      0 0 0 0 0 0 0 0 0 0 0\n") as InodeRef);
    crate::devfs::register("/proc/zoneinfo",    StaticFileInode::new(b"Node 0, zone Normal\n  pages free 1024\n") as InodeRef);
    crate::devfs::register("/proc/vmstat",      StaticFileInode::new(b"nr_free_pages 1024\nnr_zone_inactive_anon 0\nnr_zone_active_anon 0\n") as InodeRef);
    crate::devfs::register("/proc/interrupts",  StaticFileInode::new(b"           CPU0       \nLOC: 1234   Local timer interrupts\n") as InodeRef);
    crate::devfs::register("/proc/softirqs",    StaticFileInode::new(b"                CPU0       \n      HI:          0\n   TIMER:       1234\n") as InodeRef);
    crate::devfs::register("/proc/kallsyms",    StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/key-users",   StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/keys",        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/locks",       StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/crypto",      StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/execdomains", StaticFileInode::new(b"0-0\tLinux           \t[kernel]\n") as InodeRef);
    // cgroup-v2-style stubs. systemd + dbus + login probe both at
    // start-up; missing nodes make them fall back through error
    // paths or refuse to start. /proc/cgroups header lists no
    // controllers (cgroup v2 hides v1 here); /proc/self/cgroup
    // returns the v2 single-line "0::/" so the caller's parser
    // sees a unified hierarchy with no controller.
    crate::devfs::register("/proc/cgroups",     StaticFileInode::new(b"#subsys_name\thierarchy\tnum_cgroups\tenabled\n") as InodeRef);
    crate::devfs::register("/proc/self/cgroup", StaticFileInode::new(b"0::/\n") as InodeRef);
    crate::devfs::register("/proc/mounts",      StaticFileInode::new(MOUNTS_BODY)      as InodeRef);
    // /proc root inode for getdents64 enumeration of live tids.
    crate::devfs::register("/proc",              Arc::new(ProcRootInode)        as InodeRef);
    crate::devfs::register("/proc/self/status",  Arc::new(ProcSelfStatusInode)  as InodeRef);
    crate::devfs::register("/proc/self/cmdline", Arc::new(ProcSelfCmdlineInode) as InodeRef);
    crate::devfs::register("/proc/self/comm",    Arc::new(ProcSelfCommInode)    as InodeRef);
    crate::devfs::register("/proc/self/environ", Arc::new(ProcSelfEnvironInode) as InodeRef);
    crate::devfs::register("/proc/self/stat",    Arc::new(ProcSelfStatInode)    as InodeRef);
    crate::devfs::register("/proc/self/maps",    Arc::new(ProcSelfMapsInode)    as InodeRef);
    crate::devfs::register("/proc/self/fd",      Arc::new(ProcSelfFdInode)      as InodeRef);

    // /sys hierarchy (P3-19). Same Static inode shape; libc/systemd
    // probes look these up before falling back.
    crate::devfs::register("/sys/kernel/osrelease",
        StaticFileInode::new(b"0.1.0-pre\n") as InodeRef);
    crate::devfs::register("/sys/kernel/ostype",
        StaticFileInode::new(b"oxide\n") as InodeRef);
    crate::devfs::register("/sys/kernel/random/uuid",
        StaticFileInode::new(b"00000000-0000-0000-0000-000000000001\n") as InodeRef);
    crate::devfs::register("/sys/kernel/random/boot_id",
        StaticFileInode::new(b"00000000-0000-0000-0000-000000000002\n") as InodeRef);
    crate::devfs::register("/sys/kernel/random/entropy_avail",
        StaticFileInode::new(b"4096\n") as InodeRef);
    crate::devfs::register("/sys/devices/system/cpu/online",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/sys/devices/system/cpu/possible",
        StaticFileInode::new(b"0\n") as InodeRef);
    // /sys/class/net/lo/* — Linux net-class shape that ip / iproute2
    // probes. The values mirror the in-kernel LoopbackDev's contract
    // (`mtu()=65535`, MAC=00:..:00).
    crate::devfs::register("/sys/class/net/lo/address",
        StaticFileInode::new(b"00:00:00:00:00:00\n") as InodeRef);
    crate::devfs::register("/sys/class/net/lo/mtu",
        StaticFileInode::new(b"65536\n") as InodeRef);
    crate::devfs::register("/sys/class/net/lo/operstate",
        StaticFileInode::new(b"unknown\n") as InodeRef);
    crate::devfs::register("/sys/class/net/lo/type",
        StaticFileInode::new(b"772\n") as InodeRef);   // ARPHRD_LOOPBACK
    crate::devfs::register("/sys/class/net/lo/flags",
        StaticFileInode::new(b"0x9\n") as InodeRef);   // IFF_UP|IFF_LOOPBACK
    crate::devfs::register("/etc/os-release",
        StaticFileInode::new(b"NAME=oxide\nID=oxide\nVERSION=\"0.1.0-pre\"\n") as InodeRef);
    crate::devfs::register("/etc/machine-id",
        StaticFileInode::new(b"00000000000000000000000000000001\n") as InodeRef);
    crate::devfs::register("/etc/hostname",
        StaticFileInode::new(b"oxide\n") as InodeRef);
    crate::devfs::register("/etc/passwd",
        StaticFileInode::new(b"root:x:0:0:root:/:/bin/sh\n") as InodeRef);
    crate::devfs::register("/etc/group",
        StaticFileInode::new(b"root:x:0:\n") as InodeRef);
    crate::devfs::register("/etc/nsswitch.conf",
        StaticFileInode::new(b"passwd: files\ngroup: files\nhosts: files\n") as InodeRef);
    crate::devfs::register("/etc/resolv.conf",
        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/etc/localtime",
        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/etc/shadow",
        StaticFileInode::new(b"root::0:0:99999:7:::\n") as InodeRef);
    crate::devfs::register("/etc/shells",
        StaticFileInode::new(b"/bin/sh\n") as InodeRef);
    crate::devfs::register("/etc/profile",
        StaticFileInode::new(b"export PATH=/bin:/usr/bin\nexport PS1='$ '\n") as InodeRef);
    crate::devfs::register("/etc/issue",
        StaticFileInode::new(b"oxide \\r \\l\n\n") as InodeRef);
    crate::devfs::register("/etc/motd",
        StaticFileInode::new(b"Welcome to oxide.\n") as InodeRef);
    crate::devfs::register("/etc/hosts",
        StaticFileInode::new(b"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n") as InodeRef);
    crate::devfs::register("/etc/services",
        StaticFileInode::new(b"\
ssh\t\t22/tcp\nssh\t\t22/udp\n\
http\t\t80/tcp\nhttp\t\t80/udp\n\
https\t\t443/tcp\nhttps\t\t443/udp\n\
domain\t\t53/tcp\ndomain\t\t53/udp\n\
") as InodeRef);
    crate::devfs::register("/etc/protocols",
        StaticFileInode::new(b"\
ip\t0\tIP\nicmp\t1\tICMP\ntcp\t6\tTCP\nudp\t17\tUDP\n\
") as InodeRef);
    crate::devfs::register("/etc/ld.so.cache",
        StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/etc/ld.so.conf",
        StaticFileInode::new(b"include /etc/ld.so.conf.d/*.conf\n") as InodeRef);
    crate::devfs::register("/etc/timezone",
        StaticFileInode::new(b"UTC\n") as InodeRef);
    // /proc/self/auxv: Linux passes 16-byte AT_NULL-terminated entry pairs.
    // glibc/musl getauxval falls back to this file when the at-start auxv
    // vector wasn't preserved. We hand back a minimal AT_NULL-only blob
    // (8 bytes a_type=0, 8 bytes a_val=0) which signals "no entries",
    // matching the kernel's behavior for tasks that haven't execve'd.
    crate::devfs::register("/proc/self/auxv",
        StaticFileInode::new(&[0u8; 16]) as InodeRef);
    // /proc/self/wchan: kernel-stack symbol the task is parked on.
    // "0" means runnable / not in kernel — adequate for a non-debugger
    // observer.
    crate::devfs::register("/proc/self/wchan",
        StaticFileInode::new(b"0") as InodeRef);
    crate::devfs::register("/proc/self/sessionid",
        StaticFileInode::new(b"4294967295\n") as InodeRef);
    crate::devfs::register("/proc/self/oom_adj",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/self/loginuid",
        StaticFileInode::new(b"4294967295\n") as InodeRef);

    // /sys/kernel/tracing — tracefs surface (P30a). v1 exposes the
    // bare minimum: tracing_on, current_tracer, available_tracers,
    // and the trace pipe placeholder. Real ftrace event delivery
    // rides a follow-up.
    crate::devfs::register("/sys/kernel/tracing/tracing_on",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/sys/kernel/tracing/current_tracer",
        StaticFileInode::new(b"nop\n") as InodeRef);
    crate::devfs::register("/sys/kernel/tracing/available_tracers",
        StaticFileInode::new(b"nop\n") as InodeRef);
    crate::devfs::register("/sys/kernel/tracing/trace",
        StaticFileInode::new(b"# tracer: nop\n#\n") as InodeRef);
    crate::devfs::register("/sys/kernel/debug/tracing/tracing_on",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/sys/kernel/debug/tracing/current_tracer",
        StaticFileInode::new(b"nop\n") as InodeRef);
    crate::devfs::register("/proc/self/oom_score",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/self/oom_score_adj",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/self/limits",
        StaticFileInode::new(LIMITS_BODY) as InodeRef);
    crate::devfs::register("/proc/self/io",
        StaticFileInode::new(IO_BODY) as InodeRef);
    crate::devfs::register("/proc/self/mountinfo",
        StaticFileInode::new(MOUNTINFO_BODY) as InodeRef);
    crate::devfs::register("/proc/sys/kernel/random/boot_id",
        StaticFileInode::new(b"00000000-0000-0000-0000-000000000002\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/pid_max",
        StaticFileInode::new(b"32768\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/random/uuid",
        StaticFileInode::new(b"00000000-0000-0000-0000-000000000001\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/ngroups_max",
        StaticFileInode::new(b"65536\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/cap_last_cap",
        StaticFileInode::new(b"40\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/osrelease",
        StaticFileInode::new(b"5.15.0-oxide\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/ostype",
        StaticFileInode::new(b"Linux\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/version",
        StaticFileInode::new(b"#1 SMP PREEMPT oxide v0.1.0\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/hostname",
        Arc::new(ProcHostnameInode) as InodeRef);
    crate::devfs::register("/proc/sys/kernel/domainname",
        StaticFileInode::new(b"(none)\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/threads-max",
        StaticFileInode::new(b"32768\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/file-max",
        StaticFileInode::new(b"65536\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/file-nr",
        StaticFileInode::new(b"0\t0\t65536\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/nr_open",
        StaticFileInode::new(b"1048576\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/inotify/max_user_watches",
        StaticFileInode::new(b"65536\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/inotify/max_user_instances",
        StaticFileInode::new(b"128\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/inotify/max_queued_events",
        StaticFileInode::new(b"16384\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/pipe-max-size",
        StaticFileInode::new(b"4096\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/overcommit_memory",
        StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/swappiness",
        StaticFileInode::new(b"60\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/core/somaxconn",
        StaticFileInode::new(b"4096\n") as InodeRef);
}

