// Static-file registrations split out of procfs.rs to keep that
// file under the 1000-line cap. All inodes referenced here are
// defined in `procfs.rs`; this module only carries the boot-time
// `register()` walk.


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
    crate::devfs::register("/proc/self/smaps",   Arc::new(crate::procfs::smaps::ProcSelfSmapsInode) as InodeRef);
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

    // F158: /proc/net/* — Linux networking surface. v1 has loopback
    // only, no real protocol stack tables; we emit the headers + a
    // single 'lo' row so iproute2 / netstat / ifconfig / ss find
    // something parseable.
    crate::devfs::register("/proc/net/dev", StaticFileInode::new(b"\
Inter-|   Receive                                                |  Transmit\n\
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
    lo:       0       0    0    0    0     0          0         0       0       0    0    0    0     0       0          0\n\
") as InodeRef);
    crate::devfs::register("/proc/net/route", StaticFileInode::new(b"\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n\
") as InodeRef);
    crate::devfs::register("/proc/net/tcp", StaticFileInode::new(b"\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
") as InodeRef);
    crate::devfs::register("/proc/net/tcp6", StaticFileInode::new(b"\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
") as InodeRef);
    crate::devfs::register("/proc/net/udp", StaticFileInode::new(b"\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
") as InodeRef);
    crate::devfs::register("/proc/net/udp6", StaticFileInode::new(b"\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
") as InodeRef);
    crate::devfs::register("/proc/net/unix", StaticFileInode::new(b"\
Num       RefCount Protocol Flags    Type St Inode Path\n\
") as InodeRef);
    crate::devfs::register("/proc/net/raw", StaticFileInode::new(b"\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
") as InodeRef);
    crate::devfs::register("/proc/net/raw6", StaticFileInode::new(b"\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
") as InodeRef);
    crate::devfs::register("/proc/net/netlink", StaticFileInode::new(b"\
sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n\
") as InodeRef);
    crate::devfs::register("/proc/net/packet", StaticFileInode::new(b"\
sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n\
") as InodeRef);
    crate::devfs::register("/proc/net/snmp", StaticFileInode::new(b"\
Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates\n\
Ip: 1 64 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n\
Icmp: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n\
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors\n\
Tcp: 1 200 120000 -1 0 0 0 0 0 0 0 0 0 0 0\n\
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti\n\
Udp: 0 0 0 0 0 0 0 0\n\
") as InodeRef);
    crate::devfs::register("/proc/net/snmp6", StaticFileInode::new(b"") as InodeRef);
    crate::devfs::register("/proc/net/netstat", StaticFileInode::new(b"\
TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed\n\
TcpExt: 0 0 0\n\
") as InodeRef);
    crate::devfs::register("/proc/net/protocols", StaticFileInode::new(b"\
protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em\n\
PACKET   1024      0     0   no       0   no  kernel       n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\n\
TCP      2128      0     0   no     320   no  kernel       y  y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  n\n\
UDP      1024      0     0   no       0   no  kernel       y  y  y  y  y  y  y  n  n  n  n  n  n  n  n  y  y  y  n\n\
RAW       912      0     0   no       0   no  kernel       y  y  y  y  y  y  y  n  y  n  n  n  n  n  n  y  y  n  n\n\
UNIX      640      0     0   no       0   no  kernel       n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n\n\
") as InodeRef);
    crate::devfs::register("/proc/net/sockstat", StaticFileInode::new(b"\
sockets: used 0\n\
TCP: inuse 0 orphan 0 tw 0 alloc 0 mem 0\n\
UDP: inuse 0 mem 0\n\
UDPLITE: inuse 0\n\
RAW: inuse 0\n\
FRAG: inuse 0 memory 0\n\
") as InodeRef);
    crate::devfs::register("/proc/net/sockstat6", StaticFileInode::new(b"\
TCP6: inuse 0\nUDP6: inuse 0\nUDPLITE6: inuse 0\nRAW6: inuse 0\nFRAG6: inuse 0 memory 0\n\
") as InodeRef);
    crate::devfs::register("/proc/net/arp", StaticFileInode::new(b"\
IP address       HW type     Flags       HW address            Mask     Device\n\
") as InodeRef);
    crate::devfs::register("/proc/net/if_inet6", StaticFileInode::new(b"\
00000000000000000000000000000001 01 80 10 80       lo\n\
") as InodeRef);
    crate::devfs::register("/proc/net/igmp", StaticFileInode::new(b"\
Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n\
") as InodeRef);
    crate::devfs::register("/proc/net/wireless", StaticFileInode::new(b"\
Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n\
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n\
") as InodeRef);

    // F158: more /proc/sys entries — sysctl knobs Linux exposes that
    // glibc/systemd/networking tools probe at startup.
    crate::devfs::register("/proc/sys/net/ipv4/ip_forward", StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/ipv4/tcp_syncookies", StaticFileInode::new(b"1\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/ipv4/tcp_tw_reuse", StaticFileInode::new(b"2\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/ipv4/tcp_fin_timeout", StaticFileInode::new(b"60\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/ipv4/tcp_keepalive_time", StaticFileInode::new(b"7200\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/ipv4/ip_local_port_range", StaticFileInode::new(b"32768\t60999\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/ipv4/icmp_echo_ignore_all", StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/ipv6/conf/all/disable_ipv6", StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/ipv6/conf/default/disable_ipv6", StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/core/rmem_default", StaticFileInode::new(b"212992\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/core/rmem_max", StaticFileInode::new(b"212992\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/core/wmem_default", StaticFileInode::new(b"212992\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/core/wmem_max", StaticFileInode::new(b"212992\n") as InodeRef);
    crate::devfs::register("/proc/sys/net/core/netdev_max_backlog", StaticFileInode::new(b"1000\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/min_free_kbytes", StaticFileInode::new(b"4096\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/overcommit_ratio", StaticFileInode::new(b"50\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/dirty_ratio", StaticFileInode::new(b"20\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/dirty_background_ratio", StaticFileInode::new(b"10\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/page-cluster", StaticFileInode::new(b"3\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/max_map_count", StaticFileInode::new(b"65530\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/nr_hugepages", StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/sys/vm/mmap_min_addr", StaticFileInode::new(b"65536\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/sched_rr_timeslice_ms", StaticFileInode::new(b"100\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/randomize_va_space", StaticFileInode::new(b"2\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/yama/ptrace_scope", StaticFileInode::new(b"1\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/perf_event_paranoid", StaticFileInode::new(b"2\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/dmesg_restrict", StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/kptr_restrict", StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/threads-max", StaticFileInode::new(b"32768\n") as InodeRef);
    crate::devfs::register("/proc/sys/kernel/io_uring_disabled", StaticFileInode::new(b"0\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/file-max", StaticFileInode::new(b"4096\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/nr_open", StaticFileInode::new(b"1048576\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/protected_hardlinks", StaticFileInode::new(b"1\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/protected_symlinks", StaticFileInode::new(b"1\n") as InodeRef);
    crate::devfs::register("/proc/sys/fs/suid_dumpable", StaticFileInode::new(b"0\n") as InodeRef);
}

