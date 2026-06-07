// Syscall entry + dispatch table. Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::{dispatch, SyscallArgs};
use hal::USER_VA_END;
#[cfg(target_arch = "x86_64")]
#[allow(unused_imports)]
use hal::TimerOps;

use crate::s062_kill::sys_kill;
use crate::s234_tgkill::sys_tgkill;

/// PTRACE_SYSCALL self-stop. Snapshots SIGTRAP siginfo (+0x80
/// when PTRACE_O_TRACESYSGOOD), sets SIGTRAP pending, parks.
/// # C: O(1)
fn ptrace_syscall_stop_if_armed() {
    use core::sync::atomic::Ordering;
    let cur = match sched::live::current() { Some(c) => c, None => return };
    if cur.traced_by.load(Ordering::Acquire) == 0 { return; }
    if !cur.ptrace_syscall_armed.swap(false, Ordering::AcqRel) { return; }
    // SIGTRAP siginfo snapshot; O_TRACESYSGOOD marks code with 0x80.
    let opts = cur.ptrace_options.load(Ordering::Acquire);
    let code = if (opts & 0x1) != 0 { 0x80 } else { 0 };
    let tracer = cur.traced_by.load(Ordering::Acquire);
    *cur.ptrace_siginfo.lock() = Some(sched::SigInfo {
        signo: 5, code, pid: tracer, uid: 0, value: 0,
    });
    crate::ptrace_fpu::snapshot_current();
    cur.sigpending.fetch_or(1u64 << 4, Ordering::Release); // SIGTRAP
    // SAFETY: process ctx; runqueue installed; preempt-off; immediate self-park via stop_until_cont matches the SIGSTOP path.
    unsafe { sched::live::stop::stop_until_cont_sig(5); }
    // Wake: SETFPREGS-modified snapshot → restore before returning
    // to user mode so the new state takes effect.
    crate::ptrace_fpu::restore_if_dirty();
}

/// SysV-ABI hook invoked by `oxide_syscall_entry`. Returns u64 in rax.
/// # SAFETY: caller is the syscall asm; single-CPU; IF=0 (FMASK).
/// # C: O(1) + dispatch fn cost
#[no_mangle]
pub unsafe extern "C" fn oxide_syscall_dispatch(
    nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64,
) -> u64 {
    // arm64 uses generic numbering; remap to x86_64 (the table key).
    let orig_nr = nr;
    #[cfg(target_arch = "aarch64")]
    let nr = syscall::arm_abi::aarch64_nr_to_x86(nr);
    debug_ssh! { crate::signal_trace::dispatch_entry(orig_nr, nr); }
    let _ = orig_nr;
    // F206 per-task SVC-frame snapshot; deliver_arm reads via slot.
    #[cfg(target_arch = "aarch64")]
    if let Some(c) = sched::current() {
        c.svc_frame.store(hal_aarch64::current_svc_frame() as u64,
                          core::sync::atomic::Ordering::Release);
    }
    // F205: pull the 6th argument (a5) from the saved frame.
    // SysV C-ABI fits 5 args in regs after nr; a5 comes from the
    // arch's saved-syscall-frame block. See syscall_a5::read().
    // SAFETY: called from the syscall dispatch tail with per-arch save block live.
    let a5 = unsafe { crate::syscall_a5::read() };

    let args = SyscallArgs { a0, a1, a2, a3, a4, a5 };
    debug_syscall! { sched::trace::entry(nr, a0, a1, a2); }
    // seccomp KILL/TRAP/ERRNO/ALLOW filter check.
    if let Err(rv) = security::seccomp::check(nr, &[a0, a1, a2, a3, a4, 0]) { return rv as u64; }
    // F108: PTRACE_SYSCALL — if a tracer armed us, self-stop at entry.
    ptrace_syscall_stop_if_armed();
    // Arch-specific + per-arch-time syscalls handled here (kernel can
    // call hal); others fall through to the arch-neutral dispatch.
    let rv = match nr {
        #[cfg(target_arch = "x86_64")]
        syscall::nrs::NR_ARCH_PRCTL    => crate::s158_arch_prctl::kernel_arch_prctl(&args),
        syscall::nrs::NR_CLOCK_GETTIME => crate::time::kernel_clock_gettime(&args),
        syscall::nrs::NR_CLOCK_GETRES  => crate::time::kernel_clock_getres(&args),
        syscall::nrs::NR_CLOCK_SETTIME => crate::time::kernel_clock_settime(&args),
        syscall::nrs::NR_GETTIMEOFDAY  => crate::time::kernel_gettimeofday(&args),
        syscall::nrs::NR_SETTIMEOFDAY  => crate::time::kernel_settimeofday(&args),
        syscall::nrs::NR_TIME          => crate::time::kernel_time(&args),
        syscall::nrs::NR_UNAME         => crate::uname::kernel_uname(&args),
        syscall::nrs::NR_SETHOSTNAME   => crate::s170_sethostname::sys_sethostname(&args),
        syscall::nrs::NR_SETDOMAINNAME => crate::hostname::sys_setdomainname(&args),
        syscall::nrs::NR_MMAP          => crate::s009_mmap::kernel_mmap(&args),
        syscall::nrs::NR_MUNMAP        => crate::s011_munmap::kernel_munmap(&args),
        syscall::nrs::NR_EXIT          => crate::s060_exit::sys_exit(&args),
        syscall::nrs::NR_GETPID        => crate::s039_getpid::sys_getpid(&args),
        syscall::nrs::NR_GETPPID       => crate::s110_getppid::sys_getppid(&args),
        syscall::nrs::NR_READ          => crate::s000_read::sys_read(&args),
        syscall::nrs::NR_WRITE         => crate::s001_write::sys_write(&args),
        syscall::nrs::NR_OPEN          => crate::s002_open::sys_open(&args),
        syscall::nrs::NR_BRK           => crate::s012_brk::sys_brk(&args),
        syscall::nrs::NR_PIPE2         => crate::s293_pipe2::sys_pipe2(&args),
        syscall::nrs::NR_FSTAT         => crate::s005_fstat::sys_fstat(&args),
        syscall::nrs::NR_IOCTL         => crate::fs::sys_ioctl(&args),
        syscall::nrs::NR_GETCWD        => crate::s079_getcwd::sys_getcwd(&args),
        syscall::nrs::NR_CHDIR         => crate::s080_chdir::sys_chdir(&args),
        syscall::nrs::NR_FCHDIR        => crate::s081_fchdir::sys_fchdir(&args),
        syscall::nrs::NR_KILL          => sys_kill(&args),
        syscall::nrs::NR_TGKILL        => sys_tgkill(&args),
        syscall::nrs::NR_GETRANDOM     => crate::s318_getrandom::sys_getrandom(&args),
        syscall::nrs::NR_SCHED_RR_GET_INTERVAL => crate::s148_sched_rr_get_interval::sys_sched_rr_get_interval(&args),
        syscall::nrs::NR_SCHED_YIELD   => crate::s024_sched_yield::sys_sched_yield(&args),
        syscall::nrs::NR_GETTID        => crate::s186_gettid::sys_gettid(&args),
        syscall::nrs::NR_SET_TID_ADDRESS => crate::s218_set_tid_address::sys_set_tid_address(&args),
        syscall::nrs::NR_WRITEV        => crate::s020_writev::sys_writev(&args),
        syscall::nrs::NR_READV         => crate::s019_readv::sys_readv(&args),
        syscall::nrs::NR_POLL          => crate::fs::sys_poll(&args),
        syscall::nrs::NR_PPOLL         => crate::fs::sys_ppoll(&args),
        syscall::nrs::NR_SELECT        => crate::select::sys_select(&args),
        syscall::nrs::NR_PSELECT6      => crate::select::sys_pselect6(&args),
        syscall::nrs::NR_LSEEK         => crate::s008_lseek::sys_lseek(&args),
        syscall::nrs::NR_READLINK      => crate::s089_readlink::sys_readlink(&args),
        syscall::nrs::NR_READLINKAT    => crate::s267_readlinkat::sys_readlinkat(&args),
        syscall::nrs::NR_STATX         => crate::s332_statx::sys_statx(&args),
        syscall::nrs::NR_NAME_TO_HANDLE_AT => crate::handle::sys_name_to_handle_at(&args),
        syscall::nrs::NR_FCNTL         => crate::s072_fcntl::sys_fcntl(&args),
        syscall::nrs::NR_RSEQ          => crate::proc::sys_rseq(&args),
        syscall::nrs::NR_MEMBARRIER    => crate::s324_membarrier::sys_membarrier(&args),
        syscall::nrs::NR_UNSHARE       => crate::s272_unshare::sys_unshare(&args),
        syscall::nrs::NR_SETNS         => crate::s308_setns::sys_setns(&args),
        syscall::nrs::NR_PTRACE        => crate::ptrace::sys_ptrace(&args),
        syscall::nrs::NR_FANOTIFY_INIT => ::fs::inotify::sys_inotify_init1(&args),
        syscall::nrs::NR_FANOTIFY_MARK => ::fs::inotify::sys_fanotify_mark(&args),
        syscall::nrs::NR_SHMGET        => ipc::sysv_shm::sys_shmget(&args),
        syscall::nrs::NR_SHMAT         => ipc::sysv_shm::sys_shmat(&args),
        syscall::nrs::NR_SHMDT         => ipc::sysv_shm::sys_shmdt(&args),
        syscall::nrs::NR_SHMCTL        => ipc::sysv_shm::sys_shmctl(&args),
        syscall::nrs::NR_SEMGET        => ::ipc::live::sysv_sem::sys_semget(&args),
        syscall::nrs::NR_SEMOP         => ::ipc::live::sysv_sem::sys_semop(&args),
        syscall::nrs::NR_SEMCTL        => ::ipc::live::sysv_sem::sys_semctl(&args),
        syscall::nrs::NR_SEMTIMEDOP    => ::ipc::live::sysv_sem::sys_semtimedop(&args),
        syscall::nrs::NR_MSGGET        => ::ipc::live::sysv_msg::sys_msgget(&args),
        syscall::nrs::NR_MSGSND        => ::ipc::live::sysv_msg::sys_msgsnd(&args),
        syscall::nrs::NR_MSGRCV        => ::ipc::live::sysv_msg::sys_msgrcv(&args),
        syscall::nrs::NR_MSGCTL        => ::ipc::live::sysv_msg::sys_msgctl(&args),
        syscall::nrs::NR_MQ_OPEN         => ::ipc::live::posix_mq::sys_mq_open(&args),
        syscall::nrs::NR_MQ_UNLINK       => ::ipc::live::posix_mq::sys_mq_unlink(&args),
        syscall::nrs::NR_MQ_TIMEDSEND    => ::ipc::live::posix_mq::sys_mq_timedsend(&args),
        syscall::nrs::NR_MQ_TIMEDRECEIVE => ::ipc::live::posix_mq::sys_mq_timedreceive(&args),
        syscall::nrs::NR_IO_URING_SETUP    => crate::io_uring::sys_io_uring_setup(&args),
        syscall::nrs::NR_IO_URING_ENTER    => crate::io_uring::sys_io_uring_enter(&args),
        syscall::nrs::NR_IO_URING_REGISTER => crate::io_uring::sys_io_uring_register(&args),
        syscall::nrs::NR_SECCOMP       => security::seccomp::sys_seccomp(&args),
        // bpf(cmd, attr, size): admit fd-creating commands (BPF_PROG_LOAD,
        // BPF_MAP_CREATE) by returning a sentinel fd backed by an
        // anonymous tmpfs inode. v1 doesn't run loaded BPF programs;
        // verifier + JIT ride a follow-up. Other cmds → -ENOSYS so
        // userspace doesn't think it has a working bpf() world.
        syscall::nrs::NR_BPF           => security::bpf::sys_bpf(&args),
        syscall::nrs::NR_LANDLOCK_CREATE_RULESET => crate::landlock::sys_landlock_create_ruleset(&args),
        syscall::nrs::NR_LANDLOCK_ADD_RULE       => crate::landlock::sys_landlock_add_rule(&args),
        syscall::nrs::NR_LANDLOCK_RESTRICT_SELF  => crate::landlock::sys_landlock_restrict_self(&args),
        // perf_event_open: real PerfEventInode whose read returns the
        // monotonic-ns sample since open; ioctl handles ENABLE/DISABLE/
        // RESET/REFRESH. PMU hardware sampling + ring-buffer mmap
        // ride follow-ups.
        syscall::nrs::NR_PERF_EVENT_OPEN => ::fs::perf::sys_perf_event_open(&args),
        syscall::nrs::NR_USERFAULTFD => ::fs::userfaultfd::sys_userfaultfd(&args),
        // Modern mount API (P29a). fsopen/fsmount/fspick/open_tree return
        // memfd-backed fds tagged with the call's identity for future
        // mount-table integration; fsconfig/move_mount/mount_setattr admit
        // (real per-NS mount-table machinery rides a follow-up).
        // New mount API (K6) — all real now.
        syscall::nrs::NR_FSOPEN        => crate::s430_fsopen::sys_fsopen(&args),
        syscall::nrs::NR_FSCONFIG      => crate::s431_fsconfig::sys_fsconfig(&args),
        syscall::nrs::NR_FSMOUNT       => crate::s432_fsmount::sys_fsmount(&args),
        syscall::nrs::NR_MOVE_MOUNT    => crate::s429_move_mount::sys_move_mount(&args),
        syscall::nrs::NR_FSPICK        => crate::s433_fspick::sys_fspick(&args),
        syscall::nrs::NR_OPEN_TREE     => crate::s428_open_tree::sys_open_tree(&args),
        syscall::nrs::NR_MOUNT_SETATTR => crate::s442_mount_setattr::sys_mount_setattr(&args),
        syscall::nrs::NR_GETRLIMIT     => crate::s097_getrlimit::sys_getrlimit(&args),
        syscall::nrs::NR_SETRLIMIT     => crate::s160_setrlimit::sys_setrlimit(&args),
        syscall::nrs::NR_GETRUSAGE     => crate::s098_getrusage::sys_getrusage(&args),
        syscall::nrs::NR_TIMES         => crate::s100_times::sys_times(&args),
        syscall::nrs::NR_SYSINFO       => crate::s099_sysinfo::sys_sysinfo(&args),
        syscall::nrs::NR_MREMAP        => crate::s025_mremap::sys_mremap(&args),
        syscall::nrs::NR_MSYNC         => crate::s026_msync::sys_msync(&args),
        syscall::nrs::NR_MINCORE       => crate::s027_mincore::sys_mincore(&args),
        syscall::nrs::NR_MLOCK | syscall::nrs::NR_MUNLOCK | syscall::nrs::NR_MLOCKALL | syscall::nrs::NR_MUNLOCKALL
                                 => crate::s149_mlock_family::sys_mlock_family(&args),
        syscall::nrs::NR_GETPGRP   => crate::s111_getpgrp::sys_getpgrp(&args),
        syscall::nrs::NR_GETPRIORITY => crate::proc::sys_getpriority(&args),
        syscall::nrs::NR_SETPRIORITY => crate::proc::sys_setpriority(&args),
        syscall::nrs::NR_ALARM     => crate::s037_alarm::sys_alarm(&args),
        syscall::nrs::NR_PAUSE     => crate::s034_pause::sys_pause(&args),
        syscall::nrs::NR_GETITIMER => crate::s036_getitimer::sys_getitimer(&args),
        syscall::nrs::NR_SETITIMER => crate::s038_setitimer::sys_setitimer(&args),
        syscall::nrs::NR_PIDFD_OPEN  => crate::pidfd::sys_pidfd_open(&args),
        syscall::nrs::NR_PIDFD_GETFD => crate::pidfd::sys_pidfd_getfd(&args),
        syscall::nrs::NR_PIDFD_SEND_SIGNAL
                                 => crate::pidfd::sys_pidfd_send_signal(&args),
        syscall::nrs::NR_INOTIFY_INIT | syscall::nrs::NR_INOTIFY_INIT1
                                 => ::fs::inotify::sys_inotify_init1(&args),
        syscall::nrs::NR_INOTIFY_ADD_WATCH
                                 => ::fs::inotify::sys_inotify_add_watch(&args),
        syscall::nrs::NR_INOTIFY_RM_WATCH
                                 => ::fs::inotify::sys_inotify_rm_watch(&args),
        syscall::nrs::NR_SIGNALFD | syscall::nrs::NR_SIGNALFD4
                                 => ::fs::signalfd::sys_signalfd4(&args),
        syscall::nrs::NR_TIMERFD_CREATE
                                 => ::fs::timerfd::sys_timerfd_create(&args),
        syscall::nrs::NR_TIMERFD_SETTIME
                                 => ::fs::timerfd::sys_timerfd_settime(&args),
        syscall::nrs::NR_TIMERFD_GETTIME
                                 => ::fs::timerfd::sys_timerfd_gettime(&args),
        syscall::nrs::NR_EPOLL_CREATE | syscall::nrs::NR_EPOLL_CREATE1
                                 => ::fs::epoll::sys_epoll_create1(&args),
        syscall::nrs::NR_EPOLL_CTL
                                 => ::fs::epoll::sys_epoll_ctl(&args),
        syscall::nrs::NR_EPOLL_WAIT | syscall::nrs::NR_EPOLL_PWAIT
            | syscall::nrs::NR_EPOLL_PWAIT2
                                 => ::fs::epoll::sys_epoll_wait(&args),
        syscall::nrs::NR_GETPGID   => crate::s121_getpgid::sys_getpgid(&args),
        syscall::nrs::NR_GETSID    => crate::s124_getsid::sys_getsid(&args),
        syscall::nrs::NR_SETPGID       => crate::s109_setpgid::sys_setpgid(&args),
        syscall::nrs::NR_SETSID        => crate::s112_setsid::sys_setsid(&args),
        syscall::nrs::NR_UMASK         => crate::s095_umask::sys_umask(&args),
        syscall::nrs::NR_ACCESS        => crate::fs_access::sys_access(&args),
        syscall::nrs::NR_FACCESSAT     => crate::fs_access::sys_faccessat(&args),
        syscall::nrs::NR_EVENTFD | syscall::nrs::NR_EVENTFD2
                                 => crate::anonfd::sys_eventfd2(&args),
        syscall::nrs::NR_GETDENTS | syscall::nrs::NR_GETDENTS64
                                 => crate::s217_getdents64::sys_getdents64(&args),
        syscall::nrs::NR_PREAD64       => crate::s017_pread64::sys_pread64(&args),
        syscall::nrs::NR_PWRITE64      => crate::s018_pwrite64::sys_pwrite64(&args),
        syscall::nrs::NR_PREADV  => crate::s295_preadv::sys_preadv(&args),
        syscall::nrs::NR_PWRITEV => crate::s296_pwritev::sys_pwritev(&args),
        syscall::nrs::NR_PREADV2 => crate::s295_preadv::sys_preadv(&args),
        syscall::nrs::NR_PWRITEV2 => crate::s296_pwritev::sys_pwritev(&args),
        syscall::nrs::NR_MEMFD_CREATE => crate::anonfd::sys_memfd_create(&args),
        // memfd_secret(flags) — Linux's "hide from other tasks via
        // page-table partitioning" variant. v1 single-AS scheduler
        // doesn't enforce that hide; we route through memfd_create
        // so the fd is at least functional.
        syscall::nrs::NR_MEMFD_SECRET => {
            let mut sa = args; sa.a0 = 0; sa.a1 = args.a0;
            crate::anonfd::sys_memfd_create(&sa)
        }
        syscall::nrs::NR_MKDIR    => crate::s083_mkdir::sys_mkdir(&args),
        syscall::nrs::NR_MKDIRAT  => crate::s258_mkdirat::sys_mkdirat(&args),
        syscall::nrs::NR_RMDIR    => crate::s084_rmdir::sys_rmdir(&args),
        syscall::nrs::NR_UNLINK   => crate::s087_unlink::sys_unlink(&args),
        syscall::nrs::NR_UNLINKAT => crate::s263_unlinkat::sys_unlinkat(&args),
        syscall::nrs::NR_RENAME   => crate::s082_rename::sys_rename(&args),
        syscall::nrs::NR_RENAMEAT => crate::s264_renameat::sys_renameat(&args),
        syscall::nrs::NR_RENAMEAT2 => crate::s316_renameat2::sys_renameat2(&args),
        syscall::nrs::NR_TRUNCATE  => crate::s076_truncate::sys_truncate(&args),
        syscall::nrs::NR_FTRUNCATE => crate::s077_ftruncate::sys_ftruncate(&args),
        syscall::nrs::NR_FALLOCATE => sched::falloc::sys_fallocate(&args),
        syscall::nrs::NR_SENDFILE  => sched::xfer::sys_sendfile(&args),
        syscall::nrs::NR_COPY_FILE_RANGE => sched::xfer::sys_copy_file_range(&args),
        syscall::nrs::NR_SPLICE     => sched::xfer::sys_splice(&args),
        syscall::nrs::NR_TEE        => sched::xfer::sys_tee(&args),
        syscall::nrs::NR_VMSPLICE   => sched::xfer::sys_vmsplice(&args),
        syscall::nrs::NR_OPENAT        => crate::s257_openat::sys_openat(&args),
        // openat2: read flags+mode from open_how, route through openat.
        syscall::nrs::NR_OPENAT2       => {
            let how = args.a2;
            let mut sa = args; sa.a2 = 0;
            if how != 0 && how < USER_VA_END {
                // SAFETY: how validated < USER_VA_END; struct open_how
                // first u64 = flags, second = mode; CPL=0 reads.
                unsafe {
                    sa.a2 = core::ptr::read_volatile(how as *const u64);
                    sa.a3 = core::ptr::read_volatile((how + 8) as *const u64);
                }
            }
            crate::s257_openat::sys_openat(&sa)
        }
        syscall::nrs::NR_FACCESSAT2    => crate::fs_access::sys_faccessat(&args),
        syscall::nrs::NR_SYNC => 0,
        syscall::nrs::NR_REBOOT => crate::misc::sys_reboot(&args),
        nr if matches!(nr, syscall::nrs::NR_FSYNC | syscall::nrs::NR_FDATASYNC
                       | syscall::nrs::NR_SYNCFS | syscall::nrs::NR_SYNC_FILE_RANGE)
                                 => crate::misc::sys_fsync(&args),
        nr if matches!(nr, syscall::nrs::NR_PKEY_ALLOC | syscall::nrs::NR_PKEY_FREE
                       | syscall::nrs::NR_PKEY_MPROTECT | syscall::nrs::NR_KCMP
                       | syscall::nrs::NR_SET_MEMPOLICY | syscall::nrs::NR_GET_MEMPOLICY
                       | syscall::nrs::NR_MBIND | syscall::nrs::NR_SET_MEMPOLICY_HOME_NODE
                       | syscall::nrs::NR_MIGRATE_PAGES | syscall::nrs::NR_MOVE_PAGES
                       | syscall::nrs::NR_PROCESS_MADVISE | syscall::nrs::NR_PROCESS_MRELEASE)
                                 => crate::misc::dispatch(nr, &args),
        // AF_INET dgram (UDP) per `25§3`.
        syscall::nrs::NR_SOCKET   => crate::s041_socket::sys_socket(&args),
        syscall::nrs::NR_BIND     => crate::s049_bind::sys_bind(&args),
        syscall::nrs::NR_SENDTO   => crate::s044_sendto::sys_sendto(&args),
        syscall::nrs::NR_RECVFROM => crate::net_recv::sys_recvfrom(&args),
        syscall::nrs::NR_LISTEN  => crate::s050_listen::sys_listen(&args),
        syscall::nrs::NR_ACCEPT | syscall::nrs::NR_ACCEPT4
                                       => crate::s043_accept::sys_accept(&args),
        syscall::nrs::NR_CONNECT => crate::s042_connect::sys_connect(&args),
        syscall::nrs::NR_SOCKETPAIR => crate::s053_socketpair::sys_socketpair(&args),
        syscall::nrs::NR_GETSOCKNAME => crate::s051_getsockname::sys_getsockname(&args),
        syscall::nrs::NR_GETPEERNAME => crate::s052_getpeername::sys_getpeername(&args),
        syscall::nrs::NR_SHUTDOWN    => crate::s048_shutdown::sys_shutdown(&args),
        syscall::nrs::NR_SETSOCKOPT  => crate::s054_setsockopt::sys_setsockopt(&args),
        syscall::nrs::NR_GETSOCKOPT  => crate::s055_getsockopt::sys_getsockopt(&args),
        syscall::nrs::NR_SENDMSG => crate::s046_sendmsg::sys_sendmsg(&args),
        syscall::nrs::NR_RECVMSG => crate::s047_recvmsg::sys_recvmsg(&args),
        syscall::nrs::NR_SENDMMSG => crate::net::sys_sendmmsg(&args),
        syscall::nrs::NR_RECVMMSG => crate::net::sys_recvmmsg(&args),
        syscall::nrs::NR_FLOCK         => ::fs::flock::sys_flock(&args),
        syscall::nrs::NR_PERSONALITY   => sched::prctl::sys_personality(&args),
        syscall::nrs::NR_CHROOT  => crate::chroot::sys_chroot(&args),
        syscall::nrs::NR_MOUNT   => crate::mount::sys_mount(&args),
        syscall::nrs::NR_UMOUNT2 => crate::mount::sys_umount2(&args),
        syscall::nrs::NR_PIVOT_ROOT => crate::mount::sys_pivot_root(&args),
        syscall::nrs::NR_GET_MEMPOLICY => syscall::numa::sys_get_mempolicy(&args),
        syscall::nrs::NR_VHANGUP       => crate::s153_vhangup::sys_vhangup(&args),
        syscall::nrs::NR_FUTIMESAT | syscall::nrs::NR_UTIMENSAT => crate::utime::sys_utimensat(&args),
        syscall::nrs::NR_MQ_NOTIFY     => ::ipc::live::posix_mq::sys_mq_notify(&args),
        syscall::nrs::NR_MQ_GETSETATTR => ::ipc::live::posix_mq::sys_mq_getsetattr(&args),
        syscall::nrs::NR_PROCESS_VM_READV  => crate::pvmrw::sys_process_vm_readv(&args),
        syscall::nrs::NR_PROCESS_VM_WRITEV => crate::pvmrw::sys_process_vm_writev(&args),
        syscall::nrs::NR_UTIMES | syscall::nrs::NR_UTIME
            => crate::utime::sys_utime_dispatch(nr, &args),
        // link/symlink/mknod family.
        syscall::nrs::NR_LINK     => crate::s086_link::sys_link(&args),
        syscall::nrs::NR_LINKAT   => crate::s265_linkat::sys_linkat(&args),
        syscall::nrs::NR_SYMLINK  => crate::s088_symlink::sys_symlink(&args),
        syscall::nrs::NR_SYMLINKAT=> crate::s266_symlinkat::sys_symlinkat(&args),
        syscall::nrs::NR_MKNOD    => crate::s133_mknod::sys_mknod(&args),
        syscall::nrs::NR_MKNODAT  => crate::s259_mknodat::sys_mknodat(&args),
        syscall::nrs::NR_STATFS  => crate::statfs::sys_statfs(&args),
        syscall::nrs::NR_FSTATFS => crate::statfs::sys_fstatfs(&args),
        syscall::nrs::NR_GETCPU        => crate::s309_getcpu::sys_getcpu(&args),
        syscall::nrs::NR_SCHED_GETPARAM => crate::s143_sched_getparam::sys_sched_getparam(&args),
        syscall::nrs::NR_SCHED_SETSCHEDULER | syscall::nrs::NR_SCHED_GETSCHEDULER
                                 => crate::s145_sched_getscheduler::sys_sched_getscheduler(&args),
        syscall::nrs::NR_SCHED_GET_PRIORITY_MAX
                                 => crate::s146_sched_get_priority_max::sys_sched_get_priority_max(&args),
        syscall::nrs::NR_SCHED_GET_PRIORITY_MIN
                                 => crate::s147_sched_get_priority_min::sys_sched_get_priority_min(&args),
        syscall::nrs::NR_SCHED_GETAFFINITY
                                 => crate::affinity::sys_sched_getaffinity(&args),
        syscall::nrs::NR_SCHED_SETAFFINITY
                                 => crate::affinity::sys_sched_setaffinity(&args),
        syscall::nrs::NR_PRCTL         => sched::prctl::sys_prctl(&args),
        syscall::nrs::NR_FUTEX         => crate::s202_futex::sys_futex(&args),
        syscall::nrs::NR_FUTEX_WAITV   => crate::futex_waitv::sys_futex_waitv(&args),
        syscall::nrs::NR_CLONE3        => crate::s435_clone3::sys_clone3(&args),
        syscall::nrs::NR_MPROTECT      => crate::s010_mprotect::sys_mprotect(&args),
        syscall::nrs::NR_MADVISE       => crate::s028_madvise::sys_madvise(&args),
        syscall::nrs::NR_PRLIMIT64     => crate::s302_prlimit64::sys_prlimit64(&args),
        syscall::nrs::NR_RT_SIGACTION  => crate::s013_rt_sigaction::sys_rt_sigaction(&args),
        syscall::nrs::NR_RT_SIGPROCMASK => crate::s014_rt_sigprocmask::sys_rt_sigprocmask(&args),
        syscall::nrs::NR_SIGALTSTACK   => crate::s131_sigaltstack::sys_sigaltstack(&args),
        syscall::nrs::NR_NANOSLEEP     => crate::s035_nanosleep::sys_nanosleep(&args),
        syscall::nrs::NR_CLOCK_NANOSLEEP => crate::proc::sys_clock_nanosleep(&args),
        syscall::nrs::NR_CLOSE         => crate::s003_close::sys_close(&args),
        syscall::nrs::NR_CLOSE_RANGE   => crate::s436_close_range::sys_close_range(&args),
        syscall::nrs::NR_DUP           => crate::s032_dup::sys_dup(&args),
        syscall::nrs::NR_DUP2          => crate::s033_dup2::sys_dup2(&args),
        syscall::nrs::NR_DUP3          => crate::s292_dup3::sys_dup3(&args),
        syscall::nrs::NR_FORK          => crate::clone::sys_clone_dispatch(&args, 0x11 /* SIGCHLD */, 0, 0, 0, 0),
        syscall::nrs::NR_VFORK         => crate::clone::sys_clone_dispatch(&args, 0x4111 /* CLONE_VM|CLONE_VFORK|SIGCHLD */, 0, 0, 0, 0),
        // Linux x86_64 clone(flags, child_stack, ptid, ctid, tls).
        syscall::nrs::NR_CLONE         => crate::clone::sys_clone_dispatch(&args, args.a0, args.a1, args.a2, args.a3, args.a4),
        syscall::nrs::NR_EXECVE        => crate::execve::sys_execve(&args),
        // execveat(dirfd, path, argv, envp, flags) honors AT_EMPTY_PATH
        // — fexecve(3) maps to execveat(fd, "", AT_EMPTY_PATH).
        syscall::nrs::NR_EXECVEAT      => crate::execve::sys_execveat(&args),
        syscall::nrs::NR_WAIT4         => crate::wait::sys_wait4(&args),
        syscall::nrs::NR_WAITID        => crate::waitid::sys_waitid(&args),
        syscall::nrs::NR_TKILL         => sys_kill(&args),
        syscall::nrs::NR_RT_SIGPENDING => crate::s127_rt_sigpending::sys_rt_sigpending(&args),
        syscall::nrs::NR_RT_SIGSUSPEND => crate::s130_rt_sigsuspend::sys_rt_sigsuspend(&args),
        syscall::nrs::NR_RT_SIGTIMEDWAIT  => crate::s128_rt_sigtimedwait::sys_rt_sigtimedwait(&args),
        syscall::nrs::NR_RT_SIGQUEUEINFO  => crate::s129_rt_sigqueueinfo::sys_rt_sigqueueinfo(&args),
        syscall::nrs::NR_RT_TGSIGQUEUEINFO => crate::s297_rt_tgsigqueueinfo::sys_rt_tgsigqueueinfo(&args),
        // Real-impl arms that overlap with compat-stub categories.
        syscall::nrs::NR_PIPE          => {
            // pipe(int[2]) — legacy, no flag argument. Mask args.a1 so
            // stale register contents from the calling frame don't
            // accidentally enable O_NONBLOCK / O_CLOEXEC on the new
            // pipe ends. Without this, sh's `cmd | head -10` was
            // hitting EAGAIN because pipe(2) read flags off uninit r1.
            let mut a = args;
            a.a1 = 0;
            crate::s293_pipe2::sys_pipe2(&a)
        }
        syscall::nrs::NR_CREAT         => crate::s002_open::sys_open(&args),
        syscall::nrs::NR_EXIT_GROUP    => crate::s060_exit::sys_exit(&args),
        syscall::nrs::NR_INIT_MODULE   => crate::s175_init_module::sys_init_module(&args),
        syscall::nrs::NR_FINIT_MODULE  => crate::s313_finit_module::sys_finit_module(&args),
        syscall::nrs::NR_DELETE_MODULE => crate::s176_delete_module::sys_delete_module(&args),
        syscall::nrs::NR_NEWFSTATAT    => crate::fs::sys_newfstatat(&args),
        syscall::nrs::NR_STAT          => crate::s004_stat::sys_stat(&args),
        syscall::nrs::NR_LSTAT         => crate::s006_lstat::sys_lstat(&args),
        // Cred family: dispatched via sched::cred::cred_dispatch.
        // Handled in the fallthrough below to keep this match arm small.
        syscall::nrs::NR_SET_ROBUST_LIST => crate::s273_set_robust_list::sys_set_robust_list(&args),
        syscall::nrs::NR_GET_ROBUST_LIST => crate::s274_get_robust_list::sys_get_robust_list(&args),
        syscall::nrs::NR_FCHMODAT2       => crate::s452_fchmodat2::sys_fchmodat2(&args),
        syscall::nrs::NR_MSEAL           => crate::s462_mseal::sys_mseal(&args),
        syscall::nrs::NR_IOPRIO_SET      => crate::s251_ioprio_set::sys_ioprio_set(&args),
        syscall::nrs::NR_IOPRIO_GET      => crate::s252_ioprio_get::sys_ioprio_get(&args),
        syscall::nrs::NR_SCHED_GETATTR   => crate::s315_sched_getattr::sys_sched_getattr(&args),
        syscall::nrs::NR_LSM_GET_SELF_ATTR => crate::s459_lsm_get::sys_lsm_get_self_attr(&args),
        syscall::nrs::NR_LSM_SET_SELF_ATTR => crate::s460_lsm_set::sys_lsm_set_self_attr(&args),
        syscall::nrs::NR_LSM_LIST_MODULES  => crate::s461_lsm_list::sys_lsm_list_modules(&args),
        syscall::nrs::NR_FUTEX_WAKE       => crate::s454_futex_wake::sys_futex_wake(&args),
        syscall::nrs::NR_FUTEX_WAIT       => crate::s455_futex_wait::sys_futex_wait(&args),
        syscall::nrs::NR_SETXATTRAT      => crate::s463_setxattrat::sys_setxattrat(&args),
        syscall::nrs::NR_GETXATTRAT      => crate::s464_getxattrat::sys_getxattrat(&args),
        syscall::nrs::NR_LISTXATTRAT     => crate::s465_listxattrat::sys_listxattrat(&args),
        syscall::nrs::NR_REMOVEXATTRAT   => crate::s466_removexattrat::sys_removexattrat(&args),
        syscall::nrs::NR_FUTEX_REQUEUE    => crate::s456_futex_requeue::sys_futex_requeue(&args),
        syscall::nrs::NR_STATMOUNT        => crate::s457_statmount::sys_statmount(&args),
        syscall::nrs::NR_LISTMOUNT        => crate::s458_listmount::sys_listmount(&args),
        syscall::nrs::NR_FILE_GETATTR     => crate::s468_file_getattr::sys_file_getattr(&args),
        syscall::nrs::NR_FILE_SETATTR     => crate::s469_file_setattr::sys_file_setattr(&args),
        syscall::nrs::NR_RSEQ_SLICE_YIELD => crate::s471_rseq_slice_yield::sys_rseq_slice_yield(&args),
        syscall::nrs::NR_SCHED_SETPARAM   => crate::s142_sched_setparam::sys_sched_setparam(&args),
        syscall::nrs::NR_SCHED_SETATTR    => crate::s314_sched_setattr::sys_sched_setattr(&args),
        syscall::nrs::NR_OPEN_TREE_ATTR   => crate::s467_open_tree_attr::sys_open_tree_attr(&args),
        syscall::nrs::NR_SYSLOG          => syscall::dmesg::sys_syslog(&args),
        // OBSOLETE (docs/15 §2): Linux x86_64 itself ENOSYS's these reserved numbers — deliberate enosys, not accidental fall-through.
        n if crate::misc::is_obsolete(n) => -(syscall::errno::Errno::Enosys.as_i32() as i64),
        // SAFETY: dispatch tail runs on cur's per-task syscall/SVC stack; the per-arch saved frame is live; ::fs::sig_dispatch::rt_sigreturn dispatches to the matching x86/arm helper which only reads/writes saved-frame slots and user-stack frame the dispatcher previously installed via `deliver`.
        syscall::nrs::NR_RT_SIGRETURN  => unsafe { ::fs::sig_dispatch::rt_sigreturn() },
        // Compat-stub fall-through table per P3-46.
        _ => {
            if let Some(rv) = sched::cred::cred_dispatch(nr, &args) {
                rv
            } else if let Some(rv) = sched::timers::timer_dispatch(nr, &args) {
                rv
            } else if let Some(rv) = crate::perms::perms_dispatch(nr, &args) {
                rv
            } else if let Some(rv) = ::fs::xattr::xattr_dispatch(nr, &args) { rv }
            else if let Some(rv) = ::fs::keyring::keyring_dispatch(nr, &args) {
                rv
            } else if let Some(rv) = sched::compat::try_compat(nr, &args) {
                rv
            } else {
                dispatch(nr as u32, &args)
            }
        }
    };
    debug_sched! {
        klog::write_raw(b"[INFO]  syscall: nr=");
        klog::write_hex_u64(nr);
        klog::write_raw(b" rv=");
        klog::write_hex_u64(rv as u64);
        klog::write_raw(b"\n");
    }
    debug_ssh! { crate::signal_trace::syscall_nr_rv(nr, rv); }
    // POSIX timers + rseq cpu_id writeback at syscall-return tail.
    sched::timers::fire_due_timers();
    crate::proc::rseq_writeback();
    // F108: PTRACE_SYSCALL exit-stop, symmetric with the entry-stop above.
    ptrace_syscall_stop_if_armed();
    // alarm(2) deadline check: post SIGALRM if alarm_ns has passed.
    // Low-latency path for the running task; tasks parked in a blocking
    // syscall are serviced by tick_wake_expired (B20). Both paths are
    // idempotent (one-shot stores 0; interval stores now+interval).
    if let Some(cur) = sched::live::current() {
        use core::sync::atomic::Ordering;
        use sched::live::sigpend::Signum;
        let deadline = cur.alarm_ns.load(Ordering::Acquire);
        if deadline != 0 {
            #[cfg(target_arch = "x86_64")]
            let now = { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 };
            #[cfg(target_arch = "aarch64")]
            let now = { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 };
            if now >= deadline {
                let interval = cur.alarm_interval_ns.load(Ordering::Acquire);
                cur.alarm_ns.store(
                    if interval != 0 { now.saturating_add(interval) } else { 0 },
                    Ordering::Release,
                );
                cur.sigpending.fetch_or(Signum::Sigalrm.bit(), Ordering::Release);
            }
        }
    }
    // P4-02: syscall-return preempt point per `13§9`. If the tick or
    // a wakeup set need_resched while we were in the kernel, and we
    // hold no preempt_count locks, voluntarily schedule before
    // returning to user. Signal delivery follows so the user sees
    // pending signals after the resched has run.
    if sched::preempt::preempt_count() == 0 && sched::preempt::take_need_resched() {
        // SAFETY: we are at syscall-return tail, IRQs unmasked, no
        // spinlocks held; matches schedule()'s `# Ctx: process|kthread`
        // requirement per `13§8`.
        unsafe { sched::live::schedule(); }
    }
    // P3-65: deliver pending signals at syscall return.
    if let Some(p) = crate::signal::take_lowest_pending() {
        debug_ssh! { crate::signal_trace::deliver_taken(&p); }
        // Job-control signals come first — their default action is
        // stop / continue, not terminate, regardless of handler.
        // SIGSTOP (19) is uncatchable per signal(7); the others (TSTP
        // 20, TTIN 21, TTOU 22) honour a user handler.
        if matches!(p.sig, 19) || (matches!(p.sig, 20 | 21 | 22) && p.handler == 0) {
            sched::live::stop::stop_until_cont_sig(p.sig as u8);
            return rv as u64;
        }
        // SAFETY: dispatch tail; per-arch saved frame is live; the
        // helper writes only the saved-frame and user signal stack.
        let sig_rv = unsafe { crate::signal_dispatch::dispatch_pending(&p, rv as u64, &|sa| crate::s060_exit::sys_exit(sa)) };
        // aarch64: SVC restore clobbers user x0 with dispatcher retval
        // — return `sig` so it seeds handler arg0. x86 injects via rdi.
        if sig_rv != 0 { return sig_rv; }
    } else {
        debug_ssh! { crate::signal_trace::deliver_blocked(); }
    }
    rv as u64
}
