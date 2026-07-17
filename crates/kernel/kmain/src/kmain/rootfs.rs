use alloc::sync::Arc;

use crate::BootInfo;

/// Rootfs, mount graph, keymap, and first-userspace handoff.
/// # SAFETY: caller must satisfy `kernel_main` boot-entry contract.
/// # C: not measured (one-shot init)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn init(info: &BootInfo) {
    #[cfg(target_arch = "x86_64")]
    unsafe { hal_x86_64::mmu_ops::resync_kernel_master(); }

    unsafe {
        // Serialize ext4 metadata transactions per-task: the reentrant txn gate
        // keys ownership on the current task id so concurrent tasks/CPUs can't
        // race the group bitmaps/GDT/counters (was corrupting the on-disk fs:
        // group-bitmap csum mismatches + unattached inodes). Registered before
        // the first mount so every ext4 op is serialized.
        ext4::mount::set_ctx_id_hook(|| sched::current().map(|t| t.tid as u64).unwrap_or(0));
        // A gate waiter must YIELD (not busy-spin): the owner sleeps on block I/O
        // while holding the gate. tick_yield reschedules + opens the IRQ window so
        // the owner's completion lands and it can release. Without this the boot
        // deadlocks in truncate_inode (CPU-STALL, nr_running=1).
        ext4::mount::set_yield_hook(|| unsafe { sched::live::tick_yield() });
        let root_dev = block::registry::by_serial("oxide-root")
            .or_else(block::registry::first_device)
            .expect("root disk (virtio-blk serial=oxide-root) not found");
        ext4::rootfs::init_from_dev(root_dev)
            .expect("ext4 root mount (oxide-root) failed to open");
        net::sock::init();
        install_network_hooks();
        net::sock::set_iface_primary_ip_hook(crate::syscalls::siocgif::iface_primary_ip_hook);
        modules::linux_time::set_now_hook(module_time_now_ns);
        modules::registry::init_exports();
        crate::syscalls::mount::install_vfs_hooks();
        crate::syscalls::ensure_mount_filesystems_registered();
        if let Some(ext4_ty) = vfs::fs::get_fs_type("ext4") {
            let _ = vfs::mount::register_typed(ext4_ty, None, Arc::new(ext4::rootfs::Ext4RootfsFs));
        }
        boot_register("devtmpfs", "/dev",  Arc::new(::devfs::DevfsFs));
        boot_register("proc",     "/proc", Arc::new(procfs::fs_impl::ProcfsFs));
        boot_register("sysfs",    "/sys",  Arc::new(crate::sysfs::SysfsFs));
        boot_register_cgroup();
        let tmp = fs::tmpfs::TmpfsFs::new(alloc::string::String::from("/tmp"));
        let tmp_root = tmp.root_inode();
        boot_register_bind("tmpfs", "/tmp", tmp, tmp_root);
        let shm = fs::tmpfs::TmpfsFs::new(alloc::string::String::from("/dev/shm"));
        let shm_root = shm.root_inode();
        boot_register_bind("tmpfs", "/dev/shm", shm, shm_root);
        let run = fs::tmpfs::TmpfsFs::new(alloc::string::String::from("/run"));
        let run_root = run.root_inode();
        boot_register_bind("tmpfs", "/run", run, run_root);
        if let Some(home_dev) = block::registry::by_serial("oxide-home") {
            if let Ok(home_fs) = ext4::rootfs::Ext4Mount::open(home_dev) {
                boot_register("ext4", "/home", home_fs);
            }
        }
        debug_cgroup! { cgroup::selftest::run(); }
    }

    log_dev_null_owner();
    debug_boot_rootfs();
    load_keymap();
    handoff_to_userspace(info);
}

#[cfg(target_os = "oxide-kernel")]
fn log_dev_null_owner() {
    match vfs::resolve_abs("/dev/null") {
        Ok(inode) => {
            klog::write_raw(b"[BOOT-DEV-NULL] type=");
            klog::write_dec_u64(inode.file_type().to_ifmt() as u64);
            klog::write_raw(b" fs=");
            if let Some(sb) = inode.i_sb() { klog::write_raw(sb.s_type.name().as_bytes()); }
            else { klog::write_raw(b"none"); }
            klog::write_raw(b"\n");
        }
        Err(e) => {
            klog::write_raw(b"[BOOT-DEV-NULL] lookup-errno=");
            klog::write_dec_u64(e as u64);
            klog::write_raw(b"\n");
        }
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn module_time_now_ns() -> u64 {
    use hal::TimerOps;
    hal_x86_64::X86TimerOps::monotonic_ns().0
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn module_time_now_ns() -> u64 {
    use hal::TimerOps;
    hal_aarch64::ArmTimerOps::monotonic_ns().0
}

#[cfg(target_os = "oxide-kernel")]
fn debug_boot_rootfs() {
    debug_boot! {
        klog::write_raw(b"[INFO]  ext4: mounted=");
        klog::write_dec_u64(ext4::rootfs::mounted() as u64);
        klog::write_raw(b"\n");
        for path in [&b"/hello.txt"[..], &b"/etc/issue"[..]] {
            if let Some(bytes) = ext4::rootfs::read_file(path) {
                klog::write_raw(b"[INFO]  ext4 ");
                klog::write_raw(path);
                klog::write_raw(b" = ");
                klog::write_raw(&bytes);
                if !bytes.ends_with(b"\n") { klog::write_raw(b"\n"); }
            }
        }
        if ext4::rootfs::write_file(b"/hello.txt", b"WRITTEN-BY-OXIDE\n").is_some() {
            if let Some(bytes) = ext4::rootfs::read_file(b"/hello.txt") {
                klog::write_raw(b"[INFO]  ext4 RW smoke /hello.txt = ");
                klog::write_raw(&bytes);
                if !bytes.ends_with(b"\n") { klog::write_raw(b"\n"); }
            }
        }
        if let Some(bytes) = ext4::rootfs::read_file(b"/bin/sh") {
            klog::write_raw(b"[INFO]  ext4 /bin/sh size=");
            klog::write_dec_u64(bytes.len() as u64);
            let (h1, m1) = ext4::rootfs::cache_stats();
            klog::write_raw(b" cache after pass1: hits=");
            klog::write_dec_u64(h1);
            klog::write_raw(b" misses=");
            klog::write_dec_u64(m1);
            klog::write_raw(b"\n");
            let _ = ext4::rootfs::read_file(b"/bin/sh");
            let (h2, m2) = ext4::rootfs::cache_stats();
            klog::write_raw(b"[INFO]  ext4 /bin/sh cache after pass2: hits=");
            klog::write_dec_u64(h2);
            klog::write_raw(b" misses=");
            klog::write_dec_u64(m2);
            klog::write_raw(b"\n");
        }
        let s = net::sock::stack();
        let endpoint = s.bind_udp(net::Ipv4Addr::LOOPBACK, 7777).ok();
        let _ = s.send_udp_to(
            net::Ipv4Addr::LOOPBACK, 5555,
            net::Ipv4Addr::LOOPBACK, 7777,
            b"oxide-boot-smoke",
        );
        net::sock::drain_loopback();
        if let Some((_, _, _, _, _, payload)) = endpoint.and_then(|endpoint| endpoint.recv(false)) {
            klog::write_raw(b"[INFO]  net udp lo round-trip: ");
            klog::write_raw(&payload);
            klog::write_raw(b"\n");
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn install_network_hooks() {
    netlink::install_netfilter_handler(netfilter::handle);
    net::control_event::set_notifier(netlink::mcast::notify_control_event);
    net::stack::install_nf_hook(|h, p, fam| netfilter::eval(h, p, fam).as_u32());
    net::stack::install_bpf_filter_runner(|kind, insns, packet| match kind {
        net::bpf_filter::FilterKind::Ebpf =>
            security::bpf_interp::run(insns, packet).map_or(0, |r| r as u32),
        net::bpf_filter::FilterKind::Classic =>
            security::socket_filter::run(insns, packet),
    });
    net::stack::install_bpf_filter_context_runner(|kind, insns, ctx| match kind {
        net::bpf_filter::FilterKind::Ebpf =>
            security::bpf_interp::run(insns, ctx.packet).map_or(0, |r| r as u32),
        net::bpf_filter::FilterKind::Classic =>
            security::socket_filter::run_with_context(insns, security::socket_filter::Context {
                packet: ctx.packet, protocol: ctx.protocol,
                ifindex: ctx.ifindex, pay_offset: ctx.pay_offset, hatype: ctx.hatype,
                cpu: socket_filter_cpu(), random: devfs::misc::lcg_next() as u32,
            }),
    });
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn socket_filter_cpu() -> u32 {
    use hal::CpuOps;
    hal_x86_64::X86CpuOps::current_cpu()
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn socket_filter_cpu() -> u32 {
    use hal::CpuOps;
    hal_aarch64::ArmCpuOps::current_cpu()
}

#[cfg(target_os = "oxide-kernel")]
fn load_keymap() {
    if let Some(blob) = ext4::rootfs::read_file(b"/etc/keymap") {
        match drv_virtio_input::keymap::load_text(&blob) {
            Ok(name) => { debug_boot! {
                klog::write_raw(b"[INFO]  keymap loaded: ");
                klog::write_raw(name.as_bytes());
                klog::write_raw(b"\n");
            } }
            Err(_) => { debug_boot! {
                klog::write_raw(b"[WARN]  /etc/keymap: parse error\n");
            } }
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn handoff_to_userspace(info: &BootInfo) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        debug_boot! { klog::write_raw(b"[INFO]  init: handoff begin\n"); }
        fs::ptrace::install();
        #[cfg(feature = "debug-mount")]
        pmm::user_as::install_lock_step_hook();
        smoke::elf::run_as_task(info.hhdm_offset);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe { smoke::elf_arm::run(); }
}

/// Boot mount registration: do the single namei walk to the mountpoint
/// dentry (the mount engine takes the WALKED dentry, Linux
/// `mnt_set_mountpoint` — never a path string) and register only if it
/// resolves. A missing underlay is SKIPPED rather than passed as `None`,
/// which the engine reads as the namespace root. # C: O(path components)
#[cfg(target_os = "oxide-kernel")]
fn boot_register(fstype: &str, path: &str, fs: Arc<dyn vfs::fs::FileSystem>) {
    if let Some(d) = vfs::resolve_path_dentry(path) {
        if let Some(ty) = vfs::fs::get_fs_type(fstype) {
            if let Err(e) = vfs::mount::register_typed(ty, Some(d), fs) {
                klog::write_raw(b"[BOOT-MOUNT-FAIL] type=");
                klog::write_raw(fstype.as_bytes());
                klog::write_raw(b" path=");
                klog::write_raw(path.as_bytes());
                klog::write_raw(b" errno=");
                klog::write_dec_u64(e as u64);
                klog::write_raw(b"\n");
            } else {
                klog::write_raw(b"[BOOT-MOUNT-OK] type=");
                klog::write_raw(fstype.as_bytes());
                klog::write_raw(b" path=");
                klog::write_raw(path.as_bytes());
                klog::write_raw(b"\n");
            }
        } else {
            klog::write_raw(b"[BOOT-MOUNT-FAIL] type-missing=");
            klog::write_raw(fstype.as_bytes());
            klog::write_raw(b" path=");
            klog::write_raw(path.as_bytes());
            klog::write_raw(b"\n");
        }
    } else {
        klog::write_raw(b"[BOOT-MOUNT-FAIL] underlay-missing path=");
        klog::write_raw(path.as_bytes());
        klog::write_raw(b"\n");
    }
}

/// Boot bind-mount registration (per-mount root inode), same walk-then-attach
/// contract as `boot_register`. # C: O(path components)
#[cfg(target_os = "oxide-kernel")]
fn boot_register_bind(fstype: &str, path: &str, fs: Arc<dyn vfs::fs::FileSystem>, root: vfs::InodeRef) {
    if let Some(d) = vfs::resolve_path_dentry(path) {
        if let Some(ty) = vfs::fs::get_fs_type(fstype) {
            let _ = vfs::mount::register_bind_typed(ty, Some(d), fs, root);
        }
    }
}

/// Boot cgroup2 registration: rootfs owns the early static mountpoint walk;
/// cgroupfs receives the already-resolved `/sys/fs/cgroup` dentry. # C: O(path components)
#[cfg(target_os = "oxide-kernel")]
fn boot_register_cgroup() {
    if let Some(d) = vfs::resolve_path_dentry(cgroup::MOUNT) {
        let _ = cgroup::mount_at(cgroup::MOUNT, Some(d));
    }
}
