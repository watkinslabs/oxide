use alloc::sync::Arc;

use crate::BootInfo;
use super::entry::step;

/// Rootfs, mount graph, keymap, and first-userspace handoff.
///
/// Every phase below is a SEPARATE frame on purpose (Linux
/// `noinline_for_stack`). They run strictly in sequence and nothing one
/// builds outlives it — the ext4 root mount, the hook installs, the three
/// `TmpfsFs` and their `Arc<dyn FileSystem>` temporaries are all dead before
/// the handoff — but folded into one function the compiler reserves the whole
/// pile in a single prologue and holds it live underneath the deepest chain in
/// the kernel (`run_as_task` -> `install_default_runqueue` ->
/// `Task::new_with_mm`, and `init_exports` -> `spawn_kernel_thread` ->
/// `Task::new_with_mm`). Split, the phases overlap instead of summing.
/// # SAFETY: caller must satisfy `kernel_main` boot-entry contract.
/// # C: not measured (one-shot init)
#[cfg(target_os = "oxide-kernel")]
#[inline(never)]
pub unsafe fn init(info: &BootInfo) {
    console::boot_progress::publish(console::boot_progress::Phase::RootFilesystem);
    // SAFETY: forwarded boot-entry contract — single CPU, no user address space
    // live, so republishing the kernel-half master has no concurrent copier.
    #[cfg(target_arch = "x86_64")]
    unsafe { hal_x86_64::mmu_ops::resync_kernel_master(); }
    // SAFETY: forwarded boot-entry contract, which is what each phase requires;
    // each returns before the next is entered.
    unsafe { mount_root(); }
    mount_boot_filesystems();
    log_dev_null_owner();
    debug_boot_rootfs();
    step("load_keymap", load_keymap);
    console::boot_progress::publish(console::boot_progress::Phase::Userspace);
    step("handoff_to_userspace", || handoff_to_userspace(info));
}

/// Root ext4 mount plus the one-shot hook installs that must precede it.
/// Its own frame; see `init`.
/// # SAFETY: caller must satisfy `kernel_main` boot-entry contract.
/// # C: not measured (one-shot init)
#[cfg(target_os = "oxide-kernel")]
#[inline(never)]
unsafe fn mount_root() {
    // SAFETY: forwarded boot-entry contract; these one-shot hook installs run
    // before the first mount, so nothing can observe a half-installed hook.
    unsafe {
        // Serialize ext4 metadata transactions per-task: the reentrant txn gate
        // keys ownership on the current task id so concurrent tasks/CPUs can't
        // race the group bitmaps/GDT/counters (was corrupting the on-disk fs:
        // group-bitmap csum mismatches + unattached inodes). Registered before
        // the first mount so every ext4 op is serialized.
        ext4::mount::set_ctx_id_hook(|| sched::current().map(|t| t.tid as u64).unwrap_or(0));
        // PCI enumeration runs before the scheduler exists. Disks registered
        // there defer their partition-table I/O. Drain it now, with workers
        // live, before `root=` may resolve a partition or PARTUUID.
        step("block::start_deferred_partition_scans", block::registry::start_deferred_partition_scans);
        // Loop devices exist before anything asks for one: a distribution
        // opens /dev/loop0 directly during early boot, before it has spoken to
        // /dev/loop-control. They hold no backing file until one is bound, so
        // publishing them costs a registry entry each and no I/O.
        step("drv_loop::init", drv_loop::registry::init);
        // The mapper control node must exist before user space mounts an LVM
        // root or asks udev to inspect volumes. Target creation remains lazy;
        // this only publishes `/dev/mapper/control` and its fixed ABI owner.
        step("device_mapper::init", || device_mapper::init().expect("device-mapper control registration failed"));
        step("scsi::init", scsi::init);
        step("md::init", md::init);
        let _resume = step("hibernate::software_resume",
            crate::kmain::hibernate_wiring::software_resume);
        #[cfg(feature = "debug-hibernate")]
        for disk in block::registry::snapshot() {
            klog::write_raw(b"[hibernate] boot block name=");
            klog::write_raw(disk.name.as_bytes());
            klog::write_raw(b" serial=");
            klog::write_raw(disk.serial.as_deref().unwrap_or("").as_bytes());
            klog::write_raw(b"\n");
        }
        let root_spec = crate::boot_cmdline::parameter_value(b"root")
            .expect("boot command line has no root=");
        let root_dev = block::registry::resolve_root_spec(root_spec)
            .expect("requested root block device not found");
        step("ext4::rootfs::init_from_dev", || ext4::rootfs::init_from_dev(root_dev))
            .expect("ext4 root mount failed to open");
        step("pci_boot::retry_firmware_gated_drivers", pci_boot::retry_firmware_gated_drivers);
        net::sock::init();
        // Generic netlink: the nlctrl controller plus every in-kernel family
        // (VFS_DQUOT), registered before userspace can resolve one by name.
        netlink::genetlink::init();
        // cfg80211 registers the nl80211 family before any radio can announce
        // itself on it, so a radio that appears during this same pass has a
        // family to announce on.
        step("wireless::init", wireless::init);
        start_virtual_radios();
        install_network_hooks();
        net::sock::set_iface_primary_ip_hook(crate::syscalls::siocgif::iface_primary_ip_hook);
        modules::linux_time::set_now_hook(module_time_now_ns);
        modules::linux_nvme_auth::install_keyring_hooks(fs::keyring::native::key_put,
            fs::keyring::native::key_revoke, fs::keyring::native::nvme_tls_psk_refresh);
        modules::registry::init_exports();
        crate::syscalls::mount::install_vfs_hooks();
        crate::syscalls::ensure_mount_filesystems_registered();
    }
}

/// The boot mount graph: every filesystem attached under the mounted root.
/// Its own frame; see `init`.
/// # C: not measured (one-shot init)
#[cfg(target_os = "oxide-kernel")]
#[inline(never)]
fn mount_boot_filesystems() {
    if let Some(ext4_ty) = vfs::fs::get_fs_type("ext4") {
        let _ = vfs::mount::register_typed(ext4_ty, None, Arc::new(ext4::rootfs::Ext4RootfsFs));
    }
    boot_register("devtmpfs", "/dev",  Arc::new(::devfs::DevfsFs));
    boot_register("proc",     "/proc", Arc::new(procfs::fs_impl::ProcfsFs::default()));
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
        if let Some(datagram) = endpoint.and_then(|endpoint| endpoint.recv(false)) {
            klog::write_raw(b"[INFO]  net udp lo round-trip: ");
            klog::write_raw(&datagram.payload);
            klog::write_raw(b"\n");
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
fn install_network_hooks() {
    netlink::install_netfilter_handler(netfilter::handle);
    // NB: control-event notifier is installed earlier, in `runtime::init` before
    // netdev registration, so eth0's boot RTM_NEWLINK is not dropped.
    net::stack::install_nf_hook(|ctx| {
        let result = netfilter::eval_hook(ctx);
        net::stack::NfHookResult { verdict: result.verdict.as_u32(), mark: result.mark,
            actions: result.actions }
    });
    use security::bpf::sk_filter::{self, SkFilterContext};
    net::stack::install_bpf_filter_runner(|kind, insns, packet| match kind {
        // A socket with no netdevice carries neither an EtherType nor an
        // ifindex, which is exactly the zeroed pair a filter sees there.
        net::bpf_filter::FilterKind::Ebpf | net::bpf_filter::FilterKind::SkReuseport =>
            sk_filter::run(insns, SkFilterContext::bare(packet)),
        net::bpf_filter::FilterKind::Classic =>
            security::socket_filter::run(insns, packet),
    });
    net::stack::install_bpf_reuseport_runner(|insns, maps, runner, ctx| {
        let verdict = security::bpf::sk_reuseport::run(
            security::bpf::sk_reuseport::Run { insns, maps, runner },
            security::bpf::sk_reuseport::SkReuseportContext {
                packet: ctx.packet, eth_protocol: ctx.eth_protocol,
                ip_protocol: ctx.ip_protocol, bind_inany: ctx.bind_inany, hash: ctx.hash,
            });
        net::bpf_filter::ReuseportVerdict {
            action: verdict.action, selected: verdict.selected,
        }
    });
    // A socket-holding map has to be able to say what a stored socket is; the
    // network stack is the only owner of that answer.
    net::sock::sockarray::install();
    net::stack::install_bpf_filter_context_runner(|kind, insns, ctx| match kind {
        net::bpf_filter::FilterKind::Ebpf | net::bpf_filter::FilterKind::SkReuseport =>
            sk_filter::run(insns, SkFilterContext {
                packet: ctx.packet, protocol: ctx.protocol,
                ifindex: ctx.ifindex.unwrap_or(0),
            }),
        net::bpf_filter::FilterKind::Classic =>
            security::socket_filter::run_with_context(insns, security::socket_filter::Context {
                packet: ctx.packet, protocol: ctx.protocol,
                ifindex: ctx.ifindex, pay_offset: ctx.pay_offset, hatype: ctx.hatype,
                cpu: socket_filter_cpu(), random: devfs::misc::random_u64() as u32,
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

/// Its own frame; see `init`. The keymap parser works out of a multi-kilobyte
/// scan buffer, and inlined here it would be reserved for the whole of
/// `init` — including the userspace handoff, which runs after the keymap is
/// already loaded and is the deepest chain in the kernel.
/// # C: O(keymap bytes)
#[cfg(target_os = "oxide-kernel")]
#[inline(never)]
fn load_keymap() {
    if let Some(blob) = ext4::rootfs::read_file(b"/etc/keymap") {
        match drv_virtio_input::keymap::load_text(&blob) {
            Ok(_name) => { debug_boot! {
                klog::write_raw(b"[INFO]  keymap loaded: ");
                klog::write_raw(_name.as_bytes());
                klog::write_raw(b"\n");
            } }
            Err(_) => { debug_boot! {
                klog::write_raw(b"[WARN]  /etc/keymap: parse error\n");
            } }
        }
    }
}

/// First-userspace handoff. Its own frame; see `init`. `run_as_task` carries
/// the widest frame on the boot path, and folded into `init` it would sit
/// above the mount phase, which is over by the time the handoff runs.
/// # C: not measured (one-shot init)
#[cfg(target_os = "oxide-kernel")]
#[inline(never)]
fn handoff_to_userspace(info: &BootInfo) {
    let _ = info; // only the x86_64 handoff reads the boot info
    // Userspace exists from here on, so a kernel -> userspace helper may run.
    // Before this point the gate refuses every request: there is nothing to
    // exec into, and a helper started against a half-built root would fail in
    // ways no caller could interpret.
    umh::usermodehelper_enable();
    // SAFETY: reached only from `rootfs::init` under the boot-entry contract,
    // with the rootfs mounted and the scheduler running, which is what the
    // ptrace install and the first user-task exec require.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        debug_boot! { klog::write_raw(b"[INFO]  init: handoff begin\n"); }
        fs::ptrace::install();
        #[cfg(feature = "debug-wrotelock")]
        pmm::user_as::install_lock_step_hook();
        smoke::elf::run_as_task(info.hhdm_offset);
    }
    // SAFETY: same mounted-rootfs, scheduler-running handoff point as the
    // x86_64 arm above.
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
                #[cfg(feature = "debug-boot")]
                {
                    klog::write_raw(b"[BOOT-MOUNT-OK] type=");
                    klog::write_raw(fstype.as_bytes());
                    klog::write_raw(b" path=");
                    klog::write_raw(path.as_bytes());
                    klog::write_raw(b"\n");
                }
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

/// Bring up the virtual 802.11 radios the boot line asked for.
///
/// Off unless `mac80211_hwsim.radios=<n>` is on the command line, matching the
/// reference, where the virtual radio is a module nobody loads by accident. A
/// machine with real wireless hardware must not also grow two radios that are
/// not there.
/// # C: O(n)
#[cfg(target_os = "oxide-kernel")]
fn start_virtual_radios() {
    let Some(value) = crate::boot_cmdline::parameter_value(b"mac80211_hwsim.radios")
        else { return; };
    let Ok(n) = kstrtox::kstrtoul(value, 10) else { return; };
    if n == 0 { return; }
    let n = n.min(drv_mac80211_hwsim::limits::MAX_RADIOS as u64) as u32;
    let _ = drv_mac80211_hwsim::init(n);
}
