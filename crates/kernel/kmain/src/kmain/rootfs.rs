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
        let root_dev = block::registry::by_serial("oxide-root")
            .or_else(block::registry::first_device)
            .expect("root disk (virtio-blk serial=oxide-root) not found");
        ext4::rootfs::init_from_dev(root_dev)
            .expect("ext4 root mount (oxide-root) failed to open");
        net::sock::init();
        net::sock::set_iface_primary_ip_hook(crate::syscalls::siocgif::iface_primary_ip_hook);
        net::iface_addr::set_addr_change_hook(crate::syscalls::siocgif::ipv4_addr_change_hook);
        modules::registry::init_exports();
        crate::syscalls::mount::install_vfs_hooks();
        let _ = vfs::mount::register(None, Arc::new(ext4::rootfs::Ext4RootfsFs));
        boot_register("/dev",  Arc::new(::devfs::DevfsFs));
        boot_register("/proc", Arc::new(procfs::fs_impl::ProcfsFs));
        boot_register("/sys",  Arc::new(crate::sysfs::SysfsFs));
        cgroup::mount_root();
        let tmp = fs::tmpfs::TmpfsFs::new(alloc::string::String::from("/tmp"));
        let tmp_root = tmp.root_inode();
        boot_register_bind("/tmp", tmp, tmp_root);
        let shm = fs::tmpfs::TmpfsFs::new(alloc::string::String::from("/dev/shm"));
        let shm_root = shm.root_inode();
        boot_register_bind("/dev/shm", shm, shm_root);
        let run = fs::tmpfs::TmpfsFs::new(alloc::string::String::from("/run"));
        let run_root = run.root_inode();
        boot_register_bind("/run", run, run_root);
        if let Some(home_dev) = block::registry::by_serial("oxide-home") {
            if let Ok(home_fs) = ext4::rootfs::Ext4Mount::open(home_dev) {
                boot_register("/home", home_fs);
            }
        }
        debug_cgroup! { cgroup::selftest::run(); }
    }

    debug_boot_rootfs();
    load_keymap();
    handoff_to_userspace(info);
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
        netlink::install_netfilter_handler(netfilter::handle);
        net::stack::install_nf_hook(|h, p, fam| netfilter::eval(h, p, fam).as_u32());
        net::stack::install_bpf_filter_runner(
            |insns, pkt| security::bpf_interp::run(insns, pkt).map_or(false, |r| r != 0));
        let s = net::sock::stack();
        let _ = s.bind_udp(net::Ipv4Addr::LOOPBACK, 7777);
        let _ = s.send_udp_to(
            net::Ipv4Addr::LOOPBACK, 5555,
            net::Ipv4Addr::LOOPBACK, 7777,
            b"oxide-boot-smoke",
        );
        net::sock::drain_loopback();
        if let Some((_, _, payload)) = s.recv_udp(7777) {
            klog::write_raw(b"[INFO]  net udp lo round-trip: ");
            klog::write_raw(&payload);
            klog::write_raw(b"\n");
        }
    }
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
fn boot_register(path: &str, fs: Arc<dyn vfs::fs::FileSystem>) {
    if let Some(d) = vfs::resolve_path_dentry(path) {
        let _ = vfs::mount::register(Some(d), fs);
    }
}

/// Boot bind-mount registration (per-mount root inode), same walk-then-attach
/// contract as `boot_register`. # C: O(path components)
#[cfg(target_os = "oxide-kernel")]
fn boot_register_bind(path: &str, fs: Arc<dyn vfs::fs::FileSystem>, root: vfs::InodeRef) {
    if let Some(d) = vfs::resolve_path_dentry(path) {
        let _ = vfs::mount::register_bind(Some(d), fs, root);
    }
}
