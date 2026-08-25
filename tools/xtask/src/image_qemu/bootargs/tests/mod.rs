use super::core::{kernel_cmdline, KERNEL_CONSOLE_PARAMS, KERNEL_DEBUG_PARAMS, USERSPACE_CONSOLE_PARAMS, USERSPACE_DEBUG_PARAMS, SELINUX_PARAMS};
use super::super::serial_device_name;
use std::sync::Mutex;

static ENV: Mutex<()> = Mutex::new(());
fn env_held() -> std::sync::MutexGuard<'static, ()> { ENV.lock().unwrap_or_else(|e| e.into_inner()) }
fn with_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    for (k, v) in vars { match v { Some(v) => std::env::set_var(k, v), None => std::env::remove_var(k) } }
    f();
    for (k, _) in vars { std::env::remove_var(k); }
}

#[test]
fn arches_carry_the_same_parameters() {
    let _env = env_held(); let x = kernel_cmdline("x86_64", "/boot/oxide-x86_64"); let a = kernel_cmdline("aarch64", "/boot/oxide-aarch64.Image");
    let x_rest = x.strip_prefix("BOOT_IMAGE=/boot/oxide-x86_64 ").unwrap(); assert_eq!(x_rest.replace("console=ttyS0", "console=ttyAMA0"), a);
}

#[test]
fn path_valued_parameters_use_the_published_devnode() {
    with_env(&[("OXIDE_SERIAL_SHELL", None), ("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || { for arch in ["x86_64", "aarch64"] { assert!(kernel_cmdline(arch, "/img").contains("systemd.debug_shell=tty9")); } assert!(kernel_cmdline("aarch64", "/img").contains("console=ttyAMA0,115200")); });
}

#[test]
fn the_serial_control_plane_moves_the_shell_and_masks_the_login() {
    with_env(&[("OXIDE_SERIAL_SHELL", Some("1")), ("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || { for (arch, serial) in [("x86_64", "ttyS0"), ("aarch64", "ttyAMA0")] { let line = kernel_cmdline(arch, "/img"); assert!(line.split(' ').any(|t| t == format!("systemd.debug_shell={serial}"))); assert!(line.split(' ').any(|t| t == format!("systemd.mask=serial-getty@{serial}.service"))); assert!(line.contains("console=tty0 ")); } });
}

#[test]
fn an_explicit_zero_keeps_the_login_on_the_serial_line() { with_env(&[("OXIDE_SERIAL_SHELL", Some("0")), ("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || { let line = kernel_cmdline("x86_64", "/img"); assert!(line.contains("systemd.debug_shell=tty9")); assert!(!line.contains("systemd.mask=serial-getty")); }); }

#[test]
fn the_debug_shell_does_not_squat_on_the_serial_line() { with_env(&[("OXIDE_SERIAL_SHELL", None), ("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || { for (arch, ser) in [("x86_64", "ttyS0"), ("aarch64", "ttyAMA0")] { let line = kernel_cmdline(arch, "/img"); assert!(!line.contains(&format!("systemd.debug_shell={ser}"))); assert!(line.contains("systemd.debug_shell=")); } }); }

#[test]
fn boot_image_is_never_duplicated() { let _env = env_held(); assert_eq!(kernel_cmdline("x86_64", "/i").matches("BOOT_IMAGE=").count(), 1); assert_eq!(kernel_cmdline("aarch64", "/i").matches("BOOT_IMAGE=").count(), 0); }

#[test]
fn serial_console_names_match_the_uart_each_arch_programs() { let _env = env_held(); assert_eq!(serial_device_name("x86_64"), "ttyS0"); assert_eq!(serial_device_name("aarch64"), "ttyAMA0"); }

#[test]
fn vt_console_token_is_last_on_both_arches() { let _env = env_held(); for arch in ["x86_64", "aarch64"] { let line = kernel_cmdline(arch, "/img"); let last = line.rmatch_indices("console=").next().unwrap().0; assert!(line[last..].starts_with("console=tty0 ")); } }

#[test]
fn carries_the_propagation_marker() { let _env = env_held(); for arch in ["x86_64", "aarch64"] { assert!(kernel_cmdline(arch, "/img").contains("oxide.bootargs=grub")); } }

#[test]
fn disposable_boot_image_does_not_wait_for_flatpak_network_setup() { let _env = env_held(); for arch in ["x86_64", "aarch64"] { assert!(kernel_cmdline(arch, "/img").contains("systemd.mask=flatpak-add-fedora-repos.service")); } }

#[test]
fn the_debug_preset_reaches_the_line() {
    const REQUIRED: [&str; 6] = ["keep_bootcon", "initcall_debug", "ignore_loglevel", "systemd.log_level=debug", "systemd.log_target=console", "systemd.journald.forward_to_console=1"];
    with_env(&[("OXIDE_CMDLINE_DEBUG", Some("1")), ("OXIDE_CMDLINE_EXTRA", None)], || { let line = kernel_cmdline("x86_64", "/img"); for p in REQUIRED { assert!(line.split(' ').any(|t| t == p), "preset lost {p}"); } });
    assert_eq!(KERNEL_DEBUG_PARAMS.split(' ').count() + USERSPACE_DEBUG_PARAMS.split(' ').count(), REQUIRED.len());
}

#[test]
fn the_preset_is_absent_unless_asked_for() { with_env(&[("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || { let line = kernel_cmdline("x86_64", "/img"); assert!(!line.contains("initcall_debug")); assert!(!line.contains("ignore_loglevel")); assert!(!line.contains("keep_bootcon")); }); }

#[test]
fn every_boot_asks_for_the_sysrq_commands_it_is_debugged_with() { with_env(&[("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || { for arch in ["x86_64", "aarch64"] { let line = kernel_cmdline(arch, "/img"); assert!(line.split(' ').any(|t| t == "sysctl.kernel.sysrq=1")); assert!(line.split(' ').any(|t| t == "sysrq_always_enabled")); } }); }

#[test]
fn every_boot_routes_userspace_logging_through_the_kernel_ring() { with_env(&[("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || { for arch in ["x86_64", "aarch64"] { let line = kernel_cmdline(arch, "/img"); for p in ["systemd.log_target=kmsg", "systemd.journald.forward_to_kmsg=1"] { assert!(line.split(' ').any(|t| t == p)); } let last = line.rmatch_indices("console=").next().unwrap().0; assert!(line[last..].starts_with("console=tty0 ")); } }); assert_eq!(USERSPACE_CONSOLE_PARAMS.split(' ').count(), 2); }

#[test]
fn every_boot_carries_the_console_parameters() { with_env(&[("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || { for (arch, ser) in [("x86_64", "ttyS0"), ("aarch64", "ttyAMA0")] { let line = kernel_cmdline(arch, "/img"); for p in ["earlycon", "printk.time=1", &format!("console={ser},115200"), "console=tty0"] { assert!(line.split(' ').any(|t| t == p)); } } }); assert_eq!(KERNEL_CONSOLE_PARAMS.split(' ').count(), 2); }

#[test]
fn extra_parameters_compose_with_the_preset() { with_env(&[("OXIDE_CMDLINE_DEBUG", Some("1")), ("OXIDE_CMDLINE_EXTRA", Some("loglevel=8 panic=30"))], || { let line = kernel_cmdline("aarch64", "/img"); assert!(line.contains("initcall_debug")); assert!(line.contains("loglevel=8")); assert!(line.contains("panic=30")); }); }

#[test]
fn an_explicit_zero_disables_the_preset() { with_env(&[("OXIDE_CMDLINE_DEBUG", Some("0")), ("OXIDE_CMDLINE_EXTRA", None)], || { assert!(!kernel_cmdline("x86_64", "/img").contains("initcall_debug")); }); }

#[test]
fn the_default_line_does_not_ask_for_silence() { with_env(&[("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || { for arch in ["x86_64", "aarch64"] { assert!(!kernel_cmdline(arch, "/img").split(' ').any(|t| t == "quiet")); } }); }

#[test]
fn both_arches_carry_the_permissive_parameter() { for arch in ["x86_64", "aarch64"] { assert!(kernel_cmdline(arch, "/boot/oxide.elf").split(' ').any(|t| t == SELINUX_PARAMS)); } }

#[test]
fn the_module_is_never_disabled_by_the_boot_line() { for arch in ["x86_64", "aarch64"] { let line = kernel_cmdline(arch, "/boot/oxide.elf"); assert!(!line.contains("selinux=0")); assert!(!line.split(' ').any(|t| t == "selinux=off")); } }

#[test]
fn the_parameter_asks_for_permissive_and_not_for_a_disable() { assert_eq!(SELINUX_PARAMS, "enforcing=0"); }
