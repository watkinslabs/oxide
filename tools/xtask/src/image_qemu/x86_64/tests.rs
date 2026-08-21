use super::{DEFAULT_MEMORY, HardwareProfile, display_plan, native_root_uses_ahci_for, x86_grub_cfg};
use super::x86_display::DisplayPlan;
use crate::image_qemu::bootargs::kernel_cmdline_for_root;

#[test]
fn default_memory_remains_four_gib() { assert_eq!(DEFAULT_MEMORY, "4G"); }

#[test]
fn native_profile_selects_the_native_pci_nic() {
    assert_eq!(HardwareProfile::NativePci.nic_device(), "e1000e,netdev=net0,bus=pcie.0");
    assert_eq!(HardwareProfile::NativePci.nic_device_for(Some("e1000")), "e1000,netdev=net0,bus=pcie.0");
    assert_eq!(HardwareProfile::NativePci.nic_device_for(Some("e1000e")), "e1000e,netdev=net0,bus=pcie.0");
}

#[test]
fn native_profile_uses_its_first_ahci_disk_as_root() {
    assert!(kernel_cmdline_for_root("x86_64", "/img", "/dev/sda").contains("root=/dev/sda"));
    assert_eq!(native_root_uses_ahci_for(None), Ok(true));
    assert_eq!(native_root_uses_ahci_for(Some("virtio")), Ok(false));
}

#[test]
fn default_profile_can_select_the_82574e_pci_model() {
    assert_eq!(HardwareProfile::Default.nic_device_for(Some("e1000e")), "e1000e,netdev=net0,bus=pcie.0");
}

#[test]
fn native_profile_exercises_pci_xhci_and_standard_usb_hid() {
    assert_eq!(HardwareProfile::Default.input_devices(), &[] as &[&str]);
    assert_eq!(HardwareProfile::NativePci.input_devices(), &[
        "qemu-xhci,id=xhci,bus=pcie.0", "usb-kbd,bus=xhci.0", "usb-tablet,bus=xhci.0",
    ]);
    assert_eq!(HardwareProfile::Default.usb_storage_device(), None);
    assert_eq!(HardwareProfile::NativePci.usb_storage_device(),
        Some("usb-storage,drive=usb0,bus=xhci.0,serial=oxide-usb0"));
}

#[test]
fn default_display_keeps_the_firmware_framebuffer_until_native_gpu_is_requested() {
    assert_eq!(display_plan(HardwareProfile::Default, false, false),
        DisplayPlan { legacy_vga: "std", primary_virtio_gpu: false });
    assert_eq!(display_plan(HardwareProfile::Default, true, false),
        DisplayPlan { legacy_vga: "none", primary_virtio_gpu: true });
    assert_eq!(display_plan(HardwareProfile::Default, true, true),
        DisplayPlan { legacy_vga: "std", primary_virtio_gpu: false });
    assert_eq!(display_plan(HardwareProfile::NativePci, true, false),
        DisplayPlan { legacy_vga: "std", primary_virtio_gpu: false });
}

#[test]
fn native_profile_exposes_q35_vtd_with_interrupt_remapping() {
    assert_eq!(HardwareProfile::Default.machine(), "q35");
    assert_eq!(HardwareProfile::Default.iommu_device(), None);
    assert_eq!(HardwareProfile::NativePci.machine(), "q35,kernel_irqchip=split");
    assert_eq!(HardwareProfile::NativePci.iommu_device(),
        Some("intel-iommu,intremap=on,caching-mode=on,pt=off"));
    assert_eq!(HardwareProfile::NativePci.iommu_device_for(false), None,
        "the otherwise-identical native topology can isolate DMA translation");
}

#[test]
fn x86_grub_keeps_the_firmware_framebuffer_but_retains_serial_recovery() {
    let cfg = x86_grub_cfg("x86_64", "root=/dev/root");
    assert!(cfg.contains("insmod all_video"));
    assert!(cfg.contains("set gfxmode=auto"));
    assert!(cfg.contains("set gfxpayload=keep"));
    assert!(cfg.contains("terminal_input serial console"));
    assert!(cfg.contains("terminal_output serial gfxterm"));
    assert!(cfg.contains("multiboot2 /boot/oxide-x86_64 root=/dev/root"));
}
