use vfs::Ino;

pub(super) const INO_BUS_PCI_DEV:   Ino = 0x5102_0001;
pub(super) const INO_BUS_PCI_DRV:   Ino = 0x5102_0002;
pub(super) const INO_BUS_VIRT_DEV:  Ino = 0x5102_0003;
pub(super) const INO_BUS_VIRT_DRV:  Ino = 0x5102_0004;
pub(super) const INO_DEV_PCI_ROOT:  Ino = 0x5102_0005;
pub(super) const INO_DEV_VIRT_ROOT: Ino = 0x5102_0006;
pub(super) const INO_BUS_PLATFORM_DEV: Ino = 0x5102_0007;
pub(super) const INO_BUS_PLATFORM_DRV: Ino = 0x5102_0008;
pub(super) const INO_DEV_PLATFORM_ROOT: Ino = 0x5102_0009;
pub(super) const INO_SYS_DEV_CHAR:  Ino = 0x5102_000a;
pub(super) const INO_SYS_DEV_BLOCK: Ino = 0x5102_000b;
pub(super) const INO_SYMLINK:       Ino = 0x5102_0080;
pub(super) const INO_DEVICE_DIR:    Ino = 0x5102_1000;
pub(super) const INO_DRIVER_DIR:    Ino = 0x5102_1100;
pub(super) const INO_ATTR:          Ino = 0x5102_2000;
pub(super) const INO_DRIVER_ATTR:   Ino = 0x5102_3000;

pub(super) fn dev_root_canon(bus: &str) -> &'static str {
    match bus {
        "pci" => "devices/pci0000:00",
        "virtio" => "devices/virtio",
        "platform" => "devices/platform",
        // Block disks live under /sys/devices/virtual/block/<name> (60§6.3a):
        // the uevent DEVPATH MUST resolve to a real /sys dir or udevd reads
        // /sys<DEVPATH>/uevent → ENOENT and never processes the disk.
        "block" => "devices/virtual/block",
        "input" => "devices/virtual/input",
        "drm" => "devices/virtual/drm",
        "mem" => "devices/virtual/mem",
        "misc" => "devices/virtual/misc",
        "sound" => "devices/virtual/sound",
        "graphics" => "devices/virtual/graphics",
        _ => "devices/platform",
    }
}

pub(super) fn dev_root_leaf(bus: &str) -> &'static str {
    match bus {
        "pci" => "pci0000:00",
        "virtio" => "virtio",
        "platform" => "platform",
        "block" => "virtual/block",
        "input" => "virtual/input",
        "drm" => "virtual/drm",
        "mem" => "virtual/mem",
        "misc" => "virtual/misc",
        "sound" => "virtual/sound",
        "graphics" => "virtual/graphics",
        _ => "platform",
    }
}

pub(super) fn bus_devices_ino(bus: &str) -> Ino {
    match bus {
        "pci" => INO_BUS_PCI_DEV,
        "virtio" => INO_BUS_VIRT_DEV,
        "platform" => INO_BUS_PLATFORM_DEV,
        _ => INO_BUS_PLATFORM_DEV,
    }
}

pub(super) fn bus_drivers_ino(bus: &str) -> Ino {
    match bus {
        "pci" => INO_BUS_PCI_DRV,
        "virtio" => INO_BUS_VIRT_DRV,
        "platform" => INO_BUS_PLATFORM_DRV,
        _ => INO_BUS_PLATFORM_DRV,
    }
}

pub(super) fn devices_root_ino(bus: &str) -> Ino {
    match bus {
        "pci" => INO_DEV_PCI_ROOT,
        "virtio" => INO_DEV_VIRT_ROOT,
        "platform" => INO_DEV_PLATFORM_ROOT,
        _ => INO_DEV_PLATFORM_ROOT,
    }
}
