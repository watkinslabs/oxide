# 35 Drivers — v2 deferred entries

Carried at freeze 2026-05-02.

## Driver hot-plug

PCI hot-plug deferred to v2; virtio-mmio hot-plug to v1.x.

## `bind`/`unbind` via sysfs

Deferred to v1.x (writable `/sys/bus/.../driver/{bind,unbind}`).

## `MODULE_DEVICE_TABLE` autogen

For udev / initramfs match. Deferred.
