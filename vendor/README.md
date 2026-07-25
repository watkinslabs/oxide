# vendor/

Small external build and boot inputs. The boot userspace image is composed in
the sibling `../images` repository; this directory does not contain a userspace
distribution.

| Path | What | License | Source |
|---|---|---|---|
| `firmware/ovmf-x64.fd` | EDK2 OVMF UEFI firmware, x86_64 | BSD-2-Clause | https://retrage.github.io/edk2-nightly/ |
| `firmware/ovmf-aarch64.fd` | EDK2 OVMF UEFI firmware, aarch64 (QEMU `virt`) | BSD-2-Clause | https://retrage.github.io/edk2-nightly/ |
| `grub/arm64-efi/` | GRUB modules used to build the AArch64 EFI ISO | GPL-3.0-or-later | Fedora `grub2-efi-aa64-modules` |
| `cross/` | Optional AArch64 musl cross toolchain for rootfs-injected smoke helpers | mixed | local installation |
| `rust/` | Source dependencies for kernel zram compression | dual licensed | crates.io sources |

## How to populate

```
$ ./tools/fetch-vendor.sh
```

Idempotent — skips files that already exist. Pinned versions live at
the top of the script. Re-run after editing those.

## CI

CI fetches the required firmware and GRUB inputs when an AArch64 boot job needs
them.
