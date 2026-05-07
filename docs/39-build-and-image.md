# 39 Build + Image

FROZEN 2026-05-02. Dep:`02`,`07`,`29`,`36`. Provides:every workflow (`xtask kernel`,`xtask user`,`xtask image`,`xtask qemu`).
## 1 Purpose

Define workspace layout, `xtask` commands, image-build pipeline (kernel ELF + initramfs + ESP partition), QEMU runner.

## 2 Invariants (frozen)

1. Single Cargo workspace at repo root.
2. Each kernel crate `#![no_std]`.
3. `xtask` is the only build entry point users invoke; CI calls `xtask` only.
4. `cargo build` directly with the right target also works (xtask is convenience, not required).
5. Image is reproducible: same source → same hash. SOURCE_DATE_EPOCH respected.

## 3 Workspace layout

```
oxide2/
├── Cargo.toml                    # workspace root
├── rust-toolchain.toml
├── targets/
│   ├── x86_64-unknown-oxide-kernel.json
│   └── aarch64-unknown-oxide-kernel.json
│   # userspace uses upstream x86_64-unknown-linux-musl + aarch64-unknown-linux-musl
│   # per 29a§2 (no custom JSON)
├── link/
│   ├── x86_64-kernel.ld
│   └── aarch64-kernel.ld
├── docs/                         # specs (this dir)
├── kernel/                       # the kernel binary crate
├── crates/
│   ├── hal/, hal-x86_64/, hal-aarch64/
│   ├── boot-x86_64/, boot-aarch64/
│   ├── pmm/, vmm/, slab/, kalloc/
│   ├── sched/, task/, syscall/
│   ├── vfs/, fs-tmpfs/, fs-devtmpfs/, fs-devpts/, fs-procfs/, fs-sysfs/, fs-cgroup2/, fs-ext4/
│   ├── block/, ipc/, signals/, futex/
│   ├── net/, net-ipv4/, net-ipv6/, net-tcp/, net-udp/
│   ├── time/, irq/, modules/
│   ├── elf/, exec/, klog/
│   ├── drv-uart-{16550,pl011}/, drv-virtio-{blk,net,console,rng,vsock,input,gpu}/, drv-nvme/, drv-ahci/, drv-ps2-keyboard/
│   ├── userspace-abi/            # struct layouts shared with userspace
│   └── vdso-x86_64/, vdso-aarch64/
├── userspace/
│   ├── init/                     # PID 1
│   ├── libc/musl/                # vendored fork
│   ├── dynlink/                  # ld-oxide
│   ├── busybox-vendored/ or coreutils-{ls,cat,...}/
│   └── apps/                     # acceptance binaries (curl, redis built against our libc)
├── tools/
│   ├── xtask/
│   ├── oracle-{buddy,slab,sched}/
│   ├── perfrunner/
│   ├── spec-lint/
│   └── img-builder/
├── tests/
│   ├── unit/                     # arch-free hosted #[cfg(test)]
│   ├── integration/              # boots a kernel, runs a userspace test program
│   └── bench/                    # criterion-based microbenchmarks
└── bench-history/, perf-history/
```

## 4 xtask commands

```
xtask kernel    --arch <a> --profile <p>
xtask user      --arch <a>
xtask image     --arch <a>            -> boot.img
xtask qemu      --arch <a> [--gdb] [--smp N] [--mem MB]
xtask test      [--hosted | --kernel | --loom | --miri | --proptest | --all]
xtask bench     --arch <a>
xtask spec-lint                       # CI lints from `08`,`07`
xtask doc-check                       # MANIFEST consistency, frozen-revision-block lints
xtask sign-cert <key.pem>             # generate `OXIDE_TRUSTED_KEYS` for module signing
```

## 5 Image format

`boot.img` = a GPT disk image with two partitions:
1. ESP (FAT32, ~64 MiB): `EFI/BOOT/BOOT<arch>.EFI` (Limine x86 / EDK2-shim arm), kernel ELF, initramfs.cpio.zst, `limine.conf` (x86) or DTB (arm).
2. Optional: ext4 rootfs partition (when running with persistent root; otherwise `root=tmpfs`).

Initramfs structure:
```
/init                # PID 1 binary
/bin/{busybox,sh}    # static or dynlinked
/lib/ld-oxide.so.1
/lib/libc.so
/etc/{passwd,shadow,group,hosts,resolv.conf,init.conf,fstab,os-release}
/dev (empty; populated by kernel devtmpfs)
/proc, /sys, /tmp (empty mountpoints)
/sbin/getty, /sbin/login (when v2)
```

Built by `tools/img-builder/`:
- `cargo build --release -p init -p ld-oxide -p libc-shim -p busybox`.
- Strip binaries.
- Compose initramfs cpio with deterministic timestamps (SOURCE_DATE_EPOCH).
- zstd-compress.
- Build ESP image with `mtools` (`mformat`,`mcopy`).
- Build GPT with `sgdisk` or hand-rolled.

## 6 Reproducibility

- All builds set `SOURCE_DATE_EPOCH`.
- Linker uses `--build-id=none` or `--build-id=sha1` deterministic.
- Cpio archives sorted, no atime, fixed UID/GID.
- Image hash committed to `image-history/<commit>.sha256`.

## 7 QEMU invocation

`xtask qemu --arch x86_64`:
```
qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host \
  -m 4G -smp 4 \
  -drive if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on \
  -drive if=pflash,format=raw,unit=1,file=$OVMF_VARS \
  -drive format=raw,file=boot.img \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -device virtio-rng-pci \
  -nographic \
  -serial mon:stdio \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

`xtask qemu --arch aarch64`:
```
qemu-system-aarch64 \
  -machine virt -cpu max -m 4G -smp 4 \
  -bios $EDK2_AARCH64 \
  -drive format=raw,file=boot.img,if=virtio \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -device virtio-rng-pci \
  -nographic
```

`--gdb` adds `-s -S`.

## 8 Concurrency

`xtask` runs builds in parallel via Cargo's job scheduler. Image build serial post-build.

## 9 Test contract (frozen)

- `xtask kernel --arch x86_64` and `--arch aarch64` succeed clean checkout.
- `xtask user` builds.
- `xtask image` produces a `boot.img` whose hash matches across machines (with same toolchain).
- `xtask qemu` boots and prints "init started" within 3s.
- CI runs `xtask spec-lint` and `xtask doc-check`; both pass.

## 10 Failure modes

- Toolchain mismatch: xtask checks `rustc --version` vs `rust-toolchain.toml`; mismatch errors clearly.
- Missing UEFI firmware: xtask provides path hints (`OVMF_CODE`, `EDK2_AARCH64`).

## 11 Debug

`xtask qemu --gdb` + `gdb-multiarch` with kernel ELF + symbol-decoded klog.

## 12 Cross-spec

`07` (toolchain + targets), `29` (userspace), `36` (bootloader handoff), `40` (CI uses xtask).

