# Session hand-off

## Headline
Loop goal (user-set): **fix systemd, getty respawn, rip out Limine, fix
display (`docs/55`)**. #1+#2 DONE+merged. #3 (Limine) substantially
built — arm self-bootstrap trampoline boots through device init; #4
(display) not started. On `main` for #1/#2; WIP on `F376-arm-selfbootstrap`.

## Done + merged this session
- #1520 (26 R79) + #1521 (F375): cgroup.events `IN_MODIFY` notification.
- #1522 (B54): `waitid` honors `WNOWAIT` (peek, no reap) — killed ECHILD loop.
- #1523 (B55): **`PIDFD_GET_INFO` ioctl** — the getty-respawn fix.
  systemd verifies the forked getty via this ioctl; ENOTTY made it
  SIGKILL the getty. getty respawn now PASSes x86-Limine(49s),
  arm-Limine(49s), x86-GRUB(57s).

## #3 Rip out Limine — arm self-bootstrap (branch `F376-arm-selfbootstrap`, pushed, NOT merged)
x86-GRUB self-boot already works (login+respawn). Arm was Limine-only;
this branch adds a from-scratch arm64 boot path (mirrors x86 `mb2.rs`).

**WORKS (verified via `-kernel <Image>`):** arm64 Image header + MMU
trampoline (`crates/arch/boot-aarch64/src/selfboot.rs`): EL2→EL1 drop
(+ICC_SRE_EL2), TTBR0 identity + TTBR1 higher-half/HHDM (1 GiB blocks,
full 512 GiB HHDM), MAIR/TCR/SCTLR, MMU enable, higher-half jump →
shared `_start`. HHDM=`0xFFFF_8000_0000_0000`; klog via PL011 (not
semihosting); memmap from DTB `/memory` (`dtb::first_memory_region`),
kernel+DTB carved. **PMM(829MiB)/GICv3/arm-timer/user-AS + all
MMU/user smokes pass.** Linker `AT()` (KERNEL_PHYS=0x4000_0000) → flat
Image via objcopy; Limine arm UNREGRESSED (login 49s).

**REMAINING (next session, start here):** boot stops in the boot-smoke
block (`kernel_main`, kernel/src/lib.rs ~483-488). Breadcrumb bisect
(`klog::write_raw(b"[BC]...")` after each smoke) showed `dev-misc-smoke:
ok` prints but NO `[BC] post-procfs-smoke` → hangs at/around
`procfs::smoke_test()` (line 485). BUT feature-dependent: a `debug-all`
build progresses further (reaches the `ksched` smoke, past line 488),
while `debug-boot,debug-syscall` hangs — BUT that was a stale-kernel
compare; the ksched smoke (debug-sched) runs EARLIER than the
boot-smoke block and is where debug-all deadlocks (known artifact), so
debug-all never reaches procfs-smoke. On the CURRENT kernel the default
boot genuinely hangs at `procfs::smoke_test` (line 485, unconditional).

**ROOT CAUSE (fully diagnosed via runtime HHDM probes):** the kernel
Image is 129 MiB because the **128 MiB rootfs is embedded** (include_bytes
→ .rodata). QEMU's `-kernel` flat-Image load does NOT make the whole
129 MiB Image resident: runtime probes of physical RAM via HHDM showed
`@0x40000000=0` (image start — zero despite the kernel having BOOTED
from there), `@0x44000000=0x20ef` (has data), `@0x48000000..=0` (zero).
So `/proc/version` (a `&str` whose data lives at ~135 MB into the image,
present in the Image file at the right offset, VMA correctly mapped by
the 1 GiB kernel block — verified) reads ZERO because that physical RAM
was never loaded. NOT relocations (0 on both arches), NOT mapping (HHDM
read of the same phys also 0), NOT objcopy (string IS in the Image).
**THE FIX (Linux way): split the rootfs out as an initrd.** Stop
`include_bytes`-ing the 128 MiB rootfs into the kernel; instead pass it
via QEMU `-initrd <rootfs.img>` (and U-Boot/GRUB initrd), and have the
kernel read the initrd phys range from the DTB `/chosen`
(`linux,initrd-start`/`-end`) on the self-boot path (Limine path keeps
the embedded blob, or also moves to a module). Kernel shrinks to
~1.5 MB and loads cleanly. THEN reach login (default boot), REMOVE temp
PL011 breadcrumbs
(A/EL-digit/B..H in selfboot.rs + G/H in boot-aarch64/lib.rs
`_start_rust`), wire `xtask` to objcopy the Image + a `qemu-arm`
self-boot target, switch defaults, delete Limine, lockstep both
arches, PR+merge.

### Repro (arm self-boot, headless)
```
cargo run -p xtask -- kernel --arch aarch64 --features debug-boot,debug-vmm,debug-syscall
rust-objcopy -O binary target/aarch64-unknown-oxide-kernel/release/oxide-aarch64 /tmp/oxide-aarch64.Image
qemu-system-aarch64 -M virt,gic-version=3,its=on -cpu cortex-a72 -m 2G \
  -kernel /tmp/oxide-aarch64.Image -nographic -no-reboot \
  -semihosting-config enable=on,target=native
```
GIC MUST be `gic-version=3,its=on` (kernel expects GICv3). QEMU enters
at **EL1** (breadcrumb shows `A1B…`), so the EL2 block is skipped —
fine (matches Limine). `debug-all` deadlocks at the ksched smoke (known
pre-existing artifact, not a self-boot bug) — use the feature set above
(no `debug-sched`) to see past it.

## #4 Display (`docs/55-console-color-font.md`, registered in MANIFEST)
Not started. fbcon font data is valid IBM-VGA 8x16; "not even a font"
is a framebuffer format/geometry/flush mismatch — needs visual capture
(qemu screenshot). docs/55 stage A = wire `KDFONTOP` for PSF + per-VT
binding.

## First command next session
```
git checkout F376-arm-selfbootstrap   # continue arm self-boot to login
# then run the repro above and localize the post-dev-misc-smoke hang
```

## Notes
- `getty-respawn.md` = scratch (untracked, deletable).
- NEVER block on AskUserQuestion in a /loop (see auto-memory) — grind all goals.
- `release_ctty_if_leader` POSIX ctty-release was tried+reverted (pidfd alone fixed respawn).
