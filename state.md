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

**SOLVED (commit b46d1725): KB→actual-load-base mapping.** QEMU loads
the arm64 Image 2 MiB ABOVE the RAM base (reserves low 2 MiB for the
DTB) → kernel at phys 0x4020_0000, not 0x4000_0000. The trampoline
hardcoded KP=0x4000_0000 + 1 GiB block, so code ran (PC-relative, offset
self-cancelled) but baked absolute `&str` pointers resolved 2 MiB before
the data → read zero (the procfs-smoke wedge). Fix: trampoline records
the real load base (`adrp _arm_image_start` → `SB_LOAD_BASE`) and maps
KB→load_base with **2 MiB L2 blocks** (load base is 2 MiB- not 1 GiB-
aligned); high-jump = phys−load_base+KB; memmap reserves [load_base,kend).
NOT the initrd (image loads fine — proven by an 'Y' header probe at boot).

**Self-boot now boots into USERSPACE**: PMM/GICv3/timer/user-AS/all
smokes pass, procfs-smoke ok, ext4 mounts, /bin/sh loads, **systemd
starts, getty/agetty run** (syscall trace shows openat/ioctl(TCGETS/
TIOCGWINSZ)/write/ppoll/clock_nanosleep + the XTGETTCAP terminfo query).

**REMAINING (next): NO GIC IRQs deliver on self-boot → no login.**
agetty wedges right after its XTGETTCAP terminal query (`P+q6E616D65`).
Root: `tick_poll_combined` (the timer-tick hook, kernel/src/lib.rs ~938)
does BOTH the UART-RX poll AND `vvar::publish` — so when the timer IRQ
stops, console input AND the userspace clock both freeze, and agetty's
input+timeout loop spins forever (idle-loop probe: ~10 iters then the
CPU never idles again → agetty is persistently runnable, looping).
**The real problem: no interrupts fire at all** — the boot diag prints
`uart-irq-fires before=0 after=0 delta=0` and `arm-timer: irq ticks=0`.
The GICv3 isn't delivering ANY interrupt from its QEMU reset state on
self-boot (Limine works because OVMF pre-configures the GIC at EL2).
FIXED this turn: the EL2-entry path (`virtualization=on`) used to hang
at MMU-enable; removing the `SCTLR_EL1=0x30d00800` set in the EL2 block
fixed that (committed) — but even with the EL2 block running
(ICC_SRE_EL2/CNTHCTL/CNTVOFF set), IRQs STILL don't fire. So it's NOT
ICC_SRE alone — it's the GICv3 distributor/redistributor/CPU-interface
enable sequence from reset (candidates: GICD.CTLR ARE/EnableGrp1,
GICR per-PPI/SPI IGROUPR+ISENABLER+IROUTER, ICC_IGRPEN1_EL1, ICC_PMR,
ICC_CTLR). NEXT: diff the kernel's GICv3 init (crates/kernel/arch-irq/
src/gic.rs) against what a from-reset GICv3 needs; add a post-GIC-init
breadcrumb reading ICC_IGRPEN1_EL1/ICC_SRE_EL1/GICD_CTLR to see which
enable didn't take. Use `virtualization=on` (EL2 entry) for the repro so
the EL2 regs are set. THEN reach login, REMOVE temp PL011 breadcrumbs
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
