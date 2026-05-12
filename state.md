# State 2026-05-12

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `e3360a5`.

## Headline

**Fully interactive Linux shell.** Real-libc busybox, real fork+exec, real ext4-backed readdir, real pipes, real `$PATH` expansion. Tested headless via socat-over-unix-socket:

```
oxide login: root
oxide:~# uname -a
Linux oxide 5.15.0-oxide #1 SMP PREEMPT oxide v0.1.0 x86_64 GNU/Linux
oxide:~# cat /etc/issue
oxide \s on \l
oxide:~# ls /bin | head
ash
awk
bare3
basename
busybox
cat
chmod
chown
clear
cp
oxide:~# id
uid=0(root) gid=0(root) groups=0(root)
oxide:~# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
oxide:~# ps
PID  USER  TIME COMMAND
...
4118 root  0:00 {fork-child} -sh
4124 root  0:00 {fork-child} ps
```

## Bug chain closed this session

1. **fbcon klog aux sink wedge** — earlier session, disabled at `kernel/src/lib.rs:662`.
2. **qemu-mcp pty consumer** — bypass via `OXIDE_QEMU_HEADLESS=1`.
3. **stdio chardev w/ piped stdin doesn't reach guest RBR** — use `OXIDE_QEMU_UART_SOCK=/tmp/oxide-uart.sock` + socat bridge (`tools/xtask/src/image_qemu.rs`).
4. **`set_tick_poll_hook` was inside `if started > 0`** — moved to unconditional `kernel_main` init so `tick_poll_uart` runs with `-smp 1` (`b44c54c`).
5. **Linker baked BSS into on-disk ELF** — moved `.bss` to be the last section in the RW PT_LOAD so `file_sz < mem_sz` again (`f5db8b4`). Kernel binary 91 MB → 23 MB.
6. **Stack builder argv/envp cap = 8** — bumped on-kernel-stack `Heapless256` cap to 256 + grew sp-fit check to 64 KiB (`75159cc`).
7. **Ext4 lookup of directories returned ENOENT** — `Ext4RootfsFs::lookup` now uses `lookup_inode_any`, and `Ext4StatInode` got a real `readdir` impl wired through `mount.read_file_block` + `iter_active` (`e3360a5`).

## Open work (next session)

- **`ps` displays kernel-issued TIDs (0xC0DE0001…) as huge u32 PIDs.** Cosmetic; the kernel should hand out small monotonic vpids for kernel tasks too, or `/proc/N/status` should fold the kernel-private TID. Easy fix.
- **`-mon chardev=ser0` regressed in interactive mode** when chardev string became conditional. Add `-monitor none` for headless and keep `-mon chardev=ser0` for interactive — verify by hand. Low priority; headless works.
- **Re-enable fbcon klog aux sink** after debugging `fbcon_flush_pixels` virtio-gpu submit wedge (currently disabled at `kernel/src/lib.rs:662`). Wanted for GTK-mode display.
- **ARM lockstep — login input still broken.** `make qemu-arm` reaches `oxide login:` but typed bytes don't echo. Empirical IRQ-probe (reverted) showed *no IRQs fire on the dispatcher post-PL011-setup* — neither CNTV (INTID 27) nor PL011 (INTID 33). gic.rs already calls `tick_poll` for INTID 27 (`58ad285`). What still needs to happen, in order:
  1. Verify CNTV timer is actually re-armed post-smoke. Adding `arch_irq::gic::enable_intid(27)` + `hal_aarch64::timer::timer_periodic(50_000)` from `spawn_init_from_rootfs_arm()` (kernel/src/smoke/elf_arm.rs) BROKE boot in trial — kernel froze at "pmm: ready". Suggests one of those calls panics or wedges in that context. Try guarded under `pmm::user_as` lock release or move to caller of `spawn_init_from_rootfs_arm` after schedule unwinds.
  2. If timer ticks fire but RX still empty, check `tty::live::tick_poll_uart` ARM PL011 read path: `PL011_BASE_VA` may have been clobbered post-AS-activation.
  3. PR #1010 should still merge — x86 work is the headline. ARM lockstep closes in a follow-up PR.
- **`docs/v2/` cleanup of stale state.md history** — git log has the trail; state.md is short.

## Test harness

`/tmp/runtest6.sh` reproduces the interactive session above. Pattern:

```
OXIDE_QEMU_HEADLESS=1 OXIDE_QEMU_UART_SOCK=/tmp/oxide-uart.sock make qemu-x86 &
(sleep 15; printf 'root\n'; sleep 3; printf 'ls /\n'; ...) | socat - UNIX-CONNECT:/tmp/oxide-uart.sock
```

## Commits on this branch

- `b44c54c` fix(tty): install tick_poll_uart hook unconditionally — login RX works.
- `3d91393` fix(boot): heap/disk/RAM bumps — reverted by f5db8b4 after linker fix.
- `f5db8b4` fix(link): move .bss last so on-disk ELF doesn't include BSS bytes.
- `75159cc` fix(exec): bump argv/envp on-kernel-stack vec 8→256, stack check 4K→64K.
- `e3360a5` fix(ext4): open + readdir on directories — `ls /` now lists rootfs.
