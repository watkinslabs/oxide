# State 2026-05-12

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `3d91393`.

## Headline

**Interactive shell reached.** `oxide login: root` accepts, busybox login spawns `/bin/sh`, the prompt `oxide:/#` appears, and shell builtins respond to typed input:

```
oxide login: root
login[4118]: root login on 'ttyS0'
oxide:/# echo HELLO_FROM_OXIDE
HELLO_FROM_OXIDE
oxide:/#
```

## Bug chain just closed

1. **fbcon klog aux sink wedge** — `25fa9a3` (earlier session): `fbcon_flush_pixels` was looping forever in the virtio-gpu submit path on every klog call. Disabled the aux sink at `kernel/src/lib.rs:662`.
2. **qemu-mcp pty consumer** masked apparent kernel hangs late in boot. Bypass with `OXIDE_QEMU_HEADLESS=1` (no GTK, no GDB attach).
3. **stdio chardev w/ piped stdin** — QEMU's `-chardev stdio` doesn't reliably forward bytes from a pipe into the guest UART RBR. Solved by `OXIDE_QEMU_UART_SOCK=/tmp/oxide-uart.sock` + socat bridge (in `tools/xtask/src/image_qemu.rs`).
4. **`set_tick_poll_hook` was inside `if started > 0`** in `kernel/src/lib.rs` — with `-smp 1` (default headless config) the hook stayed null, so `tick_poll_uart` never ran, so COM1 RBR bytes piled up with LSR.DR=1 forever. Moved the install to unconditional `kernel_main` init (`b44c54c`).
5. **Heap too small for ELF segment staging.** `crates/kernel/exec/src/lib.rs:230` allocates `vec![0u8; mem_sz]` per LOAD segment (file + BSS). For busybox the RW segment ran 1.05 MB and `STATIC_HEAP_SIZE=32 MiB` couldn't satisfy it (fragmented). Bumped to 64 MiB (`3d91393`).
6. **Linker bakes BSS into on-disk ELF** with `file_sz = mem_sz` on the RW PT_LOAD, so 64 MiB heap pushed `oxide-x86_64` to ~85 MB. Bumped disk image 64→256 MiB and QEMU `-m` 256→512 MiB so Limine's high-memory loader doesn't OOM. **Proper fix: linker script — make BSS `file_sz=0`. Followup.**

## Test harness for shell-level interaction

`/tmp/runtest2.sh` — launches QEMU headless with unix-socket chardev, drives shell via socat with timed `printf` lines. Verified:
- `echo` (builtin) returns immediately and prints the expected output.
- `uname -a`, `ls /` (need fork+exec) currently produce no visible output — separate followup (fork-exec of /bin/busybox from running shell).

## Open work

- **Strip BSS from on-disk ELF.** Edit linker script (`link/x86_64-unknown-oxide-kernel.ld` and aarch64 sibling) so the RW PT_LOAD has `file_sz < mem_sz`. Then we can revert disk/RAM bumps.
- **fork+exec from shell.** `uname`, `ls`, etc. run `/bin/busybox <applet>` via fork+exec; output goes silently somewhere. Trace from `sys_execve` for the second forked child.
- **/root home dir missing.** Trivial: add `/root` directory to rootfs build at `tools/xtask/src/main.rs`.
- **`fbcon` klog aux sink** still disabled at `kernel/src/lib.rs:662`. Re-enable after debugging the virtio-gpu submit path.
- **ARM lockstep.** Confirm `make qemu-arm` reaches `oxide:/#` on aarch64 with the same fixes; should — the hook install path covers both arches, and the socket chardev applies to x86 only.

## Useful pointers

- Headless test loop: `/tmp/runtest2.sh` (see above).
- UART RX poll hook: `kernel/src/lib.rs:~451` (unconditional install just before SMP bring-up).
- ELF segment staging alloc: `crates/kernel/exec/src/lib.rs:230`.
- Heap size: `crates/shared/kalloc/src/lib.rs:39` `STATIC_HEAP_SIZE`.
- Disk image size: `tools/xtask/src/image_qemu.rs:148`.
- QEMU RAM: `tools/xtask/src/image_qemu.rs` `-m` flag.

## Commits this branch

- `bf8e5a5`..`c3c6e90` — earlier session (CAT wedge fix, dtrace, etc.).
- `4fe6ba0` — doc(state).
- `607cfa5` — fix(qemu): drop mux=on under HEADLESS.
- `b44c54c` — **fix(tty): install tick_poll_uart hook unconditionally — login RX works**.
- `3d91393` — **fix(boot): heap/disk/RAM bumps — interactive shell reached**.
