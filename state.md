# State 2026-05-11

## Branch
`F04-serial-getty` — PR #1010 open. HEAD `9f2fa00`.

## What shipped this run

1. **`bf8e5a5`** ungate LAPIC/GIC bring-up.
2. **`94ced16`** drop schedule_from_irq from timer ISR (cooperative-only).
3. **`6ac5a90`** batch ONLCR writes (single console_emit per NL-free run).
4. **`32d9a59`** bounded UART spin (drop on cap).
5. **`25fa9a3`** disable fbcon klog aux sink — **CAT WEDGE FIX**.
6. **`c6a26d0`** UART_DROPS atomic counter.
7. **`9f2fa00`** **dtrace framework** — structured probes via direct COM1 (gated `debug-trace`).

## CAT wedge — CLOSED 🎯

`drv_virtio_gpu::post_init::fbcon_flush_pixels` wedged the boot CPU on every klog emit through the fbcon aux sink. Disabling the sink unblocks the full boot through smokes → init → rcS → getty issue banner.

## Getty login-prompt stall — bisected to `boot_emit` on a specific `\r\n`

With the new dtrace framework, the kernel's causal chain through writev → File::write → ConsoleInode::write → console_emit → boot_emit is fully observable. After getty's `oxide Linux on /dev/ttyS0` issue lines, the trace consistently ends inside the LAST `boot_emit` call mid-`\r\n`:

```
[WV_IN=2][WV_IOV=1][WV_PRE_W][CW_IN=1][CW_OFL=5][CW_NL]<L\r
                                                       ^ wedge
```

Where `<` = boot_emit entered, `L` = lock_irqsave acquired, `\r` = first byte written. The matching `W` (write_bytes returned) marker never fires.

**What was ruled out** (tested directly via dtrace):
- THRE spin in `write_byte` — wedge persists with `SPIN_CAP=10K`, `100`, AND with NO spin/THRE check at all (`outb` only).
- BOOT_UART lock contention — single-CPU; no leak (try_lock fallback never fires `!LK!` marker).
- fbcon aux sink — disabled in `25fa9a3`.
- VEC_MSI softirq drain — disabled temporarily; same wedge.

**What this leaves**: the wedge is between `write_byte(\r)` returning and the loop iterating to `write_byte(\n)`. With write_byte being a single `outb` instruction, no iteration logic can wedge there at the kernel level. Strong remaining suspicion is **QEMU vCPU stalling on `outb` to a back-pressured chardev**, but earlier tests of disabling THRE poll didn't change behavior so this isn't conclusive.

### First task next session

Run the existing kernel build with the framework on and inspect QEMU at the wedge moment:

```sh
cargo run -p xtask -- image --arch x86_64 --features debug-boot,debug-trace
qemu_start arch=x86_64
qemu_run_until pattern="oxide Linux on /dev/ttyS0" timeout=30
# At this point we're inside the wedge.
qemu_interrupt
qemu_regs        # confirm RIP location
qemu_backtrace
qemu_mem addr=0xffffffff8112a000 length=8   # UART_DROPS
```

Other angles worth trying:
1. Switch QEMU's `-chardev stdio` to `socket` with explicit non-blocking. The mux+stdio combo in `tools/xtask/src/image_qemu.rs:364-365` may be where back-pressure shows up.
2. Try `OXIDE_QEMU_HEADLESS=1` + `-nographic` + alternative `-serial` configurations.
3. Hard-disable the `boot_emit` lock entirely (try_lock + emit, drop bytes when contended) — same effect as the `25fa9a3` precedent.

## Open work (carried)

- **Proper fbcon fix** — re-enable klog_sink without virtio-gpu wedge.
- **Display + input on GTK** — `OXIDE_QEMU_HEADLESS=1` skips GTK.
- **Real PTRACE_SINGLESTEP** — F49-F51 framework.

## Useful pointers

- **dtrace framework**: `kernel/src/debug_macros.rs:42-94`. Enable with `--features debug-boot,debug-trace`.
- Probe call sites: `kernel/src/syscalls/fs.rs:718` (sys_writev) + `kernel/src/dev/console.rs:84` (ConsoleInode::write).
- Existing tags: `WV_IN/IOV/PRE_W/OK/ERR/OUT`, `CW_IN/OFL/RUN/TAIL/NL/OUT/OUT_RAW`.
- To add new probes: `dtrace!(b"TAG")` for markers, `dtrace!(b"TAG", val)` for tag+u64.
- fbcon aux-sink (commented out): `kernel/src/lib.rs:662`.
- UART bounded spin + drop counter: `crates/arch/boot-x86_64/src/uart.rs:124-150`.
- UART_DROPS symbol: read via `nm <kernel-elf> | grep UART_DROPS`.
- Headless boot: `OXIDE_QEMU_HEADLESS=1 make qemu-x86`.
