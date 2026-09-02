# Boot debugging — making a silent boot talk

Status: LIVE. Owner: B1988.

For the case this exists to serve: two identical VMs boot the same image, one
completes, one never does, and the one that hangs produces nothing to diagnose
with.

## 1 The one-liner

```
make boot-debug-x86        # interactive, output on your terminal
make boot-debug-arm
make smoke-debug           # both arches, headless, serial log KEPT
```

`smoke-debug` writes `target/boot-logs/<arch>.log` (plus one file per attempt)
whether the boot passes or fails. A passing boot's early output is otherwise
deleted with the temp log, which is the wrong behaviour when the question is
"what did the slow one do differently", not "did it fail".

Add parameters without editing anything:

```
OXIDE_CMDLINE_EXTRA='panic=30 oops=panic loglevel=8' make boot-debug-x86
```

`OXIDE_CMDLINE_EXTRA` composes with the preset rather than replacing it.
`OXIDE_CMDLINE_DEBUG=1` is what the targets set; any caller can set it.

## 2 What the preset passes, and why each one

| Parameter | Effect |
|---|---|
| `earlycon` | Console up before device init. Without it nothing prints until the serial driver registers, ~3.4 s into boot. |
| `keep_bootcon` | Do not drop the boot console when the real one registers, so the handover window is not lost. |
| `initcall_debug` | Each init step prints its name BEFORE it runs, and its return value and duration after. |
| `ignore_loglevel` | Every record reaches the console regardless of level. |
| `printk.time=1` | Timestamp each line — the only way to tell a slow step from a stuck one. |
| `systemd.log_level=debug`, `systemd.log_target=console`, `systemd.journald.forward_to_console=1` | Service failures reach the same serial log instead of a journal the hung boot never writes. |

## 3 Reading the output

A hang names itself. The last line of the log is the step that never returned:

```
[3.612] calling  init_smp
[3.649] initcall init_smp returned 0 after 36317 usecs
[3.650] calling  init_runtime_subsystems      <- hung here if this is the last line
```

`entering initcall level: <name>` separates the phases (`early`, `runtime`,
`kthreads`, `rootfs`). Durations are microseconds, so a step that takes seconds
stands out without comparing timestamps by hand.

For a service that fails rather than a kernel step that hangs, look past
`rootfs::init` — everything after it is userspace, and the systemd parameters
above put its failures on the same wire.

## 4 The whole parameter surface

Honoured:

| Parameter | Notes |
|---|---|
| `earlycon` | Bare form resolves to the platform UART (8250 at COM1 on x86, PL011 on arm). |
| `earlycon=<name>[,io\|mmio\|mmio16\|mmio32\|mmio32be\|mmio32native,<addr>][,<baud>]` | `<name>` ∈ `uart`, `uart8250`, `ns16550`, `ns16550a`, `8250`, `pl011`. |
| `earlycon=<name>,0x<addr>[,<baud>]` | Bare address means memory-mapped. |
| `console=<name>,...` | Same grammar when `<name>` is a UART driver rather than a tty class. |
| `earlyprintk=serial[,ttyS<n>\|0x<port>][,<baud>][,keep]` | Also `ttyS<n>,<baud>` and `mmio32,0x<addr>,<baud>`. |
| `keep_bootcon` | Also the `keep` suffix on `earlyprintk=`. |
| `console=<dev>[,<baud><parity><bits><flow>]` | Repeated entries all register; the LAST backs `/dev/console`. |
| `loglevel=N`, `quiet`, `debug` | Later parameters win. A malformed value is ignored rather than installed. |
| `ignore_loglevel` | |
| `printk.time=<bool>` | |
| `printk.devkmsg=on\|off\|ratelimit` | Default here is `on`, not `ratelimit` — see §5. |
| `initcall_debug[=<bool>]` | |
| `panic=<n>` | Seconds before restart; `0` waits forever (default), negative restarts at once. |
| `oops=panic` | An unhandled kernel fault becomes a full panic instead of halting one CPU. |
| `init=`, `rdinit=` | |

Recognised and NOT honoured. Each prints `Unhonoured kernel parameter: <name>:
<what it needs>` at boot rather than being silently accepted:

`panic_on_warn`, `softlockup_panic`, `nmi_watchdog`, `hung_task_panic`,
`hung_task_timeout_secs`, `log_buf_len`, `no_console_suspend`, `slub_debug`,
`page_poison`, `debug_pagealloc`, `boot_delay`.

## 5 Behaviour worth knowing before it surprises you

- **`keep_bootcon` doubles output on aarch64.** The boot console and the real
  serial console drive the same PL011, so with both live every line appears
  twice. That is what keeping the boot console means; drop the parameter if the
  duplication is worse than the handover gap.
- **`printk.devkmsg` defaults to `on`, not `ratelimit`.** The rate limit is
  meant to exempt a privileged writer, and the writer's credentials do not
  reach the record ring here, so a default limit would drop the log daemon's
  own records.
- **The default boot line no longer passes `quiet`.** The parameter is honoured
  now; a line asking for silence while every consumer expects a talkative boot
  is a line that lies.
- **`panic=<n>` needs the power subsystem.** Before it comes up the panic path
  halts and keeps the text on screen regardless of the parameter, rather than
  announcing a restart that cannot happen.
- **A boot console drops bytes rather than wedging.** Every transmit poll is
  bounded; a back-pressured emulated UART truncates a line instead of turning a
  diagnosable hang into an undiagnosable one.

## 6 Where the pieces live

| Concern | Owner |
|---|---|
| Parsing every parameter | `crates/kernel/cmdline` — ungated, hosted-testable |
| Applying console/printk/panic policy | `crates/shared/bootparam/src/policy.rs` |
| Boot-console UART drivers | `crates/shared/bootparam/src/{uart8250,pl011,access}.rs` |
| Where a log line goes | `crates/shared/klog/src/{console,bootcon}.rs` |
| Init-step tracing | `crates/shared/klog/src/initcall.rs` |
| Panic reporting and `panic=` | `crates/shared/klog/src/oops.rs` |
| Composing the boot line | `tools/xtask/src/image_qemu/bootargs.rs` |
