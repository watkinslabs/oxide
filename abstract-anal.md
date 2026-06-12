# asm outside `crates/arch/**`

Scope: code-only inventory of assembly outside `crates/arch/**`. Excludes docs / changelog mentions. Search surface: Rust `asm!/global_asm!`, C `__asm__`, standalone `*.S`.

## Summary

| Bucket | Files | Notes |
|---|---:|---|
| Production kernel paths | 16 | strongest candidates for HAL/arch abstraction |
| Smoke / diagnostics | 6 | lower priority but still outside boundary |
| Userspace raw asm | 2 | should move to portable shim/wrapper layer |
| Standalone asm files | 2 | arch-local but not under `crates/arch/**` |

## Highest-priority moves

1. `crates/drivers/*` port-I/O helpers
2. `crates/kernel/arch-irq/*`
3. `crates/kernel/sched/src/live/schedule.rs`
4. `crates/kernel/power/src/lib.rs`
5. `crates/kernel/syscalls/src/hwrng.rs`
6. `userspace/dynlink/dynlink.c` + `userspace/hello_dyn/hello_dyn.c`

## Production kernel / driver inventory

| File | Lines | Kind | What it does | Likely abstraction target |
|---|---|---|---|---|
| `crates/drivers/drv-uart-16550/src/lib.rs` | 47, 54 | Rust inline asm | x86 `in` / `out` port I/O | HAL x86 port-I/O helper trait/module |
| `crates/drivers/drv-ps2-keyboard/src/lib.rs` | 95, 102 | Rust inline asm | x86 i8042 port I/O | same shared x86 port-I/O helper |
| `crates/drivers/drv-virtio-net/src/legacy.rs` | 136, 147, 158, 170, 183, 196 | Rust inline asm | x86 legacy virtio PCI port-I/O reads/writes | same shared x86 port-I/O helper |
| `crates/shared/kmacros/src/lib.rs` | 87 | Rust inline asm | debug-trace COM1 byte emit via `out` | HAL trace / early-console byte sink |
| `crates/kernel/arch-irq/src/smp_x86.rs` | 116, 118, 174, 193, 410 | Rust inline asm + `global_asm!` | CR4.FSGSBASE enable, `sti`, AP wait `pause`, full AP trampoline | move file or trampoline under `crates/arch/hal-x86_64` / arch boot crate |
| `crates/kernel/arch-irq/src/lapic.rs` | 134, 136, 177, 179, 389, 468, 485, 569 | Rust inline asm | IRQ open/close, pause spin, `rdmsr/wrmsr` | x86 HAL CPU/LAPIC/MSR helpers |
| `crates/kernel/arch-irq/src/gic.rs` | 150, 211, 255, 561, 578, 626, 663, 679, 681 | Rust inline asm | GIC sysregs, SGI send, IAR/EOI, timer reload, SPSR/DAIF access | arm HAL IRQ/GIC/timer helpers |
| `crates/kernel/kmain/src/kmain.rs` | 97, 99 | Rust inline asm | BSP CR4.FSGSBASE enable | x86 HAL CPU helper |
| `crates/kernel/fs/src/ptrace.rs` | 105, 142 | Rust inline asm | arm `MDSCR_EL1` single-step enable/disable | arm HAL ptrace/debug-reg helper |
| `crates/kernel/mm-pmm/src/user_as/signal.rs` | 253, 277, 297 | Rust inline asm | terminal halt, read `sp_el0`, arm fault-stop | HAL fault / terminal-stop helper |
| `crates/kernel/power/src/lib.rs` | 73, 76, 93, 107, 132, 144 | Rust inline asm | halt, reset, power-off on x86/arm | HAL power/reboot interface |
| `crates/kernel/sched/src/live/schedule.rs` | 90, 98, 113, 117, 538, 543 | Rust inline asm | irq save/restore, idle wait | HAL irq-mask guard + arch idle primitive |
| `crates/kernel/syscalls/src/059_execve.rs` | 494 | Rust inline asm | arm `TPIDR_EL0 = 0` on exec | arm HAL TLS register helper |
| `crates/kernel/syscalls/src/128_rt_sigtimedwait.rs` | 89 | Rust inline asm | x86 `sti; pause; cli` wait window | HAL wait-for-interrupt/poll primitive |
| `crates/kernel/syscalls/src/130_rt_sigsuspend.rs` | 29 | Rust inline asm | x86 `sti; pause; cli` wait window | same primitive |
| `crates/kernel/syscalls/src/hwrng.rs` | 42, 62, 89 | Rust inline asm | x86 `rdrand`; arm `RNDR` and feature probe sysreg read | HAL RNG capability + read API |
| `crates/kernel/pci-boot/src/lib.rs` | 667, 670, 675, 702, 830, 835, 857, 860 | Rust inline asm | diagnostic IRQ unmask/remask windows during PCI/MSI bring-up | HAL irq-mask scope / test helper |

## Smoke / diagnostics inventory

| File | Lines | Kind | What it does | Likely abstraction target |
|---|---|---|---|---|
| `crates/kernel/smoke/src/userspace.rs` | 227, 249 | Rust inline asm | x86 `iretq` drop-to-user, terminal `hlt` | x86 HAL user-entry helper + halt helper |
| `crates/kernel/smoke/src/userspace_arm.rs` | 83, 162 | Rust inline asm | arm terminal `wfi`, EL0 entry via `eret` | arm HAL user-entry helper + halt helper |
| `crates/kernel/smoke/src/preempt.rs` | 47, 54, 90, 94, 98, 141, 144 | Rust inline asm | IRQ mask windows, timer disable, idle park | HAL preempt/test helpers |
| `crates/kernel/smoke/src/elf.rs` | 99, 112 | Rust inline asm | x86 boot-time IRQ enable + idle wait | HAL idle/irq helpers |
| `crates/kernel/smoke/src/elf_arm.rs` | 254, 258, 291, 416, 464 | Rust inline asm | arm IRQ mask windows, idle wait, `TPIDR_EL0 = 0` | HAL idle/irq/TLS helpers |
| `crates/kernel/smoke/src/device_map.rs` | 106, 110, 513, 515, 574, 580, 581, 601, 605, 611, 612, 613 | Rust inline asm | x86/arm timer-IRQ diagnostics and sysreg reads | HAL diag helpers |
| `crates/kernel/smoke/src/canary.rs` | 61, 119, 201, 209, 247, 251, 255, 298, 302 | Rust inline asm | context-switch canary, IRQ windows, terminal halt | HAL diag + halt helpers |

## Userspace raw asm inventory

| File | Lines | Kind | What it does | Likely abstraction target |
|---|---|---|---|---|
| `userspace/hello_dyn/hello_dyn.c` | 20, 27, 35-45 | C inline asm | raw syscall wrappers for x86_64 + aarch64 | replace with shared portable `_start` / syscall wrapper per `userspace/shared/oxide_start.h` |
| `userspace/dynlink/dynlink.c` | 65-135, 639, 658 | C inline asm + file-scope asm | syscall wrappers plus arch-specific `_start` entry stubs | move to shared startup/syscall shim layer; keep arch entry in one dedicated wrapper file if still needed |

## Standalone asm files

| File | Kind | What it does | Likely abstraction target |
|---|---|---|---|
| `vdso/vdso-x86_64.S` | standalone x86 asm | vDSO entrypoints (`clock_gettime`, `gettimeofday`, `time`, `getcpu`, `clock_getres`) | keep arch-specific, but move under an explicit arch-owned subtree |
| `vdso/vdso-aarch64.S` | standalone arm asm | arm vDSO entrypoints and syscall fallbacks | same |

## Notes by cluster

### `crates/kernel/arch-irq/*`

This is the biggest concentration of non-HAL asm outside the arch tree. It includes:

- x86 AP trampoline in `smp_x86.rs`
- x86 MSR/CR4/LAPIC helpers in `lapic.rs` / `smp_x86.rs`
- arm GIC sysreg access in `gic.rs`

This looks like the first structural cleanup target: either move these files under `crates/arch/**` or shrink them to arch-neutral orchestration that only calls HAL hooks.

### Driver port-I/O

`drv-uart-16550`, `drv-ps2-keyboard`, and `drv-virtio-net` each embed their own x86 port-I/O asm. Those should collapse to one x86 HAL API (`inb/inw/inl/outb/outw/outl`) so drivers stop carrying raw instructions.

### Scheduler / wait-state asm

`sched`, `power`, `syscalls/*sigtimedwait*`, and several smoke files each open/close IRQ windows or execute idle instructions directly. Those should likely collapse into a small arch API:

- save/disable IRQ
- restore IRQ
- idle once
- halt forever
- brief interruptible wait

### TLS / sysreg one-offs

`execve.rs`, `ptrace.rs`, `hwrng.rs`, `mm-pmm/src/user_as/signal.rs`, and parts of `gic.rs` are small but important one-off sysreg uses. Those are good candidates for narrow HAL helpers rather than broad file moves.

### Userspace asm

Both userspace hits are exactly the kind of raw per-arch assembly the repo notes call out as undesirable in `.c` sources. These should be consolidated behind one shared startup/syscall abstraction instead of open-coded per program.

## Likely fix order

1. unify x86 port-I/O helpers
2. move or abstract `crates/kernel/arch-irq/*`
3. add HAL irq-mask / idle primitives, then delete duplicated `sti/cli/daif*/hlt/wfi/pause`
4. add HAL helpers for power, TLS register writes, ptrace debug regs, and hw RNG
5. remove userspace inline asm in favor of shared wrappers
6. relocate vDSO / trampoline asm into explicit arch-owned directories
