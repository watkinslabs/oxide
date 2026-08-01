# x86_64 GS-base: ring-transition inventory, `ARCH_SET_GS` blocker, and a live hole

Status: ANALYSIS (B1638). No code change in this lane.

## 1 Why this exists

`arch_prctl(ARCH_SET_GS/ARCH_GET_GS)` answers EINVAL. The reason is the
no-swapgs entry model: GS base is the kernel per-CPU area at all times,
including in ring 3, so there is no register left to carry a user GS base.
This file records the full transition inventory a `swapgs` conversion must
cover, names the site that blocks it today, and records a security defect the
inventory surfaced.

## 2 Ring-transition inventory

| # | Site | File | GS use | Mode mix |
|---|---|---|---|---|
| E1 | `oxide_syscall_entry` | `hal-x86_64/src/syscall.rs` | `gs:[16]`, `gs:[8]` in the FIRST two instructions | user only |
| E2 | `oxide_fault_common`, reached from `oxide_vec_0..31` + `oxide_vec_default` | `hal-x86_64/src/fault/stubs.rs` | none in the stub; the Rust it calls reads per-CPU | user AND kernel |
| E3 | `oxide_irq_common`, reached from 19 `oxide_irq_vec_*` heads | `hal-x86_64/src/irq.rs` | `gs:[24]` (hardirq-stack top) | user AND kernel |
| X1 | `sysretq` | `syscall.rs` | — | to user |
| X2 | `iretq` on the non-SYSRET syscall tail (label `3:`) | `syscall.rs` | — | to user |
| X3 | `iretq` at the end of `oxide_fault_common` | `fault/stubs.rs` | — | to user AND kernel |
| X4 | `oxide_irq_resume_user` `iretq` | `irq.rs` | — | to user AND kernel |

X4 has a second caller: `oxide_finish_switch_tramp` (`context.rs`) jumps into
it from the first-run scaffold `Context::new_*_with_irq_frame` writes, so a
freshly forked task reaches ring 3 through X4 without ever passing E1–E3.

Supporting state a conversion also has to touch: `Context::switch`
(`context.rs`, currently saves/restores `IA32_FS_BASE` only), BSP + AP
per-CPU setup (`X86CpuOps::set_percpu_base`, `arch-irq/src/smp_x86.rs`),
`live::spawn` fork seeding, the exec reset, and `101_ptrace/frame.rs`, which
today hard-rejects a non-zero `gs_base` with EIO.

## 3 The blocking site

**`oxide_fault_common` — specifically the four IST-routed vectors it shares
with the other 29.** `idt::install_ist_gates` routes `#DB`(1), NMI(2),
`#DF`(8) and `#MC`(18) onto per-CPU IST stacks. Those are exactly Linux's
paranoid vectors: each can arrive while CPL is already 0 but GS still holds
the user base — the one-instruction window between the exit-path `swapgs` and
`sysretq`/`iretq` — so the `testb $3, CS(%rsp)` swapgs that serves the other
29 vectors is wrong for them, and oxide has one shared entry and one shared
exit for all 33.

Linux resolves this two ways and **oxide can use neither as-is**:

1. *Sign test on `MSR_GS_BASE`* — valid only when userspace cannot write a
   kernel-looking GS base. Upstream states the constraint directly: without
   FSGSBASE the kernel enforces that a negative GSBASE indicates kernel
   GSBASE; **with FSGSBASE no assumptions can be made about the GSBASE value
   when entering from user space**. oxide runs with `CR4.FSGSBASE = 1` (see
   §4), so the sign test is user-forgeable here.
2. *FSGSBASE `rdgsbase` + reload* — needs the kernel per-CPU base recovered
   WITHOUT GS. Linux gets it from the CPU number in a GDT segment limit, then
   indexes a per-CPU offset table. oxide has no equivalent: `sync::percpu`
   derives everything from GS_BASE, `IA32_TSC_AUX` is never programmed, and
   there is no CPU-number-to-base table.

So the prerequisite for `ARCH_SET_GS` is not the `swapgs` insertion itself —
that is mechanical at E1/E3 and a CS test at E2/X3/X4. It is (a) a
GS-independent per-CPU base lookup, and (b) splitting the shared fault path
into a regular and a paranoid variant with a saved restore flag, since
paranoid exit cannot be the same unconditional tail.

## 4 Defect found by the inventory: user `wrgsbase` overwrites the kernel per-CPU base

`X86CpuOps::set_percpu_base` installs the per-CPU area with `wrgsbase`, which
requires `CR4.FSGSBASE = 1`; the AP path sets that bit explicitly and the BSP
inherits it from the bootloader (a BSP without it would `#UD` on the first
`set_percpu_base` and never boot).

With `CR4.FSGSBASE = 1` and no `swapgs`, ring 3 may execute `wrgsbase` and
replace the base that ring 0 reads for every per-CPU access. The next
`syscall` on that CPU runs `mov gs:[16], rsp` / `mov rsp, gs:[8]` against a
user-chosen base: an arbitrary kernel-mode write followed by a stack pivot to
a user-chosen kernel RSP. `gs:[24]` (hardirq-stack top) and every
`sync::percpu` accessor are reachable the same way.

Two mutually exclusive fixes:

* **Close it** — clear `CR4.FSGSBASE` and change `set_percpu_base` to write
  `IA32_GS_BASE` by `wrmsr` instead of `wrgsbase`. Small; removes the
  `rd/wrgsbase` instructions from userspace entirely. `ARCH_SET_GS` stays
  EINVAL.
* **Convert to swapgs** (§2, §3) — then a user `wrgsbase` writes the USER GS
  base, which is precisely `ARCH_SET_GS` semantics, and entry `swapgs`
  restores the kernel base. Closes the hole and implements the sub-code.

Either way this is its own lane: it is boot-critical, needs a real boot on
both arches, and does not belong in a syscall-ABI change.
