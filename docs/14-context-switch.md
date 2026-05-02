# 14 Context Switch

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`07`,`08`,`09`. Provides:`13`,`20`,`21`.

Per-arch ctxsw = one `.S` ≤50 lines saving exactly callee-saved + IP + SP + TLS-base. ABI-doc-line-by-line reviewed. Forever-running register-canary harness. No inline asm. No `#[naked]` Rust. One `.S`/arch with one extern symbol.

## 1 Purpose

Switch CPU exec from one kernel-stack ctx to another:
- Save outgoing callee-saved GP regs.
- Save outgoing SP.
- Load incoming SP.
- Load incoming callee-saved.
- Return to incoming saved IP.

NOT handled here:
- FPU/SIMD: lazy, §6.
- PT switch: caller (`13§8`).
- Per-CPU base reg update: per-CPU not per-task; caller.
- Userspace regs: saved/restored by syscall/IRQ entry, not ctxsw.

## 2 Inputs/outputs

- Deps: `Context` trait (HAL), `Task` (`13§5`).
- Provides: scheduler.
- HW: GP regs, SP, IP.

## 3 Frozen invariants

1. Save-set completeness: every ABI-callee-saved reg preserved.
2. Save-set minimality: NO ABI-caller-saved reg saved (compiler spills across the call).
3. SP atomicity: between SP-write and SP-read, no instr leaves kernel "no-stack".
4. Single-symbol surface: one `oxide_context_switch` per arch; identical sig.
5. No alloc/log/print: pure register dance. Called w/ RQ lock held; sleeping impossible.
6. Reentrancy: nested ctx (preempted scheduler) ok; touches only the two passed `Context` records.
7. No clobber outside ABI: no flags-with-meaning, no segment selectors.

## 4 Public ifc

```rust
pub trait Context: Sized {
  fn new_kernel(stack_top:*mut u8, entry:extern "C" fn(usize)->!, arg:usize) -> Self;
  fn new_user(stack_top:*mut u8, user_ip:u64, user_sp:u64) -> Self;

  // # SAFETY: prev,next valid Context records; next's saved stack valid kernel stack with valid return frame; preempt disabled; RQ lock held by caller (released by next thread post-switch).
  // # C: O(1)   # Ctx: process|irq-return path; preempt-off
  unsafe fn switch(prev:*mut Self, next:*const Self);
}
```

Per-arch impls: `hal-x86_64::Context`, `hal-aarch64::Context`. Single asm symbol wired to `Context::switch`.

## 5 x86_64

### 5.1 Save-set per SysV AMD64 ABI v1.0 §3.2.3

Callee-saved: `rbx`,`rbp`,`r12`,`r13`,`r14`,`r15`,`rsp` (implicit by switching). RFLAGS.DF must be clear for SysV (kernel never sets).

Saved here: above + `rsp`. `rip` lives on saved stack at `rsp` (call/ret mechanism).

Not saved: `rax,rcx,rdx,rsi,rdi,r8..r11` (caller-saved); `XMM0..XMM15` (caller-saved + kernel doesn't use); MXCSR/x87 ctrl (Rust kernel doesn't touch); CS/SS/DS/ES (kernel-fixed); FS/GS *base* (per-CPU/per-task, saved separately by syscall entry).

### 5.2 Struct

```rust
#[repr(C)]
pub struct ContextX86_64 { rsp:u64, rbp:u64, rbx:u64, r12:u64, r13:u64, r14:u64, r15:u64, fs_base:u64 }
```
`rip` not in struct; lives on saved stack.

### 5.3 Asm (`crates/hal-x86_64/src/context_switch.S`)

```asm
.intel_syntax noprefix
.section .text
.globl oxide_context_switch
.type  oxide_context_switch, @function
# void oxide_context_switch(ContextX86_64 *prev /* rdi */, const ContextX86_64 *next /* rsi */);
oxide_context_switch:
    mov  [rdi + 0x00], rsp
    mov  [rdi + 0x08], rbp
    mov  [rdi + 0x10], rbx
    mov  [rdi + 0x18], r12
    mov  [rdi + 0x20], r13
    mov  [rdi + 0x28], r14
    mov  [rdi + 0x30], r15
    # fs_base saved/restored by syscall entry, not here.
    mov  rsp, [rsi + 0x00]
    mov  rbp, [rsi + 0x08]
    mov  rbx, [rsi + 0x10]
    mov  r12, [rsi + 0x18]
    mov  r13, [rsi + 0x20]
    mov  r14, [rsi + 0x28]
    mov  r15, [rsi + 0x30]
    ret                       # pops new rip from new stack
.size oxide_context_switch, . - oxide_context_switch
```
18 lines incl labels+comments; under ≤50 budget.

### 5.4 Bring-up

```rust
// Prepare stack so first ret jumps to trampoline_kernel; saved callee-saved carries entry+arg.
*sp.offset(-1) = trampoline_kernel as u64;
ctx.r12 = entry as u64; ctx.r13 = arg as u64;
```
```asm
trampoline_kernel:  mov rdi, r13; jmp r12     # arg in rdi, jump entry; never returns
```

### 5.5 Syscall/IRQ user-state save is separate

User regs (RAX..R15, RFLAGS, FS_BASE, GS_BASE for KPTI swap, RIP, RSP, CS/SS) saved by syscall/IRQ entry asm in `20`. That = user state path. This = kernel state path between two kernel threads. Two distinct save sets.

Timer fires while user thread running:
1. IRQ entry saves user `pt_regs` to IRQ stack.
2. Sched picks new task.
3. `Context::switch` saves/loads kernel state.
4. IRQ exit (eventual, when target thread returns to user) restores user state.

## 6 aarch64

### 6.1 Save-set per AAPCS64 IHI 0055D §5.1.1

Callee-saved: `x19..x28`,`x29` (FP),`x30` (LR),`sp`. `q8..q15` callee-saved when present (kernel doesn't use FPSIMD; §6 lazy).

Not saved: `x0..x18` (caller-saved); `v0..v31` (lazy `§6`); pstate flags; `tpidr_el0` (saved separately by syscall entry).

### 6.2 Struct

```rust
#[repr(C)]
pub struct ContextAArch64 {
  sp:u64,
  x19:u64, x20:u64, x21:u64, x22:u64,
  x23:u64, x24:u64, x25:u64, x26:u64,
  x27:u64, x28:u64, x29:u64,
  lr:u64,           // x30
  tpidr:u64,        // user TLS base
}
```

### 6.3 Asm (`crates/hal-aarch64/src/context_switch.S`)

```asm
.section .text
.globl oxide_context_switch
.type  oxide_context_switch, %function
// void oxide_context_switch(ContextAArch64 *prev /* x0 */, const ContextAArch64 *next /* x1 */);
oxide_context_switch:
    mov  x9, sp
    str  x9,         [x0, #0x00]
    stp  x19, x20,   [x0, #0x08]
    stp  x21, x22,   [x0, #0x18]
    stp  x23, x24,   [x0, #0x28]
    stp  x25, x26,   [x0, #0x38]
    stp  x27, x28,   [x0, #0x48]
    stp  x29, x30,   [x0, #0x58]
    // tpidr saved/restored by syscall entry, not here.
    ldr  x9,         [x1, #0x00]
    mov  sp, x9
    ldp  x19, x20,   [x1, #0x08]
    ldp  x21, x22,   [x1, #0x18]
    ldp  x23, x24,   [x1, #0x28]
    ldp  x25, x26,   [x1, #0x38]
    ldp  x27, x28,   [x1, #0x48]
    ldp  x29, x30,   [x1, #0x58]
    ret
.size oxide_context_switch, . - oxide_context_switch
```
21 lines; under budget.

### 6.4 Bring-up

Same shape as x86. Initial saved callee-saved set so trampoline recovers `entry`+`arg`. Asm unchanged.

## 7 FPU/SIMD lazy save

Kernel built `+soft-float` x86 / `-fp-armv8,-neon` arm (`07§3`). Userspace freely uses FP/SIMD.

Per-CPU "FPU owner" pointer = task whose FPU state currently in registers.

Mechanism:
1. Kernel entry from user: set `CR0.TS` (x86) / clear `CPACR_EL1.FPEN` (arm). Kernel never executes FP, so trap never fires.
2. Kernel exit to user: leave TS/FPEN as-is (FPU-owner unchanged).
3. Ctxsw: do nothing about FPU. Set TS / clear FPEN.
4. New task returns to user, executes FP, traps:
   - Save FPU-owner's regs to `owner.fpu_state`.
   - Load this task's `fpu_state` into regs.
   - Set FPU-owner = this task.
   - Clear TS / set FPEN.
   - Return to user.
5. If new task IS FPU-owner: just clear TS/set FPEN, no save/restore.

Cost saved: XSAVE x86 ~150cy / FPSIMD arm similar, on every switch where target doesn't use FP between switches.

### 7.1 SMP nuance

Task T on CPU A → migrate to CPU B. CPU A's FPU-owner ptr still T. T faults on FP on B → IPI A to save T's state into `T.fpu_state`, then load on B.

v1 simplification: **don't migrate FPU-owner**. Sched skips FPU-owner during load-balance. Cost: load-balance inefficiency. Gain: no FP-fault IPI. v1.x revisit.

### 7.2 FPU state size

- x86_64 AVX2: ~832B (XSAVE x87+SSE+AVX). AVX-512 not v1 (~2576B).
- aarch64: 256B (32×16B vec + ctrl).

Allocated lazily in task struct on first FP fault.

## 8 Canary test

The bug-from-last-time guard.

### 8.1 Canary

Each kernel task: `[u64;16]` on kernel stack, init `[0xCAFE0000+i for i in 0..16]`.

### 8.2 Workload (`tests/kernel/ctxsw_canary.rs`)

```rust
fn canary_task(arg:usize) -> ! {
  let mut local: [u64;16];
  for i in 0..16 { local[i] = (0xCAFE_0000 + arg as u64) << 16 | i as u64; }
  loop {
    for i in 0..16 { local[i] = local[i].wrapping_add(1); }
    core::hint::black_box(&local);     // force into callee-saved regs
    if iter % 100 == 0 { yield_to_scheduler(); }
    for i in 0..16 { assert!(local[i] >> 32 == (0xCAFE_0000 + arg as u64)); }
  }
}
```

Spawn 64 tasks varying `arg`; preempt 1ms; run 1h. Lost callee-saved → assert fires + panic + offending regs. Bug from last time, impossible to miss.

### 8.3 Cross-checks

Each task also fills `r12..r15` (x86) / `x19..x28` (arm) with deterministic vals via `black_box`, reads back after every yield. Catches clobber per-yield, not just per-canary-window.

## 9 Perf budget

| Op | p99 cy |
|---|---|
| Same-AS ctxsw x86 (no KPTI cost) | 200 |
| Same-AS ctxsw arm | 150 |
| Cross-AS (CR3 swap, KPTI on, no PCID) | 1500 |
| Cross-AS (PCID/ASID hit) | 600 |
| FPU fault → save + load | 600 |

Bench: `bench/ctxsw_bench.rs`. Cross-AS includes PT swap (sched's job, not ctxsw asm) — measured for budget purposes.

## 10 Test contract (frozen)

- Two `.S` files exist, ≤50 lines each.
- Line-by-line ABI review: each `.S` has top-of-file comment citing SysV AMD64 ABI v1.0 §3.2.3 / AAPCS64 IHI 0055D §5.1.1 + page numbers. Reviewed by author-as-fresh-eyes after 48h cool-off (`02§1`).
- 2-thread ping-pong: 1M switches; final canary == initial.
- 64-task canary 1h @ 1ms preempt: every canary intact end.
- Hosted unit `Context::new_kernel`: build ctx, "switch" on fake stack, verify entry reached with correct arg.
- SMP migration stress: 1000 tasks × 8 vCPU; 1h; no canary fail.
- FPU lazy-save test: userspace spins FP between kernel preempts; after 1M iter, FP regs match expectation.
- Bench: within budget; no regress >5% vs baseline.

## 11 Failure modes

- Canary mismatch: panic; dump prev+next Context structs, offending task stack, per-CPU RQ.
- `Context::switch` called preempt-enabled: kassert (caller discipline error).
- Bring-up `entry` returns: trampoline ends `loop { halt(); }`; never expected. If hit = code bug, caught by trampoline.

## 12 Debug

`debug-sched-canary`: enables canary harness even outside test mode (catches in soak).

## 13 Cross-spec

`13` (caller of `Context::switch`), `20`/`21` (host asm + bring-up), `27` (KASLR/KPTI; CR3/TTBR orthogonal to ctxsw asm), `38` (`panic_static`).

## 14 Changelog

(none)

