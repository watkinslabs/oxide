# 22 IRQ + Exceptions

Status: DRAFT 2026-05-02
Depends on: `01`,`02`,`06`,`07`,`14`,`20`,`21`.
Provides to: `13`,`23`,`34`,every driver.

## 1 Purpose

Vector dispatch + IRQ controller mgmt. Per-arch entry asm, arch-free IRQ subsystem (request/free/handle), softirq + tasklet/workqueue.

## 2 Invariants (frozen)

1. IRQ entry path saves user state to a `pt_regs`-equivalent on per-CPU IRQ stack. Never on user stack.
2. Nested IRQs allowed only if explicitly permitted by handler flags. Default: not nested.
3. NMI path uses dedicated NMI stack and NMI-safe ringlet for any logging.
4. CPU exceptions (page fault, GP, divzero, ...) reuse IRQ entry plumbing but dispatch by vector to specific handlers.
5. EOI sent before handler returns; no double-EOI; no missed EOI even on panic-rollback.
6. Per-CPU `preempt_count` += 1 on IRQ entry, -= 1 on exit. `need_resched` checked at exit-to-user.
7. softirq runs with IRQ enabled, preempt disabled; max 10 reruns before deferring to `ksoftirqd`.

## 3 Public ifc

```rust
pub fn request_irq(line:u32, handler:fn(&IrqCtx)->IrqRet, name:&'static str, flags:IrqFlags) -> KR<IrqHandle>;
pub fn free_irq(h:IrqHandle);
pub fn enable_irq_line(line:u32); pub fn disable_irq_line(line:u32);

pub fn raise_softirq(kind:SoftIrqKind);
pub fn schedule_work(w:&'static Work);

pub enum IrqRet { Handled, NotMine, WakeThread }
pub enum SoftIrqKind { Hi, Timer, Net_Tx, Net_Rx, Block, Tasklet, Sched, Hrtimer, Rcu }
```

## 4 x86_64 entry

- IDT 256 entries; vectors 0..31 = exceptions, 32..255 = device IRQs (assigned via APIC routing).
- Each gate points at a tiny stub (per-vector) that pushes vector number and jumps to common entry.
- Common entry: SWAPGS if from user, save `pt_regs`, switch to IRQ stack if not already there, call `handle_irq(vector, regs)`, restore, IRETQ.
- KPTI: on entry from user, swap CR3 to kernel PT first; reverse on exit. PCID flush avoidance (ASID 0 for kernel, ASID 1 for user).
- Page fault (#PF): `cr2` read first, then dispatch to `vmm.handle_page_fault`.
- NMI: separate IST stack, paranoid path (verify GS, switch CR3 carefully).
- Double-fault: separate IST stack, kernel halt (we do not recover).

## 5 aarch64 entry

- Single vector base register `VBAR_EL1` → 16-entry vector table (4 cause classes × 4 source contexts).
- Entry stub: save `x0..x30`,`sp_el0`,`elr_el1`,`spsr_el1`,`esr_el1`,`far_el1` to stack frame.
- ESR.EC dispatches: SVC → syscall, IABT/DABT → page fault, others → exception.
- TLBI/DSB/ISB sequences explicit at entry/exit per ARM ARM D5.10.
- Generic Timer ISR: `cntp_tval_el0` reload.

## 6 IRQ controller abstraction (HAL `IrqOps`)

```rust
pub trait IrqOps {
    fn enable_line(line:u32);
    fn disable_line(line:u32);
    fn eoi(line:u32);
    fn set_affinity(line:u32, mask:CpuMask) -> KR<()>;
    fn alloc_msi(req:MsiReq) -> KR<MsiAlloc>;
    fn send_ipi(target:CpuMask, vec:u8);
    fn ack(line:u32) -> Option<u32>;   // returns vec if level-triggered shared
}
```

Impls: `hal-x86_64::Apic` (x2APIC), `hal-aarch64::GicV3`.

## 7 IRQ shared lines (legacy)

We allow shared INTx for AHCI and a few others. Each handler returns `Handled`/`NotMine`. Iterates handler chain. PCIe MSI-X is preferred; INTx is fallback.

## 8 Threaded handlers

Handlers may return `WakeThread` to defer work to a per-IRQ kthread. The hard handler does only ack+enqueue; thread does the work. Used for slow device handling (USB, audio).

## 9 softirq

Bottom halves. Static set in `SoftIrqKind`. Runs:
- on IRQ exit if any pending and not recursive,
- in `ksoftirqd/<cpu>` when too many reruns or threaded preferred.

`tasklet` deprecated in modern Linux; we don't expose. `workqueue` (kthread pool) preferred for blocking work.

## 10 Concurrency

- IRQ disable is per-CPU (PSTATE.I or RFLAGS.IF). Locks acquired in IRQ context use plain `lock` since we know IRQs are masked.
- Locks shared with process context use `lock_irqsave`.
- softirq disable: `local_bh_disable`/`enable`.
- IPI handlers: minimal — set per-CPU flag, schedule work or wake sched.

## 11 Perf budget

| Op | p99 cy |
|---|---|
| Empty IRQ entry+exit (no handler) | ≤ 200 |
| IRQ→handler→ack→exit (real device) | ≤ 800 |
| IPI delivery (sender side) | ≤ 300 |
| IPI receive→ack | ≤ 200 |
| `request_irq` | ≤ 5 µs |

## 12 Test contract (frozen)

- Synthetic IRQ generator (in HAL): trigger 1M IRQs, verify count, no missed EOI (controller queue empty).
- Shared-line stress: 8 fake handlers on same line; verify chain iteration + correct `Handled` accounting.
- Threaded handler: fake slow handler, 10K events, verify `WakeThread` defers correctly.
- IPI loom: 4-CPU loom of cross-CPU IPI delivery; no lost IPI.
- NMI stress: inject random NMI 100/sec for 1h; no panic, NMI-safe ringlet not lost.
- softirq saturation: load softirq queue beyond rerun limit; verify ksoftirqd takeover.
- Coverage ≥90%.

## 13 Failure modes

- Spurious IRQ (no handler claimed): increment per-line spurious counter; mask line if rate >100/s.
- Triple fault (or arm double-fault): kernel halt, dump regs to NMI ringlet, drain to UART.
- `request_irq` on already-busy non-shared line: EBUSY.

## 14 Debug

`debug-irq`: per-IRQ-line histogram of latencies; top-of-stack capture for last 32 IRQs per CPU.

## 15 Cross-spec

`13` (IPI for resched, preempt_count), `23` (timer IRQ), `34` (MSI-X alloc), `20`/`21` (entry asm + controller backends).

## 16 Open Questions

- IRQ remapping (Intel VT-d / arm SMMU IRQ routing) for IOMMU-protected MSIs: defer to v1.x.
- Per-CPU softirq priorities: copy Linux order? Yes.
- Threaded IRQs as default? Linux opt-in. Lean: handler-by-handler choice; default is hard.
