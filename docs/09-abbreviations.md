# 09 Abbreviations

DRAFT 2026-05-02. Dep:`08`.

Single source of truth for shorthand used across `10+` specs and code. Add here before using.

## 1 Core types

| Abbr | Long |
|---|---|
| AS | AddressSpace |
| PT | PageTable |
| PFN | PageFrameNumber (`Pfn`) |
| VA | VirtAddr |
| PA | PhysAddr |
| UVA | UserVirtAddr |
| RQ | Runqueue |
| FD | FileDescriptor (`RawFd`) |
| SB | Superblock |
| Den | Dentry |
| KR | `KResult` |
| Eno | `Errno` |
| Ctx | Context (HAL `Context` impl) |
| TS | Task (struct) |
| MM | the address-space-and-VMAs bundle (`Arc<AS>`) |
| WQ | WaitQueue |
| Sb | Submit-buffer / submission queue (block, io_uring) |
| Cb | Completion buffer / completion queue |

## 2 Subsystems

| Abbr | Subsystem |
|---|---|
| PMM | Physical Memory Manager (`10`) |
| VMM | Virtual Memory Manager (`11`) |
| Slab | Slab allocator (`12`) |
| Sched | Scheduler (`13`) |
| CtxSw | Context switch (`14`) |
| ABI | Syscall ABI (`15`) |
| VFS | Virtual File System (`16`) |
| BPC | Block + page cache (`17`) |
| Mod | Modules (`18`) |
| DPS | dev/proc/sysfs (`19`) |
| HAL-X | hal-x86_64 (`20`) |
| HAL-A | hal-aarch64 (`21`) |
| IRQ | IRQ + exceptions (`22`) |
| Time | Time + vDSO (`23`) |
| IPC | pipes/signals/futex/eventfd/etc. (`24`) |
| Net | Networking (`25`) |
| NSCG | Namespaces + cgroups (`26`) |
| Sec | Security (`27`) |
| TTY | tty/pty (`28`) |
| Init | init + userspace (`29`) |
| IOU | io_uring (`30`) |
| ELF | ELF loader + dynamic linker (`31`) |
| Pwr | Power/reset (`32`) |
| FW | Firmware tables (`33`) |
| PCI | PCI/PCIe (`34`) |
| Drv | Driver model (`35`) |
| Boot | Bootloader handoff (`36`) |
| Obs | Observability (`37`) |
| Err | Error handling (`38`) |
| Img | Build/image (`39`) |
| CI | CI/soak (`40`) |
| Dbg | Debug-flags catalog (`41`) |
| Tst | Test strategy (`42`) |
| Acc | Acceptance (`43`) |

## 3 Hardware/protocol

| Abbr | Long |
|---|---|
| PTE | Page Table Entry |
| TLB | Translation Lookaside Buffer |
| ASID | Address Space ID (arm) |
| PCID | Process Context ID (x86) |
| KPTI | Kernel Page Table Isolation |
| CR3/TTBR | page-table root register (x86/arm) |
| MMIO | Memory-Mapped I/O |
| IPI | Inter-Processor Interrupt |
| NMI | Non-Maskable Interrupt |
| GIC | Generic Interrupt Controller (arm) |
| APIC/x2APIC | x86 interrupt controllers |
| TSC | Time Stamp Counter (x86) |
| CNTVCT | virtual count register (arm) |
| FPSIMD | FP/SIMD register file (arm) |
| XSAVE | x86 FP/SSE/AVX state save |
| ECAM | Enhanced Config Access Mechanism (PCIe) |
| MSI/MSI-X | Message-Signaled Interrupts |
| DMA | Direct Memory Access |
| CET | Control-flow Enforcement Technology (x86 shadow stack) |
| PAC/BTI | Pointer Auth / Branch Target ID (arm) |

## 4 Concurrency primitives

| Abbr | Long |
|---|---|
| SL | Spinlock |
| RWL | RwLock |
| SeqL | SeqLock |
| RCU | Read-Copy-Update |
| PCpu | PerCpu |
| Atom | atomic load/store |

## 5 Status tokens

In tables: `V1` `V1.X` `V2` `STUB` `NEVER` per `15§2`.

## 6 Doc-comment markers (canonical)

| Marker | Meaning |
|---|---|
| `# C: <expr>` | Complexity. `# C: O(1)` `# C: trivial` `# C: O(n) n=children` |
| `# Lk: <classes>` | Locks taken. `# Lk: PT` `# Lk: RQ,PT` |
| `# Ctx: <list>` | Allowed contexts. `# Ctx: proc` `# Ctx: any` `# Ctx: !atomic` |
| `# Sleeps: y\|n` | May sleep |
| `# Lin: <fn>` | Linux-equivalent name (cross-ref docs) |
| `# SAFETY: <text>` | unsafe-block precondition (>30 chars, names invariant) |
| `# Pre: <expr>` | Precondition (caller responsibility) |
| `# Post: <expr>` | Postcondition (callee guarantees) |

## 7 Open Questions

- Should `# C:` annotations be machine-checked vs just human-grep? Lean: grep-only v1; ratchet later.
- A separate machine-readable manifest (TOML next to each doc) for status/deps? Lean: defer; the doc front-matter already serves.
