# 38 Error Handling

DRAFT 2026-05-02. Dep:`01`,`02`,`07`,`08`. Provides:every kernel crate.
## 1 Purpose

Define how kernel handles errors at three levels: recoverable (`KR<T>`), oopsable (recoverable with task kill), unrecoverable (panic+halt).

## 2 Invariants (frozen)

1. Every fallible kernel fn returns `KR<T>=Result<T,Errno>`. No raw `i32`, no `Option` for "failed".
2. `panic = "abort"` set in every kernel profile (`07§2`). No unwinding.
3. Panic emits one-line `&'static str` + file/line; never formats.
4. After panic: log to NMI ringlet, drain to UART, halt all CPUs via NMI IPI.
5. Kernel oops (per-task fault, e.g. user copy fault): SIGBUS/SIGSEGV to task, kernel continues.
6. `kassert!` panics; not catchable.

## 3 Public ifc

```rust
#[macro_export] macro_rules! kassert { ($c:expr,$m:literal) => {if !$c { $crate::panic_static($m,file!(),line!())}}; }

#[noreturn] pub fn panic_static(msg:&'static str, file:&'static str, line:u32) -> !;

pub fn oops(msg:&'static str, regs:&PtRegs);   // log + signal current task

pub fn copy_from_user(dst:&mut [u8], src:UVA<u8>) -> KR<()>;   // returns EFAULT, never panics
pub fn copy_to_user(dst:UVA<u8>, src:&[u8]) -> KR<()>;
```

## 4 Panic path

```
panic_static(msg, file, line):
  irq_disable_all_cpus_via_ipi();
  klog::fatal!(target:"panic", msg=msg, file=file, line=line);
  dump_per_cpu_state();          // current task, regs (best-effort), stack trace
  drain_klog_to_uart();
  halt_loop();                    # arch-specific: hlt loop / wfe loop
```

Stack trace via frame-pointer walk (kernel built `+force-frame-pointers`). Backup: dump raw stack as hex.

## 5 Oops path

User pointer fault during `copy_*_user`:
- HAL installs a per-CPU "expected fault" hook before the access.
- On page-fault, handler checks hook; if matched, sets a flag and skips the user PT walk; returns to a fixup label that returns `EFAULT`.
- Expressed in Rust via the `_safe_user_access` helper used by `copy_from_user`/`copy_to_user`.

Userspace fault not from `copy_*_user`:
- `vmm.handle_page_fault` returned `EFAULT`.
- Translate to SIGSEGV/SIGBUS based on cause.
- Deliver via signal subsystem (`24`).

## 6 Concurrency

- Panic IPIs delivered with NMI vector: receivers spin-halt without taking locks.
- Klog drain post-panic: serial polled write, no driver path.
- One panic at a time enforced by `static AtomicBool PANICKING`.

## 7 Perf budget

- `kassert!(true)` (cond holds): single test+branch ≤ 3 cy.
- `panic_static` invocation budget: not relevant; we're dying.

## 8 Test contract (frozen)

- Build test: `panic!("...{}", x)` in any kernel crate ⇒ build fails (per `07§5`).
- `static mut FOO` ⇒ build fails.
- Synthetic panic: spawn workload; trigger panic from a non-init CPU; verify panic-path log to serial includes msg, file, line, and at least 5 stack frames from the failing CPU.
- Oops harness: program does `*(0xdeadbeef as *mut u32) = 1`; verify SIGSEGV with `si_addr=0xdeadbeef`, kernel still alive.
- `copy_from_user` fuzz: random user pointers (mapped/unmapped/kernel-side); assert EFAULT for all unmapped/kernel-side, no kernel panic.

## 9 Failure modes

- Panic during panic: detect via `PANICKING` already set; skip second log path; halt directly.
- Klog ringlet full during panic: drop remaining records; emit `<...truncated...>` marker.

## 10 Debug

`debug-panic`: full register dump including caller-saved (snapshot before disabling interrupts). Larger panic dump.

## 11 Cross-spec

`07` (panic strategy + kassert), `22` (NMI IPI for cross-CPU halt), `27` (signal delivery), `04` (logging targets).

## 12 Open Questions

- Kdump-style crash dumps to disk? Defer to v1.x (needs functional disk + filesystem in panic path; tricky).
- Kernel-panic netconsole? Defer.
- Per-task "soft oops" with backtrace to userspace via `prctl(PR_SET_DEATHSIG)`-like mechanism? Defer.
