# Windows exception dispatch (KI-0436, filed as KI-0437 in the brief)

Status: implemented on x86_64, branch `B3523-exception-dispatch`. Ledger row
**`KI-0436`** — the brief named `KI-0437`, but no such row existed on `main`
(the highest id was `KI-0435`), so this lane filed the row itself. The file
name keeps the brief's id; `KI-0437` is now one of the follow-up rows below.

## 1 The mechanism being mirrored

Two layers, and the project already owned one of them.

| Layer | Windows / the reference runtime | Oxide |
|---|---|---|
| trap -> exception record | POSIX kernel raises a signal; the runtime's `SIGSEGV`/`SIGILL`/`SIGBUS`/`SIGTRAP`/`SIGFPE` handlers rebuild an `EXCEPTION_RECORD` from the raw machine status the signal frame carries | the kernel HAS an NT personality: the record is built where the trap is taken, and no signal is invented on the way |
| exception record -> user handlers | the handler repoints the signal-return registers at `KiUserExceptionDispatcher` with a frame on the interrupted user stack | the return-to-user work loop repoints the live trap frame at the same entry with the same frame |
| user dispatch | `KiUserExceptionDispatcher` -> vectored handlers -> frame handlers -> `NtContinue` on success, `NtRaiseException(first_chance=FALSE)` on failure | unchanged: the PE-side ntdll the guest loads does all of it |
| resume / terminate | `NtContinue` restores the CONTEXT; a second-chance raise terminates the process | `nt_unwind::restore_context` (already present) resumes; the second-chance raise now ends the process |

The user-visible half is the runtime's own code, already in the guest. Only the
kernel-to-`KiUserExceptionDispatcher` transition and the two service calls that
close the loop are ours.

## 2 What already existed (re-verified, not assumed)

Roughly two thirds of this row was already built, unreachable:

- `sched::nt_exception::State` — one pending exception per thread, with a
  delivery reservation. Ungated, hosted-tested.
- `syscalls::exit_to_user` — the return-to-user work loop already consults
  `nt_exception.is_pending()` and calls a frame builder.
- `pe::nt_stub` — the exact dispatcher frame contract (`context` 0x000,
  `context_ex` 0x4d0, `rec` 0x4f0, machine frame 0x590, total 0x5c0), matching
  the reference's `C_ASSERT`ed layout byte for byte.
- `syscalls::nt_unwind::restore_context` — `NtContinue`, fully implemented,
  including VMA validation of the restored RIP/RSP and FPU restore.
- `syscalls::nt_exception` — `NtRaiseException`, `RtlRaiseException`,
  `RtlRaiseStatus` publish into that state.

**The one missing link:** `State::publish` had exactly one caller, the software
raise. `mm-pmm/src/user_as/signal.rs::force_user_fault_x86` — the single funnel
every unresolved user fault passes through — ran the POSIX `force_sig_fault`
path unconditionally, with no personality branch. A hardware fault in a PE
thread therefore became a SIGSEGV. This is the `Machinery without callers`
class through the front door.

## 3 The change

1. `sched::nt_exception::fault` (new, ungated, both arches always compiled) —
   trap facts to `EXCEPTION_RECORD`. `x86_64::page_fault` /
   `x86_64::trap`, `aarch64::abort` / `aarch64::sync`, and `Raised::record()`.
2. `sched::nt_exception::context` (new, ungated) — interrupted registers to
   `CONTEXT`, the `CONTEXT_EX` chunk descriptors, the FXSAVE image, and the
   RFLAGS the dispatcher is entered with.
3. `sched::nt_exception::fault::publish_for_current` — the ONE decision about
   where an unresolved fault is reported. `mm-pmm`'s fault funnel asks it once
   and reports the signal when the answer is no.
4. `syscalls::nt_exception_frame::deliver` (new; moved out of `exit_to_user`,
   which is now 382 lines) — builds and arms the frame.
5. `sched::nt_exception::raise_disposition` — first chance dispatches, second
   chance ends the process.
6. `userspace/probes/windows-runtime` — the launcher hands the synchronous
   fault signals back to `SIG_DFL` and disables the alternate stack before it
   jumps into the PE entry.

### Call-site chain (reachability)

```
hal-x86_64 fault vector
  -> mm-pmm user_as::fault::entry::user_fault_handler          (entry.rs:37, :110)
  -> mm-pmm user_as::signal::force_user_fault_x86              (signal.rs)
  -> sched::nt_exception::fault::publish_for_current           (fault.rs)
  -> sched::nt_exception::State::publish(Pending::from_hardware)
[ same vector's epilogue ]
  -> arch-irq oxide_irq_exit_to_user                           (lapic/dispatch.rs:285)
  -> syscalls::exit_to_user::exit_to_user_mode_loop            (exception_pending arm)
  -> syscalls::exit_to_user::deliver_nt_exception
  -> syscalls::nt_exception_frame::deliver
  -> regs.rip = KiUserExceptionDispatcher, regs.rsp = frame
[ user mode ]
  -> ntdll KiUserExceptionDispatcher -> dispatch_exception
  -> NtContinue  -> syscalls::nt_unwind::restore_context       (resume)
     or NtRaiseException(first_chance=0) -> raise_disposition -> do_group_exit
```

### The context is captured at DELIVERY, not at the fault

`Pending::context` became `Option`. A hardware trap publishes none: the trap
frame is reached through a per-CPU pointer that the fault path is explicitly
forbidden to dereference, because a fault resolver may have switched tasks
before reporting (`hal_x86_64::current_fault_rsp`'s own contract). The
return-to-user pass owns the live frame and captures there — which is also
where the reference reads its saved frame when it raises out of a system call.

### Non-livelock argument

A refused delivery returns the reservation rather than terminating. The work
loop is pass-bounded, so it then resumes the faulting instruction; the re-fault
finds the slot occupied, `publish_for_current` answers `false`, and the POSIX
signal reports it. No unreachable exception can spin, and no delivery bug can
kill a process that would otherwise have lived.

## 4 Deviations, each with its reason

| # | Deviation | Reason |
|---|---|---|
| D1 | No debugger round trip before dispatch | The reference asks a debugger first over its server socket. There is no such server here — the kernel is the server — and no NT debug-object attach path exists yet (`ptrace_access::native_debug` sets the personality bit only). A first-chance exception goes straight to the dispatcher, which is what the reference does when nothing is attached (its fast path returns immediately on `!BeingDebugged`). Row `KI-0437`. |
| D2 | No `PAGE_GUARD` / write-watch resolution before the record is built | The reference resolves guard pages, growable thread stacks and write-watch faults inside the handler and reports `STATUS_GUARD_PAGE_VIOLATION` or resumes silently. Here the address-space owner resolves the fault first and only a REFUSED fault reaches this decode, so a second copy of that policy would be a split source of truth. It follows that oxide has no `STATUS_GUARD_PAGE_VIOLATION` at all until the NT allocator grows a guard attribute. Row `KI-0438`. |
| D3 | `#GP`/`#NP` never report `EXCEPTION_PRIV_INSTRUCTION` | Deciding that needs the faulting opcode decoded, which this layer does not read; the access-violation form with the all-ones address sentinel is the reference's other arm. |
| D4 | `#MF`/`#XF` report `STATUS_FLOAT_INVALID_OPERATION` unconditionally | The specific x87/SSE condition comes from the status word, which the fault classifier does not decode. This is the reference's own default when the stack-check bit is clear. |
| D5 | No `XSTATE` in the frame | The frame advertises the legacy FXSAVE image only; the `CONTEXT_EX` XState chunk describes nothing, exactly as the reference writes it for a thread with no extended state. A thread that used AVX resumes without its upper halves. Row `KI-0439`. |
| D6 | `aarch64` decodes but does not deliver | See §5. |

## 5 The aarch64 counterpart

Named and half-built. `sched::nt_exception::fault::aarch64` is complete and
tested (ESR exception class selects the access parameter: instruction abort is
an execute fault, `ISS.WnR` selects write over read; the debug and alignment
classes map as the reference's handlers do). Delivery is NOT wired, and
`publish_for_current` is therefore never called from `force_user_fault_arm`.

What the arm64 delivery needs, to the same contract:

| Piece | arm64 shape |
|---|---|
| frame layout | `context` 0x000, `context_ex` 0x390, `rec` 0x3b0, `sp` 0x450, `pc` 0x458, redzone 0x460, total 0x470 — a `pe::nt_stub` sibling of the x64 constants |
| dispatcher entry | `SP` = the frame, `x0` = record (`SP+0x3b0`), `x1` = context (`SP`), `x18` = TEB. x86 derives both pointers from RSP; arm64 passes them in the AAPCS64 argument registers |
| CONTEXT | 0x390 bytes: `Cpsr`, `X0..X30`, `Sp`, `Pc`, `V[32]`, `Fpcr`/`Fpsr`, debug registers — needs an `nt_context_image` sibling |
| breakpoint rewind | `Pc += 4` to step OVER the `brk`, where x86 rewinds `Rip` by one to point AT the `int3`. `prepare_dispatch_context` is x86-shaped and must not be reused |
| `NtContinue` | `nt_unwind::restore_context` is x86-only (`STATUS_INVALID_PARAMETER` on arm64) |

This is not "x86 first, ARM later" for a shipped surface: the whole Windows
personality is x86-only today — `NtRaiseException` answers
`STATUS_NOT_SUPPORTED` on arm64, `nt_context_image` is x86-only, and the
launcher rejects any architecture argument but `x86_64`. Exception dispatch
lands with the rest of that surface, in one lane. Row `KI-0440`.

## 6 Tests

| File | What can fail |
|---|---|
| `sched/src/nt_exception/fault/tests.rs` | 12 tests: access parameter from the `#PF` error code and from ESR, the record's field layout and parameter count, every named trap's status, the breakpoint address rewind, and the fall-back-to-signal answer |
| `sched/src/nt_exception/context/tests.rs` | 7 tests: every general register's offset, the advertised components, the selectors, the `CONTEXT_EX` chunk descriptors and their refusal on a short frame, the FXSAVE image and its duplicated control word, and the dispatcher's RFLAGS |
| `sched/tests/nt_exception_fault_report.rs` | 5 tests: an NT thread publishes and a non-NT thread does not, an undescribable condition does not, a fault while one is pending does not, and no current thread does not |
| `sched/src/nt_exception.rs` | first- vs second-chance disposition; hardware publish keeps the slot; a record with no exception code is never published |

Positive controls run and reported in the branch: shifting `ACCESS_SHIFT`
turned two decode tests red; inverting the personality test turned three report
tests red; both restored green.

## 7 Follow-up rows filed by this lane

| Row | Subject |
|---|---|
| `KI-0436` | the row this lane closes: hardware exceptions never dispatched |
| `KI-0437` | no debugger is offered a first-chance exception (D1) |
| `KI-0438` | `PAGE_GUARD` has no representation, so no `STATUS_GUARD_PAGE_VIOLATION` (D2) |
| `KI-0439` | no `XSTATE` in the frame (D5) |
| `KI-0440` | aarch64 decodes but does not deliver (D6, §5) |
| `KI-0441` | `nt_unhandled_filter` is written and never read |
| `KI-0442` | `RtlCaptureContext` reports the code selector in the data segment fields |

## 8 Not done

The one thing a boot would answer that no test here can: whether the guest's
`KiUserExceptionDispatcher` accepts this frame. Every byte of the frame is
pinned against the reference's asserted layout, but the acceptance run is the
proof. It was not run in this lane (no boots).
