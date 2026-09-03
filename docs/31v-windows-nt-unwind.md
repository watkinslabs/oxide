# Windows native unwind transfer

FROZEN 2026-09-03. Dep:`01`,`02`,`06`,`13`,`31d`,`31h`,`52`,`53`. Provides: x86-64 unwind and context-continuation transfer boundaries.

## 1 Contract

- `RtlUnwind(frame, target_ip, exception_record, return_value)` is accepted only by an NT-personality task.
- The frame and target instruction address must be valid user addresses; the frame's saved return word must be readable.
- The syscall return frame is rewritten to `RSP = frame + 8`, `RIP = target_ip`, and `RAX = return_value`.
- `NtContinue(context, test_alert)` and `RtlRestoreContext(context, record)` consume one staged 0x4d0-byte AMD64 context; malformed, non-AMD64, debug-register, and extended-xstate records are rejected before task state changes.
- Continuation restores integer, control, and legacy x87/SSE state into the current task's canonical register and FPU owners; instruction pointer, stack pointer, MXCSR, and user RFLAGS are validated before commit.
- `test_alert = TRUE` enters the existing return-to-user APC delivery path after the supplied context becomes current; `FALSE` leaves queued callbacks retained. The target thread's owned APC queue remains the sole callback source, and queueing alone never executes user code.
- `RtlCaptureContext` publishes the same integer, control, and legacy x87/SSE shape consumed by continuation.
- Linux signal and exception paths remain unchanged; structured exception dispatch and unwind metadata interpretation remain userspace/runtime work.
- The shared PE parser validates runtime-function ranges, locates the function
  covering an instruction RVA, and decodes version-1 `UNWIND_INFO` headers and
- unwind-code slots. `Image::unwind_x64` applies the supported integer-stack
  operations, restores saved nonvolatile integer registers, and obtains every
  stack word through a caller-supplied reader; XMM restoration, chained records,
  and handler dispatch remain explicit unsupported results.

## 2 Tests

- the native runtime export resolves to the tagged unwind selector;
- non-NT tasks and invalid user frame/target addresses are rejected;
- a valid transfer does not return to the caller's original user RIP;
- the native runtime exports a tagged `NtContinue` selector and the decoder preserves both context and alert arguments;
- context parsing is transactional, requires AMD64 control state, copies integer and FXSAVE payloads, and rejects debug/xstate components not owned by this boundary;
- the scheduler APC harness proves queueing and delivery requests are distinct, an empty alert test does not arm a future callback, and consuming the final callback clears the request;
- a positive-control mutation removing the control-state requirement makes the malformed-context test fail;
- runtime-function lookup rejects malformed ranges and returns the decoded
  x86-64 unwind header/code sequence;
- leaf and non-leaf x86-64 frames reconstruct caller `RIP/RSP` and saved `RBP`
  through the bounded reader; XMM records are rejected until context storage
  exists;
- x86-64 and aarch64 kernel checks retain their separate personality behavior.
