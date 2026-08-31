# Windows native unwind transfer

FROZEN 2026-08-31. Dep:`01`,`02`,`06`,`13`,`31d`,`31h`,`52`,`53`. Provides: the first x86-64 `RtlUnwind` transfer boundary.

## 1 Contract

- `RtlUnwind(frame, target_ip, exception_record, return_value)` is accepted only by an NT-personality task.
- The frame and target instruction address must be valid user addresses; the frame's saved return word must be readable.
- The syscall return frame is rewritten to `RSP = frame + 8`, `RIP = target_ip`, and `RAX = return_value`.
- Linux signal and exception paths remain unchanged; structured exception dispatch and unwind metadata interpretation remain userspace/runtime work.
- The shared PE parser validates runtime-function ranges, locates the function
  covering an instruction RVA, and decodes version-1 `UNWIND_INFO` headers and
-  unwind-code slots. `Image::unwind_x64` applies the supported integer-stack
  operations, restores saved nonvolatile integer registers, and obtains every
  stack word through a caller-supplied reader; XMM restoration, chained records,
  and handler dispatch remain explicit unsupported results.

## 2 Tests

- the native runtime export resolves to the tagged unwind selector;
- non-NT tasks and invalid user frame/target addresses are rejected;
- a valid transfer does not return to the caller's original user RIP;
- runtime-function lookup rejects malformed ranges and returns the decoded
  x86-64 unwind header/code sequence;
- leaf and non-leaf x86-64 frames reconstruct caller `RIP/RSP` and saved `RBP`
  through the bounded reader; XMM records are rejected until context storage
  exists;
- x86-64 and aarch64 kernel checks retain their separate personality behavior.
