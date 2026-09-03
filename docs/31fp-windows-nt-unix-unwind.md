# Windows NT Unix builtin-unwind contract

FROZEN 2026-09-02. Dep:`01`,`02`,`31h`,`31v`,`52`,`53`. Provides: the fixed Wine Unix builtin-unwind request ABI.

## 1

- The Unix-call slot `UnwindBuiltinDll` carries `ULONG type`, a dispatcher pointer, and a context pointer.
- The shared ABI record inserts explicit 32-bit padding after `type`; pointers remain 8-byte aligned on x86-64 and aarch64.
- Dispatcher and context layouts remain owned by the runtime boundary that implements the operation; the syscall crate does not reinterpret either pointer.
- A malformed pointer or unsupported unwind operation fails through the typed Unix-call status path.

## 2

- The slot order remains the single `WineUnixFunction` table; no alternate operation number is introduced.
- Native PE unwind metadata remains the canonical source for PE modules; builtin ELF unwind metadata is a separate runtime-owner concern.

## 3

- Hosted ABI tests cover record size, alignment, and offsets.
- Both kernel checks compile the shared record and its dispatch boundary; execution of a Wine Unix builtin remains x86-64 workload scope.
