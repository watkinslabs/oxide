# Windows NT context capture

Status: FROZEN
Date: 2026-08-31

`RtlCaptureContext` writes the x86-64 Windows `CONTEXT` layout expected by
Wine-derived code. The native boundary obtains the live user register frame,
publishes control, segment, integer, instruction-pointer, and floating-point
defaults, and copies the complete 0x4d0-byte record to userspace.

The syscall entry necessarily consumes the selector register before reaching
the NT adapter, so the captured `Rax` slot is not reconstructed from the
pre-entry call instruction. All registers preserved by the entry frame are
copied exactly; later direct-call or entry-assembly support can fill that one
ABI limitation without changing the record layout. AArch64 has no Windows
runtime execution contract in this project and returns invalid-parameter for
this x86-64-only service.
