# Windows NT Device I/O Control

Status: FROZEN

Date: 2026-08-31

## Contract

Wine exposes `NtDeviceIoControlFile` with ten x86-64 ABI arguments, including
an I/O status block and input/output buffers beyond the six register words
currently carried by Oxide's native NT call record. Oxide exposes the native
export as selector 107 and returns an explicit unsupported status for NT
callers until the extended argument transport and device-specific adapters
are implemented.

The boundary does not reinterpret the call as a Linux ioctl, file operation,
or socket operation. Device semantics will be added through owned NT
adapters over the appropriate native subsystem.
