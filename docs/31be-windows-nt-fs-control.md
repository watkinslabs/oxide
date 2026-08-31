# Windows NT Filesystem Control

Status: FROZEN

Date: 2026-08-31

## Contract

Wine exposes `NtFsControlFile` with the same ten-argument extended x86-64
shape as device I/O control, including an I/O status block and buffers.
Oxide exposes the native export as selector 109 and keeps the service at an
explicit unsupported boundary until extended argument transport and owned
filesystem-control adapters are available.

The call is not translated into a Linux `ioctl` or silently treated as an
ordinary file operation. Filesystem controls will be implemented per NT
object type and mapped to the appropriate common kernel service.
