# Windows runtime-owned PE execution handoff

Status: FROZEN  
Frozen: 2026-08-31

The NT runtime supplies the kernel with a root PE image plus an optional
explicit, copied module catalog. The tagged `ExecuteWithCatalog` service is
the handoff used by a Linux-personality Wine launcher; it is not part of the
Linux `execve` ABI.

The kernel validates and copies every user buffer, rejects duplicate or
malformed PE modules through the shared catalog, and commits the image using
the existing transactional PE loader. A successful commit switches the task
to the NT personality. A failed request leaves the caller's Linux image and
personality unchanged.

The native NT loader decides the Windows DLL search order and probes the mounted
VFS. The kernel never searches Linux ELF library directories or uses Unix `.so`
files as an alternate NT DLL source. The runtime can seed `kernel32`, `user32`,
`advapi32`, and other Wine-derived PE modules for the same canonical catalog.
