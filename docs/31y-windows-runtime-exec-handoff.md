# Windows runtime-owned PE execution handoff

Status: FROZEN  
Frozen: 2026-08-31

The NT runtime owns DLL search and supplies the kernel with a root PE image plus
an explicit, copied module catalog. The tagged `ExecuteWithCatalog` service is
the handoff used by a Linux-personality Wine launcher; it is not part of the
Linux `execve` ABI.

The kernel validates and copies every user buffer, rejects duplicate or
malformed PE modules through the shared catalog, and commits the image using
the existing transactional PE loader. A successful commit switches the task
to the NT personality. A failed request leaves the caller's Linux image and
personality unchanged.

The kernel never searches Linux library directories. The runtime decides which
`kernel32`, `user32`, `advapi32`, and other Wine-derived modules to supply.
