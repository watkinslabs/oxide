# Windows Linux-personality launcher

FROZEN 2026-08-31. Dep:`01`,`02`,`29a`,`31a`,`31h`,`31p`,`31y`,`52`,`53`. Provides: the runtime-owned launcher that submits a 64-bit PE image and DLL catalog.

## 1 Contract

- The launcher is an ELF userspace program and remains in the Linux personality while it reads the Windows image and DLL directory.
- It validates every supplied non-native DLL as PE32+ and owns all buffers until the tagged handoff returns; native `ntdll.dll` is supplied by the kernel runtime and cannot be shadowed.
- The launcher supplies a Windows-format image path separately from the Linux filesystem path used to read the image.
- The launcher submits `ExecuteWithCatalog` through the shared NT ABI records; it never invokes a Linux syscall number to emulate a Windows call.
- A Linux host returns its native unsupported-syscall error for the Oxide-only selector; the launcher does not translate that into success.
- The kernel remains responsible for copying, revalidating, dependency discovery, mapping, and transactional personality transition.
- The launcher emits phase/operation/outcome diagnostics for preflight and the tagged handoff; `unavailable` is terminal when the Oxide selector returns `ENOSYS`, and only `committed` permits exit success.
- The Notepad smoke wrapper starts the canonical `registryd` owner before the
  PE handoff and supplies its socket/database locations through the launcher
  environment; registry state is not copied into the kernel.
- A Steam game launch uses one `oxide-steam-launch-v1` record containing the
  app id, image, Windows command line, and every owned Proton component path.
  The launcher rejects duplicate, unknown, missing, relative, or stale
  record-owned inputs before reading the PE image; it then uses the same
  `ProtonLaunchConfig` and NT handoff as other Windows launches, adding the
  record's app id as both `SteamAppId` and `SteamGameId` in that launch's
  environment block.

## 2 Tests

- a real installed 64-bit Wine Notepad image and DLL directory produce a complete owned request;
- request records preserve 64-bit pointer/length layout and stable buffer addresses;
- malformed or non-PE DLLs fail before a handoff can be attempted;
- Linux-host execution reports unsupported tagged-kernel entry honestly;
- the launcher compiles through the ordinary GNU userspace workspace.
- a complete Steam launch record parses into one owned configuration;
  duplicate, unknown, and missing fields fail closed; invalid paths fail
  before image/catalog reads; `--steam-launch` reaches the existing tagged
  handoff and reports Linux-host unavailability honestly.
