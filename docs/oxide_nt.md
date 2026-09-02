# Oxide NT Compatibility Architecture

## Position

Oxide is not attempting to become a second Wine or a second Windows. The
project is implementing a native execution personality for 64-bit Windows
PE applications, backed by the existing Rust kernel. Wine-derived userspace
components remain useful at the Win32 boundary, where the amount of API and
application compatibility is too large to reproduce in the kernel.

The practical target is:

```text
64-bit Windows application
          |
          v
Wine-derived Win32 DLLs and compatibility runtime
          |
          v
ntdll / Oxide NT syscall ABI
          |
          v
Oxide NT personality
          |
          +-- PE32+ image loader
          +-- PEB/TEB and process initialization
          +-- NT handles and kernel objects
          +-- threads, stacks, TLS, exceptions, and unwind state
          +-- virtual memory, files, registry, and synchronization
          |
          v
Common Oxide kernel services
          |
          +-- scheduler   +-- VMM   +-- VFS   +-- networking
          +-- IPC         +-- input +-- audio +-- graphics
```

This differs from normal Linux plus Wine in one important respect: the
lowest Windows-facing process semantics are owned by Oxide instead of being
simulated solely by a userspace compatibility layer. The Linux personality
continues to use the same common kernel services and remains an independent
execution path.

## Responsibility boundary

Oxide owns the mechanisms that must be correct before Windows userspace can
run:

- native x86-64 PE32+ loading, mapping, relocation, imports, exports, TLS,
  and unwind metadata;
- NT process and thread identity, handles, access masks, and object lifetime;
- PEB, TEB, process parameters, environment, Windows stacks, and TLS layout;
- NT virtual-memory, file, registry, synchronization, and exception-facing
  syscall semantics;
- translation of those operations onto the scheduler, VMM, VFS, and other
  shared kernel primitives.

Wine-derived userspace owns the broad Win32 surface above that boundary,
including `kernel32`, `advapi32`, `user32`, `gdi32`, multimedia APIs, and
application compatibility behavior. This is an integration boundary, not a
requirement that Wine's Linux-specific syscall implementation be copied into
Oxide.

Graphics and media remain separate layers. DXVK can translate Direct3D 9/10/11
to Vulkan, VKD3D-Proton can translate Direct3D 12, and FAudio or equivalent
components can provide common game audio behavior. Those components consume
the Win32/NT contract exposed by the runtime; they do not define the kernel's
process model.

## What Oxide is and is not

Oxide is a native host for a Windows compatibility runtime. It is not a
Windows kernel binary emulator, and it does not promise that arbitrary
Windows drivers or kernel modules will load. Windows application machine code
runs directly as x86-64 code on x86-64 hardware.

The supported workload is intentionally 64-bit only:

- PE32+ applications and DLLs are in scope;
- PE32, WOW64, 16-bit Windows, DOS, Windows kernel drivers, and ARM Windows
  workloads are out of scope;
- AArch64 kernel builds are preservation checks for shared Rust code, not an
  ARM Windows compatibility target.

## Relationship to Wine and Proton

Wine is a compatibility layer that implements Windows userspace APIs and
maps them to Unix facilities. Proton is a gaming distribution of Wine with
graphics, audio, controller, Steam, and game-specific integration. Neither
is an alternative kernel for Oxide.

Oxide can therefore reuse the mature parts of Wine/Proton while replacing the
lowest layer they normally expect from Linux plus Wine:

```text
Normal Linux + Wine:
  Windows app -> Wine Win32/NT userspace -> Linux syscalls -> Linux kernel

Oxide:
  Windows app -> Wine-compatible Win32 userspace -> Oxide NT ABI
              -> native NT personality -> common Oxide kernel services
```

The useful reuse is selective. Wine source and behavior are references for
ABI shapes, status codes, object semantics, loader behavior, and userspace
contracts. Linux and Windows reference implementations are used to verify
the observable contract. The implementation must still use Oxide's own
ownership, scheduler, memory, and VFS mechanisms.

## Execution milestones

The first executable milestone is a native 64-bit Notepad-style PE launch.
That milestone proves the loader, process environment, ntdll relay, basic
memory and file services, synchronization, and enough Win32 userspace to
create the process. It does not mean that the entire Win32 desktop, graphics
stack, or modern game stack is complete.

After that, work proceeds by compatibility surfaces rather than by claiming
that one application represents Windows as a whole:

1. finish process/thread and handle lifecycle semantics;
2. complete memory, file, registry, synchronization, and exception coverage;
3. establish the Win32 DLL/runtime integration contract;
4. add windowing, input, graphics, audio, and networking surfaces;
5. exercise real 64-bit applications and games through repeatable boot and
   syscall/ABI harnesses.

Every surface needs focused unit tests, ABI/layout tests, target builds, and
runtime smoke coverage. A passing Notepad smoke is a useful vertical slice,
not a completion claim for the overall Windows goal.

