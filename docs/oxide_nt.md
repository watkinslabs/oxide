# Oxide NT Compatibility Architecture

FROZEN 2026-09-02. Dep:16,29,31,53.

## 1

The provider comparison leads to a specific Oxide answer: Oxide is not a
replacement for Wine or Proton. It is a native NT host underneath a
Wine-compatible userspace. Wine supplies the large Win32 compatibility
surface; Proton remains an optional gaming bundle around that surface. Oxide
supplies the process, memory, object, file, and syscall semantics that those
components normally obtain from Linux plus Wine's Unix-side implementation.

The boundary is therefore:

```text
Windows PE32+ application
          |
          v
Wine-compatible Win32 DLLs
          |
          v
Oxide ntdll-compatible relay
          |
          v
Oxide NT personality
          |
          +-- native PE32+ execution and process setup
          +-- NT handles, objects, waits, memory, files, and exceptions
          |
          v
Common Oxide kernel services
          |
          +-- scheduler, VMM, VFS, IPC, networking, graphics, and audio
```

“Native” means that Windows application code and its NT-facing operations
are hosted by Oxide's own kernel contract. It does not mean reimplementing
every Win32 DLL, copying Wine's Unix server into the kernel, or emulating
Windows kernel drivers. Linux applications continue through the Linux
personality and the same common services.

## 2

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

## 3

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

## 4

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

## 5

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

## 6

The comparison above is the right starting point, with one important change
for Oxide: Oxide is not trying to replace Wine's Win32 implementation. It is
changing the host underneath the lowest part of the compatibility stack.

Wine and Proton normally look like this:

```text
Windows application
        |
        v
Wine/Proton Win32 DLLs
        |
        v
Wine ntdll and Unix-facing implementation
        |
        v
Linux syscalls -> Linux kernel
```

The Oxide arrangement is:

```text
Windows application
        |
        v
Wine-compatible Win32 DLLs and runtime
        |
        v
Oxide ntdll-compatible relay
        |
        v
Oxide NT personality
        |
        +-- PE32+ process creation and image loading
        +-- NT processes, threads, handles, and kernel objects
        +-- virtual memory, files, synchronization, and exceptions
        |
        v
Common Oxide kernel services
        |
        +-- scheduler, VMM, VFS, IPC, networking, drivers
```

The relay is an ABI boundary, not a second operating system hidden inside the
kernel. A Wine DLL may issue an NT operation through it; the kernel validates
user pointers, access rights, object types, and handle lifetime, then maps the
operation to common Rust services. The Wine DLL must not depend on Linux-only
kernel details for the operation to work on Oxide.

### What can be reused

Wine source is useful for observable Windows behavior and mature userspace
implementations. Subject to the project's licensing and build arrangement,
the useful reuse includes:

- Win32 behavior in `kernel32`, `kernelbase`, `user32`, `gdi32`, `advapi32`,
  `winmm`, and related DLLs;
- PE loader and ntdll ABI knowledge, structure definitions, status values,
  loader ordering, TLS initialization, and exception conventions;
- registry, Unicode, process-parameter, and synchronization behavior;
- DXVK for Direct3D 9/10/11, VKD3D-Proton for Direct3D 12, and FAudio or an
  equivalent audio layer for games;
- Proton's configuration, graphics, input, controller, and game integration
  patterns where they do not assume Linux-specific kernel behavior.

The reusable unit is normally a userspace DLL or a specified ABI contract.
A Wine Unix-server implementation is a reference for semantics, but it is not
automatically the implementation of an Oxide kernel service.

### What Oxide must own

The kernel owns the parts observable at the NT boundary that cannot safely be
delegated to an untrusted compatibility DLL:

- address-space, process, and thread creation and teardown;
- native x86-64 PE32+ mapping, relocation, imports, and initial execution;
- PEB/TEB placement, Windows stack setup, TLS, and process parameters;
- handle tables, object types, access masks, waitability, and lifetime;
- virtual-memory reservations, mappings, protection, and query semantics;
- file and section operations backing executable images and mapped data;
- scheduler-coupled synchronization, exception, and termination state.

These services are implemented once and shared with the Linux personality where
the mechanism is common. The NT personality supplies Windows-visible names,
layouts, status codes, and access checks; it does not duplicate the scheduler,
page allocator, VFS, or driver implementations.

### Notepad is the first vertical slice

Notepad is valuable because it exercises the complete launch path without
pretending to represent the whole Windows ecosystem. The first milestone is a
64-bit PE process that can:

1. be selected by the executable loader as an NT personality;
2. receive a valid PEB, TEB, environment, command line, stack, and initial
   thread context;
3. resolve ntdll and Win32 imports through the native relay;
4. create, query, and terminate processes and threads through typed handles;
5. use basic file, memory, heap, TLS, synchronization, and exception paths;
6. reach the userspace windowing path supplied by the Win32 runtime.

A passing Notepad smoke test proves that vertical slice. It does not prove
`user32` completeness, arbitrary desktop applications, Direct3D, audio,
anti-cheat, or game compatibility. Those are later compatibility surfaces
with their own contract and runtime tests.

### Architecture and test gate

The Windows workload is x86-64 only. PE32, WOW64, 16-bit Windows, Windows
kernel drivers, and ARM Windows binaries are outside the target. The kernel
may still be built for AArch64 to preserve shared-code portability, but an
AArch64 build is not an ARM Wine test and must not be reported as one.

The acceptance sequence is:

```text
hosted ABI/layout tests
        |
        v
x86-64 kernel build and Windows smoke boot
        |
        v
64-bit Notepad launch
        |
        v
focused Win32/NT compatibility suites
        |
        v
graphics, audio, input, networking, and Proton-facing applications
```

Every new NT surface needs negative tests and lifecycle tests: malformed user
buffers, invalid handles, wrong object types, insufficient access masks,
teardown while waiters exist, and repeated create/use/close cycles. That is
what keeps a successful Notepad launch from becoming a collection of one-off
paths that fail on the next application.

## 7

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
