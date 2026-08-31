# Windows Compatibility Plan

## Objective

Add native 64-bit Windows game compatibility to the Rust operating
system without turning the kernel into Windows and without
reimplementing the entire Win32 ecosystem.

The target architecture is:

``` text
Windows x86-64 Game
        |
        v
Wine-derived Win32 DLLs / compatibility runtime
        |
        v
NTDLL / NT ABI boundary
        |
        v
Native NT personality
        |
        v
Rust Kernel
        |
        +-- Scheduler
        +-- Virtual Memory
        +-- VFS
        +-- Networking
        +-- IPC
        +-- Drivers
        +-- GPU / Graphics
```

The goal is to reuse Wine/Proton where it makes sense in userspace while
implementing the fundamental NT-facing kernel semantics natively.

This is not a plan to emulate Windows.

Windows x86-64 machine code should execute directly on x86-64 hardware.

The Windows compatibility gate is therefore x86-64-only. AArch64 checks cover
shared kernel and ABI compilation; they do not imply ARM Wine support, ARM
Notepad support, or a Windows workload boot on AArch64.

------------------------------------------------------------------------

## Scope

### Supported

Initial Windows compatibility is deliberately limited to:

-   x86-64 Windows applications
-   64-bit PE32+ executables
-   64-bit Windows DLLs
-   Windows games
-   game launchers where reasonably necessary
-   common Win32 APIs required by games
-   Direct3D gaming through Vulkan translation
-   Windows networking required by games
-   controllers and common game input
-   audio required by games
-   common Windows synchronization primitives
-   common filesystem behavior
-   enough registry support for games and launchers
-   Steam/Proton-oriented compatibility where useful

### Explicitly Not Supported

Do not expand the project into general Windows replacement
compatibility.

Initial versions will NOT target:

-   32-bit Windows applications
-   WOW64
-   16-bit Windows
-   DOS
-   Windows kernel drivers
-   arbitrary `.sys` drivers
-   Windows device driver compatibility
-   Active Directory
-   enterprise Windows administration
-   Windows Server
-   domain controllers
-   full Windows desktop compatibility
-   obscure legacy Win32 applications
-   Internet Explorer compatibility
-   legacy COM edge cases unless required by games
-   printers
-   scanners
-   enterprise authentication stacks
-   Microsoft Office compatibility as a project goal
-   every historical Windows API
-   perfect Windows bug compatibility

If a feature does not materially help run modern 64-bit Windows games,
it should normally remain out of scope.

------------------------------------------------------------------------

# Core Principle

Do not implement Wine inside the kernel.

Do not reimplement all of Wine.

Instead, divide responsibilities cleanly:

``` text
USERSPACE
------------------------------------------------

Windows Game
    |
Wine-derived Win32 APIs
    |
kernel32 / user32 / gdi32 / advapi32 / etc.
    |
ntdll
    |
------------------------------------------------
KERNEL BOUNDARY
------------------------------------------------
    |
Native NT syscall/personality layer
    |
Common Rust kernel primitives
```

Wine provides decades of Windows userspace compatibility.

The kernel provides native implementations of the low-level semantics
that Windows applications ultimately expect.

------------------------------------------------------------------------

# Existing Linux Architecture

The existing operating system can continue exposing its Linux
personality:

``` text
ELF Application
      |
glibc
      |
Linux syscall ABI
      |
Rust Kernel
```

Fedora/systemd userspace remains supported through this interface.

Windows becomes a second execution personality:

``` text
                    Rust Kernel
                         |
          +--------------+--------------+
          |                             |
    Linux Personality              NT Personality
          |                             |
    Linux Syscalls                  NT Syscalls
          |                             |
        glibc                         ntdll
          |                             |
 Fedora / systemd              Win32 compatibility
                                        |
                                  Windows Game
```

Both personalities should use common internal kernel services rather
than duplicating the kernel.

------------------------------------------------------------------------

# Phase 1 ... PE32+ Loader

Teach the kernel/process subsystem to recognize and launch 64-bit
Windows PE32+ binaries.

Implement:

-   DOS header validation
-   PE signature validation
-   COFF header parsing
-   PE32+ optional header
-   section table parsing
-   image mapping
-   executable/read/write permissions
-   preferred image base
-   relocations
-   imports
-   exports
-   TLS directory handling
-   exception/unwind metadata
-   ASLR-compatible mapping
-   DLL dependency discovery
-   entry-point initialization

Only PE32+ is required.

PE32 is explicitly unsupported.

The executable loader should identify ELF versus PE and select the
appropriate process personality.

``` text
exec()
 |
 +-- ELF ------> Linux personality
 |
 +-- PE32+ ----> NT personality
```

------------------------------------------------------------------------

# Phase 2 ... Windows Process Environment

A mapped PE file is not enough to run a Windows application.

Implement the minimum x86-64 Windows process environment.

Required structures include:

-   PEB
-   TEB
-   process parameters
-   environment block
-   Windows command-line representation
-   DLL loader state
-   TLS
-   thread initialization
-   Windows stack conventions
-   x86-64 Windows ABI requirements
-   exception/unwind state

Each PE process should be explicitly marked as an NT personality
process.

------------------------------------------------------------------------

# Phase 3 ... NT Syscall Interface

Create a native NT syscall personality.

The exact ABI does not have to internally resemble Windows.

The external behavior exposed through the compatibility NTDLL must
provide the semantics applications expect.

Initial syscall families should include equivalents for:

## Files

-   `NtCreateFile`
-   `NtOpenFile`
-   `NtReadFile`
-   `NtWriteFile`
-   `NtQueryInformationFile`
-   `NtSetInformationFile`
-   `NtQueryDirectoryFile`

These map into the existing VFS after NT semantics have been handled.

``` text
NtCreateFile
      |
NT path/share/access processing
      |
kernel VFS
```

## Virtual Memory

-   `NtAllocateVirtualMemory`
-   `NtFreeVirtualMemory`
-   `NtProtectVirtualMemory`
-   `NtQueryVirtualMemory`
-   `NtCreateSection`
-   `NtMapViewOfSection`
-   `NtUnmapViewOfSection`

These should use the existing VM implementation.

## Processes and Threads

Implement the required subset of:

-   process creation
-   process information
-   thread creation
-   thread termination
-   thread information
-   suspend/resume where games require it
-   process/thread handles

These ultimately use the existing scheduler and process implementation.

------------------------------------------------------------------------

# Phase 4 ... NT Object and Handle Model

Windows software relies heavily on NT handles and kernel objects.

Create an NT object abstraction over common kernel primitives.

Initial objects:

-   process
-   thread
-   file
-   directory
-   section
-   event
-   semaphore
-   mutant/mutex
-   timer
-   completion port
-   token

Example:

``` text
NT Event
   |
NT object layer
   |
kernel synchronization primitive
```

NT handles should be process-local references to kernel objects with
Windows-compatible access rights and lifetime semantics.

------------------------------------------------------------------------

# Phase 5 ... Native Synchronization

This is one of the most valuable areas to implement directly.

Support Windows-style:

-   events
-   mutexes
-   semaphores
-   timers
-   single-object waits
-   multiple-object waits
-   alertable waits
-   signal-and-wait behavior

Target operations include:

-   `NtWaitForSingleObject`
-   `NtWaitForMultipleObjects`
-   `NtSetEvent`
-   `NtResetEvent`
-   `NtReleaseSemaphore`
-   `NtReleaseMutant`

The goal is:

``` text
Windows Game
     |
WaitForSingleObject
     |
ntdll
     |
NtWaitForSingleObject
     |
SYSCALL
     |
Native Rust kernel wait implementation
```

rather than translating NT synchronization into a chain of Linux
compatibility operations.

------------------------------------------------------------------------

# Phase 6 ... Wine-Derived Userspace

Do not rewrite the enormous Win32 userspace API surface.

Adapt Wine components as the Windows userspace runtime.

Likely retained/adapted components include:

-   kernel32
-   kernelbase
-   user32
-   gdi32
-   advapi32
-   shell32
-   ole32
-   comctl32
-   winmm
-   ws2_32
-   crypt32
-   bcrypt
-   version
-   setupapi where games require it
-   common runtime support

The long-term boundary should resemble:

``` text
Win32 API
    |
Wine-derived implementation
    |
ntdll
    |
Native kernel NT interface
```

Wine should increasingly become a Win32 userspace implementation rather
than a Windows-to-Linux translation layer.

------------------------------------------------------------------------

# Phase 7 ... Filesystem Semantics

Games expect Windows filesystem behavior that differs from normal POSIX
semantics.

Implement or emulate:

-   drive letters
-   `C:\` paths
-   NT object paths
-   backslash path separators
-   case-insensitive lookup
-   case-preserving names
-   Windows file attributes
-   sharing modes
-   delete semantics
-   rename semantics
-   file locking
-   memory-mapped files
-   Windows timestamp behavior where required

Example mapping:

``` text
C:\Games\Example\data.pak
             |
NT path layer
             |
/windows/c/Games/Example/data.pak
             |
kernel VFS
```

The exact underlying mount layout is an implementation detail.

------------------------------------------------------------------------

# Phase 8 ... Registry

Implement a lightweight registry service suitable for games.

Required roots initially:

-   HKLM
-   HKCU
-   HKCR where required

Support:

-   keys
-   values
-   common value types
-   enumeration
-   persistence
-   per-user state

The registry does not necessarily belong in the kernel.

Prefer a userspace registry database/service with kernel primitives only
where required.

------------------------------------------------------------------------

# Phase 9 ... Exceptions and x86-64 Unwinding

Modern Windows games depend heavily on correct exception behavior.

Implement:

-   x86-64 Windows unwind metadata
-   structured exception handling
-   exception dispatch
-   vectored exception handling
-   stack unwinding
-   guard-page exceptions
-   access violations
-   breakpoint/debug exceptions where required

This must be correct enough for C++, game engines, crash handlers and
runtime libraries.

------------------------------------------------------------------------

# Phase 10 ... Graphics

Do not implement Direct3D from scratch.

Use the existing gaming compatibility ecosystem.

Preferred architecture:

``` text
Game
 |
 +-- Direct3D 9/10/11
 |        |
 |       DXVK
 |        |
 |      Vulkan
 |
 +-- Direct3D 12
          |
      vkd3d-proton
          |
        Vulkan
          |
     Native GPU stack
```

The OS should provide a strong native Vulkan implementation/interface.

This gives the Windows gaming personality a realistic path to modern
DirectX support without recreating Microsoft's graphics stack.

------------------------------------------------------------------------

# Phase 11 ... Audio

Provide the Windows audio APIs required by games through userspace
compatibility libraries.

Map them onto the OS native audio subsystem.

Prioritize:

-   XAudio2
-   WASAPI behavior needed by games
-   DirectSound compatibility
-   common multimedia timing APIs

Do not attempt complete historical Windows multimedia compatibility.

------------------------------------------------------------------------

# Phase 12 ... Input

Support gaming-oriented input:

-   keyboard
-   mouse
-   Xbox-style controllers
-   XInput
-   common HID game controllers
-   raw input where required

Avoid implementing unrelated Windows HID/device behavior unless a real
game requires it.

------------------------------------------------------------------------

# Phase 13 ... Networking

Windows networking APIs should ultimately use the kernel's native
network stack.

``` text
Game
 |
Winsock
 |
ws2_32
 |
NT/userspace socket adaptation
 |
kernel networking
```

Prioritize normal game networking:

-   TCP
-   UDP
-   IPv4
-   IPv6
-   DNS
-   asynchronous socket behavior required by games

------------------------------------------------------------------------

# Phase 14 ... Steam and Proton Compatibility

Steam compatibility is a major practical milestone.

The goal is not necessarily to run the Windows Steam client first.

A Linux-native Steam client running through the Linux personality may
launch Windows games through the Windows personality.

Possible architecture:

``` text
Steam Linux ELF
      |
Linux personality
      |
Rust Kernel
      |
launches
      |
Windows PE Game
      |
NT personality
```

Proton components can be selectively reused for:

-   game-specific compatibility patches
-   DXVK
-   vkd3d-proton
-   runtime libraries
-   controller compatibility
-   media compatibility
-   known game workarounds

The project should reuse proven Proton work rather than intentionally
diverging from it.

------------------------------------------------------------------------

# Kernel Architecture Rule

Do not bake Linux behavior into fundamental kernel subsystems.

Use:

``` text
Linux syscall
     |
Linux semantic adapter
     |
COMMON KERNEL API
```

and:

``` text
NT syscall
     |
NT semantic adapter
     |
COMMON KERNEL API
```

For example:

``` text
linux_openat()
      |
      +----> VFS::open()

nt_create_file()
      |
NT sharing/path/access semantics
      |
      +----> VFS::open()
```

Likewise:

``` text
linux_mmap()
     |
     +----> VM

nt_allocate_virtual_memory()
     |
     +----> VM
```

This separation is fundamental to making the kernel genuinely
multi-personality rather than implementing Windows compatibility on top
of Linux compatibility.

------------------------------------------------------------------------

# What We Are Replacing From Wine

We are NOT trying to replace all of Wine.

We are primarily replacing the lowest-level Unix/Linux translation
portions with native kernel facilities.

Conceptually, traditional Wine/Proton:

``` text
Windows Game
     |
Win32 APIs
     |
Wine
     |
NT behavior translated to Unix/Linux behavior
     |
Linux syscalls
     |
Linux kernel
```

Target:

``` text
Windows Game
     |
Wine-derived Win32 APIs
     |
NTDLL
     |
Native NT syscall ABI
     |
Rust Kernel
```

This removes the requirement for Windows applications to reach the
kernel through the Linux personality.

------------------------------------------------------------------------

# Why This Can Be Better

This architecture is not automatically faster than Wine/Proton.

Wine and Proton are heavily optimized.

The potential advantage comes from removing semantic impedance where
Windows and Linux fundamentally behave differently.

Potential improvements include:

-   native Windows-style waits
-   native NT object handles
-   fewer compatibility transitions
-   direct NT memory operations
-   native section objects
-   native Windows file-sharing behavior
-   reduced wineserver-style coordination
-   direct integration with the kernel scheduler
-   direct integration with VM
-   direct integration with asynchronous I/O

The objective is architectural cleanliness and native semantics first.

Performance improvements should be measured rather than assumed.

------------------------------------------------------------------------

# Code Ownership Estimate

For the Windows compatibility stack as a whole, a rough target is:

``` text
~20-30% custom/native OS work
~70-80% Wine/Proton-derived or other reusable userspace work
```

This is not a literal LOC guarantee.

The custom portion contains the architectural core:

-   PE execution
-   NT personality
-   objects
-   handles
-   synchronization
-   VM semantics
-   process/thread integration
-   filesystem semantics
-   kernel interfaces

The borrowed portion contains the enormous compatibility surface
accumulated by Wine and Proton.

Because the kernel already has:

-   scheduler
-   processes
-   threads
-   VFS
-   VM
-   IPC
-   networking
-   drivers

the Windows-specific additions to the entire kernel may ultimately
represent a relatively small percentage of total kernel code.

The important difference is ownership of the execution boundary.

------------------------------------------------------------------------

# Milestones

## W0 ... Architecture Preparation

-   separate Linux syscall semantics from core kernel primitives
-   define process personality abstraction
-   define executable format abstraction
-   define generic kernel object primitives

## W1 ... Hello PE

Launch a trivial hand-built x86-64 PE executable.

No Win32 API dependency.

Success:

``` text
PE -> loader -> entry point -> exit
```

## W2 ... NTDLL

Load an x86-64 PE executable with an NTDLL-compatible userspace layer.

Implement enough NT calls for basic execution.

## W3 ... Console Application

Run a simple 64-bit Windows console executable.

Support:

-   files
-   memory
-   threads
-   synchronization
-   stdout/stderr equivalent

## W4 ... Wine Win32 Runtime

Adapt the required Wine DLLs to the native NT personality.

Run simple Win32 programs.

## W5 ... Window

Display a basic Win32 GUI application.

Input and event loop functional.

## W6 ... Vulkan Game

Run a simple native Windows Vulkan game/application.

This tests Windows compatibility without DirectX translation.

## W7 ... DXVK

Run a Direct3D 11 game through DXVK.

``` text
D3D11 -> DXVK -> Vulkan -> GPU
```

## W8 ... vkd3d-proton

Run a Direct3D 12 title.

``` text
D3D12 -> vkd3d-proton -> Vulkan -> GPU
```

## W9 ... Steam Game

Launch a Windows Steam game from the Linux-native Steam environment.

## W10 ... Compatibility and Performance

Profile:

-   syscall transitions
-   waits
-   context switches
-   wineserver dependencies
-   file operations
-   memory mappings
-   graphics submission
-   shader compilation
-   frame-time variance

Move functionality into native NT kernel facilities only where there is
a measurable architectural or performance benefit.

------------------------------------------------------------------------

# Non-Goal: Recreating Windows

This project is not intended to become a clone of Windows.

The objective is:

> Run modern 64-bit Windows games directly on the OS using native CPU
> execution, a native NT kernel personality, and proven Wine/Proton
> userspace compatibility components.

We are building the kernel semantics needed by games.

We are borrowing the enormous userspace compatibility work that already
exists.

We are deliberately ignoring the rest.

------------------------------------------------------------------------

# End State

The final OS architecture should look roughly like:

``` text
                         APPLICATIONS

             Linux ELF                Windows PE32+
                 |                         |
               glibc                  Win32 DLLs
                 |                   Wine-derived
                 |                         |
                 |                       ntdll
                 |                         |
          Linux syscall ABI           NT syscall ABI
                 |                         |
                 +-----------+-------------+
                             |
                       RUST KERNEL
                             |
       +----------+----------+----------+----------+
       |          |          |          |          |
      VFS         VM      Scheduler   Network     IPC
       |          |          |          |          |
       +----------+----------+----------+----------+
                             |
                          Drivers
                             |
                          Hardware
```

Linux and Windows are application personalities.

Neither defines the internal kernel architecture.

The Rust kernel remains the operating system core.
