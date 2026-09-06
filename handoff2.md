# Notepad: loop dispatches, first paint presented, edit control now created — 2026-09-06

First command: `git log --oneline -6 && tools/issues.sh --show KI-0434 && ls -t target/windows-notepad-acceptance/uart-*.log | head -1`

Everything below is merged to `main` via PR #7520 (6 commits, branch deleted).
The last commit adds two bounded klog traces (`[WINDOWS-WNDEXTRA]` in
`nt_wine_window/long_raw/kernel.rs`, `[WINDOWS-HEAP]` in `nt_heap.rs`); the boot
that used them is uart-109399 (read below). Start a fresh branch.

## What got fixed today (each from the previous boot's log)

| Defect | Commit |
|---|---|
| `NtUserCallHwnd`/`CallMsgFilter` unclaimed → fell to Linux tables → `-ENOSYS` read as TRUE → `IsDialogMessageW(NULL)` ate every message (KI-0427 mechanism, KI-0429) | cf258e94 |
| Unclaimed win32u ids now answer `STATUS_INVALID_SYSTEM_SERVICE`, reported once as `[WINDOWS-RAW-UNCLAIMED]` | cf258e94 |
| `NtUserMoveWindow` 0x14ba admitted (SetWindowPos + NOZORDER\|NOACTIVATE[\|NOREDRAW]) | c5b66ebb |
| Default WM_ERASEBKGND fills clip box with class `hbrBackground` (now recorded at registration) | c5b66ebb |
| Default WM_PAINT runs real BeginPaint/EndPaint (PAINTSTRUCT in kernel, `DefaultPaint` completion) — first `begin-paint`/`present` milestones | c5b66ebb |
| `NtUserGet/SetProcessDpiAwarenessContext` 0x1435/0x1577 | d131fc0e |
| Builtin classes (Button, Edit, Static, …) registered from user32's W procedure array at `NtUserInitializeClientPfnArrays` — before this **no edit control was ever created** | a3d5cdc7 |

Boot history: uart-13548 (loop dispatches, no paint), uart-85330 (first present,
crash in comctl32 status bar), uart-94582 (with `debug-faultdiag`; too slow, but
gave module bases), uart-104368 (edit control created, crash in kernelbase).

## Current blocker: edit control's WM_CREATE crashes in kernelbase LocalLock (uart-109399)

`notepad.exe: segfault at 0 ip 17403a1f8 error 0` = kernelbase `LocalLock+0xa8`,
the `__TRY { *p |= 0 }` probe on a *fixed* (low nibble 0) handle; address 0 with
error 0 is a #GP, so the probed pointer was non-canonical garbage. Chain
(reference): `EditWndProc_common` → `EDIT_LockBuffer(es)`; `es` comes from
`GetWindowLongPtrW(hwnd,0)` set in WM_NCCREATE.

Measured in the last boot with the two bounded traces:
- `[WINDOWS-WNDEXTRA]` slot 0 round-trips correctly for hwnd 2
  (set 7f1ac2c4d000, get 7f1ac2c4d000). Hypothesis 1 is dead.
- `[WINDOWS-HEAP]`: the `es` block (alloc size 0x1000, flags 8 =
  HEAP_ZERO_MEMORY, base 7f1ac2c4d000) is a REUSED extent: the same base was
  freed at 50.247 and handed out again at 50.532. Nothing frees it before the
  crash. A moveable LocalAlloc did run (alloc flags 0x308 → 7f1ac2c34000, then
  RtlSetUserValueHeap), so `es->hloc32W` is a proper `&mem->ptr` handle
  (nibble 8, never probed). The only fixed-handle LocalLock in
  `EDIT_LockBuffer` is `LocalLock(es->hloc32A)`, which must be 0 in a
  zero-initialised `es`.
- Therefore the leading hypothesis: HEAP_ZERO_MEMORY is not honoured on a
  reused extent, so `es->hloc32A` (and everything else) holds the previous
  occupant's bytes. `nt_heap.rs` passes `committed=true` to
  `elf_load::nt_memory::allocate` and never looks at flag 8; `free` munmaps the
  extent, so fresh pages should be zero unless the VMM recycles the frame
  without zeroing or the munmap/mmap pair keeps the mapping. Next: hosted
  test on the VMM path (munmap then mmap the same range, read must be zero),
  then make the heap honour HEAP_ZERO_MEMORY explicitly at the owner, per the
  reference RtlAllocateHeap contract, rather than relying on fresh pages.

Second independent defect found on the way: Windows exceptions never dispatch.
The launcher (`userspace/probes/windows-runtime`, Rust) keeps Rust std's
SIGSEGV/SIGBUS handler, which resets SIG_DFL and returns on any non-guard fault
(that is the `rt_sigaction(SIGSEGV)`, `rt_sigreturn`, re-fault seen in every
crash). `wine_oxide_attach_thread` (`dlls/ntdll/unix/oxide.c` in the source
build under `target/lanes/wine-10.20-source`) never runs `signal_init_process`,
so Wine's `segv_handler` is never installed; and the reference handler needs
wineserver for `send_debug_event`. So a `__TRY/__EXCEPT_PAGE_FAULT` probe that
faults kills the process. docs/31v says exception dispatch is runtime work.
Needs a row + design; not filed yet.

## Also open

- KI-0433: unclaimed `NtGdiCreateBitmap` 0x10a7, `NtGdiCreatePatternBrushInternal`
  0x10b9, `NtGdiOpenDCW` 0x1246 (user32 init, non-fatal so far).
- KI-0434: builtin class registration deviations (trigger point, cursors,
  `NtUserInitBuiltinClasses` callback/uxtheme).
- KI-0435: the acceptance "token" check passes when the token is typed into
  GNOME's overview search (no Notepad window on screen). Do not trust A3.
- KI-0430 accelerator WM_SYSCOMMAND; KI-0431 edit system colours (red test on
  main); KI-0432 flaky namespace test.
- Gates red on main: KI-0287 lint-ratchet, KI-0318 hosted-gate, KI-0423
  test-build-gate, KI-0019 stack-gate, KI-0319 feature-gate (73 dead-code lints,
  none in touched files). Pushes used the five specific `SKIP_*` flags.

## Method / tooling that worked

- Symbolise a guest fault: bases from `[WINDOWS-PE-MODULE]` (needs
  `OXIDE_NOTEPAD_FEATURES=debug-faultdiag`, ~3× slower boot) or anchor on a
  class wndproc; `objdump -p` export table of the host's
  `/usr/lib64/wine/x86_64-windows/*.dll` (system Wine 10.20 == reference tree);
  `objdump -d --start-address` on kernelbase to read the faulting instruction.
- Reference tree for everything Windows: `../reference-wine/wine-10.20`.
- One acceptance boot per commit batch: `./tools/windows-notepad-acceptance.py`
  (~8 min). Log triage: grep `GETMESSAGE`, `WINDOWS-RAW-UNCLAIMED`,
  `WINDOWS-WINDOW-SHOW`, `USER32]`, `GDI]`, `PE-FAULT`, `segfault`.

## Next steps

1. Prove/disprove stale bytes on a reused heap extent with a hosted VMM test;
   then honour HEAP_ZERO_MEMORY in `nt_heap.rs` (reference contract) and
   verify with one acceptance boot. Also check why the extent was freed at
   50.247 in the first place (user32 init churn is fine; a wrong free is not).
2. File the exception-dispatch row; decide kernel-driven
   `KiUserExceptionDispatcher` entry vs installing Wine's handlers in `oxide.c`.
3. Drop or keep the two traces once the heap question is answered.
