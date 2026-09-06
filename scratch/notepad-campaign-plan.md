# Notepad-on-oxide campaign plan (2026-09-06)

Goal: notepad.exe (Wine 10.20 PE DLLs, oxide in-kernel NT/win32u services) runs on oxide: window shown, text typed into the edit control, painted, menus and dialogs usable. Reference trees: `../reference-wine/wine-10.20`, `../windows_reference`. One acceptance boot per merged batch (`tools/windows-notepad-acceptance.py`); every other question answered hosted.

| Status | Item | Branch | Notes |
|---|---|---|---|
| IN-PROGRESS | KI-0436 NT free leaves page tables mapped (stale `HEAP_ZERO_MEMORY` bytes, frame leak) | B3522-nt-free-zaps-page-tables | fix committed; acceptance boot pending |
| IN-PROGRESS | KI-0437 exception dispatch (`KiUserExceptionDispatcher`, `__EXCEPT_PAGE_FAULT`) | lane B-exception-dispatch | design in `scratch/exception-dispatch-KI-0437.md` |
| IN-PROGRESS | KI-0433 unclaimed GDI ordinals (CreateBitmap, CreatePatternBrushInternal, OpenDCW) + any other RAW-UNCLAIMED | lane F-gdi-bitmap-pattern-brush-opendc | |
| IN-PROGRESS | KI-0435 acceptance A3 token check locates the Notepad window | lane C-notepad-acceptance-token-locate | positive control on screen-94582 |
| OPEN | KI-0434 builtin class cursors + `NtUserInitBuiltinClasses` callback (uxtheme) | | after edit control survives WM_CREATE |
| OPEN | KI-0430 accelerator WM_SYSCOMMAND | | |
| OPEN | KI-0431 edit system colours (red test on main) | | |
| OPEN | KI-0438 page-per-allocation process heap | | perf/VMA count; not blocking |
| OPEN | next crash after KI-0436 (unknown until the boot) | | triage from uart log: `GETMESSAGE`, `WINDOWS-RAW-UNCLAIMED`, `segfault`, `PE-FAULT` |

Order: land B3522 → read its boot log → spawn the next crash lane immediately → merge lanes as they report (integration owner applies hooks, positive-controls, boots once per batch).
