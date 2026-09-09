# Hardware filter validation

| Status | Branch | Runtime | Issue |
|---|---|---|---|
| Verified | B3630-paint-region-collapse | ee58ef0b7 | KI-0894 |

- Raw mouse preselection admits possible nonclient/double-click numbers. Final target filtering accepts descendants; excluded events stay queued, preserving click history.
- Stable queue identities continue scans after excluded input, including suspended hit-test callbacks. Queue fallback exposes posted messages, quit and paint; raw input only reaches the application through the hardware preparation path.
- Exhausted scan watermark reaches the actual GetMessage wait predicate. Retained excluded input does not spin; new input remains ready even before an identity is assigned.
- debug-winpump WINDOWS-HARDWARE-FILTER records selected identity, target, message and HWND/number filter.
- Production hardware fixture:18 tests PASS. Separate production dispatcher fixture:121 tests PASS. Task/clock/user-procedure and usercopy boundaries remain hosted seams; this is not a real User32 callback ABI or visual acceptance run.
- Initial nonclient-only and retained-filter scan regressions fail before implementation: /tmp/B3630-filter-red.log.
- Removing posted fallback exclusion, wait watermark or final target filter independently fails an assertion: /tmp/B3630-filter-{peek-hook,wait-hook,target-filter}-red.log. Restored18/121 PASS: /tmp/B3630-filter-restored.log.
- Full library suites PASS:1527 IPC,3270 syscalls; /tmp/B3630-filter-{ipc,syscalls}.log.
- Both final release builds PASS: /tmp/B3630-filter-final-build.log. Both feature checks PASS: /tmp/B3630-filter-feature.log.
- Both frame-size gates PASS: /tmp/B3630-filter-frame-{x86,arm}.log.
- Both static stack gates retain KI-0019 failures. Primary report rows including exception:336x86/278ARM, previously337x86/278ARM. No new or increased reported path; exception reservations7664/6368 unchanged. Comparison excludes the reordered top20 summary, preserves complete reports and does not remove recursive/indirect uncertainty.
- Reports: /tmp/B3630-filter-final-stack-{x86,arm}.log against /tmp/B3630-pointer-position-stack-{x86,arm}.log.
- Final x86 ELF target/B3630-filter-final-x86.elf SHA25696c60f260182869f8c5e7df59e05ea85677ad9c5e801ba728a80af868cba6f52.
- Final ARM ELF target/B3630-filter-final-arm.elf SHA256126d6d06389a46e0c58fe938be940771235f4242d595887c5d0e7136b986a04f.
- No new VM launched. Child-surface input scope/owner fallback KI-0682, scrollbar procedure KI-0885, dialog rendering and Open/Save acceptance remain open. Prior failed preview retained under target/B3630-click-preview-debug.
