# Scrollbar control queries

Status: query routing repaired; KI-0885 full control behavior open. Branch: B3630-paint-region-collapse.

- Actual `control_proc::for_current` routes SBM_GETPOS, SBM_GETRANGE and SBM_GETSCROLLINFO. Range/position snapshot canonical HWND control state; SCROLLINFO uses existing live codec and canonical owner fill. No parallel state or self-send recursion.
- GETPOS sign-extends negative position. GETRANGE allows either/both null destinations, writes minimum before maximum (aliasing supported) and returns false without output when control state is absent.
- SCROLLINFO size24/28 and mask validation remain common; unrequested fields and size24 tracking tail survive unchanged. Nontracking nTrackPos reports position. Invalid/empty masks and absent data fail without fabricated output.
- Actual procedure fixture returned STATUS_NOT_IMPLEMENTED before wiring: `/tmp/B3630-control-query-red.log`, exit101. Remaining failures in that run were shared fixture-lock poisoning after the first assertion.
- All30 scroll boundary tests pass, including4 new query cases: `/tmp/B3630-control-query-final.log`. Full IPC suite1532 pass: `/tmp/B3630-control-query-ipc.log`.
- Still missing: control state setters, synchronous refresh, ordinary pointer/key/focus/caret behavior and accessibility query. Existing standard accessibility snapshot also needs dxyLineButton thumb-size semantics and pressed/capture state; retained in KI-0885. No new VM or full dialog acceptance claim.

- Both release builds, feature checks and frame gates pass. Static stack reports retain336x86/278ARM primary rows with no added/increased path (multiset comparison). KI0019 baseline failures remain, no budget/allowlist changes. Logs `/tmp/B3630-control-query-{build,feature,frame-x86,frame-arm,stack-x86,stack-arm,stack-compare}.log`.
- target/B3630-control-query-x86_64.elf: SHA256 6555cb006488e148c830fd733493f08183235594f9d197e2efd297bc60f928c2.
- target/B3630-control-query-aarch64.elf: SHA256 f07d088f0ce0960c83945bb5513da8b9828dd005975902fef5fbde833e232c3d.
