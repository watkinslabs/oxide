# Native pointer scope validation

| Status | Branch | Runtime | Issue |
|---|---|---|---|
| Verified | B3630-paint-region-collapse | a165b0c85 | KI-0682 |

- Native child surfaces supply coordinate origins; queued HWND retains the top-level scope. Capture still selects its own HWND/thread and does not change coordinate origin.
- Canonical first-child point walk selects the queue thread without allocating candidate lists or invoking the scope hit test. No duplicate HWND/input registry.
- Retrieval can walk from a transparent child to its sibling. Exhausted scope tries its immediately following owner once, on the same thread; suspended callbacks preserve that position.
- Production hardware fixture24 tests PASS, including native transparent child, cross-thread point recipient, synchronous/suspended owner walk, intervening unrelated sibling and foreign-thread owner rejection.
- Production dispatcher fixture121 tests PASS. Geometry fixtures now inspect the queued root HWND before exercising the child hit-test boundary; real driver tests verify retargeting.
- Library suites1529 IPC/3270 syscalls PASS. Logs /tmp/B3630-scope-ipc-restored.log, scope-syscalls-lib-final.log, scope-boundary-restored.log.
- Initial native-child, queue-thread and owner-walk tests fail before repair: /tmp/B3630-scope-{driver,owner,popup}-red.log.
- Replacing the direct thread lookup with scope hit selection fails the disabled-scope queue-thread assertion: /tmp/B3630-scope-thread-walk-red.log. Restored suite PASS.
- Both final release builds and feature checks PASS: /tmp/B3630-scope-final-build.log, scope-feature.log. Both frame-size gates PASS: /tmp/B3630-scope-frame-{x86,arm}.log.
- Static stack gates retain KI-0019 failures. Primary tables including exception remain336x86/278ARM with no new or increased path against /tmp/B3630-filter-final-stack-{x86,arm}.log. Exception reservations7664/6368 unchanged. Full /tmp/B3630-scope-stack-{x86,arm}.log reports retain recursive/indirect uncertainty; no global stack-safety claim.
- Final ELF target/B3630-scope-final-x86.elf SHA256 d66002eb605b8f8e64db38491a3a05519874444bd432c8e0d2236849184cb851.
- Final ELF target/B3630-scope-final-arm.elf SHA256 b03e32c5d9aaaf2a5ac5fe326d91fec327abdf93ec43090d74ba10ad8c0daeae.
- No new boot. Fixtures use hosted task/clock/user-procedure boundaries; raw User32 ABI and visual acceptance remain separate. KI-0504 thread-input ownership, KI-0861 client-layout collapse, KI-0885 scrollbar procedure and KI-0887 rendering remain open.
