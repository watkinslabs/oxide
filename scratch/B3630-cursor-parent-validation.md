# B3630 parent-first default cursor

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0462 |
| OPEN | B3630-paint-region-collapse | KI0902 error-area sound |

Raw default-procedure entry now reaches canonical default dispatch for
WM_SETCURSOR. Child handling queries canonical relative_parent, excludes
resize-border hit codes and the exact current desktop handle, and sends
original wParam/lParam outside GUI ownership. Nonzero parent response returns
TRUE without installing another cursor. Zero/failure applies the direct
cursor step and returns0, discarding the installation result.

Continuation uses the existing Send owner. Class step retains full64-bit
wParam; OEM step retains its32-bit cursor id. Resume function distinguishes
class/OEM/error-area OEM; no packing/truncation of a window handle, new queue,
or extra callback registry. Class cursor lookup and shared cursor loading
remain in the canonical owner and run only after parent decline. Error-area
beep intent survives; missing actual sound operation tracked by KI0902.

Before repair: independent production-dispatch parent test fails0 vs1,
exit101 (/tmp/B3630-cursor-parent-red.log). After repair:139 dispatcher/cursor
policy tests pass, exit0 (/tmp/B3630-cursor-parent-green.log). Cases cover
immediate parent acceptance/zero/failure, desktop and resize exclusion,
nonchild direct handling, ignored installation return, suspended decline,
full64-bit class handle, and failed parent preserving OEM/beep intent.
Cursor installation, desktop identity and sent-message execution are explicit
hosted seams; real policy/default dispatcher are exercised. Raw selector
routing reviewed in source, not independently executed by this fixture.

An intermediate test fixture allocated normal windows in the server handle
block; corrected activation/cursor scaffolding uses FIRST_OWNER_BLOCK. The
production check names the exact desktop, not every server-reserved handle.
Existing real Send boundary27 tests pass (/tmp/B3630-parent-handling-send.log);
syscall library3270 tests pass. First build correctly rejected the now-unused raw WM_SETCURSOR constant;
removed it, no warning suppression. Final build/feature validation completed below.

No new boot. Full visual Notepad acceptance and GNOME startup cause remain
unresolved; these checks do not establish rendered buttons/dialogs/cursors.

Final validation: make build and make feature-gate exit0 for both architectures;
both frame gates exit0. Static stack gates exit1 on existing KI0019 failures,
with336x86/278ARM primary rows unchanged and no added/increased path versus
futex-site baseline; exception7664/6368 unchanged. Full stack gate not green.
/tmp/B3630-parent-handling-final-{build,feature}.log;
/tmp/B3630-parent-handling-{frame,stack}-{x86,arm}.log;
/tmp/B3630-parent-handling-stack-compare.log. Current snapshots:
x86_64: 3c6f28cfd0d10e49d7f22a29e9f7cb5050e34f5e173dd8efc538d07e4a81e512 target/B3630-parent-handling-x86_64.elf
aarch64: da6783bb6bb2f7edf6fb4443401bc41404ac4ea8add84496fd4a794feb6e4a63 target/B3630-parent-handling-aarch64.elf
