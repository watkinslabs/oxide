# B3630 futex blocking-site diagnostics

| Status | Branch | Item |
|---|---|---|
| FIXED9afaf5491 | B3630-paint-region-collapse | KI-0901 |

Latest visible verification: Sept9 22:32:39–22:36:26UTC. User closed QEMU
because desktop startup remained stalled. Launcher status0 is not an
unexplained crash. No GNOME desktop appeared, no Notepad launched, no clicks
or dialog acceptance occurred. KI0865 remains open.

Artifacts: target/B3630-display-verification-debug/live.json,
manual-commands.jsonl, boot-check.png, desktop-check.png; UART
 target/boot-logs/x86_64-20260909-223239.log. Guest thread snapshot
 /tmp/B3630-display-guest-threads.json; successful SSH session status
 /tmp/B3630-display-guest-status.log. Later DisplayConfig SSH request failed
with connection refused after VM exit; it did not measure guest D-Bus.

Staged compositor SHA256:
9d2d07c8452d9035c73f44edf9dab9fc00caa54de5aa8c2310b8c04e884f6a3e.
Boot kernel SHA256:
9fef81a55a007ad6cd99960eddca292f1d22466669653e373ebe85586e98a533.
Wine11.16-debug source/staged stamp:
000982e8e976863f0a29925ab7426d09808a3e61c125c18decc4cf77f27af5da.

Thread387 snapshot: syscall202, op0x80, expected2, timeout0,
word0x55db348399c8; wchan names prior poll wait. Thread415 also records
syscall202 but names prior block submission. Futex ordinary/vector/PI
paths publish Sleeping without updating canonical task park_site. Readers
therefore expose a previous wait. This is a diagnostic defect; no mutex owner,
user backtrace, lost wake, or GNOME stall cause is established.

Repair: record current futex blocking site before every futex sleep
publication, including PI requeue and spurious-wake repark. No additional
registry, wake policy, timer, or logging filter. Source-position diagnostics
remain subject to existing KI0152 symbol-resolution limitation.

Regression drives actual ordinary/vector production waits using concurrent
host threads and existing scheduling/usercopy seams. Seed previous site;
wait and wake normally; require futex site to replace seed. Thread-local
note seam observes real production call, not a complete procfs read.
Both regressions fail before correction, pass after.
/tmp/B3630-futex-site-red.log:2 failed, exit101.
/tmp/B3630-futex-site-green.log:68 core and102 PI tests pass, exit0.
PI site calls reviewed/compiled; these two new assertions cover ordinary and
vector paths specifically. No new boot for this diagnostic repair.

All recorded stack strings are empty. Collection used uid1000 and did not record CapEff; pid_stack_body returns
empty on missing SYS_ADMIN
before walking saved context. Empty files therefore do not establish a
missing stack or unwinder failure. Next capture must use privileged reads of
/proc/PID/task/TID/stack with credentials recorded, before attempting ptrace.
Current VM no longer exists; these stacks cannot be recovered retroactively.

Validation: make build and make feature-gate exit0 on both architectures;
frame gates exit0. Static stack gates exit1 on existing KI0019 failures:
336x86/278ARM primary rows unchanged, no added/increased path;
exception7664/6368 unchanged. Full stack gate is not green.
/tmp/B3630-futex-site-{build,feature,frame-x86,frame-arm,stack-x86,
stack-arm,stack-compare}.log. IPC library1529 tests exit0.
Refused ordinary/vector waits preserve the previous site because no sleep
occurred. Existing failed-startup evidence preserved; no reboot/retry.
