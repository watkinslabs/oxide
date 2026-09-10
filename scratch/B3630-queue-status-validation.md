# Sent queue status and wait masks

| Status | Branch | Work |
|---|---|---|
| IMPLEMENTED | B3630-paint-region-collapse | KI0910 sent status and shared mask admission |
| OPEN | B3630-paint-region-collapse | KI0712 wait flags; KI0911 quit changed bits |

Public user_input::queue_status_for_current validates the mask through the
canonical WindowManager before combining its result with the sent owner.
Sent admission sets per-target changed state in the existing sent-owner thread records; queries clear only requested
changes. Starting or cancelling the last queued item clears both status
halves even while an already-started callback remains alive. Consuming one
arrival preserves changed state when other pending work remains. Failed
admission sets no changed state. No new inbox or callback queue.

message_queue::route and its reexport call wait_live::msg_wait. Both initial
readiness and the scheduler park predicate call ready::queue, which masks
QS_SENDMESSAGE before accepting the sent inbox. Extraction makes the actual
wait loop executable in the hosted boundary fixture.

nt_message_queue_boundary:34 PASS (5 actual adapter/wait checks, 20 sent
owner checks, 9 wait encoding checks). Canonical WindowManager and sent owner;
current task, scheduler parking, named-object readiness and clock are hosted
seams. Tests cover status merge/invalid masks, old versus changed bits,
initial readiness, arrival during parking with included/excluded masks,
object precedence, queue slot and finite timeout. nt_window_send_boundary:
70 PASS including copied-event status before and during actual pump callback
installation. Full syscall library3276 PASS. No fixture executes guest DLLs.

Three controls each execute one intended failing test: remove sent-status
merge; remove the sent-class mask; leave changed state after the last pending
item starts. Restored production sources and both final fixtures PASS.
Logs /tmp/B3630-queue-status-{final-tests,hooks,control-merge,
control-park-mask,control-drain}.log. Both feature checks PASS, log
/tmp/B3630-queue-status-feature-final.log. Runtime3fea856f4: both release builds, feature checks and frame gates PASS.
Static gates retain existing KI0019 failures;335x86/278ARM primary rows, no
added/increased paths versus owner-delivery baseline. Exception7664/6368
unchanged. Logs /tmp/B3630-queue-status-{final-build-x86_64,
final-build-aarch64,final-frame-x86,final-frame-arm,final-stack-x86,
final-stack-arm,stack-compare}.log. Initial separate changed-state vector added
32-64 bytes on nine deep x86 paths; replaced by changed/exit flags sharing
the existing sent-owner thread records, preserving Queue/GuiEntry size.
Retiring-thread admission remains tested across status query and drain.

KI0712: raw wait route still drops flags; changed-only/input-available,
wait-all and alertable contracts remain incomplete. KI0911: posting quit
omits posted changes; removing the last posted message leaves stale changes. No full message-wait
or desktop acceptance claim. No VM launched; About/Open/Save/menus/borders/
buttons still require final real desktop verification.

Named-object consumption/timer deadlines KI0912 and handle stride KI0844
remain open; object-precedence seam does not validate those contracts.

x86: primary rows 335 -> 335; added={} growth=[]
target/B3630-queue-status-x86_64.elf sha256=600c58ae5ec64010b3e91995295db55e0d11a3481866ed66f829eef1af66ea2a
arm: primary rows 278 -> 278; added={} growth=[]
target/B3630-queue-status-aarch64.elf sha256=8ad92fc949b475343617d93987f665f2ac59d7fecfe46fdc962e19525eea5e06
