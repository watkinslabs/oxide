# WinEvent owner-thread delivery

| Status | Branch | Work |
|---|---|---|
| IMPLEMENTED | B3630-paint-region-collapse | KI0907 copied event delivery through existing sent inbox |
| OPEN | B3630-paint-region-collapse | KI0910 public queue-status/wait-mask admission |

hook_api::resume_event posts out-of-context hooks through send::post_event,
including hooks owned by the announcing thread. In-context hooks still use
the existing client callback table. Posting locates the owner's canonical
queue across process entries, refuses missing/retiring queues, and wakes its
existing wait list after releasing GUI. No second inbox.

Send Work carries an immutable shared event payload with hook/module,
announcing thread and posting time. The common message carries event/HWND/
object/child. Existing FIFO, capacity, retrieval and nested send-wait
continuations apply. Pump invokes the client callback record without requiring a live HWND
procedure. Event work is not an InSendMessage/ReplyMessage
request, does not wait for its announcer, and survives announcer exit.
Window destruction cancels queued event work only when it belongs to that
window's owning thread queue; foreign queues retain their copied events.
Owner exit removes work through existing queue teardown.

64 send-boundary tests PASS: 8 new event cases, 29 included IPC hook tests,
27 existing send/reply/continuation tests. Actual send queue/pump/client-record
with scheduler/window-lookup/callback-execution seams. Covers another thread,
another process, same-thread asynchronous delivery, missing queue, retiring
owner, original event fields, inbox order, destruction, announcer exit,
wakeup outside GUI and resuming an interrupted send wait. Hook adapter9 PASS
(including mixed synchronous/posted chains); record4 PASS.

Six targeted controls each fail the intended test: remove post selection,
owner-pump dispatch, wakeup, sender-exit preservation, foreign-window
preservation, or nested-wait continuation. Last uses test-only copied Send
modules; others restored before release builds. All fixtures restored.
Final adjacent suites: redraw44/9, scroll56, raw-paint29, null-paint29, hook9,
record4, send64 PASS. Full IPC1537/syscall3270 PASS. Null/scroll stale fixture
arms and hidden-window setup repaired; no runtime painting change (KI0909).
Logs /tmp/B3630-hook-owner-{adjacent,boundaries,send,null-paint,ipc,syscalls,
control-post-route,control-pump,control-wake,control-sender,control-window,
control-wait}.log.

Runtime63cca0de7: both release builds/features/frame gates PASS. Static stack gates exit1 on
existing KI0019 failures; primary335x86/278ARM unchanged, no added/increased
path vs chain baseline; exception7664/6368 unchanged. Logs
/tmp/B3630-hook-owner-{build-x86_64,build-aarch64,feature,frame-x86,frame-arm,
stack-x86,stack-arm,stack-compare}.log.

No real DLL/guest callback executed by these fixtures. ARM client callback
continuation remains open. Public queue status omits the sent inbox and the
MsgWait park predicate ignores its mask (KI0910); this remains needed for full
notification acceptance. Window-hook client routing KI0908 and EnableWindow
sequence KI0904 remain open. No VM; Notepad desktop acceptance unproven.

x86: primary rows 335 -> 335; added={} growth=[]
target/B3630-hook-owner-x86_64.elf sha256=fb01c8a7e9c603a009e25012c75757f33c5913bf4594e5e1462e090896850ab0
arm: primary rows 278 -> 278; added={} growth=[]
target/B3630-hook-owner-aarch64.elf sha256=711bd456eb53755adbcf8e95a1769beb8771c0d0be184aac6ec39281ad669090
