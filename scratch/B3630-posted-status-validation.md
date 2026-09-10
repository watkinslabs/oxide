# Posted-class change-bit lifetime

| Status | Branch | Work |
|---|---|---|
| IMPLEMENTED | B3630-paint-region-collapse | KI0911 posted/quit admission and drain |
| OPEN | B3630-paint-region-collapse | KI0913 retrieval acknowledgement; KI0712 wait flags |

MessageQueue::post_quit marks QS_POSTMESSAGE and QS_ALLPOSTMESSAGE changed,
including replacement of a pending quit after a status query. Canonical
clear_drained_posted clears those changes only when neither posted entries
nor pending quit remain. read_entry, cleanup_window, quit_message removal
and take_quit_matching all call it. Other message classes remain unchanged.
No added queue state; wake bits still derive from canonical entries/quit.

Seven owner mutation tests: six fail on original source, all seven pass
after repair. Covers new/replaced quit, partial/last ordinary removal,
remaining input, pending quit, both quit retrieval paths, nonremoving or
excluded inspection, and window cleanup. These tests exercise queue mutation
before retrieval's separate changed-mask acknowledgement (KI0913).
Actual public queue-status fixture verifies arrival, query and repost through
WindowManager and the status adapter. Final35 boundary,70 send,3276 syscall
library PASS. Full IPC1544 library tests plus its existing integration targets
PASS. No guest DLL or desktop is executed by these fixtures.

Five controls each fail one executed targeted test: omit quit arrival bits,
ordinary removal drain, window cleanup drain, filtered quit removal drain,
or matching quit removal drain. Every mutation restored; final suites PASS.
Logs /tmp/B3630-posted-status-{red,ipc,boundary,control-arrival,
control-remove,control-cleanup,control-quit-peek,control-quit-take}.log.
Both release/feature and frame/static-stack validation running.

Message retrieval still omits selected changed-mask acknowledgement
(KI0913); flags KI0712, object acquisition/deadlines KI0912 and handle stride
KI0844 remain open. No full wait or Notepad acceptance claim; no VM launched.
