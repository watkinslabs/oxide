# B3630 desktop startup capture

| Status | Branch | Item |
|---|---|---|
| IN-PROGRESS | B3630-paint-region-collapse | KI0865 |

After the privileged serial prompt and session-running marker, the real
desktop-frame wait sends one bounded capture if no desktop appears after30s.
Existing UART reader preserves output throughout the wait. Capture records
reader identity/full status including effective capabilities before process
status/maps and per-thread comm/syscall/wchan/stack. Each read records its
status and stderr, including missing/inaccessible files. It does not enter
the graphical session uid, attach a debugger, or restart the VM. The shell
command is bounded by timeout10s and records final status separately from
its completion marker. Missing completion is not successful capture.

Tests execute the actual shell command against a temporary proc fixture,
including a path with spaces and disappearing stack file. Actual launch
wiring and actual frame-wait polling are separately covered. Removing the
launch hook fails (/tmp/B3630-desktop-capture-red.log); removing polling
fails (/tmp/B3630-desktop-capture-poll-red.log). Corrected tests pass3;
complete Notepad Python suite51 tests pass (desktop-capture-pytest.log).

No new boot or GNOME root-cause claim. Privileged live stack capture remains
required on next final verification. Prior empty stack reads were uid1000;
local proc stack returns an empty body without SYS_ADMIN/ptrace admission.
Futex blocking-location repair makes next captured wchan meaningful but does
not itself repair the desktop stall.
