"""Capture desktop startup evidence through the existing privileged serial shell."""
import shlex
import time

CAPTURE_AFTER_SECONDS = 30
CAPTURE_TIMEOUT_SECONDS = 10
SCRIPT = r'''
root=$1
printf '\n[NOTEPAD-DESKTOP-DIAGNOSTICS] begin\n'
id
printf 'READER-CREDENTIALS\n'
cat "$root/self/status" 2>&1
printf '\nREAD-STATUS=%s\n' "$?"
for process in "$root"/[0-9]*; do
    [ -f "$process/comm" ] || continue
    IFS= read -r name < "$process/comm"
    case "$name" in gnome-shell|gnome-session*|Xwayland|dbus-broker) ;; *) continue ;; esac
    printf '\nPROCESS=%s COMM=%s\n' "${process##*/}" "$name"
    for file in "$process/status" "$process/maps" "$process"/task/*/comm "$process"/task/*/syscall "$process"/task/*/wchan "$process"/task/*/stack; do
        printf '\nFILE=%s\n' "$file"
        cat "$file" 2>&1
        printf '\nREAD-STATUS=%s\n' "$?"
    done
 done
printf '\n[NOTEPAD-DESKTOP-DIAGNOSTICS] complete\n'
'''


def command(proc_root="/proc"):
    # Literal arguments are shell-quoted; the capture never enters the graphical
    # session's uid/environment or attaches to a target process.
    return (f"timeout {CAPTURE_TIMEOUT_SECONDS}s sh -c {shlex.quote(SCRIPT)} capture "
            f"{shlex.quote(str(proc_root))}; "
            "printf '\\n[NOTEPAD-DESKTOP-DIAGNOSTICS] exit=%s\\n' \"$?\"\n").encode()


class DesktopDiagnostics:
    def __init__(self, uart, clock=time.monotonic):
        self.uart = uart
        self.clock = clock
        self.started = clock()
        self.sent = False

    def poll(self):
        if not self.sent and self.clock() - self.started >= CAPTURE_AFTER_SECONDS:
            self.uart.sendall(command())
            self.sent = True
