#!/usr/bin/env python3
"""Drive a kexec end to end and report whether a SECOND kernel came up.

A kexec is the one question in this tree a hosted test genuinely cannot
answer: the jump does not return, so nothing on this side of it can observe
whether the relocation delivered the image. The evidence has to come from the
new kernel's own console output.

This connects to the guest UART socket qemu is already publishing
(`OXIDE_QEMU_UART_SOCK`), drives the serial root shell, points `kexec` at the
Fedora kernel the image ships, and then watches for banner lines only a
DIFFERENT kernel can print. It fails closed: silence is a failure, and so is
the running kernel still talking.

Usage: kexec-smoke.py <uart-socket> [--timeout N] [--file-load] [--log PATH]
"""

import argparse, os, re, socket, sys, time

# What the second kernel says about itself. The version banner is the only
# line that cannot be forged by the kernel that started the kexec: it names a
# build this tree did not produce.
SECOND_KERNEL_PATTERNS = [
    re.compile(rb"Linux version \d+\.\d+"),
    re.compile(rb"Command line:.*BOOT_IMAGE|Kernel command line:"),
]
# The relocation announcing itself from the kernel doing the leaving.
HANDOFF = re.compile(rb"kexec: starting new kernel")
# The boot brings up a root shell on the serial line long before it reaches a
# login prompt: `systemd.debug_shell=<serial tty>` is on the command line every
# launch here builds. Driving that shell is not a shortcut around logging in —
# it is answering ~5 s in, whereas a full boot to `login:` on a contended box
# takes minutes and is not what this test is about.
DEBUG_SHELL = re.compile(rb"Started debug-shell\.service|Early root shell")


def marker(tag):
    """A tag the shell echoes back. Matched instead of a prompt, because a
    prompt is whatever PS1 happens to say and an empty PS1 matches nothing."""
    return re.compile(tag.encode() + rb"-OK")


class Console:
    def __init__(self, path, log=None):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        for _ in range(600):
            try:
                self.s.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.1)
        else:
            raise SystemExit(f"kexec-smoke: no UART socket at {path}")
        self.s.settimeout(0.5)
        self.buf = b""
        # What the LAST completed `wait` consumed, so a caller can read the
        # value it just asked the guest to print.
        self.seen = b""
        # How long a blocked write is given before it is called a dead guest.
        # Set from the run's own timeout: a fixed cap turns a slow start into
        # a reported failure of the guest.
        self.patience = 120
        self.log = open(log, "ab") if log else None

    def pump(self):
        try:
            chunk = self.s.recv(65536)
        except socket.timeout:
            return b""
        if not chunk:
            raise SystemExit("kexec-smoke: guest closed the console")
        self.buf += chunk
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        if self.log:
            self.log.write(chunk)
            self.log.flush()
        return chunk

    def wait(self, pattern, timeout, name):
        """Wait for `pattern` anywhere in output not yet consumed."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.pump()
            m = pattern.search(self.buf)
            if m:
                self.seen = self.buf[:m.end()]
                self.buf = self.buf[m.end():]
                return True
        raise SystemExit(f"kexec-smoke: timed out after {timeout}s waiting for {name}")

    def send(self, line):
        """Type a line at the guest.

        A write to the console socket can block: early in a boot nothing is
        draining the guest's receive side, and the half-second read timeout
        applies to writes too. That surfaced as a TimeoutError traceback out
        of the polling loop — a harness failure indistinguishable, in the
        output, from a guest that never came up. Retry across the whole
        run's patience instead."""
        data = line.encode() + b"\r"
        deadline = time.time() + self.patience
        while True:
            try:
                self.s.sendall(data)
                break
            except socket.timeout:
                self.pump()
                if time.time() > deadline:
                    raise SystemExit("kexec-smoke: the guest console never accepted input")
        time.sleep(0.3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sock")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--file-load", action="store_true",
                    help="drive kexec_file_load(2) (kexec -s) instead of kexec_load(2)")
    ap.add_argument("--crash", action="store_true",
                    help="stage a CRASH kernel (kexec -p) and reach it by panicking")
    ap.add_argument("--log")
    a = ap.parse_args()

    c = Console(a.sock, a.log)
    c.patience = a.timeout
    # Nothing may be typed until the guest is producing output. The socket
    # exists before the machine does, and bytes written into it pile up in the
    # emulator's buffer until the write blocks — which then reads as a guest
    # that never accepted input, about a guest that had not started yet.
    c.wait(re.compile(rb"^\[[0-9]", re.M), a.timeout, "the kernel to start printing")
    # Poll for the shell rather than waiting for the line that announces it.
    # The announcement is printed once, early; a run that attaches to a guest
    # already past that point would wait forever for a line that has already
    # gone by, and report "no shell" about a shell that is sitting there
    # answering. Asking is the only test that works in both cases.
    deadline = time.time() + a.timeout
    while True:
        # Split so the ECHO of this line does not itself contain the marker.
        # A tty echoes what is typed before the shell has read it, so matching
        # the marker in the echo reports a shell that is answering when the
        # line is still sitting in the line discipline unread.
        c.send('echo SHELL""-OK')
        try:
            c.wait(marker("SHELL"), 5, "the shell to answer")
            break
        except SystemExit:
            if time.time() > deadline:
                raise SystemExit("kexec-smoke: the serial root shell never answered")

    # Resolve the second kernel from the image rather than hardcoding a
    # version: the Fedora package moves, and a hardcoded path fails as
    # "kexec did not work" when in fact nothing was ever loaded.
    c.send("set -x; KV=$(ls /lib/modules | head -1); "
           "K=/lib/modules/$KV/vmlinuz; I=/boot/initramfs-$KV.img; "
           "ls -l $K $I; echo KEXEC-PATHS\"\"-OK")
    c.wait(marker("KEXEC-PATHS"), 60, "the second kernel's paths")

    if a.crash:
        # The reservation has to exist before anything can be staged into it,
        # and it is the boot line that decides — a guest launched without
        # `crashkernel=` fails `kexec -p -l` with a message about the region
        # that reads like a loader bug. Read it back from the machine rather
        # than trusting the launch, so a run that lost the parameter says so.
        c.send("cat /sys/kernel/kexec_crash_size; echo CRASH-SIZE\"\"-OK")
        c.wait(marker("CRASH-SIZE"), 30, "the reserved crash size")
        if re.search(rb"^0\s*$", c.seen, re.M):
            raise SystemExit("kexec-smoke: nothing is reserved — the guest booted "
                             "without crashkernel=")

    # `-p` IS the load verb for a crash image; it does not combine with `-l`.
    verb = "-p" if a.crash else ("-s -l" if a.file_load else "-l")
    # BOTH console names, because the serial hardware differs by architecture
    # and the new kernel names it by driver: a 16550 is `ttyS0`, a PL011 is
    # `ttyAMA0`. Naming only one relocates into a kernel that boots perfectly
    # and says nothing on the port being watched — which reads exactly like a
    # relocation that did not land, and is the false negative most likely to be
    # believed. Linux accepts several `console=` and prints on all of them.
    consoles = "console=ttyS0,115200 console=ttyAMA0,115200"
    c.send(f'kexec {verb} $K --initrd=$I --command-line="{consoles} '
           f'panic=10 rdinit=/bin/sh"; echo KEXEC-LOAD\"\"-RC=$?')
    c.wait(re.compile(rb"KEXEC-LOAD-RC=0\b"), 120,
           "kexec -l to succeed (a non-zero rc here is the syscall refusing)")

    if a.crash:
        print("\n=== crash image staged; panicking ===\n", flush=True)
        # The one way to reach a crash kernel: a real panic. `kexec -e` would
        # take the ORDINARY path and prove nothing about the crash slot.
        c.send("echo c > /proc/sysrq-trigger")
        c.wait(re.compile(rb"\[PANIC\]"), 60,
               "the panic the trigger asked for (no panic means the trigger "
               "did not reach the crash key)")
    else:
        print("\n=== kexec load accepted; executing ===\n", flush=True)
        c.send("kexec -e")

    # From here the running kernel is on its way out. Two things must happen,
    # in this order: it announces the transition, and then a kernel that is
    # not it says hello.
    c.wait(HANDOFF, 60, "the relocation to announce itself")
    c.wait(SECOND_KERNEL_PATTERNS[0], 120,
           "the SECOND kernel's version banner (silence here means the jump "
           "did not land)")
    print("\n=== SECOND KERNEL IS RUNNING ===\n", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
