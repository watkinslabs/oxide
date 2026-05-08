"""qemu-mcp — interactive QEMU + GDB control surface for Claude Code.

Spawns QEMU paused at start with the GDB stub on :1234, attaches a
GDB/MI session with the kernel ELF as the symbol source, and
exposes a small tool surface for setting breakpoints, stepping,
reading registers / memory / disassembly, and inspecting serial
output.

Tool surface (in invocation order for a typical debug session):

    qemu_start(arch)           — auto-build image, spawn paused QEMU + GDB
    qemu_break(target)         — set breakpoint at `symbol` or `0xADDR`
    qemu_continue()            — `-exec-continue`; returns when stopped
    qemu_stepi(count=1)        — single-instruction step
    qemu_step(count=1)         — source-level step
    qemu_finish()              — step out of current frame
    qemu_regs()                — all CPU registers
    qemu_mem(addr, count)      — `count` bytes at `addr` (hex)
    qemu_disasm(addr, n=8)     — disassemble n insns from addr
    qemu_backtrace()           — call stack
    qemu_info(what)            — `info <what>` (e.g. "registers", "breakpoints")
    qemu_serial(clear=False)   — accumulated serial bytes since last call
    qemu_stop()                — kill QEMU + GDB

Design notes:

* Pure stdlib + `mcp` package; no `pygdbmi` / `pwntools` dep, so it
  installs cleanly on a vanilla Claude Code box (`mcp` ships with
  the harness).
* Background reader threads drain QEMU's serial stdout and GDB's
  MI stdout into ring buffers. Tool calls block on the GDB reader
  with a 30 s timeout.
* QEMU is started in `-S` (paused) mode so the first action after
  attach is `qemu_break <some_symbol>; qemu_continue` rather than
  racing the boot path.

Per oxide2's `docs/02§*` lifecycle: this tool is dev-only — it
doesn't ship in any kernel artifact and isn't on the PR-time CI
gate's hot path.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GDB_PORT = 1234
GDB_PROMPT = "(gdb)"

mcp = FastMCP("qemu-mcp")


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

@dataclass
class Session:
    arch: str
    qemu: subprocess.Popen
    gdb: subprocess.Popen
    serial: deque[str]
    serial_lock: threading.Lock
    gdb_lines: deque[str]
    gdb_lock: threading.Lock
    serial_reader: threading.Thread
    gdb_reader: threading.Thread
    serial_sock: socket.socket | None = None
    serial_sock_path: str | None = None


_SESSION: Session | None = None
_SESSION_LOCK = threading.Lock()


def _require() -> Session:
    if _SESSION is None:
        raise RuntimeError("no active session — call qemu_start first")
    return _SESSION


# ---------------------------------------------------------------------------
# Reader threads
# ---------------------------------------------------------------------------

def _drain_to(stream, buf: deque[str], lock: threading.Lock) -> None:
    """Pump `stream` line-by-line into `buf`. Exits when stream EOFs."""
    try:
        for raw in iter(stream.readline, ""):
            line = raw.rstrip("\n")
            with lock:
                buf.append(line)
    except Exception:
        # Stream closed or process died; the reader thread just exits.
        pass


def _drain_socket_to(sock: socket.socket, buf: deque[str], lock: threading.Lock) -> None:
    """Pump bytes from `sock` line-by-line into `buf`. Exits on close."""
    pending = bytearray()
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            pending.extend(chunk)
            while b"\n" in pending:
                idx = pending.index(b"\n")
                line = bytes(pending[:idx]).decode("utf-8", errors="replace")
                del pending[: idx + 1]
                with lock:
                    buf.append(line)
        if pending:
            with lock:
                buf.append(bytes(pending).decode("utf-8", errors="replace"))
    except Exception:
        pass


def _gdb_wait_prompt(s: Session, timeout: float = 30.0) -> list[str]:
    """Block until GDB emits its `(gdb)` prompt; return all lines since
    the last command. Times out if GDB takes longer than `timeout`."""
    end = time.monotonic() + timeout
    out: list[str] = []
    while time.monotonic() < end:
        with s.gdb_lock:
            while s.gdb_lines:
                line = s.gdb_lines.popleft()
                if line.startswith(GDB_PROMPT):
                    return out
                out.append(line)
        time.sleep(0.02)
    raise TimeoutError(f"GDB did not return prompt within {timeout}s; partial output:\n" + "\n".join(out))


def _gdb_cmd(s: Session, cmd: str, timeout: float = 30.0) -> list[str]:
    """Send a GDB command, return all lines emitted before the next
    prompt. Includes both MI records and CLI output."""
    if s.gdb.poll() is not None:
        raise RuntimeError("GDB has exited")
    s.gdb.stdin.write(cmd + "\n")
    s.gdb.stdin.flush()
    return _gdb_wait_prompt(s, timeout=timeout)


# ---------------------------------------------------------------------------
# Build helper
# ---------------------------------------------------------------------------

def _build_image(arch: str) -> Path:
    """Run `cargo run -p xtask -- image --arch <arch>` from the repo
    root. Returns the path to the produced disk image."""
    if arch not in ("x86_64", "aarch64"):
        raise ValueError(f"arch must be x86_64 or aarch64, got {arch!r}")
    # Build the kernel + boot artifact + GPT disk image.
    cmd = [
        "cargo", "run", "--quiet", "-p", "xtask", "--",
        "image", "--arch", arch, "--features", "debug-all",
    ]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"image build failed (exit {proc.returncode})\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    img = REPO_ROOT / "target" / f"oxide-{arch}.img"
    if not img.is_file():
        raise RuntimeError(f"expected image at {img} but it isn't there")
    return img


def _kernel_elf(arch: str) -> Path:
    """The kernel ELF GDB needs for symbols. xtask kernel writes it
    under target/<triple>/<profile>/<bin>."""
    if arch == "x86_64":
        return REPO_ROOT / "target" / "x86_64-unknown-oxide-kernel" / "release" / "oxide-x86_64"
    return REPO_ROOT / "target" / "aarch64-unknown-oxide-kernel" / "release" / "oxide-aarch64"


# ---------------------------------------------------------------------------
# Tool surface
# ---------------------------------------------------------------------------

@mcp.tool()
def qemu_start(arch: str) -> str:
    """Build the kernel image for `arch` (x86_64 or aarch64), spawn
    QEMU paused at start with the gdb-stub on :1234, and attach a
    GDB/MI session targeting the kernel ELF for symbols.

    Re-uses the same QEMU args as `xtask qemu --arch <arch>`
    (q35 + Haswell-v4 + OVMF on x86; virt + cortex-a72 + OVMF on
    arm) plus `-s -S` for the gdb-stub-paused mode.

    Returns a short status line. Subsequent calls require
    `qemu_stop` first.
    """
    global _SESSION
    with _SESSION_LOCK:
        if _SESSION is not None:
            raise RuntimeError("session already active — call qemu_stop first")

        if not shutil.which("gdb"):
            raise RuntimeError("`gdb` not on PATH — install gdb to use qemu-mcp")
        qemu_bin = f"qemu-system-{arch}"
        if not shutil.which(qemu_bin):
            raise RuntimeError(f"`{qemu_bin}` not on PATH — install QEMU")

        img = _build_image(arch)
        elf = _kernel_elf(arch)
        if not elf.is_file():
            raise RuntimeError(f"kernel ELF missing at {elf} — image build did not produce it")

        # Serial bridge via unix socket: QEMU listens, we connect.
        # `-serial stdio` doesn't reliably deliver host stdin to guest
        # UART RX when stdin is a pipe — switching to a dedicated
        # bidirectional socket per `28§*` makes byte delivery in both
        # directions deterministic.
        sock_dir = tempfile.mkdtemp(prefix="oxide-qemu-")
        sock_path = os.path.join(sock_dir, "serial.sock")

        if arch == "x86_64":
            ovmf = REPO_ROOT / "vendor/firmware/ovmf-x64.fd"
            qemu_cmd = [
                qemu_bin,
                "-machine", "q35",
                "-cpu", "Haswell-v4",
                "-m", "256M",
                "-bios", str(ovmf),
                # Boot drive as virtio-blk-pci (modern transport) so the
                # F19-F30 stack runs lockstep with aarch64. The legacy
                # `-drive format=raw,file=...` default attached as IDE,
                # which left no virtio device on the bus.
                "-drive", f"if=none,id=hd0,format=raw,file={img}",
                "-device", "virtio-blk-pci,drive=hd0,bus=pcie.0,serial=oxide-virt-blk-0,disable-legacy=on",
                "-chardev", f"socket,id=serial0,path={sock_path},server=on,wait=off",
                "-serial", "chardev:serial0",
                "-display", "none",
                "-no-reboot",
                "-no-shutdown",
                "-s", "-S",
            ]
        else:
            ovmf = REPO_ROOT / "vendor/firmware/ovmf-aarch64.fd"
            qemu_cmd = [
                qemu_bin,
                "-machine", "virt,gic-version=3,its=on",
                "-cpu", "cortex-a72",
                "-m", "256M",
                "-bios", str(ovmf),
                "-drive", f"if=none,id=hd0,format=raw,file={img}",
                "-device", "virtio-blk-pci,drive=hd0,bus=pcie.0,serial=oxide-virt-blk-0,disable-legacy=on",
                "-chardev", f"socket,id=serial0,path={sock_path},server=on,wait=off",
                "-serial", "chardev:serial0",
                "-display", "none",
                "-no-reboot",
                "-semihosting-config", "enable=on,target=native",
                "-s", "-S",
            ]

        qemu_proc = subprocess.Popen(
            qemu_cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid,  # own process group; clean kill on stop
        )

        # Briefly wait for QEMU to bind the gdb-stub port + create the
        # serial socket before we ask GDB to connect / open the socket;
        # otherwise we hit ECONNREFUSED / ENOENT.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not os.path.exists(sock_path):
            if qemu_proc.poll() is not None:
                raise RuntimeError(f"QEMU exited immediately with code {qemu_proc.returncode}")
            time.sleep(0.05)
        if not os.path.exists(sock_path):
            raise RuntimeError(f"QEMU did not create serial socket at {sock_path}")

        serial_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        serial_sock.connect(sock_path)

        gdb_proc = subprocess.Popen(
            ["gdb", "--quiet", "--interpreter=mi3", str(elf)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        serial: deque[str] = deque(maxlen=4096)
        gdb_lines: deque[str] = deque(maxlen=4096)
        serial_lock = threading.Lock()
        gdb_lock = threading.Lock()
        # QEMU stdout still carries TCG/firmware warnings; capture it so
        # users see them in `qemu_serial`.
        warnings_reader = threading.Thread(
            target=_drain_to, args=(qemu_proc.stdout, serial, serial_lock), daemon=True,
        )
        warnings_reader.start()
        serial_reader = threading.Thread(
            target=_drain_socket_to, args=(serial_sock, serial, serial_lock), daemon=True,
        )
        gdb_reader = threading.Thread(
            target=_drain_to, args=(gdb_proc.stdout, gdb_lines, gdb_lock), daemon=True,
        )
        serial_reader.start()
        gdb_reader.start()

        s = Session(
            arch=arch,
            qemu=qemu_proc,
            gdb=gdb_proc,
            serial=serial,
            serial_lock=serial_lock,
            gdb_lines=gdb_lines,
            gdb_lock=gdb_lock,
            serial_reader=serial_reader,
            gdb_reader=gdb_reader,
            serial_sock=serial_sock,
            serial_sock_path=sock_path,
        )
        _SESSION = s

        # Prime GDB: skip its banner, attach to QEMU's gdb-stub.
        _gdb_wait_prompt(s, timeout=10.0)
        attach = _gdb_cmd(s, f"-target-select extended-remote localhost:{GDB_PORT}", timeout=10.0)

        return (
            f"qemu-mcp: started arch={arch}; QEMU paused at entry; "
            f"GDB attached to localhost:{GDB_PORT}.\n"
            f"image={img}\nelf={elf}\n"
            f"attach response:\n" + "\n".join(attach[-10:])
        )


@mcp.tool()
def qemu_break(target: str) -> str:
    """Set a breakpoint at `target` (a symbol name like
    `kernel_main`, or a hex address like `0xffffffff80100abc`).
    Returns the breakpoint number + location."""
    s = _require()
    out = _gdb_cmd(s, f"-break-insert {target}")
    return "\n".join(out)


@mcp.tool()
def qemu_continue() -> str:
    """Resume execution. Returns when the CPU stops (breakpoint, fault,
    or other stop event). Output includes the stop reason + frame."""
    s = _require()
    # `-exec-continue` returns ^running immediately; the actual stop
    # event arrives later as `*stopped`. Wait for it explicitly.
    s.gdb.stdin.write("-exec-continue\n")
    s.gdb.stdin.flush()
    _gdb_wait_prompt(s, timeout=2.0)  # consume ^running
    # Wait for *stopped or process exit.
    return _wait_stopped(s, timeout=120.0)


@mcp.tool()
def qemu_run_until(pattern: str, timeout: float = 60.0,
                   poll_interval: float = 0.1) -> str:
    """Resume execution and watch the serial buffer for a regex.

    Returns the moment the pattern matches (or `timeout` elapses)
    — does NOT wait for `*stopped`. Use this when you boot the
    guest and just want to confirm specific output appeared on
    the UART (test markers like "PASS", login prompts, etc.)
    rather than hitting a breakpoint.

    `pattern` is a Python regex applied to the accumulated serial
    text. On match returns the full serial buffer up to that
    point. On timeout returns the buffer with a ``[TIMEOUT]``
    prefix so the caller can see what was captured.

    The CPU keeps running on return — call again with a new
    pattern, or `qemu_interrupt` / `qemu_stop` when done.
    """
    s = _require()
    import re as _re
    rx = _re.compile(pattern)
    # -exec-continue returns ^running immediately; we don't wait
    # for *stopped, just poll the serial buffer.
    try:
        s.gdb.stdin.write("-exec-continue\n")
        s.gdb.stdin.flush()
        _gdb_wait_prompt(s, timeout=2.0)
    except Exception:
        # Already running is fine; serial poll still works.
        pass
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with s.serial_lock:
            buf = "\n".join(s.serial)
        if rx.search(buf):
            return buf
        time.sleep(poll_interval)
    with s.serial_lock:
        buf = "\n".join(s.serial)
    return f"[TIMEOUT after {timeout}s]\n{buf}"


@mcp.tool()
def qemu_interrupt(timeout: float = 5.0) -> str:
    """Interrupt a running guest. Sends `-exec-interrupt` to GDB so
    the next memory/register read can succeed. Returns the stop
    frame. No-op if already stopped."""
    s = _require()
    s.gdb.stdin.write("-exec-interrupt\n")
    s.gdb.stdin.flush()
    return _wait_stopped(s, timeout=timeout)


@mcp.tool()
def qemu_stepi(count: int = 1) -> str:
    """Single-step `count` instructions. Returns the new PC + the
    next instruction's disassembly."""
    s = _require()
    if count < 1 or count > 1_000_000:
        raise ValueError("count must be in [1, 1_000_000]")
    out: list[str] = []
    for _ in range(count):
        out += _gdb_cmd(s, "-exec-step-instruction")
    return "\n".join(out)


@mcp.tool()
def qemu_step(count: int = 1) -> str:
    """Source-level step `count` lines."""
    s = _require()
    if count < 1 or count > 1_000_000:
        raise ValueError("count must be in [1, 1_000_000]")
    out: list[str] = []
    for _ in range(count):
        out += _gdb_cmd(s, "-exec-step")
    return "\n".join(out)


@mcp.tool()
def qemu_finish() -> str:
    """Step out of the current frame (continue until the current
    function returns)."""
    s = _require()
    out = _gdb_cmd(s, "-exec-finish")
    return "\n".join(out)


@mcp.tool()
def qemu_regs() -> str:
    """All CPU registers in hex."""
    s = _require()
    out = _gdb_cmd(s, "-data-list-register-values x")
    return "\n".join(out)


@mcp.tool()
def qemu_mem(addr: str, count: int = 64) -> str:
    """Read `count` bytes starting at `addr`. `addr` may be a
    symbol name or hex literal."""
    s = _require()
    if count < 1 or count > 4096:
        raise ValueError("count must be in [1, 4096]")
    out = _gdb_cmd(s, f"-data-read-memory-bytes {shlex.quote(addr)} {count}")
    return "\n".join(out)


@mcp.tool()
def qemu_disasm(addr: str, count: int = 8) -> str:
    """Disassemble `count` instructions starting at `addr`."""
    s = _require()
    if count < 1 or count > 4096:
        raise ValueError("count must be in [1, 4096]")
    # mode 2 = disassembly with source if available; -- 2 is the
    # MI form. End computed conservatively as start + 16*count
    # (max instruction size on x86 is 15 bytes; 16 is safe).
    end_expr = f"{addr}+{16 * count}"
    out = _gdb_cmd(s, f"-data-disassemble -s {addr} -e {end_expr} -- 2")
    return "\n".join(out)


@mcp.tool()
def qemu_backtrace() -> str:
    """Call stack of the current frame."""
    s = _require()
    out = _gdb_cmd(s, "-stack-list-frames")
    return "\n".join(out)


@mcp.tool()
def qemu_info(what: str = "registers") -> str:
    """`info <what>` via the GDB CLI command bridge. Common values:
    `registers`, `breakpoints`, `frame`, `proc`, `mem`. Forwarded
    verbatim — caller decides what to query."""
    s = _require()
    out = _gdb_cmd(s, f"-interpreter-exec console {shlex.quote('info ' + what)}")
    return "\n".join(out)


@mcp.tool()
def qemu_serial(clear: bool = False) -> str:
    """Accumulated serial output (kernel stdout). Returns everything
    captured since the session started, or since the last call with
    `clear=True`."""
    s = _require()
    with s.serial_lock:
        out = "\n".join(s.serial)
        if clear:
            s.serial.clear()
    return out


@mcp.tool()
def qemu_send_serial(text: str, append_newline: bool = True) -> str:
    """Write `text` into the guest's serial port (UART RX) — i.e.
    type into the booted system as if at a terminal. Returns the
    number of bytes sent.

    `append_newline=True` (default) appends '\\n' so e.g. typing
    "root" into a `login:` prompt commits the line. Pass
    `append_newline=False` for control bytes ("\\x03" = Ctrl-C,
    "\\x04" = EOF, etc.) or partial-line probes.

    The session bridges QEMU's serial port over a unix socket
    (`-chardev socket`), so writes to that socket arrive at the
    guest's UART RX FIFO directly. The kernel's `tick_poll_uart`
    (or future RX IRQ) picks the bytes up on the next poll and
    wakes any task parked in `read(0)`.
    """
    s = _require()
    if append_newline and not text.endswith("\n"):
        text = text + "\n"
    if s.serial_sock is None:
        raise RuntimeError("serial socket missing — re-start the session")
    data = text.encode("utf-8")
    s.serial_sock.sendall(data)
    return f"sent {len(data)} byte(s)"


@mcp.tool()
def qemu_stop() -> str:
    """Tear down the QEMU + GDB session."""
    global _SESSION
    with _SESSION_LOCK:
        if _SESSION is None:
            return "no active session"
        s = _SESSION
        try:
            s.gdb.stdin.write("-gdb-exit\n")
            s.gdb.stdin.flush()
        except Exception:
            pass
        try:
            s.gdb.terminate()
        except Exception:
            pass
        try:
            os.killpg(os.getpgid(s.qemu.pid), signal.SIGTERM)
        except Exception:
            pass
        if s.serial_sock is not None:
            try:
                s.serial_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.serial_sock.close()
            except Exception:
                pass
        # Reap.
        for proc, name in ((s.gdb, "gdb"), (s.qemu, "qemu")):
            try:
                proc.wait(timeout=2.0)
            except Exception:
                proc.kill()
        if s.serial_sock_path is not None:
            try:
                os.unlink(s.serial_sock_path)
            except Exception:
                pass
            try:
                os.rmdir(os.path.dirname(s.serial_sock_path))
            except Exception:
                pass
        _SESSION = None
        return "qemu-mcp: session stopped"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wait_stopped(s: Session, timeout: float = 30.0) -> str:
    """Wait for a `*stopped` MI record (or process exit). Returns the
    accumulated lines until the next prompt after that record."""
    end = time.monotonic() + timeout
    collected: list[str] = []
    saw_stopped = False
    while time.monotonic() < end:
        with s.gdb_lock:
            while s.gdb_lines:
                line = s.gdb_lines.popleft()
                collected.append(line)
                if line.startswith("*stopped"):
                    saw_stopped = True
                if saw_stopped and line.startswith(GDB_PROMPT):
                    return "\n".join(collected)
        if s.gdb.poll() is not None:
            return "\n".join(collected) + f"\n[gdb exited code={s.gdb.returncode}]"
        time.sleep(0.05)
    raise TimeoutError(
        f"no *stopped within {timeout}s; partial output:\n" + "\n".join(collected[-30:])
    )


if __name__ == "__main__":
    mcp.run()
