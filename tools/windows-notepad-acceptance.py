#!/usr/bin/env python3
"""One-shot visible acceptance run for the real 64-bit Wine Notepad.

The ordinary boot smoke is headless and may retry. This runner deliberately
does neither: it retains UART/QMP/framebuffer evidence for A1-A5 in the
masterplan and fails if the guest never proves a clean runtime exit.
"""
import hashlib
import atexit
import os
import re
import select
import socket
import subprocess
import sys
import time
from pathlib import Path
from notepad_qmp import QmpTransactions, QmpError
from screenshot_evidence import screenshot_completed, record_screenshot

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT.parent / "images"
RUN = str(os.getpid())
BUILD_ID = os.environ.get("OXIDE_NOTEPAD_BUILD_ID", f"notepad-{RUN}")
OUT = Path(os.environ.get("OXIDE_NOTEPAD_ACCEPTANCE_DIR", ROOT / "target/windows-notepad-acceptance"))
OUT.mkdir(parents=True, exist_ok=True)
UART = OUT / f"uart-{RUN}.sock"
QMP = OUT / f"qmp-{RUN}.sock"
UART_LOG = OUT / f"uart-{RUN}.log"
QEMU_LOG = OUT / f"qemu-{RUN}.log"
SCREEN = OUT / f"screen-{RUN}"
TIMEOUT = int(os.environ.get("WINDOWS_NOTEPAD_ACCEPTANCE_TIMEOUT", "900"))
TOKEN = os.environ.get("OXIDE_NOTEPAD_TOKEN", f"oxide-{RUN}").lower()
DEFAULT_WINE_NTDLL = ROOT / "target/lanes/wine-10.20-build/dlls/ntdll/ntdll.so"
DEFAULT_WINE_WIN32U = ROOT / "target/lanes/wine-10.20-build/dlls/win32u/win32u.so"
MILESTONES = [
    "[WINDOWS-PE-START] entry=", "[WINDOWS-NT-UNIX] entry",
    "[WINDOWS-USER32] create-window",
    "[WINDOWS-USER32] get-message", "[WINDOWS-GDI] begin-paint",
    "[WINDOWS-GDI] present", "[WINDOWS-DESKTOP] frame-ack",
]
FAULT = re.compile(r"\[FAULT\]|\[BADSTACK\]|\[BUG\]|Kernel panic|segfault at|bus error")
# Keep stdout on the acceptance UART but inherit the actual graphical session
# environment (DISPLAY/XAUTHORITY), never a guessed display or cookie path.
# This private guest gate refuses ambiguous sessions instead of selecting one.
# The application must run AS the session user, not as root holding the user's
# environment: everything a desktop application touches -- XDG_RUNTIME_DIR, the
# X cookie, its own per-user state -- is owned by that user and is refused to
# anyone else. nsenter --env alone keeps root's credentials, so the uid/gid of
# the session leader are adopted with it.
DESKTOP_LAUNCH = (b'set -- $(pgrep -x gnome-shell); if [ "$#" -eq 1 ]; then '
                  b'uid=$(stat -c %u /proc/"$1"); gid=$(stat -c %g /proc/"$1"); '
                  b'nsenter --target "$1" --env --setuid "$uid" --setgid "$gid" '
                  b'/usr/local/bin/windows-notepad-smoke; '
                  b'else echo "[WINDOWS-NOTEPAD] runtime-exit status=11 desktop-session-ambiguous"; fi\n')
qemu = None


def cleanup():
    if qemu is not None and qemu.poll() is None:
        try:
            os.killpg(qemu.pid, 15)
            qemu.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(qemu.pid, 9)
            except OSError:
                pass
    for path in (UART, QMP):
        path.unlink(missing_ok=True)


atexit.register(cleanup)


def die(message):
    print(f"windows-notepad-acceptance: FAIL — {message}", file=sys.stderr)
    raise SystemExit(1)


def wait_socket(path, deadline, label):
    while time.monotonic() < deadline:
        if path.exists():
            try:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                conn.settimeout(max(0.001, min(10, deadline - time.monotonic())))
                conn.connect(str(path))
                return conn
            except OSError:
                conn.close()
        if qemu.poll() is not None:
            die(f"QEMU exited before {label} appeared")
        time.sleep(0.25)
    die(f"{label} did not appear before timeout")


def qmp(conn, command, arguments=None):
    try:
        return conn.execute(command, arguments)
    except (QmpError, OSError, ValueError) as error:
        die(str(error))


def screenshot(conn, label):
    path = Path(f"{SCREEN}-{label}.ppm")
    path.unlink(missing_ok=True)
    qmp(conn, "screendump", {"filename": str(path)})
    completed = screenshot_completed()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size > 16:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            record_screenshot(OUT / f"screenshots-{RUN}.jsonl",
                              RUN, label, path, digest, completed)
            print(f"windows-notepad-acceptance: {label}={path} sha256={digest[:16]}")
            return path, digest
        time.sleep(0.1)
    die(f"QMP did not produce {label} screenshot")


def desktop_ready_text(text):
    """Accept only a GNOME top-bar clock, never a boot-console timestamp."""
    return re.search(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{1,2}:\d{2}\b", text) is not None


def wait_for_rendered_desktop(conn, deadline):
    """Require two OCR-confirmed GNOME frames before launching the PE."""
    probe = Path(f"{SCREEN}-gnome-probe.ppm")
    ocr_probe = Path(f"{SCREEN}-gnome-probe-ocr.png")
    stable = 0
    while time.monotonic() < deadline:
        probe.unlink(missing_ok=True)
        ocr_probe.unlink(missing_ok=True)
        qmp(conn, "screendump", {"filename": str(probe)})
        completed = time.monotonic() + 10
        while time.monotonic() < completed and not probe.is_file():
            time.sleep(0.1)
        if probe.is_file() and probe.stat().st_size > 16:
            try:
                # GNOME's top-bar clock is only a few pixels high in the
                # 1024x768 QEMU framebuffer.  OCR the top bar at 3x scale;
                # native-resolution OCR intermittently rejects a valid,
                # rendered desktop before the PE can be launched.
                preprocess = subprocess.run([
                    "convert", str(probe), "-crop", "1024x110+0+0", "-resize", "300%",
                    "-contrast-stretch", "0x10", str(ocr_probe),
                ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=10)
                ocr_input = ocr_probe if preprocess.returncode == 0 and ocr_probe.is_file() else probe
                result = subprocess.run(["tesseract", str(ocr_input), "stdout", "--psm", "11"], check=False,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, timeout=20)
                stable = stable + 1 if desktop_ready_text(result.stdout) else 0
            except (OSError, subprocess.TimeoutExpired):
                stable = 0
            if stable >= 2:
                return
        time.sleep(0.5)
    die("GNOME session marker appeared without a rendered desktop frame")


def uart_pump(conn, buffer, log, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ready, _, _ = select.select([conn], [], [], min(0.25, deadline - time.monotonic()))
        if not ready:
            continue
        data = conn.recv(65536)
        if not data:
            return
        buffer.extend(data)
        log.write(data)
        log.flush()


def wait_marker(conn, buffer, log, marker, deadline):
    while time.monotonic() < deadline:
        text = buffer.decode("utf-8", "replace")
        if FAULT.search(text):
            die(f"guest fault before {marker}")
        if marker in text:
            return
        uart_pump(conn, buffer, log, min(1, deadline - time.monotonic()))
    die(f"missing guest marker {marker}")


def keys(conn, *names):
    qmp(conn, "send-key", {"keys": [{"type": "qcode", "data": name} for name in names]})


def type_token(conn):
    keys(conn, "ctrl", "a")
    for char in TOKEN:
        keys(conn, "minus" if char == "-" else char)


def launch_on_desktop(uart, buffer, log, qmp_sock, deadline):
    wait_marker(uart, buffer, log, "sh-5.2#", deadline)
    wait_marker(uart, buffer, log, "Entering running state", deadline)
    wait_for_rendered_desktop(qmp_sock, deadline)
    screenshot(qmp_sock, "gnome-before-notepad")
    uart.sendall(DESKTOP_LAUNCH)


def ocr(path):
    try:
        result = subprocess.run(["tesseract", str(path), "stdout"], check=False,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return re.sub(r"[^a-z0-9-]", "", result.stdout.lower())


def image_build_env(base=None):
    """Return the environment required by the x86 image staging boundary."""
    build_env = dict(os.environ if base is None else base,
                     OXIDE_WINDOWS_NOTEPAD_SMOKE="1", OXIDE_QUICKBOOT_PROFILE="gnome",
                     OXIDE_SERIAL_SHELL="1")
    # Rootfs staging deliberately rejects stock Wine because the native
    # bootstrap requires the source-owned TEB attachment ABI.  Keep direct
    # acceptance invocations equivalent to `make qemu-x86`; callers may still
    # override either path for a deliberately different adapter build.
    build_env.setdefault("OXIDE_WINE_NTDLL", str(DEFAULT_WINE_NTDLL))
    build_env.setdefault("OXIDE_WINE_WIN32U", str(DEFAULT_WINE_WIN32U))
    return build_env


def prepare_image():
    """Compose the current Oxide profile before staging the kernel image."""
    build_env = image_build_env()
    cached_root = ROOT / "target" / "builds" / BUILD_ID / "root-x86_64.img"
    if cached_root.is_file() and os.environ.get("OXIDE_REBUILD_ROOTFS", "0") != "1":
        build_env["OXIDE_SKIP_ROOTFS"] = "1"
    if os.environ.get("OXIDE_REBUILD_SOURCE_IMAGE", "0") == "1":
        with QEMU_LOG.open("wb") as log:
            result = subprocess.run(["make", "gnome-x86_64"], cwd=IMAGES, env=build_env,
                                    stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            die(f"Oxide source-image composition failed; see {QEMU_LOG}")
    else:
        print(f"windows-notepad-acceptance: reusing composed source image {IMAGES / 'output/gnome-x86_64-root.img'}")
    source = IMAGES / "output/gnome-x86_64-root.img"
    if not source.is_file():
        die(f"missing composed Oxide source image {source}")
    repo_meta = ROOT.parent / "packages/repo/x86_64/repodata/repomd.xml"
    if repo_meta.is_file() and source.stat().st_mtime < repo_meta.stat().st_mtime:
        die(f"composed source image {source} predates Oxide RPM metadata; rebuild with OXIDE_REBUILD_SOURCE_IMAGE=1")
    try:
        identity = subprocess.run(
            ["debugfs", "-R", "cat /usr/lib/os-release", str(source)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        die(f"cannot inspect composed source image identity: {error}")
    if not re.search(r"^ID=oxide$", identity, re.MULTILINE):
        die("composed source image does not declare ID=oxide")
    feature_args = []
    requested_features = os.environ.get("OXIDE_NOTEPAD_FEATURES", "").strip()
    if requested_features:
        feature_args = ["--features", requested_features]
    with QEMU_LOG.open("wb") as log:
        result = subprocess.run(["cargo", "run", "--quiet", "-p", "xtask", "--", "image",
                                 "--arch", "x86_64", "--id", BUILD_ID, *feature_args], cwd=ROOT, env=build_env,
                                stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        die(f"kernel image preparation failed; see {QEMU_LOG}")


def main():
    global qemu
    if not re.fullmatch(r"[a-z0-9-]{4,64}", TOKEN):
        die("OXIDE_NOTEPAD_TOKEN must contain lowercase letters, digits, and hyphens")
    print(f"windows-notepad-acceptance: output={OUT} token={TOKEN} attempts=1")
    prepare_image()
    env = dict(os.environ)
    env.pop("OXIDE_QEMU_HEADLESS", None)
    env.update({"OXIDE_WINDOWS_NOTEPAD_SMOKE": "1", "OXIDE_WINDOWS_NOTEPAD_ACCEPTANCE": "1",
                "OXIDE_SERIAL_SHELL": "1", "OXIDE_QEMU_UART_SOCK": str(UART),
                "OXIDE_QEMU_QMP_SOCK": str(QMP)})
    # A previous interrupted run can leave either pathname behind.  The xtask
    # launcher removes the UART endpoint, but QMP is owned by this runner's
    # command contract; remove both before asking QEMU to bind them.
    UART.unlink(missing_ok=True)
    QMP.unlink(missing_ok=True)
    UART_LOG.unlink(missing_ok=True)
    with QEMU_LOG.open("ab") as log:
        qemu_env = dict(env, OXIDE_QEMU_QMP_SOCK=str(QMP), OXIDE_QEMU_UART_SOCK=str(UART))
        feature_args = []
        requested_features = os.environ.get("OXIDE_NOTEPAD_FEATURES", "").strip()
        if requested_features:
            feature_args = ["--features", requested_features]
        qemu = subprocess.Popen(["cargo", "run", "--quiet", "-p", "xtask", "--", "grub",
                                 "--arch", "x86_64", "--smp", "1", "--id", BUILD_ID,
                                 *feature_args,
                                 "--run-existing"], cwd=ROOT, env=qemu_env,
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
    deadline = time.monotonic() + TIMEOUT
    uart = wait_socket(UART, deadline, "UART socket")
    qmp_sock = QmpTransactions(lambda: wait_socket(QMP, deadline, "QMP socket"))
    buffer = bytearray()
    with UART_LOG.open("ab", buffering=0) as log:
        launch_on_desktop(uart, buffer, log, qmp_sock, deadline)
        for marker in MILESTONES:
            wait_marker(uart, buffer, log, marker, deadline)
        _, before = screenshot(qmp_sock, "before-token")
        type_token(qmp_sock)
        time.sleep(2)
        after_path, after = screenshot(qmp_sock, "after-token")
        if before == after:
            die("framebuffer did not change after token injection")
        if TOKEN not in ocr(after_path):
            die(f"OCR did not find injected token; retained {after_path}")
        print("windows-notepad-acceptance: A1/A2/A3 PASS (PE, window, present, token)")
        # This fixture is an untitled scratch document. Delete our own token
        # through real input before testing close. Notepad's DoCloseFile prompts
        # to save a nonempty modified buffer; waiting for exit at that prompt
        # would test the wrong state and eventually time out.
        keys(qmp_sock, "ctrl", "a")
        keys(qmp_sock, "backspace")
        time.sleep(1)
        cleared_path, cleared = screenshot(qmp_sock, "cleared-token")
        if cleared == after or TOKEN in ocr(cleared_path):
            die("scratch token did not clear before close")
        keys(qmp_sock, "alt", "f4")
        wait_marker(uart, buffer, log, "[WINDOWS-NOTEPAD] runtime-exit status=", deadline)
        if "[WINDOWS-NOTEPAD] runtime-exit status=0" not in buffer.decode("utf-8", "replace"):
            die("Notepad runtime exited without status 0")
        print("windows-notepad-acceptance: A4/A5 PASS (close, exit, wrapper cleanup)")
        qmp(qmp_sock, "quit")
    uart.close()
    qemu.wait(timeout=20)
    print(f"windows-notepad-acceptance: PASS — evidence retained in {OUT}")


if __name__ == "__main__":
    main()
