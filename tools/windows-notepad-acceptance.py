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
import socket
import subprocess
import sys
import time
from pathlib import Path
from notepad_qmp import QmpTransactions, QmpError
import guest_powerdown
from uart_reader import UartReader
from notepad_fault_drain import drain as drain_fault
import notepad_cadence
from notepad_dialogs import DialogChecks
from notepad_desktop_diagnostics import DesktopDiagnostics
from screenshot_evidence import screenshot_completed, record_screenshot
from notepad_evidence import token_in_notepad_window, locate_notepad_window, image_size, crop_image, menu_bar_word
from gnome_overview import overview_showing, pill_stats, window_activated
from notepad_uart_audit import audit as uart_audit, render_table as uart_audit_table, \
    render_markdown as uart_audit_markdown, load_win32u_ordinals

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT.parent / "images"
RUN = str(os.getpid())
BUILD_ID = os.environ.get("OXIDE_NOTEPAD_BUILD_ID", f"notepad-{os.environ.get('OXIDE_WINE_PROFILE', 'release')}-{RUN}")
OUT = Path(os.environ.get("OXIDE_NOTEPAD_ACCEPTANCE_DIR", ROOT / "target/windows-notepad-acceptance"))
OUT.mkdir(parents=True, exist_ok=True)
UART = OUT / f"uart-{RUN}.sock"
QMP = OUT / f"qmp-{RUN}.sock"
UART_LOG = OUT / f"uart-{RUN}.log"
QEMU_LOG = OUT / f"qemu-{RUN}.log"
SCREEN = OUT / f"screen-{RUN}"
AUDIT_MD = OUT / f"audit-{RUN}.md"
CADENCE_MD = OUT / f"cadence-{RUN}.md"
TIMEOUT = int(os.environ.get("WINDOWS_NOTEPAD_ACCEPTANCE_TIMEOUT", "900"))
# Budget for the orderly guest shutdown before cleanup() kills QEMU.
SHUTDOWN_TIMEOUT = int(os.environ.get("WINDOWS_NOTEPAD_SHUTDOWN_TIMEOUT", "60"))
# Bound on the desktop framing the shown window before the activation click.
LOCATE_SECONDS = 15
# Bound on the guest painting the typed token into its edit control.
TOKEN_SECONDS = 30
TOKEN = os.environ.get("OXIDE_NOTEPAD_TOKEN", f"oxide-{RUN}").lower()
# The runtime module's own loader drives the launch, so the milestones are the
# ones a running window produces. The Unix-call entry is deliberately absent:
# this kernel is win32k itself, the guest loads no Unix half, and requiring a
# marker the design no longer emits failed every run that actually worked.
MILESTONES = [
    "[WINDOWS-PE-START] entry=",
    "[WINDOWS-USER32] create-window", "[WINDOWS-WINDOW-SHOW] hwnd=",
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
WIN32U_ORDINALS = {}
run_succeeded = False
KEEP_ON_FAILURE = os.environ.get("OXIDE_NOTEPAD_KEEP_ON_FAILURE", "1") == "1"


def cleanup():
    if qemu is not None and qemu.poll() is None:
        if KEEP_ON_FAILURE and not run_succeeded:
            print(f"windows-notepad-acceptance: retained failed VM launcher={qemu.pid} QMP={QMP} UART={UART}", file=sys.stderr)
            return
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


def wait_for_rendered_desktop(conn, deadline, diagnostics=None):
    """Require two OCR-confirmed GNOME frames before launching the PE."""
    probe = Path(f"{SCREEN}-gnome-probe.ppm")
    ocr_probe = Path(f"{SCREEN}-gnome-probe-ocr.png")
    stable = 0
    while time.monotonic() < deadline:
        if diagnostics is not None:
            diagnostics.poll()
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


def wait_marker(reader, marker, deadline, guest=None):
    """The console is drained by UartReader throughout the run, so this only
    inspects what has already arrived. A wait that also owned the reading left
    the console unread whenever no wait was outstanding.

    `guest` is the QEMU process when the caller has one: a marker cannot
    arrive from a guest that has exited, so waiting out the whole run deadline
    to report a missing marker hides which of the two happened.
    """
    while time.monotonic() < deadline:
        if guest is not None and guest.poll() is not None:
            die(f"QEMU exited (status {guest.returncode}) while waiting for {marker}")
        text = reader.text()
        if FAULT.search(text):
            # The oops is still being written when its first line matches.
            # die() kills QEMU, so let the reader collect the rest of the
            # report first (vector, rip, GPRs, stack-guard line).
            def pump_slice():
                before = len(reader.text())
                time.sleep(0.25)
                return len(reader.text()) - before
            drain_fault(pump_slice, time.monotonic)
            die(f"guest fault before {marker}")
        if marker in text:
            return
        time.sleep(0.05)
    die(f"missing guest marker {marker}")


def keys(conn, *names):
    """Deliver a complete chord before any following command's input."""
    keys_immediate(conn, *names)


def keys_immediate(conn, *names):
    """Press and release with no delay at all, in one QMP transaction.

    `input-send-event` delivers the events it is given straight away; nothing
    between them is QEMU's doing, so what the guest then costs per character
    is the guest's.
    """
    events = [{"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": name}}}
              for down in (True, False) for name in (names if down else reversed(names))]
    qmp(conn, "input-send-event", {"events": events})


# QEMU's input-send-event "abs" axis is normalized to [0, QMP_ABS_RANGE]
# across the full display surface, independent of the guest's actual
# framebuffer resolution -- the virtio-tablet-pci device the x86 profile
# attaches (tools/xtask/src/image_qemu/x86_64.rs) reports absolute
# pointer position on that same scale.
QMP_ABS_RANGE = 0x7fff


def click(conn, x, y, width, height):
    axis_x = int(x * QMP_ABS_RANGE / max(1, width - 1))
    axis_y = int(y * QMP_ABS_RANGE / max(1, height - 1))
    qmp(conn, "input-send-event", {"events": [
        {"type": "abs", "data": {"axis": "x", "value": axis_x}},
        {"type": "abs", "data": {"axis": "y", "value": axis_y}},
    ]})
    qmp(conn, "input-send-event", {"events": [{"type": "btn", "data": {"down": True, "button": "left"}}]})
    qmp(conn, "input-send-event", {"events": [{"type": "btn", "data": {"down": False, "button": "left"}}]})


def qcode(char):
    return "minus" if char == "-" else char


def type_text(conn, text, send=keys_immediate):
    for char in text:
        send(conn, qcode(char))


def type_token(conn):
    keys(conn, "ctrl", "a")
    type_text(conn, TOKEN)


def desktop_launch_command(readback=False):
    if not readback:
        return DESKTOP_LAUNCH
    return DESKTOP_LAUNCH.replace(b'/usr/local/bin/windows-notepad-smoke',
                                 b'env OXIDE_COMPOSITOR_READBACK=1 /usr/local/bin/windows-notepad-smoke')


def launch_on_desktop(uart, reader, qmp_sock, deadline, guest=None):
    wait_marker(reader, "sh-5.2#", deadline, guest)
    wait_marker(reader, "Entering running state", deadline, guest)
    wait_for_rendered_desktop(qmp_sock, deadline, DesktopDiagnostics(uart))
    leave_overview(qmp_sock, deadline, "launch")
    screenshot(qmp_sock, "gnome-before-notepad")
    uart.sendall(desktop_launch_command(os.environ.get("OXIDE_NOTEPAD_READBACK", "0") == "1"))


def ocr_raw(path):
    """Whitespace-preserving OCR text, for phrase matching (KI-0472)."""
    try:
        result = subprocess.run(["tesseract", str(path), "stdout"], check=False,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.lower()


def ocr(path):
    return re.sub(r"[^a-z0-9-]", "", ocr_raw(path))


def overview_on_screen(path):
    return overview_showing(ocr_raw(path), *pill_stats(path))


def screendump_probe(conn, path, deadline):
    """One-off screendump not journaled as A1-A5 evidence; used for retries."""
    path.unlink(missing_ok=True)
    qmp(conn, "screendump", {"filename": str(path)})
    wait_until = min(deadline, time.monotonic() + 10)
    while time.monotonic() < wait_until and not (path.is_file() and path.stat().st_size > 16):
        time.sleep(0.1)
    return path.is_file() and path.stat().st_size > 16


def leave_overview(conn, deadline, label):
    """Escape the Activities overview until it clears (KI-0472).

    The guest session starts with the overview open; Notepad launched
    there renders only as an overview thumbnail, and injected input
    lands in the overview's own search entry instead of the app.
    """
    probe = Path(f"{SCREEN}-{label}-overview-probe.ppm")
    attempts = 0
    while time.monotonic() < deadline and attempts < 10:
        if screendump_probe(conn, probe, deadline) and not overview_on_screen(probe):
            return
        keys(conn, "esc")
        time.sleep(0.5)
        attempts += 1
    die(f"GNOME overview still visible before {label}")


def ensure_notepad_active(conn, deadline):
    """Bring Notepad to front and click its client area before typing.

    Runs after the kernel's [WINDOWS-WINDOW-SHOW] marker and before any
    token injection (KI-0472): leaves the overview if the window manager
    reopened it, locates the window by its OCR'd title bar (same helper
    A3 uses), and clicks into its body via the QMP absolute-pointer path
    so the desktop's focused window is Notepad, not whatever was focused
    behind the overview.
    """
    # The kernel's present precedes the desktop's framing of the X window
    # by however long mutter takes to start its frames client the first time
    # an X11 client maps (measured: framed and white one second after the
    # present in one run, still black and unframed one second after it in
    # another). Poll the title for a bounded time instead of one probe.
    probe = Path(f"{SCREEN}-locate-probe.ppm")
    rect = None
    locate_deadline = min(deadline, time.monotonic() + LOCATE_SECONDS)
    while True:
        leave_overview(conn, deadline, "activation")
        if not screendump_probe(conn, probe, deadline):
            die("QMP did not produce a screenshot to locate the Notepad window")
        rect = locate_notepad_window(probe)
        if rect is not None or time.monotonic() >= locate_deadline:
            break
        time.sleep(1)
    if rect is None:
        die(f"no Notepad window title located within {LOCATE_SECONDS}s of the kernel's window-show; retained {probe}")
    width, height = image_size(probe)
    left, top, right, bottom = rect
    click(conn, (left + right) // 2, (top + bottom) // 2, width, height)
    time.sleep(0.5)
    activated_path, _ = screenshot(conn, "activated")
    if overview_on_screen(activated_path) or not window_activated(ocr_raw(activated_path), locate_notepad_window(activated_path)):
        die(f"Notepad window not active after click; retained {activated_path}")


def image_build_env(base=None):
    """Return the environment required by the x86 image staging boundary."""
    build_env = dict(os.environ if base is None else base,
                     OXIDE_WINDOWS_NOTEPAD_SMOKE="1", OXIDE_QUICKBOOT_PROFILE="gnome",
                     OXIDE_SERIAL_SHELL="1")
    # The Windows runtime reaches the guest through the oxide-wine package the
    # compose installs. There is no host adapter path to point staging at.
    profile = build_env.get("OXIDE_WINE_PROFILE", "release")
    if profile not in ("release", "debug"):
        raise ValueError("OXIDE_WINE_PROFILE must be release or debug")
    build_env["OXIDE_WINE_PROFILE"] = profile
    return build_env


def verify_image_wine_profile(image, profile):
    result = subprocess.run(["python3", str(ROOT / "tools/windows-rootfs-payload-check.py"),
                             "--image", str(image), "--expected-wine-version", (ROOT / "tools/wine-version").read_text().strip(),
                             "--expected-wine-profile", profile, "--profile-only"], cwd=ROOT)
    if result.returncode:
        die(f"Wine profile {profile} does not match {image}")


def prepare_image():
    """Compose the current Oxide profile before staging the kernel image."""
    global WIN32U_ORDINALS
    build_env = image_build_env()
    cached_root = ROOT / "target" / "builds" / BUILD_ID / "root-x86_64.img"
    if cached_root.is_file() and os.environ.get("OXIDE_REBUILD_ROOTFS", "0") != "1":
        verify_image_wine_profile(cached_root, build_env["OXIDE_WINE_PROFILE"])
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
    verify_image_wine_profile(source, build_env["OXIDE_WINE_PROFILE"])
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
    verify_image_wine_profile(cached_root, build_env["OXIDE_WINE_PROFILE"])
    WIN32U_ORDINALS = load_win32u_ordinals(cached_root)


def run_uart_audit():
    """Audit whatever UART_LOG holds (partial on an early die(), complete on
    a normal exit) for unclaimed/refused Windows calls, print the table, and
    retain audit-<run>.md next to the other evidence. Findings here are a
    harness failure on their own -- a clean A1-A5 run can still have logged
    one (KI: unclaimed win32u ordinals and refused loads/callbacks were only
    ever noticed by a human reading the log)."""
    text = UART_LOG.read_bytes().decode("utf-8", "replace") if UART_LOG.is_file() else ""
    result = uart_audit(text, WIN32U_ORDINALS)
    print(uart_audit_table(result))
    AUDIT_MD.write_text(uart_audit_markdown(RUN, result))
    return result



def report_cadence(reader):
    """Print and retain the per-character interval of every typing phase."""
    labels = ["token"]
    rows = notepad_cadence.summarise(reader.text(), labels)
    table = notepad_cadence.render(rows)
    print("windows-notepad-acceptance: typing cadence by phase")
    print(table)
    CADENCE_MD.write_text(table + "\n")


def pointer_to(conn, x, y, width, height):
    """Place the absolute pointer without pressing anything."""
    qmp(conn, "input-send-event", {"events": [
        {"type": "abs", "data": {"axis": "x", "value": int(x * QMP_ABS_RANGE / max(1, width - 1))}},
        {"type": "abs", "data": {"axis": "y", "value": int(y * QMP_ABS_RANGE / max(1, height - 1))}}]})


def button(conn, down):
    qmp(conn, "input-send-event", {"events": [{"type": "btn", "data": {"down": down, "button": "left"}}]})


# The menu of a dropdown that opened, cropped from the item that opened it.
MENU_CROP_WIDTH = 340
MENU_CROP_HEIGHT = 320
# Items of the File menu that must appear underneath it.
MENU_ITEMS = ("new", "open", "save", "exit")


def drive_menu(conn):
    """A6: click File on the menu bar and read the dropdown that opens.

    A menu that opens nothing looks exactly like a menu bar that was never
    clicked, so this is checked by what is on the screen under the item and
    not by any marker the guest prints.
    """
    path, _ = screenshot(conn, "before-menu")
    width, height = image_size(path)
    rect = locate_notepad_window(path)
    if rect is None:
        die("no Notepad window located before the menu press")
    item = menu_bar_word(path, rect, "File")
    if item is None:
        die(f"no File item on the menu bar of the window at {rect}; retained {path}")
    left, top, item_width, item_height = item
    centre = (left + item_width // 2, top + item_height // 2)
    box = (max(0, left - 30), max(0, top - 12), min(width, left + MENU_CROP_WIDTH), min(height, top + MENU_CROP_HEIGHT))
    pointer_to(conn, centre[0], centre[1], width, height)
    button(conn, True)
    button(conn, False)
    # Keep the release on its target until the resulting menu is observed.
    time.sleep(1.5)
    opened, _ = screenshot(conn, "menu-open")
    crop = Path(f"{SCREEN}-menu-open-crop.png")
    crop_image(opened, box, crop)
    text = " ".join(ocr_raw(crop).split())
    print(f"menu: item={item} crop={crop} text={text!r}")
    missing = [name for name in MENU_ITEMS if name not in text]
    if missing:
        die(f"the File menu did not open: {missing} absent from the crop under the item; retained {crop}")
    keys(conn, "esc")
    time.sleep(0.5)
    print("windows-notepad-acceptance: A6 PASS (menu opens under the item that was pressed)")


def run_desktop_checks(uart, reader, qmp_sock, deadline, guest=None):
    """Drive the desktop checks; the caller owns the reader and the log."""
    launch_on_desktop(uart, reader, qmp_sock, deadline, guest)
    for marker in MILESTONES:
        wait_marker(reader, marker, deadline, guest)
    # The kernel has reported the window shown; confirm it is also the
    # active window on screen (not just present in a thumbnail behind a
    # reopened overview) before any input is typed into it (KI-0472).
    ensure_notepad_active(qmp_sock, deadline)
    _, before = screenshot(qmp_sock, "before-token")
    type_token(qmp_sock)
    # The guest paints a typed character in its own time, so a fixed wait
    # cannot tell a slow paint from a control that never draws: poll until
    # the token is inside the located window, and report the last frame when
    # the deadline passes. A screenshot diff plus a whole-frame OCR is
    # satisfied by the token landing in GNOME's overview search box instead
    # of Notepad (KI-0435), so the crop of the located window is what counts.
    found, rect, after_path, after = False, None, None, before
    token_deadline = min(deadline, time.monotonic() + TOKEN_SECONDS)
    while True:
        if guest is not None and guest.poll() is not None:
            die(f"QEMU exited (status {guest.returncode}) while waiting for the token")
        time.sleep(1)
        after_path, after = screenshot(qmp_sock, "after-token")
        found, rect = token_in_notepad_window(after_path, TOKEN, crop_path=Path(f"{SCREEN}-after-token-notepad-crop.png"))
        if found or time.monotonic() >= token_deadline:
            break
    if before == after and not found:
        die("framebuffer did not change after token injection")
    if rect is None:
        die(f"no Notepad window title located on screen; retained {after_path}")
    if not found:
        die(f"token not painted inside the Notepad window {rect} within {TOKEN_SECONDS}s; retained {after_path}")
    print("windows-notepad-acceptance: A1/A2/A3 PASS (PE, window, present, token)")
    report_cadence(reader)
    DialogChecks(sys.modules[__name__], qmp_sock, deadline, guest).run()
    drive_menu(qmp_sock)
    keys(qmp_sock, "alt", "f4")
    wait_marker(reader, "[WINDOWS-NOTEPAD] runtime-exit status=", deadline, guest)
    if "[WINDOWS-NOTEPAD] runtime-exit status=0" not in reader.text():
        die("Notepad runtime exited without status 0")
    print("windows-notepad-acceptance: A4/A5 PASS (close, exit, wrapper cleanup)")
    # `quit` kills the VM where it stands, leaving the root image holding
    # whatever was in flight; the guest that ran this acceptance owns the same
    # image the next run boots. Raise the power button instead and let systemd
    # unmount, exactly as a real machine shuts down. main() bounds the wait.
    qmp(qmp_sock, guest_powerdown.POWERDOWN)


def main():
    global qemu, run_succeeded
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
    with UART_LOG.open("ab", buffering=0) as log:
        reader = UartReader(uart, log)
        try:
            run_desktop_checks(uart, reader, qmp_sock, deadline, qemu)
        finally:
            # The reader writes the log; it must stop before the file closes,
            # on the failure path as well as the success path.
            reader.stop()
    uart.close()
    # A shutdown that does not finish is a kill, and must never be reported as
    # a clean stop: cleanup() (atexit) does the killing, this says so out loud.
    try:
        qemu.wait(timeout=SHUTDOWN_TIMEOUT)
        print("windows-notepad-acceptance: shutdown=powered-off")
    except subprocess.TimeoutExpired:
        die(f"guest did not power off within {SHUTDOWN_TIMEOUT}s")
    result = run_uart_audit()
    if not result.passed:
        die(f"unclaimed or refused Windows call(s) in the UART log; see the table above and {AUDIT_MD}")
    run_succeeded = True
    print(f"windows-notepad-acceptance: PASS — evidence retained in {OUT}")


if __name__ == "__main__":
    try:
        main()
    finally:
        # A1-A5 already failed via die() before the UART audit ran above:
        # audit whatever was captured anyway so a failed run still gets its
        # table and audit-<run>.md, not just the milestone that broke.
        if UART_LOG.is_file() and not AUDIT_MD.is_file():
            run_uart_audit()
