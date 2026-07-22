"""qemu-mcp — interactive QEMU + GDB control surface for Claude Code.

BUILDS the kernel image into a per-build namespace (target/builds/<id>/
via xtask), spawns QEMU paused with the GDB stub on a per-instance FREE
port, attaches a GDB/MI session with the namespaced kernel ELF as the
symbol source, and exposes a tool surface for setting breakpoints,
stepping, reading registers / memory / disassembly, and serial. Multiple
instances of different builds run concurrently; tools take an optional
`instance_id` (default = sole/most-recent). See the FastMCP `instructions`
(_INSTRUCTIONS below) for the full model the AI client reads.

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
    qemu_stop()                — kill QEMU + GDB, GC its build namespace
    qemu_list()                — live instances (id, build_id, arch, ports)
    qemu_gc(keep_last=1)       — reclaim dead on-disk build namespaces
(every tool above also takes an optional `instance_id`.)

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
GDB_PROMPT = "(gdb)"

# Namespaced build artifact root (per xtask --id <slug>). C90: an id'd build
# puts EVERYTHING under one folder target/builds/<id>/ — kernel ELF snapshot,
# ISO, AND the root/home/nvme/ahci disk images (buildns::blobs_dir maps an
# id'd build to target/builds/<id>). No-id legacy blobs still live at
# kernel/blobs, but the MCP always uses a build_id so it never touches it.
_BUILDS_ROOT = REPO_ROOT / "target" / "builds"

_INSTRUCTIONS = """\
qemu-mcp — build, boot, and live-debug the oxide kernel under QEMU+GDB.

BUILD MODEL (C90 namespacing): `qemu_start` BUILDS the kernel image itself (via
`cargo run -p xtask -- grub --arch <arch> --id <build_id>`) and launches it — you
do not build separately. Every build is isolated in its own folder
`target/builds/<build_id>/` (ISO + kernel ELF + root/home/nvme/ahci disks all
together). `build_id` = `<name-or-git-branch>-<UTCstamp>`.

MULTIPLE INSTANCES: N instances of DIFFERENT builds can run at once — each gets
its own build namespace, free gdb/ssh ports, sockets, and pcap. `qemu_start`
returns an `instance_id`; EVERY other tool takes an optional `instance_id`
(default = the sole / most-recently-started instance, so single-instance use
needs no id). `qemu_list()` shows live instances.

BUILD CONTROL (qemu_start kwargs): `name` (label), `features`, `smp`, `accel`
("kvm" fast / "tcg" — some SMP timing bugs ONLY repro under tcg), and the rebuild
passthrough `rebuild_vendor` / `rebuild_rootfs` / `skip_rootfs` / `clean_kernel`
(forwarded to xtask). GDB attaches with the namespaced kernel ELF as the symbol
source, on a per-instance free port.

GC: a stopped build's namespace is reclaimed automatically (it's protected while
running via a `.live` PID marker that the CLI `xtask gc` honors). `qemu_gc()`
sweeps dead namespaces manually.

TYPICAL FLOW: qemu_start(arch) -> qemu_break(symbol) -> qemu_continue() ->
qemu_regs()/qemu_mem()/qemu_disasm()/qemu_backtrace() -> qemu_serial() ->
qemu_stop(). Dev-only tool (docs/02): not in any shipped artifact.
"""

mcp = FastMCP("qemu-mcp", instructions=_INSTRUCTIONS)


# ---------------------------------------------------------------------------
# Build identity / port allocation / slug rules
# ---------------------------------------------------------------------------

# xtask slug rule: build_id must be entirely [A-Za-z0-9._-].
import re as _re_mod

_SLUG_OK = _re_mod.compile(r"[^A-Za-z0-9._-]")


def _slugify(raw: str) -> str:
    """Reduce `raw` to xtask's slug alphabet [A-Za-z0-9._-]. '/' → '-'
    first (branch names like `feat/foo`), then strip any other unsafe
    char. Empty result falls back to 'build'."""
    s = raw.replace("/", "-")
    s = _SLUG_OK.sub("", s)
    return s or "build"


def _current_branch() -> str:
    """Current git branch (`git rev-parse --abbrev-ref HEAD`), or
    'detached' if unavailable."""
    try:
        p = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                           cwd=REPO_ROOT, capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    except Exception:
        pass
    return "detached"


def _make_build_id(name: str | None) -> str:
    """Derive a build_id `<slug>-<stamp>`. slug = name or current branch
    (slugified); stamp = UTC YYYYMMDDThhmmss. Result satisfies the xtask
    slug rule."""
    slug = _slugify(name if name else _current_branch())
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    return f"{slug}-{stamp}"


def _free_port() -> int:
    """Allocate a free TCP port by binding to ('', 0) and reading the
    OS-assigned port. Closes the socket so the port is free for the
    caller to bind — a small TOCTOU window, acceptable for dev tooling."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

@dataclass
class Session:
    instance_id: str
    build_id: str
    arch: str
    gdb_port: int
    ssh_port: int | None
    sock_dir: str
    qemu: subprocess.Popen
    gdb: subprocess.Popen
    serial: deque[str]
    serial_lock: threading.Lock
    gdb_lines: deque[str]
    gdb_lock: threading.Lock
    serial_reader: threading.Thread
    gdb_reader: threading.Thread
    started_at: float = 0.0
    serial_sock: socket.socket | None = None
    serial_sock_path: str | None = None
    qmp_sock: socket.socket | None = None
    qmp_sock_path: str | None = None
    qmp_lock: threading.Lock = None  # type: ignore[assignment]


# instance_id -> Session. instance_id = build_id, or build_id#2/#3… for
# additional concurrent instances of the same build.
_SESSIONS: dict[str, Session] = {}
_SESSION_LOCK = threading.Lock()

# Serializes namespace builds (they write fixed-ish paths within a
# namespace) and marks the build_id currently being built so GC never
# rmtree's a build mid-construction.
_BUILD_LOCK = threading.Lock()
_BUILDING: set[str] = set()
_BUILDING_LOCK = threading.Lock()


def _resolve(instance_id: str | None) -> Session:
    """Resolve `instance_id` to a Session. None → the sole instance, or
    the most-recently-started one when several are live (back-compat for
    single-instance callers)."""
    with _SESSION_LOCK:
        if not _SESSIONS:
            raise RuntimeError("no active session — call qemu_start first")
        if instance_id is None:
            # Most-recently-started.
            return max(_SESSIONS.values(), key=lambda s: s.started_at)
        s = _SESSIONS.get(instance_id)
        if s is None:
            raise RuntimeError(f"no session with instance_id={instance_id!r}; "
                               f"live: {sorted(_SESSIONS)}")
        return s


_RESERVED: set[str] = set()


def _alloc_instance_id(build_id: str) -> str:
    """Pick + reserve an instance_id: build_id, or build_id#N for the Nth
    concurrent instance of an already-running/reserved build. Caller holds
    _SESSION_LOCK. The id is added to _RESERVED so a concurrent start can't
    pick the same one before this start finishes registering its Session;
    the reservation is cleared when the Session is registered (or on error)."""
    taken = set(_SESSIONS) | _RESERVED
    cand = build_id
    n = 2
    while cand in taken:
        cand = f"{build_id}#{n}"
        n += 1
    _RESERVED.add(cand)
    return cand


# ---------------------------------------------------------------------------
# .live PID markers (xtask gc protection)
# ---------------------------------------------------------------------------

# `xtask gc` (tools/xtask/src/gc.rs) spares a build namespace from reclaim if
# target/builds/<id>/.live exists AND names a PID with /proc/<pid> alive. The
# MCP writes these markers so a CLI `xtask gc` never rmtree's a build that has
# a running qemu. One PID line per live instance; file deleted when empty.
_LIVE_LOCK = threading.Lock()


def _live_path(build_id: str) -> Path:
    return _BUILDS_ROOT / build_id / ".live"


def _live_add(build_id: str, pid: int) -> None:
    """Append `pid` as a line to target/builds/<id>/.live (create dir/file as
    needed). Best-effort: never raises (teardown/start must not die over it)."""
    try:
        with _LIVE_LOCK:
            p = _live_path(build_id)
            p.parent.mkdir(parents=True, exist_ok=True)
            existing: list[str] = []
            if p.exists():
                existing = [ln for ln in p.read_text().splitlines() if ln.strip()]
            if str(pid) not in existing:
                existing.append(str(pid))
            p.write_text("\n".join(existing) + "\n")
    except Exception:
        pass


def _live_remove(build_id: str, pid: int) -> None:
    """Remove `pid`'s line from target/builds/<id>/.live; delete the file if it
    becomes empty. Best-effort: tolerate a missing/locked file, never raise."""
    try:
        with _LIVE_LOCK:
            p = _live_path(build_id)
            if not p.exists():
                return
            kept = [ln for ln in p.read_text().splitlines()
                    if ln.strip() and ln.strip() != str(pid)]
            if kept:
                p.write_text("\n".join(kept) + "\n")
            else:
                try: p.unlink()
                except FileNotFoundError: pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Garbage collection of unreferenced build namespaces
# ---------------------------------------------------------------------------

def _live_build_ids() -> set[str]:
    """build_ids referenced by ≥1 live session."""
    with _SESSION_LOCK:
        return {s.build_id for s in _SESSIONS.values()}


def _is_building(build_id: str) -> bool:
    with _BUILDING_LOCK:
        return build_id in _BUILDING


def _on_disk_build_ids() -> list[str]:
    """All build_ids present under target/builds/ (directory names)."""
    if not _BUILDS_ROOT.is_dir():
        return []
    return [p.name for p in _BUILDS_ROOT.iterdir() if p.is_dir()]


def _rmtree_namespace(build_id: str) -> None:
    """Remove the namespace dir for a build_id. C90: an id'd build holds
    EVERYTHING (ELF, ISO, disk images) under target/builds/<id>, so that one
    dir is the whole namespace. HARD GUARD: only ever touches
    target/builds/<id> — never the default root target/builds/ itself. A
    blank/dotted id is rejected so no path can resolve to a parent."""
    if not build_id or build_id in (".", "..") or "/" in build_id or "\\" in build_id:
        return
    target = _BUILDS_ROOT / build_id
    # Defensive: resolved path MUST be a direct child of _BUILDS_ROOT.
    try:
        if target.resolve().parent != _BUILDS_ROOT.resolve():
            return
    except Exception:
        return
    if target.is_dir():
        shutil.rmtree(target, ignore_errors=True)


def _gc_sweep(keep_last: int = 1) -> list[str]:
    """Collect on-disk build namespaces with no live instance, keeping the
    most-recent `keep_last` unused ones. A build is spared if it is live or
    currently mid-build. Returns the list of collected build_ids.

    'most-recent' uses the directory mtime as the recency proxy (build_ids
    also carry a sortable timestamp, but mtime is the on-disk truth)."""
    live = _live_build_ids()
    candidates = []
    for bid in _on_disk_build_ids():
        if bid in live or _is_building(bid):
            continue
        try:
            mtime = (_BUILDS_ROOT / bid).stat().st_mtime
        except OSError:
            mtime = 0.0
        candidates.append((mtime, bid))
    # Keep the `keep_last` newest unused; collect the rest.
    candidates.sort(reverse=True)  # newest first
    to_collect = [bid for _, bid in candidates[keep_last:]]
    for bid in to_collect:
        _rmtree_namespace(bid)
    return to_collect


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

def _rebuild_flags(rebuild_vendor: str | None = None, rebuild_rootfs: bool = False,
                   skip_rootfs: bool = False, clean_kernel: bool = False) -> list[str]:
    """Translate the qemu_start rebuild knobs into xtask `grub` flags. Pure
    (no I/O) so it's unit-testable.

      rebuild_vendor None      → (nothing)
      rebuild_vendor ""        → --rebuild-vendor          (all deps)
      rebuild_vendor "a,b"     → --rebuild-vendor=a,b
      rebuild_rootfs True      → --rebuild-rootfs
      skip_rootfs    True      → --skip-rootfs
      clean_kernel   True      → --clean-kernel
    """
    flags: list[str] = []
    if rebuild_vendor is not None:
        flags.append("--rebuild-vendor" if rebuild_vendor == ""
                     else f"--rebuild-vendor={rebuild_vendor}")
    if rebuild_rootfs:
        flags.append("--rebuild-rootfs")
    if skip_rootfs:
        flags.append("--skip-rootfs")
    if clean_kernel:
        flags.append("--clean-kernel")
    return flags


def _build_image(arch: str, build_id: str, features: str = "debug-boot",
                 rebuild_flags: list[str] | None = None) -> Path:
    """Run `cargo run -p xtask -- grub --arch <arch> --id <build_id>` from
    the repo root, building kernel + rootfs + ISO into the `build_id`
    namespace (everything under target/builds/<id>/). Returns the path
    to the namespaced GRUB ISO.

    Serialized behind `_BUILD_LOCK` (builds write fixed-ish paths within a
    namespace) and marked active under `_BUILDING` so GC can't rmtree a
    build mid-construction.

    Default features = `debug-boot` (matches `make qemu-x86`/`-arm`):
    boot UART sink installs + operational-pulse log lines, but no
    per-syscall flood. Pass features="debug-all" for the full firehose
    when debugging kernel internals."""
    if arch not in ("x86_64", "aarch64"):
        raise ValueError(f"arch must be x86_64 or aarch64, got {arch!r}")
    # Limine is gone on both arches: `xtask grub --arch <arch> --id <id>
    # --features <f> --build-only` yields target/builds/<id>/oxide-<arch>-
    # grub.iso (x86 multiboot2; arm EFI-stub) plus the namespaced blobs,
    # without launching qemu, so the MCP can spawn its own gdb-paused one.
    cmd = ["cargo", "run", "--quiet", "-p", "xtask", "--",
           "grub", "--arch", arch, "--id", build_id,
           "--features", features, "--build-only",
           *(rebuild_flags or [])]
    with _BUILDING_LOCK:
        _BUILDING.add(build_id)
    try:
        with _BUILD_LOCK:
            proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    finally:
        with _BUILDING_LOCK:
            _BUILDING.discard(build_id)
    if proc.returncode != 0:
        raise RuntimeError(
            f"image build failed (exit {proc.returncode})\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    img = _BUILDS_ROOT / build_id / f"oxide-{arch}-grub.iso"
    if not img.is_file():
        raise RuntimeError(f"expected boot artifact at {img} but it isn't there")
    return img


def _kernel_elf(arch: str, build_id: str) -> Path:
    """The kernel ELF GDB needs for symbols. xtask writes it under the
    namespace: target/builds/<id>/<triple>/release/oxide-<arch>."""
    triple = f"{arch}-unknown-oxide-kernel"
    return _BUILDS_ROOT / build_id / triple / "release" / f"oxide-{arch}"


def _blob(arch: str, build_id: str, kind: str) -> Path:
    """Namespaced disk image. C90: id'd disk images live alongside the ISO +
    ELF under target/builds/<id>/<kind>-<arch>.img (kind ∈ root|home|nvme|ahci)."""
    return _BUILDS_ROOT / build_id / f"{kind}-{arch}.img"


# ---------------------------------------------------------------------------
# Tool surface
# ---------------------------------------------------------------------------

@mcp.tool()
def qemu_start(arch: str, name: str | None = None, features: str = "debug-boot",
               smp: int = 1, accel: str = "kvm", mem: str = "2G", cpu: str = "",
               paused: bool = True, ssh_fwd: bool = False,
               extra_args: list[str] | None = None,
               rebuild_vendor: str | None = None, rebuild_rootfs: bool = False,
               skip_rootfs: bool = False, clean_kernel: bool = False) -> str:
    """Build the kernel image for `arch` (x86_64 or aarch64) into a
    per-build namespace, spawn QEMU with the gdb-stub on a free port, and
    attach a GDB/MI session targeting the kernel ELF for symbols.

    Multiple instances of DIFFERENT builds can run concurrently — each
    gets its own build namespace, gdb/ssh ports, sockets, and pcap. The
    returned `instance_id` identifies this instance for every other tool.

    Flags (control the run precisely):
      arch       "x86_64" | "aarch64"
      name       optional build label; slugified into the build_id
                 `<slug>-<UTCstamp>`. Default = current git branch.
      features   kernel Cargo features (default "debug-boot"; "debug-all"
                 = full trace firehose; "debug-watchdog" already default-on
                 in the boot crates so the liveness diag is always present).
      smp        vCPU count (`-smp N`, default 1). Use 2 to exercise AP
                 bring-up + the SMP=2-timing-sensitive flaky paths.
      accel      "kvm" (default, fast, x86 only) or "tcg" (pure emulation).
                 IMPORTANT: some timing-dependent bugs reproduce ONLY under
                 tcg — e.g. the x86 SMP=2 flaky-login race surfaces with
                 `accel="tcg", smp=2` but never under kvm. aarch64 on an
                 x86 host is always tcg regardless of this flag.
      mem        guest RAM (`-m`, default "2G").
      cpu        override the -cpu model (default: kvm→"host",
                 x86 tcg→"Haswell-v4", arm→"cortex-a72").
      paused     start halted under the gdb stub (`-S`) so you can set
                 breakpoints before the first instruction (default True).
                 False = run immediately (still gdb-attachable).
      ssh_fwd    add host:<freeport>→guest:22 forward (default False).
      extra_args list of raw extra QEMU args appended verbatim, for full
                 control (e.g. ["-d","int,guest_errors","-D","/tmp/q.log"]).

    Rebuild passthrough (forwarded to the xtask `grub` build command):
      rebuild_vendor  None = no-op; "" = --rebuild-vendor (rebuild ALL vendor
                      deps); "systemd,bash" = --rebuild-vendor=systemd,bash.
      rebuild_rootfs  True → --rebuild-rootfs (rebuild the rootfs image).
      skip_rootfs     True → --skip-rootfs (reuse the existing rootfs).
      clean_kernel    True → --clean-kernel (force a clean kernel rebuild).

    Returns a status line incl. the effective config and the instance_id.
    """
    # Reclaim space from prior unreferenced builds before building a new one.
    try:
        _gc_sweep(keep_last=1)
    except Exception:
        pass

    if not shutil.which("gdb"):
        raise RuntimeError("`gdb` not on PATH — install gdb to use qemu-mcp")
    qemu_bin = f"qemu-system-{arch}"
    if not shutil.which(qemu_bin):
        raise RuntimeError(f"`{qemu_bin}` not on PATH — install QEMU")
    if smp < 1:
        raise RuntimeError(f"smp must be >= 1 (got {smp})")
    if accel not in ("kvm", "tcg"):
        raise RuntimeError(f"accel must be 'kvm' or 'tcg' (got {accel!r})")

    build_id = _make_build_id(name)
    extra_args = list(extra_args or [])
    smp_args = ["-smp", str(int(smp))]
    # aarch64 on a non-arm host can't use kvm; force tcg there.
    eff_accel = "tcg" if arch == "aarch64" else accel

    # Per-instance runtime resources (no collisions across instances).
    gdb_port = _free_port()
    ssh_port = _free_port() if ssh_fwd else None
    netdev = (f"user,id=net0,hostfwd=tcp::{ssh_port}-:22" if ssh_fwd
              else "user,id=net0")
    pause_args = ["-gdb", f"tcp::{gdb_port}", "-S"] if paused else ["-gdb", f"tcp::{gdb_port}"]

    # Build into the namespace (serialized under _BUILD_LOCK internally).
    rebuild_flags = _rebuild_flags(rebuild_vendor, rebuild_rootfs,
                                   skip_rootfs, clean_kernel)
    img = _build_image(arch, build_id, features, rebuild_flags)
    elf = _kernel_elf(arch, build_id)
    if not elf.is_file():
        raise RuntimeError(f"kernel ELF missing at {elf} — image build did not produce it")
    root_img = _blob(arch, build_id, "root")
    home_img = _blob(arch, build_id, "home")

    with _SESSION_LOCK:
        instance_id = _alloc_instance_id(build_id)

    try:
        # Serial bridge via unix socket: QEMU listens, we connect.
        # `-serial stdio` doesn't reliably deliver host stdin to guest
        # UART RX when stdin is a pipe — switching to a dedicated
        # bidirectional socket per `28§*` makes byte delivery in both
        # directions deterministic.
        sock_dir = tempfile.mkdtemp(prefix="oxide-qemu-")
        sock_path = os.path.join(sock_dir, "serial.sock")
        pcap_path = os.path.join(sock_dir, "slirp.pcap")

        if arch == "x86_64":
            # GRUB ISO boots under SeaBIOS (qemu default — NO `-bios OVMF`),
            # exactly as `make qemu-x86`/`xtask grub`. The hybrid GRUB ISO is
            # BIOS-bootable; forcing OVMF made GRUB fail to set a video mode
            # ("no suitable video mode found") and OVMF #PF'd before the kernel
            # ran, so qemu_screen never captured the virtio-gpu fbcon scanout.
            # `img` is the GRUB ISO (-cdrom + -boot d); the rootfs is a
            # separate modern virtio-blk-pci drive (lockstep with aarch64).
            x86_cpu = cpu or ("host" if eff_accel == "kvm" else "Haswell-v4")
            x86_accel = ["-enable-kvm"] if eff_accel == "kvm" else ["-accel", "tcg"]
            qemu_cmd = [
                qemu_bin,
                "-machine", "q35",
                "-cpu", x86_cpu,
                *x86_accel,
                "-m", mem,
                *smp_args,
                "-cdrom", str(img),
                "-boot", "d",
                # Disk-based rootfs (F405): root + home virtio-blk drives with
                # the serials kmain's root-mount looks up (oxide-root/oxide-home).
                # Was a single stale rootfs-x86_64.img/oxide-virt-blk-0 → the
                # kmain.rs:512 "root disk serial=oxide-root not found" panic.
                "-drive", f"if=none,id=root,format=raw,file={root_img}",
                "-device", "virtio-blk-pci,drive=root,bus=pcie.0,serial=oxide-root,disable-legacy=on",
                "-drive", f"if=none,id=home,format=raw,file={home_img}",
                "-device", "virtio-blk-pci,drive=home,bus=pcie.0,serial=oxide-home,disable-legacy=on",
                # Phase 8 prep: explicit modern virtio-net so the
                # kernel sees device 0x1041 (not the QEMU-default
                # transitional 0x1000) and can DHCP/ARP through
                # SLIRP. `-nic none` suppresses the default e1000.
                "-nic", "none",
                "-netdev", netdev,
                "-device", "virtio-net-pci,netdev=net0,bus=pcie.0,disable-legacy=on",
                # F59-09: dump every frame on/off net0 to a per-instance pcap
                # so we can see whether the guest's TX kicks reach SLIRP.
                "-object", f"filter-dump,id=f0,netdev=net0,file={pcap_path}",
                # `-vga none` disables QEMU's default stdvga
                # (bochs-display, vendor 1234:1111). Without it,
                # QMP screendump captures that empty stdvga frame
                # instead of virtio-gpu's scanout — and the GTK
                # window in the xtask path renders the wrong head.
                "-vga", "none",
                # virtio-gpu modern PCI for `45` graphical-terminal arc.
                "-device", "virtio-gpu-pci,bus=pcie.0,disable-legacy=on",
                # virtio-input keyboard + mouse for `46`.
                "-device", "virtio-keyboard-pci,bus=pcie.0,disable-legacy=on",
                "-device", "virtio-mouse-pci,bus=pcie.0,disable-legacy=on",
                "-chardev", f"socket,id=serial0,path={sock_path},server=on,wait=off",
                "-serial", "chardev:serial0",
                # QMP socket so qemu_screen() can issue `screendump`
                # to capture the framebuffer (VGA / virtio-gpu).
                "-qmp", f"unix:{sock_dir}/qmp.sock,server=on,wait=off",
                "-display", "none",
                "-no-reboot",
                "-no-shutdown",
                *pause_args,
                *extra_args,
            ]
        else:
            ovmf = REPO_ROOT / "vendor/firmware/ovmf-aarch64.fd"
            arm_cpu = cpu or "cortex-a72"
            qemu_cmd = [
                qemu_bin,
                "-machine", "virt,gic-version=3,its=on",
                "-cpu", arm_cpu,
                "-m", mem,
                *smp_args,
                "-bios", str(ovmf),
                # Limine-free: `img` is the GRUB EFI-stub ISO. OVMF→GRUB→
                # `linux` boots our arm64 Image. Disk-based rootfs (F405):
                # root + home virtio-blk with the serials kmain looks up
                # (was "embedded in kernel" — stale pre-F405).
                "-cdrom", str(img),
                "-boot", "d",
                "-drive", f"if=none,id=root,format=raw,file={root_img}",
                "-device", "virtio-blk-pci,drive=root,bus=pcie.0,serial=oxide-root,disable-legacy=on",
                "-drive", f"if=none,id=home,format=raw,file={home_img}",
                "-device", "virtio-blk-pci,drive=home,bus=pcie.0,serial=oxide-home,disable-legacy=on",
                # Phase 8 prep: explicit modern virtio-net (0x1041)
                # symmetric with x86; aarch64 virt has no
                # default-NIC so `-nic none` is unnecessary.
                "-netdev", netdev,
                "-device", "virtio-net-pci,netdev=net0,bus=pcie.0,disable-legacy=on",
                # F59-09: dump every frame on/off net0 to a per-instance pcap
                # so we can see whether the guest's TX kicks reach SLIRP.
                "-object", f"filter-dump,id=f0,netdev=net0,file={pcap_path}",
                # `-vga none` disables QEMU's default stdvga
                # (bochs-display, vendor 1234:1111). Without it,
                # QMP screendump captures that empty stdvga frame
                # instead of virtio-gpu's scanout — and the GTK
                # window in the xtask path renders the wrong head.
                "-vga", "none",
                # virtio-gpu modern PCI for `45` graphical-terminal arc.
                "-device", "virtio-gpu-pci,bus=pcie.0,disable-legacy=on",
                # virtio-input keyboard + mouse for `46`.
                "-device", "virtio-keyboard-pci,bus=pcie.0,disable-legacy=on",
                "-device", "virtio-mouse-pci,bus=pcie.0,disable-legacy=on",
                "-chardev", f"socket,id=serial0,path={sock_path},server=on,wait=off",
                "-serial", "chardev:serial0",
                "-qmp", f"unix:{sock_dir}/qmp.sock,server=on,wait=off",
                "-display", "none",
                "-no-reboot",
                "-semihosting-config", "enable=on,target=native",
                *pause_args,
                *extra_args,
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

        # Mark this build live for the CLI `xtask gc` (gc.rs spares a build
        # whose .live names a still-alive PID). Written the moment the qemu
        # pid is known; removed in qemu_stop before the GC sweep.
        _live_add(build_id, qemu_proc.pid)

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

        # QMP — wait for QEMU to bind, then connect + handshake.
        qmp_path = os.path.join(sock_dir, "qmp.sock")
        qmp_deadline = time.monotonic() + 5.0
        while time.monotonic() < qmp_deadline and not os.path.exists(qmp_path):
            time.sleep(0.05)
        qmp_sock = None
        if os.path.exists(qmp_path):
            try:
                qmp_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                qmp_sock.connect(qmp_path)
                # QMP greeting (capabilities) + qmp_capabilities handshake.
                qmp_sock.settimeout(2.0)
                _ = qmp_sock.recv(4096)  # eat greeting
                qmp_sock.sendall(b'{"execute":"qmp_capabilities"}\n')
                _ = qmp_sock.recv(4096)  # eat ack
                qmp_sock.settimeout(None)
            except Exception:
                qmp_sock = None

        gdb_proc = subprocess.Popen(
            ["gdb", "--quiet", "--interpreter=mi3", str(elf)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        serial: deque[str] = deque(maxlen=65536)
        gdb_lines: deque[str] = deque(maxlen=8192)
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
            instance_id=instance_id,
            build_id=build_id,
            arch=arch,
            gdb_port=gdb_port,
            ssh_port=ssh_port,
            sock_dir=sock_dir,
            qemu=qemu_proc,
            gdb=gdb_proc,
            serial=serial,
            serial_lock=serial_lock,
            gdb_lines=gdb_lines,
            gdb_lock=gdb_lock,
            serial_reader=serial_reader,
            gdb_reader=gdb_reader,
            started_at=time.monotonic(),
            serial_sock=serial_sock,
            serial_sock_path=sock_path,
            qmp_sock=qmp_sock,
            qmp_sock_path=qmp_path if qmp_sock else None,
            qmp_lock=threading.Lock(),
        )

        # Prime GDB: skip its banner, attach to QEMU's gdb-stub on our port.
        _gdb_wait_prompt(s, timeout=10.0)
        attach = _gdb_cmd(s, f"-target-select extended-remote localhost:{gdb_port}", timeout=10.0)

        with _SESSION_LOCK:
            _SESSIONS[instance_id] = s
            _RESERVED.discard(instance_id)

        ssh_note = f" ssh=tcp::{ssh_port}-:22" if ssh_port else ""
        state = "paused at entry" if paused else "running"
        return (
            f"qemu-mcp: started instance_id={instance_id} arch={arch} smp={smp} "
            f"accel={eff_accel} mem={mem} features={features}; QEMU {state}; "
            f"GDB attached to localhost:{gdb_port}.{ssh_note}\n"
            f"build_id={build_id}\nimage={img}\nelf={elf}\n"
            f"attach response:\n" + "\n".join(attach[-10:])
        )
    except Exception:
        # Release the reservation so a retry can reuse the id, and drop any
        # .live marker we wrote before the failure so gc can reclaim it.
        try:
            if "qemu_proc" in locals() and qemu_proc is not None:
                _live_remove(build_id, qemu_proc.pid)
        except Exception:
            pass
        with _SESSION_LOCK:
            _RESERVED.discard(instance_id)
        raise


@mcp.tool()
def qemu_break(target: str, instance_id: str | None = None) -> str:
    """Set a breakpoint at `target` (a symbol name like
    `kernel_main`, or a hex address like `0xffffffff80100abc`).
    Returns the breakpoint number + location.

    `instance_id` selects which running instance (default: the sole /
    most-recently-started one)."""
    s = _resolve(instance_id)
    out = _gdb_cmd(s, f"-break-insert {target}")
    return "\n".join(out)


@mcp.tool()
def qemu_watch(expr: str, kind: str = "write", instance_id: str | None = None) -> str:
    """Set a hardware data watchpoint on `expr` (an address expression,
    e.g. `*(unsigned long*)0xffffffff81c924c0` or a symbol), via GDB MI
    `-break-watch`. `kind` selects the trigger: "write" (default,
    `-break-watch`), "read" (`-break-watch -r`), or "access"
    (`-break-watch -a`, fires on either). Returns the watchpoint number.

    Unlike `qemu_break` (code breakpoints only), this traps on a MEMORY
    ACCESS regardless of which instruction touches it — the tool needed
    to catch a wild/stale-pointer write in the act, as opposed to naming
    only whoever later stumbles onto the already-corrupted result.
    Requires the target address to be resolvable/mapped at the time this
    is called (set it after the kernel has paged in, not while paused at
    the boot entry vector — an early insert can fail and there is no
    guaranteed way to recover the session; `qemu_stop` and restart if so).
    """
    s = _resolve(instance_id)
    flag = {"write": "", "read": "-r", "access": "-a"}.get(kind)
    if flag is None:
        return f"error: kind must be one of write|read|access, got {kind!r}"
    cmd = f"-break-watch {flag} {expr}".strip()
    out = _gdb_cmd(s, cmd)
    return "\n".join(out)


@mcp.tool()
def qemu_break_delete(number: int | None = None, instance_id: str | None = None) -> str:
    """Delete breakpoint/watchpoint `number` (as returned by `qemu_break`/
    `qemu_watch`), or ALL of them if `number` is omitted, via GDB MI
    `-break-delete`. Use this to recover a session wedged by a breakpoint
    that failed to insert (e.g. set before the target address was mapped)
    — `qemu_continue`/`qemu_run_until` refuse to proceed past a pending
    failed insert otherwise, and no other tool could clear one."""
    s = _resolve(instance_id)
    cmd = "-break-delete" if number is None else f"-break-delete {number}"
    out = _gdb_cmd(s, cmd)
    return "\n".join(out)


@mcp.tool()
def qemu_continue(instance_id: str | None = None) -> str:
    """Resume execution. Returns when the CPU stops (breakpoint, fault,
    or other stop event). Output includes the stop reason + frame."""
    s = _resolve(instance_id)
    # `-exec-continue` returns ^running immediately; the actual stop
    # event arrives later as `*stopped`. Wait for it explicitly.
    s.gdb.stdin.write("-exec-continue\n")
    s.gdb.stdin.flush()
    _gdb_wait_prompt(s, timeout=2.0)  # consume ^running
    # Wait for *stopped or process exit.
    return _wait_stopped(s, timeout=120.0)


@mcp.tool()
def qemu_run_until(pattern: str, timeout: float = 60.0,
                   poll_interval: float = 0.1,
                   instance_id: str | None = None) -> str:
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
    s = _resolve(instance_id)
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
def qemu_interrupt(timeout: float = 5.0, instance_id: str | None = None) -> str:
    """Interrupt a running guest. Sends `-exec-interrupt` to GDB so
    the next memory/register read can succeed. Returns the stop
    frame. No-op if already stopped."""
    s = _resolve(instance_id)
    s.gdb.stdin.write("-exec-interrupt\n")
    s.gdb.stdin.flush()
    return _wait_stopped(s, timeout=timeout)


@mcp.tool()
def qemu_stepi(count: int = 1, instance_id: str | None = None) -> str:
    """Single-step `count` instructions. Returns the new PC + the
    next instruction's disassembly."""
    s = _resolve(instance_id)
    if count < 1 or count > 1_000_000:
        raise ValueError("count must be in [1, 1_000_000]")
    out: list[str] = []
    for _ in range(count):
        out += _gdb_cmd(s, "-exec-step-instruction")
    return "\n".join(out)


@mcp.tool()
def qemu_step(count: int = 1, instance_id: str | None = None) -> str:
    """Source-level step `count` lines."""
    s = _resolve(instance_id)
    if count < 1 or count > 1_000_000:
        raise ValueError("count must be in [1, 1_000_000]")
    out: list[str] = []
    for _ in range(count):
        out += _gdb_cmd(s, "-exec-step")
    return "\n".join(out)


@mcp.tool()
def qemu_finish(instance_id: str | None = None) -> str:
    """Step out of the current frame (continue until the current
    function returns)."""
    s = _resolve(instance_id)
    out = _gdb_cmd(s, "-exec-finish")
    return "\n".join(out)


@mcp.tool()
def qemu_regs(instance_id: str | None = None) -> str:
    """All CPU registers in hex."""
    s = _resolve(instance_id)
    out = _gdb_cmd(s, "-data-list-register-values x")
    return "\n".join(out)


@mcp.tool()
def qemu_mem(addr: str, count: int = 64, instance_id: str | None = None) -> str:
    """Read `count` bytes starting at `addr`. `addr` may be a
    symbol name or hex literal."""
    s = _resolve(instance_id)
    if count < 1 or count > 4096:
        raise ValueError("count must be in [1, 4096]")
    out = _gdb_cmd(s, f"-data-read-memory-bytes {shlex.quote(addr)} {count}")
    return "\n".join(out)


@mcp.tool()
def qemu_disasm(addr: str, count: int = 8, instance_id: str | None = None) -> str:
    """Disassemble `count` instructions starting at `addr`."""
    s = _resolve(instance_id)
    if count < 1 or count > 4096:
        raise ValueError("count must be in [1, 4096]")
    # mode 2 = disassembly with source if available; -- 2 is the
    # MI form. End computed conservatively as start + 16*count
    # (max instruction size on x86 is 15 bytes; 16 is safe).
    end_expr = f"{addr}+{16 * count}"
    out = _gdb_cmd(s, f"-data-disassemble -s {addr} -e {end_expr} -- 2")
    return "\n".join(out)


@mcp.tool()
def qemu_backtrace(instance_id: str | None = None) -> str:
    """Call stack of the current frame."""
    s = _resolve(instance_id)
    out = _gdb_cmd(s, "-stack-list-frames")
    return "\n".join(out)


@mcp.tool()
def qemu_info(what: str = "registers", instance_id: str | None = None) -> str:
    """`info <what>` via the GDB CLI command bridge. Common values:
    `registers`, `breakpoints`, `frame`, `proc`, `mem`. Forwarded
    verbatim — caller decides what to query."""
    s = _resolve(instance_id)
    out = _gdb_cmd(s, f"-interpreter-exec console {shlex.quote('info ' + what)}")
    return "\n".join(out)


def _qmp_send(s: Session, cmd: dict, timeout: float = 5.0) -> dict:
    """Send a single QMP command, return the parsed JSON response.
    Drains async events that arrive ahead of the response."""
    import json as _json
    if s.qmp_sock is None:
        raise RuntimeError("QMP not connected (this session was started before QMP support landed)")
    with s.qmp_lock:
        s.qmp_sock.settimeout(timeout)
        try:
            s.qmp_sock.sendall((_json.dumps(cmd) + "\n").encode("utf-8"))
            buf = bytearray()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    chunk = s.qmp_sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf.extend(chunk)
                # QMP frames are newline-terminated JSON objects.
                # Walk forward through complete lines until we see a
                # 'return' or 'error' (skip 'event' lines).
                while b"\n" in buf:
                    idx = buf.index(b"\n")
                    line = bytes(buf[:idx])
                    del buf[: idx + 1]
                    if not line.strip():
                        continue
                    try:
                        obj = _json.loads(line)
                    except _json.JSONDecodeError:
                        continue
                    if "event" in obj:
                        continue
                    return obj
            raise TimeoutError(f"QMP did not respond within {timeout}s")
        finally:
            s.qmp_sock.settimeout(None)


@mcp.tool()
def qemu_screen(as_text: bool = True, width: int = 120, height: int = 40,
                instance_id: str | None = None) -> str:
    """Capture the QEMU framebuffer (VGA / virtio-gpu / ramfb scanout).

    Issues QMP `screendump` to write a PPM file under /tmp, then:
      - if `as_text=True` (default), down-samples to a `width`×`height`
        ASCII brightness grid and returns it inline. Useful for
        seeing 'is the boot banner painted', 'is there a cursor',
        'is the screen all-zero', without leaving the chat.
      - if `as_text=False`, returns the PPM file path so the caller
        can open it externally.

    Linux 'no display' bug pattern: if the brightness grid is all
    spaces, the kernel never set up a scanout; if it's a wall of
    one character, the framebuffer is all-one-color (likely the
    OVMF clear-screen background); otherwise look for recognizable
    text shapes (banner, cursor blink).
    """
    s = _resolve(instance_id)
    ppm_path = os.path.join(s.sock_dir, "screen.ppm")
    try: os.unlink(ppm_path)
    except FileNotFoundError: pass
    resp = _qmp_send(s, {"execute": "screendump", "arguments": {"filename": ppm_path}})
    if "error" in resp:
        return f"qemu-mcp: screendump failed: {resp['error']}"
    # Wait briefly for QEMU to finish writing (screendump is async).
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if os.path.exists(ppm_path) and os.path.getsize(ppm_path) > 16:
            break
        time.sleep(0.05)
    if not os.path.exists(ppm_path):
        return f"qemu-mcp: screendump file did not appear at {ppm_path}"
    if not as_text:
        return f"qemu-mcp: screen dumped to {ppm_path} ({os.path.getsize(ppm_path)} bytes)"
    # Render PPM (P6, binary, 24bpp) → ASCII grid.
    return _ppm_to_ascii(ppm_path, width, height)


def _ppm_to_ascii(path: str, w: int, h: int) -> str:
    """Read a P6 PPM, downsample to `w`x`h`, map brightness to chars."""
    with open(path, "rb") as f:
        # Magic.
        magic = f.readline().strip()
        if magic != b"P6":
            return f"qemu-mcp: unsupported PPM magic {magic!r}"
        # Skip comments + width/height/maxval.
        def _hdr_token() -> int:
            while True:
                tok = b""
                while True:
                    c = f.read(1)
                    if not c: raise ValueError("EOF in PPM header")
                    if c == b'#':
                        f.readline()
                        continue
                    if c.isspace():
                        if tok: return int(tok)
                        else: continue
                    tok += c
        src_w = _hdr_token(); src_h = _hdr_token(); _maxv = _hdr_token()
        # binary pixel data follows
        data = f.read()
    if len(data) < src_w * src_h * 3:
        return f"qemu-mcp: PPM truncated: have {len(data)} bytes, expected {src_w*src_h*3}"
    # Step sizes (integer downsample).
    sx = max(1, src_w // w)
    sy = max(1, src_h // h)
    out_w = (src_w + sx - 1) // sx
    out_h = (src_h + sy - 1) // sy
    # Brightness ramp (dark → light).
    ramp = b" .:-=+*#%@"
    rows: list[str] = []
    rows.append(f"qemu-mcp: framebuffer {src_w}x{src_h}, sampled to {out_w}x{out_h}")
    for ry in range(out_h):
        line = bytearray()
        for rx in range(out_w):
            sy0 = ry * sy
            sx0 = rx * sx
            # Sample a single pixel for speed.
            off = (sy0 * src_w + sx0) * 3
            if off + 3 > len(data): break
            r, g, b = data[off], data[off+1], data[off+2]
            lum = (30*r + 59*g + 11*b) // 100
            ch = ramp[min(lum * (len(ramp) - 1) // 255, len(ramp) - 1)]
            line.append(ch)
        rows.append(line.decode("ascii"))
    return "\n".join(rows)


@mcp.tool()
def qemu_serial(clear: bool = False, instance_id: str | None = None) -> str:
    """Accumulated serial output (kernel stdout). Returns everything
    captured since the session started, or since the last call with
    `clear=True`."""
    s = _resolve(instance_id)
    with s.serial_lock:
        out = "\n".join(s.serial)
        if clear:
            s.serial.clear()
    return out


@mcp.tool()
def qemu_send_serial(text: str, append_newline: bool = True,
                     instance_id: str | None = None) -> str:
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
    s = _resolve(instance_id)
    if append_newline and not text.endswith("\n"):
        text = text + "\n"
    if s.serial_sock is None:
        raise RuntimeError("serial socket missing — re-start the session")
    data = text.encode("utf-8")
    s.serial_sock.sendall(data)
    return f"sent {len(data)} byte(s)"


@mcp.tool()
def qemu_stop(instance_id: str | None = None, keep_last: int = 1) -> str:
    """Tear down a QEMU + GDB instance and GC its build namespace.

    `instance_id` selects which instance (default: the sole /
    most-recently-started one). After the instance is removed, if its
    build_id has no remaining live instances and is not among the
    most-recent `keep_last` unused build_ids, its target/builds/<id>/
    namespace is rmtree'd."""
    with _SESSION_LOCK:
        if not _SESSIONS:
            return "no active session"
        if instance_id is None:
            s = max(_SESSIONS.values(), key=lambda x: x.started_at)
        else:
            s = _SESSIONS.get(instance_id)
            if s is None:
                return f"no session with instance_id={instance_id!r}; live: {sorted(_SESSIONS)}"
        del _SESSIONS[s.instance_id]
        build_id = s.build_id

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
    for sock in (s.serial_sock, s.qmp_sock):
        if sock is not None:
            try: sock.shutdown(socket.SHUT_RDWR)
            except Exception: pass
            try: sock.close()
            except Exception: pass
    # Reap.
    for proc, _name in ((s.gdb, "gdb"), (s.qemu, "qemu")):
        try:
            proc.wait(timeout=2.0)
        except Exception:
            proc.kill()
    # Remove the per-instance socket/qmp/pcap/screen scratch dir.
    try:
        shutil.rmtree(s.sock_dir, ignore_errors=True)
    except Exception:
        pass

    # Drop this instance's .live PID line BEFORE the GC sweep so a
    # just-stopped build becomes reclaimable (by both our sweep and the CLI
    # `xtask gc`). Best-effort; never blocks teardown.
    _live_remove(build_id, s.qemu.pid)

    # GC: if this build_id is now unreferenced and not among keep_last
    # most-recent unused builds, drop its namespace.
    collected: list[str] = []
    if build_id not in _live_build_ids() and not _is_building(build_id):
        collected = _gc_sweep(keep_last=keep_last)
    note = f" gc-collected={collected}" if collected else ""
    return f"qemu-mcp: instance {s.instance_id} stopped (build {build_id}).{note}"


@mcp.tool()
def qemu_list() -> str:
    """List live instances: instance_id, build_id, arch, gdb/ssh ports."""
    with _SESSION_LOCK:
        if not _SESSIONS:
            return "no live instances"
        rows = ["instance_id\tbuild_id\tarch\tgdb\tssh"]
        for iid, s in sorted(_SESSIONS.items()):
            rows.append(f"{iid}\t{s.build_id}\t{s.arch}\t{s.gdb_port}\t{s.ssh_port or '-'}")
    return "\n".join(rows)


@mcp.tool()
def qemu_gc(keep_last: int = 1) -> str:
    """Sweep on-disk build namespaces (target/builds/*) with no live
    instance, keeping the most-recent `keep_last` unused
    ones. Builds that are live or mid-build are never touched. Returns
    the collected build_ids."""
    collected = _gc_sweep(keep_last=keep_last)
    if not collected:
        return "qemu-mcp: gc — nothing to collect"
    return "qemu-mcp: gc collected:\n" + "\n".join(collected)


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
