#!/usr/bin/env python3
"""Cold hibernation acceptance: one raw disk, two QEMU processes, one RAM nonce."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

REPO = Path(__file__).resolve().parent.parent
PROBE_SOURCE = REPO / "tools/hibernate-two-boot/probe.c"
ARM_SYSROOT = Path("/usr/aarch64-redhat-linux/sys-root/fc42")
PAGE_BYTES = 4096
HIBERNATE_SIG_OFFSET = PAGE_BYTES - 10
HIBERNATE_SIG = b"S1SUSPEND\0"
SWAP_SIG = b"SWAPSPACE2"
NONCE = re.compile(rb"HIBERNATE-NONCE:([0-9a-f]{64})")
PASS = re.compile(rb"HIBERNATE-RESUME-PASS")
FAIL = re.compile(rb"HIBERNATE-PROBE-FAIL:[^\r\n]+")
FRESH_FAIL = re.compile(rb"HIBERNATE-FRESH-BOOT-FAIL")
SHELL_OK = re.compile(rb"HIBSHELL-42")


class Failure(RuntimeError):
    pass


class Console:
    def __init__(self, path, process, log, timeout):
        self.process = process
        self.timeout = timeout
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(0.5)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self.socket.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if process.poll() is not None:
                    raise Failure(f"QEMU exited {process.returncode} before UART appeared")
                time.sleep(0.1)
        else:
            raise Failure(f"UART socket did not appear: {path}")
        self._initialize(process, log, timeout, mirror=True)

    def _initialize(self, process, log, timeout, mirror):
        self.socket.setblocking(False)
        self.process = process
        self.timeout = timeout
        self.buffer = b""
        self.all = b""
        self.log = open(log, "ab", buffering=0)
        self.mirror = mirror
        self.eof = False

    @classmethod
    def connected(cls, connected_socket, process, log, timeout, mirror=False):
        console = cls.__new__(cls)
        console.socket = connected_socket
        console._initialize(process, log, timeout, mirror)
        return console

    def close(self):
        self.socket.close()
        self.log.close()

    def _drain(self):
        while True:
            try:
                chunk = self.socket.recv(65536)
            except BlockingIOError:
                return
            if not chunk:
                self.eof = True
                return
            self.buffer += chunk
            self.all += chunk
            self.log.write(chunk)
            if self.mirror:
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()

    def pump(self, timeout=0.5):
        if self.eof:
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pass
            return
        readable, _, _ = select.select([self.socket], [], [], timeout)
        if readable:
            self._drain()

    def wait_any(self, patterns, timeout, label):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for pattern in patterns:
                match = pattern.search(self.buffer)
                if match:
                    self.buffer = self.buffer[match.end():]
                    return pattern, match
            if self.process.poll() is not None:
                for pattern in patterns:
                    match = pattern.search(self.buffer)
                    if match:
                        return pattern, match
                raise Failure(f"QEMU exited {self.process.returncode} before {label}")
            self.pump()
        raise Failure(f"timed out after {timeout}s waiting for {label}")

    def send(self, command):
        pending = memoryview(command.encode() + b"\r")
        deadline = time.monotonic() + min(self.timeout, 30)
        while pending:
            if self.process.poll() is not None:
                raise Failure(f"QEMU exited {self.process.returncode} while writing UART command")
            if self.eof:
                raise Failure("guest UART closed while writing a command")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Failure("timed out writing UART command while draining guest output")
            readable, writable, _ = select.select(
                [self.socket], [self.socket], [], min(0.5, remaining))
            if readable:
                self._drain()
                if self.eof and pending:
                    raise Failure("guest UART closed while writing a command")
            if writable:
                try:
                    pending = pending[self.socket.send(pending):]
                except BlockingIOError:
                    pass

    def wait_shell(self):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            self.send('echo HIBSHELL-$((6*7))')
            try:
                self.wait_any([SHELL_OK], 5, "serial root shell")
                return
            except Failure:
                if self.process.poll() is not None:
                    raise
        raise Failure("serial root shell never answered")

    def wait_exit(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None: return self.process.returncode
            self.pump()
            failed = FAIL.search(self.all)
            if failed: raise Failure(failed.group().decode(errors="replace"))
        raise Failure("guest did not power off before the deadline")


def run(command, env=None):
    print("+", " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=REPO, env=env, check=True)


def build_probe(arch, output):
    if arch == "x86_64":
        command = ["gcc"]
    else:
        if not ARM_SYSROOT.is_dir():
            raise Failure(f"missing AArch64 GNU sysroot {ARM_SYSROOT}")
        command = ["aarch64-linux-gnu-gcc", f"--sysroot={ARM_SYSROOT}"]
    run(command + ["-O2", "-Wall", "-Wextra", "-Werror", str(PROBE_SOURCE), "-o", str(output)])
    program_headers = subprocess.check_output(["readelf", "-l", output], text=True)
    expected = "/lib64/ld-linux-x86-64.so.2" if arch == "x86_64" else "/lib/ld-linux-aarch64.so.1"
    if expected not in program_headers:
        raise Failure(f"{arch} probe is not linked through the GNU glibc interpreter {expected}")


def debugfs(image, request, ignore=False):
    result = subprocess.run(["debugfs", "-w", "-R", request, image],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode and not ignore:
        raise Failure(f"debugfs failed: {request}")


def inject_fixture(root_image, probe, work):
    service = work / "oxide-hibernate-fresh-guard.service"
    service.write_text(
        "[Unit]\nDescription=Oxide hibernation fresh-boot guard\nAfter=local-fs.target\n"
        "[Service]\nType=oneshot\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\n"
        "ExecStart=/usr/local/bin/oxide-hibernate-probe --fresh-guard\n"
        "[Install]\nWantedBy=basic.target\n")
    debugfs(root_image, "rm /usr/local/bin/oxide-hibernate-probe", True)
    debugfs(root_image, f"write {probe} /usr/local/bin/oxide-hibernate-probe")
    debugfs(root_image, "sif /usr/local/bin/oxide-hibernate-probe mode 0100755")
    debugfs(root_image, "mkdir /etc/systemd/system", True)
    debugfs(root_image, "mkdir /etc/systemd/system/basic.target.wants", True)
    destination = "/etc/systemd/system/oxide-hibernate-fresh-guard.service"
    debugfs(root_image, f"rm {destination}", True)
    debugfs(root_image, f"write {service} {destination}")
    want = "/etc/systemd/system/basic.target.wants/oxide-hibernate-fresh-guard.service"
    debugfs(root_image, f"rm {want}", True)
    debugfs(root_image, f"symlink {want} ../oxide-hibernate-fresh-guard.service")


def artifact(build_id, arch, name):
    base = REPO / "target/builds" / build_id
    if name == "root": return base / f"root-{arch}.img"
    if name == "home": return base / f"home-{arch}.img"
    if name == "iso": return base / f"oxide-{arch}-grub.iso"
    return base / f"{arch}-unknown-oxide-kernel/release/oxide-{arch}"


def build_image(build_id, arch, features=None, reuse_root=False):
    env = os.environ.copy()
    env["OXIDE_SERIAL_SHELL"] = "1"
    env["OXIDE_CMDLINE_EXTRA"] = "resume=/dev/vdc resume_offset=0"
    if reuse_root: env["OXIDE_SKIP_ROOTFS"] = "1"
    command = ["cargo", "run", "--quiet", "-p", "xtask", "--", "grub",
               "--arch", arch, "--id", build_id, "--smp", "2", "--build-only"]
    if features: command += ["--features", features]
    run(command, env)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()


def parse_build_id(notes):
    match = re.search(rb"Build ID: ([0-9a-fA-F]+)", notes)
    if not match: raise Failure("kernel ELF has no GNU build identity")
    return bytes.fromhex(match.group(1).decode())


def linked_build_id(path):
    result = subprocess.run(["readelf", "-n", path], cwd=REPO,
                            check=True, capture_output=True)
    return parse_build_id(result.stdout)


def start_qemu(build_id, arch, disk, memory, smp, work, label, timeout):
    uart = work / f"{label}.sock"
    qmp = work / f"{label}.qmp"
    log = work / f"{label}.serial.log"
    qemu_log = work / f"{label}.qemu.serial.log"
    uart.unlink(missing_ok=True)
    qmp.unlink(missing_ok=True)
    env = os.environ.copy()
    env.update({
        "OXIDE_QEMU_HEADLESS": "1",
        "OXIDE_QEMU_UART_SOCK": str(uart),
        "OXIDE_QEMU_QMP_SOCK": str(qmp),
        "OXIDE_QEMU_HIBERNATE_DISK": str(disk),
        "OXIDE_QEMU_MEMORY": memory,
        # QEMU and the socket client must never concurrently append to one
        # inode. Keep the transport transcript and QEMU's independent evidence
        # in separate files.
        "OXIDE_SERIAL_LOG": str(qemu_log),
        "OXIDE_QEMU_PROFILE": "default",
    })
    command = ["cargo", "run", "--quiet", "-p", "xtask", "--", "grub",
               "--arch", arch, "--id", build_id, "--run-existing", "--smp", str(smp)]
    host_log = open(work / f"{label}.host.log", "wb")
    process = subprocess.Popen(command, cwd=REPO, env=env, stdout=host_log,
                               stderr=subprocess.STDOUT, start_new_session=True)
    try:
        console = Console(str(uart), process, log, timeout)
    except Exception:
        host_log.close()
        stop_qemu(process)
        raise
    return process, console, host_log


def stop_qemu(process):
    if process.poll() is not None: return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def prepare_disk(path, bytes_count):
    if path.exists():
        raise Failure(f"refusing to overwrite existing disk {path}")
    with open(path, "xb") as disk:
        disk.truncate(bytes_count)


def marker(path):
    with open(path, "rb") as disk:
        disk.seek(HIBERNATE_SIG_OFFSET)
        return disk.read(10)


def modify_header(path, case):
    with open(path, "r+b", buffering=0) as disk:
        if case == "header":
            disk.seek(0)
            first = disk.read(1)
            disk.seek(0)
            disk.write(bytes([first[0] ^ 0xff]))
        elif case == "fresh":
            disk.seek(HIBERNATE_SIG_OFFSET)
            disk.write(SWAP_SIG)
        else:
            return
        os.fsync(disk.fileno())


def boot_a(build_id, arch, disk, memory, work, timeout):
    process, console, host_log = start_qemu(build_id, arch, disk, memory, 2, work, "boot-a", timeout)
    try:
        console.wait_shell()
        console.send("/usr/local/bin/oxide-hibernate-probe /dev/vdc")
        found, match = console.wait_any([re.compile(rb"HIBERNATE-REQUEST"), FAIL], timeout, "hibernate request")
        if found is FAIL: raise Failure(match.group().decode(errors="replace"))
        if console.wait_exit(timeout) != 0:
            raise Failure(f"boot A QEMU exited {process.returncode}")
        if PASS.search(console.all) or re.search(rb"HIBERNATE-NONCE:", console.all):
            raise Failure("boot A exposed the RAM-only nonce before cold restore")
    finally:
        console.close()
        host_log.close()
        stop_qemu(process)
    if marker(disk) != HIBERNATE_SIG:
        raise Failure("boot A powered off without the durable hibernation marker")


def boot_b(build_id, arch, disk, memory, smp, work, timeout, expect_resume):
    process, console, host_log = start_qemu(build_id, arch, disk, memory, smp, work, "boot-b", timeout)
    try:
        found, match = console.wait_any([PASS, FRESH_FAIL, FAIL], timeout,
                                        "restored caller or persistent fresh-boot guard")
        if expect_resume:
            if found is not PASS:
                raise Failure(match.group().decode(errors="replace"))
            nonces = NONCE.findall(console.all)
            if len(nonces) != 1:
                raise Failure(f"restored caller exposed {len(nonces)} RAM-only nonces")
            if FRESH_FAIL.search(console.all):
                raise Failure("fresh-boot guard ran during a claimed restore")
        elif found is PASS:
            raise Failure("incompatible cold boot reached the saved destination")
        elif found is FAIL:
            raise Failure(match.group().decode(errors="replace"))
    finally:
        console.close()
        host_log.close()
        stop_qemu(process)


def clear_guard(root_image):
    debugfs(root_image, "rm /var/lib/oxide-hibernate-pending", True)


def run_case(args, arch, case, base_id, alternate_id, probe, arch_work):
    root = artifact(base_id, arch, "root")
    clear_guard(root)
    disk = arch_work / f"{case}.raw"
    prepare_disk(disk, 6 * 1024**3 if arch == "x86_64" else 4 * 1024**3)
    memory = "4G" if arch == "x86_64" else "2G"
    case_work = arch_work / case
    case_work.mkdir()
    boot_a(base_id, arch, disk, memory, case_work, args.timeout)
    modify_header(disk, case)
    resume_id, resume_memory, resume_smp = base_id, memory, 2
    if case == "ram": resume_memory = "3G"
    if case == "smp": resume_smp = 1
    if case == "build":
        resume_id = alternate_id
        shutil.copy2(artifact(base_id, arch, "root"), artifact(alternate_id, arch, "root"))
        shutil.copy2(artifact(base_id, arch, "home"), artifact(alternate_id, arch, "home"))
    boot_b(resume_id, arch, disk, resume_memory, resume_smp, case_work,
           args.timeout, expect_resume=(case == "positive"))
    print(f"hibernate-two-boot: PASS arch={arch} case={case} disk={disk}")


def self_test(work):
    if parse_build_id(b"Build ID: 001122aAbB\n") != bytes.fromhex("001122aabb"):
        raise Failure("GNU build identity parser changed byte value")
    try:
        parse_build_id(b"no note")
    except Failure:
        pass
    else:
        raise Failure("missing GNU build identity was accepted")
    interleaved = (b"HIBERNATE-NONCE:" + b"ab" * 32 +
                   b"\nsystemd: unrelated serial output\nHIBERNATE-RESUME-PASS\n")
    if len(NONCE.findall(interleaved)) != 1 or PASS.search(interleaved) is None:
        raise Failure("interleaved restored-caller evidence was not recognized")

    for arch in ["x86_64", "aarch64"]:
        probe = work / f"probe-{arch}"
        build_probe(arch, probe)
        image = work / f"header-{arch}.raw"
        with open(image, "xb") as disk: disk.truncate(3 * PAGE_BYTES)
        command = [str(probe), "--header-only", str(image)]
        if arch == "aarch64": command = ["qemu-aarch64-static", "-L", str(ARM_SYSROOT / "usr")] + command
        run(command)
        with open(image, "rb") as disk:
            page = disk.read(PAGE_BYTES)
        if page[1024:1028] != (1).to_bytes(4, "little"):
            raise Failure("probe wrote the wrong swap version layout")
        if page[-10:] != SWAP_SIG:
            raise Failure("probe wrote the wrong swap signature layout")

    class RunningProcess:
        returncode = None

        @staticmethod
        def poll():
            return None

    client, peer = socket.socketpair()
    console = Console.connected(client, RunningProcess(), work / "uart-transcript.log", 5)
    noise = b"guest-output-backpressure\n" * 131072
    command = b"echo HIBSHELL-$((6*7))\r"
    received = bytearray()
    peer_error = []

    def flood_and_receive():
        try:
            peer.settimeout(5)
            peer.sendall(noise)
            while len(received) < len(command):
                chunk = peer.recv(len(command) - len(received))
                if not chunk:
                    break
                received.extend(chunk)
        except Exception as error:
            peer_error.append(error)

    thread = threading.Thread(target=flood_and_receive)
    thread.start()
    try:
        console.send(command[:-1].decode())
        thread.join(5)
        if thread.is_alive() or peer_error or bytes(received) != command:
            raise Failure("UART transport did not drain output while sending a command")
        if len(console.all) != len(noise):
            raise Failure("UART transport lost guest output while relieving backpressure")
    finally:
        console.close()
        peer.close()
        thread.join(1)

    class EofBeforeExitProcess:
        def __init__(self):
            self.returncode = None
            self.exited = threading.Event()

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            if not self.exited.wait(timeout):
                raise subprocess.TimeoutExpired("qemu", timeout)
            return self.returncode

    client, peer = socket.socketpair()
    process = EofBeforeExitProcess()
    console = Console.connected(client, process, work / "uart-eof-transcript.log", 5)
    peer.close()
    thread = threading.Thread(target=lambda: (time.sleep(0.05),
        setattr(process, "returncode", 0), process.exited.set()))
    thread.start()
    try:
        if console.wait_exit(1) != 0:
            raise Failure("UART EOF before QEMU exit lost the process status")
    finally:
        console.close()
        thread.join(1)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=["x86_64", "aarch64", "both"], default="both")
    parser.add_argument("--case", choices=["positive", "fresh", "ram", "smp", "build", "header", "all"], default="positive")
    parser.add_argument("--id", default="hibernate-two-boot")
    parser.add_argument("--alternate-features", default="debug-ssh")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--timeout", type=int, default=900)
    return parser.parse_args()


def main():
    args = parse_args()
    stamp = f"{int(time.time())}-{os.getpid()}"
    work = REPO / "target/hibernate-two-boot" / stamp
    work.mkdir(parents=True)
    try:
        if args.self_test:
            self_test(work)
            print("hibernate-two-boot: fixture self-test PASS")
            return 0
        arches = ["x86_64", "aarch64"] if args.arch == "both" else [args.arch]
        cases = ["positive", "fresh", "ram", "smp", "build", "header"] if args.case == "all" else [args.case]
        for arch in arches:
            base_id = f"{args.id}-{arch}"
            alternate_id = f"{base_id}-alternate"
            if args.build:
                build_image(base_id, arch)
                if "build" in cases:
                    alt_dir = artifact(alternate_id, arch, "root").parent
                    alt_dir.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(artifact(base_id, arch, "root"), artifact(alternate_id, arch, "root"))
                    shutil.copy2(artifact(base_id, arch, "home"), artifact(alternate_id, arch, "home"))
                    build_image(alternate_id, arch, args.alternate_features, reuse_root=True)
            required = [artifact(base_id, arch, name) for name in ["root", "home", "iso", "elf"]]
            if "build" in cases:
                required += [artifact(alternate_id, arch, name) for name in ["root", "home", "iso", "elf"]]
            missing = [str(path) for path in required if not path.is_file()]
            if missing: raise Failure("missing artifacts (use --build): " + ", ".join(missing))
            if "build" in cases:
                base_elf = artifact(base_id, arch, "elf")
                alternate_elf = artifact(alternate_id, arch, "elf")
                if sha256(base_elf) == sha256(alternate_elf):
                    raise Failure("alternate kernel ELF is byte-identical to boot A")
                if linked_build_id(base_elf) == linked_build_id(alternate_elf):
                    raise Failure("alternate kernel has the same hibernation build identity as boot A")
            arch_work = work / arch
            arch_work.mkdir()
            probe = arch_work / "oxide-hibernate-probe"
            build_probe(arch, probe)
            inject_fixture(artifact(base_id, arch, "root"), probe, arch_work)
            for case in cases:
                run_case(args, arch, case, base_id, alternate_id, probe, arch_work)
        return 0
    except (Failure, subprocess.CalledProcessError) as error:
        print(f"hibernate-two-boot: FAIL: {error}; evidence={work}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
