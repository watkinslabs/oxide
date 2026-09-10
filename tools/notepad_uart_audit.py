"""Structured audit of a Notepad-acceptance UART capture (INFRA row for this
lane; see scratch/known_issues.md).

The acceptance harness only checked the A1-A5 milestone markers; a run that
hit those milestones could still PASS while the guest logged an unadmitted
win32u ordinal, a refused DLL load, a failed delay-load resolution, a
rejected WndProc/user callback, a kernelbase delay-load failure line, a
`[BUG]` line, a segfault, or a PE fault -- each one only noticed later by a
human reading the log. This module turns a UART log into a list of
`Finding`s (kind, detail, first timestamp, occurrence count) plus a verdict,
so the harness can fail the run itself.

Marker shapes (kernel UART / console output):
  [WINDOWS-RAW-UNCLAIMED] ordinal=<hex>                         -- unadmitted win32u ordinal
  [WINDOWS-LDR-FAIL] step=<step> name=<dll>                     -- runtime DLL load refused
  [WINDOWS-DELAYLOAD-FAIL] dll=<dll> api=<name> status=<hex>    -- delay-load resolution failed
  [WINDOWS-WNDPROC-REJECT] reason=...                           -- WndProc create callback refused
  [WINDOWS-USER-CALLBACK-REJECT] reason=...                     -- user callback-table entry refused
  failed to delay load <dll>.<api>                              -- kernelbase console line
  [BUG] ...
  segfault at ...
  [WINDOWS-PE-FAULT] ...                                        -- NT-personality user fault record

win32u ordinal decoding follows the shape the syscall surface gate uses
(crates/kernel/syscalls/tests/windows_call_surface/win32u.rs): each export's
body is a fixed 8-byte service thunk `mov r10,rcx; mov eax,imm32`; the
32-bit immediate is the ordinal. This module re-derives that mapping from a
shipped win32u.dll PE export table using only the standard library.
"""
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

TIMESTAMP_RE = re.compile(r"\[(\d+\.\d+)\]")

WIN32U_IMAGE_PATH = "/usr/local/lib/oxide/windows/x86_64-windows/win32u.dll"

# (kind, human label, compiled pattern, detail template using named groups)
_FINDING_SPECS = [
    ("frame-readback-mismatch", "X-server pixels differ from retained frame",
     re.compile(r"\[WINDOWS-FRAME-READBACK-MISMATCH\](?P<rest>[^\r\n]*)")),
    ("text-measure-refused", "text measurement refused",
     re.compile(r"\[WINDOWS-TEXTMEASURE-DROP\](?P<rest>[^\r\n]*)")),
    ("text-output-refused", "text output refused",
     re.compile(r"\[WINDOWS-TEXTOUT-DROP\](?P<rest>[^\r\n]*)")),
    ("scroll-proc-unhandled", "scrollbar procedure message unhandled",
     re.compile(r"\[WINDOWS-SCROLL-PROC-UNHANDLED\](?P<rest>[^\r\n]*)")),
    ("scroll-paint-fail", "scrollbar drawing callback failed",
     re.compile(r"\[WINDOWS-SCROLL-PAINT-FAIL\](?P<rest>[^\r\n]*)")),
    ("window-create-fail", "window creation failed",
     re.compile(r"\[WINDOWS-WINDOW-CREATE-FAIL\](?P<rest>[^\r\n]*)")),
    ("bridge-refused", "compositor bridge operation refused",
     re.compile(r"\[WINDOWS-BRIDGE-REFUSED\](?P<rest>[^\r\n]*)")),
    ("raw-unclaimed", "unadmitted win32u ordinal",
     re.compile(r"\[WINDOWS-RAW-UNCLAIMED\] ordinal=(?P<ordinal>[0-9a-fA-F]+)")),
    ("ldr-fail", "runtime DLL load refused",
     re.compile(r"\[WINDOWS-LDR-FAIL\] step=(?P<step>\S+) name=(?P<name>\S+)")),
    ("delayload-fail", "delay-load resolution failed",
     re.compile(r"\[WINDOWS-DELAYLOAD-FAIL\] dll=(?P<dll>\S+) api=(?P<api>\S+) status=(?P<status>[0-9a-fA-F]+)")),
    ("wndproc-reject", "WndProc create callback refused",
     re.compile(r"\[WINDOWS-WNDPROC-REJECT\] reason=(?P<reason>\S+)")),
    ("user-callback-reject", "user callback-table entry refused",
     re.compile(r"\[WINDOWS-USER-CALLBACK-REJECT\] reason=(?P<reason>\S+)")),
    ("delayload-fail-console", "kernelbase delay-load failure",
     re.compile(r"failed to delay load (?P<dll>\S+?)\.(?P<api>\S+)")),
    ("bug", "kernel [BUG] line",
     re.compile(r"\[BUG\](?P<rest>[^\r\n]*)")),
    ("segfault", "guest segfault",
     re.compile(r"segfault at(?P<rest>[^\r\n]*)")),
    ("pe-fault", "NT-personality user fault",
     re.compile(r"\[WINDOWS-PE-FAULT\](?P<rest>[^\r\n]*)")),
]


@dataclass(frozen=True)
class Finding:
    kind: str
    label: str
    detail: str
    first_ts: str
    count: int


@dataclass(frozen=True)
class AuditResult:
    findings: list = field(default_factory=list)

    @property
    def passed(self):
        return len(self.findings) == 0


def _nearest_timestamp(text, positions, index):
    """Timestamp of the last `[<seconds>]` marker at or before `index`."""
    lo, hi = 0, len(positions)
    while lo < hi:
        mid = (lo + hi) // 2
        if positions[mid][0] <= index:
            lo = mid + 1
        else:
            hi = mid
    return positions[lo - 1][1] if lo > 0 else "?"


def _detail_for(kind, match, win32u_ordinals):
    if kind == "raw-unclaimed":
        ordinal = int(match.group("ordinal"), 16)
        name = (win32u_ordinals or {}).get(ordinal)
        return f"ordinal=0x{ordinal:04x} name={name}" if name else f"ordinal=0x{ordinal:04x}"
    if kind == "ldr-fail":
        return f"step={match.group('step')} name={match.group('name')}"
    if kind == "delayload-fail":
        return f"dll={match.group('dll')} api={match.group('api')} status=0x{match.group('status')}"
    if kind in ("wndproc-reject", "user-callback-reject"):
        return f"reason={match.group('reason')}"
    if kind == "delayload-fail-console":
        return f"{match.group('dll')}.{match.group('api')}"
    if kind in ("bug", "segfault", "pe-fault", "window-create-fail", "bridge-refused", "text-measure-refused", "text-output-refused", "frame-readback-mismatch"):
        return match.group("rest").strip()[:200]
    return match.group(0)[:200]


def parse_uart_log(text, win32u_ordinals=None):
    """Scan `text` for every documented failure/reject marker.

    Returns a list of `Finding`, one per distinct (kind, detail) pair, each
    carrying the first timestamp it appeared at and how many times it
    recurred. Findings are ordered by first appearance.
    """
    timestamp_positions = [(m.start(), m.group(1)) for m in TIMESTAMP_RE.finditer(text)]
    grouped = {}  # (kind, detail) -> [first_index, first_ts, count]
    order = []
    for kind, label, pattern in _FINDING_SPECS:
        for match in pattern.finditer(text):
            detail = _detail_for(kind, match, win32u_ordinals)
            key = (kind, detail)
            ts = _nearest_timestamp(text, timestamp_positions, match.start())
            if key not in grouped:
                grouped[key] = [match.start(), ts, 1, label]
                order.append(key)
            else:
                grouped[key][2] += 1
    order.sort(key=lambda key: grouped[key][0])
    return [Finding(kind=key[0], label=grouped[key][3], detail=key[1],
                    first_ts=grouped[key][1], count=grouped[key][2]) for key in order]


def audit(text, win32u_ordinals=None):
    """Parse `text` and return an `AuditResult`."""
    return AuditResult(findings=parse_uart_log(text, win32u_ordinals))


def render_table(result):
    """Human-readable table for stdout; a clean run gets one PASS line."""
    if result.passed:
        return "notepad-uart-audit: PASS — no unclaimed/refused Windows calls in the UART log"
    lines = ["notepad-uart-audit: FAIL — unclaimed/refused Windows calls found",
             f"{'kind':<24}{'first_ts':<12}{'count':<8}detail"]
    for finding in result.findings:
        lines.append(f"{finding.kind:<24}{finding.first_ts:<12}{finding.count:<8}{finding.detail}")
    return "\n".join(lines)


def render_markdown(run_id, result):
    """`audit-<run>.md` body: same findings, kept as evidence next to the run."""
    lines = [f"# UART audit — run {run_id}", "",
             f"Verdict: {'PASS' if result.passed else 'FAIL'}", ""]
    if result.passed:
        lines.append("No unclaimed or refused Windows calls found.")
    else:
        lines.append("| kind | label | first_ts | count | detail |")
        lines.append("|---|---|---|---|---|")
        for finding in result.findings:
            detail = finding.detail.replace("|", "\\|")
            lines.append(f"| {finding.kind} | {finding.label} | {finding.first_ts} | {finding.count} | {detail} |")
    lines.append("")
    return "\n".join(lines)


# --- win32u ordinal decoding (PE export table, stdlib only) ----------------

_STUB_MOV_R10_RCX = bytes((0x4c, 0x8b, 0xd1))
_STUB_MOV_EAX_IMM32 = 0xb8


def _rva_to_offset(sections, rva):
    for vaddr, vsize, rawptr, rawsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawptr + (rva - vaddr)
    return None


def parse_win32u_exports(data):
    """ordinal(int) -> export name, decoded from a win32u.dll image's export
    table. Only exports whose body is the fixed 8-byte service thunk
    (mov r10,rcx; mov eax,imm32) are admitted -- same shape the syscall
    surface gate decodes (win32u.rs `stub_ordinal`)."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {}
    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return {}
    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
    opt_hdr_size = struct.unpack_from("<H", data, coff_off + 16)[0]
    opt_off = coff_off + 20
    magic = struct.unpack_from("<H", data, opt_off)[0]
    is_pe32plus = magic == 0x20b
    dd_off = opt_off + (112 if is_pe32plus else 96)
    export_rva, _export_size = struct.unpack_from("<II", data, dd_off)
    if export_rva == 0:
        return {}
    sections = []
    sec_off = opt_off + opt_hdr_size
    for _ in range(num_sections):
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, sec_off + 8)
        sections.append((vaddr, vsize, rawptr, rawsize))
        sec_off += 40
    exp_off = _rva_to_offset(sections, export_rva)
    if exp_off is None:
        return {}
    (_characteristics, _ts, _maj, _min, _name_rva, _base, _num_funcs, num_names,
     addr_funcs_rva, addr_names_rva, addr_ords_rva) = struct.unpack_from("<IIHHIIIIIII", data, exp_off)
    funcs_off = _rva_to_offset(sections, addr_funcs_rva)
    names_off = _rva_to_offset(sections, addr_names_rva)
    ords_off = _rva_to_offset(sections, addr_ords_rva)
    if None in (funcs_off, names_off, ords_off):
        return {}
    result = {}
    for i in range(num_names):
        name_ptr_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
        name_off = _rva_to_offset(sections, name_ptr_rva)
        if name_off is None:
            continue
        end = data.find(b"\x00", name_off)
        if end == -1:
            continue
        name = data[name_off:end].decode("ascii", "replace")
        ord_index = struct.unpack_from("<H", data, ords_off + i * 2)[0]
        func_rva = struct.unpack_from("<I", data, funcs_off + ord_index * 4)[0]
        func_off = _rva_to_offset(sections, func_rva)
        if func_off is None or func_off + 8 > len(data):
            continue
        stub = data[func_off:func_off + 8]
        if stub[:3] == _STUB_MOV_R10_RCX and stub[3] == _STUB_MOV_EAX_IMM32:
            ordinal = struct.unpack_from("<I", stub, 4)[0]
            result[ordinal] = name
    return result


def load_win32u_ordinals(image):
    """Capture names from the validated, offline guest disk before boot.

    A missing or unreadable DLL leaves raw ordinals in the audit; it never
    substitutes another installation's names.
    """
    if not Path(image).is_file():
        return {}
    try:
        with tempfile.TemporaryDirectory(prefix="oxide-uart-ordinals-") as temporary:
            path = Path(temporary) / "win32u.dll"
            result = subprocess.run(["debugfs", "-R", f"dump {WIN32U_IMAGE_PATH} {path}", str(image)],
                                    capture_output=True, timeout=30)
            if result.returncode == 0 and path.is_file():
                return parse_win32u_exports(path.read_bytes())
    except (OSError, subprocess.TimeoutExpired, struct.error, IndexError):
        return {}
    return {}
